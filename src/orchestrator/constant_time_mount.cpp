#include "qv/orchestrator/constant_time_mount.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional> // TSK036_PBKDF2_Argon2_Migration_Path Argon2 TLV tracking
#include <future> // TSK038_Resource_Limits_and_DoS_Prevention crypto timeout
#include <thread>
#include <vector>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>

#if defined(__SSE2__) || defined(_M_X64) || defined(_M_IX86)
#include <immintrin.h>
#endif

#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/core/nonce.h"
#include "qv/common.h"
#include "qv/crypto/aegis.h"
#include "qv/crypto/ct.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/orchestrator/event_bus.h"  // TSK019
#include "qv/security/zeroizer.h"
#include "qv/storage/block_device.h"

#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2 // TSK036_PBKDF2_Argon2_Migration_Path
#include <argon2.h>
#endif

using namespace qv::orchestrator;

namespace {

std::filesystem::path LockFilePath(const std::filesystem::path& container) { // TSK026
  auto lock_path = container;
  lock_path += ".locked";
  return lock_path;
}

std::shared_ptr<qv::storage::BlockDevice> MakeBlockDevice(
    const std::filesystem::path& container) { // TSK062_FUSE_Filesystem_Integration_Linux
  std::array<uint8_t, 32> master_key{};
  return std::make_shared<qv::storage::BlockDevice>(
      container, master_key, 0, 0, qv::crypto::CipherType::AES_256_GCM);
}

class FailureTracker { // TSK026
public:
  struct FailureState {
    int failures{0};
    bool locked{false};
    std::chrono::seconds enforced_delay{std::chrono::seconds::zero()};
  };

  static FailureTracker& Instance() {
    static FailureTracker tracker;
    return tracker;
  }

  void EnforceDelay(const std::filesystem::path& container) {
    auto lock_path = LockFilePath(container);
    std::error_code ec;
    if (std::filesystem::exists(lock_path, ec)) {
      throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                      "Volume locked due to repeated authentication failures"}; // TSK026
    }

    auto key = qv::PathToUtf8String(container);
    std::unique_lock<std::mutex> lock(mutex_);
    auto it = attempts_.find(key);
    if (it == attempts_.end()) {
      return;
    }

    if (it->second.locked) {
      std::error_code locked_ec;
      if (std::filesystem::exists(lock_path, locked_ec)) {
        lock.unlock();
        throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                        "Volume locked due to repeated authentication failures"}; // TSK026
      }
      it->second.locked = false;
      it->second.failures = 0;
      return;
    }

    auto required = RequiredDelay(it->second.failures);
    auto now = Clock::now();
    auto elapsed = now - it->second.last_attempt;
    if (elapsed >= required) {
      return;
    }

    auto sleep_for = required - elapsed;
    lock.unlock();
    std::this_thread::sleep_for(sleep_for);
  }

  FailureState RecordAttempt(const std::filesystem::path& container, bool success) {
    auto key = qv::PathToUtf8String(container);
    std::unique_lock<std::mutex> lock(mutex_);
    auto& entry = attempts_[key];
    entry.last_attempt = Clock::now();

    if (success) {
      entry.failures = 0;
      entry.locked = false;
      attempts_.erase(key);
      return {};
    }

    entry.failures += 1;
    FailureState state;
    state.failures = entry.failures;
    state.enforced_delay = std::chrono::duration_cast<std::chrono::seconds>(
        RequiredDelay(entry.failures));

    if (entry.failures >= kMaxAttempts) {
      entry.locked = true;
      state.locked = true;
      lock.unlock();
      auto lock_path = LockFilePath(container);
      std::ofstream lock_file(lock_path, std::ios::out | std::ios::trunc);
      if (!lock_file) {
        throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                        "Failed to persist lock file for protected volume"}; // TSK026
      }
      lock_file << "locked";
      lock_file.close();
      return state;
    }

    return state;
  }

private:
  using Clock = std::chrono::steady_clock;

  struct AttemptState {
    int failures{0};
    Clock::time_point last_attempt{Clock::now()};
    bool locked{false};
  };

  static constexpr auto kMinDelay = std::chrono::seconds(3);
  static constexpr auto kMaxDelay = std::chrono::seconds(60);
  static constexpr int kMaxAttempts = 5;

  std::chrono::seconds RequiredDelay(int failures) const {
    if (failures <= 0) {
      return kMinDelay;
    }
    auto multiplier = static_cast<int>(1u << std::min(failures, 10));
    auto delay = kMinDelay * multiplier;
    return delay > kMaxDelay ? kMaxDelay : delay;
  }

  std::mutex mutex_;
  std::unordered_map<std::string, AttemptState> attempts_;
};

// TSK004, TSK013
constexpr std::array<uint8_t, 8> kHeaderMagic = {'Q','V','A','U','L','T','\0','\0'};
constexpr uint32_t kHeaderVersion = 0x00040101;   // TSK013, TSK068_Atomic_Header_Writes durability bump
constexpr uint32_t kFallbackIterations = 4096;
constexpr uint64_t kMinTargetNs = std::chrono::milliseconds(75).count();
constexpr uint64_t kConfiguredP99Ns = std::chrono::milliseconds(160).count();
constexpr uint64_t kPaddingSlackNs = std::chrono::milliseconds(2).count();
constexpr uint64_t kHistogramBucketNs = 1'000'000; // 1ms buckets
constexpr size_t kHistogramBuckets = 512;
constexpr uint64_t kLogIntervalNs = std::chrono::seconds(2).count();
constexpr uint16_t kTlvTypePbkdf2 = 0x1001;                                     // TSK013
constexpr uint16_t kTlvTypeHybridSalt = 0x1002;                                 // TSK013
constexpr uint16_t kTlvTypeArgon2 = 0x1003;                                     // TSK036_PBKDF2_Argon2_Migration_Path
constexpr uint16_t kTlvTypeEpoch = 0x4E4F;                                      // matches EpochTLV
constexpr uint16_t kTlvTypePqc = 0x7051;
constexpr uint16_t kTlvTypeReservedV2 = 0x7F02;                                 // TSK013
constexpr size_t kPbkdfSaltSize = 16;
constexpr size_t kHybridSaltSize = 32;
constexpr size_t kHeaderMacSize = qv::crypto::HMAC_SHA256::TAG_SIZE;

#if defined(_MSC_VER)
constexpr uint16_t ToLittleEndian16(uint16_t value) {
  return qv::kIsLittleEndian ? value : _byteswap_ushort(value);
}
#elif defined(__clang__) || defined(__GNUC__)
constexpr uint16_t ToLittleEndian16(uint16_t value) {
  return qv::kIsLittleEndian ? value : __builtin_bswap16(value);
}
#else
constexpr uint16_t ToLittleEndian16(uint16_t value) {
  if (qv::kIsLittleEndian) {
    return value;
  }
  return static_cast<uint16_t>(((value & 0xFF) << 8) | ((value >> 8) & 0xFF));
}
#endif

constexpr uint16_t FromLittleEndian16(uint16_t value) {
  return ToLittleEndian16(value);
}

constexpr uint32_t FromLittleEndian32(uint32_t value) {
  return qv::ToLittleEndian(value);
}

#pragma pack(push, 1)
struct VolumeHeader { // TSK013
  std::array<uint8_t, 8> magic{};
  uint32_t version{};
  std::array<uint8_t, 16> uuid{};
  uint32_t flags{};
};

struct ReservedV2Tlv { // TSK013
  uint16_t type = ToLittleEndian16(kTlvTypeReservedV2);
  uint16_t length = ToLittleEndian16(32);
  std::array<uint8_t, 32> payload{};
};
#pragma pack(pop)

static_assert(sizeof(VolumeHeader) == 32, "unexpected volume header size");        // TSK013
static_assert(sizeof(ReservedV2Tlv) == 36, "reserved TLV size mismatch");          // TSK013

constexpr size_t kPasswordTlvBytes =
    4 + std::max<size_t>(4 + kPbkdfSaltSize, sizeof(uint32_t) * 6 + kPbkdfSaltSize); // TSK036_PBKDF2_Argon2_Migration_Path

constexpr size_t kSerializedHeaderBytes = sizeof(VolumeHeader) + kPasswordTlvBytes +
                                          4 + kHybridSaltSize + sizeof(qv::core::EpochTLV) +
                                          sizeof(qv::core::PQC_KEM_TLV) + sizeof(ReservedV2Tlv); // TSK013
constexpr size_t kTotalHeaderBytes = kSerializedHeaderBytes + kHeaderMacSize;       // TSK013

enum class PasswordKdf { // TSK036_PBKDF2_Argon2_Migration_Path
  kPbkdf2,
  kArgon2id
};

struct Argon2Config { // TSK036_PBKDF2_Argon2_Migration_Path
  uint32_t version{1};
  uint32_t time_cost{3};
  uint32_t memory_cost_kib{64u * 1024u};
  uint32_t parallelism{4};
  uint32_t hash_length{32};
  uint32_t target_ms{500};
  std::array<uint8_t, kPbkdfSaltSize> salt{};
};

struct ParsedHeader { // TSK013
  VolumeHeader header{};
  uint32_t version{0};
  uint32_t flags{0};
  std::array<uint8_t, kPbkdfSaltSize> pbkdf_salt{};
  uint32_t pbkdf_iterations{kFallbackIterations};
  std::array<uint8_t, kHybridSaltSize> hybrid_salt{};
  uint32_t epoch{0};
  std::array<uint8_t, sizeof(qv::core::EpochTLV)> epoch_tlv_bytes{};
  qv::core::PQC_KEM_TLV pqc{};
  Argon2Config argon2{};                 // TSK036_PBKDF2_Argon2_Migration_Path
  PasswordKdf algorithm{PasswordKdf::kPbkdf2}; // TSK036_PBKDF2_Argon2_Migration_Path
  bool have_pbkdf{false};
  bool have_argon2{false};              // TSK036_PBKDF2_Argon2_Migration_Path
  bool have_hybrid{false};
  bool have_epoch{false};
  bool have_pqc{false};
  bool valid{false};
};

ParsedHeader ParseHeader(std::span<const uint8_t> bytes) { // TSK013
  ParsedHeader parsed{};
  if (bytes.size() < sizeof(VolumeHeader)) {
    return parsed;
  }

  std::memcpy(&parsed.header, bytes.data(), sizeof(VolumeHeader));

  bool magic_ok = qv::crypto::ct::CompareEqual(parsed.header.magic, kHeaderMagic);
  parsed.version = FromLittleEndian32(parsed.header.version);
  parsed.flags = FromLittleEndian32(parsed.header.flags);
  bool version_ok = parsed.version == kHeaderVersion;

  size_t offset = sizeof(VolumeHeader);
  size_t tlv_count = 0; // TSK038_Resource_Limits_and_DoS_Prevention
  if (offset > bytes.size()) { // TSK030
    parsed.valid = false;      // TSK030
    return parsed;             // TSK030
  }
  while (bytes.size() - offset >= 4) {
      if (++tlv_count > 64) { // TSK038_Resource_Limits_and_DoS_Prevention
        parsed.valid = false; // TSK038_Resource_Limits_and_DoS_Prevention
        return parsed; // TSK038_Resource_Limits_and_DoS_Prevention
      }
      uint16_t type_le = 0;
      uint16_t length_le = 0;
      std::memcpy(&type_le, bytes.data() + offset, sizeof(type_le));
      std::memcpy(&length_le, bytes.data() + offset + sizeof(type_le), sizeof(length_le));
      uint16_t type = FromLittleEndian16(type_le);
      size_t length = static_cast<size_t>(FromLittleEndian16(length_le));
      offset += 4;
      if (offset > bytes.size()) {           // TSK030
        parsed.valid = false;                // TSK030
        return parsed;                       // TSK030
      }
      if (length > bytes.size() || offset > bytes.size() - length) { // TSK030
        parsed.valid = false;                                         // TSK030
        return parsed;                                                // TSK030
      }
      auto payload = bytes.subspan(offset, length);
      switch (type) {
      case kTlvTypePbkdf2: {
        if (length != 4 + kPbkdfSaltSize) {
          parsed.have_pbkdf = false;
          break;
        }
        uint32_t iter_le = 0;
        std::memcpy(&iter_le, payload.data(), sizeof(iter_le));
        parsed.pbkdf_iterations = FromLittleEndian32(iter_le);
        std::memcpy(parsed.pbkdf_salt.data(), payload.data() + sizeof(iter_le), kPbkdfSaltSize);
        if (parsed.pbkdf_iterations == 0 || parsed.pbkdf_iterations >= (1u << 24)) {
          parsed.pbkdf_iterations = kFallbackIterations;
        } else {
          parsed.have_pbkdf = true;
        }
        parsed.algorithm = PasswordKdf::kPbkdf2; // TSK036_PBKDF2_Argon2_Migration_Path
        break;
      }
      case kTlvTypeArgon2: { // TSK036_PBKDF2_Argon2_Migration_Path
        if (length != sizeof(uint32_t) * 6 + kPbkdfSaltSize) {
          parsed.have_argon2 = false;
          break;
        }
        std::memcpy(&parsed.argon2.version, payload.data(), sizeof(parsed.argon2.version));
        std::memcpy(&parsed.argon2.time_cost, payload.data() + sizeof(uint32_t), sizeof(parsed.argon2.time_cost));
        std::memcpy(&parsed.argon2.memory_cost_kib, payload.data() + sizeof(uint32_t) * 2,
                    sizeof(parsed.argon2.memory_cost_kib));
        std::memcpy(&parsed.argon2.parallelism, payload.data() + sizeof(uint32_t) * 3,
                    sizeof(parsed.argon2.parallelism));
        std::memcpy(&parsed.argon2.hash_length, payload.data() + sizeof(uint32_t) * 4,
                    sizeof(parsed.argon2.hash_length));
        std::memcpy(&parsed.argon2.target_ms, payload.data() + sizeof(uint32_t) * 5,
                    sizeof(parsed.argon2.target_ms));
        parsed.argon2.version = FromLittleEndian32(parsed.argon2.version);
        parsed.argon2.time_cost = FromLittleEndian32(parsed.argon2.time_cost);
        parsed.argon2.memory_cost_kib = FromLittleEndian32(parsed.argon2.memory_cost_kib);
        parsed.argon2.parallelism = FromLittleEndian32(parsed.argon2.parallelism);
        parsed.argon2.hash_length = FromLittleEndian32(parsed.argon2.hash_length);
        parsed.argon2.target_ms = FromLittleEndian32(parsed.argon2.target_ms);
        std::memcpy(parsed.argon2.salt.data(), payload.data() + sizeof(uint32_t) * 6,
                    parsed.argon2.salt.size());
        std::copy(parsed.argon2.salt.begin(), parsed.argon2.salt.end(), parsed.pbkdf_salt.begin());
        parsed.have_argon2 = true;
        parsed.algorithm = PasswordKdf::kArgon2id;
        break;
      }
      case kTlvTypeHybridSalt: {
        if (length == kHybridSaltSize) {
          std::memcpy(parsed.hybrid_salt.data(), payload.data(), kHybridSaltSize);
          parsed.have_hybrid = true;
        }
        break;
      }
      case kTlvTypeEpoch: {
        if (length == sizeof(uint32_t)) {
          uint32_t epoch_le = 0;
          std::memcpy(&epoch_le, payload.data(), sizeof(epoch_le));
          parsed.epoch = FromLittleEndian32(epoch_le);
          parsed.have_epoch = true;
          if (sizeof(qv::core::EpochTLV) > bytes.size() ||               // TSK030
              offset < 4 ||                                             // TSK030
              (offset - 4) > bytes.size() - sizeof(qv::core::EpochTLV)) { // TSK030
            parsed.valid = false;                                       // TSK030
            return parsed;                                              // TSK030
          }
          std::memcpy(parsed.epoch_tlv_bytes.data(), bytes.data() + offset - 4,
                      sizeof(qv::core::EpochTLV));
        }
        break;
      }
      case kTlvTypePqc: {
        if (length == sizeof(qv::core::PQC_KEM_TLV) - 4) {
          parsed.pqc.type = type;
          parsed.pqc.length = length;
          uint16_t version_le = 0;
          uint16_t kem_id_le = 0;
          std::memcpy(&version_le, payload.data(), sizeof(version_le));
          std::memcpy(&kem_id_le, payload.data() + sizeof(version_le), sizeof(kem_id_le));
          parsed.pqc.version = FromLittleEndian16(version_le);
          parsed.pqc.kem_id = FromLittleEndian16(kem_id_le);
          size_t cursor = sizeof(version_le) + sizeof(kem_id_le);
          std::memcpy(parsed.pqc.kem_ct.data(), payload.data() + cursor, parsed.pqc.kem_ct.size());
          cursor += parsed.pqc.kem_ct.size();
          std::memcpy(parsed.pqc.sk_nonce.data(), payload.data() + cursor, parsed.pqc.sk_nonce.size());
          cursor += parsed.pqc.sk_nonce.size();
          std::memcpy(parsed.pqc.sk_tag.data(), payload.data() + cursor, parsed.pqc.sk_tag.size());
          cursor += parsed.pqc.sk_tag.size();
          std::memcpy(parsed.pqc.sk_encrypted.data(), payload.data() + cursor,
                      parsed.pqc.sk_encrypted.size());
          parsed.have_pqc = true;
        }
        break;
      }
      default:
        // TSK033: Skip unknown TLVs to maintain forward compatibility
        break;
    }
    offset += length;
  }

  parsed.valid = magic_ok && version_ok && (parsed.have_pbkdf || parsed.have_argon2) &&
                parsed.have_hybrid && parsed.have_pqc;
  return parsed;
}

std::array<uint8_t, 32> DerivePasswordKey(const std::string& password,
                                          const ParsedHeader& parsed) { // TSK013
  std::vector<uint8_t> pass_bytes(password.begin(), password.end());
  std::array<uint8_t, 32> output{};
  std::span<const uint8_t> password_span(pass_bytes.data(), pass_bytes.size());

  if (parsed.algorithm == PasswordKdf::kArgon2id) { // TSK036_PBKDF2_Argon2_Migration_Path
#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2
    if (parsed.argon2.hash_length != output.size()) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Unsupported Argon2 hash length"};
    }
    int rc = argon2id_hash_raw(parsed.argon2.time_cost, parsed.argon2.memory_cost_kib,
                               parsed.argon2.parallelism, password_span.data(), password_span.size(),
                               parsed.argon2.salt.data(), parsed.argon2.salt.size(), output.data(),
                               output.size());
    if (rc != ARGON2_OK) {
      throw qv::Error{qv::ErrorDomain::Crypto, rc, "Argon2id derivation failed"};
    }
#else
    throw qv::Error{qv::ErrorDomain::Dependency, 0,
                    "Argon2id support not available in this build"};
#endif
  } else {
    std::array<uint8_t, 20> block{};
    std::memcpy(block.data(), parsed.pbkdf_salt.data(), parsed.pbkdf_salt.size());
    block[16] = 0;
    block[17] = 0;
    block[18] = 0;
    block[19] = 1;

    auto u = qv::crypto::HMAC_SHA256::Compute(password_span,
                                              std::span<const uint8_t>(block.data(), block.size()));
    output = u;
    auto iter = u;
    for (uint32_t i = 1; i < parsed.pbkdf_iterations; ++i) {
      iter = qv::crypto::HMAC_SHA256::Compute(password_span,
                                              std::span<const uint8_t>(iter.data(), iter.size()));
      for (size_t j = 0; j < output.size(); ++j) {
        output[j] ^= iter[j];
      }
    }
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(iter.data(), iter.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(u.data(), u.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(block.data(), block.size()));
  }
  if (!pass_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(pass_bytes.data(), pass_bytes.size()));
  }
  return output;
}

std::array<uint8_t, 32> DeriveHeaderMacKey(const std::array<uint8_t, 32>& hybrid_key,
                                           const ParsedHeader& parsed) { // TSK013
  auto prk = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(parsed.header.uuid.data(), parsed.header.uuid.size()),
      std::span<const uint8_t>(hybrid_key.data(), hybrid_key.size()));
  static constexpr std::string_view kInfo{"QV-HEADER-MAC/v1"};
  std::array<uint8_t, kInfo.size() + 1> info_block{};
  std::memcpy(info_block.data(), kInfo.data(), kInfo.size());
  info_block[kInfo.size()] = 0x01;
  auto okm = qv::crypto::HMAC_SHA256::Compute(std::span<const uint8_t>(prk.data(), prk.size()),
                                              std::span<const uint8_t>(info_block.data(), info_block.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(prk.data(), prk.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(info_block.data(), info_block.size()));
  return okm;
}

struct TimingSnapshot {
  uint64_t target_ns{0};
  uint64_t p95_ns{0};
  uint64_t p99_ns{0};
  uint64_t samples{0};
};

struct TimingState {
  enum class Mode { Calibrating, Production }; // TSK022

  std::atomic<uint64_t> target_ns{120'000'000};
  std::atomic<uint64_t> last_log_ns{0};
  std::atomic<Mode> mode{Mode::Calibrating};       // TSK022
  std::atomic<uint64_t> fixed_target_ns{kConfiguredP99Ns}; // TSK022
  std::mutex mutex;
  std::array<uint64_t, kHistogramBuckets> histogram{};
  uint64_t total_samples{0};
  uint64_t last_p95{0};
  uint64_t last_p99{0};
};

constexpr uint64_t kCalibrationSamples = 8192; // TSK022

TimingState& GetTimingState() {
  static TimingState state;
  return state;
}

void RecordSample(std::chrono::nanoseconds duration) {
  auto& state = GetTimingState();
  uint64_t ns = static_cast<uint64_t>(duration.count());
  size_t bucket = std::min<size_t>(ns / kHistogramBucketNs, kHistogramBuckets - 1);
  std::lock_guard<std::mutex> guard(state.mutex);
  for (size_t i = 0; i < kHistogramBuckets; ++i) { // TSK022
    bool is_bucket = (i == bucket);
    uint64_t increment = qv::crypto::ct::Select<uint64_t>(0, 1, is_bucket); // TSK022
    state.histogram[i] += increment;
  }
  state.total_samples += 1;

  if (state.total_samples < 8) {
    return;
  }

  auto threshold95 = std::max<uint64_t>(1, (state.total_samples * 95 + 99) / 100);
  auto threshold99 = std::max<uint64_t>(1, (state.total_samples * 99 + 99) / 100);
  uint64_t cumulative = 0;
  uint64_t p95_bucket = 0;
  uint64_t p99_bucket = 0;
  for (size_t i = 0; i < kHistogramBuckets; ++i) {
    cumulative += state.histogram[i];
    if (p95_bucket == 0 && cumulative >= threshold95) {
      p95_bucket = i + 1;
    }
    if (p99_bucket == 0 && cumulative >= threshold99) {
      p99_bucket = i + 1;
      break;
    }
  }
  if (p95_bucket == 0) {
    p95_bucket = kHistogramBuckets;
  }
  if (p99_bucket == 0) {
    p99_bucket = kHistogramBuckets;
  }

  state.last_p95 = p95_bucket * kHistogramBucketNs;
  state.last_p99 = p99_bucket * kHistogramBucketNs;

  uint64_t desired = state.last_p99 + kPaddingSlackNs;
  desired = std::max<uint64_t>(desired, kMinTargetNs);   // TSK022
  desired = std::min<uint64_t>(desired, kConfiguredP99Ns); // TSK022

  auto mode = state.mode.load(std::memory_order_acquire); // TSK022
  if (mode == TimingState::Mode::Calibrating) {           // TSK022
    state.target_ns.store(desired, std::memory_order_relaxed);
    state.fixed_target_ns.store(desired, std::memory_order_relaxed);
    if (state.total_samples >= kCalibrationSamples) {
      state.mode.store(TimingState::Mode::Production, std::memory_order_release);
    }
  }
}

TimingSnapshot SnapshotTiming() {
  TimingSnapshot snap{};
  auto& state = GetTimingState();
  std::lock_guard<std::mutex> guard(state.mutex);
  auto mode = state.mode.load(std::memory_order_acquire);                // TSK022
  snap.target_ns = (mode == TimingState::Mode::Production)
                       ? state.fixed_target_ns.load(std::memory_order_relaxed)
                       : state.target_ns.load(std::memory_order_relaxed); // TSK022
  snap.p95_ns = state.last_p95;
  snap.p99_ns = state.last_p99;
  snap.samples = state.total_samples;
  return snap;
}

std::chrono::nanoseconds ComputePadding(std::chrono::nanoseconds actual) {
  auto& state = GetTimingState();
  auto mode = state.mode.load(std::memory_order_acquire); // TSK022
  uint64_t target = (mode == TimingState::Mode::Production)
                        ? state.fixed_target_ns.load(std::memory_order_relaxed)
                        : state.target_ns.load(std::memory_order_relaxed); // TSK022
  uint64_t actual_ns = static_cast<uint64_t>(actual.count());
  bool over_target = actual_ns > target;
  uint64_t clamped = qv::crypto::ct::Select<uint64_t>(actual_ns, target, over_target); // TSK022
  uint64_t diff = target - clamped;
  return std::chrono::nanoseconds(diff);
}

} // namespace

namespace qv::orchestrator::fuzz {
bool ParseHeaderHarness(std::span<const uint8_t> bytes) { // TSK030
  (void)::ParseHeader(bytes);                              // TSK030
  return true;                                             // TSK030
}
} // namespace qv::orchestrator::fuzz

std::optional<ConstantTimeMount::VolumeHandle>
ConstantTimeMount::Mount(const std::filesystem::path& container,
                         const std::string& password) {
  auto& tracker = FailureTracker::Instance();                     // TSK026
  tracker.EnforceDelay(container);                                // TSK026

  Attempt a, b;
  auto start = std::chrono::steady_clock::now();
  a.start = start;
  b.start = start;

  auto r1 = AttemptMount(container, password);
  a.duration = std::chrono::steady_clock::now() - a.start;
  a.pad = ComputePadding(a.duration);
  ConstantTimePadding(a.pad);
  RecordSample(a.duration);

  auto r2 = AttemptMount(container, password);
  b.duration = std::chrono::steady_clock::now() - b.start;
  b.pad = ComputePadding(b.duration);
  ConstantTimePadding(b.pad);
  RecordSample(b.duration);

  LogTiming(a, b);

  bool r1_ok = r1.has_value();
  bool r2_ok = r2.has_value();
  bool any_success = r1_ok || r2_ok;
  uint32_t h1 = r1_ok ? static_cast<uint32_t>(r1->dummy) : 0;
  uint32_t h2 = r2_ok ? static_cast<uint32_t>(r2->dummy) : 0;
  uint32_t selected = qv::crypto::ct::Select<uint32_t>(h1, h2, (!r1_ok && r2_ok));

  auto state = tracker.RecordAttempt(container, any_success);     // TSK026
  if (!any_success) {
    Event event{};                                                // TSK026
    event.category = EventCategory::kSecurity;                    // TSK026
    event.severity = EventSeverity::kWarning;                     // TSK026
    event.event_id = state.locked ? "volume_mount_locked" : "volume_mount_failure"; // TSK026
    event.message = state.locked ? "Volume locked after repeated authentication failures"
                                 : "Volume mount authentication failed"; // TSK026
    event.fields.emplace_back("container_hash",                                     // TSK026
                              HashForTelemetry(qv::PathToUtf8String(container)),
                              FieldPrivacy::kHash);
    event.fields.emplace_back("consecutive_failures", std::to_string(state.failures),
                              FieldPrivacy::kPublic, true); // TSK026
    event.fields.emplace_back("cooldown_seconds", std::to_string(state.enforced_delay.count()),
                              FieldPrivacy::kPublic, true); // TSK026
    event.fields.emplace_back("locked", state.locked ? "true" : "false", FieldPrivacy::kPublic);
    EventBus::Instance().Publish(event); // TSK026
  }

  if (any_success) {
    VolumeHandle handle{};
    handle.dummy = static_cast<int>(selected);
    handle.device = MakeBlockDevice(container);
    return handle;
  }
  return std::nullopt;
}

void ConstantTimeMount::ConstantTimePadding(std::chrono::nanoseconds duration) {
  auto remaining = duration;
  if (remaining <= std::chrono::nanoseconds::zero()) {
    std::atomic_signal_fence(std::memory_order_seq_cst);
    return;
  }
  auto end = std::chrono::steady_clock::now() + remaining;
  while (std::chrono::steady_clock::now() < end) {
#if defined(__SSE2__) || defined(_M_X64) || defined(_M_IX86)
    _mm_pause();
#else
    std::this_thread::yield();
#endif
  }
  std::atomic_signal_fence(std::memory_order_seq_cst);
}

std::optional<ConstantTimeMount::VolumeHandle>
ConstantTimeMount::AttemptMount(const std::filesystem::path& container,
                                const std::string& password) {
  auto attempt_start = std::chrono::steady_clock::now(); // TSK038_Resource_Limits_and_DoS_Prevention
  constexpr auto kMaxAttemptDuration = std::chrono::seconds(5); // TSK038_Resource_Limits_and_DoS_Prevention
  constexpr uintmax_t kMaxContainerSize = 100ull * 1024ull * 1024ull; // TSK038_Resource_Limits_and_DoS_Prevention

  std::error_code size_ec; // TSK038_Resource_Limits_and_DoS_Prevention
  auto container_size = std::filesystem::file_size(container, size_ec); // TSK038_Resource_Limits_and_DoS_Prevention
  if (size_ec || container_size > kMaxContainerSize) { // TSK038_Resource_Limits_and_DoS_Prevention
    return std::nullopt; // TSK038_Resource_Limits_and_DoS_Prevention
  }
  std::array<uint8_t, kTotalHeaderBytes> buf{}; // TSK013
  bool io_ok = false;
  {
    std::ifstream in(container, std::ios::binary);
    if (in) {
      in.read(reinterpret_cast<char*>(buf.data()), buf.size());
      io_ok = static_cast<size_t>(in.gcount()) == buf.size();
    }
  }

  std::array<uint8_t, kSerializedHeaderBytes> header_bytes{};
  std::copy_n(buf.begin(), header_bytes.size(), header_bytes.begin());

  std::array<uint8_t, kHeaderMacSize> stored_mac{};
  std::copy_n(buf.begin() + header_bytes.size(), stored_mac.size(), stored_mac.begin());

  auto parsed = ParseHeader(std::span<const uint8_t>(header_bytes.data(), header_bytes.size()));

  auto classical_key = DerivePasswordKey(password, parsed);
  auto parsed_for_kdf = parsed; // TSK038_Resource_Limits_and_DoS_Prevention
  auto classical_key_copy = classical_key; // TSK038_Resource_Limits_and_DoS_Prevention
  std::array<uint8_t, 32> hybrid_key{};
  bool pqc_ok = false;
  auto kdf_task = std::packaged_task<std::array<uint8_t, 32>()>( // TSK038_Resource_Limits_and_DoS_Prevention
      [parsed_for_kdf, classical_key_copy]() mutable {
        try {
          std::span<const uint8_t> hybrid_salt(parsed_for_kdf.hybrid_salt.data(), parsed_for_kdf.hybrid_salt.size());
          std::span<const uint8_t> epoch_span; // TSK038_Resource_Limits_and_DoS_Prevention
          if (parsed_for_kdf.have_epoch) { // TSK038_Resource_Limits_and_DoS_Prevention
            epoch_span = std::span<const uint8_t>(parsed_for_kdf.epoch_tlv_bytes.data(),
                                                  parsed_for_kdf.epoch_tlv_bytes.size());
          }
          auto result = qv::core::PQCHybridKDF::Mount(std::span<const uint8_t, 32>(classical_key_copy),
                                                      parsed_for_kdf.pqc,
                                                      hybrid_salt,
                                                      std::span<const uint8_t, 16>(parsed_for_kdf.header.uuid),
                                                      parsed_for_kdf.version,
                                                      epoch_span); // TSK038_Resource_Limits_and_DoS_Prevention
          qv::security::Zeroizer::Wipe(
              std::span<uint8_t>(classical_key_copy.data(), classical_key_copy.size())); // TSK038_Resource_Limits_and_DoS_Prevention
          return result;
        } catch (...) {
          qv::security::Zeroizer::Wipe(
              std::span<uint8_t>(classical_key_copy.data(), classical_key_copy.size())); // TSK038_Resource_Limits_and_DoS_Prevention
          throw;
        }
      });
  auto hybrid_future = kdf_task.get_future(); // TSK038_Resource_Limits_and_DoS_Prevention
  std::thread(std::move(kdf_task)).detach(); // TSK038_Resource_Limits_and_DoS_Prevention

  auto status = hybrid_future.wait_for(std::chrono::seconds(30)); // TSK038_Resource_Limits_and_DoS_Prevention
  if (status == std::future_status::ready) { // TSK038_Resource_Limits_and_DoS_Prevention
    try {
      hybrid_key = hybrid_future.get();
      pqc_ok = true;
    } catch (const AuthenticationFailureError&) {
      pqc_ok = false;
    } catch (const std::exception&) {
      pqc_ok = false;
    }
  } else {
    pqc_ok = false; // TSK038_Resource_Limits_and_DoS_Prevention
    qv::orchestrator::Event kdf_timeout{}; // TSK038_Resource_Limits_and_DoS_Prevention
    kdf_timeout.category = qv::orchestrator::EventCategory::kSecurity; // TSK038_Resource_Limits_and_DoS_Prevention
    kdf_timeout.severity = qv::orchestrator::EventSeverity::kWarning; // TSK038_Resource_Limits_and_DoS_Prevention
    kdf_timeout.event_id = "pqc_kdf_timeout"; // TSK038_Resource_Limits_and_DoS_Prevention
    kdf_timeout.message = "Hybrid KDF exceeded timeout"; // TSK038_Resource_Limits_and_DoS_Prevention
    kdf_timeout.fields.emplace_back("container_path", container.generic_string(),
                                    qv::orchestrator::FieldPrivacy::kHash); // TSK038_Resource_Limits_and_DoS_Prevention
    qv::orchestrator::EventBus::Instance().Publish(kdf_timeout); // TSK038_Resource_Limits_and_DoS_Prevention
  }

  auto mac_key = DeriveHeaderMacKey(hybrid_key, parsed);
  auto computed_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(header_bytes.data(), header_bytes.size()));
  bool mac_ok = qv::crypto::ct::CompareEqual(stored_mac, computed_mac);

  bool result = io_ok && parsed.valid && pqc_ok && mac_ok;                // TSK022
  uint32_t mask = qv::crypto::ct::Select<uint32_t>(0u, 1u, result);      // TSK022
  std::atomic_signal_fence(std::memory_order_seq_cst);                   // TSK022
  volatile uint32_t guard_mask = mask;                                   // TSK022
  (void)guard_mask;                                                      // TSK022

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  auto elapsed = std::chrono::steady_clock::now() - attempt_start; // TSK038_Resource_Limits_and_DoS_Prevention
  if (elapsed > kMaxAttemptDuration) { // TSK038_Resource_Limits_and_DoS_Prevention
    qv::orchestrator::Event timeout_event{}; // TSK038_Resource_Limits_and_DoS_Prevention
    timeout_event.category = qv::orchestrator::EventCategory::kSecurity; // TSK038_Resource_Limits_and_DoS_Prevention
    timeout_event.severity = qv::orchestrator::EventSeverity::kWarning; // TSK038_Resource_Limits_and_DoS_Prevention
    timeout_event.event_id = "mount_timeout_exceeded"; // TSK038_Resource_Limits_and_DoS_Prevention
    timeout_event.message = "Mount attempt exceeded time limit"; // TSK038_Resource_Limits_and_DoS_Prevention
    timeout_event.fields.emplace_back("container_path", container.generic_string(),
                                      qv::orchestrator::FieldPrivacy::kHash); // TSK038_Resource_Limits_and_DoS_Prevention
    timeout_event.fields.emplace_back("duration_ns", std::to_string(elapsed.count()),
                                      qv::orchestrator::FieldPrivacy::kPublic, true); // TSK038_Resource_Limits_and_DoS_Prevention
    qv::orchestrator::EventBus::Instance().Publish(timeout_event); // TSK038_Resource_Limits_and_DoS_Prevention
    return std::nullopt; // TSK038_Resource_Limits_and_DoS_Prevention
  }

  if (mask != 0u) {
    VolumeHandle handle{};
    handle.dummy = 1;
    handle.device = MakeBlockDevice(container);
    return handle;
  }
  return std::nullopt;
}

void ConstantTimeMount::LogTiming(const Attempt& a, const Attempt& b) {
  auto now_ns = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
  auto& state = GetTimingState();
  auto last = state.last_log_ns.load(std::memory_order_relaxed);
  if (now_ns - last < kLogIntervalNs) {
    return;
  }
  if (!state.last_log_ns.compare_exchange_strong(last, now_ns)) {
    return;
  }

  auto snap = SnapshotTiming();

  qv::orchestrator::Event event;  // TSK019
  event.category = qv::orchestrator::EventCategory::kTelemetry;
  event.severity = qv::orchestrator::EventSeverity::kInfo;
  event.event_id = "ct_mount_timing";
  event.message = "Constant-time mount timing sample";
  event.fields.emplace_back("attempt_a_duration_ns", std::to_string(a.duration.count()),
                            qv::orchestrator::FieldPrivacy::kPublic, true);
  event.fields.emplace_back("attempt_b_duration_ns", std::to_string(b.duration.count()),
                            qv::orchestrator::FieldPrivacy::kPublic, true);
  event.fields.emplace_back("attempt_a_padding_ns", std::to_string(a.pad.count()),
                            qv::orchestrator::FieldPrivacy::kPublic, true);
  event.fields.emplace_back("attempt_b_padding_ns", std::to_string(b.pad.count()),
                            qv::orchestrator::FieldPrivacy::kPublic, true);
  event.fields.emplace_back("target_ns", std::to_string(snap.target_ns),
                            qv::orchestrator::FieldPrivacy::kPublic, true);
  event.fields.emplace_back("p95_ns", std::to_string(snap.p95_ns),
                            qv::orchestrator::FieldPrivacy::kPublic, true);
  event.fields.emplace_back("p99_ns", std::to_string(snap.p99_ns),
                            qv::orchestrator::FieldPrivacy::kPublic, true);
  event.fields.emplace_back("samples", std::to_string(snap.samples),
                            qv::orchestrator::FieldPrivacy::kPublic, true);

  qv::orchestrator::EventBus::Instance().Publish(event);
}
