#include "qv/orchestrator/volume_manager.h"

#include <algorithm> // TSK033 skip/zero TLV payloads
#include <array>
#include <cerrno>
#include <chrono>    // TSK036_PBKDF2_Argon2_Migration_Path adaptive calibration
#include <cstring>
#include <fstream>
#include <functional> // TSK036_PBKDF2_Argon2_Migration_Path progress callbacks
#include <iomanip>    // TSK029
#include <iterator>   // TSK024_Key_Rotation_and_Lifecycle_Management
#include <limits>     // TSK024_Key_Rotation_and_Lifecycle_Management
#include <random>
#include <span>
#include <sstream>      // TSK033 version formatting
#include <string_view>
#include <vector>
#include <optional>     // TSK036_PBKDF2_Argon2_Migration_Path Argon2 TLV control

#include "qv/common.h"
#include "qv/core/nonce.h"
#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/aes_gcm.h" // TSK024_Key_Rotation_and_Lifecycle_Management
#include "qv/crypto/hmac_sha256.h"
#include "qv/error.h"
#include "qv/orchestrator/event_bus.h" // TSK024_Key_Rotation_and_Lifecycle_Management
#include "qv/orchestrator/io_util.h"   // TSK068_Atomic_Header_Writes atomic persistence
#include "qv/security/zeroizer.h"

#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2 // TSK036_PBKDF2_Argon2_Migration_Path
#include <argon2.h>
#endif

#ifndef QV_SENSITIVE_FUNCTION  // TSK028A_Memory_Wiping_Gaps
#if defined(_MSC_VER)
#define QV_SENSITIVE_BEGIN __pragma(optimize("", off))
#define QV_SENSITIVE_END __pragma(optimize("", on))
#define QV_SENSITIVE_FUNCTION __declspec(noinline)
#elif defined(__clang__)
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION [[clang::optnone]] __attribute__((noinline))
#elif defined(__GNUC__)
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION __attribute__((noinline, optimize("O0")))
#else
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION
#endif
#endif  // QV_SENSITIVE_FUNCTION TSK028A_Memory_Wiping_Gaps

using namespace qv::orchestrator;

namespace {

  constexpr std::array<char, 8> kVolumeMagic = {'Q', 'V', 'A', 'U', 'L', 'T', '\0', '\0'}; // TSK013
  constexpr uint32_t kHeaderVersion = VolumeManager::kLatestHeaderVersion;                  // TSK033 align serialization with published target
  constexpr uint16_t kTlvTypePbkdf2 = 0x1001;                                              // TSK013
  constexpr uint16_t kTlvTypeHybridSalt = 0x1002;                                          // TSK013
  constexpr uint16_t kTlvTypeArgon2 = 0x1003;                                              // TSK036_PBKDF2_Argon2_Migration_Path
  constexpr uint16_t kTlvTypeEpoch = 0x4E4F; // matches EpochTLV
  constexpr uint16_t kTlvTypePqcKem = 0x7051;
  constexpr uint16_t kTlvTypeReservedV2 = 0x7F02; // TSK033 reserved for ACL metadata staging
  constexpr uint32_t kDefaultFlags = 0;
  constexpr uint32_t kDefaultPbkdfIterations = 600'000; // TSK036_PBKDF2_Argon2_Migration_Path baseline
  constexpr uint32_t kBenchmarkIterations = 100'000;    // TSK036_PBKDF2_Argon2_Migration_Path calibration sample size
  constexpr size_t kPbkdfSaltSize = 16;
  constexpr size_t kHybridSaltSize = 32;
  constexpr std::chrono::milliseconds kDefaultTargetDuration{500}; // TSK036_PBKDF2_Argon2_Migration_Path
  constexpr uint32_t kMinPbkdfIterations = 50'000;                 // TSK036_PBKDF2_Argon2_Migration_Path floor
  constexpr uint32_t kMaxPbkdfIterations = 8'000'000;              // TSK036_PBKDF2_Argon2_Migration_Path ceiling

  using PasswordKdf = VolumeManager::PasswordKdf;                                   // TSK036_PBKDF2_Argon2_Migration_Path
  using ProgressCallback = VolumeManager::ProgressCallback;                         // TSK036_PBKDF2_Argon2_Migration_Path

  struct Argon2Config { // TSK036_PBKDF2_Argon2_Migration_Path serialized TLV payload
    uint32_t version{1};
    uint32_t time_cost{3};
    uint32_t memory_cost_kib{64u * 1024u};
    uint32_t parallelism{4};
    uint32_t hash_length{32};
    uint32_t target_ms{static_cast<uint32_t>(kDefaultTargetDuration.count())};
    std::array<uint8_t, kPbkdfSaltSize> salt{};
  };

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

  struct VolumeHeader { // TSK013
    std::array<char, 8> magic = kVolumeMagic;
    uint32_t version = qv::ToLittleEndian(kHeaderVersion);
    std::array<uint8_t, 16> uuid{};
    uint32_t flags = qv::ToLittleEndian(kDefaultFlags);
  };

#pragma pack(push, 1)
  struct ReservedV2Tlv { // TSK033 future ACL metadata placeholder
    uint16_t type = ToLittleEndian16(kTlvTypeReservedV2);
    uint16_t length = ToLittleEndian16(32);
    std::array<uint8_t, 32> payload{};
  };
#pragma pack(pop)

  static_assert(sizeof(VolumeHeader) == 32, "volume header must be 32 bytes");  // TSK013
  static_assert(sizeof(ReservedV2Tlv) == 36, "reserved TLV layout unexpected"); // TSK013

  void FillRandom(std::span<uint8_t> out) { // TSK013
    std::random_device rd;
    std::mt19937_64 gen(rd());
    for (size_t i = 0; i < out.size();) {
      auto value = gen();
      for (size_t j = 0; j < sizeof(value) && i < out.size(); ++j, ++i) {
        out[i] = static_cast<uint8_t>((value >> (j * 8)) & 0xFF);
      }
    }
  }

  std::array<uint8_t, 16> GenerateUuidV4() { // TSK013
    std::array<uint8_t, 16> uuid{};
    FillRandom(uuid);
    uuid[6] = static_cast<uint8_t>((uuid[6] & 0x0F) | 0x40);
    uuid[8] = static_cast<uint8_t>((uuid[8] & 0x3F) | 0x80);
    return uuid;
  }

  std::string FormatUuid(const std::array<uint8_t, 16>& uuid) { // TSK029
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < uuid.size(); ++i) {
      oss << std::setw(2) << static_cast<int>(uuid[i]);
      if (i == 3 || i == 5 || i == 7 || i == 9) {
        oss << '-';
      }
    }
    return oss.str();
  }

  std::array<uint8_t, 32> DerivePasswordKey(std::span<const uint8_t> password,
                                            const std::array<uint8_t, kPbkdfSaltSize>& salt,
                                            uint32_t iterations,
                                            ProgressCallback progress = {}) { // TSK036_PBKDF2_Argon2_Migration_Path
    std::array<uint8_t, 32> output{};
    std::array<uint8_t, 20> block{};
    std::memcpy(block.data(), salt.data(), salt.size());
    block[16] = 0;
    block[17] = 0;
    block[18] = 0;
    block[19] = 1;

    iterations = std::max<uint32_t>(iterations, 1u);                       // TSK036_PBKDF2_Argon2_Migration_Path guard zero

    auto u = qv::crypto::HMAC_SHA256::Compute(password,
                                              std::span<const uint8_t>(block.data(), block.size()));
    output = u;
    auto iter = u;
    if (progress) {
      progress(1, iterations);
    }
    for (uint32_t i = 1; i < iterations; ++i) {
      iter = qv::crypto::HMAC_SHA256::Compute(password,
                                              std::span<const uint8_t>(iter.data(), iter.size()));
      for (size_t j = 0; j < output.size(); ++j) {
        output[j] ^= iter[j];
      }

      if (progress && (i + 1) % 10'000 == 0) {
        progress(i + 1, iterations);
      }
    }

    qv::security::Zeroizer::Wipe(std::span<uint8_t>(iter.data(), iter.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(u.data(), u.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(block.data(), block.size()));
    if (progress && iterations % 10'000 != 0) {
      progress(iterations, iterations);
    }
    return output;
  }

  std::array<uint8_t, 32> DerivePasswordKeyArgon2id(std::span<const uint8_t> password,
                                                    const Argon2Config& config) { // TSK036_PBKDF2_Argon2_Migration_Path
#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2
    std::array<uint8_t, 32> output{};
    if (config.hash_length != output.size()) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Unsupported Argon2 hash length"};
    }
    int rc = argon2id_hash_raw(static_cast<uint32_t>(config.time_cost),
                               static_cast<uint32_t>(config.memory_cost_kib),
                               static_cast<uint32_t>(config.parallelism),
                               password.data(), password.size(), config.salt.data(), config.salt.size(),
                               output.data(), output.size());
    if (rc != ARGON2_OK) {
      throw qv::Error{qv::ErrorDomain::Crypto, rc, "Argon2id derivation failed"};
    }
    return output;
#else
    (void)password;
    (void)config;
    throw qv::Error{qv::ErrorDomain::Dependency, 0,
                    "Argon2id support not available in this build"};
#endif
  }

  std::array<uint8_t, 32> DeriveHeaderMacKey(
      std::span<const uint8_t, 32> hybrid_key,
      const std::array<uint8_t, 16>& uuid) { // TSK024_Key_Rotation_and_Lifecycle_Management
    auto metadata_root =
        qv::core::DeriveMetadataKey(hybrid_key); // TSK024_Key_Rotation_and_Lifecycle_Management
    auto prk = qv::crypto::HMAC_SHA256::Compute( // TSK024_Key_Rotation_and_Lifecycle_Management
        std::span<const uint8_t>(uuid.data(),
                                 uuid.size()), // TSK024_Key_Rotation_and_Lifecycle_Management
        std::span<const uint8_t>(
            metadata_root.data(),
            metadata_root.size())); // TSK024_Key_Rotation_and_Lifecycle_Management
    static constexpr std::string_view kInfo{"QV-HEADER-MAC/v1"};
    std::array<uint8_t, kInfo.size() + 1> info_block{};
    std::memcpy(info_block.data(), kInfo.data(), kInfo.size());
    info_block[kInfo.size()] = 0x01;
    auto okm = qv::crypto::HMAC_SHA256::Compute(
        std::span<const uint8_t>(prk.data(), prk.size()),
        std::span<const uint8_t>(info_block.data(), info_block.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(prk.data(), prk.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(info_block.data(), info_block.size()));
    qv::security::Zeroizer::Wipe(
        std::span<uint8_t>(metadata_root.data(),
                           metadata_root.size())); // TSK024_Key_Rotation_and_Lifecycle_Management
    return okm;
  }

  template <typename T> void AppendRaw(std::vector<uint8_t>& out, const T& value) {
    auto bytes = qv::AsBytesConst(value);
    out.insert(out.end(), bytes.begin(), bytes.end());
  }

  class VectorWipeGuard { // TSK028_Secure_Deletion_and_Data_Remanence
  public:
    explicit VectorWipeGuard(std::vector<uint8_t>& vec) noexcept : vec_(vec) {}
    VectorWipeGuard(const VectorWipeGuard&) = delete;
    VectorWipeGuard& operator=(const VectorWipeGuard&) = delete;
    VectorWipeGuard(VectorWipeGuard&& other) noexcept : vec_(other.vec_), active_(other.active_) {
      other.active_ = false;
    }
    VectorWipeGuard& operator=(VectorWipeGuard&&) = delete;
    ~VectorWipeGuard() { Release(); }

    void Release() noexcept {
      if (!active_) {
        return;
      }
      qv::security::Zeroizer::WipeVector(vec_);
      vec_.clear();
      active_ = false;
    }

  private:
    std::vector<uint8_t>& vec_;
    bool active_{true};
  };

  void AppendUint16(std::vector<uint8_t>& out, uint16_t value) {
    const uint16_t le = ToLittleEndian16(value);
    AppendRaw(out, le);
  }

  void AppendUint32(std::vector<uint8_t>& out, uint32_t value) {
    const uint32_t le = qv::ToLittleEndian(value);
    AppendRaw(out, le);
  }

  struct ParsedHeader {                        // TSK024_Key_Rotation_and_Lifecycle_Management
    VolumeHeader header{};                     // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t header_version{0};                // TSK024_Key_Rotation_and_Lifecycle_Management
    PasswordKdf algorithm{PasswordKdf::kPbkdf2}; // TSK036_PBKDF2_Argon2_Migration_Path
    uint32_t pbkdf_iterations{0};              // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, kPbkdfSaltSize>
        pbkdf_salt{}; // TSK036_PBKDF2_Argon2_Migration_Path shared salt storage
    Argon2Config argon2{};                     // TSK036_PBKDF2_Argon2_Migration_Path
    bool have_argon2{false};                   // TSK036_PBKDF2_Argon2_Migration_Path
    std::array<uint8_t, kHybridSaltSize>
        hybrid_salt{};                      // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::core::EpochTLV epoch_tlv{};         // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t epoch_value{0};                // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::core::PQC_KEM_TLV kem_blob{};       // TSK024_Key_Rotation_and_Lifecycle_Management
    ReservedV2Tlv reserved_v2{};            // TSK024_Key_Rotation_and_Lifecycle_Management
    bool reserved_v2_present{false};        // TSK033 optional TLV tracking
    std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE>
        mac{};                        // TSK024_Key_Rotation_and_Lifecycle_Management
    std::vector<uint8_t> payload;     // TSK024_Key_Rotation_and_Lifecycle_Management
  };

  struct DerivedKeyset {                // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> data{};     // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> metadata{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> index{};    // TSK024_Key_Rotation_and_Lifecycle_Management
  };

  DerivedKeyset MakeDerivedKeyset(
      std::span<const uint8_t, 32> master) {     // TSK024_Key_Rotation_and_Lifecycle_Management
    DerivedKeyset keys{};                        // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.data = qv::core::DeriveDataKey(master); // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.metadata =
        qv::core::DeriveMetadataKey(master);       // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.index = qv::core::DeriveIndexKey(master); // TSK024_Key_Rotation_and_Lifecycle_Management
    return keys;                                   // TSK024_Key_Rotation_and_Lifecycle_Management
  }

  std::vector<uint8_t> SerializeHeaderPayload(
      const VolumeHeader& header, PasswordKdf algorithm, uint32_t pbkdf_iterations,
      const std::array<uint8_t, kPbkdfSaltSize>& password_salt,
      const std::optional<Argon2Config>& argon2,
      const std::array<uint8_t, kHybridSaltSize>& hybrid_salt, const qv::core::EpochTLV& epoch,
      const qv::core::PQC_KEM_TLV& kem_blob,
      const ReservedV2Tlv& reserved) { // TSK024_Key_Rotation_and_Lifecycle_Management
    std::vector<uint8_t> serialized;   // TSK024_Key_Rotation_and_Lifecycle_Management
    serialized.reserve(1024);          // TSK024_Key_Rotation_and_Lifecycle_Management

    AppendRaw(serialized, header); // TSK024_Key_Rotation_and_Lifecycle_Management

    if (algorithm == PasswordKdf::kPbkdf2) { // TSK036_PBKDF2_Argon2_Migration_Path
      AppendUint16(serialized, kTlvTypePbkdf2);
      AppendUint16(serialized, static_cast<uint16_t>(4 + password_salt.size()));
      AppendUint32(serialized, pbkdf_iterations);
      serialized.insert(serialized.end(), password_salt.begin(), password_salt.end());
    } else if (algorithm == PasswordKdf::kArgon2id) { // TSK036_PBKDF2_Argon2_Migration_Path
      if (!argon2) {
        throw qv::Error{qv::ErrorDomain::Internal, 0, "Missing Argon2 configuration"};
      }
      AppendUint16(serialized, kTlvTypeArgon2);
      constexpr uint16_t kArgon2PayloadSize = static_cast<uint16_t>(sizeof(uint32_t) * 6 + kPbkdfSaltSize);
      AppendUint16(serialized, kArgon2PayloadSize);
      AppendUint32(serialized, argon2->version);
      AppendUint32(serialized, argon2->time_cost);
      AppendUint32(serialized, argon2->memory_cost_kib);
      AppendUint32(serialized, argon2->parallelism);
      AppendUint32(serialized, argon2->hash_length);
      AppendUint32(serialized, argon2->target_ms);
      serialized.insert(serialized.end(), argon2->salt.begin(), argon2->salt.end());
    }

    AppendUint16(serialized, kTlvTypeHybridSalt); // TSK024_Key_Rotation_and_Lifecycle_Management
    AppendUint16(
        serialized,
        static_cast<uint16_t>(hybrid_salt.size())); // TSK024_Key_Rotation_and_Lifecycle_Management
    serialized.insert(serialized.end(), hybrid_salt.begin(),
                      hybrid_salt.end()); // TSK024_Key_Rotation_and_Lifecycle_Management

    AppendRaw(serialized, epoch); // TSK024_Key_Rotation_and_Lifecycle_Management

    auto pqc_blob = kem_blob; // TSK024_Key_Rotation_and_Lifecycle_Management
    pqc_blob.type =
        ToLittleEndian16(kTlvTypePqcKem); // TSK024_Key_Rotation_and_Lifecycle_Management
    pqc_blob.length = ToLittleEndian16(
        static_cast<uint16_t>(sizeof(qv::core::PQC_KEM_TLV) - sizeof(uint16_t) * 2));
    pqc_blob.version =
        ToLittleEndian16(pqc_blob.version); // TSK024_Key_Rotation_and_Lifecycle_Management
    pqc_blob.kem_id =
        ToLittleEndian16(pqc_blob.kem_id); // TSK024_Key_Rotation_and_Lifecycle_Management
    AppendRaw(serialized, pqc_blob);       // TSK024_Key_Rotation_and_Lifecycle_Management

    if (reserved.length > 0) {                         // TSK033 only emit when present
      auto reserved_copy = reserved;                   // TSK024_Key_Rotation_and_Lifecycle_Management
      uint16_t reserved_length = reserved_copy.length; // TSK033 clamp payload
      if (reserved_length > reserved_copy.payload.size()) { // TSK033 clamp payload
        reserved_length = static_cast<uint16_t>(reserved_copy.payload.size());
      }
      reserved_copy.type =
          ToLittleEndian16(kTlvTypeReservedV2); // TSK024_Key_Rotation_and_Lifecycle_Management
      reserved_copy.length =
          ToLittleEndian16(reserved_length); // TSK024_Key_Rotation_and_Lifecycle_Management
      AppendRaw(serialized, reserved_copy);  // TSK024_Key_Rotation_and_Lifecycle_Management
    }

    return serialized; // TSK024_Key_Rotation_and_Lifecycle_Management
  }

  uint32_t DeterminePbkdfIterations(std::span<const uint8_t> password,
                                     const std::array<uint8_t, kPbkdfSaltSize>& salt,
                                     const VolumeManager::KdfPolicy& policy) { // TSK036_PBKDF2_Argon2_Migration_Path
    if (policy.iteration_override) {
      return std::clamp<uint32_t>(*policy.iteration_override, kMinPbkdfIterations, kMaxPbkdfIterations);
    }
    auto baseline = std::max<uint32_t>(kBenchmarkIterations, 1u);
    auto start = std::chrono::steady_clock::now();
    auto sample = DerivePasswordKey(password, salt, baseline);
    auto elapsed = std::chrono::steady_clock::now() - start;
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(sample.data(), sample.size()));
    auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();
    if (elapsed_ns <= 0) {
      return kDefaultPbkdfIterations;
    }
    auto target_ns = std::max<int64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(policy.target_duration).count(), 1);
    long double per_iter_ns = static_cast<long double>(elapsed_ns) / static_cast<long double>(baseline);
    if (per_iter_ns <= 0.0L) {
      return kDefaultPbkdfIterations;
    }
    auto computed = static_cast<uint64_t>(static_cast<long double>(target_ns) / per_iter_ns);
    if (computed == 0) {
      computed = kMinPbkdfIterations;
    }
    computed = std::clamp<uint64_t>(computed, kMinPbkdfIterations, kMaxPbkdfIterations);
    return static_cast<uint32_t>(computed);
  }

  ParsedHeader
  ParseHeader(const std::vector<uint8_t>& blob) { // TSK024_Key_Rotation_and_Lifecycle_Management
    if (blob.size() <
        sizeof(VolumeHeader) +
            qv::crypto::HMAC_SHA256::TAG_SIZE) { // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Invalid container header"};
    }

    ParsedHeader parsed{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::memcpy(&parsed.header, blob.data(),
                sizeof(VolumeHeader)); // TSK024_Key_Rotation_and_Lifecycle_Management
    parsed.header_version =
        qv::ToLittleEndian(parsed.header.version); // TSK024_Key_Rotation_and_Lifecycle_Management
    if (parsed.header.magic != kVolumeMagic) {     // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Unrecognized volume magic"};
    }

    const size_t mac_size =
        qv::crypto::HMAC_SHA256::TAG_SIZE; // TSK024_Key_Rotation_and_Lifecycle_Management
    const size_t payload_size =
        blob.size() - mac_size; // TSK024_Key_Rotation_and_Lifecycle_Management
    parsed.payload.assign(
        blob.begin(), blob.begin() + payload_size); // TSK024_Key_Rotation_and_Lifecycle_Management
    std::copy(blob.begin() + payload_size, blob.end(),
              parsed.mac.begin()); // TSK024_Key_Rotation_and_Lifecycle_Management

    size_t offset = sizeof(VolumeHeader); // TSK024_Key_Rotation_and_Lifecycle_Management
    bool have_pbkdf = false;
    bool have_hybrid = false;
    bool have_epoch = false;
    bool have_pqc = false;

    while (offset < payload_size) {
      if (payload_size - offset < sizeof(uint16_t) * 2) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Volume header truncated"};
      }
      uint16_t type_le = 0;
      uint16_t length_le = 0;
      std::memcpy(&type_le, parsed.payload.data() + offset, sizeof(type_le));
      std::memcpy(&length_le, parsed.payload.data() + offset + sizeof(uint16_t), sizeof(length_le));
      const uint16_t type = ToLittleEndian16(type_le);
      const uint16_t length = ToLittleEndian16(length_le);
      const size_t value_offset = offset + sizeof(uint16_t) * 2;
      if (value_offset + length > payload_size) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Volume header truncated"};
      }

      const uint8_t* value = parsed.payload.data() + value_offset;

      switch (type) {
      case kTlvTypePbkdf2: {
        if (length < sizeof(uint32_t)) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "PBKDF2 TLV malformed"};
        }
        std::memcpy(&parsed.pbkdf_iterations, value, sizeof(parsed.pbkdf_iterations));
        parsed.pbkdf_iterations =
            qv::ToLittleEndian(parsed.pbkdf_iterations); // TSK024_Key_Rotation_and_Lifecycle_Management
        const size_t salt_bytes = length - sizeof(uint32_t);
        if (salt_bytes != parsed.pbkdf_salt.size()) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "PBKDF2 salt length unexpected"};
        }
        std::memcpy(parsed.pbkdf_salt.data(), value + sizeof(uint32_t), salt_bytes);
        have_pbkdf = true;
        parsed.algorithm = PasswordKdf::kPbkdf2; // TSK036_PBKDF2_Argon2_Migration_Path
        break;
      }
      case kTlvTypeArgon2: { // TSK036_PBKDF2_Argon2_Migration_Path
        constexpr size_t kExpectedLength = sizeof(uint32_t) * 6 + kPbkdfSaltSize;
        if (length != kExpectedLength) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Argon2 TLV malformed"};
        }
        Argon2Config cfg{};
        std::memcpy(&cfg.version, value, sizeof(cfg.version));
        std::memcpy(&cfg.time_cost, value + sizeof(uint32_t), sizeof(cfg.time_cost));
        std::memcpy(&cfg.memory_cost_kib, value + sizeof(uint32_t) * 2, sizeof(cfg.memory_cost_kib));
        std::memcpy(&cfg.parallelism, value + sizeof(uint32_t) * 3, sizeof(cfg.parallelism));
        std::memcpy(&cfg.hash_length, value + sizeof(uint32_t) * 4, sizeof(cfg.hash_length));
        std::memcpy(&cfg.target_ms, value + sizeof(uint32_t) * 5, sizeof(cfg.target_ms));
        cfg.version = qv::ToLittleEndian(cfg.version);
        cfg.time_cost = qv::ToLittleEndian(cfg.time_cost);
        cfg.memory_cost_kib = qv::ToLittleEndian(cfg.memory_cost_kib);
        cfg.parallelism = qv::ToLittleEndian(cfg.parallelism);
        cfg.hash_length = qv::ToLittleEndian(cfg.hash_length);
        cfg.target_ms = qv::ToLittleEndian(cfg.target_ms);
        std::memcpy(cfg.salt.data(), value + sizeof(uint32_t) * 6, cfg.salt.size());
        parsed.argon2 = cfg;
        parsed.have_argon2 = true;
        parsed.algorithm = PasswordKdf::kArgon2id;
        std::copy(cfg.salt.begin(), cfg.salt.end(), parsed.pbkdf_salt.begin());
        break;
      }
      case kTlvTypeHybridSalt: {
        if (length != parsed.hybrid_salt.size()) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Hybrid salt TLV malformed"};
        }
        std::memcpy(parsed.hybrid_salt.data(), value, parsed.hybrid_salt.size());
        have_hybrid = true;
        break;
      }
      case kTlvTypeEpoch: {
        if (length != sizeof(parsed.epoch_tlv.epoch)) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Epoch TLV malformed"};
        }
        parsed.epoch_tlv.type = ToLittleEndian16(kTlvTypeEpoch);
        parsed.epoch_tlv.length = qv::ToLittleEndian(static_cast<uint16_t>(length));
        std::memcpy(&parsed.epoch_tlv.epoch, value, sizeof(parsed.epoch_tlv.epoch));
        parsed.epoch_value = qv::ToLittleEndian(parsed.epoch_tlv.epoch);
        have_epoch = true;
        break;
      }
      case kTlvTypePqcKem: {
        if (length != sizeof(qv::core::PQC_KEM_TLV) - sizeof(uint16_t) * 2) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "PQC TLV malformed"};
        }
        parsed.kem_blob.type = ToLittleEndian16(kTlvTypePqcKem);
        parsed.kem_blob.length =
            ToLittleEndian16(static_cast<uint16_t>(length)); // TSK024_Key_Rotation_and_Lifecycle_Management
        std::memcpy(reinterpret_cast<uint8_t*>(&parsed.kem_blob) + sizeof(uint16_t) * 2, value,
                    length);
        parsed.kem_blob.version =
            ToLittleEndian16(parsed.kem_blob.version); // TSK024_Key_Rotation_and_Lifecycle_Management
        parsed.kem_blob.kem_id =
            ToLittleEndian16(parsed.kem_blob.kem_id); // TSK024_Key_Rotation_and_Lifecycle_Management
        have_pqc = true;
        break;
      }
      case kTlvTypeReservedV2: {
        if (length > parsed.reserved_v2.payload.size()) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Reserved TLV malformed"};
        }
        parsed.reserved_v2_present = length > 0;
        parsed.reserved_v2.type = ToLittleEndian16(kTlvTypeReservedV2);
        parsed.reserved_v2.length = static_cast<uint16_t>(length);
        std::fill(parsed.reserved_v2.payload.begin(), parsed.reserved_v2.payload.end(), 0);
        if (length > 0) {
          std::memcpy(parsed.reserved_v2.payload.data(), value, length);
        }
        break;
      }
      default:
        // TSK033 readers must skip unknown TLV types for forward compatibility
        break;
      }

      offset = value_offset + length;
    }

    if (offset != payload_size) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Unexpected trailing bytes in header"};
    }
    if ((!have_pbkdf && !parsed.have_argon2) || !have_hybrid || !have_epoch || !have_pqc) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Required TLV missing"};
    }

    return parsed; // TSK024_Key_Rotation_and_Lifecycle_Management
  }

  std::filesystem::path MetadataDirFor(
      const std::filesystem::path& container) { // TSK024_Key_Rotation_and_Lifecycle_Management
    auto parent = container.parent_path();      // TSK024_Key_Rotation_and_Lifecycle_Management
    auto name = container.filename().string();  // TSK024_Key_Rotation_and_Lifecycle_Management
    if (name.empty()) {                         // TSK024_Key_Rotation_and_Lifecycle_Management
      name = "volume";                          // TSK024_Key_Rotation_and_Lifecycle_Management
    }
    return parent / (name + ".meta"); // TSK024_Key_Rotation_and_Lifecycle_Management
  }

#pragma pack(push, 1)
  struct KeyBackupRecord { // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<char, 8> magic{'Q', 'V', 'B',  'A',
                              'C', 'K', '\0', '\0'}; // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t version =
        qv::ToLittleEndian(0x00010000u); // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 16> uuid{};      // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t epoch{0};                   // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::core::PQC::CIPHERTEXT_SIZE>
        kem_ct{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>
        nonce{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>
        tag{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, sizeof(DerivedKeyset)>
        encrypted_keys{}; // TSK024_Key_Rotation_and_Lifecycle_Management
  };
#pragma pack(pop)

  std::optional<std::filesystem::path>
  PerformKeyBackup(const std::filesystem::path& container, uint32_t epoch,
                   const std::array<uint8_t, 16>& uuid, DerivedKeyset& keyset,
                   const std::filesystem::path&
                       backup_public_key) { // TSK024_Key_Rotation_and_Lifecycle_Management
    std::ifstream in(backup_public_key,
                     std::ios::binary); // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!in) {                          // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;            // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to open backup key: " + backup_public_key.string()};
    }
    std::vector<uint8_t> pk_bytes((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());
    VectorWipeGuard pk_guard(pk_bytes); // TSK028_Secure_Deletion_and_Data_Remanence
    if (pk_bytes.size() !=
        qv::core::PQC::PUBLIC_KEY_SIZE) { // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Backup key size mismatch"};
    }
    std::array<uint8_t, qv::core::PQC::PUBLIC_KEY_SIZE>
        pk{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::copy(pk_bytes.begin(), pk_bytes.end(),
              pk.begin()); // TSK024_Key_Rotation_and_Lifecycle_Management

    qv::core::PQCKeyEncapsulation kem; // TSK024_Key_Rotation_and_Lifecycle_Management
    auto enc = kem.Encapsulate(pk);    // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::security::Zeroizer::ScopeWiper secret_guard(enc.shared_secret.data(),
                                                    enc.shared_secret.size());

    std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>
        nonce{};       // TSK024_Key_Rotation_and_Lifecycle_Management
    FillRandom(nonce); // TSK024_Key_Rotation_and_Lifecycle_Management

    static constexpr std::string_view kBackupContext{
        "QV-BACKUP/v1"};            // TSK024_Key_Rotation_and_Lifecycle_Management
    std::vector<uint8_t> aad;       // TSK024_Key_Rotation_and_Lifecycle_Management
    VectorWipeGuard aad_guard(aad); // TSK028_Secure_Deletion_and_Data_Remanence
    aad.insert(aad.end(), kBackupContext.begin(),
               kBackupContext.end());                // TSK024_Key_Rotation_and_Lifecycle_Management
    aad.insert(aad.end(), uuid.begin(), uuid.end()); // TSK024_Key_Rotation_and_Lifecycle_Management
    const uint32_t epoch_le =
        qv::ToLittleEndian(epoch); // TSK024_Key_Rotation_and_Lifecycle_Management
    const uint8_t* epoch_bytes =
        reinterpret_cast<const uint8_t*>(&epoch_le); // TSK024_Key_Rotation_and_Lifecycle_Management
    aad.insert(aad.end(), epoch_bytes,
               epoch_bytes + sizeof(epoch_le)); // TSK024_Key_Rotation_and_Lifecycle_Management

    auto keyset_bytes = qv::AsBytesConst(keyset); // TSK024_Key_Rotation_and_Lifecycle_Management
    auto enc_result =
        qv::crypto::AES256_GCM_Encrypt( // TSK024_Key_Rotation_and_Lifecycle_Management
            keyset_bytes, std::span<const uint8_t>(aad.data(), aad.size()),
            std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce.data(),
                                                                         nonce.size()),
            std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(enc.shared_secret.data(),
                                                                       enc.shared_secret.size()));
    VectorWipeGuard ciphertext_guard(
        enc_result.ciphertext); // TSK028_Secure_Deletion_and_Data_Remanence
    qv::security::Zeroizer::ScopeWiper tag_guard(enc_result.tag.data(), enc_result.tag.size());
    if (enc_result.ciphertext.size() !=
        sizeof(DerivedKeyset)) { // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Crypto, 0, "Unexpected backup ciphertext length"};
    }

    KeyBackupRecord record{};                 // TSK024_Key_Rotation_and_Lifecycle_Management
    record.uuid = uuid;                       // TSK024_Key_Rotation_and_Lifecycle_Management
    record.epoch = qv::ToLittleEndian(epoch); // TSK024_Key_Rotation_and_Lifecycle_Management
    record.kem_ct = enc.ciphertext;           // TSK024_Key_Rotation_and_Lifecycle_Management
    record.nonce = nonce;                     // TSK024_Key_Rotation_and_Lifecycle_Management
    record.tag = enc_result.tag;              // TSK024_Key_Rotation_and_Lifecycle_Management
    std::copy(enc_result.ciphertext.begin(),
              enc_result.ciphertext.end(), // TSK024_Key_Rotation_and_Lifecycle_Management
              record.encrypted_keys.begin());

    auto metadata_dir = MetadataDirFor(container); // TSK024_Key_Rotation_and_Lifecycle_Management
    std::filesystem::create_directories(
        metadata_dir);                // TSK024_Key_Rotation_and_Lifecycle_Management
    auto backup_path = metadata_dir / // TSK024_Key_Rotation_and_Lifecycle_Management
                       ("key_backup.epoch_" + std::to_string(epoch) +
                        ".bin"); // TSK024_Key_Rotation_and_Lifecycle_Management

    std::ofstream out(backup_path,
                      std::ios::binary |
                          std::ios::trunc); // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!out) {                             // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;                // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to write backup file: " + backup_path.string()};
    }
    out.write(reinterpret_cast<const char*>(&record),
              sizeof(record)); // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!out) {                // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;   // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to persist backup file: " + backup_path.string()};
    }

    qv::security::Zeroizer::Wipe(
        std::span<uint8_t>(enc.shared_secret.data(), enc.shared_secret.size()));
    qv::security::Zeroizer::Wipe(
        std::span<uint8_t>(enc_result.ciphertext.data(), enc_result.ciphertext.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(aad.data(), aad.size()));

    return backup_path; // TSK024_Key_Rotation_and_Lifecycle_Management
  }
} // namespace

VolumeManager::VolumeManager() { // TSK036_PBKDF2_Argon2_Migration_Path
#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2
  kdf_policy_.algorithm = PasswordKdf::kArgon2id;
#else
  kdf_policy_.algorithm = PasswordKdf::kPbkdf2;
#endif
  kdf_policy_.target_duration = kDefaultTargetDuration;
}

VolumeManager::VolumeManager(KdfPolicy policy) : kdf_policy_(policy) { // TSK036_PBKDF2_Argon2_Migration_Path
  if (kdf_policy_.target_duration.count() <= 0) {
    kdf_policy_.target_duration = kDefaultTargetDuration;
  }
}

void VolumeManager::SetKdfPolicy(const KdfPolicy& policy) { // TSK036_PBKDF2_Argon2_Migration_Path
  kdf_policy_ = policy;
  if (kdf_policy_.target_duration.count() <= 0) {
    kdf_policy_.target_duration = kDefaultTargetDuration;
  }
}

const VolumeManager::KdfPolicy& VolumeManager::GetKdfPolicy() const { // TSK036_PBKDF2_Argon2_Migration_Path
  return kdf_policy_;
}

VolumeManager::ChunkEncryptionResult VolumeManager::EncryptChunk(
    std::span<const uint8_t> plaintext, uint32_t epoch, int64_t chunk_index,
    uint64_t logical_offset, uint32_t chunk_size, qv::core::NonceGenerator& nonce_gen,
    std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE> data_key) { // TSK040_AAD_Binding_and_Chunk_Authentication
  auto nonce_record = nonce_gen.NextAuthenticated();                       // TSK040
  auto envelope = qv::core::MakeChunkAAD(epoch, chunk_index, logical_offset,
                                         chunk_size, nonce_record.mac);     // TSK040
  auto enc_result = qv::crypto::AES256_GCM_Encrypt(                         // TSK040
      plaintext, qv::AsBytesConst(envelope),
      std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(
          nonce_record.nonce.data(), nonce_record.nonce.size()),
      data_key);

  ChunkEncryptionResult sealed{};                                           // TSK040
  sealed.nonce = nonce_record.nonce;                                        // TSK040
  sealed.tag = enc_result.tag;                                              // TSK040
  sealed.nonce_chain_mac = nonce_record.mac;                                // TSK040
  sealed.ciphertext = std::move(enc_result.ciphertext);                     // TSK040
  return sealed;                                                            // TSK040
}

std::vector<uint8_t> VolumeManager::DecryptChunk(
    const ChunkEncryptionResult& sealed_chunk, uint32_t epoch, int64_t chunk_index,
    uint64_t logical_offset, uint32_t chunk_size,
    std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE> data_key) { // TSK040_AAD_Binding_and_Chunk_Authentication
  auto envelope = qv::core::MakeChunkAAD(epoch, chunk_index, logical_offset,
                                         chunk_size, sealed_chunk.nonce_chain_mac); // TSK040
  return qv::crypto::AES256_GCM_Decrypt(                                            // TSK040
      std::span<const uint8_t>(sealed_chunk.ciphertext.data(), sealed_chunk.ciphertext.size()),
      qv::AsBytesConst(envelope),
      std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(sealed_chunk.nonce.data(),
                                                                   sealed_chunk.nonce.size()),
      std::span<const uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>(sealed_chunk.tag.data(),
                                                                 sealed_chunk.tag.size()),
      data_key);
}

QV_SENSITIVE_BEGIN
QV_SENSITIVE_FUNCTION std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Create(const std::filesystem::path& container, const std::string& password) {
  if (std::filesystem::exists(container)) {
    throw qv::Error{qv::ErrorDomain::Validation,
                    qv::errors::validation::kVolumeExists, // TSK020
                    "Container already exists: " + container.string()};
  }

  if (container.has_parent_path()) {
    std::filesystem::create_directories(container.parent_path());
  }

  VolumeHeader header{}; // TSK013
  header.uuid = GenerateUuidV4();

  std::array<uint8_t, kPbkdfSaltSize> password_salt{};
  FillRandom(password_salt);

  std::array<uint8_t, kHybridSaltSize> hybrid_salt{};
  FillRandom(hybrid_salt);

  std::vector<uint8_t> password_bytes(password.begin(), password.end());
  VectorWipeGuard password_guard(password_bytes); // TSK028_Secure_Deletion_and_Data_Remanence, TSK028A_Memory_Wiping_Gaps
  std::optional<Argon2Config> argon2_config; // TSK036_PBKDF2_Argon2_Migration_Path
  uint32_t pbkdf_iterations = 0;             // TSK036_PBKDF2_Argon2_Migration_Path
  std::array<uint8_t, 32> classical_key{};   // TSK036_PBKDF2_Argon2_Migration_Path
  std::span<const uint8_t> password_span(password_bytes.data(), password_bytes.size());
  const auto wipe_password_bytes = [&]() noexcept {
    if (!password_bytes.empty()) {
      qv::security::Zeroizer::Wipe(
          std::span<uint8_t>(password_bytes.data(), password_bytes.size()));  // TSK028A_Memory_Wiping_Gaps
      password_bytes.clear();
    }
  };
  try {
    if (kdf_policy_.algorithm == PasswordKdf::kArgon2id) {
      Argon2Config cfg{};
      cfg.target_ms = static_cast<uint32_t>(kdf_policy_.target_duration.count());
      std::copy(password_salt.begin(), password_salt.end(), cfg.salt.begin());
      classical_key = DerivePasswordKeyArgon2id(password_span, cfg);
      argon2_config = cfg;
    } else {
      pbkdf_iterations = DeterminePbkdfIterations(password_span, password_salt, kdf_policy_);
      classical_key = DerivePasswordKey(password_span, password_salt, pbkdf_iterations, kdf_policy_.progress);
    }
    wipe_password_bytes();
  } catch (...) {
    wipe_password_bytes();
    throw;
  }
  qv::security::Zeroizer::ScopeWiper classical_guard(classical_key.data(), classical_key.size());

  qv::core::EpochTLV epoch{};
  epoch.type = ToLittleEndian16(kTlvTypeEpoch);
  epoch.length = ToLittleEndian16(static_cast<uint16_t>(sizeof(epoch.epoch)));
  epoch.epoch = qv::ToLittleEndian(static_cast<uint32_t>(1));
  const auto epoch_bytes = qv::AsBytesConst(epoch);

  auto creation = qv::core::PQCHybridKDF::Create(
      std::span<const uint8_t, 32>(classical_key),
      std::span<const uint8_t>(hybrid_salt.data(), hybrid_salt.size()),
      std::span<const uint8_t, 16>(header.uuid), kHeaderVersion, epoch_bytes);
  qv::security::Zeroizer::ScopeWiper creation_guard(creation.hybrid_key.data(),
                                                    creation.hybrid_key.size());

  auto mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()),
      header.uuid); // TSK024_Key_Rotation_and_Lifecycle_Management
  qv::security::Zeroizer::ScopeWiper mac_guard(
      mac_key.data(), mac_key.size()); // TSK028_Secure_Deletion_and_Data_Remanence

  ReservedV2Tlv reserved_v2{};
  auto payload = SerializeHeaderPayload(
      header, kdf_policy_.algorithm, pbkdf_iterations, password_salt, argon2_config, hybrid_salt,
      epoch, creation.kem_blob,
      reserved_v2); // TSK024_Key_Rotation_and_Lifecycle_Management

  auto mac =
      qv::crypto::HMAC_SHA256::Compute(std::span<const uint8_t>(mac_key.data(), mac_key.size()),
                                       std::span<const uint8_t>(payload.data(), payload.size()));
  payload.insert(payload.end(), mac.begin(), mac.end());

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(creation.hybrid_key.data(), creation.hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  try {
    AtomicReplace(container, std::span<const uint8_t>(payload.data(), payload.size()));
  } catch (const qv::Error& err) {
    throw qv::Error{err.domain(), err.code(),
                    "Failed to finalize container header update"}; // TSK068_Atomic_Header_Writes uniform messaging
  }

  qv::orchestrator::Event created{}; // TSK029
  created.category = EventCategory::kLifecycle;
  created.severity = EventSeverity::kInfo;
  created.event_id = "volume_created";
  created.message = "New encrypted volume created";
  created.fields.emplace_back("container", qv::PathToUtf8String(container), FieldPrivacy::kRedact);
  created.fields.emplace_back("uuid", FormatUuid(header.uuid), FieldPrivacy::kPublic);
  if (kdf_policy_.algorithm == PasswordKdf::kPbkdf2) {
    created.fields.emplace_back("pbkdf_iterations", std::to_string(pbkdf_iterations),
                                FieldPrivacy::kPublic, true);
  } else {
    created.fields.emplace_back("kdf", "argon2id", FieldPrivacy::kPublic, true);
    created.fields.emplace_back("argon2_memory_kib", std::to_string(argon2_config->memory_cost_kib),
                                FieldPrivacy::kPublic, true);
  }
  qv::orchestrator::EventBus::Instance().Publish(created);

  ConstantTimeMount::VolumeHandle handle{};
  handle.dummy = 1;
  return handle;
}
QV_SENSITIVE_END

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Mount(const std::filesystem::path& container, const std::string& password) {
  auto handle = ctm_.Mount(container, password); // TSK029
  if (handle) {
    qv::orchestrator::Event mounted{}; // TSK029
    mounted.category = EventCategory::kLifecycle;
    mounted.severity = EventSeverity::kInfo;
    mounted.event_id = "volume_mounted";
    mounted.message = "Encrypted volume mounted";
    mounted.fields.emplace_back("container", qv::PathToUtf8String(container),
                                FieldPrivacy::kRedact);
    qv::orchestrator::EventBus::Instance().Publish(mounted);
  }
  return handle;
}

QV_SENSITIVE_BEGIN
QV_SENSITIVE_FUNCTION std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Rekey(const std::filesystem::path& container, const std::string& current_password,
                     const std::string& new_password,
                     std::optional<std::filesystem::path> backup_public_key) {
  if (!std::filesystem::exists(container)) { // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::IO, qv::errors::io::kContainerMissing,
                    "Container not found: " + container.string()};
  }

  qv::orchestrator::Event initiated{}; // TSK029
  initiated.category = EventCategory::kLifecycle;
  initiated.severity = EventSeverity::kInfo;
  initiated.event_id = "rekey_initiated";
  initiated.message = "Volume rekey operation started";
  initiated.fields.emplace_back("container", qv::PathToUtf8String(container),
                                FieldPrivacy::kRedact);
  qv::orchestrator::EventBus::Instance().Publish(initiated);

  std::ifstream in(container, std::ios::binary); // TSK024_Key_Rotation_and_Lifecycle_Management
  if (!in) {                                     // TSK024_Key_Rotation_and_Lifecycle_Management
    const int err = errno;                       // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open container for rekey: " + container.string()};
  }

  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto parsed = ParseHeader(blob); // TSK024_Key_Rotation_and_Lifecycle_Management

  std::vector<uint8_t> current_bytes(current_password.begin(), current_password.end());
  VectorWipeGuard current_guard(current_bytes); // TSK028_Secure_Deletion_and_Data_Remanence
  std::array<uint8_t, 32> classical_key{}; // TSK036_PBKDF2_Argon2_Migration_Path
  std::span<const uint8_t> current_span(current_bytes.data(), current_bytes.size());
  if (parsed.algorithm == PasswordKdf::kArgon2id) {
    classical_key = DerivePasswordKeyArgon2id(current_span, parsed.argon2);
  } else {
    classical_key = DerivePasswordKey(current_span, parsed.pbkdf_salt, parsed.pbkdf_iterations);
  }
  qv::security::Zeroizer::ScopeWiper classical_guard(classical_key.data(), classical_key.size());
  if (!current_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(current_bytes.data(), current_bytes.size()));
  }

  auto hybrid_key = qv::core::PQCHybridKDF::Mount(
      std::span<const uint8_t, 32>(classical_key.data(), classical_key.size()), parsed.kem_blob,
      std::span<const uint8_t>(parsed.hybrid_salt.data(), parsed.hybrid_salt.size()),
      std::span<const uint8_t, 16>(parsed.header.uuid), parsed.header_version,
      qv::AsBytesConst(parsed.epoch_tlv)); // TSK024_Key_Rotation_and_Lifecycle_Management
  qv::security::Zeroizer::ScopeWiper hybrid_guard(hybrid_key.data(), hybrid_key.size());

  auto mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(hybrid_key.data(), hybrid_key.size()), parsed.header.uuid);
  qv::security::Zeroizer::ScopeWiper mac_guard(mac_key.data(), mac_key.size());

  auto expected_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(parsed.payload.data(), parsed.payload.size()));

  if (expected_mac != parsed.mac) { // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::AuthenticationFailureError("Header authentication failed");
  }

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  if (parsed.epoch_value ==
      std::numeric_limits<uint32_t>::max()) { // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    throw qv::Error{qv::ErrorDomain::State, 0, "Epoch counter overflow"};
  }

  const uint32_t old_epoch = parsed.epoch_value; // TSK024_Key_Rotation_and_Lifecycle_Management
  const uint32_t new_epoch = old_epoch + 1;      // TSK024_Key_Rotation_and_Lifecycle_Management

  std::array<uint8_t, kPbkdfSaltSize>
      new_password_salt{}; // TSK036_PBKDF2_Argon2_Migration_Path
  std::array<uint8_t, kHybridSaltSize>
      new_hybrid_salt{}; // TSK024_Key_Rotation_and_Lifecycle_Management
  FillRandom(new_password_salt);
  FillRandom(new_hybrid_salt);

  std::vector<uint8_t> new_bytes(new_password.begin(), new_password.end());
  VectorWipeGuard new_guard(new_bytes); // TSK028_Secure_Deletion_and_Data_Remanence
  std::optional<Argon2Config> new_argon2; // TSK036_PBKDF2_Argon2_Migration_Path
  uint32_t new_iterations = 0;            // TSK036_PBKDF2_Argon2_Migration_Path
  std::array<uint8_t, 32> new_classical_key{};
  std::span<const uint8_t> new_span(new_bytes.data(), new_bytes.size());
  if (kdf_policy_.algorithm == PasswordKdf::kArgon2id) {
    Argon2Config cfg{};
    cfg.target_ms = static_cast<uint32_t>(kdf_policy_.target_duration.count());
    std::copy(new_password_salt.begin(), new_password_salt.end(), cfg.salt.begin());
    new_classical_key = DerivePasswordKeyArgon2id(new_span, cfg);
    new_argon2 = cfg;
  } else {
    new_iterations = DeterminePbkdfIterations(new_span, new_password_salt, kdf_policy_);
    new_classical_key = DerivePasswordKey(new_span, new_password_salt, new_iterations, kdf_policy_.progress);
  }
  qv::security::Zeroizer::ScopeWiper new_classical_guard(new_classical_key.data(),
                                                         new_classical_key.size());
  if (!new_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(new_bytes.data(), new_bytes.size()));
  }

  auto new_epoch_tlv =
      qv::core::MakeEpochTlv(new_epoch); // TSK024_Key_Rotation_and_Lifecycle_Management
  auto creation = qv::core::PQCHybridKDF::Create(
      std::span<const uint8_t, 32>(new_classical_key.data(), new_classical_key.size()),
      std::span<const uint8_t>(new_hybrid_salt.data(), new_hybrid_salt.size()),
      std::span<const uint8_t, 16>(parsed.header.uuid), parsed.header_version,
      qv::AsBytesConst(new_epoch_tlv));
  qv::security::Zeroizer::ScopeWiper creation_guard(creation.hybrid_key.data(),
                                                    creation.hybrid_key.size());

  auto new_mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()),
      parsed.header.uuid);
  qv::security::Zeroizer::ScopeWiper new_mac_guard(new_mac_key.data(), new_mac_key.size());

  auto derived_keys = MakeDerivedKeyset(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()));
  qv::security::Zeroizer::ScopeWiper derived_data_guard(derived_keys.data.data(),
                                                        derived_keys.data.size());
  qv::security::Zeroizer::ScopeWiper derived_metadata_guard(derived_keys.metadata.data(),
                                                            derived_keys.metadata.size());
  qv::security::Zeroizer::ScopeWiper derived_index_guard(derived_keys.index.data(),
                                                         derived_keys.index.size());

  auto payload = SerializeHeaderPayload(parsed.header, kdf_policy_.algorithm, new_iterations,
                                        new_password_salt, new_argon2, new_hybrid_salt,
                                        new_epoch_tlv, creation.kem_blob,
                                        parsed.reserved_v2); // TSK024_Key_Rotation_and_Lifecycle_Management

  auto new_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(new_mac_key.data(), new_mac_key.size()),
      std::span<const uint8_t>(payload.data(), payload.size()));
  payload.insert(payload.end(), new_mac.begin(), new_mac.end());

  if (payload.size() !=
      parsed.payload.size() + parsed.mac.size()) { // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::Internal, 0, "Header size changed unexpectedly"};
  }

  try {
    AtomicReplace(container, std::span<const uint8_t>(payload.data(), payload.size()));
  } catch (const qv::Error& err) {
    throw qv::Error{err.domain(), err.code(),
                    "Failed to finalize container header update"}; // TSK068_Atomic_Header_Writes uniform messaging
  }

  std::optional<std::filesystem::path> backup_path; // TSK024_Key_Rotation_and_Lifecycle_Management
  if (backup_public_key) {
    backup_path = PerformKeyBackup(container, new_epoch, parsed.header.uuid, derived_keys,
                                   *backup_public_key);
  }

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(new_classical_key.data(), new_classical_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(creation.hybrid_key.data(), creation.hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(new_mac_key.data(), new_mac_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(derived_keys.data.data(), derived_keys.data.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(derived_keys.metadata.data(), derived_keys.metadata.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(derived_keys.index.data(), derived_keys.index.size()));

  qv::orchestrator::Event event{}; // TSK024_Key_Rotation_and_Lifecycle_Management
  event.category = EventCategory::kSecurity;
  event.severity = EventSeverity::kInfo;
  event.event_id = "volume_rekeyed";
  event.message = "Volume encryption keys rotated";
  event.fields.emplace_back("container", qv::PathToUtf8String(container), FieldPrivacy::kRedact);
  event.fields.emplace_back("old_epoch", std::to_string(old_epoch), FieldPrivacy::kPublic, true);
  event.fields.emplace_back("new_epoch", std::to_string(new_epoch), FieldPrivacy::kPublic, true);
  if (kdf_policy_.algorithm == PasswordKdf::kPbkdf2) {
    event.fields.emplace_back("pbkdf_iterations", std::to_string(new_iterations), FieldPrivacy::kPublic, true);
  } else {
    event.fields.emplace_back("kdf", "argon2id", FieldPrivacy::kPublic, true);
    if (new_argon2) {
      event.fields.emplace_back("argon2_memory_kib", std::to_string(new_argon2->memory_cost_kib),
                                FieldPrivacy::kPublic, true);
    }
  }
  event.fields.emplace_back("key_material_destroyed", "true", FieldPrivacy::kPublic);
  if (backup_public_key) {
    event.fields.emplace_back("backup_escrow",
                              backup_path ? qv::PathToUtf8String(*backup_path)
                                          : qv::PathToUtf8String(*backup_public_key),
                              FieldPrivacy::kRedact);
  }
  qv::orchestrator::EventBus::Instance().Publish(event);

  ConstantTimeMount::VolumeHandle handle{}; // TSK024_Key_Rotation_and_Lifecycle_Management
  handle.dummy = 1; // TSK024_Key_Rotation_and_Lifecycle_Management
  return handle; // TSK024_Key_Rotation_and_Lifecycle_Management
}
QV_SENSITIVE_END

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Migrate(const std::filesystem::path& container, uint32_t target_version,
                       const std::string& password) { // TSK033
  if (!std::filesystem::exists(container)) { // TSK033
    throw qv::Error{qv::ErrorDomain::IO, qv::errors::io::kContainerMissing,
                    "Container not found: " + container.string()};
  }

  if (target_version == 0) { // TSK033 treat zero as request for latest
    target_version = VolumeManager::kLatestHeaderVersion;
  }

  std::ifstream in(container, std::ios::binary); // TSK033
  if (!in) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open container for migration: " + container.string()};
  }
  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto parsed = ParseHeader(blob); // TSK033 reuse validated parser

  std::vector<uint8_t> password_bytes(password.begin(), password.end());
  VectorWipeGuard password_guard(password_bytes); // TSK028_Secure_Deletion_and_Data_Remanence
  std::array<uint8_t, 32> classical_key{}; // TSK036_PBKDF2_Argon2_Migration_Path
  std::span<const uint8_t> password_span(password_bytes.data(), password_bytes.size());
  if (parsed.algorithm == PasswordKdf::kArgon2id) {
    classical_key = DerivePasswordKeyArgon2id(password_span, parsed.argon2);
  } else {
    classical_key = DerivePasswordKey(password_span, parsed.pbkdf_salt, parsed.pbkdf_iterations);
  }
  qv::security::Zeroizer::ScopeWiper classical_guard(classical_key.data(), classical_key.size());
  if (!password_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(password_bytes.data(), password_bytes.size()));
  }

  auto hybrid_key = qv::core::PQCHybridKDF::Mount(
      std::span<const uint8_t, 32>(classical_key.data(), classical_key.size()), parsed.kem_blob,
      std::span<const uint8_t>(parsed.hybrid_salt.data(), parsed.hybrid_salt.size()),
      std::span<const uint8_t, 16>(parsed.header.uuid), parsed.header_version,
      qv::AsBytesConst(parsed.epoch_tlv)); // TSK033 authenticate existing header state
  qv::security::Zeroizer::ScopeWiper hybrid_guard(hybrid_key.data(), hybrid_key.size());

  auto mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(hybrid_key.data(), hybrid_key.size()), parsed.header.uuid); // TSK033
  qv::security::Zeroizer::ScopeWiper mac_guard(mac_key.data(), mac_key.size());

  auto expected_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(parsed.payload.data(), parsed.payload.size()));
  if (expected_mac != parsed.mac) { // TSK033 enforce password correctness
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::AuthenticationFailureError("Header authentication failed");
  }

  const uint32_t current_version = parsed.header_version; // TSK033
  if (current_version == target_version) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    return std::nullopt;
  }

  if (current_version > target_version) { // TSK033 block downgrades
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Cannot downgrade volume header version"};
  }

  constexpr uint32_t kVersionV4_0 = 0x00040000u; // TSK033 legacy baseline
  if (!(current_version == kVersionV4_0 &&
        target_version == VolumeManager::kLatestHeaderVersion)) { // TSK033 supported path
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{qv::ErrorDomain::Validation, 0, "No migration path available"};
  }

  ReservedV2Tlv reserved = parsed.reserved_v2_present ? parsed.reserved_v2 : ReservedV2Tlv{}; // TSK033
  if (!parsed.reserved_v2_present) { // TSK033 add ACL staging TLV for new version
    reserved.length = static_cast<uint16_t>(reserved.payload.size());
  }

  parsed.header.version = qv::ToLittleEndian(target_version); // TSK033 bump version field
  std::optional<Argon2Config> existing_argon2;
  if (parsed.have_argon2) {
    existing_argon2 = parsed.argon2;
  }
  auto payload = SerializeHeaderPayload(parsed.header, parsed.algorithm, parsed.pbkdf_iterations,
                                        parsed.pbkdf_salt, existing_argon2, parsed.hybrid_salt,
                                        parsed.epoch_tlv, parsed.kem_blob,
                                        reserved); // TSK033 rebuild header TLVs
  auto new_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(payload.data(), payload.size()));
  payload.insert(payload.end(), new_mac.begin(), new_mac.end());

  try {
    AtomicReplace(container, std::span<const uint8_t>(payload.data(), payload.size()));
  } catch (const qv::Error& err) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{err.domain(), err.code(),
                    "Failed to finalize container header update"}; // TSK068_Atomic_Header_Writes uniform messaging
  }

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  auto format_version = [](uint32_t version) { // TSK033 helper for diagnostics
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << version;
    return oss.str();
  };

  qv::orchestrator::Event event{}; // TSK033
  event.category = EventCategory::kLifecycle;
  event.severity = EventSeverity::kInfo;
  event.event_id = "volume_migrated";
  event.message = "Volume header format upgraded";
  event.fields.emplace_back("container", qv::PathToUtf8String(container), FieldPrivacy::kRedact);
  event.fields.emplace_back("from_version", format_version(current_version), FieldPrivacy::kPublic,
                            true);
  event.fields.emplace_back("to_version", format_version(target_version), FieldPrivacy::kPublic,
                            true);
  qv::orchestrator::EventBus::Instance().Publish(event);

  ConstantTimeMount::VolumeHandle handle{};
  handle.dummy = 1;
  return handle;
}
