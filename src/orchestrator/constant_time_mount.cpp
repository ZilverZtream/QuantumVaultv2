#include "qv/orchestrator/constant_time_mount.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

#if defined(__SSE2__) || defined(_M_X64) || defined(_M_IX86)
#include <immintrin.h>
#endif

#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/ct.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/security/zeroizer.h"

using namespace qv::orchestrator;

namespace {

// TSK004
constexpr std::array<uint8_t, 8> kHeaderMagic = {'Q','V','C','T','M','T','4','1'};
constexpr uint16_t kHeaderVersion = 0x0401;
constexpr uint32_t kFallbackIterations = 4096;
constexpr uint64_t kMinTargetNs = std::chrono::milliseconds(75).count();
constexpr uint64_t kConfiguredP99Ns = std::chrono::milliseconds(160).count();
constexpr uint64_t kPaddingSlackNs = std::chrono::milliseconds(2).count();
constexpr uint64_t kHistogramBucketNs = 1'000'000; // 1ms buckets
constexpr size_t kHistogramBuckets = 512;
constexpr uint64_t kLogIntervalNs = std::chrono::seconds(2).count();
constexpr uint16_t kPqcTlvType = 0x7051;

#pragma pack(push, 1)
struct HeaderFixed {
  std::array<uint8_t, 8> magic{};
  uint16_t version{};
  uint16_t reserved{};
  uint32_t header_size{};
  uint32_t pbkdf_iterations{};
  std::array<uint8_t, 16> pbkdf_salt{};
  std::array<uint8_t, 32> hybrid_salt{};
};

struct ContainerHeaderWire {
  HeaderFixed fixed;
  qv::core::PQC_KEM_TLV pqc;
  std::array<uint8_t, 32> mac{};
};
#pragma pack(pop)

static_assert(sizeof(ContainerHeaderWire) == sizeof(HeaderFixed) + sizeof(qv::core::PQC_KEM_TLV) + 32);

struct ParsedHeader {
  ContainerHeaderWire header{};
  bool valid{false};
};

struct TimingSnapshot {
  uint64_t target_ns{0};
  uint64_t p95_ns{0};
  uint64_t p99_ns{0};
  uint64_t samples{0};
};

struct TimingState {
  std::atomic<uint64_t> target_ns{120'000'000};
  std::atomic<uint64_t> last_log_ns{0};
  std::mutex mutex;
  std::array<uint64_t, kHistogramBuckets> histogram{};
  uint64_t total_samples{0};
  uint64_t last_p95{0};
  uint64_t last_p99{0};
};

TimingState& GetTimingState() {
  static TimingState state;
  return state;
}

ParsedHeader ParseHeader(const std::array<uint8_t, sizeof(ContainerHeaderWire)>& buf) {
  ParsedHeader result;
  std::memcpy(&result.header, buf.data(), sizeof(ContainerHeaderWire));

  bool magic_ok = qv::crypto::ct::CompareEqual(result.header.fixed.magic, kHeaderMagic);
  bool version_ok = result.header.fixed.version == kHeaderVersion;
  bool size_ok = result.header.fixed.header_size == sizeof(ContainerHeaderWire);
  bool iter_ok = result.header.fixed.pbkdf_iterations > 0 &&
                 result.header.fixed.pbkdf_iterations < (1u << 24);
  bool tlv_ok = result.header.pqc.type == kPqcTlvType &&
                result.header.pqc.length == sizeof(qv::core::PQC_KEM_TLV) - 4;

  if (!magic_ok) {
    result.header.fixed.magic = kHeaderMagic;
  }
  if (!version_ok) {
    result.header.fixed.version = kHeaderVersion;
  }
  if (!size_ok) {
    result.header.fixed.header_size = sizeof(ContainerHeaderWire);
  }
  if (!iter_ok) {
    result.header.fixed.pbkdf_iterations = kFallbackIterations;
  }
  if (!tlv_ok) {
    result.header.pqc.type = kPqcTlvType;
    result.header.pqc.length = sizeof(qv::core::PQC_KEM_TLV) - 4;
    result.header.pqc.kem_ct.fill(0);
    result.header.pqc.sk_nonce.fill(0);
    result.header.pqc.sk_encrypted.fill(0);
    result.header.pqc.sk_tag.fill(0);
    result.header.pqc.reserved.fill(0);
  }
  if (!(magic_ok && version_ok && size_ok && iter_ok && tlv_ok)) {
    result.header.mac.fill(0);
  }
  result.valid = magic_ok && version_ok && size_ok && iter_ok && tlv_ok;
  return result;
}

std::array<uint8_t, 32> DerivePasswordKey(const std::string& password,
                                          const ContainerHeaderWire& header) {
  std::vector<uint8_t> pass_bytes(password.begin(), password.end());
  std::array<uint8_t, 32> output{};
  std::array<uint8_t, 20> salt_block{};
  std::memcpy(salt_block.data(), header.fixed.pbkdf_salt.data(), header.fixed.pbkdf_salt.size());
  salt_block[16] = 0;
  salt_block[17] = 0;
  salt_block[18] = 0;
  salt_block[19] = 1;

  auto u = qv::crypto::HMAC_SHA256::Compute(pass_bytes, {salt_block.data(), salt_block.size()});
  output = u;
  auto iter = u;
  for (uint32_t i = 1; i < header.fixed.pbkdf_iterations; ++i) {
    iter = qv::crypto::HMAC_SHA256::Compute(pass_bytes, {iter.data(), iter.size()});
    for (size_t j = 0; j < output.size(); ++j) {
      output[j] ^= iter[j];
    }
  }
  qv::security::Zeroizer::Wipe({iter.data(), iter.size()});
  qv::security::Zeroizer::Wipe({u.data(), u.size()});
  if (!pass_bytes.empty()) {
    qv::security::Zeroizer::Wipe({pass_bytes.data(), pass_bytes.size()});
  }
  return output;
}

void RecordSample(std::chrono::nanoseconds duration) {
  auto& state = GetTimingState();
  uint64_t ns = static_cast<uint64_t>(duration.count());
  size_t bucket = std::min<size_t>(ns / kHistogramBucketNs, kHistogramBuckets - 1);
  std::lock_guard<std::mutex> guard(state.mutex);
  state.histogram[bucket] += 1;
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
  if (desired < kMinTargetNs) desired = kMinTargetNs;
  if (desired > kConfiguredP99Ns) desired = kConfiguredP99Ns;
  state.target_ns.store(desired, std::memory_order_relaxed);
}

TimingSnapshot SnapshotTiming() {
  TimingSnapshot snap{};
  auto& state = GetTimingState();
  std::lock_guard<std::mutex> guard(state.mutex);
  snap.target_ns = state.target_ns.load(std::memory_order_relaxed);
  snap.p95_ns = state.last_p95;
  snap.p99_ns = state.last_p99;
  snap.samples = state.total_samples;
  return snap;
}

std::chrono::nanoseconds ComputePadding(std::chrono::nanoseconds actual) {
  auto& state = GetTimingState();
  uint64_t target = state.target_ns.load(std::memory_order_relaxed);
  uint64_t actual_ns = static_cast<uint64_t>(actual.count());
  uint64_t min_val = qv::crypto::ct::Select<uint64_t>(target, actual_ns, actual_ns < target);
  uint64_t diff = target - min_val;
  return std::chrono::nanoseconds(diff);
}

std::array<uint8_t, sizeof(ContainerHeaderWire)> SerializeHeader(const ContainerHeaderWire& header) {
  std::array<uint8_t, sizeof(ContainerHeaderWire)> bytes{};
  std::memcpy(bytes.data(), &header, sizeof(ContainerHeaderWire));
  return bytes;
}

} // namespace

std::optional<ConstantTimeMount::VolumeHandle>
ConstantTimeMount::Mount(const std::filesystem::path& container,
                         const std::string& password) {
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

  if (any_success) {
    return VolumeHandle{static_cast<int>(selected)};
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
  std::array<uint8_t, sizeof(ContainerHeaderWire)> buf{};
  bool io_ok = false;
  {
    std::ifstream in(container, std::ios::binary);
    if (in) {
      in.read(reinterpret_cast<char*>(buf.data()), buf.size());
      io_ok = static_cast<size_t>(in.gcount()) == buf.size();
    }
  }

  auto parsed = ParseHeader(buf);
  auto header_bytes = SerializeHeader(parsed.header);

  auto classical_key = DerivePasswordKey(password, parsed.header);
  std::array<uint8_t, 32> hybrid_key{};
  bool pqc_ok = false;
  try {
    hybrid_key = qv::core::PQCHybridKDF::Mount(classical_key,
                                               {parsed.header.pqc.kem_ct.data(), parsed.header.pqc.kem_ct.size()},
                                               {parsed.header.pqc.sk_encrypted.data(), parsed.header.pqc.sk_encrypted.size()},
                                               parsed.header.pqc.sk_nonce,
                                               parsed.header.pqc.sk_tag,
                                               {parsed.header.fixed.hybrid_salt.data(), parsed.header.fixed.hybrid_salt.size()});
    pqc_ok = true;
  } catch (const AuthenticationFailureError&) {
    pqc_ok = false;
  } catch (const std::exception&) {
    pqc_ok = false;
  }

  auto computed_mac = qv::crypto::HMAC_SHA256::Compute({hybrid_key.data(), hybrid_key.size()},
      {header_bytes.data(), header_bytes.size() - parsed.header.mac.size()});
  bool mac_ok = qv::crypto::ct::CompareEqual(parsed.header.mac, computed_mac);

  uint32_t mask = (io_ok ? 1u : 0u) & (parsed.valid ? 1u : 0u) & (pqc_ok ? 1u : 0u) & (mac_ok ? 1u : 0u);

  qv::security::Zeroizer::Wipe({classical_key.data(), classical_key.size()});
  qv::security::Zeroizer::Wipe({hybrid_key.data(), hybrid_key.size()});

  if (mask != 0u) {
    return VolumeHandle{1};
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
  std::clog << "{\"event\":\"ct_mount_timing\",";
  std::clog << "\"durations_ns\":[" << a.duration.count() << ',' << b.duration.count() << "],";
  std::clog << "\"padding_ns\":[" << a.pad.count() << ',' << b.pad.count() << "],";
  std::clog << "\"target_ns\":" << snap.target_ns << ',';
  std::clog << "\"p95_ns\":" << snap.p95_ns << ',';
  std::clog << "\"p99_ns\":" << snap.p99_ns << ',';
  std::clog << "\"samples\":" << snap.samples << "}" << std::endl;
}
