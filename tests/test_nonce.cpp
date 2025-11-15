#include "qv/core/nonce.h"
#include "qv/security/secure_buffer.h"
#include "qv/security/zeroizer.h"
#include <algorithm> // TSK014
#include <array>
#include <atomic>     // TSK067_Nonce_Safety
#include <cassert>
#include <chrono>     // TSK015
#include <cstdint>
#include <filesystem> // TSK014
#include <fstream>    // TSK021_Nonce_Log_Durability_and_Crash_Safety
#include <iostream>
#include <iterator>   // TSK021_Nonce_Log_Durability_and_Crash_Safety
#include <mutex>      // TSK067_Nonce_Safety
#include <span>
#include <string>          // TSK067_Nonce_Safety
#include <thread>          // TSK067_Nonce_Safety
#include <unordered_set>   // TSK067_Nonce_Safety
#include <utility>         // TSK067_Nonce_Safety
#include <vector>

#if !defined(_WIN32)
#include <sys/resource.h> // TSK085
#endif

namespace {

void TestZeroizerWipe() { // TSK006
  std::array<uint8_t, 32> secret{};
  secret.fill(0xAA);
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(secret.data(), secret.size()));
  for ([[maybe_unused]] auto byte : secret) {
    assert(byte == 0 && "zeroizer must wipe buffers");
  }
}

void TestZeroizerScopeWiper() { // TSK006
  std::array<uint8_t, 16> secret{};
  {
    secret.fill(0x42);
    qv::security::Zeroizer::ScopeWiper<uint8_t> guard{std::span<uint8_t>(secret)};
    (void)guard;
  }
  for ([[maybe_unused]] auto byte : secret) {
    assert(byte == 0 && "scope wiper must zero on destruction");
  }
}

void TestZeroizerVectorHelper() { // TSK006
  std::vector<uint32_t> data(8, 0xA5A5A5A5);
  qv::security::Zeroizer::WipeVector(data);
  for ([[maybe_unused]] auto value : data) {
    assert(value == 0 && "vector helper must zeroize elements");
  }
}

#if !defined(_WIN32)
void TestZeroizerLockFailure() { // TSK085
  if (!qv::security::Zeroizer::MemoryLockingSupported()) {
    return;
  }

  struct rlimit original_limit {};
  if (::getrlimit(RLIMIT_MEMLOCK, &original_limit) != 0) {
    return;
  }

  struct LimitGuard { // TSK085
    struct rlimit limit;
    explicit LimitGuard(struct rlimit value) : limit(value) {}
    ~LimitGuard() { ::setrlimit(RLIMIT_MEMLOCK, &limit); }
  } guard{original_limit};

  struct rlimit zero_limit = original_limit;
  zero_limit.rlim_cur = 0;
  if (::setrlimit(RLIMIT_MEMLOCK, &zero_limit) != 0) {
    return;
  }

  std::array<uint8_t, 4096> buffer{};
  auto span = std::span<uint8_t>(buffer.data(), buffer.size());
  const auto status = qv::security::Zeroizer::TryLockMemory(span);
  assert(status == qv::security::Zeroizer::LockStatus::BestEffort &&
         "lock failure should report best-effort");
  qv::security::Zeroizer::UnlockMemory(span);
}
#else
void TestZeroizerLockFailure() { // TSK085
  // RLIMIT_MEMLOCK controls are POSIX-specific.
}
#endif

void TestSecureBufferLifecycle() { // TSK006
  qv::security::SecureBuffer<uint32_t> buf(4);
  auto span = buf.AsSpan();
  for ([[maybe_unused]] auto value : span) {
    assert(value == 0 && "secure buffer must start zeroed");
  }
  for (auto& value : span) {
    value = 0x12345678;
  }
  auto bytes = std::span<uint8_t>(reinterpret_cast<uint8_t*>(span.data()), span.size() * sizeof(uint32_t));
  qv::security::Zeroizer::Wipe(bytes);
  for ([[maybe_unused]] auto value : span) {
    assert(value == 0 && "secure buffer wipe must zero data");
  }
}

void TestNonceRekeyPolicy() { // TSK015
  std::filesystem::remove("qv_nonce.log");
  std::filesystem::remove("qv_nonce.log.wal"); // TSK021_Nonce_Log_Durability_and_Crash_Safety
  qv::core::NonceGenerator ng(11, 0);
  ng.SetPolicy(2, std::chrono::hours{24 * 365});
  [[maybe_unused]] auto initial_status = ng.GetStatus();
  assert(initial_status.reason == qv::core::NonceGenerator::RekeyReason::kNone &&
         "fresh generator must not require rekey");
  [[maybe_unused]] auto first = ng.NextAuthenticated();
  [[maybe_unused]] auto second = ng.NextAuthenticated();
  [[maybe_unused]] auto persisted = ng.LastPersisted();
  assert(persisted.has_value() && "persisted record must exist after appends");
  assert(persisted->counter == second.counter && "persisted counter must match last append");
  [[maybe_unused]] auto status = ng.GetStatus();
  assert(status.reason == qv::core::NonceGenerator::RekeyReason::kNonceBudget &&
         "nonce budget should trigger rekey status");
  [[maybe_unused]] bool refused = false;
  try {
    (void)ng.NextAuthenticated();
  } catch (const qv::Error& err) {
    refused = (err.domain == qv::ErrorDomain::Security);
  }
  assert(refused && "generator must refuse once nonce budget depleted");
}

void TestNonceWalRecovery() { // TSK021_Nonce_Log_Durability_and_Crash_Safety
  std::filesystem::remove("qv_nonce.log");
  std::filesystem::remove("qv_nonce.log.wal");
  {
    qv::core::NonceLog log(std::filesystem::path("qv_nonce.log"));
    [[maybe_unused]] auto mac = log.Append(1, std::span<const uint8_t>{}); // TSK128_Missing_AAD_Validation_in_Chunks
    (void)mac;
  }
  std::filesystem::path wal_path{"qv_nonce.log.wal"};
  assert(std::filesystem::exists(wal_path) && "wal file must exist after append");
  std::ifstream wal_in(wal_path, std::ios::binary);
  std::vector<uint8_t> wal_bytes((std::istreambuf_iterator<char>(wal_in)),
                                 std::istreambuf_iterator<char>());
  constexpr std::array<char, 8> kWalMagic{'Q', 'V', 'W', 'A', 'L', '0', '1', 'A'}; // TSK_CRIT_01_Nonce_Replay_Stopgap
  constexpr uint32_t kWalVersion = 1;
  constexpr size_t kWalHeaderSize = kWalMagic.size() + sizeof(uint32_t) + sizeof(uint32_t) +
                                    sizeof(uint64_t) + sizeof(uint32_t);
  assert(wal_bytes.size() >= kWalHeaderSize + sizeof(uint64_t) + 32 &&
         "wal record must include append entry");
  const uint8_t* base = wal_bytes.data();
  assert(std::equal(kWalMagic.begin(), kWalMagic.end(), base) && "wal magic must match");
  base += kWalMagic.size();
  uint32_t version_le;
  std::memcpy(&version_le, base, sizeof(version_le));
  base += sizeof(version_le);
  uint32_t version = qv::ToLittleEndian(version_le);
  assert(version == kWalVersion && "unexpected wal version");
  uint32_t type_le;
  std::memcpy(&type_le, base, sizeof(type_le));
  uint32_t type = qv::ToLittleEndian(type_le);
  assert(type == 3 && "wal entry must record append operations"); // TSK_CRIT_01_Nonce_Replay_Stopgap

  qv::core::NonceLog recovered(std::filesystem::path("qv_nonce.log"));
  assert(recovered.EntryCount() == 1 && "recovery must preserve entries");
  assert(recovered.GetLastCounter() == 1 && "recovered counter must match");
  assert(!std::filesystem::exists(wal_path) && "wal should be cleared after recovery");
  qv::core::NonceLog verifier(std::filesystem::path("qv_nonce.log"));
  assert(verifier.EntryCount() == 1 && "log should remain stable post recovery");
}

void TestNonceDetectsCorruption() { // TSK021_Nonce_Log_Durability_and_Crash_Safety
  std::filesystem::remove("qv_nonce.log");
  std::filesystem::remove("qv_nonce.log.wal");
  {
    qv::core::NonceLog log(std::filesystem::path("qv_nonce.log"));
    [[maybe_unused]] auto mac = log.Append(1, std::span<const uint8_t>{}); // TSK128_Missing_AAD_Validation_in_Chunks
  }
  auto log_path = std::filesystem::path("qv_nonce.log");
  auto size = std::filesystem::file_size(log_path);
  std::filesystem::resize_file(log_path, size - 1);
  [[maybe_unused]] bool threw = false;
  try {
    qv::core::NonceLog fail(log_path);
    (void)fail;
  } catch (const qv::Error&) {
    threw = true;
  }
  assert(threw && "corrupt log must throw on reload");
  std::filesystem::remove("qv_nonce.log");
  std::filesystem::remove("qv_nonce.log.wal");
}

void TestConcurrentNonceGeneration() { // TSK067_Nonce_Safety
  std::filesystem::remove("qv_nonce.log");
  std::filesystem::remove("qv_nonce.log.wal");
  qv::core::NonceGenerator generator(17, 0);
  constexpr size_t kThreads = 8;
  constexpr size_t kIterationsPerThread = 256;
  std::atomic<uint64_t> chunk_index{0};
  std::mutex results_mutex;
  std::vector<std::pair<uint64_t, std::array<uint8_t, 12>>> results;
  results.reserve(kThreads * kIterationsPerThread);

  auto worker = [&]() {
    std::vector<std::pair<uint64_t, std::array<uint8_t, 12>>> local;
    local.reserve(kIterationsPerThread);
    for (size_t i = 0; i < kIterationsPerThread; ++i) {
      uint64_t index = chunk_index.fetch_add(1, std::memory_order_relaxed);
      auto record = generator.NextAuthenticated();
      local.emplace_back(index, record.nonce);
    }
    std::lock_guard<std::mutex> guard(results_mutex);
    results.insert(results.end(), local.begin(), local.end());
  };

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (size_t i = 0; i < kThreads; ++i) {
    threads.emplace_back(worker);
  }
  for (auto& thread : threads) {
    thread.join();
  }

  assert(results.size() == kThreads * kIterationsPerThread &&
         "all nonce records must be collected"); // TSK067_Nonce_Safety

  std::unordered_set<std::string> observed;
  observed.reserve(results.size());
  constexpr char kHexDigits[] = "0123456789abcdef";
  for (const auto& [index, nonce] : results) {
    std::string key = std::to_string(index);
    key.push_back(':');
    for (auto byte : nonce) {
      key.push_back(kHexDigits[(byte >> 4) & 0x0F]);
      key.push_back(kHexDigits[byte & 0x0F]);
    }
    auto [_, inserted] = observed.insert(std::move(key));
    assert(inserted && "duplicate chunk/nonce pair detected"); // TSK067_Nonce_Safety
  }

  assert(generator.CurrentCounter() == results.size() &&
         "counter must reflect number of emitted nonces"); // TSK067_Nonce_Safety

  std::filesystem::remove("qv_nonce.log");
  std::filesystem::remove("qv_nonce.log.wal");
}

} // namespace

int main() {
  std::filesystem::remove("qv_nonce.log");      // TSK014
  std::filesystem::remove("qv_nonce.log.wal"); // TSK021_Nonce_Log_Durability_and_Crash_Safety
  qv::core::NonceGenerator ng(7, 0);
  [[maybe_unused]] auto record_a = ng.NextAuthenticated();
  [[maybe_unused]] auto record_b = ng.NextAuthenticated();
  assert(record_a.counter + 1 == record_b.counter && "counter must increment"); // TSK014
  assert(!(record_a.nonce == record_b.nonce) && "authenticated nonces must be unique"); // TSK014
  assert(!std::all_of(record_a.mac.begin(), record_a.mac.end(), [](uint8_t b) { return b == 0; }) &&
         "nonce MAC should not be all zeros"); // TSK014
  [[maybe_unused]] auto c = ng.Next();
  assert(!(record_b.nonce == c) && "mixed API must still yield unique nonces"); // TSK014
  TestZeroizerWipe();
  TestZeroizerScopeWiper();
  TestZeroizerVectorHelper();
  TestZeroizerLockFailure();
  TestSecureBufferLifecycle();
  TestNonceRekeyPolicy();
  TestNonceWalRecovery();       // TSK021_Nonce_Log_Durability_and_Crash_Safety
  TestNonceDetectsCorruption(); // TSK021_Nonce_Log_Durability_and_Crash_Safety
  TestConcurrentNonceGeneration(); // TSK067_Nonce_Safety
  std::cout << "nonce test ok\n";
  return 0;
}
