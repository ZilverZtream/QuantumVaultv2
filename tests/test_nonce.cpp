#include "qv/core/nonce.h"
#include "qv/security/secure_buffer.h"
#include "qv/security/zeroizer.h"
#include <algorithm> // TSK014
#include <array>
#include <cassert>
#include <chrono> // TSK015
#include <cstdint>
#include <filesystem> // TSK014
#include <fstream>   // TSK021_Nonce_Log_Durability_and_Crash_Safety
#include <iostream>
#include <iterator> // TSK021_Nonce_Log_Durability_and_Crash_Safety
#include <span>
#include <vector>

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
    [[maybe_unused]] auto mac = log.Append(1);
  }
  std::filesystem::path wal_path{"qv_nonce.log.wal"};
  assert(std::filesystem::exists(wal_path) && "wal file must exist after append");
  std::ifstream wal_in(wal_path, std::ios::binary);
  std::vector<uint8_t> wal_bytes((std::istreambuf_iterator<char>(wal_in)),
                                 std::istreambuf_iterator<char>());
  constexpr std::array<char, 8> kWalMagic{'Q', 'V', 'W', 'A', 'L', '0', '1', 'A'};
  [[maybe_unused]] constexpr uint32_t kWalVersion = 1; // TSK021_Nonce_Log_Durability_and_Crash_Safety
  constexpr size_t kWalHeaderSize = kWalMagic.size() + sizeof(uint32_t) + sizeof(uint32_t) +
                                    sizeof(uint64_t) + sizeof(uint32_t);
  size_t offset = 0;
  size_t last_commit_offset = 0;
  while (offset + kWalHeaderSize <= wal_bytes.size()) {
    const uint8_t* base = wal_bytes.data() + offset;
    assert(std::equal(kWalMagic.begin(), kWalMagic.end(), base) && "wal magic must match");
    base += kWalMagic.size();
    uint32_t version_le;
    std::memcpy(&version_le, base, sizeof(version_le));
    base += sizeof(version_le);
    [[maybe_unused]] uint32_t version = qv::ToLittleEndian(version_le);
    assert(version == kWalVersion && "unexpected wal version");
    uint32_t type_le;
    std::memcpy(&type_le, base, sizeof(type_le));
    base += sizeof(type_le);
    uint32_t type = qv::ToLittleEndian(type_le);
    uint64_t size_le;
    std::memcpy(&size_le, base, sizeof(size_le));
    base += sizeof(size_le);
    uint64_t payload_size = qv::ToLittleEndian(size_le);
    uint32_t checksum_le;
    std::memcpy(&checksum_le, base, sizeof(checksum_le));
    base += sizeof(checksum_le);
    (void)checksum_le;
    offset += kWalHeaderSize + static_cast<size_t>(payload_size);
    if (type == 2) {
      last_commit_offset = offset - (kWalHeaderSize + static_cast<size_t>(payload_size));
    }
  }
  assert(last_commit_offset > 0 && "commit record must exist");
  std::filesystem::resize_file(wal_path, last_commit_offset);
  qv::core::NonceLog recovered(std::filesystem::path("qv_nonce.log"));
  assert(recovered.EntryCount() == 1 && "recovery must preserve entries");
  assert(recovered.GetLastCounter() == 1 && "recovered counter must match");
  qv::core::NonceLog verifier(std::filesystem::path("qv_nonce.log"));
  assert(verifier.EntryCount() == 1 && "log should remain stable post recovery");
}

void TestNonceDetectsCorruption() { // TSK021_Nonce_Log_Durability_and_Crash_Safety
  std::filesystem::remove("qv_nonce.log");
  std::filesystem::remove("qv_nonce.log.wal");
  {
    qv::core::NonceLog log(std::filesystem::path("qv_nonce.log"));
    [[maybe_unused]] auto mac = log.Append(1);
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
  TestSecureBufferLifecycle();
  TestNonceRekeyPolicy();
  TestNonceWalRecovery();       // TSK021_Nonce_Log_Durability_and_Crash_Safety
  TestNonceDetectsCorruption(); // TSK021_Nonce_Log_Durability_and_Crash_Safety
  std::cout << "nonce test ok\n";
  return 0;
}
