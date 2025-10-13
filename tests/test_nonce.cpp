#include "qv/core/nonce.h"
#include "qv/security/secure_buffer.h"
#include "qv/security/zeroizer.h"
#include <array>
#include <algorithm> // TSK014
#include <cassert>
#include <cstdint>
#include <filesystem> // TSK014
#include <iostream>
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

} // namespace

int main() {
  std::filesystem::remove("qv_nonce.log"); // TSK014
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
  std::cout << "nonce test ok\n";
  return 0;
}
