#include "qv/core/nonce.h"
#include "qv/security/secure_buffer.h"
#include "qv/security/zeroizer.h"
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

namespace {

void TestZeroizerWipe() { // TSK006
  std::array<uint8_t, 32> secret{};
  secret.fill(0xAA);
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(secret.data(), secret.size()));
  for (auto byte : secret) {
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
  for (auto byte : secret) {
    assert(byte == 0 && "scope wiper must zero on destruction");
  }
}

void TestZeroizerVectorHelper() { // TSK006
  std::vector<uint32_t> data(8, 0xA5A5A5A5);
  qv::security::Zeroizer::WipeVector(data);
  for (auto value : data) {
    assert(value == 0 && "vector helper must zeroize elements");
  }
}

void TestSecureBufferLifecycle() { // TSK006
  qv::security::SecureBuffer<uint32_t> buf(4);
  auto span = buf.AsSpan();
  for (auto value : span) {
    assert(value == 0 && "secure buffer must start zeroed");
  }
  for (auto& value : span) {
    value = 0x12345678;
  }
  auto bytes = std::span<uint8_t>(reinterpret_cast<uint8_t*>(span.data()), span.size() * sizeof(uint32_t));
  qv::security::Zeroizer::Wipe(bytes);
  for (auto value : span) {
    assert(value == 0 && "secure buffer wipe must zero data");
  }
}

} // namespace

int main() {
  qv::core::NonceGenerator ng(7, 0);
  auto a = ng.Next();
  auto b = ng.Next();
  assert(!(a == b) && "nonces must be unique");
  TestZeroizerWipe();
  TestZeroizerScopeWiper();
  TestZeroizerVectorHelper();
  TestSecureBufferLifecycle();
  std::cout << "nonce test ok\n";
  return 0;
}
