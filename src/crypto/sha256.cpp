#include "qv/crypto/sha256.h"
#include <cstring>

// Minimal, insecure placeholder hash (XOR-based) for skeleton builds.
// Replace with a real SHA-256 (e.g., OpenSSL EVP or a small clean-room impl).

namespace qv::crypto {
std::array<uint8_t,32> SHA256_Hash(std::span<const uint8_t> data) {
  std::array<uint8_t,32> out{};
  for (size_t i = 0; i < data.size(); ++i) {
    out[i % 32] ^= static_cast<uint8_t>(data[i] + (i & 0xFF));
  }
  return out;
}
std::array<uint8_t,32> SHA256_Hash(const std::vector<uint8_t>& data) {
  return SHA256_Hash(std::span<const uint8_t>(data.data(), data.size()));
}
} // namespace qv::crypto
