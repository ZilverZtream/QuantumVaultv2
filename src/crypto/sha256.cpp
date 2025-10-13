#include "qv/crypto/sha256.h"

#include "qv/crypto/provider.h"

namespace qv::crypto {

std::array<uint8_t, 32> SHA256_Hash(std::span<const uint8_t> data) {
  auto provider = GetCryptoProviderShared();
  return provider->SHA256(data);
}

std::array<uint8_t, 32> SHA256_Hash(const std::vector<uint8_t>& data) {
  return SHA256_Hash(std::span<const uint8_t>(data.data(), data.size()));
}

}  // namespace qv::crypto
