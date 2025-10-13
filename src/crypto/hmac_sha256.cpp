#include "qv/crypto/hmac_sha256.h"

#include "qv/crypto/provider.h"

using namespace qv::crypto;

std::array<uint8_t, HMAC_SHA256::TAG_SIZE>
HMAC_SHA256::Compute(std::span<const uint8_t> key, std::span<const uint8_t> msg) {
  auto provider = GetCryptoProviderShared();
  return provider->HMACSHA256(key, msg);
}
