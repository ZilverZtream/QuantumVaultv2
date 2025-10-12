#include "qv/crypto/hmac_sha256.h"
#include <cstring>
#include <array>

using namespace qv::crypto;

std::array<uint8_t, HMAC_SHA256::TAG_SIZE>
HMAC_SHA256::Compute(std::span<const uint8_t> key, std::span<const uint8_t> msg) {
  // Tiny placeholder to keep the skeleton buildable.
  // DO NOT USE IN PRODUCTION.
  std::array<uint8_t, TAG_SIZE> out{};
  size_t ki = 0;
  for (size_t i = 0; i < msg.size(); ++i) {
    out[i % TAG_SIZE] ^= static_cast<uint8_t>(msg[i] + (key.empty() ? 0 : key[ki]));
    if (!key.empty()) ki = (ki + 1) % key.size();
  }
  return out;
}
