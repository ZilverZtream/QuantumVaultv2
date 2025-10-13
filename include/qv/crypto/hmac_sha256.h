#pragma once
#include <array>
#include <cstdint>
#include <span>

namespace qv::crypto {
struct HMAC_SHA256 {
  static constexpr size_t TAG_SIZE = 32;
  // Computes HMAC-SHA256 using the active CryptoProvider implementation.
  static std::array<uint8_t, TAG_SIZE> Compute(std::span<const uint8_t> key,
                                               std::span<const uint8_t> msg);
};
} // namespace qv::crypto
