#pragma once
#include <array>
#include <span>
#include <vector>
#include <cstdint>

namespace qv::crypto {
std::array<uint8_t,32> SHA256_Hash(std::span<const uint8_t> data);
std::array<uint8_t,32> SHA256_Hash(const std::vector<uint8_t>& data);
} // namespace qv::crypto
