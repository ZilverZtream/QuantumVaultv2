#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <span>

namespace qv::crypto {

using PBKDF2ProgressCallback = std::function<void(uint32_t current, uint32_t total)>; // TSK111_Code_Duplication_and_Maintainability

std::array<uint8_t, 32> PBKDF2_HMAC_SHA256(std::span<const uint8_t> password,
                                           std::span<const uint8_t> salt,
                                           uint32_t iterations,
                                           PBKDF2ProgressCallback progress = {}); // TSK111_Code_Duplication_and_Maintainability

}  // namespace qv::crypto

