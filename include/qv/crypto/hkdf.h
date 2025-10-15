#pragma once

#include <array>
#include <span>

#include "qv/common.h"

namespace qv::crypto {

std::array<uint8_t, 32> HKDF_SHA256(std::span<const uint8_t> ikm,
                                    std::span<const uint8_t> salt,
                                    std::span<const uint8_t> info); // TSK106_Cryptographic_Implementation_Weaknesses

}  // namespace qv::crypto
