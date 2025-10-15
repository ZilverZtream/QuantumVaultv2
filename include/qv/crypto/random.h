#pragma once

#include <span>

#include "qv/common.h"

namespace qv::crypto {

void SystemRandomBytes(std::span<uint8_t> out); // TSK106_Cryptographic_Implementation_Weaknesses

}  // namespace qv::crypto
