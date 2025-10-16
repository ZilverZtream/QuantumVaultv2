#pragma once

#include <array>
#include <filesystem>

#include "qv/common.h"

namespace qv::crypto {

[[nodiscard]] std::array<uint8_t, 32> HashKeyfile(
    const std::filesystem::path& path); // TSK711_Keyfiles_and_PKCS11_FIDO2 bounded keyfile digest

} // namespace qv::crypto

