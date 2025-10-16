#pragma once

#include <optional>
#include <span>

#include "qv/security/secure_buffer.h"

namespace qv::orchestrator::credentials {

struct DerivationInputs {
  std::span<const uint8_t> password;  // TSK711_Keyfiles_and_PKCS11_FIDO2 password bytes
  std::optional<std::span<const uint8_t>> keyfile;      // TSK711_Keyfiles_and_PKCS11_FIDO2 optional keyfile blob
  std::optional<std::span<const uint8_t>> pkcs11_blob;  // TSK711_Keyfiles_and_PKCS11_FIDO2 optional PKCS#11 secret
  std::optional<std::span<const uint8_t>> fido2_secret; // TSK711_Keyfiles_and_PKCS11_FIDO2 optional FIDO2 secret
};

[[nodiscard]] qv::security::SecureBuffer<uint8_t> DerivePreKey(
    const DerivationInputs& inputs); // TSK711_Keyfiles_and_PKCS11_FIDO2 pre-KDF combiner

} // namespace qv::orchestrator::credentials

