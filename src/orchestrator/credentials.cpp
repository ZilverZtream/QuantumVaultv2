#include "qv/orchestrator/credentials.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "qv/crypto/hkdf.h"             // TSK235_Credential_Derivation_Weak_Combining HKDF combiner
#include "qv/crypto/hmac_sha256.h"      // TSK235_Credential_Derivation_Weak_Combining keyfile authenticator
#include "qv/crypto/sha256.h"           // TSK711_Keyfiles_and_PKCS11_FIDO2 digest primitive
#include "qv/error.h"                   // TSK235_Credential_Derivation_Weak_Combining validation errors
#include "qv/security/zeroizer.h"       // TSK711_Keyfiles_and_PKCS11_FIDO2 wipe intermediates

namespace qv::orchestrator::credentials {

namespace {

constexpr size_t kMinHardwareEntropyBytes = 16;                                      // TSK235_Credential_Derivation_Weak_Combining entropy floor
constexpr std::string_view kCombineInfo = "QV-CRED-COMBINE/v1";                      // TSK235_Credential_Derivation_Weak_Combining HKDF info label
constexpr std::string_view kPasswordLabel = "QV-CRED-PASSWORD/v1";                   // TSK235_Credential_Derivation_Weak_Combining label separation
constexpr std::string_view kKeyfileLabel = "QV-CRED-KEYFILE/v1";                     // TSK235_Credential_Derivation_Weak_Combining label separation
constexpr std::string_view kPkcs11Label = "QV-CRED-PKCS11/v1";                       // TSK235_Credential_Derivation_Weak_Combining label separation
constexpr std::string_view kFido2Label = "QV-CRED-FIDO2/v1";                         // TSK235_Credential_Derivation_Weak_Combining label separation
constexpr std::array<uint8_t, 11> kKeyfileMagic{
    'Q', 'V', 'K', 'E', 'Y', 'F', 'I', 'L', 'E', 'V', '1'};                           // TSK235_Credential_Derivation_Weak_Combining keyfile format tag

std::span<const uint8_t> AsBytes(std::string_view view) {
  return {reinterpret_cast<const uint8_t*>(view.data()), view.size()};                // TSK235_Credential_Derivation_Weak_Combining span helper
}

std::array<uint8_t, 32> HashSpan(std::span<const uint8_t> input) {
  if (input.empty()) {
    return {};
  }
  auto digest = qv::crypto::SHA256_Hash(input); // TSK711_Keyfiles_and_PKCS11_FIDO2 fold contribution
  return digest;
}

void ValidateHardwareEntropy(std::span<const uint8_t> input, std::string_view source) {
  if (input.size() < kMinHardwareEntropyBytes) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(source) + " credential lacks minimum entropy"};       // TSK235_Credential_Derivation_Weak_Combining entropy size
  }
  if (std::all_of(input.begin() + 1, input.end(),
                  [first = input.front()](uint8_t byte) { return byte == first; })) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(source) + " credential has insufficient variance"};   // TSK235_Credential_Derivation_Weak_Combining entropy variance
  }
}

std::array<uint8_t, 32> AuthenticateKeyfile(std::span<const uint8_t> keyfile,
                                            std::span<const uint8_t> password_digest) {
  constexpr size_t kHmacSize = qv::crypto::HMAC_SHA256::TAG_SIZE;                     // TSK235_Credential_Derivation_Weak_Combining HMAC tag size
  if (keyfile.size() <= kKeyfileMagic.size() + kHmacSize) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Keyfile is too small for authenticated format"};               // TSK235_Credential_Derivation_Weak_Combining keyfile size
  }
  if (!std::equal(kKeyfileMagic.begin(), kKeyfileMagic.end(), keyfile.begin())) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Keyfile header mismatch"};                                      // TSK235_Credential_Derivation_Weak_Combining keyfile header
  }

  auto payload = keyfile.subspan(kKeyfileMagic.size(),
                                 keyfile.size() - kKeyfileMagic.size() - kHmacSize);  // TSK235_Credential_Derivation_Weak_Combining keyfile payload
  if (payload.empty()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Keyfile payload missing"};                                      // TSK235_Credential_Derivation_Weak_Combining payload validation
  }

  auto provided_mac = keyfile.subspan(keyfile.size() - kHmacSize);                     // TSK235_Credential_Derivation_Weak_Combining provided MAC
  auto computed_mac = qv::crypto::HMAC_SHA256::Compute(password_digest, payload);      // TSK235_Credential_Derivation_Weak_Combining HMAC verification
  const bool mac_ok = std::equal(computed_mac.begin(), computed_mac.end(), provided_mac.begin());
  if (!mac_ok) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(computed_mac.data(), computed_mac.size()));
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Keyfile authentication failed"};                               // TSK235_Credential_Derivation_Weak_Combining HMAC failure
  }

  auto digest = qv::crypto::SHA256_Hash(payload);                                     // TSK235_Credential_Derivation_Weak_Combining keyfile digest
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(computed_mac.data(), computed_mac.size()));
  return digest;
}

void AppendContribution(std::vector<uint8_t>& buffer, std::string_view label,
                        std::span<const uint8_t> data) {
  const uint16_t length = static_cast<uint16_t>(data.size());                         // TSK235_Credential_Derivation_Weak_Combining length encoding
  buffer.insert(buffer.end(), label.begin(), label.end());
  buffer.push_back(static_cast<uint8_t>(length >> 8));
  buffer.push_back(static_cast<uint8_t>(length & 0xFF));
  buffer.insert(buffer.end(), data.begin(), data.end());
}

} // namespace

qv::security::SecureBuffer<uint8_t> DerivePreKey(const DerivationInputs& inputs) {
  if (inputs.password.empty()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Password credential is required"};                             // TSK235_Credential_Derivation_Weak_Combining mandatory password
  }

  auto password_digest = HashSpan(inputs.password);                                   // TSK235_Credential_Derivation_Weak_Combining password binding
  std::vector<uint8_t> ikm_buffer;                                                    // TSK235_Credential_Derivation_Weak_Combining HKDF material
  ikm_buffer.reserve(128);

  AppendContribution(ikm_buffer, kPasswordLabel,
                     std::span<const uint8_t>(password_digest.data(), password_digest.size()));

  if (inputs.keyfile && !inputs.keyfile->empty()) {
    auto keyfile_digest = AuthenticateKeyfile(*inputs.keyfile,
                                              std::span<const uint8_t>(password_digest.data(),
                                                                        password_digest.size()));
    AppendContribution(ikm_buffer, kKeyfileLabel,
                       std::span<const uint8_t>(keyfile_digest.data(), keyfile_digest.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(keyfile_digest.data(), keyfile_digest.size()));
  }

  if (inputs.pkcs11_blob && !inputs.pkcs11_blob->empty()) {
    ValidateHardwareEntropy(*inputs.pkcs11_blob, "PKCS#11");
    auto digest = HashSpan(*inputs.pkcs11_blob);
    AppendContribution(ikm_buffer, kPkcs11Label,
                       std::span<const uint8_t>(digest.data(), digest.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(digest.data(), digest.size()));
  }

  if (inputs.fido2_secret && !inputs.fido2_secret->empty()) {
    ValidateHardwareEntropy(*inputs.fido2_secret, "FIDO2");
    auto digest = HashSpan(*inputs.fido2_secret);
    AppendContribution(ikm_buffer, kFido2Label,
                       std::span<const uint8_t>(digest.data(), digest.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(digest.data(), digest.size()));
  }

  auto hkdf_output = qv::crypto::HKDF_SHA256(
      std::span<const uint8_t>(ikm_buffer.data(), ikm_buffer.size()),
      std::span<const uint8_t>(password_digest.data(), password_digest.size()), AsBytes(kCombineInfo));

  qv::security::SecureBuffer<uint8_t> accumulator(hkdf_output.size());                // TSK235_Credential_Derivation_Weak_Combining HKDF output
  std::copy(hkdf_output.begin(), hkdf_output.end(), accumulator.data());

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(password_digest.data(), password_digest.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(hkdf_output.data(), hkdf_output.size()));
  if (!ikm_buffer.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(ikm_buffer.data(), ikm_buffer.size()));
  }

  return accumulator;
}

} // namespace qv::orchestrator::credentials

