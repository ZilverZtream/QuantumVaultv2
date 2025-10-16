#include "qv/orchestrator/credentials.h"

#include <array>

#include "qv/crypto/sha256.h"          // TSK711_Keyfiles_and_PKCS11_FIDO2 digest primitive
#include "qv/security/zeroizer.h"       // TSK711_Keyfiles_and_PKCS11_FIDO2 wipe intermediates

namespace qv::orchestrator::credentials {

namespace {

void XorDigest(std::span<uint8_t> acc, const std::array<uint8_t, 32>& digest) {
  for (size_t i = 0; i < acc.size(); ++i) {
    acc[i] ^= digest[i];
  }
}

std::array<uint8_t, 32> HashSpan(std::span<const uint8_t> input) {
  if (input.empty()) {
    return {};
  }
  auto digest = qv::crypto::SHA256_Hash(input); // TSK711_Keyfiles_and_PKCS11_FIDO2 fold contribution
  return digest;
}

} // namespace

qv::security::SecureBuffer<uint8_t> DerivePreKey(const DerivationInputs& inputs) {
  qv::security::SecureBuffer<uint8_t> accumulator(32); // TSK711_Keyfiles_and_PKCS11_FIDO2 256-bit accumulator
  auto acc_span = accumulator.AsSpan();

  if (!inputs.password.empty()) {
    auto digest = HashSpan(inputs.password);
    XorDigest(acc_span, digest);
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(digest.data(), digest.size()));
  }
  if (inputs.keyfile && !inputs.keyfile->empty()) {
    auto digest = HashSpan(*inputs.keyfile);
    XorDigest(acc_span, digest);
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(digest.data(), digest.size()));
  }
  if (inputs.pkcs11_blob && !inputs.pkcs11_blob->empty()) {
    auto digest = HashSpan(*inputs.pkcs11_blob);
    XorDigest(acc_span, digest);
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(digest.data(), digest.size()));
  }
  if (inputs.fido2_secret && !inputs.fido2_secret->empty()) {
    auto digest = HashSpan(*inputs.fido2_secret);
    XorDigest(acc_span, digest);
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(digest.data(), digest.size()));
  }

  return accumulator;
}

} // namespace qv::orchestrator::credentials

