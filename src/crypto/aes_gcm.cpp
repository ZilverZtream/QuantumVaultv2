#include "qv/crypto/aes_gcm.h"

#include "qv/crypto/provider.h"
#include "qv/security/secure_buffer.h" // TSK_CRIT_03
#include "qv/security/zeroizer.h"       // TSK_CRIT_03

namespace qv::crypto {

AES256_GCM::EncryptionResult AES256_GCM_Encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad,
    std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
    std::span<const uint8_t, AES256_GCM::KEY_SIZE> key) {
  // TSK004, TSK014, TSK040_AAD_Binding_and_Chunk_Authentication
  auto provider = GetCryptoProviderShared();
  return provider->EncryptAES256GCM(plaintext, aad, nonce, key);
}

std::vector<uint8_t> AES256_GCM_Decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> aad,
    std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
    std::span<const uint8_t, AES256_GCM::TAG_SIZE> tag,
    std::span<const uint8_t, AES256_GCM::KEY_SIZE> key) {
  auto provider = GetCryptoProviderShared();
  return provider->DecryptAES256GCM(ciphertext, aad, nonce, tag, key);
}

// TSK_CRIT_03: Secure decrypt directly into locked, non-pageable memory
void AES256_GCM_Decrypt_Secure(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> aad,
    std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
    std::span<const uint8_t, AES256_GCM::TAG_SIZE> tag,
    std::span<const uint8_t, AES256_GCM::KEY_SIZE> key,
    qv::security::SecureBuffer<uint8_t>& dest_buffer) {
  // Decrypt via provider (unfortunately still returns std::vector)
  auto provider = GetCryptoProviderShared();
  std::vector<uint8_t> plaintext = provider->DecryptAES256GCM(ciphertext, aad, nonce, tag, key);

  // Immediately transfer to SecureBuffer and wipe the temporary vector
  if (plaintext.size() != dest_buffer.size()) {
    qv::security::Zeroizer::WipeVector(plaintext);
    throw qv::Error{qv::ErrorDomain::Validation, -1,
                    "Decrypted size mismatch in secure decrypt"};
  }

  std::memcpy(dest_buffer.data(), plaintext.data(), plaintext.size());
  qv::security::Zeroizer::WipeVector(plaintext);
}

} // namespace qv::crypto
