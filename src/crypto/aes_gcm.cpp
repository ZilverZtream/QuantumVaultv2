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
  std::vector<uint8_t> plaintext(ciphertext.size());
  size_t decrypted_size = provider->DecryptAES256GCM(ciphertext, aad, nonce, tag, key,
                                                      std::span<uint8_t>(plaintext.data(), plaintext.size()));
  plaintext.resize(decrypted_size);
  return plaintext;
}

// TSK_CRIT_03: Secure decrypt directly into locked, non-pageable memory
// TSK802_Insecure_Crypto_Interface_Flaw: Now decrypts directly into SecureBuffer
// without intermediate pageable std::vector, eliminating plaintext exposure window
void AES256_GCM_Decrypt_Secure(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> aad,
    std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
    std::span<const uint8_t, AES256_GCM::TAG_SIZE> tag,
    std::span<const uint8_t, AES256_GCM::KEY_SIZE> key,
    qv::security::SecureBuffer<uint8_t>& dest_buffer) {
  // Decrypt directly into the SecureBuffer - no intermediate pageable memory!
  auto provider = GetCryptoProviderShared();
  size_t decrypted_size = provider->DecryptAES256GCM(ciphertext, aad, nonce, tag, key,
                                                      std::span<uint8_t>(dest_buffer.data(), dest_buffer.size()));

  // Verify the decrypted size matches expected buffer size
  if (decrypted_size != dest_buffer.size()) {
    throw qv::Error{qv::ErrorDomain::Validation, -1,
                    "Decrypted size mismatch in secure decrypt"};
  }
}

} // namespace qv::crypto
