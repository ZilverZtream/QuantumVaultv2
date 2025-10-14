#include "qv/crypto/aes_gcm.h"

#include "qv/crypto/provider.h"

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

} // namespace qv::crypto
