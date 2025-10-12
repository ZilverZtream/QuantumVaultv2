#include "qv/crypto/aes_gcm.h"
#include <cstring>

using namespace qv::crypto;

bool AES256_GCM_Encrypt(std::span<const uint8_t> plaintext,
                        std::span<const uint8_t> aad,
                        const std::array<uint8_t,12>& nonce,
                        std::span<const uint8_t,32> key,
                        std::vector<uint8_t>& ciphertext_out,
                        std::array<uint8_t,16>& tag_out) {
  // STUB: just XORs and fills tag deterministically for demo.
  ciphertext_out.resize(plaintext.size());
  for (size_t i = 0; i < plaintext.size(); ++i) {
    ciphertext_out[i] = plaintext[i] ^ key[i % key.size()] ^ nonce[i % nonce.size()];
  }
  for (size_t i = 0; i < tag_out.size(); ++i) {
    tag_out[i] = (i < aad.size() ? aad[i] : 0) ^ (i < key.size() ? key[i] : 0) ^ (i < nonce.size() ? nonce[i] : 0);
  }
  return true;
}

bool AES256_GCM_Decrypt(std::span<const uint8_t> ciphertext,
                        std::span<const uint8_t> aad,
                        const std::span<const uint8_t,12> nonce,
                        const std::span<const uint8_t,16> tag,
                        std::span<const uint8_t,32> key,
                        std::vector<uint8_t>& plaintext_out) {
  // STUB: no authentication check; mirrors the XOR.
  plaintext_out.resize(ciphertext.size());
  for (size_t i = 0; i < ciphertext.size(); ++i) {
    plaintext_out[i] = ciphertext[i] ^ key[i % key.size()] ^ nonce[i % nonce.size()];
  }
  return true;
}
