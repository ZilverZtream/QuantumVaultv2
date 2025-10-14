#include "qv/crypto/aegis.h"

#include <algorithm>
#include <cstring>

#include "qv/crypto/aes_gcm.h"

#if QV_HAVE_SODIUM
#include <sodium.h>
#endif

namespace qv::crypto {

namespace {
// TSK061_Block_Device_and_Chunk_Storage_Engine
#if defined(QV_HAVE_SODIUM) && defined(crypto_aead_aegis128l_KEYBYTES)
constexpr bool kHasAEGIS128L = true;
#else
constexpr bool kHasAEGIS128L = false;
#endif

#if defined(QV_HAVE_SODIUM) && defined(crypto_aead_aegis256_KEYBYTES)
constexpr bool kHasAEGIS256 = true;
#else
constexpr bool kHasAEGIS256 = false;
#endif

#if defined(QV_HAS_AEGIS128X)
constexpr bool kHasAEGIS128X = true;
#else
constexpr bool kHasAEGIS128X = false;
#endif

constexpr size_t kAESGcmNonceSize = AES256_GCM::NONCE_SIZE;
constexpr size_t kAESGcmKeySize = AES256_GCM::KEY_SIZE;
constexpr size_t kAESGcmTagSize = AES256_GCM::TAG_SIZE;

}  // namespace

const char* CipherTypeName(CipherType cipher) {
  switch (cipher) {
    case CipherType::AEGIS_128X:
      return "AEGIS-128X";
    case CipherType::AEGIS_128L:
      return "AEGIS-128L";
    case CipherType::AEGIS_256:
      return "AEGIS-256";
    case CipherType::AES_256_GCM:
      return "AES-256-GCM";
    case CipherType::CHACHA20_POLY1305:
      return "ChaCha20-Poly1305";
  }
  return "Unknown";
}

bool CipherAvailable(CipherType cipher) {
  switch (cipher) {
    case CipherType::AEGIS_128X:
      return kHasAEGIS128X;
    case CipherType::AEGIS_128L:
      return kHasAEGIS128L;
    case CipherType::AEGIS_256:
      return kHasAEGIS256;
    case CipherType::AES_256_GCM:
      return true;
    case CipherType::CHACHA20_POLY1305:
      return false;
  }
  return false;
}

AEGISEncryptResult AEGIS128X_Encrypt(
    std::span<const uint8_t> /*plaintext*/,
    std::span<const uint8_t> /*associated_data*/,
    std::span<const uint8_t, kAEGIS128XNonceSize> /*nonce*/,
    std::span<const uint8_t, kAEGIS128XKeySize> /*key*/) {
  throw Error{ErrorDomain::Crypto, 0,
              "AEGIS-128X not implemented. Provide libaegis to enable support."};
}

std::vector<uint8_t> AEGIS128X_Decrypt(
    std::span<const uint8_t> /*ciphertext*/,
    std::span<const uint8_t> /*associated_data*/,
    std::span<const uint8_t, kAEGIS128XNonceSize> /*nonce*/,
    std::span<const uint8_t, kAEGIS128XTagSize> /*tag*/,
    std::span<const uint8_t, kAEGIS128XKeySize> /*key*/) {
  throw Error{ErrorDomain::Crypto, 0,
              "AEGIS-128X not implemented. Provide libaegis to enable support."};
}

AEGISEncryptResult AEGIS128L_Encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t, kAEGIS128LNonceSize> nonce,
    std::span<const uint8_t, kAEGIS128LKeySize> key) {
#if !kHasAEGIS128L
  throw Error{ErrorDomain::Crypto, 0,
              "AEGIS-128L is unavailable. Build with libsodium >= 1.0.20."};
#else
  AEGISEncryptResult result;
  result.ciphertext.resize(plaintext.size());
  result.tag.resize(crypto_aead_aegis128l_ABYTES);
  unsigned long long ciphertext_len = 0;
  int ret = crypto_aead_aegis128l_encrypt_detached(
      result.ciphertext.data(),
      result.tag.data(),
      &ciphertext_len,
      plaintext.data(),
      plaintext.size(),
      associated_data.data(),
      associated_data.size(),
      nullptr,
      nonce.data(),
      key.data());
  if (ret != 0) {
    throw Error{ErrorDomain::Crypto, 0, "AEGIS-128L encryption failed"};
  }
  if (ciphertext_len != plaintext.size()) {
    result.ciphertext.resize(ciphertext_len);
  }
  return result;
#endif
}

std::vector<uint8_t> AEGIS128L_Decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t, kAEGIS128LNonceSize> nonce,
    std::span<const uint8_t, kAEGIS128LTagSize> tag,
    std::span<const uint8_t, kAEGIS128LKeySize> key) {
#if !kHasAEGIS128L
  throw Error{ErrorDomain::Crypto, 0,
              "AEGIS-128L is unavailable. Build with libsodium >= 1.0.20."};
#else
  std::vector<uint8_t> plaintext(ciphertext.size());
  int ret = crypto_aead_aegis128l_decrypt_detached(
      plaintext.data(),
      nullptr,
      ciphertext.data(),
      ciphertext.size(),
      tag.data(),
      associated_data.data(),
      associated_data.size(),
      nonce.data(),
      key.data());
  if (ret != 0) {
    throw Error{ErrorDomain::Crypto, 0,
                "AEGIS-128L authentication failed"};
  }
  return plaintext;
#endif
}

AEGISEncryptResult AEGIS256_Encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t, kAEGIS256NonceSize> nonce,
    std::span<const uint8_t, kAEGIS256KeySize> key) {
#if !kHasAEGIS256
  throw Error{ErrorDomain::Crypto, 0,
              "AEGIS-256 is unavailable. Build with libsodium >= 1.0.20."};
#else
  AEGISEncryptResult result;
  result.ciphertext.resize(plaintext.size());
  result.tag.resize(crypto_aead_aegis256_ABYTES);
  unsigned long long ciphertext_len = 0;
  int ret = crypto_aead_aegis256_encrypt_detached(
      result.ciphertext.data(),
      result.tag.data(),
      &ciphertext_len,
      plaintext.data(),
      plaintext.size(),
      associated_data.data(),
      associated_data.size(),
      nullptr,
      nonce.data(),
      key.data());
  if (ret != 0) {
    throw Error{ErrorDomain::Crypto, 0, "AEGIS-256 encryption failed"};
  }
  if (ciphertext_len != plaintext.size()) {
    result.ciphertext.resize(ciphertext_len);
  }
  return result;
#endif
}

std::vector<uint8_t> AEGIS256_Decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t, kAEGIS256NonceSize> nonce,
    std::span<const uint8_t, kAEGIS256TagSize> tag,
    std::span<const uint8_t, kAEGIS256KeySize> key) {
#if !kHasAEGIS256
  throw Error{ErrorDomain::Crypto, 0,
              "AEGIS-256 is unavailable. Build with libsodium >= 1.0.20."};
#else
  std::vector<uint8_t> plaintext(ciphertext.size());
  int ret = crypto_aead_aegis256_decrypt_detached(
      plaintext.data(),
      nullptr,
      ciphertext.data(),
      ciphertext.size(),
      tag.data(),
      associated_data.data(),
      associated_data.size(),
      nonce.data(),
      key.data());
  if (ret != 0) {
    throw Error{ErrorDomain::Crypto, 0,
                "AEGIS-256 authentication failed"};
  }
  return plaintext;
#endif
}

AEADEncryptResult AEAD_Encrypt(
    CipherType cipher,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> key) {
  AEADEncryptResult result{};
  result.cipher_used = cipher;
  switch (cipher) {
    case CipherType::AEGIS_128X: {
      if (!CipherAvailable(cipher)) {
        throw Error{ErrorDomain::Crypto, 0, "AEGIS-128X unavailable"};
      }
      auto derived_key = std::span<const uint8_t, kAEGIS128XKeySize>(key.data(), kAEGIS128XKeySize);
      auto derived_nonce = std::span<const uint8_t, kAEGIS128XNonceSize>(nonce.data(), kAEGIS128XNonceSize);
      auto enc = AEGIS128X_Encrypt(plaintext, associated_data, derived_nonce, derived_key);
      result.ciphertext = std::move(enc.ciphertext);
      result.tag = std::move(enc.tag);
      break;
    }
    case CipherType::AEGIS_128L: {
      if (!CipherAvailable(cipher)) {
        throw Error{ErrorDomain::Crypto, 0, "AEGIS-128L unavailable"};
      }
      auto derived_key = std::span<const uint8_t, kAEGIS128LKeySize>(key.data(), kAEGIS128LKeySize);
      auto derived_nonce = std::span<const uint8_t, kAEGIS128LNonceSize>(nonce.data(), kAEGIS128LNonceSize);
      auto enc = AEGIS128L_Encrypt(plaintext, associated_data, derived_nonce, derived_key);
      result.ciphertext = std::move(enc.ciphertext);
      result.tag = std::move(enc.tag);
      break;
    }
    case CipherType::AEGIS_256: {
      if (!CipherAvailable(cipher)) {
        throw Error{ErrorDomain::Crypto, 0, "AEGIS-256 unavailable"};
      }
      auto derived_key = std::span<const uint8_t, kAEGIS256KeySize>(key.data(), kAEGIS256KeySize);
      auto derived_nonce = std::span<const uint8_t, kAEGIS256NonceSize>(nonce.data(), kAEGIS256NonceSize);
      auto enc = AEGIS256_Encrypt(plaintext, associated_data, derived_nonce, derived_key);
      result.ciphertext = std::move(enc.ciphertext);
      result.tag = std::move(enc.tag);
      break;
    }
    case CipherType::AES_256_GCM: {
      if (nonce.size() < kAESGcmNonceSize || key.size() < kAESGcmKeySize) {
        throw Error{ErrorDomain::Crypto, 0, "AES-GCM parameters invalid"};
      }
      auto enc = AES256_GCM_Encrypt(
          plaintext,
          associated_data,
          std::span<const uint8_t, kAESGcmNonceSize>(nonce.data(), kAESGcmNonceSize),
          std::span<const uint8_t, kAESGcmKeySize>(key.data(), kAESGcmKeySize));
      result.ciphertext = std::move(enc.ciphertext);
      result.tag.assign(enc.tag.begin(), enc.tag.end());
      break;
    }
    case CipherType::CHACHA20_POLY1305:
      throw Error{ErrorDomain::Crypto, 0, "ChaCha20-Poly1305 not implemented"};
  }
  return result;
}

std::vector<uint8_t> AEAD_Decrypt(
    CipherType cipher,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> tag,
    std::span<const uint8_t> key) {
  switch (cipher) {
    case CipherType::AEGIS_128X: {
      if (!CipherAvailable(cipher)) {
        throw Error{ErrorDomain::Crypto, 0, "AEGIS-128X unavailable"};
      }
      auto derived_key = std::span<const uint8_t, kAEGIS128XKeySize>(key.data(), kAEGIS128XKeySize);
      auto derived_nonce = std::span<const uint8_t, kAEGIS128XNonceSize>(nonce.data(), kAEGIS128XNonceSize);
      auto derived_tag = std::span<const uint8_t, kAEGIS128XTagSize>(tag.data(), kAEGIS128XTagSize);
      return AEGIS128X_Decrypt(ciphertext, associated_data, derived_nonce, derived_tag, derived_key);
    }
    case CipherType::AEGIS_128L: {
      if (!CipherAvailable(cipher)) {
        throw Error{ErrorDomain::Crypto, 0, "AEGIS-128L unavailable"};
      }
      auto derived_key = std::span<const uint8_t, kAEGIS128LKeySize>(key.data(), kAEGIS128LKeySize);
      auto derived_nonce = std::span<const uint8_t, kAEGIS128LNonceSize>(nonce.data(), kAEGIS128LNonceSize);
      auto derived_tag = std::span<const uint8_t, kAEGIS128LTagSize>(tag.data(), kAEGIS128LTagSize);
      return AEGIS128L_Decrypt(ciphertext, associated_data, derived_nonce, derived_tag, derived_key);
    }
    case CipherType::AEGIS_256: {
      if (!CipherAvailable(cipher)) {
        throw Error{ErrorDomain::Crypto, 0, "AEGIS-256 unavailable"};
      }
      auto derived_key = std::span<const uint8_t, kAEGIS256KeySize>(key.data(), kAEGIS256KeySize);
      auto derived_nonce = std::span<const uint8_t, kAEGIS256NonceSize>(nonce.data(), kAEGIS256NonceSize);
      auto derived_tag = std::span<const uint8_t, kAEGIS256TagSize>(tag.data(), kAEGIS256TagSize);
      return AEGIS256_Decrypt(ciphertext, associated_data, derived_nonce, derived_tag, derived_key);
    }
    case CipherType::AES_256_GCM: {
      if (nonce.size() < kAESGcmNonceSize || key.size() < kAESGcmKeySize ||
          tag.size() < kAESGcmTagSize) {
        throw Error{ErrorDomain::Crypto, 0, "AES-GCM parameters invalid"};
      }
      return AES256_GCM_Decrypt(
          ciphertext,
          associated_data,
          std::span<const uint8_t, kAESGcmNonceSize>(nonce.data(), kAESGcmNonceSize),
          std::span<const uint8_t, kAESGcmTagSize>(tag.data(), kAESGcmTagSize),
          std::span<const uint8_t, kAESGcmKeySize>(key.data(), kAESGcmKeySize));
    }
    case CipherType::CHACHA20_POLY1305:
      throw Error{ErrorDomain::Crypto, 0, "ChaCha20-Poly1305 not implemented"};
  }
  throw Error{ErrorDomain::Crypto, 0, "Unknown cipher"};
}

}  // namespace qv::crypto

