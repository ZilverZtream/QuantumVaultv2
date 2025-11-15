#pragma once

#include <array>
#include <memory>
#include <span>
#include <vector>

#include "qv/crypto/aes_gcm.h"

namespace qv::crypto {

class CryptoProvider {
public:
  virtual ~CryptoProvider() = default;

  virtual AES256_GCM::EncryptionResult EncryptAES256GCM(
      std::span<const uint8_t> plaintext,
      std::span<const uint8_t> aad,
      std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
      std::span<const uint8_t, AES256_GCM::KEY_SIZE> key) = 0;

  // TSK802_Insecure_Crypto_Interface_Flaw: Decrypt directly into destination buffer
  // to avoid plaintext exposure in pageable std::vector memory.
  // Returns the actual size of decrypted data written to destination.
  // Throws AuthenticationFailureError on tag mismatch.
  virtual size_t DecryptAES256GCM(
      std::span<const uint8_t> ciphertext,
      std::span<const uint8_t> aad,
      std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
      std::span<const uint8_t, AES256_GCM::TAG_SIZE> tag,
      std::span<const uint8_t, AES256_GCM::KEY_SIZE> key,
      std::span<uint8_t> destination) = 0;

  virtual std::array<uint8_t, 32> HMACSHA256(
      std::span<const uint8_t> key,
      std::span<const uint8_t> message) = 0;

  virtual std::array<uint8_t, 32> SHA256(
      std::span<const uint8_t> data) = 0;
};

class OpenSSLCryptoProvider : public CryptoProvider {
public:
  AES256_GCM::EncryptionResult EncryptAES256GCM(
      std::span<const uint8_t> plaintext,
      std::span<const uint8_t> aad,
      std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
      std::span<const uint8_t, AES256_GCM::KEY_SIZE> key) override;

  size_t DecryptAES256GCM(
      std::span<const uint8_t> ciphertext,
      std::span<const uint8_t> aad,
      std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
      std::span<const uint8_t, AES256_GCM::TAG_SIZE> tag,
      std::span<const uint8_t, AES256_GCM::KEY_SIZE> key,
      std::span<uint8_t> destination) override;

  std::array<uint8_t, 32> HMACSHA256(
      std::span<const uint8_t> key,
      std::span<const uint8_t> message) override;

  std::array<uint8_t, 32> SHA256(
      std::span<const uint8_t> data) override;
};

std::shared_ptr<CryptoProvider> GetCryptoProviderShared();
CryptoProvider& GetCryptoProvider();
void SetCryptoProvider(std::shared_ptr<CryptoProvider> provider);
void EnsureCryptoProviderInitialized(); // TSK072_CryptoProvider_Init_and_KAT runtime initialization hook
void ResetCryptoProviderForTesting();    // TSK110_Initialization_and_Cleanup_Order test-only reset hook

}  // namespace qv::crypto

