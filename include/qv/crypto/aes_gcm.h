#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace qv::crypto {

struct AES256_GCM {
  static constexpr size_t KEY_SIZE = 32;
  static constexpr size_t NONCE_SIZE = 12;
  static constexpr size_t TAG_SIZE = 16;

  struct EncryptionResult {
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, TAG_SIZE> tag;
  };
};

// Encrypts |plaintext| using AES-256-GCM. Throws qv::Error on provider failures.
AES256_GCM::EncryptionResult AES256_GCM_Encrypt(std::span<const uint8_t> plaintext,
                                               std::span<const uint8_t> aad,
                                               std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
                                               std::span<const uint8_t, AES256_GCM::KEY_SIZE> key);

// Decrypts |ciphertext| and validates |tag|. Throws AuthenticationFailureError on
// tag mismatch and qv::Error on other provider failures.
std::vector<uint8_t> AES256_GCM_Decrypt(std::span<const uint8_t> ciphertext,
                                        std::span<const uint8_t> aad,
                                        std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
                                        std::span<const uint8_t, AES256_GCM::TAG_SIZE> tag,
                                        std::span<const uint8_t, AES256_GCM::KEY_SIZE> key);
} // namespace qv::crypto
