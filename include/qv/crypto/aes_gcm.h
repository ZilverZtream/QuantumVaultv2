#pragma once
#include <array>
#include <span>
#include <vector>

namespace qv::crypto {

struct AES256_GCM {
  static constexpr size_t KEY_SIZE = 32;
  static constexpr size_t NONCE_SIZE = 12;
  static constexpr size_t TAG_SIZE = 16;
};

// STUB implementations — replace with a vetted library
bool AES256_GCM_Encrypt(std::span<const uint8_t> plaintext,
                        std::span<const uint8_t> aad,
                        const std::array<uint8_t,12>& nonce,
                        std::span<const uint8_t,32> key,
                        std::vector<uint8_t>& ciphertext_out,
                        std::array<uint8_t,16>& tag_out);

bool AES256_GCM_Decrypt(std::span<const uint8_t> ciphertext,
                        std::span<const uint8_t> aad,
                        const std::span<const uint8_t,12> nonce,
                        const std::span<const uint8_t,16> tag,
                        std::span<const uint8_t,32> key,
                        std::vector<uint8_t>& plaintext_out);
} // namespace qv::crypto
