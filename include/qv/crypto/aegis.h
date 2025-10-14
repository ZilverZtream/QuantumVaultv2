#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "qv/error.h"

namespace qv::crypto {

// TSK061_Block_Device_and_Chunk_Storage_Engine
constexpr size_t kAEGIS128XKeySize = 16;
constexpr size_t kAEGIS128XNonceSize = 16;
constexpr size_t kAEGIS128XTagSize = 16;

constexpr size_t kAEGIS128LKeySize = 16;
constexpr size_t kAEGIS128LNonceSize = 16;
constexpr size_t kAEGIS128LTagSize = 16;

constexpr size_t kAEGIS256KeySize = 32;
constexpr size_t kAEGIS256NonceSize = 32;
constexpr size_t kAEGIS256TagSize = 32;

struct AEGISEncryptResult {
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> tag;
};

enum class CipherType : uint8_t {
  AEGIS_128X = 0,
  AEGIS_128L = 1,
  AEGIS_256 = 2,
  AES_256_GCM = 3,
  CHACHA20_POLY1305 = 4,
};

const char* CipherTypeName(CipherType cipher);
bool CipherAvailable(CipherType cipher);

AEGISEncryptResult AEGIS128X_Encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t, kAEGIS128XNonceSize> nonce,
    std::span<const uint8_t, kAEGIS128XKeySize> key);

std::vector<uint8_t> AEGIS128X_Decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t, kAEGIS128XNonceSize> nonce,
    std::span<const uint8_t, kAEGIS128XTagSize> tag,
    std::span<const uint8_t, kAEGIS128XKeySize> key);

AEGISEncryptResult AEGIS128L_Encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t, kAEGIS128LNonceSize> nonce,
    std::span<const uint8_t, kAEGIS128LKeySize> key);

std::vector<uint8_t> AEGIS128L_Decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t, kAEGIS128LNonceSize> nonce,
    std::span<const uint8_t, kAEGIS128LTagSize> tag,
    std::span<const uint8_t, kAEGIS128LKeySize> key);

AEGISEncryptResult AEGIS256_Encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t, kAEGIS256NonceSize> nonce,
    std::span<const uint8_t, kAEGIS256KeySize> key);

std::vector<uint8_t> AEGIS256_Decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t, kAEGIS256NonceSize> nonce,
    std::span<const uint8_t, kAEGIS256TagSize> tag,
    std::span<const uint8_t, kAEGIS256KeySize> key);

struct AEADEncryptResult {
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> tag;
  CipherType cipher_used;
};

AEADEncryptResult AEAD_Encrypt(
    CipherType cipher,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> key);

std::vector<uint8_t> AEAD_Decrypt(
    CipherType cipher,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> associated_data,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> tag,
    std::span<const uint8_t> key);

}  // namespace qv::crypto

