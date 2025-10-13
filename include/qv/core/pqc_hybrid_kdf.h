#pragma once
#include <array>
#include <span>
#include <vector>
#include "qv/common.h"
#include "qv/error.h"
#include "qv/security/secure_buffer.h"
#include "qv/security/zeroizer.h"

namespace qv::core {

namespace PQC { // TSK003
  // ML-KEM-768 sizes
  static constexpr size_t PUBLIC_KEY_SIZE = 1184;
  static constexpr size_t SECRET_KEY_SIZE = 2400;
  static constexpr size_t CIPHERTEXT_SIZE = 1088;
  static constexpr size_t SHARED_SECRET_SIZE = 32;
  static constexpr uint16_t KEM_TLV_VERSION = 0x0401; // v4.1
}

struct PQC_KEM_TLV { // TSK003
  uint16_t type = 0x7051; // 'pQ'
  uint16_t length = sizeof(PQC_KEM_TLV) - 4;
  uint16_t version = PQC::KEM_TLV_VERSION;
  uint16_t kem_id = 0x0300; // ML-KEM-768
  std::array<uint8_t, PQC::CIPHERTEXT_SIZE> kem_ct{};
  std::array<uint8_t, 12> sk_nonce{};
  std::array<uint8_t, 16> sk_tag{};
  std::array<uint8_t, PQC::SECRET_KEY_SIZE> sk_encrypted{};
} __attribute__((packed));

class PQCKeyEncapsulation {
public:
  struct KeyPair {
    std::array<uint8_t, PQC::PUBLIC_KEY_SIZE> pk{};
    qv::security::SecureBuffer<uint8_t> sk{PQC::SECRET_KEY_SIZE};
  };
  struct EncapsulationResult {
    std::array<uint8_t, PQC::CIPHERTEXT_SIZE> ciphertext{};
    std::array<uint8_t, PQC::SHARED_SECRET_SIZE> shared_secret{};
  };
  KeyPair GenerateKeypair();            // STUB: returns random
  EncapsulationResult Encapsulate(const std::array<uint8_t, PQC::PUBLIC_KEY_SIZE>& pk);
  std::array<uint8_t, PQC::SHARED_SECRET_SIZE> Decapsulate(
    std::span<const uint8_t, PQC::SECRET_KEY_SIZE> sk,
    std::span<const uint8_t, PQC::CIPHERTEXT_SIZE> ct);
};

class PQCHybridKDF {
public:
  struct CreationResult {
    PQC_KEM_TLV kem_blob;
    std::array<uint8_t, 32> hybrid_key;
  };
  static CreationResult Create(std::span<const uint8_t, 32> classical_key,
                               std::span<const uint8_t> salt,
                               std::span<const uint8_t, 16> volume_uuid,
                               uint32_t header_version,
                               std::span<const uint8_t> epoch_tlv);
  static std::array<uint8_t, 32> Mount(std::span<const uint8_t, 32> classical_key,
                                       const PQC_KEM_TLV& kem_blob,
                                       std::span<const uint8_t> salt,
                                       std::span<const uint8_t, 16> volume_uuid,
                                       uint32_t header_version,
                                       std::span<const uint8_t> epoch_tlv);
private:
  static std::array<uint8_t, 32> DeriveHybridKey(std::span<const uint8_t, 32> classical_key,
                                                 std::span<const uint8_t, 32> pqc_shared_secret,
                                                 std::span<const uint8_t> salt,
                                                 std::span<const uint8_t, 16> volume_uuid);
};

} // namespace qv::core
