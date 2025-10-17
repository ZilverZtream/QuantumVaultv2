#pragma once

// TSK710_Implement_Hidden_Volumes hidden volume descriptor definitions

#include <array>
#include <span>
#include <vector>
#include <cstdint>

#include "qv/common.h"
#include "qv/crypto/aes_gcm.h"

namespace qv::core {

struct HiddenVolumeDescriptor { // TSK710_Implement_Hidden_Volumes protected inner layout descriptor
  uint64_t start_offset{0};
  uint64_t length{0};
  uint32_t epoch{0};
  std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE> nonce{};
  std::array<uint8_t, qv::crypto::AES256_GCM::TAG_SIZE> tag{};
};

std::array<uint8_t, qv::crypto::AES256_GCM::KEY_SIZE> // TSK710_Implement_Hidden_Volumes derive AEAD key
DeriveHiddenVolumeKey(std::span<const uint8_t> password,
                      std::span<const uint8_t, 16> container_uuid);

bool VerifyHiddenVolumeDescriptor( // TSK710_Implement_Hidden_Volumes authenticate descriptor contents
    const HiddenVolumeDescriptor& descriptor,
    std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE> key,
    uint32_t expected_epoch,
    std::span<const uint8_t, 16> container_uuid);

struct IntegrityRoot { // TSK715_Header_Integrity_Chain_and_qv-fsck Merkle binding for metadata
  std::array<uint8_t, 32> merkle_root{};
  uint64_t generation{0};
  std::array<uint8_t, 32> parity{};
  bool parity_valid{false};
};

IntegrityRoot ParseIntegrityRoot(std::span<const uint8_t> payload); // TSK715_Header_Integrity_Chain_and_qv-fsck decode TLV payload
std::vector<uint8_t> SerializeIntegrityRoot(const IntegrityRoot& root); // TSK715_Header_Integrity_Chain_and_qv-fsck encode TLV payload
bool WriteIntegrityRoot(std::span<uint8_t> payload, const IntegrityRoot& root); // TSK715_Header_Integrity_Chain_and_qv-fsck fixed-buffer encode

}  // namespace qv::core

