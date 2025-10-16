#pragma once

// TSK710_Implement_Hidden_Volumes hidden volume descriptor definitions

#include <array>
#include <span>
#include <vector>

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

}  // namespace qv::core

