#include "qv/core/header.h"

// TSK710_Implement_Hidden_Volumes hidden volume descriptor verification logic

#include <algorithm>
#include <array>
#include <cstring>
#include <string_view>
#include <vector>

#include "qv/crypto/aes_gcm.h"
#include "qv/crypto/hkdf.h"
#include "qv/error.h"

namespace qv::core {

namespace {
constexpr std::string_view kHiddenInfoLabel{"QV-HIDDEN/v1"}; // TSK710_Implement_Hidden_Volumes binding label

std::array<uint8_t, qv::crypto::AES256_GCM::KEY_SIZE> MakeZeroKey() {
  std::array<uint8_t, qv::crypto::AES256_GCM::KEY_SIZE> key{};
  key.fill(0u);
  return key;
}

}  // namespace

std::array<uint8_t, qv::crypto::AES256_GCM::KEY_SIZE> DeriveHiddenVolumeKey(
    std::span<const uint8_t> password, std::span<const uint8_t, 16> container_uuid) {
  if (password.empty()) {
    return MakeZeroKey();
  }
  auto key = qv::crypto::HKDF_SHA256(password, container_uuid,
                                     std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(kHiddenInfoLabel.data()),
                                                             kHiddenInfoLabel.size())); // TSK710_Implement_Hidden_Volumes HKDF derivation
  return key;
}

bool VerifyHiddenVolumeDescriptor(
    const HiddenVolumeDescriptor& descriptor,
    std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE> key,
    uint32_t expected_epoch,
    std::span<const uint8_t, 16> container_uuid) {
  if (descriptor.length == 0) {
    return false;
  }
  if (!container_uuid.data()) {
    return false;
  }
  if (descriptor.epoch != expected_epoch) {
    return false;
  }

  std::array<uint8_t, sizeof(uint64_t) * 2 + sizeof(uint32_t) + container_uuid.size()> aad{};
  uint64_t start_le = qv::ToLittleEndian64(descriptor.start_offset);
  uint64_t length_le = qv::ToLittleEndian64(descriptor.length);
  uint32_t epoch_le = qv::ToLittleEndian(descriptor.epoch);
  std::memcpy(aad.data(), &start_le, sizeof(start_le));
  std::memcpy(aad.data() + sizeof(start_le), &length_le, sizeof(length_le));
  std::memcpy(aad.data() + sizeof(start_le) + sizeof(length_le), &epoch_le, sizeof(epoch_le));
  std::memcpy(aad.data() + sizeof(start_le) + sizeof(length_le) + sizeof(epoch_le), container_uuid.data(),
              container_uuid.size());

  try {
    auto nonce = descriptor.nonce;
    auto tag = descriptor.tag;
    auto plaintext = qv::crypto::AES256_GCM_Decrypt(
        std::span<const uint8_t>(),
        std::span<const uint8_t>(aad.data(), aad.size()),
        std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce),
        std::span<const uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>(tag), key);
    return plaintext.empty();
  } catch (const qv::AuthenticationFailureError&) { // TSK710_Implement_Hidden_Volumes strict AEAD validation
    return false;
  }
}

}  // namespace qv::core

