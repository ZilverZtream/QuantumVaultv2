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
    uint64_t expected_sequence,
    uint64_t now_seconds,
    uint64_t max_age_seconds,
    std::span<const uint8_t, 16> container_uuid,
    std::span<const uint8_t, 16> expected_binding) {
  if (descriptor.length == 0) {
    return false;
  }
  if (!container_uuid.data()) {
    return false;
  }
  if (!expected_binding.data()) {
    return false;
  }
  if (descriptor.epoch != expected_epoch) {
    return false;
  }
  if (descriptor.sequence_number != expected_sequence) {
    return false;
  }
  if (max_age_seconds == 0) {
    return false;
  }
  if (descriptor.created_timestamp > now_seconds) {
    return false;
  }
  if (now_seconds - descriptor.created_timestamp > max_age_seconds) {
    return false;
  }
  if (!std::equal(descriptor.system_binding.begin(), descriptor.system_binding.end(), expected_binding.begin(),
                  expected_binding.end())) {
    return false;
  }

  std::array<uint8_t, sizeof(uint64_t) * 4 + sizeof(uint32_t) + container_uuid.size() + expected_binding.size()> aad{};
  uint64_t start_le = qv::ToLittleEndian64(descriptor.start_offset);
  uint64_t length_le = qv::ToLittleEndian64(descriptor.length);
  uint32_t epoch_le = qv::ToLittleEndian(descriptor.epoch);
  uint64_t seq_le = qv::ToLittleEndian64(descriptor.sequence_number);
  uint64_t ts_le = qv::ToLittleEndian64(descriptor.created_timestamp);
  std::memcpy(aad.data(), &start_le, sizeof(start_le));
  std::memcpy(aad.data() + sizeof(start_le), &length_le, sizeof(length_le));
  std::memcpy(aad.data() + sizeof(start_le) + sizeof(length_le), &epoch_le, sizeof(epoch_le));
  std::memcpy(aad.data() + sizeof(start_le) + sizeof(length_le) + sizeof(epoch_le), &seq_le, sizeof(seq_le));
  std::memcpy(aad.data() + sizeof(start_le) + sizeof(length_le) + sizeof(epoch_le) + sizeof(seq_le), &ts_le,
              sizeof(ts_le));
  const size_t binding_offset = sizeof(start_le) + sizeof(length_le) + sizeof(epoch_le) + sizeof(seq_le) + sizeof(ts_le);
  std::memcpy(aad.data() + binding_offset, expected_binding.data(), expected_binding.size());
  std::memcpy(aad.data() + binding_offset + expected_binding.size(), container_uuid.data(), container_uuid.size());

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

IntegrityRoot ParseIntegrityRoot(std::span<const uint8_t> payload) { // TSK715_Header_Integrity_Chain_and_qv-fsck decode helper
  IntegrityRoot root{};
  if (payload.size() < root.merkle_root.size()) {
    return root;
  }
  std::copy_n(payload.begin(), root.merkle_root.size(), root.merkle_root.begin());

  if (payload.size() >= root.merkle_root.size() + sizeof(uint64_t)) {
    uint64_t gen_le = 0;
    std::memcpy(&gen_le, payload.data() + root.merkle_root.size(), sizeof(uint64_t));
    root.generation = qv::FromLittleEndian64(gen_le);
  }

  const size_t parity_flag_offset = root.merkle_root.size() + sizeof(uint64_t);
  if (payload.size() > parity_flag_offset) {
    const bool parity_present = payload[parity_flag_offset] != 0;
    const size_t parity_offset = parity_flag_offset + 1;
    if (parity_present && payload.size() >= parity_offset + root.parity.size()) {
      std::copy_n(payload.begin() + parity_offset, root.parity.size(), root.parity.begin());
      root.parity_valid = true;
    }
  }

  return root;
}

std::vector<uint8_t> SerializeIntegrityRoot(const IntegrityRoot& root) { // TSK715_Header_Integrity_Chain_and_qv-fsck encode helper
  const size_t base_size = root.merkle_root.size() + sizeof(uint64_t) + 1;
  const size_t total_size = base_size + (root.parity_valid ? root.parity.size() : 0);
  std::vector<uint8_t> buffer(total_size, 0);
  std::copy(root.merkle_root.begin(), root.merkle_root.end(), buffer.begin());
  const uint64_t gen_le = qv::ToLittleEndian64(root.generation);
  std::memcpy(buffer.data() + root.merkle_root.size(), &gen_le, sizeof(gen_le));
  buffer[root.merkle_root.size() + sizeof(uint64_t)] = root.parity_valid ? 1 : 0;
  if (root.parity_valid) {
    std::copy(root.parity.begin(), root.parity.end(),
              buffer.begin() + base_size);
  }
  return buffer;
}

bool WriteIntegrityRoot(std::span<uint8_t> payload,
                        const IntegrityRoot& root) { // TSK715_Header_Integrity_Chain_and_qv-fsck fixed-buffer encode
  const size_t required = root.merkle_root.size() + sizeof(uint64_t) + 1 +
                          (root.parity_valid ? root.parity.size() : 0);
  if (payload.size() < required) {
    return false;
  }
  const auto encoded = SerializeIntegrityRoot(root);
  std::copy(encoded.begin(), encoded.end(), payload.begin());
  if (payload.size() > encoded.size()) {
    std::fill(payload.begin() + encoded.size(), payload.end(), 0);
  }
  return true;
}

}  // namespace qv::core

