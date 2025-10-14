#include "qv/common.h" // TSK040_AAD_Binding_and_Chunk_Authentication serialization helper
#include "qv/core/nonce.h"
#include "qv/crypto/aes_gcm.h"
#include "qv/error.h" // TSK040_AAD_Binding_and_Chunk_Authentication tamper detection

#include <array>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <span>
#include <vector>

int main() {

  std::filesystem::remove("qv_nonce.log");      // TSK040_AAD_Binding_and_Chunk_Authentication clean slate
  std::filesystem::remove("qv_nonce.log.wal");  // TSK040

  qv::core::NonceGenerator nonce_gen(42, 0);     // TSK040
  std::array<uint8_t, qv::crypto::AES256_GCM::KEY_SIZE> data_key{};
  for (size_t i = 0; i < data_key.size(); ++i) { // TSK040 deterministic keying for reproducible test
    data_key[i] = static_cast<uint8_t>(i);
  }

  std::vector<uint8_t> plaintext(4096);
  for (size_t i = 0; i < plaintext.size(); ++i) { // TSK040
    plaintext[i] = static_cast<uint8_t>((i * 17) & 0xFF);
  }

  constexpr uint32_t kEpoch = 42;                 // TSK040
  constexpr int64_t kChunkIndex = 3;              // TSK040
  constexpr uint64_t kLogicalOffset = 8192;       // TSK040
  const uint32_t chunk_size = static_cast<uint32_t>(plaintext.size()); // TSK040

  auto nonce_record = nonce_gen.NextAuthenticated(); // TSK040 bind nonce log
  auto envelope = qv::core::MakeChunkAAD(kEpoch, kChunkIndex, kLogicalOffset, chunk_size,
                                         nonce_record.mac); // TSK040
  auto enc_result = qv::crypto::AES256_GCM_Encrypt(
      std::span<const uint8_t>(plaintext.data(), plaintext.size()),
      qv::AsBytesConst(envelope),
      std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce_record.nonce.data(),
                                                                   nonce_record.nonce.size()),
      std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(data_key.data(), data_key.size()));

  auto recovered = qv::crypto::AES256_GCM_Decrypt(
      std::span<const uint8_t>(enc_result.ciphertext.data(), enc_result.ciphertext.size()),
      qv::AsBytesConst(envelope),
      std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce_record.nonce.data(),
                                                                   nonce_record.nonce.size()),
      std::span<const uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>(enc_result.tag.data(),
                                                                 enc_result.tag.size()),
      std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(data_key.data(), data_key.size()));
  assert(recovered == plaintext && "chunk round-trip must succeed"); // TSK040

  auto metadata_envelope = qv::core::MakeMetadataAAD(
      kEpoch, kChunkIndex, kLogicalOffset, chunk_size,
      envelope.nonce_chain_mac); // TSK040 ensure context separation
  bool metadata_rejected = false;
  try {
    (void)qv::crypto::AES256_GCM_Decrypt(
        std::span<const uint8_t>(enc_result.ciphertext.data(), enc_result.ciphertext.size()),
        qv::AsBytesConst(metadata_envelope),
        std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce_record.nonce.data(),
                                                                     nonce_record.nonce.size()),
        std::span<const uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>(enc_result.tag.data(),
                                                                   enc_result.tag.size()),
        std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(data_key.data(), data_key.size()));
  } catch (const qv::AuthenticationFailureError&) {
    metadata_rejected = true;
  }
  assert(metadata_rejected && "metadata context must reject chunk ciphertext"); // TSK040

  auto manifest_envelope = qv::core::MakeManifestAAD(
      kEpoch, kChunkIndex, kLogicalOffset, chunk_size,
      envelope.nonce_chain_mac); // TSK040 cross-context rejection
  bool manifest_rejected = false;
  try {
    (void)qv::crypto::AES256_GCM_Decrypt(
        std::span<const uint8_t>(enc_result.ciphertext.data(), enc_result.ciphertext.size()),
        qv::AsBytesConst(manifest_envelope),
        std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce_record.nonce.data(),
                                                                     nonce_record.nonce.size()),
        std::span<const uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>(enc_result.tag.data(),
                                                                   enc_result.tag.size()),
        std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(data_key.data(), data_key.size()));
  } catch (const qv::AuthenticationFailureError&) {
    manifest_rejected = true;
  }
  assert(manifest_rejected && "manifest context must reject chunk ciphertext"); // TSK040

  auto tampered_mac = envelope; // TSK040 clone to mutate MAC
  tampered_mac.nonce_chain_mac[0] ^= 0xFF; // TSK040 bind nonce log chain
  bool mac_rejected = false;
  try {
    (void)qv::crypto::AES256_GCM_Decrypt(
        std::span<const uint8_t>(enc_result.ciphertext.data(), enc_result.ciphertext.size()),
        qv::AsBytesConst(tampered_mac),
        std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce_record.nonce.data(),
                                                                     nonce_record.nonce.size()),
        std::span<const uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>(enc_result.tag.data(),
                                                                   enc_result.tag.size()),
        std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(data_key.data(), data_key.size()));
  } catch (const qv::AuthenticationFailureError&) {
    mac_rejected = true;
  }
  assert(mac_rejected && "nonce MAC tampering must be detected"); // TSK040

  bool offset_rejected = false;
  try {
    auto wrong_offset = qv::core::MakeChunkAAD(kEpoch, kChunkIndex, kLogicalOffset + 512, chunk_size,
                                               nonce_record.mac); // TSK040 offset bind
    (void)qv::crypto::AES256_GCM_Decrypt(
        std::span<const uint8_t>(enc_result.ciphertext.data(), enc_result.ciphertext.size()),
        qv::AsBytesConst(wrong_offset),
        std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce_record.nonce.data(),
                                                                     nonce_record.nonce.size()),
        std::span<const uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>(enc_result.tag.data(),
                                                                   enc_result.tag.size()),
        std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(data_key.data(), data_key.size()));
  } catch (const qv::AuthenticationFailureError&) {
    offset_rejected = true;
  }
  assert(offset_rejected && "logical offset mismatch must trigger authentication failure"); // TSK040

  std::cout << "chunk aad authentication ok\n";
  return 0;
}
