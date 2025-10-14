#include "qv/storage/chunk_manager.h"

#include <algorithm>
#include <cstring>

#include "qv/common.h"
#include "qv/core/nonce.h"
#include "qv/crypto/aes_gcm.h"
#include "qv/security/zeroizer.h"

namespace qv::storage {

namespace {
// TSK061_Block_Device_and_Chunk_Storage_Engine
constexpr uint64_t kChunkPayloadSize = kChunkSize;

std::array<uint8_t, 32> DeriveChunkKey(std::span<const uint8_t, 32> master) {
  return qv::core::DeriveDataKey(master);
}

}  // namespace

ChunkManager::ChunkManager(const std::filesystem::path& container,
                           std::array<uint8_t, 32> master_key,
                           uint32_t epoch,
                           qv::crypto::CipherType cipher)
    : container_(container),
      master_key_(master_key),
      data_key_(DeriveChunkKey(master_key_)),
      epoch_(epoch),
      cipher_(ResolveCipher(cipher)),
      nonce_generator_(epoch_),
      device_(container_, master_key_, epoch_, 0, cipher_) {}

std::vector<uint8_t> ChunkManager::MakeNonce(const qv::core::NonceGenerator::NonceRecord& record,
                                             int64_t chunk_index) const {
  size_t required = 0;
  switch (cipher_) {
    case qv::crypto::CipherType::AEGIS_128X:
    case qv::crypto::CipherType::AEGIS_128L:
      required = qv::crypto::kAEGIS128LNonceSize;
      break;
    case qv::crypto::CipherType::AEGIS_256:
      required = qv::crypto::kAEGIS256NonceSize;
      break;
    case qv::crypto::CipherType::AES_256_GCM:
      required = qv::crypto::AES256_GCM::NONCE_SIZE;
      break;
    case qv::crypto::CipherType::CHACHA20_POLY1305:
      required = 12;
      break;
  }
  if (required == 0) {
    throw Error{ErrorDomain::Crypto, 0, "Unsupported cipher selection"};
  }
  std::vector<uint8_t> nonce(required, 0u);
  size_t copy_bytes = std::min<size_t>(record.nonce.size(), nonce.size());
  std::copy_n(record.nonce.begin(), copy_bytes, nonce.begin());
  uint64_t index_le = qv::core::ToLittleEndian64(static_cast<uint64_t>(chunk_index));
  auto* index_ptr = reinterpret_cast<const uint8_t*>(&index_le);
  for (size_t i = copy_bytes; i < nonce.size(); ++i) {
    size_t idx = (i - copy_bytes) % sizeof(index_le);
    nonce[i] = index_ptr[idx];
  }
  return nonce;
}

qv::crypto::CipherType ChunkManager::ResolveCipher(qv::crypto::CipherType requested) const {
  if (qv::crypto::CipherAvailable(requested)) {
    return requested;
  }
  if (requested == qv::crypto::CipherType::AEGIS_128X &&
      qv::crypto::CipherAvailable(qv::crypto::CipherType::AEGIS_128L)) {
    return qv::crypto::CipherType::AEGIS_128L;
  }
  if (qv::crypto::CipherAvailable(qv::crypto::CipherType::AEGIS_256)) {
    return qv::crypto::CipherType::AEGIS_256;
  }
  return qv::crypto::CipherType::AES_256_GCM;
}

void ChunkManager::WriteChunk(uint64_t logical_offset, std::span<const uint8_t> data) {
  if (data.size() > kChunkPayloadSize) {
    throw Error{ErrorDomain::Validation, 0, "Chunk write exceeds payload size"};
  }
  if (logical_offset % kChunkPayloadSize != 0) {
    throw Error{ErrorDomain::Validation, 0, "Logical offset must align with chunk size"};
  }
  int64_t chunk_index = static_cast<int64_t>(logical_offset / kChunkPayloadSize);
  auto nonce_record = nonce_generator_.NextAuthenticated();
  auto nonce = MakeNonce(nonce_record, chunk_index);
  std::array<uint8_t, kChunkPayloadSize> plaintext{};
  std::fill(plaintext.begin(), plaintext.end(), 0);
  std::copy(data.begin(), data.end(), plaintext.begin());
  auto aad_envelope = qv::core::MakeChunkAAD(epoch_, chunk_index, logical_offset,
                                             static_cast<uint32_t>(data.size()),
                                             nonce_record.mac);
  auto aad_bytes = qv::AsBytesConst(aad_envelope);
  auto encrypt_result = qv::crypto::AEAD_Encrypt(
      cipher_,
      std::span<const uint8_t>(plaintext.data(), plaintext.size()),
      aad_bytes,
      nonce,
      std::span<const uint8_t>(data_key_.data(), data_key_.size()));
  if (encrypt_result.ciphertext.size() != kChunkPayloadSize) {
    throw Error{ErrorDomain::Crypto, 0, "Encrypted chunk size mismatch"};
  }

  ChunkHeader header{};
  header.logical_offset = logical_offset;
  header.data_size = static_cast<uint32_t>(data.size());
  header.epoch = epoch_;
  header.chunk_index = chunk_index;
  std::fill(header.tag.begin(), header.tag.end(), 0);
  std::copy_n(encrypt_result.tag.begin(),
              std::min<size_t>(encrypt_result.tag.size(), header.tag.size()),
              header.tag.begin());
  std::fill(header.nonce.begin(), header.nonce.end(), 0);
  std::copy_n(nonce.begin(), std::min<size_t>(nonce.size(), header.nonce.size()), header.nonce.begin());
  std::copy(nonce_record.mac.begin(), nonce_record.mac.end(), header.aad_mac.begin());
  header.cipher_id = static_cast<uint8_t>(cipher_);
  header.tag_size = static_cast<uint8_t>(encrypt_result.tag.size());
  header.nonce_size = static_cast<uint8_t>(nonce.size());

  device_.WriteChunk(header, encrypt_result.ciphertext);

  qv::security::Zeroizer::Wipe(plaintext);
}

std::vector<uint8_t> ChunkManager::ReadChunk(uint64_t logical_offset) {
  if (logical_offset % kChunkPayloadSize != 0) {
    throw Error{ErrorDomain::Validation, 0, "Logical offset must align with chunk size"};
  }
  int64_t chunk_index = static_cast<int64_t>(logical_offset / kChunkPayloadSize);
  auto record = device_.ReadChunk(chunk_index);
  auto cipher = static_cast<qv::crypto::CipherType>(record.header.cipher_id);
  if (!qv::crypto::CipherAvailable(cipher) && cipher != qv::crypto::CipherType::AES_256_GCM) {
    throw Error{ErrorDomain::Crypto, 0, "Cipher unavailable for chunk"};
  }
  auto aad_envelope = qv::core::MakeChunkAAD(record.header.epoch,
                                             record.header.chunk_index,
                                             record.header.logical_offset,
                                             record.header.data_size,
                                             record.header.aad_mac);
  auto aad_bytes = qv::AsBytesConst(aad_envelope);
  if (record.header.nonce_size == 0 || record.header.nonce_size > record.header.nonce.size()) {
    throw Error{ErrorDomain::Validation, 0, "Invalid nonce size in header"};
  }
  if (record.header.tag_size == 0 || record.header.tag_size > record.header.tag.size()) {
    throw Error{ErrorDomain::Validation, 0, "Invalid tag size in header"};
  }
  auto nonce_span = std::span<const uint8_t>(record.header.nonce.data(), record.header.nonce_size);
  auto tag_span = std::span<const uint8_t>(record.header.tag.data(), record.header.tag_size);
  auto plaintext = qv::crypto::AEAD_Decrypt(
      cipher,
      record.ciphertext,
      aad_bytes,
      nonce_span,
      tag_span,
      std::span<const uint8_t>(data_key_.data(), data_key_.size()));
  if (plaintext.size() < record.header.data_size) {
    throw Error{ErrorDomain::Crypto, 0, "Decrypted payload truncated"};
  }
  plaintext.resize(record.header.data_size);
  return plaintext;
}

}  // namespace qv::storage

