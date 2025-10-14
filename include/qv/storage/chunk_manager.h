#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

#include "qv/core/nonce.h"
#include "qv/crypto/aegis.h"
#include "qv/storage/block_device.h"

namespace qv::storage {

// TSK061_Block_Device_and_Chunk_Storage_Engine
class ChunkManager {
public:
  ChunkManager(const std::filesystem::path& container,
               std::array<uint8_t, 32> master_key,
               uint32_t epoch,
               qv::crypto::CipherType cipher = qv::crypto::CipherType::AEGIS_128X);

  void WriteChunk(uint64_t logical_offset, std::span<const uint8_t> data);
  std::vector<uint8_t> ReadChunk(uint64_t logical_offset);

  qv::crypto::CipherType ActiveCipher() const { return cipher_; }

private:
  std::filesystem::path container_;
  std::array<uint8_t, 32> master_key_{};
  std::array<uint8_t, 32> data_key_{};
  uint32_t epoch_{0};
  qv::crypto::CipherType cipher_{qv::crypto::CipherType::AES_256_GCM};
  qv::core::NonceGenerator nonce_generator_;
  BlockDevice device_;

  std::vector<uint8_t> MakeNonce(const qv::core::NonceGenerator::NonceRecord& record,
                                 int64_t chunk_index) const;
  qv::crypto::CipherType ResolveCipher(qv::crypto::CipherType requested) const;
};

}  // namespace qv::storage

