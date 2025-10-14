#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <span>
#include <vector>

#include "qv/common.h"
#include "qv/crypto/aegis.h"
#include "qv/error.h"
#include "qv/storage/chunk_layout.h"

namespace qv::storage {

// TSK061_Block_Device_and_Chunk_Storage_Engine
struct ChunkReadResult {
  ChunkHeader header;
  std::vector<uint8_t> ciphertext;
};

class BlockDevice {
public:
  BlockDevice(const std::filesystem::path& container_path,
              std::array<uint8_t, 32> master_key,
              uint32_t epoch,
              uint64_t volume_size,
              qv::crypto::CipherType default_cipher);
  ~BlockDevice();

  BlockDevice(const BlockDevice&) = delete;
  BlockDevice& operator=(const BlockDevice&) = delete;

  void WriteChunk(const ChunkHeader& header, std::span<const uint8_t> ciphertext);
  ChunkReadResult ReadChunk(int64_t chunk_index);

  uint64_t RecordSize() const { return record_size_; }

private:
  std::filesystem::path path_;
  std::array<uint8_t, 32> master_key_{};
  uint32_t epoch_{0};
  qv::crypto::CipherType default_cipher_{qv::crypto::CipherType::AES_256_GCM};
  std::fstream file_;
  uint64_t record_size_{sizeof(ChunkHeader) + kChunkSize};
  std::mutex io_mutex_;

  void EnsureOpenUnlocked();
  void EnsureSizeUnlocked(uint64_t size);
  std::streampos OffsetForChunk(int64_t chunk_index) const;
};

}  // namespace qv::storage

