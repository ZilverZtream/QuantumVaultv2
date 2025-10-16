#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <shared_mutex> // TSK710_Implement_Hidden_Volumes guard protected regions
#include <span>
#include <vector>

#include "qv/common.h"
#include "qv/crypto/aegis.h"
#include "qv/error.h"
#include "qv/storage/chunk_layout.h"
#include "qv/crypto/hmac_sha256.h"  // TSK121_Missing_Authentication_in_Metadata derive metadata MAC key

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

  void Flush();  // TSK131_Missing_Flush_on_Close ensure pending writes reach the container

  std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> MetadataMacKey() const {
    return metadata_mac_key_;  // TSK121_Missing_Authentication_in_Metadata expose derived metadata MAC key
  }

  void SetProtectedExtents(std::vector<Extent> exts);              // TSK710_Implement_Hidden_Volumes guard configuration
  [[nodiscard]] bool IsProtected(uint64_t offset, uint64_t length) const; // TSK710_Implement_Hidden_Volumes query helper

private:
  std::filesystem::path path_;
  std::array<uint8_t, 32> master_key_{};
  uint32_t epoch_{0};
  qv::crypto::CipherType default_cipher_{qv::crypto::CipherType::AES_256_GCM};
  std::fstream file_;
  uint64_t record_size_{sizeof(ChunkHeader) + kChunkSize};
  std::mutex io_mutex_;
  mutable std::shared_mutex protected_mutex_; // TSK710_Implement_Hidden_Volumes shared guard
  std::vector<Extent> protected_extents_;      // TSK710_Implement_Hidden_Volumes protected map

  std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> metadata_mac_key_{};  // TSK121_Missing_Authentication_in_Metadata cached metadata authenticator

  void EnsureOpenUnlocked();
  void EnsureSizeUnlocked(uint64_t size);
  uint64_t ByteOffsetForChunk(int64_t chunk_index) const; // TSK107_Platform_Specific_Issues 64-bit offsets
  std::streampos OffsetForChunk(int64_t chunk_index) const;
};

}  // namespace qv::storage

