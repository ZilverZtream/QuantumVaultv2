#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <shared_mutex> // TSK118_Nonce_Reuse_Vulnerabilities
#include <span>
#include <vector>

#include "qv/core/nonce.h"
#include "qv/crypto/aegis.h"
#include "qv/storage/block_device.h"
#include "qv/storage/chunk_cache.h"
#include "qv/storage/read_ahead.h"

namespace qv::storage {

// TSK061_Block_Device_and_Chunk_Storage_Engine
class ChunkManager {
public:
  ChunkManager(const std::filesystem::path& container,
               std::array<uint8_t, 32> master_key,
               uint32_t epoch,
               qv::crypto::CipherType cipher = qv::crypto::CipherType::AEGIS_128X);
  ~ChunkManager(); // TSK125_Missing_Secure_Deletion_for_Keys explicit key wiping

  void WriteChunk(uint64_t logical_offset, std::span<const uint8_t> data);
  std::vector<uint8_t> ReadChunk(uint64_t logical_offset, bool for_prefetch = false);

  void Flush();  // TSK064_Performance_Optimization_and_Caching

  qv::crypto::CipherType ActiveCipher() const { return cipher_; }

private:
  std::filesystem::path container_;
  std::array<uint8_t, 32> master_key_{};
  std::array<uint8_t, 32> data_key_{};
  uint32_t epoch_{0};
  qv::crypto::CipherType cipher_{qv::crypto::CipherType::AES_256_GCM};
  qv::core::NonceGenerator nonce_generator_;
  BlockDevice device_;
  ChunkCache cache_;
  std::unique_ptr<ReadAheadManager> read_ahead_;
  std::mutex sequential_mutex_;
  std::mutex persist_mutex_; // TSK067_Nonce_Safety
  mutable std::shared_mutex nonce_mutex_; // TSK118_Nonce_Reuse_Vulnerabilities generator guard
  mutable std::mutex nonce_freshness_mutex_; // TSK128_Missing_AAD_Validation_in_Chunks freshness guard
  int64_t last_read_chunk_{-1};
  uint64_t sequential_read_count_{0};
  int64_t read_ahead_window_end_{-1};
  uint64_t nonce_replay_floor_{0};          // TSK128_Missing_AAD_Validation_in_Chunks replay window tracking
  uint64_t nonce_high_watermark_{0};        // TSK128_Missing_AAD_Validation_in_Chunks observed counter max

  std::vector<uint8_t> MakeNonce(const qv::core::NonceGenerator::NonceRecord& record,
                                 int64_t chunk_index) const;
  qv::crypto::CipherType ResolveCipher(qv::crypto::CipherType requested) const;
  std::vector<uint8_t> ReadChunkFromDevice(int64_t chunk_index);
  void PersistChunk(int64_t chunk_index, const std::vector<uint8_t>& data);
  void HandleSequentialRead(int64_t chunk_index);
};

}  // namespace qv::storage

