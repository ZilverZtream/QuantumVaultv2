#pragma once

#include <array>
#include <cstdint>

#include "qv/crypto/aegis.h"

namespace qv::storage {

// TSK061_Block_Device_and_Chunk_Storage_Engine
constexpr size_t kChunkSize = 64 * 1024;
constexpr size_t kChunksPerGroup = 1024;

#pragma pack(push, 1)
struct ChunkHeader {
  uint64_t logical_offset;
  uint32_t data_size;
  uint32_t epoch;
  int64_t chunk_index;
  std::array<uint8_t, 32> tag;
  std::array<uint8_t, 32> nonce;
  std::array<uint8_t, 32> aad_mac;
  uint8_t cipher_id;
  uint8_t tag_size;
  uint8_t nonce_size;
  uint8_t reserved[5]{};
  uint32_t integrity_version{0};        // TSK122_Weak_CRC32_for_Chunk_Headers versioned MAC binding
  std::array<uint8_t, 32> header_mac{}; // TSK122_Weak_CRC32_for_Chunk_Headers dedicated MAC field
};
#pragma pack(pop)

static_assert(sizeof(ChunkHeader) == 160, "ChunkHeader must be 160 bytes"); // TSK122_Weak_CRC32_for_Chunk_Headers

#pragma pack(push, 1)
struct ChunkGroupHeader {
  std::array<uint8_t, 8> magic{'Q', 'V', 'C', 'H', 'U', 'N', 'K', '\0'};
  uint32_t version{1};
  uint32_t chunks_used{0};
  uint8_t default_cipher{static_cast<uint8_t>(qv::crypto::CipherType::AEGIS_128X)};
  uint8_t reserved[3]{};
  std::array<uint8_t, kChunksPerGroup / 8> allocation_bitmap{};
};
#pragma pack(pop)

}  // namespace qv::storage

