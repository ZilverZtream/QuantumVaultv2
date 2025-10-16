#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <vector>

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

struct Extent { // TSK710_Implement_Hidden_Volumes protected region description
  uint64_t offset{0};
  uint64_t length{0};

  [[nodiscard]] bool empty() const noexcept { return length == 0; }

  [[nodiscard]] uint64_t EndExclusive() const noexcept {
    if (length == 0) {
      return offset;
    }
    const uint64_t max_value = std::numeric_limits<uint64_t>::max();
    if (offset > max_value - (length - 1)) {
      return max_value;
    }
    return offset + length;
  }

  [[nodiscard]] bool Intersects(uint64_t other_offset, uint64_t other_length) const noexcept {
    if (length == 0 || other_length == 0) {
      return false;
    }
    const uint64_t end = EndExclusive();
    const Extent other{other_offset, other_length};
    const uint64_t other_end = other.EndExclusive();
    return !(other_end <= offset || end <= other_offset);
  }
};

inline void NormalizeExtents(std::vector<Extent>& extents) { // TSK710_Implement_Hidden_Volumes merge map
  extents.erase(std::remove_if(extents.begin(), extents.end(),
                               [](const Extent& e) { return e.empty(); }),
                extents.end());
  std::sort(extents.begin(), extents.end(),
            [](const Extent& lhs, const Extent& rhs) {
              if (lhs.offset == rhs.offset) {
                return lhs.length < rhs.length;
              }
              return lhs.offset < rhs.offset;
            });
  std::vector<Extent> merged;
  merged.reserve(extents.size());
  for (const auto& extent : extents) {
    if (extent.empty()) {
      continue;
    }
    if (merged.empty()) {
      merged.push_back(extent);
      continue;
    }
    auto& last = merged.back();
    const uint64_t last_end = last.EndExclusive();
    if (extent.offset <= last_end) {
      const uint64_t candidate_end = extent.EndExclusive();
      if (candidate_end > last_end) {
        const uint64_t new_length = candidate_end - last.offset;
        last.length = new_length;
      }
    } else {
      merged.push_back(extent);
    }
  }
  extents.swap(merged);
}

}  // namespace qv::storage

