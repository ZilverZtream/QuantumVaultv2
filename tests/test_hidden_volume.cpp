#include "qv/platform/volume_filesystem.h"

#include <array>
#include <cerrno>
#include <filesystem>
#include <iostream>
#include <optional>
#include <vector>

#include "qv/crypto/aes_gcm.h"
#include "qv/error.h"
#include "qv/storage/block_device.h"
#include "qv/storage/chunk_layout.h"

int main() {
  using qv::storage::Extent;
  const auto temp_dir = std::filesystem::temp_directory_path();

  // TSK710_Implement_Hidden_Volumes ensure decoy guard rejects writes into protected extent
  const auto guard_container = temp_dir / "qv_hidden_guard.container";
  if (std::filesystem::exists(guard_container)) {
    std::filesystem::remove(guard_container);
  }
  {
    std::array<uint8_t, 32> master_key{};
    qv::storage::BlockDevice device(guard_container, master_key, 1, 0,
                                    qv::crypto::CipherType::AES_256_GCM);
    device.SetProtectedExtents({Extent{0, qv::storage::kChunkSize}});
    qv::storage::ChunkHeader header{};
    header.chunk_index = 0;
    header.logical_offset = 0;
    header.epoch = 1;
    header.data_size = static_cast<uint32_t>(qv::storage::kChunkSize);
    std::vector<uint8_t> payload(qv::storage::kChunkSize, 0u);
    bool rejected = false;
    try {
      device.WriteChunk(header, payload);
    } catch (const qv::Error& error) {
      if (error.domain == qv::ErrorDomain::Fs && error.native_code &&
          *error.native_code == EROFS) {
        rejected = true;
      } else {
        std::cerr << "unexpected error: " << error.message << std::endl;
        return 1;
      }
    }
    if (!rejected) {
      std::cerr << "protected write was not rejected" << std::endl;
      return 1;
    }
  }
  std::filesystem::remove(guard_container);

  // TSK710_Implement_Hidden_Volumes verify hidden layout enforces capacity limits
  const auto hidden_container = temp_dir / "qv_hidden_region.container";
  if (std::filesystem::exists(hidden_container)) {
    std::filesystem::remove(hidden_container);
  }
  std::array<uint8_t, 32> master_key{};
  auto device = std::make_shared<qv::storage::BlockDevice>(
      hidden_container, master_key, 2, 0, qv::crypto::CipherType::AES_256_GCM);

  constexpr uint64_t kMetadataBytes = 1024ull * 1024ull;
  const uint64_t chunk_size = qv::storage::kChunkSize;
  const uint64_t metadata_chunks = (kMetadataBytes + chunk_size - 1) / chunk_size;
  const uint64_t total_chunks = metadata_chunks + 4;  // leave three data chunks
  Extent hidden_region{chunk_size * 2, total_chunks * chunk_size};

  qv::platform::VolumeFilesystem filesystem(device, hidden_region);
  filesystem.CreateFileNode("/inner", 0644, 0, 0);

  std::vector<uint8_t> oversized(chunk_size * 4, 0xAB);
  bool exhausted = false;
  try {
    filesystem.WriteFileRange("/inner", 0, oversized);
  } catch (const qv::Error& error) {
    if (error.domain == qv::ErrorDomain::Fs && error.native_code &&
        *error.native_code == ENOSPC) {
      exhausted = true;
    } else {
      std::cerr << "unexpected hidden write error: " << error.message << std::endl;
      return 1;
    }
  }
  if (!exhausted) {
    std::cerr << "hidden region exhaustion was not reported" << std::endl;
    return 1;
  }

  std::filesystem::remove(hidden_container);
  std::cout << "hidden volume guards ok" << std::endl;
  return 0;
}
