#include "qv/storage/block_device.h"

#include <cstring>
#include <filesystem>
#include <fstream>

namespace qv::storage {

// TSK061_Block_Device_and_Chunk_Storage_Engine

namespace {
constexpr uint64_t kHeaderSize = sizeof(ChunkHeader);
constexpr uint64_t kPayloadSize = kChunkSize;
}  // namespace

BlockDevice::BlockDevice(const std::filesystem::path& container_path,
                         std::array<uint8_t, 32> master_key,
                         uint32_t epoch,
                         uint64_t /*volume_size*/,
                         qv::crypto::CipherType default_cipher)
    : path_(container_path),
      master_key_(master_key),
      epoch_(epoch),
      default_cipher_(default_cipher),
      record_size_(kHeaderSize + kPayloadSize) {
  EnsureOpenUnlocked();
}

BlockDevice::~BlockDevice() {
  if (file_.is_open()) {
    file_.flush();
    file_.close();
  }
}

void BlockDevice::EnsureOpenUnlocked() {
  if (file_.is_open()) {
    return;
  }
  if (!std::filesystem::exists(path_)) {
    std::ofstream create(path_, std::ios::binary | std::ios::trunc);
    if (!create) {
      throw Error{ErrorDomain::IO, 0,
                  "Failed to create container file: " + PathToUtf8String(path_)};
    }
  }
  file_.open(path_, std::ios::binary | std::ios::in | std::ios::out);
  if (!file_) {
    throw Error{ErrorDomain::IO, 0,
                "Failed to open container file: " + PathToUtf8String(path_)};
  }
}

void BlockDevice::EnsureSizeUnlocked(uint64_t size) {
  auto current_size = std::filesystem::exists(path_) ? std::filesystem::file_size(path_) : 0ULL;
  if (current_size >= size) {
    return;
  }
  std::filesystem::resize_file(path_, size);
}

std::streampos BlockDevice::OffsetForChunk(int64_t chunk_index) const {
  if (chunk_index < 0) {
    throw Error{ErrorDomain::Validation, 0, "Negative chunk index"};
  }
  return static_cast<std::streampos>(static_cast<uint64_t>(chunk_index) * record_size_);
}

void BlockDevice::WriteChunk(const ChunkHeader& header, std::span<const uint8_t> ciphertext) {
  if (ciphertext.size() != kPayloadSize) {
    throw Error{ErrorDomain::Validation, 0, "Ciphertext must be exactly one chunk"};
  }
  std::scoped_lock lock(io_mutex_);
  EnsureOpenUnlocked();
  auto offset = OffsetForChunk(header.chunk_index);
  EnsureSizeUnlocked(static_cast<uint64_t>(offset) + record_size_);
  file_.seekp(offset);
  if (!file_) {
    throw Error{ErrorDomain::IO, 0, "Failed to seek for write"};
  }
  file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
  file_.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
  file_.flush();
  if (!file_) {
    throw Error{ErrorDomain::IO, 0, "Failed to write chunk"};
  }
}

ChunkReadResult BlockDevice::ReadChunk(int64_t chunk_index) {
  std::scoped_lock lock(io_mutex_);
  EnsureOpenUnlocked();
  auto offset = OffsetForChunk(chunk_index);
  file_.seekg(offset);
  if (!file_) {
    throw Error{ErrorDomain::IO, 0, "Failed to seek for read"};
  }
  ChunkReadResult result{};
  result.ciphertext.resize(kPayloadSize);
  file_.read(reinterpret_cast<char*>(&result.header), sizeof(result.header));
  if (file_.gcount() != static_cast<std::streamsize>(sizeof(result.header))) {
    throw Error{ErrorDomain::IO, 0, "Failed to read chunk header"};
  }
  file_.read(reinterpret_cast<char*>(result.ciphertext.data()), result.ciphertext.size());
  if (file_.gcount() != static_cast<std::streamsize>(result.ciphertext.size())) {
    throw Error{ErrorDomain::IO, 0, "Failed to read chunk payload"};
  }
  return result;
}

}  // namespace qv::storage

