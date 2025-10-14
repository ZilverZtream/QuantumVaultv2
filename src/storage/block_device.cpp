#include "qv/storage/block_device.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <vector>

namespace qv::storage {

// TSK061_Block_Device_and_Chunk_Storage_Engine

namespace {
constexpr uint64_t kHeaderSize = sizeof(ChunkHeader);
constexpr uint64_t kPayloadSize = kChunkSize;

// TSK078_Chunk_Integrity_and_Bounds: CRC32 implementation for chunk headers.
constexpr uint32_t kCRC32Polynomial = 0xEDB88320u;

constexpr std::array<uint32_t, 256> MakeCRC32Table() {
  std::array<uint32_t, 256> table{};
  for (uint32_t i = 0; i < table.size(); ++i) {
    uint32_t value = i;
    for (uint32_t bit = 0; bit < 8; ++bit) {
      if (value & 1u) {
        value = (value >> 1) ^ kCRC32Polynomial;
      } else {
        value >>= 1;
      }
    }
    table[i] = value;
  }
  return table;
}

constexpr std::array<uint32_t, 256> kCRC32Table = MakeCRC32Table();

uint32_t ComputeCRC32(std::span<const uint8_t> data) {
  uint32_t crc = 0xFFFFFFFFu;
  for (auto byte : data) {
    uint32_t index = (crc ^ static_cast<uint32_t>(byte)) & 0xFFu;
    crc = (crc >> 8) ^ kCRC32Table[index];
  }
  return crc ^ 0xFFFFFFFFu;
}

uint32_t ExtractStoredCRC(const ChunkHeader& header) {
  uint32_t stored = 0;
  std::memcpy(&stored, header.reserved.data(), sizeof(stored));
  if (!qv::kIsLittleEndian) {
    stored = qv::detail::ByteSwap32(stored);  // NOLINT(bugprone-narrowing-conversions)
  }
  return stored;
}

uint32_t ComputeHeaderCRC(const ChunkHeader& header) {
  ChunkHeader copy = header;
  std::fill(copy.reserved.begin(), copy.reserved.end(), 0);
  auto header_bytes = qv::AsBytesConst(copy);
  return ComputeCRC32(std::span<const uint8_t>(header_bytes.data(), header_bytes.size()));
}

ChunkHeader PrepareHeaderForWrite(const ChunkHeader& header) {
  ChunkHeader prepared = header;
  std::fill(prepared.reserved.begin(), prepared.reserved.end(), 0);
  const uint32_t crc = ComputeHeaderCRC(prepared);
  uint32_t stored = qv::ToLittleEndian(crc);
  std::memcpy(prepared.reserved.data(), &stored, sizeof(stored));
  return prepared;
}

void VerifyHeaderCRCOrThrow(ChunkHeader& header) {
  const uint32_t stored = ExtractStoredCRC(header);
  ChunkHeader sanitized = header;
  std::fill(sanitized.reserved.begin(), sanitized.reserved.end(), 0);
  const uint32_t computed = ComputeHeaderCRC(sanitized);
  if (stored != computed) {
    throw Error{ErrorDomain::Validation, 0, "Chunk header CRC mismatch"};
  }
  header = sanitized;
}
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
  const uint64_t base_offset = static_cast<uint64_t>(static_cast<std::streamoff>(offset));
  const uint64_t current_size =
      std::filesystem::exists(path_) ? std::filesystem::file_size(path_) : 0ULL;
  const uint64_t final_size = std::max<uint64_t>(base_offset + record_size_, current_size);
  const uint64_t staging_offset_value = final_size;

  ChunkHeader prepared_header = PrepareHeaderForWrite(header);  // TSK078_Chunk_Integrity_and_Bounds
  std::vector<uint8_t> record(static_cast<size_t>(record_size_));
  std::memcpy(record.data(), &prepared_header, sizeof(prepared_header));
  std::memcpy(record.data() + sizeof(prepared_header), ciphertext.data(), ciphertext.size());

  EnsureSizeUnlocked(staging_offset_value + record_size_);

  auto write_buffer = [&](std::streampos position) {
    file_.seekp(position);
    if (!file_) {
      throw Error{ErrorDomain::IO, 0, "Failed to seek for write"};
    }
    file_.write(reinterpret_cast<const char*>(record.data()), static_cast<std::streamsize>(record.size()));
    file_.flush();
    if (!file_) {
      throw Error{ErrorDomain::IO, 0, "Failed to write chunk"};
    }
  };

  write_buffer(static_cast<std::streampos>(staging_offset_value));  // TSK078_Chunk_Integrity_and_Bounds
  write_buffer(offset);
  std::filesystem::resize_file(path_, final_size);  // TSK078_Chunk_Integrity_and_Bounds
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
  VerifyHeaderCRCOrThrow(result.header);  // TSK078_Chunk_Integrity_and_Bounds
  return result;
}

}  // namespace qv::storage

