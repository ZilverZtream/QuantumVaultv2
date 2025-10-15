#include "qv/storage/block_device.h"

#include <algorithm>
#include <array>
#include <cstdint> // TSK107_Platform_Specific_Issues explicit 64-bit math
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <system_error> // TSK098_Exception_Safety_and_Resource_Leaks
#include <limits>       // TSK100_Integer_Overflow_and_Arithmetic overflow guards
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

class ResizeRollbackGuard { // TSK098_Exception_Safety_and_Resource_Leaks
 public:
  ResizeRollbackGuard(const std::filesystem::path& path, uint64_t rollback_size)
      : path_(path), rollback_size_(rollback_size) {}

  ResizeRollbackGuard(const ResizeRollbackGuard&) = delete;
  ResizeRollbackGuard& operator=(const ResizeRollbackGuard&) = delete;

  ResizeRollbackGuard(ResizeRollbackGuard&& other) noexcept
      : path_(std::move(other.path_)), rollback_size_(other.rollback_size_), committed_(other.committed_) {
    other.committed_ = true;
  }

  ResizeRollbackGuard& operator=(ResizeRollbackGuard&& other) noexcept {
    if (this != &other) {
      path_ = std::move(other.path_);
      rollback_size_ = other.rollback_size_;
      committed_ = other.committed_;
      other.committed_ = true;
    }
    return *this;
  }

  ~ResizeRollbackGuard() {
    if (!committed_) {
      std::error_code ec;
      std::filesystem::resize_file(path_, rollback_size_, ec);
    }
  }

  void Commit() noexcept { committed_ = true; }

 private:
  std::filesystem::path path_;
  uint64_t rollback_size_{0};
  bool committed_{false};
};

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
                  "Failed to create container file"}; // TSK103_Logging_and_Information_Disclosure generic error
    }
  }
  file_.open(path_, std::ios::binary | std::ios::in | std::ios::out);
  if (!file_) {
    throw Error{ErrorDomain::IO, 0,
                "Failed to open container file"}; // TSK103_Logging_and_Information_Disclosure generic error
  }
}

void BlockDevice::EnsureSizeUnlocked(uint64_t size) {
  auto current_size = std::filesystem::exists(path_) ? std::filesystem::file_size(path_) : 0ULL;
  if (current_size >= size) {
    return;
  }
  std::filesystem::resize_file(path_, size);
}

uint64_t BlockDevice::ByteOffsetForChunk(int64_t chunk_index) const { // TSK107_Platform_Specific_Issues
  if (chunk_index < 0) {
    throw Error{ErrorDomain::Validation, 0, "Negative chunk index"};
  }
  const uint64_t u_index = static_cast<uint64_t>(chunk_index);
  if (record_size_ != 0 && u_index > std::numeric_limits<uint64_t>::max() / record_size_) {
    throw Error{ErrorDomain::Validation, 0, "Chunk offset overflow"}; // TSK100_Integer_Overflow_and_Arithmetic guard chunk offset
  }
  return u_index * record_size_;
}

std::streampos BlockDevice::OffsetForChunk(int64_t chunk_index) const { // TSK107_Platform_Specific_Issues
  const uint64_t offset = ByteOffsetForChunk(chunk_index);
  static_assert(sizeof(std::streamoff) >= sizeof(int64_t),
                "BlockDevice requires 64-bit stream offsets"); // TSK107_Platform_Specific_Issues enforce large file support
#if defined(_WIN32)
  const __int64 native_offset = static_cast<__int64>(offset);
  return std::streampos(static_cast<std::streamoff>(native_offset));
#else
  const int64_t native_offset = static_cast<int64_t>(offset);
  return std::streampos(static_cast<std::streamoff>(native_offset));
#endif
}

void BlockDevice::WriteChunk(const ChunkHeader& header, std::span<const uint8_t> ciphertext) {
  if (ciphertext.size() != kPayloadSize) {
    throw Error{ErrorDomain::Validation, 0, "Ciphertext must be exactly one chunk"};
  }
  if (header.chunk_index < 0) {  // TSK108_Data_Structure_Invariants guard invalid chunk indices
    throw Error{ErrorDomain::Validation, 0, "Negative chunk index"};
  }
  const uint64_t chunk_index_u = static_cast<uint64_t>(header.chunk_index);
  if (chunk_index_u > std::numeric_limits<uint64_t>::max() / kPayloadSize) {
    throw Error{ErrorDomain::Validation, 0, "Logical offset overflow"};
  }
  const uint64_t expected_offset = chunk_index_u * kPayloadSize;  // TSK108_Data_Structure_Invariants
  if (header.logical_offset != expected_offset) {
    throw Error{ErrorDomain::Validation, 0, "Header logical offset mismatch"};
  }
  if (header.epoch != epoch_) {  // TSK108_Data_Structure_Invariants bind to nonce generator epoch
    throw Error{ErrorDomain::Validation, 0, "Chunk epoch mismatch"};
  }
  std::scoped_lock lock(io_mutex_);
  EnsureOpenUnlocked();
  auto offset = OffsetForChunk(header.chunk_index);
  const uint64_t base_offset = ByteOffsetForChunk(header.chunk_index); // TSK107_Platform_Specific_Issues preserve 64-bit arithmetic
  const uint64_t current_size =
      std::filesystem::exists(path_) ? std::filesystem::file_size(path_) : 0ULL;
  const uint64_t final_size = std::max<uint64_t>(base_offset + record_size_, current_size);
  const uint64_t staging_offset_value = final_size;

  std::vector<uint8_t> previous_record; // TSK098_Exception_Safety_and_Resource_Leaks
  if (base_offset + record_size_ <= current_size) {
    previous_record.resize(static_cast<size_t>(record_size_));
    file_.seekg(offset);
    if (!file_) {
      throw Error{ErrorDomain::IO, 0, "Failed to seek for backup"};
    }
    file_.read(reinterpret_cast<char*>(previous_record.data()),
               static_cast<std::streamsize>(previous_record.size()));
    if (file_.gcount() != static_cast<std::streamsize>(previous_record.size())) {
      throw Error{ErrorDomain::IO, 0, "Failed to read existing chunk for backup"};
    }
    file_.clear();
  }

  ChunkHeader prepared_header = PrepareHeaderForWrite(header);  // TSK078_Chunk_Integrity_and_Bounds
  std::vector<uint8_t> record(static_cast<size_t>(record_size_));
  std::memcpy(record.data(), &prepared_header, sizeof(prepared_header));
  std::memcpy(record.data() + sizeof(prepared_header), ciphertext.data(), ciphertext.size());

  EnsureSizeUnlocked(staging_offset_value + record_size_);
  ResizeRollbackGuard rollback(path_, current_size); // TSK098_Exception_Safety_and_Resource_Leaks

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
  try {
    write_buffer(offset);
  } catch (...) {
    if (!previous_record.empty()) {
      try {
        file_.clear();
        file_.seekp(offset);
        if (file_) {
          file_.write(reinterpret_cast<const char*>(previous_record.data()),
                      static_cast<std::streamsize>(previous_record.size()));
          file_.flush();
        }
      } catch (...) {
        // Swallow secondary failure and rethrow original error.
      }
    }
    throw;
  }
  std::filesystem::resize_file(path_, final_size);  // TSK078_Chunk_Integrity_and_Bounds
  rollback.Commit();
}

ChunkReadResult BlockDevice::ReadChunk(int64_t chunk_index) {
  if (chunk_index < 0) {  // TSK108_Data_Structure_Invariants prevent negative indices
    throw Error{ErrorDomain::Validation, 0, "Negative chunk index"};
  }
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
  if (result.header.chunk_index != chunk_index) {
    throw Error{ErrorDomain::Validation, 0, "Chunk index mismatch"};  // TSK108_Data_Structure_Invariants
  }
  if (result.header.epoch != epoch_) {
    throw Error{ErrorDomain::Validation, 0, "Chunk epoch mismatch"};
  }
  const uint64_t chunk_index_u = static_cast<uint64_t>(chunk_index);
  if (chunk_index_u > std::numeric_limits<uint64_t>::max() / kPayloadSize) {
    throw Error{ErrorDomain::Validation, 0, "Chunk logical offset overflow"};
  }
  if (result.header.logical_offset != chunk_index_u * kPayloadSize) {
    throw Error{ErrorDomain::Validation, 0, "Chunk logical offset mismatch"};
  }
  return result;
}

}  // namespace qv::storage

