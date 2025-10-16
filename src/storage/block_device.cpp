#include "qv/storage/block_device.h"

#include <algorithm>
#include <array>
#include <cstdint> // TSK107_Platform_Specific_Issues explicit 64-bit math
#include <cstring>
#include <exception> // TSK116_Incorrect_Error_Propagation preserve original failure details
#include <filesystem>
#include <iostream>   // TSK109_Error_Code_Handling surface rollback errors
#include <fstream>
#include <span>
#include <string>     // TSK116_Incorrect_Error_Propagation enrich rollback diagnostics
#include <system_error> // TSK098_Exception_Safety_and_Resource_Leaks
#include <limits>       // TSK100_Integer_Overflow_and_Arithmetic overflow guards
#include <vector>

#include "qv/crypto/ct.h"              // TSK122_Weak_CRC32_for_Chunk_Headers constant-time MAC verify
#include "qv/crypto/hmac_sha256.h"      // TSK122_Weak_CRC32_for_Chunk_Headers header authentication

namespace qv::storage {

// TSK061_Block_Device_and_Chunk_Storage_Engine

namespace {
constexpr uint64_t kHeaderSize = sizeof(ChunkHeader);
constexpr uint64_t kPayloadSize = kChunkSize;

// TSK078_Chunk_Integrity_and_Bounds: CRC32 implementation for chunk headers.
constexpr uint32_t kCRC32Polynomial = 0xEDB88320u;

constexpr std::array<uint8_t, 16> kMetadataMacContext{
    'Q', 'V', '-', 'M', 'E', 'T', 'A', 'D', 'A', 'T', 'A', '-', 'M', 'A', 'C', '1'};  // TSK121_Missing_Authentication_in_Metadata

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
constexpr uint32_t kHeaderIntegrityVersion = 1; // TSK122_Weak_CRC32_for_Chunk_Headers version binding

using HeaderMac = std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE>;

HeaderMac ComputeHeaderMAC(const ChunkHeader& header, std::span<const uint8_t> key) {
  ChunkHeader canonical = header;
  canonical.header_mac.fill(0);
  auto header_bytes = qv::AsBytesConst(canonical);
  return qv::crypto::HMAC_SHA256::Compute(key, header_bytes);
}

ChunkHeader PrepareHeaderForWrite(const ChunkHeader& header, std::span<const uint8_t> key) {
  ChunkHeader prepared = header;
  prepared.integrity_version = qv::ToLittleEndian(kHeaderIntegrityVersion);
  prepared.header_mac.fill(0);
  const HeaderMac mac = ComputeHeaderMAC(prepared, key);
  prepared.header_mac = mac;
  return prepared;
}

void VerifyHeaderMACOrThrow(ChunkHeader& header, std::span<const uint8_t> key) {
  const uint32_t version = qv::FromLittleEndian32(header.integrity_version);
  if (version != kHeaderIntegrityVersion) {
    throw Error{ErrorDomain::Validation, 0,
                "Chunk header integrity version unsupported"}; // TSK122_Weak_CRC32_for_Chunk_Headers
  }
  const HeaderMac stored_mac = header.header_mac;
  ChunkHeader canonical = header;
  canonical.header_mac.fill(0);
  const HeaderMac computed = ComputeHeaderMAC(canonical, key);
  if (!qv::crypto::ct::CompareEqual(stored_mac, computed)) {
    throw Error{ErrorDomain::Validation, 0, "Chunk header MAC mismatch"};
  }
  header = canonical;
  header.header_mac = stored_mac;
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
      if (ec) {
        std::clog << "{\"event\":\"block_device_error\",\"message\":\"rollback resize failed\",\"error_code\":"
                  << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling make failure visible
      }
    }
  }

  void Commit() noexcept { committed_ = true; }

 private:
  std::filesystem::path path_;
  uint64_t rollback_size_{0};
  bool committed_{false};
};

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
  metadata_mac_key_ = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(master_key_.data(), master_key_.size()),
      std::span<const uint8_t>(kMetadataMacContext.data(), kMetadataMacContext.size()));
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
  if (record_size_ != 0 && u_index > 0 &&
      record_size_ > std::numeric_limits<uint64_t>::max() / u_index) {
    throw Error{ErrorDomain::Validation, 0, "Chunk offset overflow"};  // TSK100_Integer_Overflow_and_Arithmetic guard chunk offset // TSK119_Integer_Overflow_in_Chunk_Calculations avoid division-based overflow
  }
  return u_index * record_size_;
}

std::streampos BlockDevice::OffsetForChunk(int64_t chunk_index) const { // TSK107_Platform_Specific_Issues
  const uint64_t offset = ByteOffsetForChunk(chunk_index);
  if (offset > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
    throw Error{ErrorDomain::Validation, 0, "Chunk offset exceeds stream range"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard cast
  }
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

  ChunkHeader prepared_header = PrepareHeaderForWrite(
      header, std::span<const uint8_t>(master_key_));  // TSK122_Weak_CRC32_for_Chunk_Headers
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
    const std::exception_ptr original = std::current_exception();
    bool rollback_failed = false;
    std::string rollback_message;
    if (!previous_record.empty()) {
      try {
        file_.clear();
        file_.seekp(offset);
        if (file_) {
          file_.write(reinterpret_cast<const char*>(previous_record.data()),
                      static_cast<std::streamsize>(previous_record.size()));
          file_.flush();
        }
      } catch (const std::exception& rollback_error) {
        rollback_failed = true;
        rollback_message = rollback_error.what();
      } catch (...) {
        rollback_failed = true;
        rollback_message = "unknown rollback error"; // TSK116_Incorrect_Error_Propagation capture secondary failure
      }
    }
    if (rollback_failed) {
      try {
        std::rethrow_exception(original);
      } catch (const Error& error) {
        auto context = error.context;
        context.emplace_back("rollback_restore_failed");
        auto message = std::string(error.what()) + " (rollback failed: " + rollback_message + ")";
        throw Error{error.domain, error.code, std::move(message), error.native_code, error.retryability,
                    std::move(context)}; // TSK116_Incorrect_Error_Propagation preserve rollback diagnostics
      } catch (...) {
        std::rethrow_exception(original);
      }
    }
    std::rethrow_exception(original);
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
  VerifyHeaderMACOrThrow(result.header, std::span<const uint8_t>(master_key_));  // TSK122_Weak_CRC32_for_Chunk_Headers
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

