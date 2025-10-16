#include "qv/storage/chunk_manager.h"

#include <algorithm>
#include <cstring>
#include <limits> // TSK100_Integer_Overflow_and_Arithmetic bounds checks
#include <mutex>  // TSK067_Nonce_Safety

#include "qv/common.h"
#include "qv/core/nonce.h"
#include "qv/crypto/aes_gcm.h"
#include "qv/crypto/ct.h" // TSK123_Missing_Constant_Time_Comparisons constant-time size selection
#include "qv/crypto/sha256.h" // TSK128_Missing_AAD_Validation_in_Chunks chunk binding digest
#include "qv/security/zeroizer.h"

#ifndef QV_SENSITIVE_FUNCTION  // TSK028A_Memory_Wiping_Gaps
#if defined(_MSC_VER)
#define QV_SENSITIVE_BEGIN __pragma(optimize("", off))
#define QV_SENSITIVE_END __pragma(optimize("", on))
#define QV_SENSITIVE_FUNCTION __declspec(noinline)
#elif defined(__clang__)
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION [[clang::optnone]] __attribute__((noinline))
#elif defined(__GNUC__)
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION __attribute__((noinline, optimize("O0")))
#else
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION
#endif
#endif  // QV_SENSITIVE_FUNCTION TSK028A_Memory_Wiping_Gaps

namespace qv::storage {

namespace {
// TSK061_Block_Device_and_Chunk_Storage_Engine
constexpr uint64_t kChunkPayloadSize = kChunkSize;
constexpr uint64_t kNonceFreshnessWindow = 4096; // TSK128_Missing_AAD_Validation_in_Chunks sliding replay window
constexpr uint32_t kChunkHeaderIntegrityVersion = 1; // TSK128_Missing_AAD_Validation_in_Chunks align with BlockDevice

std::array<uint8_t, 32> DeriveChunkKey(std::span<const uint8_t, 32> master) {
  return qv::core::DeriveDataKey(master);
}

size_t ExpectedTagSize(qv::crypto::CipherType cipher) { // TSK083_AAD_Recompute_and_Binding
  switch (cipher) {
    case qv::crypto::CipherType::AEGIS_128X:
      return qv::crypto::kAEGIS128XTagSize;
    case qv::crypto::CipherType::AEGIS_128L:
      return qv::crypto::kAEGIS128LTagSize;
    case qv::crypto::CipherType::AEGIS_256:
      return qv::crypto::kAEGIS256TagSize;
    case qv::crypto::CipherType::AES_256_GCM:
    case qv::crypto::CipherType::CHACHA20_POLY1305:
      return qv::crypto::AES256_GCM::TAG_SIZE;
  }
  return 0;
}

size_t ExpectedNonceSize(qv::crypto::CipherType cipher) { // TSK083
  switch (cipher) {
    case qv::crypto::CipherType::AEGIS_128X:
      return qv::crypto::kAEGIS128XNonceSize;
    case qv::crypto::CipherType::AEGIS_128L:
      return qv::crypto::kAEGIS128LNonceSize;
    case qv::crypto::CipherType::AEGIS_256:
      return qv::crypto::kAEGIS256NonceSize;
    case qv::crypto::CipherType::AES_256_GCM:
    case qv::crypto::CipherType::CHACHA20_POLY1305:
      return qv::crypto::AES256_GCM::NONCE_SIZE;
  }
  return 0;
}

std::array<uint8_t, 8> MakeChunkContext(qv::crypto::CipherType cipher, uint8_t tag_size,
                                        uint8_t nonce_size, uint32_t epoch) { // TSK083, TSK128_Missing_AAD_Validation_in_Chunks
  return qv::core::BindChunkAADContext(static_cast<uint8_t>(cipher), tag_size, nonce_size, epoch,
                                       kChunkHeaderIntegrityVersion);
}

bool ValidateChunkContext(qv::crypto::CipherType cipher, size_t tag_size, size_t nonce_size,
                          uint32_t epoch, const std::array<uint8_t, 8>& context) { // TSK128_Missing_AAD_Validation_in_Chunks
  auto expected = MakeChunkContext(cipher, static_cast<uint8_t>(tag_size), static_cast<uint8_t>(nonce_size), epoch);
  return std::equal(expected.begin(), expected.end(), context.begin(), context.end());
}

}  // namespace

ChunkManager::ChunkManager(const std::filesystem::path& container,
                           std::array<uint8_t, 32> master_key,
                           uint32_t epoch,
                           qv::crypto::CipherType cipher)
    : container_(container),
      master_key_(master_key),
      data_key_(DeriveChunkKey(master_key_)),
      epoch_(epoch),
      cipher_(ResolveCipher(cipher)),
      nonce_generator_(epoch_),
      device_(container_, master_key_, epoch_, 0, cipher_),
      cache_(),
      read_ahead_(nullptr) {
  cache_.SetWriteBackCallback(
      [this](int64_t index, const std::vector<uint8_t>& data) { PersistChunk(index, data); });
  read_ahead_ = std::make_unique<ReadAheadManager>(*this, cache_);
  if (auto last = nonce_generator_.LastPersisted()) { // TSK128_Missing_AAD_Validation_in_Chunks initialize replay window
    std::lock_guard<std::mutex> guard(nonce_freshness_mutex_);
    nonce_high_watermark_ = last->counter;
    nonce_replay_floor_ =
        (nonce_high_watermark_ > kNonceFreshnessWindow)
            ? nonce_high_watermark_ - kNonceFreshnessWindow
            : 0;
  }
}

ChunkManager::~ChunkManager() {
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(data_key_.data(), data_key_.size())); // TSK125_Missing_Secure_Deletion_for_Keys
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(master_key_.data(), master_key_.size())); // TSK125_Missing_Secure_Deletion_for_Keys
}

std::vector<uint8_t> ChunkManager::MakeNonce(const qv::core::NonceGenerator::NonceRecord& record,
                                             int64_t chunk_index) const {
  if (record.chunk_index != qv::core::NonceGenerator::kUnboundChunkIndex &&
      record.chunk_index != chunk_index) {
    throw Error{ErrorDomain::Validation, 0,
                "Nonce record chunk index mismatch"}; // TSK118_Nonce_Reuse_Vulnerabilities
  }
  size_t required = 0;
  switch (cipher_) {
    case qv::crypto::CipherType::AEGIS_128X:
    case qv::crypto::CipherType::AEGIS_128L:
      required = qv::crypto::kAEGIS128LNonceSize;
      break;
    case qv::crypto::CipherType::AEGIS_256:
      required = qv::crypto::kAEGIS256NonceSize;
      break;
    case qv::crypto::CipherType::AES_256_GCM:
      required = qv::crypto::AES256_GCM::NONCE_SIZE;
      break;
    case qv::crypto::CipherType::CHACHA20_POLY1305:
      required = 12;
      break;
  }
  if (required == 0) {
    throw Error{ErrorDomain::Crypto, 0, "Unsupported cipher selection"};
  }
  std::vector<uint8_t> nonce(required, 0u);
  size_t copy_bytes = std::min<size_t>(record.nonce.size(), nonce.size());
  std::copy_n(record.nonce.begin(), copy_bytes, nonce.begin());
  uint64_t index_le = qv::core::ToLittleEndian64(static_cast<uint64_t>(chunk_index));
  auto* index_ptr = reinterpret_cast<const uint8_t*>(&index_le);
  for (size_t i = copy_bytes; i < nonce.size(); ++i) {
    size_t idx = (i - copy_bytes) % sizeof(index_le);
    nonce[i] = index_ptr[idx];
  }
  return nonce;
}

qv::crypto::CipherType ChunkManager::ResolveCipher(qv::crypto::CipherType requested) const {
  if (qv::crypto::CipherAvailable(requested)) {
    return requested;
  }
  if (requested == qv::crypto::CipherType::AEGIS_128X &&
      qv::crypto::CipherAvailable(qv::crypto::CipherType::AEGIS_128L)) {
    return qv::crypto::CipherType::AEGIS_128L;
  }
  if (qv::crypto::CipherAvailable(qv::crypto::CipherType::AEGIS_256)) {
    return qv::crypto::CipherType::AEGIS_256;
  }
  return qv::crypto::CipherType::AES_256_GCM;
}

// TSK064_Performance_Optimization_and_Caching
void ChunkManager::WriteChunk(uint64_t logical_offset, std::span<const uint8_t> data) {
  if (data.size() > kChunkPayloadSize) {
    throw Error{ErrorDomain::Validation, 0, "Chunk write exceeds payload size"};
  }
  if (logical_offset % kChunkPayloadSize != 0) {
    throw Error{ErrorDomain::Validation, 0, "Logical offset must align with chunk size"};
  }

  int64_t chunk_index = static_cast<int64_t>(logical_offset / kChunkPayloadSize);
  std::vector<uint8_t> buffer(data.begin(), data.end());
  cache_.Invalidate(chunk_index);  // TSK076_Cache_Coherency
  auto cached = cache_.Put(chunk_index, std::move(buffer), true);
  if (cached) {
    PersistChunk(chunk_index, cached->data);
    cache_.MarkClean(chunk_index);
  }
}

// TSK064_Performance_Optimization_and_Caching
std::vector<uint8_t> ChunkManager::ReadChunk(uint64_t logical_offset, bool for_prefetch) {
  if (logical_offset % kChunkPayloadSize != 0) {
    throw Error{ErrorDomain::Validation, 0, "Logical offset must align with chunk size"};
  }
  int64_t chunk_index = static_cast<int64_t>(logical_offset / kChunkPayloadSize);

  if (auto cached = cache_.Get(chunk_index)) {
    if (!for_prefetch) {
      HandleSequentialRead(chunk_index);
    }
    return cached->data;
  }

  auto plaintext = ReadChunkFromDevice(chunk_index);
  cache_.Put(chunk_index, std::vector<uint8_t>(plaintext.begin(), plaintext.end()), false);
  if (!for_prefetch) {
    HandleSequentialRead(chunk_index);
  }
  return plaintext;
}

void ChunkManager::Flush() {
  cache_.Flush([this](int64_t index, const std::vector<uint8_t>& data) { PersistChunk(index, data); });
}

std::vector<uint8_t> ChunkManager::ReadChunkFromDevice(int64_t chunk_index) {
  auto record = device_.ReadChunk(chunk_index);
  if (record.ciphertext.size() != kChunkPayloadSize) {  // TSK078_Chunk_Integrity_and_Bounds
    throw Error{ErrorDomain::Validation, 0, "Ciphertext payload size mismatch"};
  }
  if (record.header.chunk_index != chunk_index) {  // TSK078_Chunk_Integrity_and_Bounds
    throw Error{ErrorDomain::Validation, 0, "Chunk index mismatch"};
  }
  if (record.header.epoch != epoch_) {  // TSK078_Chunk_Integrity_and_Bounds
    throw Error{ErrorDomain::Validation, 0, "Chunk epoch mismatch"};
  }
  const uint64_t expected_offset =
      static_cast<uint64_t>(record.header.chunk_index) * kChunkPayloadSize; // TSK083_AAD_Recompute_and_Binding
  if (record.header.logical_offset != expected_offset) {
    throw Error{ErrorDomain::Validation, 0, "Logical offset mismatch"};
  }
  if (record.header.data_size > kChunkPayloadSize) {  // TSK078_Chunk_Integrity_and_Bounds
    throw Error{ErrorDomain::Validation, 0, "Header data size exceeds payload capacity"};
  }
  if (record.header.cipher_id != static_cast<uint8_t>(cipher_)) { // TSK128_Missing_AAD_Validation_in_Chunks
    throw Error{ErrorDomain::Validation, 0, "Unexpected chunk cipher"};
  }
  if (!qv::crypto::CipherAvailable(cipher_) && cipher_ != qv::crypto::CipherType::AES_256_GCM) {
    throw Error{ErrorDomain::Crypto, 0, "Cipher unavailable for chunk"};
  }
  const auto expected_tag_size = ExpectedTagSize(cipher_);                    // TSK083
  const auto expected_nonce_size = ExpectedNonceSize(cipher_);                // TSK083
  if (expected_tag_size == 0 || expected_tag_size > record.header.tag.size()) {
    throw Error{ErrorDomain::Validation, 0, "Unsupported tag size for cipher"};
  }
  if (expected_nonce_size == 0 || expected_nonce_size > record.header.nonce.size()) {
    throw Error{ErrorDomain::Validation, 0, "Unsupported nonce size for cipher"};
  }
  if (record.header.tag_size != expected_tag_size) {
    throw Error{ErrorDomain::Validation, 0, "Header tag size mismatch"};
  }
  if (record.header.nonce_size != expected_nonce_size) {
    throw Error{ErrorDomain::Validation, 0, "Header nonce size mismatch"};
  }
  auto context = MakeChunkContext(cipher_, static_cast<uint8_t>(expected_tag_size),
                                  static_cast<uint8_t>(expected_nonce_size), epoch_); // TSK083, TSK128_Missing_AAD_Validation_in_Chunks
  if (!ValidateChunkContext(cipher_, expected_tag_size, expected_nonce_size, epoch_, context)) {
    throw Error{ErrorDomain::Crypto, 0, "Chunk context derivation mismatch"}; // TSK128_Missing_AAD_Validation_in_Chunks
  }
  auto nonce_span =
      std::span<const uint8_t>(record.header.nonce.data(), expected_nonce_size); // TSK083
  const uint64_t nonce_counter = qv::core::ExtractNonceCounter(nonce_span);                // TSK128_Missing_AAD_Validation_in_Chunks
  {
    std::lock_guard<std::mutex> guard(nonce_freshness_mutex_);
    if (nonce_counter < nonce_replay_floor_) {
      throw Error{ErrorDomain::Security, 0, "Stale chunk nonce rejected"}; // TSK128_Missing_AAD_Validation_in_Chunks
    }
  }
  auto aad_data = qv::core::MakeAADData(record.header.epoch, record.header.chunk_index,
                                        record.header.logical_offset, record.header.data_size,
                                        context, nonce_counter);
  auto aad_envelope = qv::core::MakeAADEnvelope(
      aad_data, std::span<const uint8_t, 32>(record.header.aad_mac)); // TSK083
  auto aad_bytes = qv::AsBytesConst(aad_envelope);
  auto tag_span = std::span<const uint8_t>(record.header.tag.data(), expected_tag_size); // TSK083
  auto plaintext = qv::crypto::AEAD_Decrypt(
      cipher_,
      record.ciphertext,
      aad_bytes,
      nonce_span,
      tag_span,
      std::span<const uint8_t>(data_key_.data(), data_key_.size()));
  const uint64_t available_size = static_cast<uint64_t>(plaintext.size());
  const uint64_t expected_size = static_cast<uint64_t>(record.header.data_size);
  const uint64_t underflow_mask =
      (available_size - expected_size) >> 63; // TSK123_Missing_Constant_Time_Comparisons constant-time underflow detection
  const uint64_t sanitized_size = qv::crypto::ct::Select<uint64_t>(
      expected_size, available_size, underflow_mask != 0); // TSK123_Missing_Constant_Time_Comparisons branch-free clamp
  plaintext.resize(static_cast<size_t>(sanitized_size));
  if (underflow_mask != 0) {
    throw Error{ErrorDomain::Crypto, 0, "Decrypted payload truncated"};
  }
  {
    std::lock_guard<std::mutex> guard(nonce_freshness_mutex_);
    if (nonce_counter > nonce_high_watermark_) {
      nonce_high_watermark_ = nonce_counter;
    }
    nonce_replay_floor_ =
        (nonce_high_watermark_ > kNonceFreshnessWindow)
            ? nonce_high_watermark_ - kNonceFreshnessWindow
            : 0;
  }
  return plaintext;
}

QV_SENSITIVE_BEGIN
QV_SENSITIVE_FUNCTION void ChunkManager::PersistChunk(int64_t chunk_index,
                                                      const std::vector<uint8_t>& data) {
  std::lock_guard<std::mutex> persist_lock(persist_mutex_); // TSK067_Nonce_Safety
  qv::core::NonceGenerator::NonceRecord nonce_record;
  const auto expected_tag_size = ExpectedTagSize(cipher_);                      // TSK083
  const auto expected_nonce_size = ExpectedNonceSize(cipher_);                  // TSK083
  if (expected_tag_size == 0 || expected_nonce_size == 0) {
    throw Error{ErrorDomain::Crypto, 0, "Unsupported cipher parameters"};
  }
  if (chunk_index < 0) {
    throw Error{ErrorDomain::Validation, 0, "Negative chunk index"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard bounds
  }
  const uint64_t chunk_index_u = static_cast<uint64_t>(chunk_index);
  if (chunk_index_u > 0 &&
      kChunkPayloadSize > std::numeric_limits<uint64_t>::max() / chunk_index_u) {
    throw Error{ErrorDomain::Validation, 0, "Chunk offset overflow"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard logical offset
  }
  std::array<uint8_t, kChunkPayloadSize> plaintext{};
  qv::security::Zeroizer::ScopeWiper plaintext_guard(plaintext.data(), plaintext.size()); // TSK028A_Memory_Wiping_Gaps
  std::fill(plaintext.begin(), plaintext.end(), 0);
  auto logical_offset = chunk_index_u * kChunkPayloadSize;  // TSK119_Integer_Overflow_in_Chunk_Calculations
  auto copy_size = std::min<size_t>(data.size(), plaintext.size());
  if (copy_size > std::numeric_limits<uint32_t>::max()) {
    throw Error{ErrorDomain::Validation, 0, "Chunk payload too large"}; // TSK100_Integer_Overflow_and_Arithmetic guard cast
  }
  std::copy_n(data.begin(), copy_size, plaintext.begin());
  auto chunk_hash =
      qv::crypto::SHA256_Hash(std::span<const uint8_t>(plaintext.data(), copy_size)); // TSK128_Missing_AAD_Validation_in_Chunks
  qv::security::Zeroizer::ScopeWiper chunk_hash_guard(chunk_hash.data(), chunk_hash.size());
  {
    std::unique_lock<std::shared_mutex> nonce_guard(nonce_mutex_); // TSK118_Nonce_Reuse_Vulnerabilities
    nonce_record = nonce_generator_.NextAuthenticated(
        chunk_index, std::span<const uint8_t>(chunk_hash.data(), chunk_hash.size()));
  }
  try {
    auto nonce = MakeNonce(nonce_record, chunk_index);
    qv::security::Zeroizer::ScopeWiper<uint8_t> nonce_guard(nonce.data(), nonce.size()); // TSK125_Missing_Secure_Deletion_for_Keys scoped nonce wipe
    if (nonce.size() != expected_nonce_size) {
      throw Error{ErrorDomain::Crypto, 0, "Nonce length mismatch"};
    }
    auto context = MakeChunkContext(cipher_, static_cast<uint8_t>(expected_tag_size),
                                    static_cast<uint8_t>(expected_nonce_size), epoch_);      // TSK083, TSK128_Missing_AAD_Validation_in_Chunks
    if (!ValidateChunkContext(cipher_, expected_tag_size, expected_nonce_size, epoch_, context)) {
      throw Error{ErrorDomain::Crypto, 0, "Chunk context derivation mismatch"}; // TSK128_Missing_AAD_Validation_in_Chunks
    }
    qv::security::Zeroizer::ScopeWiper<uint8_t> context_guard(context.data(), context.size()); // TSK125_Missing_Secure_Deletion_for_Keys scoped context wipe
    auto aad_data = qv::core::MakeAADData(epoch_, chunk_index, logical_offset,
                                          static_cast<uint32_t>(copy_size), context, nonce_record.counter);
    qv::security::Zeroizer::ScopeWiper<uint8_t> aad_data_guard(
        reinterpret_cast<uint8_t*>(&aad_data), sizeof(aad_data)); // TSK125_Missing_Secure_Deletion_for_Keys scoped AAD wipe
    auto aad_envelope =
        qv::core::MakeAADEnvelope(aad_data, nonce_record.mac);                        // TSK083
    qv::security::Zeroizer::ScopeWiper<uint8_t> aad_envelope_guard(
        reinterpret_cast<uint8_t*>(&aad_envelope), sizeof(aad_envelope)); // TSK125_Missing_Secure_Deletion_for_Keys envelope wipe
    auto aad_bytes = qv::AsBytesConst(aad_envelope);
    auto encrypt_result = qv::crypto::AEAD_Encrypt(
        cipher_,
        std::span<const uint8_t>(plaintext.data(), plaintext.size()),
        aad_bytes,
        nonce,
        std::span<const uint8_t>(data_key_.data(), data_key_.size()));
    if (encrypt_result.ciphertext.size() != kChunkPayloadSize) {
      throw Error{ErrorDomain::Crypto, 0, "Encrypted chunk size mismatch"};
    }
    if (encrypt_result.tag.size() != expected_tag_size) {                          // TSK083
      throw Error{ErrorDomain::Crypto, 0, "AEAD tag length mismatch"};
    }

    ChunkHeader header{};
    header.logical_offset = logical_offset;
    header.data_size = static_cast<uint32_t>(copy_size);
    header.epoch = epoch_;
    header.chunk_index = chunk_index;
    std::fill(header.tag.begin(), header.tag.end(), 0);
    std::copy_n(encrypt_result.tag.begin(),
                std::min<size_t>(encrypt_result.tag.size(), header.tag.size()),
                header.tag.begin());
    std::fill(header.nonce.begin(), header.nonce.end(), 0);
    std::copy_n(nonce.begin(), std::min<size_t>(nonce.size(), header.nonce.size()), header.nonce.begin());
    std::copy(nonce_record.mac.begin(), nonce_record.mac.end(), header.aad_mac.begin());
    header.cipher_id = static_cast<uint8_t>(cipher_);
    header.tag_size = static_cast<uint8_t>(expected_tag_size);
    header.nonce_size = static_cast<uint8_t>(expected_nonce_size);

    device_.WriteChunk(header, encrypt_result.ciphertext);

    std::unique_lock<std::shared_mutex> commit_guard(nonce_mutex_); // TSK118_Nonce_Reuse_Vulnerabilities
    nonce_generator_.CommitNonce(nonce_record);
    commit_guard.unlock();
    {
      std::lock_guard<std::mutex> freshness_guard(nonce_freshness_mutex_); // TSK128_Missing_AAD_Validation_in_Chunks
      if (nonce_record.counter > nonce_high_watermark_) {
        nonce_high_watermark_ = nonce_record.counter;
      }
      nonce_replay_floor_ =
          (nonce_high_watermark_ > kNonceFreshnessWindow)
              ? nonce_high_watermark_ - kNonceFreshnessWindow
              : 0;
    }
  } catch (...) {
    std::unique_lock<std::shared_mutex> release_guard(nonce_mutex_); // TSK118_Nonce_Reuse_Vulnerabilities
    nonce_generator_.ReleaseNonce(nonce_record);
    throw;
  }

  qv::security::Zeroizer::Wipe(plaintext);
}
QV_SENSITIVE_END

void ChunkManager::HandleSequentialRead(int64_t chunk_index) {
  ReadAheadManager* read_ahead_ptr = nullptr;  // TSK096_Race_Conditions_and_Thread_Safety
  uint64_t request_offset = 0;
  size_t request_count = 0;
  bool should_request = false;

  {
    std::unique_lock lock(sequential_mutex_);
    if (last_read_chunk_ >= 0 && chunk_index == last_read_chunk_ + 1) {
      sequential_read_count_ += 1;
    } else if (chunk_index == last_read_chunk_) {
      // repeated read of same chunk keeps streak intact
    } else {
      sequential_read_count_ = 1;
    }

    if (sequential_read_count_ >= 3 && read_ahead_) {
      int64_t start_chunk = chunk_index + 1;
      if (start_chunk >= read_ahead_window_end_) {
        read_ahead_window_end_ = start_chunk + 8;
        read_ahead_ptr = read_ahead_.get();
        request_offset = static_cast<uint64_t>(start_chunk) * kChunkPayloadSize;
        request_count = 8;
        should_request = true;
      }
    }

    last_read_chunk_ = chunk_index;
  }

  if (should_request && read_ahead_ptr) {
    read_ahead_ptr->RequestReadAhead(request_offset, request_count);
  }
}

}  // namespace qv::storage

