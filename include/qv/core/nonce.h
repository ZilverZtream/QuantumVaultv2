#pragma once
#include "qv/common.h"
#include "qv/error.h"
#include <algorithm>
#include <array>
#include <chrono> // TSK015
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory> // TSK133_Race_in_Nonce_Log_Recovery scoped log locks
#include <mutex>
#include <new>      // TSK032_Backup_Recovery_and_Disaster_Recovery
#include <optional> // TSK015
#include <limits>   // TSK071_Epoch_Overflow_Safety exported thresholds
#include <span>
#include <string_view> // TSK024_Key_Rotation_and_Lifecycle_Management
#include <vector>

#include "qv/crypto/hkdf.h"                     // TSK106_Cryptographic_Implementation_Weaknesses
#include "qv/crypto/hmac_sha256.h"              // TSK024_Key_Rotation_and_Lifecycle_Management
#include "qv/security/zeroizer.h"               // TSK024_Key_Rotation_and_Lifecycle_Management

namespace qv::core {

  class NonceLog {
    struct LogEntry {
      uint64_t counter;
    std::array<uint8_t, 32> mac;
    };
    std::array<uint8_t, 32> key_{};
    std::array<uint8_t, 32> last_mac_{};
    std::filesystem::path path_;
    std::vector<LogEntry> entries_;
    bool loaded_{false};
    mutable std::mutex mu_;
    struct FileLock;                                       // TSK133_Race_in_Nonce_Log_Recovery forward-declare lock wrapper
    std::unique_ptr<FileLock> file_lock_;                  // TSK133_Race_in_Nonce_Log_Recovery serialized file access

  public:
    NonceLog() = default;
    explicit NonceLog(const std::filesystem::path& path);
    NonceLog(const std::filesystem::path& path, std::nothrow_t) noexcept; // TSK032_Backup_Recovery_and_Disaster_Recovery
    std::array<uint8_t, 32> Append(uint64_t counter,
                                   std::span<const uint8_t> binding); // TSK014, TSK128_Missing_AAD_Validation_in_Chunks binding
    std::array<uint8_t, 32> LastMac() const;          // TSK014
    bool VerifyChain();
    size_t Repair(); // TSK032_Backup_Recovery_and_Disaster_Recovery
    uint64_t GetLastCounter() const;
    size_t EntryCount() const;

  private:
    void EnsureLoadedUnlocked();
    void ReloadUnlocked();
    void PersistUnlocked();
    void InitializeNewLog();
    void EnsureFileLock();      // TSK133_Race_in_Nonce_Log_Recovery acquire/process-level guard
    void AppendEntryToFileUnlocked(
        uint64_t counter,
        std::span<const uint8_t, 32> mac); // TSK_CRIT_09_Nonce_Log_Write_Amplification_DoS append durability
  };

  class NonceGenerator {
  public:
    enum class RekeyReason : uint8_t { // TSK015
      kNone = 0,
      kNonceBudget,
      kEpochExpired,
      kCounterLimit,
    };
    static constexpr int64_t kUnboundChunkIndex = std::numeric_limits<int64_t>::min(); // TSK118_Nonce_Reuse_Vulnerabilities sentinel binding

    struct NonceRecord { // TSK014
      std::array<uint8_t, 12> nonce;
      uint64_t counter;
      std::array<uint8_t, 32> mac;
      std::array<uint8_t, 32> binding{};        // TSK128_Missing_AAD_Validation_in_Chunks bind MAC to payload digest
      uint8_t binding_size{0};                  // TSK128_Missing_AAD_Validation_in_Chunks explicit length for binding data
      int64_t chunk_index{kUnboundChunkIndex}; // TSK118_Nonce_Reuse_Vulnerabilities bind reservation to chunk
    };
    struct Status { // TSK015
      uint64_t counter{0};
      uint64_t nonces_emitted{0};
      uint64_t remaining_nonce_budget{0};
      std::chrono::system_clock::time_point epoch_started{};
      std::chrono::system_clock::time_point now{};
      RekeyReason reason{RekeyReason::kNone};
    };
    explicit NonceGenerator(uint32_t epoch, uint64_t start_counter = 0);
    NonceRecord NextAuthenticated(int64_t chunk_index = kUnboundChunkIndex,
                                  std::span<const uint8_t> binding = {}); // TSK014, TSK118_Nonce_Reuse_Vulnerabilities, TSK128_Missing_AAD_Validation_in_Chunks
    std::array<uint8_t, 12> Next();
    uint64_t CurrentCounter() const {
      std::lock_guard<std::mutex> lock(state_mutex_);  // TSK096_Race_Conditions_and_Thread_Safety
      return counter_;
    }
    bool NeedsRekey() const;                                                // TSK015
    Status GetStatus() const;                                               // TSK015
    Status EvaluateStatus(std::chrono::system_clock::time_point now) const; // TSK015
    void SetEpochStart(std::chrono::system_clock::time_point start);        // TSK015
    void SetPolicy(uint64_t max_nonces, std::chrono::hours max_age);        // TSK015
    std::optional<NonceRecord> LastPersisted() const;                       // TSK015
  private:
    uint32_t epoch_;
    uint64_t counter_{0};
    NonceLog log_;
    struct RekeyPolicy { // TSK015
      uint64_t max_nonces = 50'000'000ULL;
      std::chrono::hours max_age = std::chrono::hours{24 * 30};
    };
    RekeyPolicy policy_{};                                  // TSK015
    std::chrono::system_clock::time_point epoch_started_{};         // TSK015
    std::chrono::steady_clock::time_point epoch_started_monotonic_; // TSK118_Nonce_Reuse_Vulnerabilities monotonic ageing
    uint64_t base_counter_{0};                              // TSK015
    mutable std::mutex state_mutex_;                        // TSK067_Nonce_Safety
    RekeyReason DetermineRekeyReason(uint64_t candidate,
                                     std::chrono::steady_clock::time_point now) const; // TSK015, TSK118_Nonce_Reuse_Vulnerabilities
    static std::array<uint8_t, 12> MakeNonceBytes(uint32_t epoch, uint64_t counter);   // TSK015
  };

// TSK016_Windows_Compatibility_Fixes ensure portable packed layout without compiler-specific
// attributes.
#pragma pack(push, 1)
  struct EpochTLV {
    uint16_t type = 0x4E4F; // 'NO'
    uint16_t length = 4;
    uint32_t epoch;
  };

  inline constexpr uint32_t kEpochOverflowHardLimit =
      std::numeric_limits<uint32_t>::max(); // TSK071_Epoch_Overflow_Safety share limit
  inline constexpr uint32_t kEpochOverflowWarningMargin = 16u; // TSK071_Epoch_Overflow_Safety guard band
  inline constexpr uint32_t kEpochOverflowUnsafeMargin = 1u;   // TSK071_Epoch_Overflow_Safety final slot reserved

  uint32_t EpochOverflowWarningThreshold();     // TSK071_Epoch_Overflow_Safety exported helpers
  uint32_t EpochOverflowUnsafeThreshold();      // TSK071_Epoch_Overflow_Safety exported helpers
  bool EpochRequiresOverflowWarning(uint32_t epoch); // TSK071_Epoch_Overflow_Safety exported helpers
  bool EpochRekeyWouldBeUnsafe(uint32_t epoch);      // TSK071_Epoch_Overflow_Safety exported helpers

  inline constexpr const char* RekeyReasonToString(NonceGenerator::RekeyReason reason) { // TSK015
    switch (reason) {
    case NonceGenerator::RekeyReason::kNone:
      return "none";
    case NonceGenerator::RekeyReason::kNonceBudget:
      return "nonce-budget";
    case NonceGenerator::RekeyReason::kEpochExpired:
      return "epoch-expired";
    case NonceGenerator::RekeyReason::kCounterLimit:
      return "counter-limit";
    }
    return "unknown";
  }

  inline EpochTLV MakeEpochTlv(uint32_t epoch) { // TSK015
    EpochTLV tlv{};
    tlv.type = qv::ToLittleEndian(static_cast<uint16_t>(0x4E4F));
    tlv.length = qv::ToLittleEndian(static_cast<uint16_t>(sizeof(tlv.epoch)));
    tlv.epoch = qv::ToLittleEndian(epoch);
    return tlv;
  }

  inline bool ValidateEpochTlv(const EpochTLV& tlv, uint32_t expected_epoch) { // TSK015
    if (qv::ToLittleEndian(tlv.type) != 0x4E4F) {
      return false;
    }
    if (qv::ToLittleEndian(tlv.length) != sizeof(tlv.epoch)) {
      return false;
    }
    return qv::ToLittleEndian(tlv.epoch) == expected_epoch;
  }

  inline constexpr std::array<uint8_t, 8> kAADContextChunkData = {'Q', 'V', 'C', 'H',
                                                                  'U', 'N', 'K', 'D'}; // TSK014

  inline constexpr std::array<uint8_t, 8> BindChunkAADContext( // TSK083_AAD_Recompute_and_Binding
      uint8_t cipher_id, uint8_t tag_size, uint8_t nonce_size,
      uint32_t epoch = 0, uint32_t header_version = 0) { // TSK128_Missing_AAD_Validation_in_Chunks strengthen binding
    auto context = kAADContextChunkData;
    context[0] ^= cipher_id;
    context[1] ^= tag_size;
    context[2] ^= nonce_size;
    context[3] ^= static_cast<uint8_t>(cipher_id ^ tag_size);
    context[4] ^= static_cast<uint8_t>(cipher_id ^ nonce_size);
    context[5] ^= static_cast<uint8_t>(tag_size ^ nonce_size);
    context[6] ^= static_cast<uint8_t>(((cipher_id + tag_size) ^ static_cast<uint8_t>(epoch)) & 0xFFu);
    context[7] ^= static_cast<uint8_t>(((cipher_id + nonce_size) ^ static_cast<uint8_t>(header_version)) & 0xFFu);
    return context;
  }
  inline constexpr std::array<uint8_t, 8> kAADContextMetadata = {'Q', 'V', 'M', 'E',
                                                                 'T', 'A', 'D', 'T'}; // TSK014
  inline constexpr std::array<uint8_t, 8> kAADContextManifest = {'Q', 'V', 'M', 'A',
                                                                 'N', 'I', 'F', 'S'}; // TSK014

  inline std::array<uint8_t, 32>
  DerivePurposeKey(std::span<const uint8_t, 32> master, std::string_view label) { // TSK024_Key_Rotation_and_Lifecycle_Management
    if (label.empty()) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "HKDF label must not be empty"};
    }
    if (label.size() + 1 > 64) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "HKDF label too long"};
    }
    static constexpr std::array<uint8_t, 0> kEmptySalt{};
    const std::span<const uint8_t> info_span(
        reinterpret_cast<const uint8_t*>(label.data()), label.size());
    return qv::crypto::HKDF_SHA256(
        master, std::span<const uint8_t>(kEmptySalt.data(), kEmptySalt.size()),
        info_span); // TSK106_Cryptographic_Implementation_Weaknesses
  }

  inline std::array<uint8_t, 32>
  DeriveDataKey(std::span<const uint8_t, 32> master) { // TSK024_Key_Rotation_and_Lifecycle_Management
    return DerivePurposeKey(master, "QV-DATA-KEY/v1");
  }

  inline std::array<uint8_t, 32>
  DeriveMetadataKey(std::span<const uint8_t, 32> master) { // TSK024_Key_Rotation_and_Lifecycle_Management
    return DerivePurposeKey(master, "QV-METADATA-KEY/v1");
  }

  inline std::array<uint8_t, 32>
  DeriveIndexKey(std::span<const uint8_t, 32> master) { // TSK024_Key_Rotation_and_Lifecycle_Management
    return DerivePurposeKey(master, "QV-INDEX-KEY/v1");
  }

  struct AADData { // TSK014
    uint32_t epoch;
    int64_t chunk_index;
    uint64_t logical_offset;
    uint32_t chunk_size;
    uint64_t nonce_counter;              // TSK128_Missing_AAD_Validation_in_Chunks freshness binding
    uint8_t context[8];
  };

  struct AADEnvelope { // TSK014
    AADData data;
    std::array<uint8_t, 32> nonce_chain_mac;
  };
#pragma pack(pop)

  static_assert(sizeof(EpochTLV) == 8,
                "EpochTLV packing mismatch"); // TSK016_Windows_Compatibility_Fixes
  static_assert(sizeof(AADData) == 40,
                "AADData packing mismatch"); // TSK016_Windows_Compatibility_Fixes
  static_assert(sizeof(AADEnvelope) == 72,
                "AADEnvelope packing mismatch"); // TSK016_Windows_Compatibility_Fixes

  inline constexpr uint64_t ToLittleEndian64(uint64_t value) { // TSK014
    return qv::kIsLittleEndian ? value : qv::detail::ByteSwap64(value);
  }

  inline AADData MakeAADData(uint32_t epoch, int64_t chunk_index, uint64_t logical_offset,
                             uint32_t chunk_size, const std::array<uint8_t, 8>& context,
                             uint64_t nonce_counter = 0) { // TSK014, TSK128_Missing_AAD_Validation_in_Chunks
    AADData data{};
    data.epoch = qv::ToLittleEndian(epoch);
    const uint64_t index_le = ToLittleEndian64(static_cast<uint64_t>(chunk_index));
    std::memcpy(&data.chunk_index, &index_le, sizeof(index_le));
    const uint64_t offset_le = ToLittleEndian64(logical_offset);
    std::memcpy(&data.logical_offset, &offset_le, sizeof(offset_le));
    data.chunk_size = qv::ToLittleEndian(chunk_size);
    const uint64_t counter_le = ToLittleEndian64(nonce_counter);
    std::memcpy(&data.nonce_counter, &counter_le, sizeof(counter_le));
    std::copy(context.begin(), context.end(), std::begin(data.context));
    return data;
  }

  inline AADEnvelope MakeAADEnvelope(const AADData& data,
                                     std::span<const uint8_t, 32> nonce_chain_mac) { // TSK014
    AADEnvelope envelope{};
    envelope.data = data;
    std::copy(nonce_chain_mac.begin(), nonce_chain_mac.end(), envelope.nonce_chain_mac.begin());
    return envelope;
  }

  inline AADEnvelope MakeChunkAAD(uint32_t epoch, int64_t chunk_index, uint64_t logical_offset,
                                  uint32_t chunk_size,
                                  std::span<const uint8_t, 32> nonce_chain_mac,
                                  uint64_t nonce_counter = 0) { // TSK014, TSK128_Missing_AAD_Validation_in_Chunks
    return MakeAADEnvelope(
        MakeAADData(epoch, chunk_index, logical_offset, chunk_size, kAADContextChunkData, nonce_counter),
        nonce_chain_mac);
  }

  inline uint64_t ExtractNonceCounter(std::span<const uint8_t> nonce) { // TSK128_Missing_AAD_Validation_in_Chunks
    constexpr size_t kEpochPrefix = sizeof(uint32_t);
    if (nonce.size() < kEpochPrefix + sizeof(uint64_t)) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Nonce too short for counter"};
    }
    uint64_t counter_be = 0;
    std::memcpy(&counter_be, nonce.data() + kEpochPrefix, sizeof(counter_be));
    return qv::kIsLittleEndian ? qv::detail::ByteSwap64(counter_be) : counter_be;
  }

  inline AADEnvelope MakeMetadataAAD(
      uint32_t epoch, int64_t record_index, uint64_t logical_offset, uint32_t record_size,
      std::span<const uint8_t, 32> nonce_chain_mac,
      uint64_t nonce_counter = 0) { // TSK040_AAD_Binding_and_Chunk_Authentication metadata scope, TSK128_Missing_AAD_Validation_in_Chunks
    return MakeAADEnvelope(
        MakeAADData(epoch, record_index, logical_offset, record_size, kAADContextMetadata, nonce_counter),
        nonce_chain_mac);
  }

  inline AADEnvelope MakeManifestAAD(
      uint32_t epoch, int64_t record_index, uint64_t logical_offset, uint32_t record_size,
      std::span<const uint8_t, 32> nonce_chain_mac,
      uint64_t nonce_counter = 0) { // TSK040_AAD_Binding_and_Chunk_Authentication manifest scope, TSK128_Missing_AAD_Validation_in_Chunks
    return MakeAADEnvelope(
        MakeAADData(epoch, record_index, logical_offset, record_size, kAADContextManifest, nonce_counter),
        nonce_chain_mac);
  }

} // namespace qv::core
