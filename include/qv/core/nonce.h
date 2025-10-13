#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <span>
#include <vector>
#include <algorithm>
#include <cstring>
#include "qv/common.h"
#include "qv/error.h"

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
public:
  NonceLog() = default;
  explicit NonceLog(const std::filesystem::path& path);
  std::array<uint8_t, 32> Append(uint64_t counter); // TSK014
  std::array<uint8_t, 32> LastMac() const; // TSK014
  bool VerifyChain();
  uint64_t GetLastCounter() const;
  size_t EntryCount() const;
private:
  void EnsureLoadedUnlocked();
  void ReloadUnlocked();
  void PersistUnlocked();
  void InitializeNewLog();
};

class NonceGenerator {
  uint32_t epoch_;
  std::atomic<uint64_t> counter_;
  NonceLog log_;
public:
  struct NonceRecord { // TSK014
    std::array<uint8_t, 12> nonce;
    uint64_t counter;
    std::array<uint8_t, 32> mac;
  };
  explicit NonceGenerator(uint32_t epoch, uint64_t start_counter = 0);
  NonceRecord NextAuthenticated(); // TSK014
  std::array<uint8_t, 12> Next();
  uint64_t CurrentCounter() const { return counter_.load(std::memory_order_acquire); }
  bool NeedsRekey() const {
    return counter_.load(std::memory_order_acquire) > (UINT64_MAX - 100'000'000ULL);
  }
};

// TSK016_Windows_Compatibility_Fixes ensure portable packed layout without compiler-specific attributes.
#pragma pack(push, 1)
struct EpochTLV {
  uint16_t type = 0x4E4F; // 'NO'
  uint16_t length = 4;
  uint32_t epoch;
};

inline constexpr std::array<uint8_t, 8> kAADContextChunkData = {'Q','V','C','H','U','N','K','D'}; // TSK014
inline constexpr std::array<uint8_t, 8> kAADContextMetadata = {'Q','V','M','E','T','A','D','T'}; // TSK014
inline constexpr std::array<uint8_t, 8> kAADContextManifest = {'Q','V','M','A','N','I','F','S'}; // TSK014

struct AADData { // TSK014
  uint32_t epoch;
  int64_t  chunk_index;
  uint64_t logical_offset;
  uint32_t chunk_size;
  uint8_t  context[8];
};

struct AADEnvelope { // TSK014
  AADData data;
  std::array<uint8_t, 32> nonce_chain_mac;
};
#pragma pack(pop)

static_assert(sizeof(EpochTLV) == 8, "EpochTLV packing mismatch"); // TSK016_Windows_Compatibility_Fixes
static_assert(sizeof(AADData) == 32, "AADData packing mismatch");   // TSK016_Windows_Compatibility_Fixes
static_assert(sizeof(AADEnvelope) == 64, "AADEnvelope packing mismatch"); // TSK016_Windows_Compatibility_Fixes

inline constexpr uint64_t ToLittleEndian64(uint64_t value) { // TSK014
  return qv::kIsLittleEndian ? value : qv::detail::ByteSwap64(value);
}

inline AADData MakeAADData(uint32_t epoch,
                           int64_t chunk_index,
                           uint64_t logical_offset,
                           uint32_t chunk_size,
                           const std::array<uint8_t, 8>& context) { // TSK014
  AADData data{};
  data.epoch = qv::ToLittleEndian(epoch);
  const uint64_t index_le = ToLittleEndian64(static_cast<uint64_t>(chunk_index));
  std::memcpy(&data.chunk_index, &index_le, sizeof(index_le));
  const uint64_t offset_le = ToLittleEndian64(logical_offset);
  std::memcpy(&data.logical_offset, &offset_le, sizeof(offset_le));
  data.chunk_size = qv::ToLittleEndian(chunk_size);
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

inline AADEnvelope MakeChunkAAD(uint32_t epoch,
                                int64_t chunk_index,
                                uint64_t logical_offset,
                                uint32_t chunk_size,
                                std::span<const uint8_t, 32> nonce_chain_mac) { // TSK014
  return MakeAADEnvelope(MakeAADData(epoch, chunk_index, logical_offset, chunk_size, kAADContextChunkData),
                         nonce_chain_mac);
}

} // namespace qv::core
