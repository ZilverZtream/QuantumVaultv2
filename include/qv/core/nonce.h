#pragma once
#include <array>
#include <atomic>
#include <filesystem>
#include <mutex>
#include "qv/common.h"
#include "qv/error.h"

namespace qv::core {

class NonceLog {
  int fd_{-1};
  std::array<uint8_t, 32> key_{};
  std::array<uint8_t, 32> last_mac_{};
  std::filesystem::path path_;
  mutable std::mutex mu_;
public:
  NonceLog() = default;
  explicit NonceLog(const std::filesystem::path& path);
  ~NonceLog();
  void Append(uint64_t counter);
  bool VerifyChain();
  uint64_t GetLastCounter() const;
};

class NonceGenerator {
  uint32_t epoch_;
  std::atomic<uint64_t> counter_;
  NonceLog log_;
public:
  explicit NonceGenerator(uint32_t epoch, uint64_t start_counter = 0);
  std::array<uint8_t, 12> Next();
  uint64_t CurrentCounter() const { return counter_.load(std::memory_order_acquire); }
  bool NeedsRekey() const {
    return counter_.load(std::memory_order_acquire) > (UINT64_MAX - 100'000'000ULL);
  }
};

struct EpochTLV {
  uint16_t type = 0x4E4F; // 'NO'
  uint16_t length = 4;
  uint32_t epoch;
} __attribute__((packed));

struct AADData {
  uint32_t epoch;
  int64_t  chunk_index;
  uint64_t logical_offset;
  uint32_t chunk_size;
  uint8_t  context[8] = {'Q','V','C','H','U','N','K',0};
} __attribute__((packed));

} // namespace qv::core
