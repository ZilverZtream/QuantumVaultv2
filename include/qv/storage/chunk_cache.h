#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace qv::storage {

// TSK064_Performance_Optimization_and_Caching
struct CachedChunk {
  int64_t chunk_idx{0};
  std::vector<uint8_t> data;
  bool dirty{false};
  std::chrono::steady_clock::time_point last_access{};
};

class ChunkCache {
 public:
  explicit ChunkCache(size_t max_size = 128 * 1024 * 1024);

  std::shared_ptr<CachedChunk> Get(int64_t chunk_idx);

  std::shared_ptr<CachedChunk> Put(int64_t chunk_idx,
                                   std::vector<uint8_t> data,
                                   bool dirty);

  std::vector<int64_t> GetDirtyChunks() const;

  void MarkClean(int64_t chunk_idx);

  void Flush(std::function<void(int64_t, const std::vector<uint8_t>&)> write_fn);

  void SetWriteBackCallback(std::function<void(int64_t, const std::vector<uint8_t>&)> callback);

 private:
  struct EvictedChunk {
    int64_t index{0};
    std::shared_ptr<CachedChunk> chunk;
  };

  void TouchLocked(int64_t chunk_idx, const std::shared_ptr<CachedChunk>& chunk);

  EvictedChunk EvictLRULocked();

  size_t max_size_;
  size_t current_size_{0};

  std::unordered_map<int64_t, std::shared_ptr<CachedChunk>> cache_;
  std::list<int64_t> lru_list_;
  std::unordered_map<int64_t, std::list<int64_t>::iterator> lru_map_;

  std::function<void(int64_t, const std::vector<uint8_t>&)> write_back_;

  mutable std::shared_mutex mutex_;
};

}  // namespace qv::storage
