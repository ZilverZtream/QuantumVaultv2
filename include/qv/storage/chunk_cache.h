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
  uint64_t version{0};  // TSK096_Race_Conditions_and_Thread_Safety
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

  void Invalidate(int64_t chunk_idx);  // TSK076_Cache_Coherency

  void Flush(std::function<void(int64_t, const std::vector<uint8_t>&)> write_fn);

  void SetWriteBackCallback(std::function<void(int64_t, const std::vector<uint8_t>&)> callback);

 private:
  struct EvictedChunk {
    int64_t index{0};
    std::shared_ptr<CachedChunk> chunk;
  };

  struct CacheEntry {
    std::shared_ptr<CachedChunk> chunk;
    uint64_t version{0};
  };

  struct LruNode { // TSK105_Resource_Leaks_and_Lifecycle
    int64_t index{0};
    std::weak_ptr<CachedChunk> chunk;
  };

  struct EraseResult {
    std::shared_ptr<CachedChunk> chunk;
    uint64_t generation{0};
    uint64_t previous_generation{0};  // TSK115_Memory_Leaks_and_Resource_Management rollback support
  };

  void TouchLocked(int64_t chunk_idx, const std::shared_ptr<CachedChunk>& chunk);

  EvictedChunk EvictLRULocked();

  EraseResult EraseLocked(int64_t chunk_idx);  // TSK076_Cache_Coherency

  void CheckInvariantsLocked() const;  // TSK108_Data_Structure_Invariants debug validation

  size_t max_size_;
  size_t current_size_{0};

  std::unordered_map<int64_t, CacheEntry> cache_;
  std::list<LruNode> lru_list_;                                    // TSK105_Resource_Leaks_and_Lifecycle
  std::unordered_map<int64_t, std::list<LruNode>::iterator> lru_map_; // TSK105_Resource_Leaks_and_Lifecycle

  std::function<void(int64_t, const std::vector<uint8_t>&)> write_back_;

  std::unordered_map<int64_t, uint64_t> cache_generations_;  // TSK096_Race_Conditions_and_Thread_Safety

  mutable std::shared_mutex mutex_;
};

}  // namespace qv::storage
