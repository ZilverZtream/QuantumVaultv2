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

// TSK112_Documentation_and_Code_Clarity: Thread-safety — all public methods synchronize
// on mutex_, while helpers suffixed with *Locked expect the caller to hold the lock.
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
  };

  /// TSK112_Documentation_and_Code_Clarity: Updates LRU access bookkeeping.
  ///
  /// Preconditions:
  ///   - mutex_ must be held by the caller (write lock)
  ///   - chunk_idx exists in both cache_ and lru_map_
  ///
  /// Invariants maintained:
  ///   - lru_list_.size() == lru_map_.size() == cache_.size()
  ///   - lru_list_.front()->index == chunk_idx after return
  ///   - chunk->last_access is refreshed to now
  ///
  /// Thread-safety: NOT thread-safe; relies on external synchronization.
  void TouchLocked(int64_t chunk_idx, const std::shared_ptr<CachedChunk>& chunk);

  EvictedChunk EvictLRULocked();

  EraseResult EraseLocked(int64_t chunk_idx);  // TSK076_Cache_Coherency

  void CheckInvariantsLocked() const;  // TSK108_Data_Structure_Invariants debug validation

  size_t max_size_;
  size_t current_size_{0};

  std::unordered_map<int64_t, CacheEntry> cache_;
  std::list<LruNode> lru_list_;                                    // TSK105_Resource_Leaks_and_Lifecycle
  // TSK112_Documentation_and_Code_Clarity: Invariant — lru_list_, lru_map_, and cache_ contain
  // the same set of keys; size counters track the aggregate payload of cache_.
  std::unordered_map<int64_t, std::list<LruNode>::iterator> lru_map_; // TSK105_Resource_Leaks_and_Lifecycle

  std::function<void(int64_t, const std::vector<uint8_t>&)> write_back_;

  std::unordered_map<int64_t, uint64_t> cache_generations_;  // TSK096_Race_Conditions_and_Thread_Safety

  mutable std::shared_mutex mutex_;
};

}  // namespace qv::storage
