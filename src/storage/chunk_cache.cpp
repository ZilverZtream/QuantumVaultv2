#include "qv/storage/chunk_cache.h"

#include <algorithm>
#include <cassert>  // TSK108_Data_Structure_Invariants
#include <iterator> // TSK105_Resource_Leaks_and_Lifecycle
#include <mutex> // TSK067_Nonce_Safety

namespace qv::storage {

// TSK064_Performance_Optimization_and_Caching
ChunkCache::ChunkCache(size_t max_size) : max_size_(max_size) {}

std::shared_ptr<CachedChunk> ChunkCache::Get(int64_t chunk_idx) {
  std::unique_lock write_lock(mutex_);  // TSK104_Concurrency_Deadlock_and_Lock_Ordering avoid upgrades
  CheckInvariantsLocked();             // TSK108_Data_Structure_Invariants
  auto it = cache_.find(chunk_idx);
  if (it == cache_.end()) {
    CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants ensure structural parity on miss
    return nullptr;
  }
  auto chunk = it->second.chunk;
  TouchLocked(chunk_idx, chunk);
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants post-touch validation
  return chunk;
}

std::shared_ptr<CachedChunk> ChunkCache::Put(int64_t chunk_idx,
                                             std::vector<uint8_t> data,
                                             bool dirty) {
  std::vector<std::shared_ptr<CachedChunk>> to_flush;
  std::function<void(int64_t, const std::vector<uint8_t>&)> callback;
  std::shared_ptr<CachedChunk> inserted;  // TSK104_Concurrency_Deadlock_and_Lock_Ordering retain result outside lock
  {
    std::unique_lock lock(mutex_);

    CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants pre-insert validation

    auto erased = EraseLocked(chunk_idx);  // TSK076_Cache_Coherency

    while (current_size_ + data.size() > max_size_ && !cache_.empty()) {
      auto evicted = EvictLRULocked();
      if (evicted.chunk && evicted.chunk->dirty && write_back_) {
        to_flush.push_back(evicted.chunk);
      }
    }

    auto chunk = std::make_shared<CachedChunk>();
    chunk->chunk_idx = chunk_idx;
    chunk->data = std::move(data);
    chunk->dirty = dirty;
    chunk->last_access = std::chrono::steady_clock::now();
    chunk->version = erased.generation;

    current_size_ += chunk->data.size();
    cache_[chunk_idx] = CacheEntry{chunk, chunk->version};
    TouchLocked(chunk_idx, chunk);  // TSK105_Resource_Leaks_and_Lifecycle reuse LRU helper
    inserted = chunk;
    callback = write_back_;

    CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants confirm accounting updated
  }

  if (callback) {
    for (const auto& chunk : to_flush) {
      callback(chunk->chunk_idx, chunk->data);
    }
  }

  return inserted;
}

std::vector<int64_t> ChunkCache::GetDirtyChunks() const {
  std::shared_lock lock(mutex_);
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants monitor read paths
  std::vector<int64_t> dirty;
  dirty.reserve(cache_.size());
  for (const auto& [idx, entry] : cache_) {
    if (entry.chunk && entry.chunk->dirty) {
      dirty.push_back(idx);
    }
  }
  return dirty;
}

void ChunkCache::MarkClean(int64_t chunk_idx) {
  std::unique_lock lock(mutex_);
  CheckInvariantsLocked();
  if (auto it = cache_.find(chunk_idx); it != cache_.end()) {
    it->second.chunk->dirty = false;
  }
  CheckInvariantsLocked();
}

void ChunkCache::Invalidate(int64_t chunk_idx) {  // TSK076_Cache_Coherency
  std::unique_lock lock(mutex_);
  CheckInvariantsLocked();
  EraseLocked(chunk_idx);
  CheckInvariantsLocked();
}

void ChunkCache::Flush(std::function<void(int64_t, const std::vector<uint8_t>&)> write_fn) {
  struct DirtyEntry {
    int64_t index;
    std::shared_ptr<CachedChunk> chunk;
  };
  std::vector<DirtyEntry> dirty_chunks;  // TSK076_Cache_Coherency
  {
    std::unique_lock lock(mutex_);
    CheckInvariantsLocked();
    for (auto& [idx, entry] : cache_) {
      if (entry.chunk && entry.chunk->dirty) {
        entry.chunk->dirty = false;
        dirty_chunks.push_back(DirtyEntry{idx, entry.chunk});
      }
    }
    CheckInvariantsLocked();
  }

  std::sort(dirty_chunks.begin(), dirty_chunks.end(),
            [](const DirtyEntry& lhs, const DirtyEntry& rhs) { return lhs.index < rhs.index; });

  for (const auto& entry : dirty_chunks) {
    write_fn(entry.index, entry.chunk->data);
  }
}

void ChunkCache::SetWriteBackCallback(
    std::function<void(int64_t, const std::vector<uint8_t>&)> callback) {
  std::unique_lock lock(mutex_);
  CheckInvariantsLocked();
  write_back_ = std::move(callback);
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants callback updates do not affect structure
}

void ChunkCache::TouchLocked(int64_t chunk_idx, const std::shared_ptr<CachedChunk>& chunk) {
  // TSK112_Documentation_and_Code_Clarity: Maintain the parallel LRU structures in lock-step
  // so invariants described in the header remain valid for debugging assertions.
  auto map_it = lru_map_.find(chunk_idx);
  if (map_it != lru_map_.end()) {
    lru_list_.erase(map_it->second);
  }
  lru_list_.push_front(LruNode{chunk_idx, chunk});
  lru_map_[chunk_idx] = lru_list_.begin();
  chunk->last_access = std::chrono::steady_clock::now();
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants validate LRU bookkeeping
}

ChunkCache::EvictedChunk ChunkCache::EvictLRULocked() {
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants pre-eviction audit
  EvictedChunk evicted{};
  if (lru_list_.empty()) {
    CheckInvariantsLocked();
    return evicted;
  }

  while (!lru_list_.empty()) {
    auto node_it = std::prev(lru_list_.end());
    if (node_it->chunk.expired()) {  // TSK105_Resource_Leaks_and_Lifecycle prune stale nodes
      lru_map_.erase(node_it->index);
      lru_list_.pop_back();
      CheckInvariantsLocked();
      continue;
    }

    auto victim_idx = node_it->index;
    auto erased = EraseLocked(victim_idx);
    evicted.index = victim_idx;
    evicted.chunk = erased.chunk;
    if (!evicted.chunk) {
      CheckInvariantsLocked();
      continue;
    }
    CheckInvariantsLocked();
    return evicted;
  }

  CheckInvariantsLocked();
  return evicted;
}

ChunkCache::EraseResult ChunkCache::EraseLocked(int64_t chunk_idx) {  // TSK076_Cache_Coherency
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants pre-erase snapshot
  EraseResult result{};
  auto& generation = cache_generations_[chunk_idx];
  generation += 1;
  result.generation = generation;

  if (auto existing = cache_.find(chunk_idx); existing != cache_.end()) {
    if (existing->second.chunk) {
      current_size_ -= existing->second.chunk->data.size();  // TSK105_Resource_Leaks_and_Lifecycle guard null
    }
    if (auto lru_it = lru_map_.find(chunk_idx); lru_it != lru_map_.end()) {
      lru_list_.erase(lru_it->second);
      lru_map_.erase(lru_it);
    }
    result.chunk = existing->second.chunk;
    cache_.erase(existing);
  }

  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants ensure size accounting updated
  return result;
}

void ChunkCache::CheckInvariantsLocked() const {  // TSK108_Data_Structure_Invariants central validation
#ifndef NDEBUG
  size_t counted_size = 0;
  assert(cache_.size() == lru_map_.size());
  assert(lru_map_.size() == lru_list_.size());
  for (const auto& [idx, entry] : cache_) {
    auto lru_it = lru_map_.find(idx);
    assert(lru_it != lru_map_.end());
    assert(lru_it->second != lru_list_.end());
    if (entry.chunk) {
      counted_size += entry.chunk->data.size();
    }
  }

  size_t listed_entries = 0;
  for (const auto& node : lru_list_) {
    ++listed_entries;
    auto cache_it = cache_.find(node.index);
    assert(cache_it != cache_.end());
    if (auto shared = node.chunk.lock()) {
      assert(cache_it->second.chunk == shared);
    }
  }
  assert(listed_entries == lru_list_.size());
  assert(counted_size == current_size_);
  assert(current_size_ <= max_size_);
#else
  (void)this;
#endif
}

}  // namespace qv::storage
