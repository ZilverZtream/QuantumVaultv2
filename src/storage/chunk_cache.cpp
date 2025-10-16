#include "qv/storage/chunk_cache.h"

#include <algorithm>
#include <cassert>  // TSK108_Data_Structure_Invariants
#include <iterator> // TSK105_Resource_Leaks_and_Lifecycle
#include <limits>   // TSK115_Memory_Leaks_and_Resource_Management generation bounds
#include <mutex> // TSK067_Nonce_Safety
#include <utility> // TSK113_Performance_and_Scalability batching helpers

namespace qv::storage {

namespace {

constexpr uint64_t kGenerationResetThreshold =
    static_cast<uint64_t>(std::numeric_limits<uint32_t>::max() / 2);  // TSK115_Memory_Leaks_and_Resource_Management cap generation drift

constexpr size_t kExpiredPruneInterval = 32;  // TSK126_Inefficient_Chunk_Cache_Eviction amortize global sweeps

class FlushBufferPool { // TSK113_Performance_and_Scalability reuse staging buffers
 public:
  std::vector<uint8_t> Acquire(size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = buffers_.begin(); it != buffers_.end(); ++it) {
      if (it->capacity() >= size) {
        auto buffer = std::move(*it);
        buffers_.erase(it);
        buffer.resize(size);
        return buffer;
      }
    }
    return std::vector<uint8_t>(size);
  }

  void Release(std::vector<uint8_t> buffer) {
    std::lock_guard<std::mutex> lock(mutex_);
    buffer.clear();
    buffers_.push_back(std::move(buffer));
  }

 private:
  std::mutex mutex_;
  std::vector<std::vector<uint8_t>> buffers_;
};

FlushBufferPool& SharedFlushPool() {
  static FlushBufferPool pool;
  return pool;
}

void FlushDirtyOutsideLock(std::vector<std::shared_ptr<CachedChunk>>& chunks,
                           const std::function<void(int64_t, const std::vector<uint8_t>&)>& callback,
                           bool preserve_chunk_storage) {
  if (!callback || chunks.empty()) {
    chunks.clear();
    return;
  }

  std::sort(chunks.begin(), chunks.end(), [](const auto& lhs, const auto& rhs) {
    return lhs->chunk_idx < rhs->chunk_idx;
  });

  auto& pool = SharedFlushPool();
  size_t index = 0;
  while (index < chunks.size()) {
    size_t run_end = index + 1;
    while (run_end < chunks.size() &&
           chunks[run_end]->chunk_idx == chunks[run_end - 1]->chunk_idx + 1) {
      ++run_end;
    }

    for (size_t i = index; i < run_end; ++i) {
      auto& chunk = chunks[i];
      if (!chunk) {
        continue;
      }
      const auto chunk_index = chunk->chunk_idx;
      std::vector<uint8_t> buffer;
      const bool reuse_storage =
          !preserve_chunk_storage && chunk.use_count() == 1;  // TSK113_Performance_and_Scalability reuse eviction storage
      if (reuse_storage) {
        buffer = std::move(chunk->data);
      } else {
        buffer = pool.Acquire(chunk->data.size());
        std::copy(chunk->data.begin(), chunk->data.end(), buffer.begin());
      }
      try {
        callback(chunk_index, buffer);
      } catch (...) {
        if (reuse_storage) {
          chunk->data = std::move(buffer);  // TSK115_Memory_Leaks_and_Resource_Management restore on failure
        } else {
          pool.Release(std::move(buffer));
        }
        throw;
      }
      pool.Release(std::move(buffer));
      chunk.reset();
    }

    index = run_end;
  }

  chunks.clear();
}

}  // namespace

// TSK064_Performance_Optimization_and_Caching
ChunkCache::ChunkCache(size_t max_size) : max_size_(max_size) {}

std::shared_ptr<CachedChunk> ChunkCache::Get(int64_t chunk_idx) {
  std::unique_lock write_lock(mutex_);  // TSK104_Concurrency_Deadlock_and_Lock_Ordering avoid upgrades
  CheckInvariantsLocked();             // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
  std::shared_ptr<CachedChunk> result;
  auto it = cache_.find(chunk_idx);
  if (it != cache_.end()) {
    auto chunk = it->second.chunk;
    TouchLocked(chunk_idx, chunk);
    result = std::move(chunk);
  }
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
  return result;
}

std::shared_ptr<CachedChunk> ChunkCache::Put(int64_t chunk_idx,
                                             std::vector<uint8_t> data,
                                             bool dirty) {
  std::vector<std::shared_ptr<CachedChunk>> to_flush;
  std::function<void(int64_t, const std::vector<uint8_t>&)> callback;
  std::shared_ptr<CachedChunk> inserted;  // TSK104_Concurrency_Deadlock_and_Lock_Ordering retain result outside lock
  ChunkCache::EraseResult erased{};
  std::shared_ptr<CachedChunk> replaced_chunk;
  {
    std::unique_lock lock(mutex_);
    CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check

    erased = EraseLocked(chunk_idx);  // TSK076_Cache_Coherency
    replaced_chunk = erased.chunk;

    size_t reclaim_needed = 0;  // TSK126_Inefficient_Chunk_Cache_Eviction batch eviction sizing
    if (current_size_ + data.size() > max_size_) {
      reclaim_needed = current_size_ + data.size() - max_size_;
    }

    while (reclaim_needed > 0 && (!lru_list_.empty() || !cache_.empty())) {
      auto evicted = EvictLRULocked();
      if (!evicted.chunk) {
        if (lru_list_.empty()) {
          break;  // only expired placeholders remained
        }
        continue;
      }

      if (evicted.chunk->dirty && write_back_) {
        to_flush.push_back(evicted.chunk);  // TSK126_Inefficient_Chunk_Cache_Eviction defer write-back until unlocked
      }

      const size_t evicted_size = evicted.chunk->data.size();
      if (evicted_size >= reclaim_needed) {
        reclaim_needed = 0;
      } else {
        reclaim_needed -= evicted_size;
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

    CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
  }

  if (callback) {
    try {
      FlushDirtyOutsideLock(to_flush, callback, false);  // TSK113_Performance_and_Scalability staged eviction writes
    } catch (...) {
      std::unique_lock lock(mutex_);
      if (inserted) {
        if (auto cache_it = cache_.find(chunk_idx); cache_it != cache_.end() &&
                                                  cache_it->second.chunk == inserted) {
          current_size_ -= inserted->data.size();
          if (auto lru_it = lru_map_.find(chunk_idx); lru_it != lru_map_.end()) {
            lru_list_.erase(lru_it->second);
            lru_map_.erase(lru_it);
          }
          cache_.erase(cache_it);
        }
      }
      cache_generations_[chunk_idx] = erased.previous_generation;  // TSK115_Memory_Leaks_and_Resource_Management rollback state
      if (replaced_chunk) {
        replaced_chunk->version = erased.previous_generation;
        current_size_ += replaced_chunk->data.size();
        cache_[chunk_idx] = CacheEntry{replaced_chunk, replaced_chunk->version};
        TouchLocked(chunk_idx, replaced_chunk);
      }
      for (auto& chunk : to_flush) {
        if (!chunk) {
          continue;
        }
        cache_generations_[chunk->chunk_idx] = chunk->version;
        current_size_ += chunk->data.size();
        cache_[chunk->chunk_idx] = CacheEntry{chunk, chunk->version};
        TouchLocked(chunk->chunk_idx, chunk);
      }
      CheckInvariantsLocked();
      throw;
    }
  }

  return inserted;
}

std::vector<int64_t> ChunkCache::GetDirtyChunks() const {
  std::shared_lock lock(mutex_);
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
  std::vector<int64_t> dirty;
  dirty.reserve(cache_.size());
  for (const auto& [idx, entry] : cache_) {
    if (entry.chunk && entry.chunk->dirty) {
      dirty.push_back(idx);
    }
  }
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
  return dirty;
}

void ChunkCache::MarkClean(int64_t chunk_idx) {
  std::unique_lock lock(mutex_);
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
  if (auto it = cache_.find(chunk_idx); it != cache_.end()) {
    it->second.chunk->dirty = false;
  }
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
}

void ChunkCache::Invalidate(int64_t chunk_idx) {  // TSK076_Cache_Coherency
  std::unique_lock lock(mutex_);
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
  EraseLocked(chunk_idx);
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
}

void ChunkCache::Flush(std::function<void(int64_t, const std::vector<uint8_t>&)> write_fn) {
  struct DirtyEntry {
    int64_t index;
    std::shared_ptr<CachedChunk> chunk;
  };
  std::vector<DirtyEntry> dirty_chunks;  // TSK076_Cache_Coherency
  {
    std::unique_lock lock(mutex_);
    CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
    for (auto& [idx, entry] : cache_) {
      if (entry.chunk && entry.chunk->dirty) {
        entry.chunk->dirty = false;
        dirty_chunks.push_back(DirtyEntry{idx, entry.chunk});
      }
    }
    CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
  }

  std::vector<std::shared_ptr<CachedChunk>> flush_chunks;
  flush_chunks.reserve(dirty_chunks.size());
  for (auto& entry : dirty_chunks) {
    flush_chunks.push_back(std::move(entry.chunk));
  }

  FlushDirtyOutsideLock(flush_chunks, write_fn, true); // TSK113_Performance_and_Scalability batched flush staging
}

void ChunkCache::SetWriteBackCallback(
    std::function<void(int64_t, const std::vector<uint8_t>&)> callback) {
  std::unique_lock lock(mutex_);
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
  write_back_ = std::move(callback);
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
}

void ChunkCache::PruneExpiredLocked() {
  if (lru_list_.empty()) {
    return;
  }

  for (auto it = lru_list_.begin(); it != lru_list_.end();) {
    if (!it->chunk.expired()) {
      ++it;
      continue;
    }

    if (auto generation_it = cache_generations_.find(it->index);
        generation_it != cache_generations_.end() &&
        generation_it->second >= kGenerationResetThreshold) {
      generation_it->second = 0;  // TSK115_Memory_Leaks_and_Resource_Management clamp runaway counters // TSK126_Inefficient_Chunk_Cache_Eviction batch prune generation reset
    }
    lru_map_.erase(it->index);  // TSK126_Inefficient_Chunk_Cache_Eviction remove expired node bookkeeping
    it = lru_list_.erase(it);
  }
}

void ChunkCache::TouchLocked(int64_t chunk_idx, const std::shared_ptr<CachedChunk>& chunk) {
  // TSK112_Documentation_and_Code_Clarity: Maintain the parallel LRU structures in lock-step
  // so invariants described in the header remain valid for debugging assertions.
  const bool already_front = !lru_list_.empty() && lru_list_.front().index == chunk_idx;  // TSK126_Inefficient_Chunk_Cache_Eviction avoid redundant moves
  if (already_front) {
    lru_list_.front().chunk = chunk;
  } else {
    if (auto map_it = lru_map_.find(chunk_idx); map_it != lru_map_.end()) {
      lru_list_.erase(map_it->second);
    }
    lru_list_.push_front(LruNode{chunk_idx, chunk});
  }
  lru_map_[chunk_idx] = lru_list_.begin();
  chunk->last_access = std::chrono::steady_clock::now();
}

ChunkCache::EvictedChunk ChunkCache::EvictLRULocked() {
  CheckInvariantsLocked();  // TSK108_Data_Structure_Invariants // TSK126_Inefficient_Chunk_Cache_Eviction boundary-only invariant check
  EvictedChunk evicted{};
  if (lru_list_.empty()) {
    CheckInvariantsLocked();
    return evicted;
  }

  if (++eviction_prune_stride_ >= kExpiredPruneInterval) {
    PruneExpiredLocked();  // TSK126_Inefficient_Chunk_Cache_Eviction amortize stale sweeps
    eviction_prune_stride_ = 0;
  }

  while (!lru_list_.empty()) {
    auto node_it = std::prev(lru_list_.end());
    if (node_it->chunk.expired()) {
      PruneExpiredLocked();
      if (lru_list_.empty()) {
        break;
      }
      continue;
    }

    auto victim_idx = node_it->index;
    auto erased = EraseLocked(victim_idx);
    evicted.index = victim_idx;
    evicted.chunk = erased.chunk;
    if (evicted.chunk) {
      break;
    }
  }

  CheckInvariantsLocked();
  return evicted;
}

ChunkCache::EraseResult ChunkCache::EraseLocked(int64_t chunk_idx) {  // TSK076_Cache_Coherency
  EraseResult result{};
  auto& generation = cache_generations_[chunk_idx];
  uint64_t previous_generation = generation;
  if (generation >= kGenerationResetThreshold) {
    generation = 0;  // TSK115_Memory_Leaks_and_Resource_Management prevent overflow runaway
    previous_generation = 0;
  }
  generation += 1;
  result.previous_generation = previous_generation;
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
