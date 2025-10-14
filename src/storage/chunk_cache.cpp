#include "qv/storage/chunk_cache.h"

#include <algorithm>
#include <mutex> // TSK067_Nonce_Safety

namespace qv::storage {

// TSK064_Performance_Optimization_and_Caching
ChunkCache::ChunkCache(size_t max_size) : max_size_(max_size) {}

std::shared_ptr<CachedChunk> ChunkCache::Get(int64_t chunk_idx) {
  std::shared_ptr<CachedChunk> chunk;
  {
    std::shared_lock read_lock(mutex_);  // TSK076_Cache_Coherency
    auto it = cache_.find(chunk_idx);
    if (it == cache_.end()) {
      return nullptr;
    }
    chunk = it->second;
  }

  std::unique_lock write_lock(mutex_);
  auto it = cache_.find(chunk_idx);
  if (it == cache_.end()) {
    return nullptr;
  }
  chunk = it->second;
  TouchLocked(chunk_idx, chunk);
  return chunk;
}

std::shared_ptr<CachedChunk> ChunkCache::Put(int64_t chunk_idx,
                                             std::vector<uint8_t> data,
                                             bool dirty) {
  std::vector<std::shared_ptr<CachedChunk>> to_flush;
  std::function<void(int64_t, const std::vector<uint8_t>&)> callback;
  {
    std::unique_lock lock(mutex_);

    EraseLocked(chunk_idx);  // TSK076_Cache_Coherency

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

    current_size_ += chunk->data.size();
    cache_[chunk_idx] = chunk;
    lru_list_.push_front(chunk_idx);
    lru_map_[chunk_idx] = lru_list_.begin();
    callback = write_back_;
  }

  if (callback) {
    for (const auto& chunk : to_flush) {
      callback(chunk->chunk_idx, chunk->data);
    }
  }

  return Get(chunk_idx);
}

std::vector<int64_t> ChunkCache::GetDirtyChunks() const {
  std::shared_lock lock(mutex_);
  std::vector<int64_t> dirty;
  dirty.reserve(cache_.size());
  for (const auto& [idx, chunk] : cache_) {
    if (chunk->dirty) {
      dirty.push_back(idx);
    }
  }
  return dirty;
}

void ChunkCache::MarkClean(int64_t chunk_idx) {
  std::unique_lock lock(mutex_);
  if (auto it = cache_.find(chunk_idx); it != cache_.end()) {
    it->second->dirty = false;
  }
}

void ChunkCache::Invalidate(int64_t chunk_idx) {  // TSK076_Cache_Coherency
  std::unique_lock lock(mutex_);
  EraseLocked(chunk_idx);
}

void ChunkCache::Flush(std::function<void(int64_t, const std::vector<uint8_t>&)> write_fn) {
  struct DirtyEntry {
    int64_t index;
    std::shared_ptr<CachedChunk> chunk;
  };
  std::vector<DirtyEntry> dirty_chunks;  // TSK076_Cache_Coherency
  {
    std::unique_lock lock(mutex_);
    for (auto& [idx, chunk] : cache_) {
      if (chunk->dirty) {
        chunk->dirty = false;
        dirty_chunks.push_back(DirtyEntry{idx, chunk});
      }
    }
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
  write_back_ = std::move(callback);
}

void ChunkCache::TouchLocked(int64_t chunk_idx, const std::shared_ptr<CachedChunk>& chunk) {
  auto map_it = lru_map_.find(chunk_idx);
  if (map_it != lru_map_.end()) {
    lru_list_.erase(map_it->second);
  }
  lru_list_.push_front(chunk_idx);
  lru_map_[chunk_idx] = lru_list_.begin();
  chunk->last_access = std::chrono::steady_clock::now();
}

ChunkCache::EvictedChunk ChunkCache::EvictLRULocked() {
  EvictedChunk evicted{};
  if (lru_list_.empty()) {
    return evicted;
  }

  auto victim_idx = lru_list_.back();
  lru_list_.pop_back();
  lru_map_.erase(victim_idx);

  if (auto it = cache_.find(victim_idx); it != cache_.end()) {
    evicted.index = victim_idx;
    evicted.chunk = it->second;
    current_size_ -= it->second->data.size();
    cache_.erase(it);
  }

  return evicted;
}

void ChunkCache::EraseLocked(int64_t chunk_idx) {  // TSK076_Cache_Coherency
  if (auto existing = cache_.find(chunk_idx); existing != cache_.end()) {
    current_size_ -= existing->second->data.size();
    if (auto lru_it = lru_map_.find(chunk_idx); lru_it != lru_map_.end()) {
      lru_list_.erase(lru_it->second);
      lru_map_.erase(lru_it);
    }
    cache_.erase(existing);
  }
}

}  // namespace qv::storage
