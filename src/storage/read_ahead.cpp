#include "qv/storage/read_ahead.h"

#include "qv/storage/chunk_cache.h"
#include "qv/storage/chunk_layout.h"
#include "qv/storage/chunk_manager.h"

namespace qv::storage {

// TSK064_Performance_Optimization_and_Caching
ReadAheadManager::ReadAheadManager(ChunkManager& mgr, ChunkCache& cache)
    : chunk_mgr_(mgr), cache_(cache) {
  worker_ = std::thread([this]() { WorkerLoop(); });
}

ReadAheadManager::~ReadAheadManager() {
  running_ = false;
  queue_cv_.notify_all();
  if (worker_.joinable()) {
    worker_.join();
  }
}

void ReadAheadManager::RequestReadAhead(uint64_t offset, size_t num_chunks) {
  if (!running_) {
    return;
  }
  {
    std::lock_guard lock(queue_mutex_);
    requests_.push({offset, num_chunks});
  }
  queue_cv_.notify_one();
}

void ReadAheadManager::WorkerLoop() {
  while (running_) {
    ReadAheadRequest request{};
    {
      std::unique_lock lock(queue_mutex_);
      queue_cv_.wait(lock, [this]() { return !requests_.empty() || !running_; });
      if (!running_) {
        return;
      }
      request = requests_.front();
      requests_.pop();
    }

    for (size_t i = 0; i < request.num_chunks; ++i) {
      int64_t chunk_idx = static_cast<int64_t>((request.logical_offset / kChunkSize) + i);
      if (cache_.Get(chunk_idx)) {
        continue;
      }
      try {
        chunk_mgr_.ReadChunk(static_cast<uint64_t>(chunk_idx) * kChunkSize, true);
      } catch (...) {
        // Ignore read-ahead failures and continue with next chunk.
      }
    }
  }
}

}  // namespace qv::storage
