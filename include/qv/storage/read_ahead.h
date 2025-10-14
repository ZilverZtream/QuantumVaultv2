#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <queue>
#include <thread>

namespace qv::storage {

class ChunkCache;
class ChunkManager;

// TSK064_Performance_Optimization_and_Caching
class ReadAheadManager {
 public:
  ReadAheadManager(ChunkManager& mgr, ChunkCache& cache);
  ~ReadAheadManager();

  ReadAheadManager(const ReadAheadManager&) = delete;
  ReadAheadManager& operator=(const ReadAheadManager&) = delete;

  void RequestReadAhead(uint64_t offset, size_t num_chunks);

 private:
  struct ReadAheadRequest {
    uint64_t logical_offset{0};
    size_t num_chunks{0};
  };

  void WorkerLoop();

  ChunkManager& chunk_mgr_;
  ChunkCache& cache_;
  std::thread worker_;
  std::atomic<bool> running_{true};

  std::queue<ReadAheadRequest> requests_;
  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;
};

}  // namespace qv::storage
