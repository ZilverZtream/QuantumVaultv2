#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <span>
#include <vector>

#include "qv/crypto/aegis.h"
#include "qv/storage/chunk_manager.h"

namespace {

constexpr size_t kTestSize = 100 * 1024 * 1024;
constexpr size_t kReadBufferSize = 1024 * 1024;

// TSK064_Performance_Optimization_and_Caching
std::unique_ptr<qv::storage::ChunkManager> OpenManager(const std::filesystem::path& container) {
  std::array<uint8_t, 32> master_key{};
  auto cipher = qv::crypto::CipherType::AEGIS_128X;
  if (!qv::crypto::CipherAvailable(cipher)) {
    cipher = qv::crypto::CipherType::AEGIS_128L;
  }
  if (!qv::crypto::CipherAvailable(cipher)) {
    cipher = qv::crypto::CipherType::AES_256_GCM;
  }
  return std::make_unique<qv::storage::ChunkManager>(container, master_key, 0, cipher);
}

void BenchmarkSequentialWrite(const std::filesystem::path& container) {
  auto manager = OpenManager(container);
  const size_t chunk_size = qv::storage::kChunkSize;
  std::vector<uint8_t> chunk(chunk_size, 0);

  auto start = std::chrono::high_resolution_clock::now();
  const size_t chunk_count = (kTestSize + chunk_size - 1) / chunk_size;
  for (size_t idx = 0; idx < chunk_count; ++idx) {
    const size_t chunk_offset = idx * chunk_size;
    const size_t to_copy = std::min(chunk_size, kTestSize - chunk_offset);
    for (size_t i = 0; i < to_copy; ++i) {
      chunk[i] = static_cast<uint8_t>((chunk_offset + i) & 0xFF);
    }
    manager->WriteChunk(chunk_offset,
                        std::span<const uint8_t>(chunk.data(), to_copy));
  }
  manager->Flush();
  auto end = std::chrono::high_resolution_clock::now();

  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  double throughput = (kTestSize / (1024.0 * 1024.0)) / (duration.count() / 1000.0);
  std::cout << "Sequential Write: " << throughput << " MB/s\n";
}

void BenchmarkSequentialRead(const std::filesystem::path& container) {
  auto manager = OpenManager(container);
  std::vector<uint8_t> buffer(kReadBufferSize, 0);
  const size_t chunk_size = qv::storage::kChunkSize;

  auto start = std::chrono::high_resolution_clock::now();
  size_t total_read = 0;
  while (total_read < kTestSize) {
    const size_t chunk_offset = total_read;
    auto chunk = manager->ReadChunk(chunk_offset);
    const size_t to_copy = std::min(chunk_size, kTestSize - chunk_offset);
    std::memcpy(buffer.data(), chunk.data(), std::min(to_copy, chunk.size()));
    total_read += chunk_size;
  }
  auto end = std::chrono::high_resolution_clock::now();

  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  double throughput = (kTestSize / (1024.0 * 1024.0)) / (duration.count() / 1000.0);
  std::cout << "Sequential Read: " << throughput << " MB/s\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::filesystem::path container = std::filesystem::temp_directory_path() / "qv_perf_bench.container";
  if (argc > 1) {
    container = argv[1];
  }
  if (std::filesystem::exists(container)) {
    std::filesystem::remove(container);
  }

  BenchmarkSequentialWrite(container);
  BenchmarkSequentialRead(container);

  std::error_code ec;
  std::filesystem::remove(container, ec);
  return 0;
}
