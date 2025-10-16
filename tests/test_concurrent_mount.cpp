#include "qv/core/nonce.h" // TSK034

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <span>      // TSK128_Missing_AAD_Validation_in_Chunks
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace tsk034 { // TSK034

  class TempDir { // TSK034
  public:
    TempDir() {
      auto base = std::filesystem::temp_directory_path();
      auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
      auto name = std::string{"qv_concurrent_"} +
                  std::to_string(static_cast<unsigned long long>(stamp));
      path_ = base / name;
      std::filesystem::create_directories(path_);
    }

    ~TempDir() {
      std::error_code ec;
      std::filesystem::remove_all(path_, ec);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

  private:
    std::filesystem::path path_{};
  };

} // namespace tsk034

namespace { // TSK034

  struct Options { // TSK034
    size_t threads{4};
  };

  Options ParseOptions(int argc, char** argv) { // TSK034
    Options opts;
    for (int i = 1; i < argc; ++i) {
      std::string_view arg{argv[i]};
      constexpr std::string_view kThreadsPrefix{"--threads="};
      if (arg.starts_with(kThreadsPrefix)) {
        auto value = arg.substr(kThreadsPrefix.size());
        try {
          opts.threads = static_cast<size_t>(std::stoul(std::string(value)));
        } catch (...) {
          std::cerr << "Invalid thread count: " << value << "\n";
        }
      }
    }
    if (opts.threads == 0) {
      opts.threads = 1;
    }
    return opts;
  }

  void RunConcurrentNonceLog(size_t thread_count) { // TSK034
    tsk034::TempDir dir;
    auto path = dir.path() / "nonce.log";
    std::filesystem::remove(path);
    qv::core::NonceLog log(path);
    const size_t per_thread = 128;
    std::atomic<uint64_t> counter{1};
    std::atomic<uint64_t> next_expected{1};
    auto worker = [&log, &counter, &next_expected, per_thread]() {
      for (size_t i = 0; i < per_thread; ++i) {
        auto counter_value = counter.fetch_add(1, std::memory_order_relaxed);
        while (next_expected.load(std::memory_order_acquire) != counter_value) {
          std::this_thread::yield();
        }
        log.Append(counter_value, std::span<const uint8_t>{}); // TSK128_Missing_AAD_Validation_in_Chunks
        next_expected.fetch_add(1, std::memory_order_release);
      }
    };
    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (size_t i = 0; i < thread_count; ++i) {
      threads.emplace_back(worker);
    }
    for (auto& thread : threads) {
      thread.join();
    }
    const size_t expected_entries = thread_count * per_thread;
    if (log.EntryCount() != expected_entries) {
      std::cerr << "Expected " << expected_entries << " entries but observed "
                << log.EntryCount() << std::endl;
      std::abort();
    }
    if (log.GetLastCounter() != expected_entries) {
      std::cerr << "Unexpected last counter after concurrent appends" << std::endl;
      std::abort();
    }
    if (!log.VerifyChain()) {
      std::cerr << "Nonce chain verification failed after concurrent access" << std::endl;
      std::abort();
    }
    std::cout << "Concurrent test passed with " << thread_count << " threads" << std::endl;
  }

} // namespace

int main(int argc, char** argv) { // TSK034
  auto opts = ParseOptions(argc, argv);
  RunConcurrentNonceLog(opts.threads);
  return 0;
}
