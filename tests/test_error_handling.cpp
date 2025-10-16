#include "qv/core/nonce.h" // TSK034
#include "qv/error.h"      // TSK034
#include "qv/security/secure_buffer.h" // TSK034
#include "qv/security/zeroizer.h"      // TSK034

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdarg>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#include <cerrno>
#include <cstring>
#include <dlfcn.h>   // TSK034
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace tsk034 { // TSK034

  class TempDir { // TSK034
  public:
    TempDir() {
      auto base = std::filesystem::temp_directory_path();
      auto name = std::string{"qv_error_handling_"} +
                  std::to_string(static_cast<unsigned long long>(std::chrono::steady_clock::now()
                                                                     .time_since_epoch()
                                                                     .count()));
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

#if !defined(_WIN32)
  std::atomic<int> g_fail_aligned_alloc_budget{-1}; // TSK034

  struct FailAlignedAllocGuard { // TSK034
    explicit FailAlignedAllocGuard(int budget) { g_fail_aligned_alloc_budget.store(budget); }
    ~FailAlignedAllocGuard() { g_fail_aligned_alloc_budget.store(-1); }
  };

  std::mutex& FailMutex() { // TSK034
    static std::mutex mu;
    return mu;
  }

  std::string& FailPath() { // TSK034
    static std::string path;
    return path;
  }

  std::atomic<int>& FailWriteBudget() { // TSK034
    static std::atomic<int> budget{-1};
    return budget;
  }

  std::atomic<int>& TargetFd() { // TSK034
    static std::atomic<int> fd{-1};
    return fd;
  }

  std::atomic<int>& FailOpenError() { // TSK034
    static std::atomic<int> err{0};
    return err;
  }

  struct DiskFullGuard { // TSK034
    DiskFullGuard(const std::filesystem::path& temp_path, int writes_before_failure)
        : active_(true) {
      std::lock_guard<std::mutex> lock(FailMutex());
      FailPath() = temp_path.string();
      FailWriteBudget().store(writes_before_failure);
      TargetFd().store(-1);
      FailOpenError().store(0);
    }

    DiskFullGuard(const DiskFullGuard&) = delete;
    DiskFullGuard& operator=(const DiskFullGuard&) = delete;

    ~DiskFullGuard() {
      if (!active_) {
        return;
      }
      std::lock_guard<std::mutex> lock(FailMutex());
      FailPath().clear();
      FailWriteBudget().store(-1);
      TargetFd().store(-1);
      FailOpenError().store(0);
    }

    void Release() {
      if (!active_) {
        return;
      }
      std::lock_guard<std::mutex> lock(FailMutex());
      FailPath().clear();
      FailWriteBudget().store(-1);
      TargetFd().store(-1);
      FailOpenError().store(0);
      active_ = false;
    }

  private:
    bool active_{false};
  };

  struct OpenFailureGuard { // TSK034
    OpenFailureGuard(const std::filesystem::path& path, int error) : active_(true) {
      std::lock_guard<std::mutex> lock(FailMutex());
      FailPath() = path.string();
      FailOpenError().store(error);
      TargetFd().store(-1);
      FailWriteBudget().store(-1);
    }

    OpenFailureGuard(const OpenFailureGuard&) = delete;
    OpenFailureGuard& operator=(const OpenFailureGuard&) = delete;

    ~OpenFailureGuard() { Release(); }

    void Release() {
      if (!active_) {
        return;
      }
      std::lock_guard<std::mutex> lock(FailMutex());
      FailPath().clear();
      FailOpenError().store(0);
      TargetFd().store(-1);
      FailWriteBudget().store(-1);
      active_ = false;
    }

  private:
    bool active_{false};
  };

  extern "C" void* aligned_alloc(size_t alignment, size_t size) noexcept { // TSK034
    using Fn = void* (*)(size_t, size_t);
    static Fn real_aligned_alloc = nullptr;
    if (!real_aligned_alloc) {
      real_aligned_alloc = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "aligned_alloc"));
    }
    auto budget = g_fail_aligned_alloc_budget.load();
    if (budget >= 0) {
      if (g_fail_aligned_alloc_budget.fetch_sub(1) == 0) {
        errno = ENOMEM;
        return nullptr;
      }
    }
    if (!real_aligned_alloc) {
      void* ptr = nullptr;
      if (posix_memalign(&ptr, alignment, size) != 0) {
        errno = ENOMEM;
        return nullptr;
      }
      return ptr;
    }
    return real_aligned_alloc(alignment, size);
  }

  extern "C" int open(const char* pathname, int flags, ...) noexcept { // TSK034
    using Fn = int (*)(const char*, int, ...);
    static Fn real_open = nullptr;
    if (!real_open) {
      real_open = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "open"));
    }
    if (!real_open) {
      errno = EMFILE;
      return -1;
    }
    va_list args;
    va_start(args, flags);
    mode_t mode = static_cast<mode_t>(0);
    if ((flags & O_CREAT) != 0) {
      mode = static_cast<mode_t>(va_arg(args, int));
    }
    va_end(args);

    {
      std::lock_guard<std::mutex> lock(FailMutex());
      if (!FailPath().empty() && pathname && FailPath() == pathname) {
        int err = FailOpenError().load();
        if (err != 0) {
          FailOpenError().store(0);
          errno = err;
          return -1;
        }
      }
    }

    int fd = real_open(pathname, flags, mode);
    if (fd >= 0) {
      std::lock_guard<std::mutex> lock(FailMutex());
      if (!FailPath().empty() && pathname && FailPath() == pathname) {
        TargetFd().store(fd);
      }
    }
    return fd;
  }

  extern "C" ssize_t write(int fd, const void* buf, size_t count) noexcept { // TSK034
    using Fn = ssize_t (*)(int, const void*, size_t);
    static Fn real_write = nullptr;
    if (!real_write) {
      real_write = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "write"));
    }
    auto target = TargetFd().load();
    if (fd >= 0 && target >= 0 && fd == target) {
      auto& budget = FailWriteBudget();
      auto remaining = budget.load();
      if (remaining >= 0) {
        if (budget.fetch_sub(1) <= 0) {
          errno = ENOSPC;
          return -1;
        }
      }
    }
    if (!real_write) {
      errno = EBADF;
      return -1;
    }
    return real_write(fd, buf, count);
  }
#endif // !_WIN32

  struct BufferRegistry { // TSK034
    std::mutex mutex;
    std::vector<qv::security::SecureBuffer<uint8_t>*> buffers;

    static BufferRegistry& Instance() {
      static BufferRegistry registry;
      return registry;
    }

    void Register(qv::security::SecureBuffer<uint8_t>* buffer) {
      std::lock_guard<std::mutex> lock(mutex);
      buffers.push_back(buffer);
    }

    void Unregister(qv::security::SecureBuffer<uint8_t>* buffer) {
      std::lock_guard<std::mutex> lock(mutex);
      buffers.erase(std::remove(buffers.begin(), buffers.end(), buffer), buffers.end());
    }
  };

  void SimulatedSignalHandler(int signum) { // TSK034
    (void)signum;
    auto& registry = BufferRegistry::Instance();
    std::lock_guard<std::mutex> lock(registry.mutex);
    for (auto* buffer : registry.buffers) {
      if (!buffer) {
        continue;
      }
      auto span = buffer->AsU8Span();
      qv::security::Zeroizer::Wipe(span);
    }
  }

  class BufferRegistration { // TSK034
  public:
    explicit BufferRegistration(qv::security::SecureBuffer<uint8_t>& buffer) : buffer_(buffer) {
      BufferRegistry::Instance().Register(&buffer_);
    }
    ~BufferRegistration() { BufferRegistry::Instance().Unregister(&buffer_); }

  private:
    qv::security::SecureBuffer<uint8_t>& buffer_;
  };

} // namespace tsk034

namespace { // TSK034

  void TestSecureBufferAllocationFailure() { // TSK034
#if defined(_WIN32)
    qv::security::SecureBuffer<uint8_t> buffer(1);
    (void)buffer;
#else
    tsk034::FailAlignedAllocGuard guard(0);
    bool caught = false;
    try {
      qv::security::SecureBuffer<uint8_t> buffer(32);
      (void)buffer;
    } catch (const std::bad_alloc&) {
      caught = true;
    }
    if (!caught) {
      std::cerr << "SecureBuffer must propagate allocation failure" << std::endl;
      std::abort();
    }
#endif
  }

  void TestNonceLogDiskFullSimulation() { // TSK034
#if defined(_WIN32)
    std::cout << "Skipping disk full simulation on Windows\n";
#else
    tsk034::TempDir dir;
    auto log_path = dir.path() / "nonce.log";
    std::filesystem::remove(log_path);
    {
      qv::core::NonceLog log(log_path);
      (void)log.Append(1, std::span<const uint8_t>{}); // TSK128_Missing_AAD_Validation_in_Chunks
    }
    auto temp_path = log_path;
    temp_path += ".tmp";
    tsk034::DiskFullGuard guard(temp_path, 0);
    bool threw = false;
    try {
      qv::core::NonceLog log(log_path);
      (void)log.Append(2, std::span<const uint8_t>{}); // TSK128_Missing_AAD_Validation_in_Chunks
    } catch (const qv::Error& err) {
      threw = (err.domain == qv::ErrorDomain::IO) && (err.code == ENOSPC);
    }
    if (!threw) {
      std::cerr << "Expected ENOSPC error during snapshot write" << std::endl;
      std::abort();
    }
    guard.Release();
    qv::core::NonceLog verify(log_path);
    auto retained = verify.EntryCount();
    if (retained < 1) {
      std::cerr << "Nonce log should retain entries after ENOSPC (actual " << retained << ")"
                << std::endl;
      std::abort();
    }
    if (!verify.VerifyChain()) {
      std::cerr << "Nonce log chain verification failed after ENOSPC" << std::endl;
      std::abort();
    }
#endif
  }

  void TestPermissionDeniedHandling() { // TSK034
#if defined(_WIN32)
    std::cout << "Skipping permission denied simulation on Windows\n";
#else
    tsk034::TempDir dir;
    auto log_path = dir.path() / "restricted_nonce.log";
    auto wal_path = log_path;
    wal_path += ".wal";
    tsk034::OpenFailureGuard guard(wal_path, EACCES);
    bool threw = false;
    try {
      qv::core::NonceLog log(log_path);
      (void)log;
    } catch (const qv::Error& err) {
      threw = (err.domain == qv::ErrorDomain::IO) && (err.code == EACCES);
    } catch (const std::filesystem::filesystem_error&) {
      threw = true;
    }
    guard.Release();
    if (!threw) {
      std::cerr << "Nonce log initialization should fail for restricted directory" << std::endl;
      std::abort();
    }
#endif
  }

  void TestConcurrentNonceAppends() { // TSK034
    tsk034::TempDir dir;
    auto log_path = dir.path() / "concurrent_nonce.log";
    std::filesystem::remove(log_path);
    qv::core::NonceLog log(log_path);
    constexpr size_t kThreads = 4;
    constexpr size_t kAppendsPerThread = 32;
    std::atomic<uint64_t> counter{1};
    std::atomic<uint64_t> next_expected{1};
    auto worker = [&log, &counter, &next_expected]() {
      for (size_t i = 0; i < kAppendsPerThread; ++i) {
        auto value = counter.fetch_add(1, std::memory_order_relaxed);
        while (next_expected.load(std::memory_order_acquire) != value) {
          std::this_thread::yield();
        }
        log.Append(value, std::span<const uint8_t>{}); // TSK128_Missing_AAD_Validation_in_Chunks
        next_expected.fetch_add(1, std::memory_order_release);
      }
    };
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (size_t i = 0; i < kThreads; ++i) {
      threads.emplace_back(worker);
    }
    for (auto& t : threads) {
      t.join();
    }
    const size_t expected = kThreads * kAppendsPerThread;
    if (log.EntryCount() != expected) {
      std::cerr << "Expected " << expected << " entries, found " << log.EntryCount() << std::endl;
      std::abort();
    }
    if (log.GetLastCounter() != expected) {
      std::cerr << "Last counter mismatch after concurrent appends" << std::endl;
      std::abort();
    }
    if (!log.VerifyChain()) {
      std::cerr << "Nonce chain verification failed after concurrent appends" << std::endl;
      std::abort();
    }
  }

  void TestSignalHandlerZeroizesBuffers() { // TSK034
    qv::security::SecureBuffer<uint8_t> first(16);
    qv::security::SecureBuffer<uint8_t> second(16);
    {
      auto span1 = first.AsSpan();
      auto span2 = second.AsSpan();
      for (auto& byte : span1) {
        byte = 0xAA;
      }
      for (auto& byte : span2) {
        byte = 0x55;
      }
    }
    tsk034::BufferRegistration reg1(first);
    tsk034::BufferRegistration reg2(second);
    tsk034::SimulatedSignalHandler(SIGTERM);
    auto span1 = first.AsSpan();
    auto span2 = second.AsSpan();
    for (auto byte : span1) {
      if (byte != 0) {
        std::cerr << "Signal handler must wipe first buffer" << std::endl;
        std::abort();
      }
    }
    for (auto byte : span2) {
      if (byte != 0) {
        std::cerr << "Signal handler must wipe second buffer" << std::endl;
        std::abort();
      }
    }
  }

} // namespace

int main() { // TSK034
  TestSecureBufferAllocationFailure();
  TestNonceLogDiskFullSimulation();
  TestPermissionDeniedHandling();
  TestConcurrentNonceAppends();
  TestSignalHandlerZeroizesBuffers();
  std::cout << "test_error_handling completed" << std::endl;
  return 0;
}
