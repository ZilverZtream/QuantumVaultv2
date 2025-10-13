#include "qv/security/zeroizer.h"

// TSK006
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>

// TSK031
#include <cstdlib>
#include <iostream>
#include <mutex>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/resource.h>
#endif

namespace qv::security {
  namespace {

    inline void PortableZero(std::span<uint8_t> data) noexcept { // TSK006
      volatile uint8_t* ptr = reinterpret_cast<volatile uint8_t*>(data.data());
      for (std::size_t i = 0; i < data.size(); ++i) {
        ptr[i] = 0;
      }
    }

#if !defined(_WIN32) && (defined(_POSIX_VERSION) || defined(__APPLE__))
    constexpr bool kHasPosixLocking = true; // TSK006
#else
    constexpr bool kHasPosixLocking = false; // TSK006
#endif

#if kHasPosixLocking
    void AdjustMemlockLimitIfNeeded() { // TSK031
      struct rlimit current {};
      if (::getrlimit(RLIMIT_MEMLOCK, &current) != 0) {
        std::clog << "SecureBuffer warning: unable to query RLIMIT_MEMLOCK; "
                  << "mlock() may fail.\n"; // TSK031
        return;
      }

      constexpr rlim_t kDesired = 128U * 1024U * 1024U; // 128 MiB // TSK031
      if (current.rlim_cur >= kDesired) {
        return;
      }

      struct rlimit requested = current;
      if (current.rlim_max == RLIM_INFINITY || current.rlim_max >= kDesired) {
        requested.rlim_cur = kDesired;
      } else {
        requested.rlim_cur = current.rlim_max;
      }
      if (requested.rlim_cur <= current.rlim_cur) {
        return;
      }
      if (requested.rlim_max < requested.rlim_cur) {
        requested.rlim_max = requested.rlim_cur;
      }

      if (::setrlimit(RLIMIT_MEMLOCK, &requested) != 0) {
        std::clog <<
            "SecureBuffer warning: could not raise RLIMIT_MEMLOCK; run with CAP_IPC_LOCK "
            "or `ulimit -l unlimited`.\n"; // TSK031
      }
    }

    void MaybeEnableProcessWideLocking() { // TSK031
      const char* env = std::getenv("QV_USE_MLOCKALL");
      if (!env || env[0] == '\0' || env[0] == '0') {
        return;
      }

      if (::mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        std::clog << "SecureBuffer warning: mlockall() failed despite QV_USE_MLOCKALL; "
                  << "sensitive pages may swap.\n"; // TSK031
      }
    }

    void EnsurePosixLockingConfigured() { // TSK031
      static std::once_flag once;
      std::call_once(once, []() {
        AdjustMemlockLimitIfNeeded();
        MaybeEnableProcessWideLocking();
      });
    }
#endif

  } // namespace

  void Zeroizer::Wipe(std::span<uint8_t> data) noexcept { // TSK006
    if (data.empty()) {
      return;
    }

#if defined(_WIN32)
    ::SecureZeroMemory(data.data(), data.size());
#endif

    PortableZero(data);
    std::atomic_signal_fence(std::memory_order_seq_cst);
  }

  bool Zeroizer::MemoryLockingSupported() noexcept { // TSK006
#if defined(_WIN32)
    return true;
#else
    return kHasPosixLocking;
#endif
  }

  bool Zeroizer::TryLockMemory(std::span<uint8_t> data) noexcept { // TSK006
    if (data.empty()) {
      return true;
    }

#if defined(_WIN32)
    return ::VirtualLock(data.data(), data.size()) != 0;
#elif kHasPosixLocking
    EnsurePosixLockingConfigured(); // TSK031
    return ::mlock(data.data(), data.size()) == 0;
#else
    (void)data;
    return false;
#endif
  }

  void Zeroizer::UnlockMemory(std::span<uint8_t> data) noexcept { // TSK006
    if (data.empty()) {
      return;
    }

#if defined(_WIN32)
    ::VirtualUnlock(data.data(), data.size());
#elif kHasPosixLocking
    ::munlock(data.data(), data.size());
#else
    (void)data;
#endif
  }

} // namespace qv::security
