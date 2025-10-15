#include "qv/security/zeroizer.h"

#include "qv/orchestrator/event_bus.h" // TSK085

// TSK006
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector> // TSK085
#include <span>

// TSK031
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <string> // TSK085

#include <cerrno> // TSK085

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

    struct LockedRegion { // TSK085
      uint8_t* ptr{nullptr};
      std::size_t size{0};
      std::size_t refcount{0};
    };

    std::mutex g_lock_registry_mutex;          // TSK085
    std::vector<LockedRegion> g_lock_registry; // TSK085

    void RegisterLock(uint8_t* ptr, std::size_t size) noexcept { // TSK085
      if (!ptr || size == 0) {
        return;
      }
      std::lock_guard<std::mutex> guard(g_lock_registry_mutex);
      for (auto& region : g_lock_registry) {
        if (region.ptr == ptr && region.size == size) {
          region.refcount += 1;
          return;
        }
      }
      g_lock_registry.push_back(LockedRegion{ptr, size, 1});
    }

    bool UnregisterLock(uint8_t* ptr, std::size_t size) noexcept { // TSK085
      if (!ptr || size == 0) {
        return false;
      }
      std::lock_guard<std::mutex> guard(g_lock_registry_mutex);
      for (auto it = g_lock_registry.begin(); it != g_lock_registry.end(); ++it) {
        if (it->ptr == ptr && it->size == size) {
          if (it->refcount > 1) {
            it->refcount -= 1;
          } else {
            g_lock_registry.erase(it);
          }
          return true;
        }
      }
      return false;
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

    void MaybeEnableProcessWideLocking() { // TSK031, TSK107_Platform_Specific_Issues
      const char* env = std::getenv("QV_USE_MLOCKALL");
      if (!env || env[0] == '\0' || env[0] == '0') {
        return;
      }

#if (defined(__linux__) || defined(__FreeBSD__)) && defined(MCL_CURRENT) && defined(MCL_FUTURE)
      if (::mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        const int err = errno;                                                    // TSK085
        std::clog << "SecureBuffer warning: mlockall() failed despite QV_USE_MLOCKALL; "
                  << "sensitive pages may swap.\n"; // TSK031
        qv::orchestrator::Event event;                                            // TSK085
        event.category = qv::orchestrator::EventCategory::kSecurity;              // TSK085
        event.severity = qv::orchestrator::EventSeverity::kWarning;               // TSK085
        event.event_id = "memory_lock_failure";                                  // TSK085
        event.message = "Process-wide memory locking failed";                    // TSK085
        event.fields.emplace_back("errno", std::to_string(err),                  // TSK085
                                  qv::orchestrator::FieldPrivacy::kPublic, true); // TSK085
        qv::orchestrator::EventBus::Instance().Publish(event);                    // TSK085
      }
#else
      std::clog << "SecureBuffer notice: mlockall() not available on this platform; "
                << "QV_USE_MLOCKALL ignored.\n"; // TSK031, TSK107_Platform_Specific_Issues
#endif
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

  Zeroizer::LockStatus Zeroizer::TryLockMemory(std::span<uint8_t> data) noexcept { // TSK006, TSK085
    if (data.empty()) {
      return LockStatus::Locked;
    }

#if defined(_WIN32)
    if (::VirtualLock(data.data(), data.size()) != 0) {
      RegisterLock(data.data(), data.size());
      return LockStatus::Locked;
    }
    return LockStatus::BestEffort;
#elif kHasPosixLocking
    EnsurePosixLockingConfigured(); // TSK031
    if (::mlock(data.data(), data.size()) == 0) {
      RegisterLock(data.data(), data.size());
      return LockStatus::Locked;
    }
    return LockStatus::BestEffort;
#else
    (void)data;
    return LockStatus::Unsupported;
#endif
  }

  void Zeroizer::UnlockMemory(std::span<uint8_t> data) noexcept { // TSK006, TSK085
    if (data.empty()) {
      return;
    }

#if defined(_WIN32)
    if (!UnregisterLock(data.data(), data.size())) {
      return;
    }
    ::VirtualUnlock(data.data(), data.size());
#elif kHasPosixLocking
    if (!UnregisterLock(data.data(), data.size())) {
      return;
    }
    ::munlock(data.data(), data.size());
#else
    (void)data;
#endif
  }

} // namespace qv::security
