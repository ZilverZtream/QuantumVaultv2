#pragma once
// TSK718_AutoLock_and_MemoryLocking orchestrator session idle-lock coordination

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>

namespace qv::orchestrator {

class IdleLock { // TSK718_AutoLock_and_MemoryLocking idle timeout helper
 public:
  using Clock = std::chrono::steady_clock;
  using Duration = Clock::duration;

  void Arm(Duration timeout);   // TSK718_AutoLock_and_MemoryLocking
  void Disarm() noexcept;       // TSK718_AutoLock_and_MemoryLocking
  void NotifyActivity() noexcept; // TSK718_AutoLock_and_MemoryLocking
  void Tick();                  // TSK718_AutoLock_and_MemoryLocking

  std::function<void()> on_expire; // TSK718_AutoLock_and_MemoryLocking callback

 private:
  std::mutex mutex_;
  Duration timeout_{Duration::zero()};
  Clock::time_point last_activity_{Clock::now()};
  Clock::time_point last_tick_{Clock::now()};
  bool armed_{false};
};

class Session { // TSK718_AutoLock_and_MemoryLocking auto-lock session manager
 public:
  Session();

  void SetLockAction(std::function<void()> action);        // TSK718_AutoLock_and_MemoryLocking
  void ConfigureIdleTimeout(Duration timeout);             // TSK718_AutoLock_and_MemoryLocking
  void DisableIdleTimeout() noexcept;                      // TSK718_AutoLock_and_MemoryLocking
  void NotifyActivity() noexcept;                          // TSK718_AutoLock_and_MemoryLocking
  void Tick();                                             // TSK718_AutoLock_and_MemoryLocking
  bool Locked() const noexcept { return locked_.load(std::memory_order_acquire); }

  static void ActivityThunk(void* context) noexcept;       // TSK718_AutoLock_and_MemoryLocking adapter bridge

 private:
  void TriggerLock();

  mutable std::mutex mutex_;
  std::function<void()> lock_action_;
  IdleLock idle_lock_;
  std::atomic<bool> locked_{false};
};

}  // namespace qv::orchestrator
