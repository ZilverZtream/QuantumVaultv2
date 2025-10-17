#include "qv/orchestrator/session.h"
// TSK718_AutoLock_and_MemoryLocking idle auto-lock implementation

namespace qv::orchestrator {

namespace {
constexpr IdleLock::Duration kSleepTolerance = std::chrono::seconds(2); // TSK718_AutoLock_and_MemoryLocking resume guard
}  // namespace

void IdleLock::Arm(Duration timeout) { // TSK718_AutoLock_and_MemoryLocking
  std::lock_guard<std::mutex> guard(mutex_);
  if (timeout <= Duration::zero()) {
    armed_ = false;
    timeout_ = Duration::zero();
    return;
  }
  timeout_ = timeout;
  last_activity_ = Clock::now();
  last_tick_ = last_activity_;
  armed_ = true;
}

void IdleLock::Disarm() noexcept { // TSK718_AutoLock_and_MemoryLocking
  std::lock_guard<std::mutex> guard(mutex_);
  armed_ = false;
  timeout_ = Duration::zero();
}

void IdleLock::NotifyActivity() noexcept { // TSK718_AutoLock_and_MemoryLocking
  std::lock_guard<std::mutex> guard(mutex_);
  if (!armed_) {
    return;
  }
  last_activity_ = Clock::now();
}

void IdleLock::Tick() { // TSK718_AutoLock_and_MemoryLocking
  std::function<void()> expire;
  {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!armed_) {
      last_tick_ = Clock::now();
      return;
    }
    const auto now = Clock::now();
    const auto since_activity = now - last_activity_;
    const auto since_tick = now - last_tick_;
    last_tick_ = now;
    if (since_activity >= timeout_) {
      armed_ = false;
      expire = on_expire;
    } else if (since_tick > timeout_ + kSleepTolerance) {
      armed_ = false;
      expire = on_expire;
    }
  }
  if (expire) {
    expire();
  }
}

Session::Session() { idle_lock_.on_expire = [this]() { TriggerLock(); }; }

void Session::SetLockAction(std::function<void()> action) { // TSK718_AutoLock_and_MemoryLocking
  std::lock_guard<std::mutex> guard(mutex_);
  lock_action_ = std::move(action);
  locked_.store(false, std::memory_order_release);
}

void Session::ConfigureIdleTimeout(IdleLock::Duration timeout) { // TSK718_AutoLock_and_MemoryLocking
  locked_.store(false, std::memory_order_release);
  idle_lock_.Arm(timeout);
}

void Session::DisableIdleTimeout() noexcept { // TSK718_AutoLock_and_MemoryLocking
  idle_lock_.Disarm();
}

void Session::NotifyActivity() noexcept { // TSK718_AutoLock_and_MemoryLocking
  if (Locked()) {
    return;
  }
  idle_lock_.NotifyActivity();
}

void Session::Tick() { // TSK718_AutoLock_and_MemoryLocking
  if (Locked()) {
    return;
  }
  idle_lock_.Tick();
}

void Session::TriggerLock() { // TSK718_AutoLock_and_MemoryLocking
  if (locked_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  std::function<void()> action;
  {
    std::lock_guard<std::mutex> guard(mutex_);
    action = lock_action_;
  }
  if (action) {
    action();
  }
}

void Session::ActivityThunk(void* context) noexcept { // TSK718_AutoLock_and_MemoryLocking
  auto* session = static_cast<Session*>(context);
  if (!session) {
    return;
  }
  session->NotifyActivity();
}

}  // namespace qv::orchestrator
