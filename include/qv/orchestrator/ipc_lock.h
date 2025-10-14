#pragma once

#include <filesystem>
#include <string>

namespace qv::orchestrator {

// TSK075_Lockout_Persistence_and_IPC cross-process synchronization gate
class ScopedIpcLock {
public:
  ScopedIpcLock() = default;
  ScopedIpcLock(const ScopedIpcLock&) = delete;
  ScopedIpcLock& operator=(const ScopedIpcLock&) = delete;
  ScopedIpcLock(ScopedIpcLock&& other) noexcept;
  ScopedIpcLock& operator=(ScopedIpcLock&& other) noexcept;
  ~ScopedIpcLock();

  [[nodiscard]] static ScopedIpcLock Acquire(const std::string& name);
  [[nodiscard]] static ScopedIpcLock ForPath(const std::filesystem::path& path);

  [[nodiscard]] bool locked() const noexcept { return locked_; }
  explicit operator bool() const noexcept { return locked_; }

private:
  ScopedIpcLock(bool locked
#if defined(_WIN32)
                , void* handle
#else
                , void* semaphore
#endif
                ) noexcept;

  void Release() noexcept;

#if defined(_WIN32)
  void* handle_{nullptr};
#else
  void* semaphore_{nullptr};
#endif
  bool locked_{false};
};

}  // namespace qv::orchestrator
