#pragma once
// TSK718_AutoLock_and_MemoryLocking platform abstraction for sensitive memory locking

#include <cstddef>
#include <cstdint>

namespace qv::platform {

enum class MemoryLockStatus {
  kLocked,
  kBestEffort,
  kUnsupported,
};

MemoryLockStatus LockMemory(void* ptr, std::size_t length) noexcept; // TSK718_AutoLock_and_MemoryLocking
void UnlockMemory(void* ptr, std::size_t length) noexcept;           // TSK718_AutoLock_and_MemoryLocking
bool MemoryLockSupported() noexcept;                                // TSK718_AutoLock_and_MemoryLocking

class MemoryLockGuard { // TSK718_AutoLock_and_MemoryLocking RAII helper
 public:
  MemoryLockGuard() noexcept = default;
  MemoryLockGuard(void* ptr, std::size_t length) noexcept { Reset(ptr, length); }

  MemoryLockGuard(const MemoryLockGuard&) = delete;
  MemoryLockGuard& operator=(const MemoryLockGuard&) = delete;

  MemoryLockGuard(MemoryLockGuard&& other) noexcept { MoveFrom(other); }
  MemoryLockGuard& operator=(MemoryLockGuard&& other) noexcept {
    if (this != &other) {
      Release();
      MoveFrom(other);
    }
    return *this;
  }

  ~MemoryLockGuard() { Release(); }

  void Reset(void* ptr, std::size_t length) noexcept {
    Release();
    ptr_ = ptr;
    length_ = length;
    if (!ptr_ || length_ == 0) {
      status_ = MemoryLockStatus::kBestEffort;
      return;
    }
    status_ = LockMemory(ptr_, length_);
    should_unlock_ = (status_ == MemoryLockStatus::kLocked);
  }

  void Release() noexcept {
    if (should_unlock_ && ptr_ && length_ > 0) {
      UnlockMemory(ptr_, length_);
    }
    ptr_ = nullptr;
    length_ = 0;
    should_unlock_ = false;
    status_ = MemoryLockStatus::kBestEffort;
  }

  MemoryLockStatus status() const noexcept { return status_; }
  bool locked() const noexcept { return status_ == MemoryLockStatus::kLocked; }

 private:
  void MoveFrom(MemoryLockGuard& other) noexcept {
    ptr_ = other.ptr_;
    length_ = other.length_;
    status_ = other.status_;
    should_unlock_ = other.should_unlock_;
    other.ptr_ = nullptr;
    other.length_ = 0;
    other.status_ = MemoryLockStatus::kBestEffort;
    other.should_unlock_ = false;
  }

  void* ptr_{nullptr};
  std::size_t length_{0};
  MemoryLockStatus status_{MemoryLockStatus::kBestEffort};
  bool should_unlock_{false};
};

}  // namespace qv::platform
