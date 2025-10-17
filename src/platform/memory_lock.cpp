#include "qv/platform/memory_lock.h"
// TSK718_AutoLock_and_MemoryLocking platform-specific implementations for VirtualLock/mlock

#include <cerrno>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#else
#if defined(_POSIX_VERSION) || defined(__APPLE__)
#include <sys/mman.h>
#endif
#endif

namespace qv::platform {

MemoryLockStatus LockMemory(void* ptr, std::size_t length) noexcept { // TSK718_AutoLock_and_MemoryLocking
  if (!ptr || length == 0) {
    return MemoryLockStatus::kBestEffort;
  }
#if defined(_WIN32)
  if (::VirtualLock(ptr, length) != 0) {
    return MemoryLockStatus::kLocked;
  }
  const DWORD err = ::GetLastError();
  if (err == ERROR_NOT_SUPPORTED) {
    return MemoryLockStatus::kUnsupported;
  }
  return MemoryLockStatus::kBestEffort;
#elif defined(_POSIX_VERSION) || defined(__APPLE__)
  if (::mlock(ptr, length) == 0) {
    return MemoryLockStatus::kLocked;
  }
  if (errno == ENOSYS) {
    return MemoryLockStatus::kUnsupported;
  }
  return MemoryLockStatus::kBestEffort;
#else
  (void)ptr;
  (void)length;
  return MemoryLockStatus::kUnsupported;
#endif
}

void UnlockMemory(void* ptr, std::size_t length) noexcept { // TSK718_AutoLock_and_MemoryLocking
  if (!ptr || length == 0) {
    return;
  }
#if defined(_WIN32)
  ::VirtualUnlock(ptr, length);
#elif defined(_POSIX_VERSION) || defined(__APPLE__)
  ::munlock(ptr, length);
#else
  (void)ptr;
  (void)length;
#endif
}

bool MemoryLockSupported() noexcept { // TSK718_AutoLock_and_MemoryLocking
#if defined(_WIN32)
  return true;
#elif defined(_POSIX_VERSION) || defined(__APPLE__)
  return true;
#else
  return false;
#endif
}

}  // namespace qv::platform
