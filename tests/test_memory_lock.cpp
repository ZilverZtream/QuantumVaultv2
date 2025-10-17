#include "qv/platform/memory_lock.h"  // TSK718_AutoLock_and_MemoryLocking

#include <array>
#include <cstdint>

int main() {
  std::array<std::uint8_t, 64> buffer{};
  auto status = qv::platform::LockMemory(buffer.data(), buffer.size());
  if (status == qv::platform::MemoryLockStatus::kUnsupported) {
    return 0;  // Accept unsupported platforms without failure
  }
  if (status != qv::platform::MemoryLockStatus::kLocked &&
      status != qv::platform::MemoryLockStatus::kBestEffort) {
    return 1;
  }
  qv::platform::UnlockMemory(buffer.data(), buffer.size());
  return 0;
}
