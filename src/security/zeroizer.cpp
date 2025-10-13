#include "qv/security/zeroizer.h"

// TSK006
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>

#if defined(_WIN32)
#  define NOMINMAX
#  include <windows.h>
#else
#  include <sys/mman.h>
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
constexpr bool kHasPosixLocking = true;
#else
constexpr bool kHasPosixLocking = false;
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
