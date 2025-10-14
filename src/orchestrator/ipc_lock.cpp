#include "qv/orchestrator/ipc_lock.h"

#include <cstdint>
#include <string_view>

#if defined(_WIN32)
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "qv/common.h"

namespace qv::orchestrator {
namespace {

// TSK075_Lockout_Persistence_and_IPC derive stable IPC name from volume path
uint64_t Fnv1a64(std::string_view input) noexcept {
  uint64_t hash = 1469598103934665603ull;
  for (unsigned char c : input) {
    hash ^= static_cast<uint64_t>(c);
    hash *= 1099511628211ull;
  }
  return hash;
}

std::string MakeBaseName(const std::filesystem::path& path) {
  const std::string canonical = qv::PathToUtf8String(path);
  const uint64_t hash = Fnv1a64(canonical);
  static constexpr char kHex[] = "0123456789abcdef";
  std::string encoded(16, '0');
  uint64_t value = hash;
  for (int idx = 15; idx >= 0; --idx) {
    encoded[idx] = kHex[value & 0x0F];
    value >>= 4;
  }
  return "qvlock" + encoded; // TSK075_Lockout_Persistence_and_IPC
}

#if defined(_WIN32)
std::wstring ToWide(const std::string& value) {
  std::wstring result;
  result.reserve(value.size());
  for (unsigned char c : value) {
    result.push_back(static_cast<wchar_t>(c));
  }
  return result;
}
#endif

}  // namespace

ScopedIpcLock::ScopedIpcLock(bool locked
#if defined(_WIN32)
                             , void* handle
#else
                             , void* semaphore
#endif
                             ) noexcept
    : locked_(locked) {
#if defined(_WIN32)
  handle_ = handle;
#else
  semaphore_ = semaphore;
#endif
}

ScopedIpcLock::ScopedIpcLock(ScopedIpcLock&& other) noexcept { *this = std::move(other); }

ScopedIpcLock& ScopedIpcLock::operator=(ScopedIpcLock&& other) noexcept {
  if (this == &other) {
    return *this;
  }
  Release();
  locked_ = other.locked_;
#if defined(_WIN32)
  handle_ = other.handle_;
  other.handle_ = nullptr;
#else
  semaphore_ = other.semaphore_;
  other.semaphore_ = nullptr;
#endif
  other.locked_ = false;
  return *this;
}

ScopedIpcLock::~ScopedIpcLock() { Release(); }

ScopedIpcLock ScopedIpcLock::Acquire(const std::string& name) {
#if defined(_WIN32)
  const std::wstring mutex_name = ToWide("Global\\" + name);
  HANDLE handle = CreateMutexW(nullptr, FALSE, mutex_name.c_str());
  if (!handle) {
    return {};
  }
  const DWORD wait_result = WaitForSingleObject(handle, INFINITE);
  if (wait_result != WAIT_OBJECT_0 && wait_result != WAIT_ABANDONED) {
    CloseHandle(handle);
    return {};
  }
  return ScopedIpcLock(true, handle);
#else
  std::string sem_name = "/" + name;
  if (sem_name.size() > 30) {  // macOS named semaphore limit
    sem_name.resize(30);
  }
  sem_t* semaphore = sem_open(sem_name.c_str(), O_CREAT, 0600, 1);
  if (semaphore == SEM_FAILED) {
    return {};
  }
  while (sem_wait(semaphore) == -1 && errno == EINTR) {
  }
  return ScopedIpcLock(true, semaphore);
#endif
}

ScopedIpcLock ScopedIpcLock::ForPath(const std::filesystem::path& path) {
  return Acquire(MakeBaseName(path));
}

void ScopedIpcLock::Release() noexcept {
  if (!locked_) {
    return;
  }
#if defined(_WIN32)
  if (handle_) {
    ReleaseMutex(static_cast<HANDLE>(handle_));
    CloseHandle(static_cast<HANDLE>(handle_));
    handle_ = nullptr;
  }
#else
  if (semaphore_) {
    sem_post(static_cast<sem_t*>(semaphore_));
    sem_close(static_cast<sem_t*>(semaphore_));
    semaphore_ = nullptr;
  }
#endif
  locked_ = false;
}

}  // namespace qv::orchestrator
