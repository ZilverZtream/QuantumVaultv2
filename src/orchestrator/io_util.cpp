#include "qv/orchestrator/io_util.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <span>
#include <system_error>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#else
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#endif

namespace qv::orchestrator {
namespace {

constexpr const char* kAtomicReplaceErrorMessage =
    "Atomic file replace failed"; // TSK068_Atomic_Header_Writes uniform error text

#ifdef _WIN32
int NativeOpen(const std::filesystem::path& path) { // TSK068_Atomic_Header_Writes platform abstraction
  return _wopen(path.c_str(), _O_CREAT | _O_WRONLY | _O_TRUNC | _O_BINARY | _O_SEQUENTIAL,
                _S_IREAD | _S_IWRITE);
}

int NativeClose(int fd) { return _close(fd); }

int NativeFsync(int fd) { return _commit(fd); }

int NativeWrite(int fd, const uint8_t* data, size_t size) {
  return _write(fd, data, static_cast<unsigned int>(size));
}

bool NativeRename(const std::filesystem::path& from,
                  const std::filesystem::path& to) { // TSK068_Atomic_Header_Writes atomic swap
  return ::MoveFileExW(from.c_str(), to.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

void SyncDirectory(const std::filesystem::path& dir) { // TSK068_Atomic_Header_Writes ensure metadata durability
  HANDLE handle = ::CreateFileW(
      dir.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    throw Error{ErrorDomain::IO, static_cast<int>(::GetLastError()),
                kAtomicReplaceErrorMessage};
  }
  if (!::FlushFileBuffers(handle)) {
    auto err = static_cast<int>(::GetLastError());
    ::CloseHandle(handle);
    throw Error{ErrorDomain::IO, err, kAtomicReplaceErrorMessage};
  }
  ::CloseHandle(handle);
}

#else

int NativeOpen(const std::filesystem::path& path) { // TSK068_Atomic_Header_Writes platform abstraction
  return ::open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
}

int NativeClose(int fd) { return ::close(fd); }

int NativeFsync(int fd) { return ::fsync(fd); }

ssize_t NativeWrite(int fd, const uint8_t* data, size_t size) {
  return ::write(fd, data, size);
}

bool NativeRename(const std::filesystem::path& from,
                  const std::filesystem::path& to) { // TSK068_Atomic_Header_Writes atomic swap
  return ::rename(from.c_str(), to.c_str()) == 0;
}

void SyncDirectory(const std::filesystem::path& dir) { // TSK068_Atomic_Header_Writes ensure metadata durability
  int dir_fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
  if (dir_fd < 0) {
    throw Error{ErrorDomain::IO, errno, kAtomicReplaceErrorMessage};
  }
  if (::fsync(dir_fd) != 0) {
    int err = errno;
    ::close(dir_fd);
    throw Error{ErrorDomain::IO, err, kAtomicReplaceErrorMessage};
  }
  ::close(dir_fd);
}

#endif

void WriteAll(int fd, std::span<const uint8_t> payload) { // TSK068_Atomic_Header_Writes
  size_t written = 0;
  while (written < payload.size()) {
    auto chunk = NativeWrite(fd, payload.data() + written, payload.size() - written);
    if (chunk < 0) {
      throw Error{ErrorDomain::IO, errno, kAtomicReplaceErrorMessage};
    }
    written += static_cast<size_t>(chunk);
  }
}

class TempFileGuard { // TSK068_Atomic_Header_Writes ensure cleanup on failure
 public:
  explicit TempFileGuard(std::filesystem::path path) noexcept : path_(std::move(path)) {}
  TempFileGuard(const TempFileGuard&) = delete;
  TempFileGuard& operator=(const TempFileGuard&) = delete;
  ~TempFileGuard() noexcept {
    if (!path_.empty()) {
      std::error_code ec;
      std::filesystem::remove(path_, ec);
    }
  }

  void Release() noexcept { path_.clear(); }

 private:
  std::filesystem::path path_;
};

std::filesystem::path MakeTempPath(const std::filesystem::path& dir,
                                   const std::filesystem::path& base) { // TSK068_Atomic_Header_Writes unique temp
  auto token = std::filesystem::unique_path("%%%%%%%%");
  auto stem = base.filename().string();
  auto unique = token.string();
  auto temp_name = stem + ".tmp." + unique;
  return dir / temp_name;
}

}  // namespace

void AtomicReplace(const std::filesystem::path& target, std::span<const uint8_t> payload,
                   const AtomicReplaceHooks& hooks) {
  if (target.empty()) {
    throw Error{ErrorDomain::Validation, 0, "Target path required"};
  }
  auto dir = target.parent_path();
  if (dir.empty()) {
    dir = std::filesystem::current_path();
  }

  auto temp_path = MakeTempPath(dir, target);
  TempFileGuard cleanup(temp_path);

  int fd = NativeOpen(temp_path);
  if (fd < 0) {
    throw Error{ErrorDomain::IO, errno, kAtomicReplaceErrorMessage};
  }

  try {
    WriteAll(fd, payload);
    if (NativeFsync(fd) != 0) {
      throw Error{ErrorDomain::IO, errno, kAtomicReplaceErrorMessage};
    }
  } catch (...) {
    NativeClose(fd);
    throw;
  }

  if (NativeClose(fd) != 0) {
    throw Error{ErrorDomain::IO, errno, kAtomicReplaceErrorMessage};
  }

  if (hooks.before_rename) {
    hooks.before_rename(temp_path, target);
  }

  if (!NativeRename(temp_path, target)) {
    int err = errno;
#ifdef _WIN32
    if (err == 0) {
      err = static_cast<int>(::GetLastError());
    }
#endif
    throw Error{ErrorDomain::IO, err, kAtomicReplaceErrorMessage};
  }
  cleanup.Release();

  auto sync_dir = dir;
  if (sync_dir.empty()) {
    sync_dir = std::filesystem::current_path();
  }
  SyncDirectory(sync_dir);
}

}  // namespace qv::orchestrator
