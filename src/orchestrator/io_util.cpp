#include "qv/orchestrator/io_util.h"

#include "qv/common.h"  // TSK109_Error_Code_Handling UTF-8 path diagnostics
#include "qv/crypto/random.h"  // TSK140_Temporary_File_Security_Vulnerabilities entropy for temp tokens

#include <array>   // TSK140_Temporary_File_Security_Vulnerabilities token generation
#include <cerrno>
#include <chrono>   // TSK101_File_IO_Persistence_and_Atomicity retry backoff
#include <csignal>  // TSK140_Temporary_File_Security_Vulnerabilities signal cleanup hooks
#include <cstdint>
#include <cstdio>
#include <cstdlib>   // TSK140_Temporary_File_Security_Vulnerabilities atexit hooks
#include <filesystem>
#include <iostream> // TSK101_File_IO_Persistence_and_Atomicity surface cleanup failures
#include <mutex>    // TSK140_Temporary_File_Security_Vulnerabilities tracked temp registry
#include <span>
#include <sstream>      // TSK109_Error_Code_Handling formatted context traces
#include <string>
#include <string_view>  // TSK109_Error_Code_Handling context formatter interface
#include <type_traits>  // TSK109_Error_Code_Handling generic context helpers
#include <unordered_set>  // TSK140_Temporary_File_Security_Vulnerabilities track active temps
#include <vector>         // TSK140_Temporary_File_Security_Vulnerabilities batched cleanup
#include <system_error>
#include <thread> // TSK101_File_IO_Persistence_and_Atomicity retry backoff

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/statfs.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/param.h>
#include <sys/mount.h>
#endif
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
constexpr const char* kAtomicUnsupportedMessage =
    "Filesystem does not support atomic rename"; // TSK107_Platform_Specific_Issues user-facing error
constexpr const char* kTempFilesystemUnencryptedMessage =
    "Temporary path is not on an encrypted filesystem"; // TSK140_Temporary_File_Security_Vulnerabilities enforcement message

class ErrorContext { // TSK109_Error_Code_Handling accumulate nested call context
 public:
  void Push(std::string context) { context_stack_.push_back(std::move(context)); }
  void Pop() {
    if (!context_stack_.empty()) {
      context_stack_.pop_back();
    }
  }
  [[nodiscard]] std::vector<std::string> Stack() const { return context_stack_; }
  [[nodiscard]] std::string Format(std::string_view message) const {
    std::ostringstream oss;
    oss << message;
    for (auto it = context_stack_.rbegin(); it != context_stack_.rend(); ++it) {
      oss << "\n  while: " << *it;
    }
    return oss.str();
  }

 private:
  std::vector<std::string> context_stack_;
};

class ScopedErrorContext { // TSK109_Error_Code_Handling automatic push/pop helper
 public:
  ScopedErrorContext(ErrorContext& ctx, std::string description) : ctx_(ctx) {
    ctx_.Push(std::move(description));
  }
  ScopedErrorContext(const ScopedErrorContext&) = delete;
  ScopedErrorContext& operator=(const ScopedErrorContext&) = delete;
  ~ScopedErrorContext() { ctx_.Pop(); }

 private:
  ErrorContext& ctx_;
};

qv::Retryability ClassifyNativeError(int native) { // TSK109_Error_Code_Handling retry taxonomy
  switch (native) {
#if defined(EINTR)
    case EINTR:
#endif
#if defined(EAGAIN)
    case EAGAIN:
#endif
#if defined(EWOULDBLOCK)
    case EWOULDBLOCK:
#endif
      return qv::Retryability::kRetryable;
#if defined(EBUSY)
    case EBUSY:
      return qv::Retryability::kTransient;
#endif
#if defined(ETIMEDOUT)
    case ETIMEDOUT:
      return qv::Retryability::kTransient;
#endif
#if defined(_WIN32)
    case ERROR_LOCK_VIOLATION:
    case ERROR_SHARING_VIOLATION:
      return qv::Retryability::kTransient;
#endif
    default:
      break;
  }
  return qv::Retryability::kFatal;
}

qv::Retryability ClassifyErrorCode(const std::error_code& ec) { // TSK109_Error_Code_Handling std::error_code bridge
  return ClassifyNativeError(ec.value());
}

std::vector<std::string> MergeContext(const std::vector<std::string>& existing,
                                      const ErrorContext& ctx) { // TSK109_Error_Code_Handling accumulate stack
  auto merged = existing;
  auto stack = ctx.Stack();
  merged.insert(merged.end(), stack.begin(), stack.end());
  return merged;
}

[[noreturn]] void ThrowIoError(const ErrorContext& ctx, int code, std::string message,
                               std::optional<int> native = std::nullopt,
                               qv::Retryability retry = qv::Retryability::kFatal) { // TSK109_Error_Code_Handling unify throws
  auto stack = ctx.Stack();
  std::optional<int> native_value = native;
  if (!native_value.has_value() && code != 0) {
    native_value = code;
  }
  throw Error{ErrorDomain::IO, code, ctx.Format(std::move(message)), native_value, retry, std::move(stack)};
}

[[noreturn]] void ThrowValidationError(const ErrorContext& ctx, std::string message) { // TSK109_Error_Code_Handling
  auto stack = ctx.Stack();
  throw Error{ErrorDomain::Validation, 0, ctx.Format(std::move(message)), std::nullopt,
              qv::Retryability::kFatal, std::move(stack)};
}

Error AugmentError(const Error& err, const ErrorContext& ctx) { // TSK109_Error_Code_Handling append context to nested errors
  return Error{err.domain,
               err.code,
               ctx.Format(err.what()),
               err.native_code,
               err.retryability,
               MergeContext(err.context, ctx)};
}

[[noreturn]] void RethrowSystemError(const std::system_error& sys_err,
                                     const ErrorContext& ctx) { // TSK109_Error_Code_Handling preserve errno
  auto stack = ctx.Stack();
  throw Error{ErrorDomain::IO,
              sys_err.code().value(),
              ctx.Format(sys_err.what()),
              sys_err.code().value(),
              ClassifyErrorCode(sys_err.code()),
              std::move(stack)};
}

[[noreturn]] void RethrowUnknownError(const std::exception& ex,
                                      const ErrorContext& ctx) { // TSK109_Error_Code_Handling
  throw Error{ErrorDomain::Internal, 0, ctx.Format(ex.what()), std::nullopt,
              qv::Retryability::kFatal, ctx.Stack()};
}

template <typename Func>
auto WithContext(ErrorContext& ctx, std::string description, Func&& fn)
    -> std::invoke_result_t<Func&> { // TSK109_Error_Code_Handling scope wrapper
  ScopedErrorContext scoped(ctx, std::move(description));
  try {
    if constexpr (std::is_void_v<std::invoke_result_t<Func&>>) {
      fn();
      return;
    } else {
      return fn();
    }
  } catch (const Error& err) {
    if (err.context.empty()) {
      throw AugmentError(err, ctx);
    }
    throw;
  } catch (const std::system_error& sys_err) {
    RethrowSystemError(sys_err, ctx);
  } catch (const std::exception& ex) {
    RethrowUnknownError(ex, ctx);
  }
}

#ifdef _WIN32
std::wstring ToWidePath(const std::filesystem::path& path) { // TSK107_Platform_Specific_Issues
  return path.wstring();
}

bool SupportsAtomicRename(const std::filesystem::path& dir) { // TSK107_Platform_Specific_Issues
  std::filesystem::path probe = dir;
  if (probe.empty()) {
    probe = std::filesystem::current_path();
  }
  std::error_code ec;
  auto absolute = std::filesystem::weakly_canonical(probe, ec);
  if (ec) {
    absolute = std::filesystem::absolute(probe, ec);
    if (ec) {
      return false;
    }
  }
  auto root = absolute.root_path();
  if (root.empty()) {
    root = absolute;
  }
  std::wstring volume = root.wstring();
  if (!volume.empty() && volume.back() != L'\\' && volume.back() != L'/') {
    volume.push_back(L'\\');
  }
  DWORD flags = 0;
  if (!::GetVolumeInformationW(volume.c_str(), nullptr, 0, nullptr, nullptr, &flags, nullptr, 0)) {
    return false;
  }
#if defined(FILE_REMOTE_DEVICE)
  if ((flags & FILE_REMOTE_DEVICE) != 0U) {
    return false;
  }
#endif
#if defined(FILE_SUPPORTS_POSIX_UNLINK_RENAME)
  return (flags & FILE_SUPPORTS_POSIX_UNLINK_RENAME) != 0U;
#else
  return true;
#endif
}
#else
bool SupportsAtomicRename(const std::filesystem::path& dir) { // TSK107_Platform_Specific_Issues
  std::filesystem::path probe = dir;
  if (probe.empty()) {
    probe = std::filesystem::current_path();
  }
  std::error_code ec;
  auto absolute = std::filesystem::weakly_canonical(probe, ec);
  if (ec) {
    absolute = std::filesystem::absolute(probe, ec);
  }
  if (absolute.empty()) {
    return false;
  }

  struct statfs info {
  };
  if (::statfs(absolute.c_str(), &info) != 0) {
    return false;
  }

#if defined(__linux__)
  switch (info.f_type) {
    case 0x6969:      // NFS_SUPER_MAGIC
    case 0xFF534D42:  // CIFS
    case 0xFE534D42:  // SMB2
    case 0x517B:      // SMB
      return false;
    default:
      return true;
  }
#elif defined(__APPLE__) || defined(__FreeBSD__)
  return (info.f_flags & MNT_LOCAL) != 0;
#else
  return true;
#endif
}
#endif

#ifdef _WIN32
int NativeOpen(const std::filesystem::path& path) { // TSK068_Atomic_Header_Writes platform abstraction
  const std::wstring native = ToWidePath(path); // TSK107_Platform_Specific_Issues ensure wide API use
  return _wopen(native.c_str(), _O_CREAT | _O_WRONLY | _O_TRUNC | _O_BINARY | _O_SEQUENTIAL,
                _S_IREAD | _S_IWRITE);
}

int NativeClose(int fd) { return _close(fd); }

int NativeFsync(int fd) {
  // TSK107_Platform_Specific_Issues: _commit() provides best-effort fsync-equivalent semantics on Windows.
  // It forces dirty buffers to disk but may still depend on storage write-back policies.
  // TSK112_Documentation_and_Code_Clarity: Windows lacks a direct fsync; _commit flushes file
  // contents but metadata durability still relies on the subsequent directory FlushFileBuffers call.
  return _commit(fd);
}

int NativeWrite(int fd, const uint8_t* data, size_t size) {
  return _write(fd, data, static_cast<unsigned int>(size));
}

bool NativeRename(const std::filesystem::path& from,
                  const std::filesystem::path& to) { // TSK068_Atomic_Header_Writes atomic swap
  const std::wstring native_from = ToWidePath(from);   // TSK107_Platform_Specific_Issues ensure wide API use
  const std::wstring native_to = ToWidePath(to);       // TSK107_Platform_Specific_Issues ensure wide API use
  return ::MoveFileExW(native_from.c_str(), native_to.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

void SyncDirectory(const std::filesystem::path& dir) { // TSK068_Atomic_Header_Writes ensure metadata durability
  const std::wstring native = ToWidePath(dir);         // TSK107_Platform_Specific_Issues ensure wide API use
  HANDLE handle = ::CreateFileW(
      native.c_str(), GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const int saved_error = static_cast<int>(::GetLastError());          // TSK109_Error_Code_Handling snapshot win32 error
    throw Error{ErrorDomain::IO,
                saved_error,
                std::string(kAtomicReplaceErrorMessage) + ": open directory failed",
                saved_error,
                ClassifyNativeError(saved_error)};
  }
  if (!::FlushFileBuffers(handle)) {
    const int err = static_cast<int>(::GetLastError());                  // TSK109_Error_Code_Handling preserve before cleanup
    ::CloseHandle(handle);
    throw Error{ErrorDomain::IO,
                err,
                std::string(kAtomicReplaceErrorMessage) + ": directory flush failed",
                err,
                ClassifyNativeError(err)};
  }
  ::CloseHandle(handle);
}

#else

int NativeOpen(const std::filesystem::path& path) { // TSK068_Atomic_Header_Writes platform abstraction
  return ::open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
}

int NativeClose(int fd) { return ::close(fd); }

int NativeFsync(int fd) {
  // TSK112_Documentation_and_Code_Clarity: POSIX provides ::fsync which commits both file data and
  // metadata for the descriptor, contrasting with the Windows _commit fallback documented above.
  return ::fsync(fd);
}

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
    const int saved_errno = errno;                                       // TSK109_Error_Code_Handling preserve errno
    throw Error{ErrorDomain::IO,
                saved_errno,
                std::string(kAtomicReplaceErrorMessage) + ": open directory failed",
                saved_errno,
                ClassifyNativeError(saved_errno)};
  }
  if (::fsync(dir_fd) != 0) {
    const int err = errno;                                               // TSK109_Error_Code_Handling snapshot before close
    ::close(dir_fd);
    throw Error{ErrorDomain::IO,
                err,
                std::string(kAtomicReplaceErrorMessage) + ": directory flush failed",
                err,
                ClassifyNativeError(err)};
  }
  ::close(dir_fd);
}

#endif

bool IsTransientFsyncError(int err) { // TSK101_File_IO_Persistence_and_Atomicity classify retryable failures
#ifdef _WIN32
  return err == EINTR || err == EAGAIN;
#else
  return err == EINTR || err == EAGAIN || err == EBUSY;
#endif
}

void SyncFileWithRetry(int fd, ErrorContext& ctx) { // TSK101_File_IO_Persistence_and_Atomicity durability retry loop
  constexpr int kMaxRetries = 4;
  std::chrono::milliseconds backoff{5};
  for (int attempt = 0;; ++attempt) {
    if (NativeFsync(fd) == 0) {
      return;
    }
    const int saved_errno = errno;                           // TSK109_Error_Code_Handling preserve errno
    if (saved_errno == EINTR) {
      continue;
    }
    if (attempt >= kMaxRetries || !IsTransientFsyncError(saved_errno)) {
      ThrowIoError(ctx,
                   saved_errno,
                   std::string(kAtomicReplaceErrorMessage) + ": fsync failed", // TSK109_Error_Code_Handling richer detail
                   saved_errno,
                   ClassifyNativeError(saved_errno));
    }
    std::this_thread::sleep_for(backoff);
    backoff *= 2;
  }
}

void WriteAll(int fd, std::span<const uint8_t> payload, ErrorContext& ctx) { // TSK068_Atomic_Header_Writes
  size_t written = 0;
  while (written < payload.size()) {
    auto chunk = NativeWrite(fd, payload.data() + written, payload.size() - written);
    if (chunk < 0) {
      const int saved_errno = errno;                         // TSK109_Error_Code_Handling snapshot native error
      if (saved_errno == EINTR) { // TSK101_File_IO_Persistence_and_Atomicity retry interrupted writes
        continue;
      }
      ThrowIoError(ctx,
                   saved_errno,
                   std::string(kAtomicReplaceErrorMessage) + ": write failed", // TSK109_Error_Code_Handling stage detail
                   saved_errno,
                   ClassifyNativeError(saved_errno));
    }
    if (chunk == 0) {
      ThrowIoError(ctx,
                   0,
                   std::string(kAtomicReplaceErrorMessage) + ": short write",
                   0,
                   qv::Retryability::kFatal); // TSK109_Error_Code_Handling treat zero-write as fatal
    }
    written += static_cast<size_t>(chunk);
  }
}

class TempFileRegistry { // TSK140_Temporary_File_Security_Vulnerabilities global cleanup coordinator
 public:
  static TempFileRegistry& Instance() {
    static TempFileRegistry instance;
    return instance;
  }

  void Track(const std::filesystem::path& path) {
    EnsureHandlers();
    std::lock_guard<std::mutex> lock(mutex_);
    tracked_.insert(path);
  }

  void Untrack(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    tracked_.erase(path);
  }

  void CleanupAll() noexcept {
    std::vector<std::filesystem::path> snapshot;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      snapshot.assign(tracked_.begin(), tracked_.end());
      tracked_.clear();
    }
    for (const auto& candidate : snapshot) {
      std::error_code ec;
      if (!std::filesystem::remove(candidate, ec) && ec) {
        std::cerr << "TempFileRegistry cleanup failed for " << candidate << ": " << ec.message()
                  << '\n';
      }
    }
  }

  static void HandleSignal(int signal) noexcept {
    TempFileRegistry::Instance().CleanupAll();
    std::signal(signal, SIG_DFL);
    std::raise(signal);
  }

 private:
  TempFileRegistry() = default;

  void EnsureHandlers() {
    std::call_once(handlers_once_, [] {
      std::atexit([] { TempFileRegistry::Instance().CleanupAll(); });
#if defined(SIGINT)
      std::signal(SIGINT, TempFileRegistry::HandleSignal);
#endif
#if defined(SIGTERM)
      std::signal(SIGTERM, TempFileRegistry::HandleSignal);
#endif
#if defined(SIGHUP)
      std::signal(SIGHUP, TempFileRegistry::HandleSignal);
#endif
#if defined(SIGQUIT)
      std::signal(SIGQUIT, TempFileRegistry::HandleSignal);
#endif
    });
  }

  std::mutex mutex_;
  std::unordered_set<std::filesystem::path> tracked_;
  std::once_flag handlers_once_;
};

class TempFileGuard { // TSK068_Atomic_Header_Writes ensure cleanup on failure
 public:
  explicit TempFileGuard(std::filesystem::path path) noexcept : path_(std::move(path)) {
    if (!path_.empty()) {
      TempFileRegistry::Instance().Track(path_); // TSK140_Temporary_File_Security_Vulnerabilities ensure lifecycle tracking
    }
  }
  TempFileGuard(const TempFileGuard&) = delete;
  TempFileGuard& operator=(const TempFileGuard&) = delete;
  ~TempFileGuard() noexcept {
    if (!path_.empty()) {
      std::error_code ec;
      if (!std::filesystem::remove(path_, ec) && ec) { // TSK101_File_IO_Persistence_and_Atomicity surface cleanup failures
        std::cerr << "TempFileGuard cleanup failed for " << path_ << ": " << ec.message()
                  << '\n';
      } else {
        TempFileRegistry::Instance().Untrack(path_); // TSK140_Temporary_File_Security_Vulnerabilities stop tracking once removed
      }
    }
  }

  void Release() noexcept {
    if (!path_.empty()) {
      TempFileRegistry::Instance().Untrack(path_); // TSK140_Temporary_File_Security_Vulnerabilities manual lifecycle release
    }
    path_.clear();
  }

 private:
  std::filesystem::path path_;
};

std::string GenerateTempToken() { // TSK140_Temporary_File_Security_Vulnerabilities cryptographically strong token
  std::array<uint8_t, 16> random{};
  qv::crypto::SystemRandomBytes(std::span<uint8_t>(random.data(), random.size()));
  static constexpr char kHex[] = "0123456789abcdef";
  std::string token;
  token.reserve(random.size() * 2);
  for (auto byte : random) {
    token.push_back(kHex[(byte >> 4) & 0x0F]);
    token.push_back(kHex[byte & 0x0F]);
  }
  return token;
}

std::filesystem::path MakeTempPath(const std::filesystem::path& dir,
                                   const std::filesystem::path& base) { // TSK068_Atomic_Header_Writes unique temp
  const auto token = GenerateTempToken(); // TSK140_Temporary_File_Security_Vulnerabilities expand entropy surface
  std::filesystem::path temp_name = base.filename();
  temp_name += ".tmp.";
  temp_name += token;
  return dir / temp_name; // TSK107_Platform_Specific_Issues avoid lossy conversions
}

bool PathOnEncryptedFilesystem(const std::filesystem::path& dir) { // TSK140_Temporary_File_Security_Vulnerabilities enforce encrypted staging
  std::filesystem::path probe = dir;
  if (probe.empty()) {
    std::error_code ec;
    probe = std::filesystem::current_path(ec);
    if (ec) {
      return false;
    }
  }

#if defined(_WIN32)
  const std::wstring native = ToWidePath(probe);
  const DWORD attributes = ::GetFileAttributesW(native.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    return false;
  }
#if defined(FILE_ATTRIBUTE_ENCRYPTED)
  if ((attributes & FILE_ATTRIBUTE_ENCRYPTED) != 0U) {
    return true;
  }
#endif
  return false;
#elif defined(__APPLE__) || defined(__FreeBSD__)
  struct statfs info {
  };
  if (::statfs(probe.c_str(), &info) != 0) {
    return false;
  }
#if defined(MNT_CRYPT)
  return (info.f_flags & MNT_CRYPT) != 0;
#else
  return false;
#endif
#elif defined(__linux__) && defined(STATX_ATTR_ENCRYPTED)
  struct statx encrypted {
  };
  if (::statx(AT_FDCWD, probe.c_str(), AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT,
              STATX_BASIC_STATS | STATX_ATTRIBUTES, &encrypted) != 0) {
    return false;
  }
  if ((encrypted.stx_attributes_mask & STATX_ATTR_ENCRYPTED) == 0) {
    return false;
  }
  return (encrypted.stx_attributes & STATX_ATTR_ENCRYPTED) != 0;
#else
  (void)probe;
  return false;
#endif
}

void EnsurePrivatePermissions(int fd, const std::filesystem::path& path, const ErrorContext& ctx) {
#if defined(_WIN32)
  (void)fd;
  const std::wstring native = ToWidePath(path);
  if (_wchmod(native.c_str(), _S_IREAD | _S_IWRITE) != 0) {
    const int saved_error = errno;
    ThrowIoError(ctx,
                 saved_error,
                 std::string(kAtomicReplaceErrorMessage) + ": failed to harden temp file permissions",
                 saved_error,
                 ClassifyNativeError(saved_error)); // TSK140_Temporary_File_Security_Vulnerabilities enforce private ACLs
  }
#else
  if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
    const int saved_errno = errno;
    ThrowIoError(ctx,
                 saved_errno,
                 std::string(kAtomicReplaceErrorMessage) + ": failed to harden temp file permissions",
                 saved_errno,
                 ClassifyNativeError(saved_errno)); // TSK140_Temporary_File_Security_Vulnerabilities enforce private ACLs
  }
#endif
}

}  // namespace

void AtomicReplace(const std::filesystem::path& target, std::span<const uint8_t> payload,
                   const AtomicReplaceHooks& hooks) {
  ErrorContext ctx;                                                      // TSK109_Error_Code_Handling contextual diagnostics
  const std::string target_utf8 = target.empty() ? std::string("<empty>") : qv::PathToUtf8String(target);
  ScopedErrorContext root(ctx, "atomic replace target=" + target_utf8); // TSK109_Error_Code_Handling primary context

  try {
    if (target.empty()) {
      ThrowValidationError(ctx, "Target path required");
    }

    auto dir = target.parent_path();
    if (dir.empty()) {
      dir = WithContext(ctx, "resolving current working directory", [] {
        return std::filesystem::current_path();
      });
    }

    WithContext(ctx, "checking atomic rename support", [&] {
      if (!SupportsAtomicRename(dir)) { // TSK107_Platform_Specific_Issues proactively guard non-atomic filesystems
        ThrowIoError(ctx, 0, kAtomicUnsupportedMessage, std::nullopt, qv::Retryability::kFatal);
      }
    });

    if (!PathOnEncryptedFilesystem(dir)) {
      ThrowIoError(ctx,
                   0,
                   kTempFilesystemUnencryptedMessage,
                   std::nullopt,
                   qv::Retryability::kFatal); // TSK140_Temporary_File_Security_Vulnerabilities enforce encrypted staging
    }

    auto temp_path = MakeTempPath(dir, target);
    TempFileGuard cleanup(temp_path);

    int fd = WithContext(ctx, "opening temporary payload file", [&]() {
      int handle = NativeOpen(temp_path);
      if (handle < 0) {
        const int saved_errno = errno;
        ThrowIoError(ctx,
                     saved_errno,
                     std::string(kAtomicReplaceErrorMessage) + ": open failed",
                     saved_errno,
                     ClassifyNativeError(saved_errno));
      }
      return handle;
    });

    EnsurePrivatePermissions(fd, temp_path, ctx); // TSK140_Temporary_File_Security_Vulnerabilities enforce restrictive ACLs

    try {
      WithContext(ctx, "writing payload", [&] { WriteAll(fd, payload, ctx); });
      WithContext(ctx, "syncing payload", [&] { SyncFileWithRetry(fd, ctx); });
    } catch (...) {
      NativeClose(fd);
      throw;
    }

    WithContext(ctx, "closing temporary payload file", [&] {
      if (NativeClose(fd) != 0) {
        const int saved_errno = errno;
        ThrowIoError(ctx,
                     saved_errno,
                     std::string(kAtomicReplaceErrorMessage) + ": close failed",
                     saved_errno,
                     ClassifyNativeError(saved_errno));
      }
    });

    if (hooks.before_rename) {
      WithContext(ctx, "executing before_rename hook", [&] { hooks.before_rename(temp_path, target); });
    }

    WithContext(ctx, "renaming temporary file into place", [&] {
      if (!NativeRename(temp_path, target)) {
        int err = errno;
#ifdef _WIN32
        if (err == 0) {
          err = static_cast<int>(::GetLastError());
        }
#endif
        ThrowIoError(ctx,
                     err,
                     std::string(kAtomicReplaceErrorMessage) + ": rename failed",
                     err,
                     ClassifyNativeError(err));
      }
    });

    WithContext(ctx, "verifying renamed target", [&] {
      std::error_code verify_ec;
      const bool exists_after = std::filesystem::exists(target, verify_ec);
      if (verify_ec) { // TSK101_File_IO_Persistence_and_Atomicity verify rename
        ThrowIoError(ctx,
                     verify_ec.value(),
                     std::string(kAtomicReplaceErrorMessage) + ": existence check failed",
                     verify_ec.value(),
                     ClassifyErrorCode(verify_ec));
      }
      if (!exists_after) {
        ThrowIoError(ctx,
                     0,
                     std::string(kAtomicReplaceErrorMessage) + ": renamed file missing",
                     0,
                     qv::Retryability::kFatal);
      }
    });

    cleanup.Release();

    auto sync_dir = dir;
    if (sync_dir.empty()) {
      sync_dir = WithContext(ctx, "resolving directory for metadata sync", [] {
        return std::filesystem::current_path();
      });
    }
    WithContext(ctx, "syncing directory metadata", [&] { SyncDirectory(sync_dir); });
  } catch (const Error& err) {
    if (err.context.empty()) {
      throw AugmentError(err, ctx);
    }
    throw;
  } catch (const std::system_error& sys_err) {
    RethrowSystemError(sys_err, ctx);
  } catch (const std::exception& ex) {
    RethrowUnknownError(ex, ctx);
  }
}

}  // namespace qv::orchestrator
