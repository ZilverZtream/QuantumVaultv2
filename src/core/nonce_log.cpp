#include "qv/core/nonce.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/crypto/provider.h" // TSK072_CryptoProvider_Init_and_KAT reuse provider runtime init
#include "qv/crypto/random.h"   // TSK124_Insecure_Randomness_Usage provide OS randomness fallback
#include "qv/error.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>      // TSK101_File_IO_Persistence_and_Atomicity retry backoff
#include <exception>   // TSK101_File_IO_Persistence_and_Atomicity log cleanup errors
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream> // TSK101_File_IO_Persistence_and_Atomicity surface cleanup failures
#include <limits>      // TSK095_Memory_Safety_and_Buffer_Bounds overflow guards
#include <memory>       // TSK133_Race_in_Nonce_Log_Recovery file lock lifetime
#include <mutex>        // TSK023_Production_Crypto_Provider_Complete_Integration sodium init guard
#include <stdexcept>  // TSK104_Concurrency_Deadlock_and_Lock_Ordering misuse detection
#include <system_error>
#include <thread>      // TSK101_File_IO_Persistence_and_Atomicity retry backoff
#include <type_traits> // TSK100_Integer_Overflow_and_Arithmetic checked casts
#include <vector>
#include <span>        // TSK124_Insecure_Randomness_Usage span adapter for RNG inputs

// TSK021_Nonce_Log_Durability_and_Crash_Safety introduce explicit fsync helpers and
// platform-specific primitives.
#ifndef _WIN32
#include <fcntl.h>
#include <sys/file.h>   // TSK133_Race_in_Nonce_Log_Recovery advisory locking
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#else
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#endif

#ifndef _WIN32
#include <openssl/err.h>
#include <openssl/rand.h>
#else
#include <bcrypt.h>
#include <windows.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib") // TSK016_Windows_Compatibility_Fixes ensure RNG linkage
#endif
extern "C" BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength); // TSK134_Insufficient_Entropy_for_Keys Windows fallback RNG
#endif

#if QV_HAVE_SODIUM
#include <sodium.h> // TSK023_Production_Crypto_Provider_Complete_Integration cryptographic RNG
#endif

using namespace qv;
using namespace qv::core;
using qv::crypto::HMAC_SHA256;

namespace {
  constexpr std::array<char, 8> kHeaderMagic{'Q', 'V', 'N', 'O', 'N', 'C', 'E', '1'};
  constexpr uint32_t kLogVersion = 1;
  constexpr size_t kMacSize = 32;
  constexpr size_t kEntrySize = sizeof(uint64_t) + kMacSize;
  constexpr size_t kHeaderSize =
      kHeaderMagic.size() + sizeof(uint32_t) + kMacSize; // TSK_CRIT_09_Nonce_Log_Write_Amplification_DoS

#ifdef _WIN32
  using NativeStat = struct _stat64; // TSK021_Nonce_Log_Durability_and_Crash_Safety
#else
  using NativeStat = struct stat; // TSK021_Nonce_Log_Durability_and_Crash_Safety
#endif

  std::filesystem::path ResolveDirectory(const std::filesystem::path& path) {
    auto dir = path.parent_path();
    if (dir.empty()) {
      return std::filesystem::current_path();
    }
    return dir;
  }

  template <typename Target, typename Source>
  Target CheckedUnsignedCast(Source value, const char* context) { // TSK100_Integer_Overflow_and_Arithmetic cast guard
    static_assert(std::is_unsigned_v<Target>);
    static_assert(std::is_unsigned_v<Source>);
    if (value > std::numeric_limits<Target>::max()) {
      throw Error{ErrorDomain::Validation, 0, context};
    }
    return static_cast<Target>(value);
  }

  size_t CheckedAdd(size_t lhs, size_t rhs, const char* context) { // TSK100_Integer_Overflow_and_Arithmetic addition guard
    if (lhs > std::numeric_limits<size_t>::max() - rhs) {
      throw Error{ErrorDomain::Validation, 0, context};
    }
    return lhs + rhs;
  }

#ifdef _WIN32
  int NativeOpen(const std::filesystem::path& path, int flags, int mode) {
    return _wopen(path.c_str(), flags | _O_BINARY, mode);
  }

  int NativeClose(int fd) {
    return _close(fd);
  }

  int NativeFsync(int fd) {
    return _commit(fd);
  }

  int NativeStatPath(const std::filesystem::path& path, NativeStat* info) {
    return _wstat64(path.c_str(), info);
  }

  ssize_t NativeWrite(int fd, const uint8_t* data, size_t size) {
    return _write(fd, data, static_cast<unsigned int>(size));
  }
#else
  int NativeOpen(const std::filesystem::path& path, int flags, mode_t mode) {
    return ::open(path.c_str(), flags, mode);
  }

  int NativeClose(int fd) {
    return ::close(fd);
  }

  int NativeFsync(int fd) {
    return ::fsync(fd);
  }

  int NativeStatPath(const std::filesystem::path& path, NativeStat* info) {
    return ::stat(path.c_str(), info);
  }

  ssize_t NativeWrite(int fd, const uint8_t* data, size_t size) {
    return ::write(fd, data, size);
  }
#endif

  bool ShouldRetryFsync(int err) { // TSK101_File_IO_Persistence_and_Atomicity classify retryable failures
#ifdef _WIN32
    return err == EINTR || err == EAGAIN;
#else
    return err == EINTR || err == EAGAIN || err == EBUSY;
#endif
  }

  void WriteAll(int fd, std::span<const uint8_t> bytes) { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    size_t offset = 0;
    while (offset < bytes.size()) {
      ssize_t written = NativeWrite(fd, bytes.data() + offset, bytes.size() - offset);
      if (written < 0) {
        int err = errno;
        if (err == EINTR) { // TSK101_File_IO_Persistence_and_Atomicity retry interrupted writes
          continue;
        }
        throw Error{ErrorDomain::IO, err, "Failed to write nonce log snapshot"};
      }
      if (written == 0) {
        throw Error{ErrorDomain::IO, 0, "Failed to write nonce log snapshot"}; // TSK101_File_IO_Persistence_and_Atomicity short write
      }
      offset += static_cast<size_t>(written);
    }
  }

  void SyncFileDescriptor(int fd) { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    constexpr int kMaxRetries = 4; // TSK101_File_IO_Persistence_and_Atomicity retry fsync
    std::chrono::milliseconds backoff{5};
    for (int attempt = 0;; ++attempt) {
      if (NativeFsync(fd) == 0) {
        return;
      }
      int err = errno;
      if (err == EINTR) {
        continue;
      }
      if (attempt >= kMaxRetries || !ShouldRetryFsync(err)) {
        throw Error{ErrorDomain::IO, err, "Failed to fsync nonce log"};
      }
      std::this_thread::sleep_for(backoff);
      backoff *= 2;
    }
  }

  void SyncDirectory(const std::filesystem::path& dir) { // TSK021_Nonce_Log_Durability_and_Crash_Safety
#ifndef _WIN32
    int dir_fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
    if (dir_fd >= 0) {
      if (::fsync(dir_fd) != 0) {
        int err = errno;
        ::close(dir_fd);
        throw Error{ErrorDomain::IO, err, "Failed to fsync nonce log directory"};
      }
      ::close(dir_fd);
    }
#else
    HANDLE handle = ::CreateFileW(
        dir.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL, nullptr); // TSK101_File_IO_Persistence_and_Atomicity ensure metadata flush
    if (handle == INVALID_HANDLE_VALUE) {
      throw Error{ErrorDomain::IO, static_cast<int>(::GetLastError()),
                  "Failed to fsync nonce log directory"};
    }
    if (!::FlushFileBuffers(handle)) {
      auto err = static_cast<int>(::GetLastError());
      ::CloseHandle(handle);
      throw Error{ErrorDomain::IO, err, "Failed to fsync nonce log directory"};
    }
    ::CloseHandle(handle);
#endif
  }

  void VerifySameFilesystem(const std::filesystem::path& lhs,
                            const std::filesystem::path& rhs) { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    NativeStat lhs_stat{};
    if (NativeStatPath(lhs, &lhs_stat) != 0) {
      throw Error{ErrorDomain::IO, errno, "Failed to stat nonce temp file"};
    }
    auto dir = ResolveDirectory(rhs);
    NativeStat dir_stat{};
    if (NativeStatPath(dir, &dir_stat) != 0) {
      throw Error{ErrorDomain::IO, errno, "Failed to stat nonce directory"};
    }
    if (lhs_stat.st_dev != dir_stat.st_dev) {
      throw Error{ErrorDomain::IO, 0, "Nonce log temp file on different filesystem"};
    }
  }

  std::filesystem::path LockPathFor(const std::filesystem::path& path) { // TSK133_Race_in_Nonce_Log_Recovery lock file suffix
    auto lock = path;
    lock += ".lock";
    return lock;
  }

  class NonceLogFileLock {                                             // TSK133_Race_in_Nonce_Log_Recovery cross-process guard
  public:
    explicit NonceLogFileLock(const std::filesystem::path& path) {
      std::error_code ec;
      auto parent = path.parent_path();
      if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
          throw Error{ErrorDomain::IO, ec.value(),
                      "Failed to create nonce lock directory " +
                          qv::PathToUtf8String(parent)};
        }
      }
#ifdef _WIN32
      handle_ = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (handle_ == INVALID_HANDLE_VALUE) {
        auto err = static_cast<int>(::GetLastError());
        throw Error{ErrorDomain::IO, err,
                    "Failed to lock nonce log " + qv::PathToUtf8String(path)};
      }
#else
      fd_ = ::open(path.c_str(), O_RDWR | O_CREAT, 0600);
      if (fd_ < 0) {
        throw Error{ErrorDomain::IO, errno,
                    "Failed to open nonce log lock " + qv::PathToUtf8String(path)};
      }
      if (::flock(fd_, LOCK_EX) != 0) {
        int err = errno;
        ::close(fd_);
        fd_ = -1;
        throw Error{ErrorDomain::IO, err,
                    "Failed to acquire nonce log lock " + qv::PathToUtf8String(path)};
      }
#endif
    }

    NonceLogFileLock(const NonceLogFileLock&) = delete;
    NonceLogFileLock& operator=(const NonceLogFileLock&) = delete;

    ~NonceLogFileLock() {
#ifdef _WIN32
      if (handle_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
      }
#else
      if (fd_ >= 0) {
        ::flock(fd_, LOCK_UN);
        ::close(fd_);
        fd_ = -1;
      }
#endif
    }

  private:
#ifdef _WIN32
    HANDLE handle_{INVALID_HANDLE_VALUE};
#else
    int fd_{-1};
#endif
  };

} // namespace

struct NonceLog::FileLock {                                             // TSK133_Race_in_Nonce_Log_Recovery member indirection
  explicit FileLock(const std::filesystem::path& path) : guard(path) {}
  NonceLogFileLock guard;
};

namespace {

  class TempFileGuard { // TSK028_Secure_Deletion_and_Data_Remanence
  public:
    explicit TempFileGuard(std::filesystem::path path) noexcept : path_(std::move(path)) {}
    TempFileGuard(const TempFileGuard&) = delete;
    TempFileGuard& operator=(const TempFileGuard&) = delete;
    ~TempFileGuard() noexcept {
      try {
        Cleanup();
      } catch (const std::exception& ex) {
        std::cerr << "TempFileGuard cleanup threw: " << ex.what() << '\n'; // TSK101_File_IO_Persistence_and_Atomicity surface cleanup failures
      } catch (...) {
        std::cerr << "TempFileGuard cleanup encountered unknown failure\n"; // TSK101_File_IO_Persistence_and_Atomicity surface cleanup failures
      }
    }

    void Release() noexcept { path_.clear(); }

  private:
    void Cleanup() { // TSK_CRIT_17: Remove false security - modern filesystems don't guarantee in-place overwrites
      if (path_.empty()) {
        return;
      }
      std::error_code exists_ec;
      if (!std::filesystem::exists(path_, exists_ec) || exists_ec) {
        path_.clear();
        return;
      }
      // TSK_CRIT_17: Removed insecure zeroing attempt - CoW and journaling filesystems
      // provide no guarantee that writing zeros will overwrite data in-place.
      // Sensitive data may persist on disk. For true secure deletion, use
      // platform-specific APIs if available or accept data remanence.
      std::error_code remove_ec;
      if (!std::filesystem::remove(path_, remove_ec) && remove_ec) { // TSK101_File_IO_Persistence_and_Atomicity surface cleanup failures
        std::cerr << "TempFileGuard cleanup failed for " << path_ << ": "
                  << remove_ec.message() << '\n';
      }
      path_.clear();
    }

    std::filesystem::path path_;
  };

  void WriteSnapshotFile(const std::filesystem::path& path,
                         std::span<const uint8_t> bytes) { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    auto temp_path = path;
    temp_path += ".tmp";
    TempFileGuard temp_guard(temp_path); // TSK028_Secure_Deletion_and_Data_Remanence
    auto dir = ResolveDirectory(path);
    if (!dir.empty()) {
      std::filesystem::create_directories(dir);
    }
#ifdef _WIN32
    int fd = NativeOpen(temp_path, _O_WRONLY | _O_CREAT | _O_TRUNC, _S_IREAD | _S_IWRITE);
#else
    int fd = NativeOpen(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
#endif
    if (fd < 0) {
      throw Error{ErrorDomain::IO, errno, "Failed to open nonce temp file"};
    }
    try {
      WriteAll(fd, bytes);
      SyncFileDescriptor(fd);
    } catch (...) {
      NativeClose(fd);
      throw;
    }
    NativeClose(fd);

#ifndef _WIN32
    SyncDirectory(ResolveDirectory(temp_path));
#endif
    VerifySameFilesystem(temp_path, path);

    std::error_code rename_ec;
    std::filesystem::rename(temp_path, path, rename_ec);
    if (rename_ec) {
      std::error_code remove_ec;
      if (!std::filesystem::remove(path, remove_ec) && remove_ec) {
        throw Error{ErrorDomain::IO, remove_ec.value(),
                    "Failed to replace nonce log " + qv::PathToUtf8String(path)};
      }
      std::error_code retry_ec;
      std::filesystem::rename(temp_path, path, retry_ec);
      if (retry_ec) {
        throw Error{ErrorDomain::IO, retry_ec.value(),
                    "Failed to replace nonce log " + qv::PathToUtf8String(path)}; // TSK101_File_IO_Persistence_and_Atomicity ensure rename success
      }
    }
    std::error_code verify_ec;
    if (!std::filesystem::exists(path, verify_ec) || verify_ec) { // TSK101_File_IO_Persistence_and_Atomicity verify rename
      throw Error{ErrorDomain::IO, verify_ec ? verify_ec.value() : 0,
                  "Failed to replace nonce log " + qv::PathToUtf8String(path)};
    }
    temp_guard.Release();
#ifndef _WIN32
    SyncDirectory(ResolveDirectory(path));
#endif
  }

  // TSK_CRIT_19: The binding parameter should contain a hash of PLAINTEXT data or other
  // critical unencrypted metadata, NOT ciphertext (which is already authenticated by the AEAD tag).
  // Proper use: bind hash of plaintext chunk, file path, user ID, or other metadata.
  std::array<uint8_t, kMacSize> ComputeMac(std::span<const uint8_t, kMacSize> prev_mac,
                                           uint64_t counter,
                                           std::span<const uint8_t, kMacSize> key,
                                           std::span<const uint8_t> binding) { // TSK128_Missing_AAD_Validation_in_Chunks bind metadata
    struct MACHeader {
      std::array<uint8_t, kMacSize> previous;
      uint64_t counter_be;
      uint16_t binding_size_le;
    };
    if (binding.size() > std::numeric_limits<uint16_t>::max()) {
      throw Error{ErrorDomain::Validation, 0, "Nonce binding too large"};
    }
    MACHeader header{};
    std::copy(prev_mac.begin(), prev_mac.end(), header.previous.begin());
    header.counter_be = qv::ToBigEndian(counter);
    header.binding_size_le = qv::ToLittleEndian(static_cast<uint16_t>(binding.size()));
    std::vector<uint8_t> mac_input;
    mac_input.reserve(sizeof(MACHeader) + binding.size());
    auto header_bytes = qv::AsBytesConst(header);
    mac_input.insert(mac_input.end(), header_bytes.begin(), header_bytes.end());
    mac_input.insert(mac_input.end(), binding.begin(), binding.end());
    return HMAC_SHA256::Compute(key, mac_input);
  }

  template <typename Fn>
  bool TryRngProvider(Fn&& fn, std::vector<std::string>& failures) { // TSK124_Insecure_Randomness_Usage iterate RNG options
    try {
      fn();
      return true;
    } catch (const Error& err) {
      failures.emplace_back(err.what());
    } catch (const std::exception& ex) {
      failures.emplace_back(ex.what());
    }
    return false;
  }

  void GenerateKey(std::array<uint8_t, kMacSize>& key) { // TSK124_Insecure_Randomness_Usage resilient RNG selection
    key.fill(0); // TSK134_Insufficient_Entropy_for_Keys clear previous key material
    std::array<uint8_t, kMacSize> candidate{}; // TSK134_Insufficient_Entropy_for_Keys stage key until success
    std::vector<std::string> failures;
#if QV_HAVE_SODIUM
    if (TryRngProvider(
            [&]() {
              qv::crypto::EnsureCryptoProviderInitialized(); // TSK072_CryptoProvider_Init_and_KAT single runtime init
              candidate.fill(0);
              randombytes_buf(candidate.data(), candidate.size());       // TSK023_Production_Crypto_Provider_Complete_Integration libsodium RNG
            },
            failures)) {
      key = candidate;
      return;
    }
#endif
    if (TryRngProvider(
            [&]() {
              candidate.fill(0);
              qv::crypto::SystemRandomBytes(std::span<uint8_t>(candidate.data(), candidate.size()));
            },
            failures)) {
      key = candidate;
      return;
    }
#if defined(_WIN32)
    if (TryRngProvider(
            [&]() {
              candidate.fill(0);
              const NTSTATUS status = BCryptGenRandom(nullptr, candidate.data(),
                                                      static_cast<ULONG>(candidate.size()),
                                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
              if (!BCRYPT_SUCCESS(status) &&
                  !RtlGenRandom(candidate.data(), static_cast<ULONG>(candidate.size()))) {
                throw Error{ErrorDomain::Security, static_cast<int>(status),
                            "Windows RNG failed"}; // TSK134_Insufficient_Entropy_for_Keys fallback to legacy API
              }
            },
            failures)) {
      key = candidate;
      return;
    }
#else
    if (TryRngProvider(
            [&]() {
              candidate.fill(0);
              if (RAND_status() == 0) { // TSK134_Insufficient_Entropy_for_Keys ensure entropy available
                RAND_poll();
                if (RAND_status() == 0) {
                  throw Error{ErrorDomain::Security, 0, "Insufficient entropy"};
                }
              }
              if (RAND_bytes(candidate.data(), static_cast<int>(candidate.size())) != 1) {
                const auto err = static_cast<int>(ERR_get_error());
                throw Error{ErrorDomain::Security, err,
                            "RAND_bytes failed"}; // TSK023_Production_Crypto_Provider_Complete_Integration OpenSSL RNG fallback
              }
            },
            failures)) {
      key = candidate;
      return;
    }
#endif

    std::string message =
        "Failed to generate nonce log key using available RNG providers"; // TSK124_Insecure_Randomness_Usage
    if (!failures.empty()) {
      message.append(": ");
      for (size_t i = 0; i < failures.size(); ++i) {
        if (i != 0) {
          message.append("; ");
        }
        message.append(failures[i]);
      }
    }
    throw Error{ErrorDomain::Security, 0, message};
  }

  std::vector<uint8_t> SerializeHeader(uint32_t version, std::span<const char, 8> magic,
                                       std::span<const uint8_t, kMacSize> key) {
    std::vector<uint8_t> bytes;
    bytes.reserve(8 + 4 + kMacSize);
    bytes.insert(bytes.end(), magic.begin(), magic.end());
    uint32_t ver_le = qv::ToLittleEndian(version);
    uint8_t ver_bytes[4];
    std::memcpy(ver_bytes, &ver_le, sizeof(ver_le));
    bytes.insert(bytes.end(), ver_bytes, ver_bytes + sizeof(ver_bytes));
    bytes.insert(bytes.end(), key.begin(), key.end());
    return bytes;
  }

  void AppendEntryBytes(std::vector<uint8_t>& out, uint64_t counter,
                        const std::array<uint8_t, kMacSize>& mac) {
    uint64_t counter_be = qv::ToBigEndian(counter);
    uint8_t counter_bytes[sizeof(counter_be)];
    std::memcpy(counter_bytes, &counter_be, sizeof(counter_be));
    out.insert(out.end(), counter_bytes, counter_bytes + sizeof(counter_bytes));
    out.insert(out.end(), mac.begin(), mac.end());
  }

} // namespace

void NonceLog::EnsureFileLock() {                                      // TSK133_Race_in_Nonce_Log_Recovery lazy guard setup
  if (file_lock_) {
    return;
  }
  if (path_.empty()) {
    throw std::logic_error("NonceLog path must be set before locking");
  }
  auto lock_path = LockPathFor(path_);
  file_lock_ = std::make_unique<FileLock>(lock_path);
}

NonceLog::NonceLog(const std::filesystem::path& path) : path_(path) {
  if (!path_.parent_path().empty()) {
    std::filesystem::create_directories(path_.parent_path());
  }
  EnsureFileLock();
  std::lock_guard<std::mutex> lock(mu_);
  if (std::filesystem::exists(path_)) {
    ReloadUnlocked();
  } else {
    InitializeNewLog();
  }
}

NonceLog::NonceLog(const std::filesystem::path& path, std::nothrow_t) noexcept
    : path_(path) { // TSK032_Backup_Recovery_and_Disaster_Recovery
  key_.fill(0);
  last_mac_.fill(0);
  entries_.clear();
  loaded_ = false;
}

void NonceLog::InitializeNewLog() {
  if (!path_.parent_path().empty()) {
    std::filesystem::create_directories(path_.parent_path());
  }
  EnsureFileLock();
  GenerateKey(key_);
  last_mac_.fill(0);
  entries_.clear();
  PersistUnlocked();
}

void NonceLog::EnsureLoadedUnlocked() {
  EnsureFileLock();
  if (loaded_) {
    return;
  }
  if (!std::filesystem::exists(path_)) {
    throw Error{ErrorDomain::IO, 0,
                "Nonce log missing at " +
                    qv::PathToUtf8String(path_)}; // TSK016_Windows_Compatibility_Fixes
  }
  ReloadUnlocked();
}

void NonceLog::ReloadUnlocked() {
  EnsureFileLock();
  std::ifstream in(path_, std::ios::binary);
  if (!in.is_open()) {
    throw Error{ErrorDomain::IO, 0,
                "Failed to open nonce log " +
                    qv::PathToUtf8String(path_)}; // TSK016_Windows_Compatibility_Fixes
  }
  in.seekg(0, std::ios::end);
  auto size = static_cast<std::streamoff>(in.tellg());
  in.seekg(0, std::ios::beg);
  if (size < static_cast<std::streamoff>(kHeaderSize)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log truncated"};
  }
  std::vector<uint8_t> data(static_cast<size_t>(size));
  in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
  if (!in) {
    throw Error{ErrorDomain::IO, 0,
                "Failed to read nonce log " +
                    qv::PathToUtf8String(path_)}; // TSK016_Windows_Compatibility_Fixes
  }

  const uint8_t* cursor = data.data();
  if (!std::equal(kHeaderMagic.begin(), kHeaderMagic.end(), cursor)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log header magic mismatch"};
  }
  cursor += kHeaderMagic.size();

  uint32_t version_le = 0;
  std::memcpy(&version_le, cursor, sizeof(version_le));
  cursor += sizeof(version_le);
  uint32_t version = qv::ToLittleEndian(version_le);
  if (version != kLogVersion) {
    throw Error{ErrorDomain::Validation, static_cast<int>(version),
                "Nonce log version unsupported"};
  }

  std::copy(cursor, cursor + kMacSize, key_.begin());
  cursor += kMacSize;

  size_t payload_remaining = data.size() - kHeaderSize;
  if (payload_remaining % kEntrySize != 0) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log truncated"};
  }

  entries_.clear();
  entries_.reserve(payload_remaining / kEntrySize);
  std::array<uint8_t, kMacSize> prev{};
  for (size_t offset = 0; offset < payload_remaining; offset += kEntrySize) {
    const uint8_t* entry_ptr = cursor + offset;
    uint64_t counter_be = 0;
    std::memcpy(&counter_be, entry_ptr, sizeof(counter_be));
    uint64_t counter = qv::ToBigEndian(counter_be);
    std::array<uint8_t, kMacSize> mac{};
    std::copy(entry_ptr + sizeof(counter_be),
              entry_ptr + sizeof(counter_be) + kMacSize, mac.begin());
    if (!entries_.empty() && counter <= entries_.back().counter) {
      throw Error{ErrorDomain::Validation, 0, "Nonce log counters not monotonic"};
    }
    auto expected = ComputeMac(prev, counter, key_);
    if (!std::equal(expected.begin(), expected.end(), mac.begin())) {
      throw Error{ErrorDomain::Validation, 0, "Nonce log MAC chain broken"};
    }
    entries_.push_back(LogEntry{counter, mac});
    prev = mac;
  }

  last_mac_ = entries_.empty() ? std::array<uint8_t, kMacSize>{} : entries_.back().mac;
  loaded_ = true;
}

void NonceLog::PersistUnlocked() {
  if (mu_.try_lock()) {  // TSK104_Concurrency_Deadlock_and_Lock_Ordering enforce external locking
    mu_.unlock();
    throw std::logic_error("PersistUnlocked requires caller to hold mu_");
  }
  EnsureFileLock();
  std::vector<uint8_t> file_bytes = SerializeHeader(kLogVersion, kHeaderMagic, key_);
  for (const auto& entry : entries_) {
    AppendEntryBytes(file_bytes, entry.counter, entry.mac);
  }
  WriteSnapshotFile(path_, file_bytes); // TSK021_Nonce_Log_Durability_and_Crash_Safety atomic rewrite when repairing
  loaded_ = true;
}

void NonceLog::AppendEntryToFileUnlocked(
    uint64_t counter,
    std::span<const uint8_t, 32> mac) { // TSK_CRIT_09_Nonce_Log_Write_Amplification_DoS
  EnsureFileLock();
#ifdef _WIN32
  int fd = NativeOpen(path_, _O_WRONLY | _O_APPEND, _S_IREAD | _S_IWRITE);
#else
  int fd = NativeOpen(path_, O_WRONLY | O_APPEND, 0600);
#endif
  if (fd < 0) {
    throw Error{ErrorDomain::IO, errno,
                "Failed to open nonce log for append"};
  }
  std::array<uint8_t, kEntrySize> record{};
  uint64_t counter_be = qv::ToBigEndian(counter);
  std::memcpy(record.data(), &counter_be, sizeof(counter_be));
  std::memcpy(record.data() + sizeof(counter_be), mac.data(), mac.size());
  try {
    WriteAll(fd, std::span<const uint8_t>(record.data(), record.size()));
    SyncFileDescriptor(fd);
  } catch (...) {
    NativeClose(fd);
    throw;
  }
  NativeClose(fd);
}

std::array<uint8_t, 32> NonceLog::Append(uint64_t counter,
                                         std::span<const uint8_t> binding) {
  std::lock_guard<std::mutex> lock(mu_);
  EnsureLoadedUnlocked();
  if (!entries_.empty() && counter <= entries_.back().counter) {
    throw Error{ErrorDomain::Validation, 0, "Counter not strictly increasing"};
  }
  auto mac = ComputeMac(last_mac_, counter, key_, binding);
  AppendEntryToFileUnlocked(counter, std::span<const uint8_t, 32>(mac)); // TSK_CRIT_09_Nonce_Log_Write_Amplification_DoS append-only persistence
  entries_.push_back(LogEntry{counter, mac});
  last_mac_ = mac;
  return mac; // TSK014
}

bool NonceLog::VerifyChain() {
  std::lock_guard<std::mutex> lock(mu_);
  try {
    loaded_ = false;
    ReloadUnlocked();
  } catch (...) {
    return false;
  }
  return true;
}

size_t NonceLog::Repair() { // TSK032_Backup_Recovery_and_Disaster_Recovery
  std::lock_guard<std::mutex> lock(mu_);
  loaded_ = false;
  EnsureFileLock();

  if (!std::filesystem::exists(path_)) {
    entries_.clear();
    last_mac_.fill(0);
    key_.fill(0);
    loaded_ = true;
    return 0;
  }

  std::ifstream in(path_, std::ios::binary);
  if (!in.is_open()) {
    throw Error{ErrorDomain::IO, 0,
                "Failed to open nonce log " + qv::PathToUtf8String(path_)};
  }
  in.seekg(0, std::ios::end);
  auto size = static_cast<std::streamoff>(in.tellg());
  in.seekg(0, std::ios::beg);
  if (size <= 0) {
    entries_.clear();
    last_mac_.fill(0);
    key_.fill(0);
    loaded_ = true;
    return 0;
  }

  if (size < static_cast<std::streamoff>(kHeaderSize)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log truncated"};
  }

  std::vector<uint8_t> data(static_cast<size_t>(size));
  in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
  if (!in) {
    throw Error{ErrorDomain::IO, 0,
                "Failed to read nonce log " + qv::PathToUtf8String(path_)};
  }

  const uint8_t* cursor = data.data();
  if (!std::equal(kHeaderMagic.begin(), kHeaderMagic.end(), cursor)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log header magic mismatch"};
  }
  cursor += kHeaderMagic.size();

  uint32_t version_le = 0;
  std::memcpy(&version_le, cursor, sizeof(version_le));
  cursor += sizeof(version_le);
  uint32_t version = qv::ToLittleEndian(version_le);
  if (version != kLogVersion) {
    throw Error{ErrorDomain::Validation, static_cast<int>(version),
                "Nonce log version unsupported"};
  }

  std::copy(cursor, cursor + kMacSize, key_.begin());
  cursor += kMacSize;

  size_t payload_remaining = data.size() - kHeaderSize;
  size_t entry_slots = payload_remaining / kEntrySize;
  size_t trailing_bytes = payload_remaining % kEntrySize;

  std::vector<LogEntry> valid_entries;
  valid_entries.reserve(entry_slots);
  std::array<uint8_t, kMacSize> prev{};

  bool chain_broken = false;
  for (size_t i = 0; i < entry_slots; ++i) {
    const uint8_t* entry_ptr = cursor + (i * kEntrySize);
    uint64_t counter_be = 0;
    std::memcpy(&counter_be, entry_ptr, sizeof(counter_be));
    uint64_t counter = qv::ToBigEndian(counter_be);
    std::array<uint8_t, kMacSize> mac{};
    std::copy(entry_ptr + sizeof(counter_be),
              entry_ptr + sizeof(counter_be) + kMacSize, mac.begin());
    if (!valid_entries.empty() && counter <= valid_entries.back().counter) {
      chain_broken = true;
      break;
    }
    auto expected = ComputeMac(prev, counter, key_);
    if (!std::equal(expected.begin(), expected.end(), mac.begin())) {
      chain_broken = true;
      break;
    }
    valid_entries.push_back(LogEntry{counter, mac});
    prev = mac;
  }

  entries_ = std::move(valid_entries);
  last_mac_ = entries_.empty() ? std::array<uint8_t, kMacSize>{} : entries_.back().mac;

  size_t truncated = 0;
  if (entry_slots > entries_.size()) {
    truncated = entry_slots - entries_.size();
  }
  if (trailing_bytes != 0) {
    truncated = std::max<size_t>(truncated, 1);
  }
  if (chain_broken) {
    truncated = std::max<size_t>(truncated, 1);
  }

  if (truncated > 0) {
    PersistUnlocked();
  } else {
    loaded_ = true;
  }
  return truncated;
}

uint64_t NonceLog::GetLastCounter() const {
  std::lock_guard<std::mutex> lock(mu_);
  const_cast<NonceLog*>(this)->EnsureLoadedUnlocked();
  if (entries_.empty()) {
    return 0;
  }
  return entries_.back().counter;
}

size_t NonceLog::EntryCount() const {
  std::lock_guard<std::mutex> lock(mu_);
  const_cast<NonceLog*>(this)->EnsureLoadedUnlocked();
  return entries_.size();
}

std::array<uint8_t, 32> NonceLog::LastMac() const { // TSK014
  std::lock_guard<std::mutex> lock(mu_);
  const_cast<NonceLog*>(this)->EnsureLoadedUnlocked();
  return last_mac_;
}
