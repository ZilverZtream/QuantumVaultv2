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
#include <memory>       // TSK133_Race_in_Nonce_Log_Recovery WAL guard lifetime
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
  constexpr std::array<char, 8> kTrailerMagic{'Q', 'V', 'N', 'T', 'R', 'L', 'R', '1'};
  constexpr std::array<char, 8> kCommitMagic{'Q', 'V', 'C', 'O', 'M', 'M', 'I'}; // TSK021_Nonce_Log_Durability_and_Crash_Safety
  constexpr std::array<char, 8> kWalMagic{'Q', 'V', 'W', 'A', 'L', '0', '1', 'A'}; // TSK021_Nonce_Log_Durability_and_Crash_Safety
  constexpr uint32_t kLogVersion = 1;
  constexpr uint32_t kWalVersion = 1; // TSK021_Nonce_Log_Durability_and_Crash_Safety
  constexpr size_t kMacSize = 32;
  constexpr size_t kEntrySize = sizeof(uint64_t) + kMacSize;
  constexpr size_t kWalHeaderSize = kWalMagic.size() + sizeof(uint32_t) + sizeof(uint32_t) +
                                    sizeof(uint64_t) + sizeof(uint32_t); // TSK021_Nonce_Log_Durability_and_Crash_Safety

  enum class WalRecordType : uint32_t { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    kBegin = 1,
    kCommit = 2,
  };

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

  uint32_t ComputeFNV1a(std::span<const uint8_t> data); // TSK021_Nonce_Log_Durability_and_Crash_Safety forward decl

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

  std::filesystem::path WalPathFor(const std::filesystem::path& path) { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    auto wal = path;
    wal += ".wal";
    return wal;
  }

  std::filesystem::path WalLockPathFor(const std::filesystem::path& path) { // TSK133_Race_in_Nonce_Log_Recovery lock file suffix
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
                    "Failed to lock nonce WAL " + qv::PathToUtf8String(path)};
      }
#else
      fd_ = ::open(path.c_str(), O_RDWR | O_CREAT, 0600);
      if (fd_ < 0) {
        throw Error{ErrorDomain::IO, errno,
                    "Failed to open nonce WAL lock " + qv::PathToUtf8String(path)};
      }
      if (::flock(fd_, LOCK_EX) != 0) {
        int err = errno;
        ::close(fd_);
        fd_ = -1;
        throw Error{ErrorDomain::IO, err,
                    "Failed to acquire nonce WAL lock " + qv::PathToUtf8String(path)};
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

  void WriteWalRecord(const std::filesystem::path& wal_path, WalRecordType type,
                      std::span<const uint8_t> payload) { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    int flags = 0;
#ifdef _WIN32
    flags = _O_WRONLY | _O_CREAT | _O_APPEND;
    int fd = NativeOpen(wal_path, flags, _S_IREAD | _S_IWRITE);
#else
    flags = O_WRONLY | O_CREAT | O_APPEND;
    int fd = NativeOpen(wal_path, flags, 0600);
#endif
    if (fd < 0) {
      throw Error{ErrorDomain::IO, errno, "Failed to open nonce WAL"};
    }

    std::vector<uint8_t> record;
    record.insert(record.end(), kWalMagic.begin(), kWalMagic.end());
    uint32_t version_le = qv::ToLittleEndian(kWalVersion);
    record.insert(record.end(), reinterpret_cast<uint8_t*>(&version_le),
                  reinterpret_cast<uint8_t*>(&version_le) + sizeof(version_le));
    uint32_t type_le = qv::ToLittleEndian(static_cast<uint32_t>(type));
    record.insert(record.end(), reinterpret_cast<uint8_t*>(&type_le),
                  reinterpret_cast<uint8_t*>(&type_le) + sizeof(type_le));
    uint64_t size_le = qv::ToLittleEndian(static_cast<uint64_t>(payload.size()));
    record.insert(record.end(), reinterpret_cast<uint8_t*>(&size_le),
                  reinterpret_cast<uint8_t*>(&size_le) + sizeof(size_le));
    uint32_t checksum = ComputeFNV1a(payload);
    uint32_t checksum_le = qv::ToLittleEndian(checksum);
    record.insert(record.end(), reinterpret_cast<uint8_t*>(&checksum_le),
                  reinterpret_cast<uint8_t*>(&checksum_le) + sizeof(checksum_le));
    record.insert(record.end(), payload.begin(), payload.end());

    try {
      WriteAll(fd, record);
      SyncFileDescriptor(fd);
    } catch (...) {
      NativeClose(fd);
      throw;
    }
    NativeClose(fd);
  }

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

  struct WalReplayState { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    bool has_pending{false};
    std::vector<uint8_t> pending;
  };

  WalReplayState ParseWal(const std::vector<uint8_t>& wal_bytes) { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    WalReplayState state;
    size_t offset = 0;
    while (offset + kWalHeaderSize <= wal_bytes.size()) {
      if (offset > wal_bytes.size()) { // TSK095_Memory_Safety_and_Buffer_Bounds
        throw Error{ErrorDomain::Validation, 0, "Nonce WAL offset exceeds buffer"};
      }
      if (kWalHeaderSize > wal_bytes.size() - offset) { // TSK095_Memory_Safety_and_Buffer_Bounds
        throw Error{ErrorDomain::Validation, 0, "Nonce WAL truncated"};
      }
      const uint8_t* base = wal_bytes.data() + offset;
      if (!std::equal(kWalMagic.begin(), kWalMagic.end(), base)) {
        throw Error{ErrorDomain::Validation, 0, "Nonce WAL magic mismatch"};
      }
      base += kWalMagic.size();
      uint32_t version_le;
      std::memcpy(&version_le, base, sizeof(version_le));
      base += sizeof(version_le);
      uint32_t version = qv::ToLittleEndian(version_le);
      if (version != kWalVersion) {
        throw Error{ErrorDomain::Validation, static_cast<int>(version), "Nonce WAL version"};
      }
      uint32_t type_le;
      std::memcpy(&type_le, base, sizeof(type_le));
      base += sizeof(type_le);
      auto type = static_cast<WalRecordType>(qv::ToLittleEndian(type_le));
      uint64_t size_le;
      std::memcpy(&size_le, base, sizeof(size_le));
      base += sizeof(size_le);
      uint64_t payload_size = qv::ToLittleEndian(size_le);
      uint32_t checksum_le;
      std::memcpy(&checksum_le, base, sizeof(checksum_le));
      base += sizeof(checksum_le);
      uint32_t checksum = qv::ToLittleEndian(checksum_le);
      size_t header_consumed = kWalHeaderSize;
      if (payload_size > std::numeric_limits<size_t>::max()) { // TSK095_Memory_Safety_and_Buffer_Bounds
        throw Error{ErrorDomain::Validation, 0, "Nonce WAL payload too large"};
      }
      size_t payload_length = static_cast<size_t>(payload_size);
      if (header_consumed > wal_bytes.size() - offset ||
          payload_length > wal_bytes.size() - offset - header_consumed) { // TSK095_Memory_Safety_and_Buffer_Bounds
        throw Error{ErrorDomain::Validation, 0, "Nonce WAL truncated"};
      }
      const size_t payload_offset = offset + header_consumed;
      std::span<const uint8_t> payload{wal_bytes.data() + payload_offset, payload_length};
      if (ComputeFNV1a(payload) != checksum) {
        throw Error{ErrorDomain::Validation, 0, "Nonce WAL checksum mismatch"};
      }
      size_t record_advance = header_consumed + payload_length;               // TSK095_Memory_Safety_and_Buffer_Bounds
      // overflow guard TSK095_Memory_Safety_and_Buffer_Bounds
      if (record_advance < header_consumed ||
          offset > std::numeric_limits<size_t>::max() - record_advance) {
        throw Error{ErrorDomain::Validation, 0, "Nonce WAL offset overflow"};
      }
      offset += record_advance;
      if (type == WalRecordType::kBegin) {
        state.has_pending = true;
        state.pending.assign(payload.begin(), payload.end());
      } else if (type == WalRecordType::kCommit) {
        state.has_pending = false;
        state.pending.clear();
      } else {
        throw Error{ErrorDomain::Validation, 0, "Nonce WAL record type"};
      }
    }
    if (offset != wal_bytes.size()) {
      throw Error{ErrorDomain::Validation, 0, "Nonce WAL trailing bytes"};
    }
    return state;
  }

  void EnsureIntegrityMarker(const std::vector<uint8_t>& bytes) { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    if (bytes.size() < kCommitMagic.size()) {
      throw Error{ErrorDomain::Validation, 0, "Nonce log missing integrity marker"};
    }
    auto marker_begin = bytes.end() - static_cast<std::ptrdiff_t>(kCommitMagic.size());
    if (!std::equal(kCommitMagic.begin(), kCommitMagic.end(), marker_begin)) {
      throw Error{ErrorDomain::Validation, 0, "Nonce log integrity marker mismatch"};
    }
  }

  uint32_t ComputeFNV1a(std::span<const uint8_t> data) {
    uint32_t hash = 2166136261u;
    for (auto byte : data) {
      hash ^= byte;
      hash *= 16777619u;
    }
    return hash;
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

  void AppendTrailer(std::vector<uint8_t>& out, uint32_t checksum, uint32_t entry_count) {
    out.insert(out.end(), kTrailerMagic.begin(), kTrailerMagic.end());
    uint32_t checksum_le = qv::ToLittleEndian(checksum);
    uint8_t checksum_bytes[4];
    std::memcpy(checksum_bytes, &checksum_le, sizeof(checksum_le));
    out.insert(out.end(), checksum_bytes, checksum_bytes + sizeof(checksum_bytes));
    uint32_t count_le = qv::ToLittleEndian(entry_count);
    uint8_t count_bytes[4];
    std::memcpy(count_bytes, &count_le, sizeof(count_le));
    out.insert(out.end(), count_bytes, count_bytes + sizeof(count_bytes));
  }

} // namespace

void NonceLog::EnsureWalLock() {                                        // TSK133_Race_in_Nonce_Log_Recovery lazy guard setup
  if (wal_lock_) {
    return;
  }
  if (path_.empty()) {
    throw std::logic_error("NonceLog path must be set before locking");
  }
  auto lock_path = WalLockPathFor(path_);
  wal_lock_ = std::make_unique<FileLock>(lock_path);
}

NonceLog::NonceLog(const std::filesystem::path& path) : path_(path) {
  if (!path_.parent_path().empty()) {
    std::filesystem::create_directories(path_.parent_path());
  }
  EnsureWalLock();
  std::lock_guard<std::mutex> lock(mu_);
  RecoverWalUnlocked(); // TSK021_Nonce_Log_Durability_and_Crash_Safety
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
  EnsureWalLock();
  GenerateKey(key_);
  last_mac_.fill(0);
  entries_.clear();
  PersistUnlocked();
}

void NonceLog::EnsureLoadedUnlocked() {
  EnsureWalLock();
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

void NonceLog::RecoverWalUnlocked() { // TSK021_Nonce_Log_Durability_and_Crash_Safety
  EnsureWalLock();
  auto wal_path = WalPathFor(path_);
  if (!std::filesystem::exists(wal_path)) {
    return;
  }
  std::ifstream wal(wal_path, std::ios::binary);
  if (!wal.is_open()) {
    throw Error{ErrorDomain::IO, 0,
                "Failed to open nonce WAL " + qv::PathToUtf8String(wal_path)};
  }
  wal.seekg(0, std::ios::end);
  auto size = static_cast<std::streamoff>(wal.tellg());
  wal.seekg(0, std::ios::beg);
  if (size < 0) {
    throw Error{ErrorDomain::IO, 0, "Failed to determine nonce WAL size"};
  }
  if (size == 0) {
    return;
  }
  std::vector<uint8_t> wal_bytes(static_cast<size_t>(size));
  wal.read(reinterpret_cast<char*>(wal_bytes.data()), static_cast<std::streamsize>(wal_bytes.size()));
  if (!wal) {
    throw Error{ErrorDomain::IO, 0,
                "Failed to read nonce WAL " + qv::PathToUtf8String(wal_path)};
  }
  auto state = ParseWal(wal_bytes);
  if (!state.has_pending) {
    return;
  }
  EnsureIntegrityMarker(state.pending);
  WriteSnapshotFile(path_, state.pending);
  WriteWalRecord(wal_path, WalRecordType::kCommit, {});
}

void NonceLog::ReloadUnlocked() {
  EnsureWalLock();
  std::ifstream in(path_, std::ios::binary);
  if (!in.is_open()) {
    throw Error{ErrorDomain::IO, 0,
                "Failed to open nonce log " +
                    qv::PathToUtf8String(path_)}; // TSK016_Windows_Compatibility_Fixes
  }
  in.seekg(0, std::ios::end);
  auto size = static_cast<std::streamoff>(in.tellg());
  in.seekg(0, std::ios::beg);
  if (size < static_cast<std::streamoff>(kHeaderMagic.size() + 4 + kMacSize +
                                         kTrailerMagic.size() + 8 + kCommitMagic.size())) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log truncated"};
  }
  std::vector<uint8_t> data(static_cast<size_t>(size));
  in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
  if (!in) {
    throw Error{ErrorDomain::IO, 0,
                "Failed to read nonce log " +
                    qv::PathToUtf8String(path_)}; // TSK016_Windows_Compatibility_Fixes
  }

  EnsureIntegrityMarker(data); // TSK021_Nonce_Log_Durability_and_Crash_Safety

  const size_t committed_size = data.size() - kCommitMagic.size();

  const size_t trailer_size = CheckedAdd(kTrailerMagic.size(), size_t{8},
                                         "Nonce log trailer size overflow"); // TSK100_Integer_Overflow_and_Arithmetic trailer guard
  size_t minimum_payload = CheckedAdd(trailer_size, kHeaderMagic.size(),
                                      "Nonce log minimum payload overflow (header)"); // TSK100_Integer_Overflow_and_Arithmetic
  minimum_payload = CheckedAdd(minimum_payload, sizeof(uint32_t),
                               "Nonce log minimum payload overflow (version)");     // TSK100_Integer_Overflow_and_Arithmetic
  minimum_payload = CheckedAdd(minimum_payload, kMacSize,
                               "Nonce log minimum payload overflow (mac)");         // TSK100_Integer_Overflow_and_Arithmetic
  if (committed_size < minimum_payload) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log too small"};
  }

  const size_t payload_size = committed_size - trailer_size;
  if (payload_size > data.size()) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log payload overflow"}; // TSK100_Integer_Overflow_and_Arithmetic pointer guard
  }
  const uint8_t* payload = data.data();
  const uint8_t* payload_end = data.data() + payload_size;                    // TSK030
  const uint8_t* trailer_ptr = data.data() + payload_size;
  const uint8_t* committed_end = data.data() + committed_size;                // TSK030

  auto ensure_range = [](const uint8_t* cursor, const uint8_t* limit,
                         size_t needed) -> bool { // TSK095_Memory_Safety_and_Buffer_Bounds
    if (cursor > limit) {
      return false;
    }
    size_t remaining = static_cast<size_t>(limit - cursor);
    return needed <= remaining;
  };

  auto ensure_payload = [&](size_t needed) {                                  // TSK030
    if (!ensure_range(payload, payload_end, needed)) {                        // TSK095_Memory_Safety_and_Buffer_Bounds
      throw Error{ErrorDomain::Validation, 0, "Nonce log truncated"};        // TSK030
    }
  };

  auto ensure_trailer = [&](size_t needed) {                                  // TSK030
    if (!ensure_range(trailer_ptr, committed_end, needed)) {                  // TSK095_Memory_Safety_and_Buffer_Bounds
      throw Error{ErrorDomain::Validation, 0, "Nonce log truncated"};        // TSK030
    }
  };

  ensure_trailer(kTrailerMagic.size());                                       // TSK030
  if (!std::equal(kTrailerMagic.begin(), kTrailerMagic.end(), trailer_ptr)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log trailer missing"};
  }
  trailer_ptr += kTrailerMagic.size();

  uint32_t stored_checksum_le;
  ensure_trailer(sizeof(stored_checksum_le));                                 // TSK030
  std::memcpy(&stored_checksum_le, trailer_ptr, sizeof(stored_checksum_le));
  trailer_ptr += sizeof(stored_checksum_le);
  uint32_t stored_checksum = qv::ToLittleEndian(stored_checksum_le);

  uint32_t stored_count_le;
  ensure_trailer(sizeof(stored_count_le));                                    // TSK030
  std::memcpy(&stored_count_le, trailer_ptr, sizeof(stored_count_le));
  uint32_t stored_count = qv::ToLittleEndian(stored_count_le);

  ensure_payload(kHeaderMagic.size());                                        // TSK030
  if (!std::equal(kHeaderMagic.begin(), kHeaderMagic.end(), payload)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log header magic mismatch"};
  }
  payload += kHeaderMagic.size();

  uint32_t version_le;
  ensure_payload(sizeof(version_le));                                         // TSK030
  std::memcpy(&version_le, payload, sizeof(version_le));
  payload += sizeof(version_le);
  uint32_t version = qv::ToLittleEndian(version_le);
  if (version != kLogVersion) {
    throw Error{ErrorDomain::Validation, static_cast<int>(version),
                "Nonce log version unsupported"};
  }

  ensure_payload(kMacSize);                                                   // TSK030
  std::copy(payload, payload + kMacSize, key_.begin());
  payload += kMacSize;

  if (payload > payload_end) {                                                // TSK095_Memory_Safety_and_Buffer_Bounds
    throw Error{ErrorDomain::Validation, 0, "Nonce log truncated"};
  }
  const size_t entries_bytes = static_cast<size_t>(payload_end - payload);    // TSK030
  const size_t header_overhead = CheckedAdd(CheckedAdd(kHeaderMagic.size(), sizeof(uint32_t),
                                                       "Nonce log header overhead overflow"),
                                            kMacSize,
                                            "Nonce log MAC overhead overflow"); // TSK100_Integer_Overflow_and_Arithmetic header guard
  if (entries_bytes < header_overhead) { // TSK_CRIT_15 prevent underflow
    throw Error{ErrorDomain::Validation, 0, "Nonce log entries truncated"};
  }
  const size_t entry_bytes = entries_bytes - header_overhead; // TSK_CRIT_15 safe after bounds check
  if (entry_bytes % kEntrySize != 0) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log entry misalignment"};
  }

  const size_t computed_count = entry_bytes / kEntrySize;
  if (computed_count > std::numeric_limits<uint32_t>::max()) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log entry count overflow"}; // TSK100_Integer_Overflow_and_Arithmetic count guard
  }
  const uint32_t computed_count32 = static_cast<uint32_t>(computed_count);
  const bool count_mismatch = stored_count != computed_count32;  // TSK108_Data_Structure_Invariants derive from entries size

  uint32_t computed_checksum =
      ComputeFNV1a(std::span<const uint8_t>(data.data(), payload_size));
  if (stored_checksum != computed_checksum) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log checksum mismatch"};
  }

  entries_.clear();
  entries_.reserve(computed_count);
  std::array<uint8_t, kMacSize> prev{};

  for (uint32_t i = 0; i < computed_count32; ++i) {
    uint64_t counter_be;
    ensure_payload(sizeof(counter_be));                                       // TSK030
    std::memcpy(&counter_be, payload, sizeof(counter_be));
    payload += sizeof(counter_be);
    uint64_t counter = qv::ToBigEndian(counter_be);

    std::array<uint8_t, kMacSize> mac{};
    ensure_payload(kMacSize);                                                 // TSK030
    std::copy(payload, payload + kMacSize, mac.begin());
    payload += kMacSize;

    auto expected = ComputeMac(prev, counter, key_);
    if (!std::equal(expected.begin(), expected.end(), mac.begin())) {
      throw Error{ErrorDomain::Validation, 0, "Nonce log MAC chain broken"};
    }

    entries_.push_back(LogEntry{counter, mac});
    prev = mac;
  }

  last_mac_ = entries_.empty() ? std::array<uint8_t, kMacSize>{} : entries_.back().mac;

  if (count_mismatch) {  // TSK108_Data_Structure_Invariants rewrite trailer from canonical size
    PersistUnlocked();
    return;
  }

  loaded_ = true;
}

void NonceLog::PersistUnlocked() {
  if (mu_.try_lock()) {  // TSK104_Concurrency_Deadlock_and_Lock_Ordering enforce external locking
    mu_.unlock();
    throw std::logic_error("PersistUnlocked requires caller to hold mu_");
  }
  EnsureWalLock();
  std::vector<uint8_t> buffer = SerializeHeader(kLogVersion, kHeaderMagic, key_);
  for (const auto& entry : entries_) {
    AppendEntryBytes(buffer, entry.counter, entry.mac);
  }

  uint32_t checksum = ComputeFNV1a(buffer);
  std::vector<uint8_t> file_bytes = buffer;
  const uint32_t entry_count =
      CheckedUnsignedCast<uint32_t>(entries_.size(), "Nonce log entry count overflow"); // TSK100_Integer_Overflow_and_Arithmetic cast guard
  AppendTrailer(file_bytes, checksum, entry_count);
  file_bytes.insert(file_bytes.end(), kCommitMagic.begin(), kCommitMagic.end()); // TSK021_Nonce_Log_Durability_and_Crash_Safety

  auto wal_path = WalPathFor(path_); // TSK021_Nonce_Log_Durability_and_Crash_Safety
  WriteWalRecord(wal_path, WalRecordType::kBegin, file_bytes); // TSK021_Nonce_Log_Durability_and_Crash_Safety
  try {
    WriteSnapshotFile(path_, file_bytes); // TSK021_Nonce_Log_Durability_and_Crash_Safety
  } catch (...) {
    throw;
  }
  WriteWalRecord(wal_path, WalRecordType::kCommit, {}); // TSK021_Nonce_Log_Durability_and_Crash_Safety
  loaded_ = true;
}

std::array<uint8_t, 32> NonceLog::Append(uint64_t counter,
                                         std::span<const uint8_t> binding) {
  std::lock_guard<std::mutex> lock(mu_);
  EnsureLoadedUnlocked();
  if (!entries_.empty() && counter <= entries_.back().counter) {
    throw Error{ErrorDomain::Validation, 0, "Counter not strictly increasing"};
  }
  auto mac = ComputeMac(last_mac_, counter, key_, binding);
  entries_.push_back(LogEntry{counter, mac});
  last_mac_ = mac;
  PersistUnlocked();
  return mac; // TSK014
}

std::array<uint8_t, 32> NonceLog::Preview(uint64_t counter,
                                          std::span<const uint8_t> binding) {
  std::lock_guard<std::mutex> lock(mu_);
  EnsureLoadedUnlocked();
  if (!entries_.empty() && counter <= entries_.back().counter) {
    throw Error{ErrorDomain::Validation, 0, "Counter not strictly increasing"};
  }
  return ComputeMac(last_mac_, counter, key_, binding); // TSK118_Nonce_Reuse_Vulnerabilities
}

void NonceLog::Commit(uint64_t counter, std::span<const uint8_t, 32> mac,
                      std::span<const uint8_t> binding) {
  std::lock_guard<std::mutex> lock(mu_);
  EnsureLoadedUnlocked();
  if (!entries_.empty() && counter <= entries_.back().counter) {
    throw Error{ErrorDomain::Validation, 0, "Counter not strictly increasing"};
  }
  auto expected = ComputeMac(last_mac_, counter, key_, binding);
  if (!std::equal(expected.begin(), expected.end(), mac.begin(), mac.end())) {
    throw Error{ErrorDomain::Validation, 0, "Nonce MAC mismatch"}; // TSK118_Nonce_Reuse_Vulnerabilities
  }
  entries_.push_back(LogEntry{counter, expected});
  last_mac_ = expected;
  PersistUnlocked();
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
  RecoverWalUnlocked();

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

  std::vector<uint8_t> data(static_cast<size_t>(size));
  in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
  if (!in) {
    throw Error{ErrorDomain::IO, 0,
                "Failed to read nonce log " + qv::PathToUtf8String(path_)};
  }

  EnsureIntegrityMarker(data);

  const size_t committed_size = data.size() - kCommitMagic.size();
  const size_t trailer_size = CheckedAdd(kTrailerMagic.size(), size_t{8},
                                         "Nonce log trailer size overflow"); // TSK100_Integer_Overflow_and_Arithmetic trailer guard
  size_t minimum_payload = CheckedAdd(trailer_size, kHeaderMagic.size(),
                                      "Nonce log minimum payload overflow (header)"); // TSK100_Integer_Overflow_and_Arithmetic
  minimum_payload = CheckedAdd(minimum_payload, sizeof(uint32_t),
                               "Nonce log minimum payload overflow (version)");     // TSK100_Integer_Overflow_and_Arithmetic
  minimum_payload = CheckedAdd(minimum_payload, kMacSize,
                               "Nonce log minimum payload overflow (mac)");         // TSK100_Integer_Overflow_and_Arithmetic
  if (committed_size < minimum_payload) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log too small"};
  }

  const size_t payload_size = committed_size - trailer_size;
  if (payload_size > data.size()) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log payload overflow"}; // TSK100_Integer_Overflow_and_Arithmetic pointer guard
  }
  const uint8_t* payload = data.data();
  const uint8_t* payload_end = data.data() + payload_size;
  const uint8_t* trailer_ptr = data.data() + payload_size;

  if (!std::equal(kHeaderMagic.begin(), kHeaderMagic.end(), payload)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log header magic mismatch"};
  }
  payload += kHeaderMagic.size();

  uint32_t version_le = 0;
  std::memcpy(&version_le, payload, sizeof(version_le));
  payload += sizeof(version_le);
  uint32_t version = qv::ToLittleEndian(version_le);
  if (version != kLogVersion) {
    throw Error{ErrorDomain::Validation, static_cast<int>(version),
                "Nonce log version unsupported"};
  }

  if (static_cast<size_t>(payload_end - payload) < kMacSize) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log truncated"};
  }
  std::copy(payload, payload + kMacSize, key_.begin());
  payload += kMacSize;

  if (!std::equal(kTrailerMagic.begin(), kTrailerMagic.end(), trailer_ptr)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log trailer missing"};
  }
  trailer_ptr += kTrailerMagic.size();

  uint32_t stored_checksum_le = 0;
  std::memcpy(&stored_checksum_le, trailer_ptr, sizeof(stored_checksum_le));
  trailer_ptr += sizeof(stored_checksum_le);
  uint32_t stored_checksum = qv::ToLittleEndian(stored_checksum_le);

  uint32_t stored_count_le = 0;
  std::memcpy(&stored_count_le, trailer_ptr, sizeof(stored_count_le));
  uint32_t stored_count = qv::ToLittleEndian(stored_count_le);

  const size_t entries_bytes = static_cast<size_t>(payload_end - payload);
  const size_t header_overhead = CheckedAdd(CheckedAdd(kHeaderMagic.size(), sizeof(uint32_t),
                                                       "Nonce log header overhead overflow"),
                                            kMacSize,
                                            "Nonce log MAC overhead overflow"); // TSK100_Integer_Overflow_and_Arithmetic header guard
  if (entries_bytes < header_overhead) { // TSK_CRIT_15 prevent underflow
    throw Error{ErrorDomain::Validation, 0, "Nonce log entries truncated"};
  }
  const size_t entry_bytes = entries_bytes - header_overhead; // TSK_CRIT_15 safe after bounds check
  const size_t entry_slots = entry_bytes / kEntrySize;
  const size_t trailing_bytes = entry_bytes % kEntrySize;

  std::vector<LogEntry> valid_entries;
  valid_entries.reserve(entry_slots);
  std::array<uint8_t, kMacSize> prev{};

  for (size_t i = 0; i < entry_slots; ++i) {
    uint64_t counter_be = 0;
    std::memcpy(&counter_be, payload, sizeof(counter_be));
    payload += sizeof(counter_be);
    uint64_t counter = qv::ToBigEndian(counter_be);

    std::array<uint8_t, kMacSize> mac{};
    std::copy(payload, payload + kMacSize, mac.begin());
    payload += kMacSize;

    if (!valid_entries.empty() && counter <= valid_entries.back().counter) {
      break;
    }

    auto expected = ComputeMac(prev, counter, key_);
    if (!std::equal(expected.begin(), expected.end(), mac.begin())) {
      break;
    }

    valid_entries.push_back(LogEntry{counter, mac});
    prev = mac;
  }

  const uint32_t computed_checksum =
      ComputeFNV1a(std::span<const uint8_t>(data.data(), payload_size));

  entries_ = std::move(valid_entries);
  last_mac_ = entries_.empty() ? std::array<uint8_t, kMacSize>{} : entries_.back().mac;

  size_t truncated = 0;
  if (stored_count > entries_.size()) {
    truncated = stored_count - entries_.size();
  }
  if (entry_slots > entries_.size()) {
    truncated = std::max(truncated, entry_slots - entries_.size());
  }
  if (trailing_bytes != 0) {
    truncated = std::max<size_t>(truncated, 1);
  }

  bool needs_rewrite = truncated > 0 || stored_checksum != computed_checksum;
  if (needs_rewrite) {
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
