#include "qv/core/nonce.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/error.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex> // TSK023_Production_Crypto_Provider_Complete_Integration sodium init guard
#include <system_error>
#include <vector>

// TSK021_Nonce_Log_Durability_and_Crash_Safety introduce explicit fsync helpers and
// platform-specific primitives.
#ifndef _WIN32
#include <fcntl.h>
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

  void WriteAll(int fd, std::span<const uint8_t> bytes) { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    size_t offset = 0;
    while (offset < bytes.size()) {
      ssize_t written = NativeWrite(fd, bytes.data() + offset, bytes.size() - offset);
      if (written < 0) {
        throw Error{ErrorDomain::IO, errno, "Failed to write nonce log snapshot"};
      }
      offset += static_cast<size_t>(written);
    }
  }

  void SyncFileDescriptor(int fd) { // TSK021_Nonce_Log_Durability_and_Crash_Safety
    if (NativeFsync(fd) != 0) {
      throw Error{ErrorDomain::IO, errno, "Failed to fsync nonce log"};
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
    (void)dir;
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
      std::filesystem::remove(path, remove_ec);
      if (remove_ec) {
        throw Error{ErrorDomain::IO, remove_ec.value(),
                    "Failed to replace nonce log " + qv::PathToUtf8String(path)};
      }
      std::filesystem::rename(temp_path, path);
    }
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
      if (offset + header_consumed + payload_size > wal_bytes.size()) {
        throw Error{ErrorDomain::Validation, 0, "Nonce WAL truncated"};
      }
      std::span<const uint8_t> payload{wal_bytes.data() + offset + header_consumed,
                                       static_cast<size_t>(payload_size)};
      if (ComputeFNV1a(payload) != checksum) {
        throw Error{ErrorDomain::Validation, 0, "Nonce WAL checksum mismatch"};
      }
      offset += header_consumed + static_cast<size_t>(payload_size);
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

  std::array<uint8_t, kMacSize> ComputeMac(std::span<const uint8_t, kMacSize> prev_mac,
                                           uint64_t counter,
                                           std::span<const uint8_t, kMacSize> key) {
    struct MACInput {
      std::array<uint8_t, kMacSize> previous;
      uint64_t counter_be;
    };
    MACInput input{};
    std::copy(prev_mac.begin(), prev_mac.end(), input.previous.begin());
    input.counter_be = qv::ToBigEndian(counter);
    return HMAC_SHA256::Compute(key, qv::AsBytes(input));
  }

#if QV_HAVE_SODIUM
void GenerateKey(std::array<uint8_t, kMacSize>& key) {
  static std::once_flag sodium_once;                                      // TSK023_Production_Crypto_Provider_Complete_Integration init guard
  std::call_once(sodium_once, []() {
    if (sodium_init() < 0) {
      throw Error{ErrorDomain::Security, 0, "sodium_init failed"};       // TSK023_Production_Crypto_Provider_Complete_Integration propagate failure
    }
  });
  randombytes_buf(key.data(), key.size());                                // TSK023_Production_Crypto_Provider_Complete_Integration libsodium RNG
}
#elif defined(_WIN32)
void GenerateKey(std::array<uint8_t, kMacSize>& key) {
  const NTSTATUS status = BCryptGenRandom(nullptr,
                                          key.data(),
                                          static_cast<ULONG>(key.size()),
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (!BCRYPT_SUCCESS(status)) {
    throw Error{ErrorDomain::Security, static_cast<int>(status),
                "BCryptGenRandom failed"};  // TSK016_Windows_Compatibility_Fixes
#ifdef _WIN32
  void GenerateKey(std::array<uint8_t, kMacSize>& key) {
    const NTSTATUS status = BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
      throw Error{ErrorDomain::Security, static_cast<int>(status),
                  "BCryptGenRandom failed"}; // TSK016_Windows_Compatibility_Fixes
    }
  }
#else
void GenerateKey(std::array<uint8_t, kMacSize>& key) {
  if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
    auto err = static_cast<int>(ERR_get_error());
    throw Error{ErrorDomain::Security, err, "RAND_bytes failed"};        // TSK023_Production_Crypto_Provider_Complete_Integration OpenSSL RNG
  void GenerateKey(std::array<uint8_t, kMacSize>& key) {
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
      auto err = static_cast<int>(ERR_get_error());
      throw Error{ErrorDomain::Security, err, "RAND_bytes failed"};
    }
  }
#endif

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

NonceLog::NonceLog(const std::filesystem::path& path) : path_(path) {
  std::lock_guard<std::mutex> lock(mu_);
  RecoverWalUnlocked(); // TSK021_Nonce_Log_Durability_and_Crash_Safety
  if (std::filesystem::exists(path_)) {
    ReloadUnlocked();
  } else {
    InitializeNewLog();
  }
}

void NonceLog::InitializeNewLog() {
  if (!path_.parent_path().empty()) {
    std::filesystem::create_directories(path_.parent_path());
  }
  GenerateKey(key_);
  last_mac_.fill(0);
  entries_.clear();
  PersistUnlocked();
}

void NonceLog::EnsureLoadedUnlocked() {
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

  const size_t trailer_size = kTrailerMagic.size() + 8;
  if (committed_size < trailer_size + kHeaderMagic.size() + 4 + kMacSize) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log too small"};
  }

  const size_t payload_size = committed_size - trailer_size;
  const uint8_t* payload = data.data();
  const uint8_t* trailer_ptr = data.data() + payload_size;

  if (!std::equal(kTrailerMagic.begin(), kTrailerMagic.end(), trailer_ptr)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log trailer missing"};
  }
  trailer_ptr += kTrailerMagic.size();

  uint32_t stored_checksum_le;
  std::memcpy(&stored_checksum_le, trailer_ptr, sizeof(stored_checksum_le));
  trailer_ptr += sizeof(stored_checksum_le);
  uint32_t stored_checksum = qv::ToLittleEndian(stored_checksum_le);

  uint32_t stored_count_le;
  std::memcpy(&stored_count_le, trailer_ptr, sizeof(stored_count_le));
  uint32_t stored_count = qv::ToLittleEndian(stored_count_le);

  if (!std::equal(kHeaderMagic.begin(), kHeaderMagic.end(), payload)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log header magic mismatch"};
  }
  payload += kHeaderMagic.size();

  uint32_t version_le;
  std::memcpy(&version_le, payload, sizeof(version_le));
  payload += sizeof(version_le);
  uint32_t version = qv::ToLittleEndian(version_le);
  if (version != kLogVersion) {
    throw Error{ErrorDomain::Validation, static_cast<int>(version),
                "Nonce log version unsupported"};
  }

  std::copy(payload, payload + kMacSize, key_.begin());
  payload += kMacSize;

  const size_t entries_bytes = payload_size - (kHeaderMagic.size() + 4 + kMacSize);
  if (entries_bytes % kEntrySize != 0) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log entry misalignment"};
  }

  const uint32_t computed_count = static_cast<uint32_t>(entries_bytes / kEntrySize);
  if (stored_count != computed_count) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log entry count mismatch"};
  }

  uint32_t computed_checksum =
      ComputeFNV1a(std::span<const uint8_t>(data.data(), payload_size));
  if (stored_checksum != computed_checksum) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log checksum mismatch"};
  }

  entries_.clear();
  entries_.reserve(computed_count);
  std::array<uint8_t, kMacSize> prev{};

  for (uint32_t i = 0; i < computed_count; ++i) {
    uint64_t counter_be;
    std::memcpy(&counter_be, payload, sizeof(counter_be));
    payload += sizeof(counter_be);
    uint64_t counter = qv::ToBigEndian(counter_be);

    std::array<uint8_t, kMacSize> mac{};
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
  loaded_ = true;
}

void NonceLog::PersistUnlocked() {
  std::vector<uint8_t> buffer = SerializeHeader(kLogVersion, kHeaderMagic, key_);
  for (const auto& entry : entries_) {
    AppendEntryBytes(buffer, entry.counter, entry.mac);
  }

  uint32_t checksum = ComputeFNV1a(buffer);
  std::vector<uint8_t> file_bytes = buffer;
  AppendTrailer(file_bytes, checksum, static_cast<uint32_t>(entries_.size()));
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

std::array<uint8_t, 32> NonceLog::Append(uint64_t counter) {
  std::lock_guard<std::mutex> lock(mu_);
  EnsureLoadedUnlocked();
  if (!entries_.empty() && counter <= entries_.back().counter) {
    throw Error{ErrorDomain::Validation, 0, "Counter not strictly increasing"};
  }
  auto mac = ComputeMac(last_mac_, counter, key_);
  entries_.push_back(LogEntry{counter, mac});
  last_mac_ = mac;
  PersistUnlocked();
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
