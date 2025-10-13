#include "qv/core/nonce.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/error.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <vector>

#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#else
#include <windows.h>
#include <bcrypt.h>
#endif

using namespace qv;
using namespace qv::core;
using qv::crypto::HMAC_SHA256;

namespace {
constexpr std::array<char, 8> kHeaderMagic{'Q','V','N','O','N','C','E','1'};
constexpr std::array<char, 8> kTrailerMagic{'Q','V','N','T','R','L','R','1'};
constexpr uint32_t kLogVersion = 1;
constexpr size_t kMacSize = 32;
constexpr size_t kEntrySize = sizeof(uint64_t) + kMacSize;

uint32_t ComputeFNV1a(std::span<const uint8_t> data) {
  uint32_t hash = 2166136261u;
  for (auto byte : data) {
    hash ^= byte;
    hash *= 16777619u;
  }
  return hash;
}

std::array<uint8_t, kMacSize> ComputeMac(
    std::span<const uint8_t, kMacSize> prev_mac,
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

#ifdef _WIN32
std::wstring ToWide(const std::filesystem::path& path) {
  return path.wstring();
}

void FlushHandle(HANDLE handle, const std::filesystem::path& path) {
  if (!FlushFileBuffers(handle)) {
    auto err = static_cast<int>(GetLastError());
    CloseHandle(handle);
    throw Error{ErrorDomain::IO, err, "FlushFileBuffers failed for " + path.string()};
  }
  CloseHandle(handle);
}

void FlushFile(const std::filesystem::path& path) {
  auto wide = ToWide(path);
  HANDLE handle = CreateFileW(wide.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    auto err = static_cast<int>(GetLastError());
    throw Error{ErrorDomain::IO, err, "CreateFileW failed for " + path.string()};
  }
  FlushHandle(handle, path);
}

void FlushDirectory(const std::filesystem::path& path) {
  auto wide = ToWide(path);
  HANDLE handle = CreateFileW(wide.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    auto err = static_cast<int>(GetLastError());
    throw Error{ErrorDomain::IO, err, "CreateFileW (dir) failed for " + path.string()};
  }
  FlushHandle(handle, path);
}

void GenerateKey(std::array<uint8_t, kMacSize>& key) {
  if (BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
    throw Error{ErrorDomain::Security, static_cast<int>(GetLastError()),
                "BCryptGenRandom failed"};
  }
}
#else
void FlushFd(int fd, const std::filesystem::path& path) {
  if (::fsync(fd) != 0) {
    auto err = errno;
    ::close(fd);
    throw Error{ErrorDomain::IO, err, "fsync failed for " + path.string()};
  }
  ::close(fd);
}

void FlushFile(const std::filesystem::path& path) {
  int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    throw Error{ErrorDomain::IO, errno, "open failed for " + path.string()};
  }
  FlushFd(fd, path);
}

void FlushDirectory(const std::filesystem::path& path) {
  int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY);
  if (fd < 0) {
    throw Error{ErrorDomain::IO, errno, "open dir failed for " + path.string()};
  }
  FlushFd(fd, path);
}

void GenerateKey(std::array<uint8_t, kMacSize>& key) {
  if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
    auto err = static_cast<int>(ERR_get_error());
    throw Error{ErrorDomain::Security, err, "RAND_bytes failed"};
  }
}
#endif

std::vector<uint8_t> SerializeHeader(
    uint32_t version,
    std::span<const char, 8> magic,
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

void AppendEntryBytes(std::vector<uint8_t>& out,
                      uint64_t counter,
                      const std::array<uint8_t, kMacSize>& mac) {
  uint64_t counter_be = qv::ToBigEndian(counter);
  uint8_t counter_bytes[sizeof(counter_be)];
  std::memcpy(counter_bytes, &counter_be, sizeof(counter_be));
  out.insert(out.end(), counter_bytes, counter_bytes + sizeof(counter_bytes));
  out.insert(out.end(), mac.begin(), mac.end());
}

void AppendTrailer(std::vector<uint8_t>& out,
                   uint32_t checksum,
                   uint32_t entry_count) {
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

}  // namespace

NonceLog::NonceLog(const std::filesystem::path& path) : path_(path) {
  std::lock_guard<std::mutex> lock(mu_);
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
    throw Error{ErrorDomain::IO, 0, "Nonce log missing at " + path_.string()};
  }
  ReloadUnlocked();
}

void NonceLog::ReloadUnlocked() {
  std::ifstream in(path_, std::ios::binary);
  if (!in.is_open()) {
    throw Error{ErrorDomain::IO, 0, "Failed to open nonce log " + path_.string()};
  }
  in.seekg(0, std::ios::end);
  auto size = static_cast<std::streamoff>(in.tellg());
  in.seekg(0, std::ios::beg);
  if (size < static_cast<std::streamoff>(kHeaderMagic.size() + 4 + kMacSize + kTrailerMagic.size() + 8)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log truncated"};
  }
  std::vector<uint8_t> data(static_cast<size_t>(size));
  in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
  if (!in) {
    throw Error{ErrorDomain::IO, 0, "Failed to read nonce log " + path_.string()};
  }

  const size_t trailer_size = kTrailerMagic.size() + 8;
  if (data.size() < trailer_size + kHeaderMagic.size() + 4 + kMacSize) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log too small"};
  }

  const size_t payload_size = data.size() - trailer_size;
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
    throw Error{ErrorDomain::Validation, static_cast<int>(version), "Nonce log version unsupported"};
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

  uint32_t computed_checksum = ComputeFNV1a(
      std::span<const uint8_t>(data.data(), payload_size));
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

  auto temp_path = path_;
  temp_path += ".tmp";

  {
    std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
      throw Error{ErrorDomain::IO, 0, "Failed to open temp nonce log " + temp_path.string()};
    }
    out.write(reinterpret_cast<const char*>(file_bytes.data()),
              static_cast<std::streamsize>(file_bytes.size()));
    if (!out) {
      throw Error{ErrorDomain::IO, 0, "Failed to write temp nonce log " + temp_path.string()};
    }
    out.flush();
    if (!out) {
      throw Error{ErrorDomain::IO, 0, "Failed to flush temp nonce log " + temp_path.string()};
    }
  }

  FlushFile(temp_path);
  std::error_code rename_ec;
  std::filesystem::rename(temp_path, path_, rename_ec);
  if (rename_ec) {
    std::error_code remove_ec;
    std::filesystem::remove(path_, remove_ec);
    if (remove_ec) {
      throw Error{ErrorDomain::IO, remove_ec.value(),
                  "Failed to replace nonce log " + path_.string()};
    }
    std::filesystem::rename(temp_path, path_);
  }
  FlushFile(path_);
  if (!path_.parent_path().empty()) {
    FlushDirectory(path_.parent_path());
  }
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
