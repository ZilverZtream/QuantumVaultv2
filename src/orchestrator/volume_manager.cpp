#include "qv/orchestrator/volume_manager.h"

#include <algorithm> // TSK033 skip/zero TLV payloads
#include <array>
#include <cerrno>
#include <chrono>    // TSK036_PBKDF2_Argon2_Migration_Path adaptive calibration
#include <cmath>     // TSK141_Integer_Overflow_And_Wraparound_Issues safe PBKDF scaling
#include <cstring>
#include <fstream>
#include <functional> // TSK036_PBKDF2_Argon2_Migration_Path progress callbacks
#include <iomanip>    // TSK029
#include <iterator>   // TSK024_Key_Rotation_and_Lifecycle_Management
#include <limits>     // TSK024_Key_Rotation_and_Lifecycle_Management
#include <optional>     // TSK036_PBKDF2_Argon2_Migration_Path Argon2 TLV control
#include <span>
#include <sstream>      // TSK033 version formatting
#include <string>       // TSK149_Path_Traversal_And_Injection string assembly for validation
#include <string_view>
#include <system_error> // TSK074_Migration_Rollback_and_Backup non-throwing filesystem ops
#include <type_traits>  // TSK099_Input_Validation_and_Sanitization checked casts
#include <vector>
#include <cstdlib>      // TSK099_Input_Validation_and_Sanitization container root policy
#if defined(_WIN32)
#include <io.h>        // TSK146_Permission_And_Ownership_Issues Windows chmod
#include <sys/stat.h>  // TSK146_Permission_And_Ownership_Issues permission macros
#else
#include <sys/stat.h>   // TSK146_Permission_And_Ownership_Issues ownership checks
#include <unistd.h>     // TSK146_Permission_And_Ownership_Issues geteuid for ownership validation
#endif

#include "qv/common.h"
#include "qv/core/nonce.h"
#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/hkdf.h"   // TSK106_Cryptographic_Implementation_Weaknesses
#include "qv/crypto/aegis.h"   // TSK083_AAD_Recompute_and_Binding cipher identifiers
#include "qv/crypto/aes_gcm.h" // TSK024_Key_Rotation_and_Lifecycle_Management
#include "qv/crypto/sha256.h"  // TSK128_Missing_AAD_Validation_in_Chunks payload binding
#include "qv/crypto/random.h"  // TSK106_Cryptographic_Implementation_Weaknesses
#include "qv/crypto/hmac_sha256.h"
#include "qv/crypto/pbkdf2.h"  // TSK111_Code_Duplication_and_Maintainability shared PBKDF2
#include "qv/error.h"
#include "qv/errors.h"  // TSK111_Code_Duplication_and_Maintainability centralized messages
#include "qv/orchestrator/event_bus.h" // TSK024_Key_Rotation_and_Lifecycle_Management
#include "qv/orchestrator/io_util.h"   // TSK068_Atomic_Header_Writes atomic persistence
#include "qv/orchestrator/password_policy.h" // TSK135_Password_Complexity_Enforcement shared policy
#include "qv/orchestrator/header_serializer.h"  // TSK111_Code_Duplication_and_Maintainability
#include "qv/security/secure_buffer.h" // TSK097_Cryptographic_Key_Management secure allocator for secrets
#include "qv/security/zeroizer.h"
#include "qv/tlv/parser.h"  // TSK111_Code_Duplication_and_Maintainability TLV iteration

#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2 // TSK036_PBKDF2_Argon2_Migration_Path
#include <argon2.h>
#endif

#ifndef QV_SENSITIVE_FUNCTION  // TSK028A_Memory_Wiping_Gaps
#if defined(_MSC_VER)
#define QV_SENSITIVE_BEGIN __pragma(optimize("", off))
#define QV_SENSITIVE_END __pragma(optimize("", on))
#define QV_SENSITIVE_FUNCTION __declspec(noinline)
#elif defined(__clang__)
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION [[clang::optnone]] __attribute__((noinline))
#elif defined(__GNUC__)
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION __attribute__((noinline, optimize("O0")))
#else
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION
#endif
#endif  // QV_SENSITIVE_FUNCTION TSK028A_Memory_Wiping_Gaps

using namespace qv::orchestrator;

namespace {

#if !defined(_WIN32)
void RequireOwnedDirectory(const std::filesystem::path& dir) { // TSK146_Permission_And_Ownership_Issues ensure trusted parents
  const auto native = dir.native();
  struct stat info {
  };
  if (::lstat(native.c_str(), &info) != 0) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to inspect directory ownership: " + qv::PathToUtf8String(dir)};
  }
  if (!S_ISDIR(info.st_mode)) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Parent path is not a directory: " + qv::PathToUtf8String(dir)};
  }
  if (info.st_uid != ::geteuid()) {
    throw qv::Error{qv::ErrorDomain::Security, 0,
                    "Parent directory ownership mismatch: " + qv::PathToUtf8String(dir)};
  }
  if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
    throw qv::Error{qv::ErrorDomain::Security, 0,
                    "Parent directory must not be group/world writable: " + qv::PathToUtf8String(dir)};
  }
}
#endif

void EnsureDirectorySecure(const std::filesystem::path& dir) { // TSK146_Permission_And_Ownership_Issues reject unsafe parents
  if (dir.empty()) {
    return;
  }
  std::error_code status_ec;
  auto status = std::filesystem::symlink_status(dir, status_ec);
  if (status_ec) {
    throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(status_ec.value()),
                    "Failed to inspect parent directory: " + qv::PathToUtf8String(dir)};
  }
  if (!std::filesystem::exists(status)) {
    return;
  }
  if (!std::filesystem::is_directory(status)) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Parent path is not a directory: " + qv::PathToUtf8String(dir)};
  }
#if defined(_WIN32)
  if (std::filesystem::is_symlink(status)) {
    throw qv::Error{qv::ErrorDomain::Security, 0,
                    "Refusing to use symlink parent directory: " + qv::PathToUtf8String(dir)};
  }
#else
  RequireOwnedDirectory(dir);
#endif
}

void EnsureSecureParentDirectory(const std::filesystem::path& path) { // TSK146_Permission_And_Ownership_Issues guard ancestry
  if (!path.has_parent_path()) {
    return;
  }
  EnsureDirectorySecure(path.parent_path());
}

void HardenPrivateDirectory(const std::filesystem::path& dir) { // TSK146_Permission_And_Ownership_Issues enforce 0700
  if (dir.empty()) {
    return;
  }
#if defined(_WIN32)
  if (_wchmod(dir.c_str(), _S_IREAD | _S_IWRITE | _S_IEXEC) != 0) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to restrict directory permissions: " + qv::PathToUtf8String(dir)};
  }
#else
  std::error_code perm_ec;
  std::filesystem::permissions(dir,
                               std::filesystem::perms::owner_read |
                                   std::filesystem::perms::owner_write |
                                   std::filesystem::perms::owner_exec,
                               std::filesystem::perm_options::replace, perm_ec);
  if (perm_ec) {
    throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(perm_ec.value()),
                    "Failed to restrict directory permissions: " + qv::PathToUtf8String(dir)};
  }
#endif
}

void HardenPrivateFile(const std::filesystem::path& path) { // TSK146_Permission_And_Ownership_Issues enforce 0600
#if defined(_WIN32)
  if (_wchmod(path.c_str(), _S_IREAD | _S_IWRITE) != 0) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to restrict file permissions: " + qv::PathToUtf8String(path)};
  }
#else
  std::error_code perm_ec;
  std::filesystem::permissions(path,
                               std::filesystem::perms::owner_read |
                                   std::filesystem::perms::owner_write,
                               std::filesystem::perm_options::replace, perm_ec);
  if (perm_ec) {
    throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(perm_ec.value()),
                    "Failed to restrict file permissions: " + qv::PathToUtf8String(path)};
  }
#endif
}

template <typename To, typename From>
To CheckedCast(From value) { // TSK099_Input_Validation_and_Sanitization
  static_assert(std::is_integral_v<From>, "CheckedCast requires integral source type");
  static_assert(std::is_integral_v<To>, "CheckedCast requires integral destination type");

  using ToLimits = std::numeric_limits<To>;
  if constexpr (std::is_unsigned_v<To>) {
    if constexpr (std::is_signed_v<From>) {
      if (value < 0) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Negative value for checked_cast"};
      }
      const auto promoted = static_cast<unsigned long long>(static_cast<std::make_unsigned_t<From>>(value));
      if (promoted > static_cast<unsigned long long>(ToLimits::max())) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Integer overflow during checked_cast"};
      }
    } else {
      if (static_cast<unsigned long long>(value) > static_cast<unsigned long long>(ToLimits::max())) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Integer overflow during checked_cast"};
      }
    }
  } else {
    if constexpr (std::is_signed_v<From>) {
      const auto promoted = static_cast<long long>(value);
      const auto min_value = static_cast<long long>(ToLimits::min());
      const auto max_value = static_cast<long long>(ToLimits::max());
      if (promoted < min_value || promoted > max_value) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Integer overflow during checked_cast"};
      }
    } else {
      if (static_cast<unsigned long long>(value) > static_cast<unsigned long long>(ToLimits::max())) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Integer overflow during checked_cast"};
      }
    }
  }

  return static_cast<To>(value);
}

void ValidatePassword(const std::string& password) { // TSK135_Password_Complexity_Enforcement centralized enforcement
  EnforcePasswordPolicy(password);
}

constexpr std::size_t kPasswordHistoryDepth = 5; // TSK135_Password_Complexity_Enforcement rotation window

std::filesystem::path PasswordHistoryPath(const std::filesystem::path& container) { // TSK135_Password_Complexity_Enforcement
  auto history_path = container;
  history_path += ".history";
  return history_path;
}

std::string BytesToHexLower(std::span<const uint8_t> bytes) { // TSK135_Password_Complexity_Enforcement utility hex encoder
  static constexpr char kHex[] = "0123456789abcdef";
  std::string encoded;
  encoded.reserve(bytes.size() * 2);
  for (auto byte : bytes) {
    encoded.push_back(kHex[byte >> 4]);
    encoded.push_back(kHex[byte & 0x0F]);
  }
  return encoded;
}

std::filesystem::path MakeMigrationTempPath(const std::filesystem::path& container) { // TSK140_Temporary_File_Security_Vulnerabilities unpredictable staging names
  std::array<uint8_t, 16> random_token{};
  qv::crypto::SystemRandomBytes(std::span<uint8_t>(random_token.data(), random_token.size()));
  auto temp = container;
  temp += ".migrate.";
  temp += BytesToHexLower(std::span<const uint8_t>(random_token.data(), random_token.size()));
  temp += ".tmp";
  return temp;
}

std::string HashPasswordForHistory(const std::filesystem::path& container,
                                   const std::string& password) { // TSK135_Password_Complexity_Enforcement
  const auto container_utf8 = qv::PathToUtf8String(container);
  std::vector<uint8_t> material;
  material.reserve(container_utf8.size() + password.size() + 1);
  material.insert(material.end(), container_utf8.begin(), container_utf8.end());
  material.push_back(0x00);
  material.insert(material.end(), password.begin(), password.end());
  auto digest = qv::crypto::SHA256_Hash(std::span<const uint8_t>(material.data(), material.size()));
  return BytesToHexLower(std::span<const uint8_t>(digest.data(), digest.size()));
}

std::vector<std::string> LoadPasswordHistory(const std::filesystem::path& container) { // TSK135_Password_Complexity_Enforcement
  std::vector<std::string> history;
  const auto path = PasswordHistoryPath(container);
  std::error_code exists_ec;
  if (!std::filesystem::exists(path, exists_ec) || exists_ec) {
    return history;
  }

  std::ifstream in(path);
  if (!in) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    std::string(qv::errors::msg::kPasswordHistoryPersistFailed) + ": open"};
  }

  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    std::size_t begin = line.find_first_not_of(" \t");
    if (begin == std::string::npos) {
      continue;
    }
    if (line[begin] == '#') {
      continue;
    }
    std::size_t end = line.find_last_not_of(" \t");
    history.emplace_back(line.substr(begin, end - begin + 1));
  }

  if (in.bad()) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    std::string(qv::errors::msg::kPasswordHistoryPersistFailed) + ": read"};
  }
  return history;
}

void AppendHistoryEntry(std::vector<std::string>& history, const std::string& entry) { // TSK135_Password_Complexity_Enforcement
  auto existing = std::find(history.begin(), history.end(), entry);
  if (existing != history.end()) {
    history.erase(existing);
  }
  history.push_back(entry);
  if (history.size() > kPasswordHistoryDepth) {
    history.erase(history.begin(), history.begin() + (history.size() - kPasswordHistoryDepth));
  }
}

void PersistPasswordHistory(const std::filesystem::path& container,
                            const std::vector<std::string>& history) { // TSK135_Password_Complexity_Enforcement
  std::string serialized = "# TSK135_Password_Complexity_Enforcement\n";
  for (const auto& entry : history) {
    serialized.append(entry);
    serialized.push_back('\n');
  }
  std::vector<uint8_t> payload(serialized.begin(), serialized.end());
  auto history_path = PasswordHistoryPath(container);
  EnsureSecureParentDirectory(history_path); // TSK146_Permission_And_Ownership_Issues validate history location
  try {
    AtomicReplace(history_path, std::span<const uint8_t>(payload.data(), payload.size()));
    HardenPrivateFile(history_path); // TSK146_Permission_And_Ownership_Issues enforce 0600 history
  } catch (const qv::Error& err) {
    throw qv::Error{err.domain(), err.code(),
                    std::string(qv::errors::msg::kPasswordHistoryPersistFailed) + ": " + err.what()};
  }
}

std::string EnsurePasswordNotReused(const std::filesystem::path& container,
                                    const std::vector<std::string>& history,
                                    const std::string& password) { // TSK135_Password_Complexity_Enforcement
  const auto hashed = HashPasswordForHistory(container, password);
  if (std::find(history.begin(), history.end(), hashed) != history.end()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(qv::errors::msg::kPasswordReused)};
  }
  return hashed;
}

enum class Utf8ValidationResult { // TSK149_Path_Traversal_And_Injection
  kOk,
  kInvalidEncoding,
  kDisallowed,
};

bool ContainsForbiddenAsciiChar(char32_t cp) noexcept { // TSK149_Path_Traversal_And_Injection
  switch (cp) {
    case '|':
    case '&':
    case ';':
    case '<':
    case '>':
    case '\'':
    case '"':
    case '`':
    case '$':
    case '\n':
    case '\r':
    case '\t':
      return true;
    default:
      return false;
  }
}

bool IsDisallowedUnicodeCodePoint(char32_t cp) noexcept { // TSK149_Path_Traversal_And_Injection
  if (cp == 0x7F) {
    return true;
  }
  if (cp >= 0x200B && cp <= 0x200F) {
    return true;
  }
  if (cp >= 0x202A && cp <= 0x202E) {
    return true;
  }
  if (cp >= 0x2066 && cp <= 0x2069) {
    return true;
  }
  if (cp >= 0x2000 && cp <= 0x200A) {
    return true;
  }
  switch (cp) {
    case 0x00A0:
    case 0x034F:
    case 0x1680:
    case 0x2007:
    case 0x2024:
    case 0x2027:
    case 0x2028:
    case 0x2029:
    case 0x202F:
    case 0x205F:
    case 0x2060:
    case 0x2061:
    case 0x2062:
    case 0x2063:
    case 0x2064:
    case 0x2215:
    case 0x2044:
    case 0x29F8:
    case 0x3000:
    case 0xFEFF:
    case 0xFF0E:
    case 0xFF0F:
      return true;
    default:
      return false;
  }
}

bool DecodeNextUtf8CodePoint(std::string_view raw, size_t& index,
                             char32_t& cp) noexcept { // TSK149_Path_Traversal_And_Injection
  if (index >= raw.size()) {
    return false;
  }
  const unsigned char lead = static_cast<unsigned char>(raw[index]);
  ++index;
  if (lead < 0x80) {
    cp = static_cast<char32_t>(lead);
    return true;
  }
  if ((lead >> 5) == 0x6) {
    if (index >= raw.size()) {
      return false;
    }
    const unsigned char b1 = static_cast<unsigned char>(raw[index]);
    if ((b1 & 0xC0) != 0x80) {
      return false;
    }
    ++index;
    cp = static_cast<char32_t>(((lead & 0x1F) << 6) | (b1 & 0x3F));
    if (cp < 0x80) {
      return false;
    }
    return true;
  }
  if ((lead >> 4) == 0xE) {
    if (index + 1 >= raw.size()) {
      return false;
    }
    const unsigned char b1 = static_cast<unsigned char>(raw[index]);
    const unsigned char b2 = static_cast<unsigned char>(raw[index + 1]);
    if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) {
      return false;
    }
    index += 2;
    cp = static_cast<char32_t>(((lead & 0x0F) << 12) | ((b1 & 0x3F) << 6) |
                               (b2 & 0x3F));
    if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) {
      return false;
    }
    return true;
  }
  if ((lead >> 3) == 0x1E) {
    if (index + 2 >= raw.size()) {
      return false;
    }
    const unsigned char b1 = static_cast<unsigned char>(raw[index]);
    const unsigned char b2 = static_cast<unsigned char>(raw[index + 1]);
    const unsigned char b3 = static_cast<unsigned char>(raw[index + 2]);
    if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) {
      return false;
    }
    index += 3;
    cp = static_cast<char32_t>(((lead & 0x07) << 18) | ((b1 & 0x3F) << 12) |
                               ((b2 & 0x3F) << 6) | (b3 & 0x3F));
    if (cp < 0x10000 || cp > 0x10FFFF) {
      return false;
    }
    return true;
  }
  return false;
}

Utf8ValidationResult CheckUtf8Safety(std::string_view raw) noexcept { // TSK149_Path_Traversal_And_Injection
  size_t index = 0;
  while (index < raw.size()) {
    char32_t cp = 0;
    if (!DecodeNextUtf8CodePoint(raw, index, cp)) {
      return Utf8ValidationResult::kInvalidEncoding;
    }
    if (cp <= 0x1F || ContainsForbiddenAsciiChar(cp) ||
        IsDisallowedUnicodeCodePoint(cp)) {
      return Utf8ValidationResult::kDisallowed;
    }
  }
  return Utf8ValidationResult::kOk;
}

void RequireUtf8Safety(std::string_view raw,
                       std::string_view what) { // TSK149_Path_Traversal_And_Injection
  switch (CheckUtf8Safety(raw)) {
    case Utf8ValidationResult::kOk:
      return;
    case Utf8ValidationResult::kInvalidEncoding:
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      std::string(what) + " contains invalid UTF-8 encoding"};
    case Utf8ValidationResult::kDisallowed:
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      std::string(what) + " contains unsupported characters"};
  }
}

void RequireSafePathComponent(const std::filesystem::path& component,
                              std::string_view description) { // TSK149_Path_Traversal_And_Injection
  const std::string text = qv::PathToUtf8String(component);
  RequireUtf8Safety(text, description);
  if (text.empty() || text == "." || text == ".." ||
      text.find_first_of("/\\") != std::string::npos) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(description) + " contains reserved path segments"};
  }
}

std::filesystem::path ComputeContainerRoot() { // TSK099_Input_Validation_and_Sanitization
  const char* env_root = std::getenv("QV_CONTAINER_ROOT");
  std::filesystem::path base;
  if (env_root && *env_root) {
    base = std::filesystem::path(env_root);
  } else {
    std::error_code cwd_ec;
    base = std::filesystem::current_path(cwd_ec);
    if (cwd_ec) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      std::string(qv::errors::msg::kUnableToResolveWorkingDirectory)};
    }
  }
  std::error_code ec;
  auto canonical = std::filesystem::weakly_canonical(base, ec);
  if (ec) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(qv::errors::msg::kUnableToCanonicalizeContainerRoot)};
  }
  return canonical;
}

const std::filesystem::path& AllowedContainerRoot() { // TSK099_Input_Validation_and_Sanitization
  static const std::filesystem::path root = ComputeContainerRoot();
  return root;
}

std::filesystem::path SanitizeContainerPath(
    const std::filesystem::path& path) { // TSK099_Input_Validation_and_Sanitization
  RequireUtf8Safety(qv::PathToUtf8String(path),
                    "Container path"); // TSK149_Path_Traversal_And_Injection
  std::error_code ec;
  auto canonical = std::filesystem::weakly_canonical(path, ec);
  if (ec) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(qv::errors::msg::kFailedToCanonicalizeContainerPath)};
  }
  if (canonical.empty()) { // TSK149_Path_Traversal_And_Injection
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(qv::errors::msg::kPathEscapeAttemptDetected)};
  }
  const auto& base = AllowedContainerRoot();
  auto relative = std::filesystem::relative(canonical, base, ec);
  if (ec || relative.is_absolute()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(qv::errors::msg::kContainerEscapesAllowedRoot)};
  }
  for (const auto& component : relative) {
    if (component == "..") {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      std::string(qv::errors::msg::kPathEscapeAttemptDetected)};
    }
    RequireSafePathComponent(component,
                             "Container path component"); // TSK149_Path_Traversal_And_Injection
  }
  RequireUtf8Safety(qv::PathToUtf8String(canonical),
                    "Container path"); // TSK149_Path_Traversal_And_Injection
  return canonical;
}


  class ScopedPathRemoval { // TSK074_Migration_Rollback_and_Backup cleanup staged files on failure
   public:
    explicit ScopedPathRemoval(std::filesystem::path path) noexcept
        : path_(std::move(path)) {}
    ScopedPathRemoval(const ScopedPathRemoval&) = delete;
    ScopedPathRemoval& operator=(const ScopedPathRemoval&) = delete;
    ~ScopedPathRemoval() noexcept {
      if (!path_.empty()) {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
      }
    }

    void Release() noexcept { path_.clear(); }

   private:
    std::filesystem::path path_;
  };

  constexpr std::array<char, 8> kVolumeMagic = {'Q', 'V', 'A', 'U', 'L', 'T', '\0', '\0'}; // TSK013
  constexpr uint32_t kHeaderVersion = VolumeManager::kLatestHeaderVersion;                  // TSK033 align serialization with published target
  // TSK112_Documentation_and_Code_Clarity: TLV type identifiers (little-endian) encode
  // well-known header extensions. The ASCII pairs document human-readable tags used by
  // interoperability tooling when inspecting raw headers.
  constexpr uint16_t kTlvTypePbkdf2 = 0x1001;                                              // Password-based KDF parameters // TSK112
  constexpr uint16_t kTlvTypeHybridSalt = 0x1002;                                          // PQC hybrid KDF salt // TSK112
  constexpr uint16_t kTlvTypeArgon2 = 0x1003;                                              // Argon2id KDF parameters // TSK112
  constexpr uint16_t kTlvTypeEpoch = 0x4E4F;                                               // 'NO' nonce/epoch counter // TSK112
  constexpr uint16_t kTlvTypePqcKem = 0x7051;                                              // 'pQ' post-quantum KEM blob // TSK112
  constexpr uint16_t kTlvTypeReservedV2 = 0x7F02;                                          // Reserved V2 payload // TSK112
  constexpr uint32_t kDefaultFlags = 0;
  constexpr uint32_t kDefaultPbkdfIterations = 600'000; // TSK036_PBKDF2_Argon2_Migration_Path baseline
  constexpr uint32_t kBenchmarkIterations = 100'000;    // TSK036_PBKDF2_Argon2_Migration_Path calibration sample size
  constexpr size_t kPbkdfSaltSize = 16;
  constexpr size_t kHybridSaltSize = 32;
  constexpr std::chrono::milliseconds kDefaultTargetDuration{500}; // TSK036_PBKDF2_Argon2_Migration_Path
  constexpr uint32_t kMinPbkdfIterations = 50'000;                 // TSK036_PBKDF2_Argon2_Migration_Path floor
  constexpr uint32_t kMaxPbkdfIterations = 8'000'000;              // TSK036_PBKDF2_Argon2_Migration_Path ceiling

  using PasswordKdf = VolumeManager::PasswordKdf;                                   // TSK036_PBKDF2_Argon2_Migration_Path
  using ProgressCallback = VolumeManager::ProgressCallback;                         // TSK036_PBKDF2_Argon2_Migration_Path

  struct Argon2Config { // TSK036_PBKDF2_Argon2_Migration_Path serialized TLV payload
    uint32_t version{1};
    uint32_t time_cost{3};
    uint32_t memory_cost_kib{64u * 1024u};
    uint32_t parallelism{4};
    uint32_t hash_length{32};
    uint32_t target_ms{static_cast<uint32_t>(kDefaultTargetDuration.count())};
    std::array<uint8_t, kPbkdfSaltSize> salt{};
  };

  struct VolumeHeader { // TSK013
    std::array<char, 8> magic = kVolumeMagic;
    uint32_t version = qv::ToLittleEndian(kHeaderVersion);
    std::array<uint8_t, 16> uuid{};
    uint32_t flags = qv::ToLittleEndian(kDefaultFlags);
  };

#pragma pack(push, 1)
  struct ReservedV2Tlv { // TSK033 future ACL metadata placeholder
    uint16_t type = qv::ToLittleEndian16(kTlvTypeReservedV2);
    uint16_t length = qv::ToLittleEndian16(32);
    std::array<uint8_t, 32> payload{};
  };
#pragma pack(pop)

  static_assert(sizeof(VolumeHeader) == 32, "volume header must be 32 bytes");  // TSK013
  static_assert(sizeof(ReservedV2Tlv) == 36, "reserved TLV layout unexpected"); // TSK013

  constexpr uint8_t kAesGcmCipherId =                                         // TSK083_AAD_Recompute_and_Binding
      static_cast<uint8_t>(qv::crypto::CipherType::AES_256_GCM);
  constexpr uint8_t kAesGcmTagSize =                                          // TSK083
      static_cast<uint8_t>(qv::crypto::AES256_GCM::TAG_SIZE);
  constexpr uint8_t kAesGcmNonceSize =                                        // TSK083
      static_cast<uint8_t>(qv::crypto::AES256_GCM::NONCE_SIZE);
  constexpr uint32_t kChunkHeaderIntegrityVersion = 1;                         // TSK128_Missing_AAD_Validation_in_Chunks

  qv::core::AADEnvelope MakeChunkEnvelope(uint32_t epoch, int64_t chunk_index, // TSK083
                                          uint64_t logical_offset,
                                          uint32_t chunk_size,
                                          std::span<const uint8_t, 32> nonce_chain_mac,
                                          uint64_t nonce_counter) {
    auto context = qv::core::BindChunkAADContext(kAesGcmCipherId, kAesGcmTagSize, kAesGcmNonceSize,
                                                 epoch, kChunkHeaderIntegrityVersion);
    auto aad_data =
        qv::core::MakeAADData(epoch, chunk_index, logical_offset, chunk_size, context, nonce_counter);
    return qv::core::MakeAADEnvelope(aad_data, nonce_chain_mac);
  }

  void FillRandom(std::span<uint8_t> out) { // TSK013
    qv::crypto::SystemRandomBytes(out); // TSK106_Cryptographic_Implementation_Weaknesses
  }

  std::array<uint8_t, 16> GenerateUuidV4() { // TSK013
    std::array<uint8_t, 16> uuid{};
    FillRandom(uuid);
    uuid[6] = static_cast<uint8_t>((uuid[6] & 0x0F) | 0x40);
    uuid[8] = static_cast<uint8_t>((uuid[8] & 0x3F) | 0x80);
    return uuid;
  }

  std::string FormatUuid(const std::array<uint8_t, 16>& uuid) { // TSK029
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < uuid.size(); ++i) {
      oss << std::setw(2) << static_cast<int>(uuid[i]);
      if (i == 3 || i == 5 || i == 7 || i == 9) {
        oss << '-';
      }
    }
    return oss.str();
  }

  std::array<uint8_t, 32> DerivePasswordKey(std::span<const uint8_t> password,
                                            const std::array<uint8_t, kPbkdfSaltSize>& salt,
                                            uint32_t iterations,
                                            ProgressCallback progress = {}) { // TSK111_Code_Duplication_and_Maintainability
    return qv::crypto::PBKDF2_HMAC_SHA256(
        password, std::span<const uint8_t>(salt.data(), salt.size()), iterations,
        progress);
  }

  std::array<uint8_t, 32> DerivePasswordKeyArgon2id(std::span<const uint8_t> password,
                                                    const Argon2Config& config) { // TSK036_PBKDF2_Argon2_Migration_Path
#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2
    std::array<uint8_t, 32> output{};
    if (config.hash_length != output.size()) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      std::string(qv::errors::msg::kUnsupportedArgon2HashLength)};
    }
    int rc = argon2id_hash_raw(static_cast<uint32_t>(config.time_cost),
                               static_cast<uint32_t>(config.memory_cost_kib),
                               static_cast<uint32_t>(config.parallelism),
                               password.data(), password.size(), config.salt.data(), config.salt.size(),
                               output.data(), output.size());
    if (rc != ARGON2_OK) {
      throw qv::Error{qv::ErrorDomain::Crypto, rc,
                      std::string(qv::errors::msg::kArgon2DerivationFailed)};
    }
    return output;
#else
    (void)password;
    (void)config;
    throw qv::Error{qv::ErrorDomain::Dependency, 0,
                    std::string(qv::errors::msg::kArgon2Unavailable)};
#endif
  }

  std::array<uint8_t, 32> DeriveHeaderMacKey(
      std::span<const uint8_t, 32> hybrid_key,
      const std::array<uint8_t, 16>& uuid) { // TSK024_Key_Rotation_and_Lifecycle_Management
    auto metadata_root =
        qv::core::DeriveMetadataKey(hybrid_key); // TSK024_Key_Rotation_and_Lifecycle_Management
    static constexpr std::string_view kInfo{"QV-HEADER-MAC/v1"};
    const std::span<const uint8_t> info_span(
        reinterpret_cast<const uint8_t*>(kInfo.data()), kInfo.size());
    auto okm = qv::crypto::HKDF_SHA256(
        std::span<const uint8_t>(metadata_root.data(), metadata_root.size()),
        std::span<const uint8_t>(uuid.data(), uuid.size()), info_span); // TSK106_Cryptographic_Implementation_Weaknesses
    qv::security::Zeroizer::Wipe(
        std::span<uint8_t>(metadata_root.data(),
                           metadata_root.size())); // TSK024_Key_Rotation_and_Lifecycle_Management
    return okm;
  }

  class VectorWipeGuard { // TSK028_Secure_Deletion_and_Data_Remanence
  public:
    explicit VectorWipeGuard(std::vector<uint8_t>& vec) noexcept : vec_(vec) {}
    VectorWipeGuard(const VectorWipeGuard&) = delete;
    VectorWipeGuard& operator=(const VectorWipeGuard&) = delete;
    VectorWipeGuard(VectorWipeGuard&& other) noexcept : vec_(other.vec_), active_(other.active_) {
      other.active_ = false;
    }
    VectorWipeGuard& operator=(VectorWipeGuard&&) = delete;
    ~VectorWipeGuard() { Release(); }

    void Release() noexcept {
      if (!active_) {
        return;
      }
      qv::security::Zeroizer::WipeVector(vec_);
      vec_.clear();
      active_ = false;
    }

  private:
    std::vector<uint8_t>& vec_;
    bool active_{true};
  };

  struct ParsedHeader {                        // TSK024_Key_Rotation_and_Lifecycle_Management
    VolumeHeader header{};                     // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t header_version{0};                // TSK024_Key_Rotation_and_Lifecycle_Management
    PasswordKdf algorithm{PasswordKdf::kPbkdf2}; // TSK036_PBKDF2_Argon2_Migration_Path
    uint32_t pbkdf_iterations{0};              // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, kPbkdfSaltSize>
        pbkdf_salt{}; // TSK036_PBKDF2_Argon2_Migration_Path shared salt storage
    Argon2Config argon2{};                     // TSK036_PBKDF2_Argon2_Migration_Path
    bool have_argon2{false};                   // TSK036_PBKDF2_Argon2_Migration_Path
    std::array<uint8_t, kHybridSaltSize>
        hybrid_salt{};                      // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::core::EpochTLV epoch_tlv{};         // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t epoch_value{0};                // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::core::PQC_KEM_TLV kem_blob{};       // TSK024_Key_Rotation_and_Lifecycle_Management
    ReservedV2Tlv reserved_v2{};            // TSK024_Key_Rotation_and_Lifecycle_Management
    bool reserved_v2_present{false};        // TSK033 optional TLV tracking
    std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE>
        mac{};                        // TSK024_Key_Rotation_and_Lifecycle_Management
    std::vector<uint8_t> payload;     // TSK024_Key_Rotation_and_Lifecycle_Management
  };

  struct DerivedKeyset {                // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> data{};     // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> metadata{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> index{};    // TSK024_Key_Rotation_and_Lifecycle_Management
  };

  DerivedKeyset MakeDerivedKeyset(
      std::span<const uint8_t, 32> master) {     // TSK024_Key_Rotation_and_Lifecycle_Management
    DerivedKeyset keys{};                        // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.data = qv::core::DeriveDataKey(master); // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.metadata =
        qv::core::DeriveMetadataKey(master);       // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.index = qv::core::DeriveIndexKey(master); // TSK024_Key_Rotation_and_Lifecycle_Management
    return keys;                                   // TSK024_Key_Rotation_and_Lifecycle_Management
  }

  std::vector<uint8_t> SerializeHeaderPayload(
      const VolumeHeader& header, PasswordKdf algorithm, uint32_t pbkdf_iterations,
      const std::array<uint8_t, kPbkdfSaltSize>& password_salt,
      const std::optional<Argon2Config>& argon2,
      const std::array<uint8_t, kHybridSaltSize>& hybrid_salt, const qv::core::EpochTLV& epoch,
      const qv::core::PQC_KEM_TLV& kem_blob,
      const ReservedV2Tlv& reserved) { // TSK111_Code_Duplication_and_Maintainability
    qv::orchestrator::HeaderSerializer serializer;
    serializer.AddHeader(header);

    if (algorithm == PasswordKdf::kPbkdf2) {
      std::array<uint8_t, sizeof(uint32_t) + kPbkdfSaltSize> pbkdf_payload{};
      const uint32_t iter_le = qv::ToLittleEndian(pbkdf_iterations);
      std::memcpy(pbkdf_payload.data(), &iter_le, sizeof(iter_le));
      std::copy(password_salt.begin(), password_salt.end(), pbkdf_payload.begin() + sizeof(uint32_t));
      serializer.AddTLV(kTlvTypePbkdf2, std::span<const uint8_t>(pbkdf_payload.data(), pbkdf_payload.size()));
    } else if (algorithm == PasswordKdf::kArgon2id) {
      if (!argon2) {
        throw qv::Error{qv::ErrorDomain::Internal, 0, std::string(qv::errors::msg::kMissingArgon2Configuration)};
      }
      std::array<uint8_t, sizeof(uint32_t) * 6 + kPbkdfSaltSize> argon_payload{};
      auto write_field = [&](size_t index, uint32_t value) {
        const uint32_t le = qv::ToLittleEndian(value);
        std::memcpy(argon_payload.data() + index * sizeof(uint32_t), &le, sizeof(le));
      };
      write_field(0, argon2->version);
      write_field(1, argon2->time_cost);
      write_field(2, argon2->memory_cost_kib);
      write_field(3, argon2->parallelism);
      write_field(4, argon2->hash_length);
      write_field(5, argon2->target_ms);
      std::copy(argon2->salt.begin(), argon2->salt.end(),
                argon_payload.begin() + sizeof(uint32_t) * 6);
      serializer.AddTLV(kTlvTypeArgon2, std::span<const uint8_t>(argon_payload.data(), argon_payload.size()));
    }

    serializer.AddTLV(kTlvTypeHybridSalt, std::span<const uint8_t>(hybrid_salt.data(), hybrid_salt.size()));
    serializer.AddStruct(epoch);

    auto pqc_copy = kem_blob;
    pqc_copy.type = qv::ToLittleEndian16(kTlvTypePqcKem);
    pqc_copy.length = qv::ToLittleEndian16(
        CheckedCast<uint16_t>(sizeof(qv::core::PQC_KEM_TLV) - sizeof(uint16_t) * 2));
    pqc_copy.version = qv::ToLittleEndian16(pqc_copy.version);
    pqc_copy.kem_id = qv::ToLittleEndian16(pqc_copy.kem_id);
    serializer.AddStruct(pqc_copy);

    if (reserved.length > 0) {
      auto reserved_copy = reserved;
      uint16_t reserved_length = reserved_copy.length;
      if (reserved_length > reserved_copy.payload.size()) {
        reserved_length = CheckedCast<uint16_t>(reserved_copy.payload.size());
      }
      reserved_copy.type = qv::ToLittleEndian16(kTlvTypeReservedV2);
      reserved_copy.length = qv::ToLittleEndian16(reserved_length);
      std::fill(reserved_copy.payload.begin(), reserved_copy.payload.end(), 0);
      if (reserved_length > 0) {
        std::copy_n(reserved.payload.begin(), reserved_length, reserved_copy.payload.begin());
      }
      serializer.AddStruct(reserved_copy);
    }

    return serializer.Finalize();
  }

  uint32_t DeterminePbkdfIterations(std::span<const uint8_t> password,
                                     const std::array<uint8_t, kPbkdfSaltSize>& salt,
                                     const VolumeManager::KdfPolicy& policy) { // TSK036_PBKDF2_Argon2_Migration_Path
    // TSK112_Documentation_and_Code_Clarity: Sample a baseline derivation to estimate
    // per-iteration cost, then scale to meet the policy target duration. The clamp keeps
    // results within security bounds even if timing jitter produces outliers.
    if (policy.iteration_override) {
      return std::clamp<uint32_t>(*policy.iteration_override, kMinPbkdfIterations, kMaxPbkdfIterations);
    }
    auto baseline = std::max<uint32_t>(kBenchmarkIterations, 1u);
    auto start = std::chrono::steady_clock::now();
    auto sample = DerivePasswordKey(password, salt, baseline);
    auto elapsed = std::chrono::steady_clock::now() - start;
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(sample.data(), sample.size()));
    auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();
    if (elapsed_ns <= 0) {
      return kDefaultPbkdfIterations;
    }
    auto target_ns = std::max<int64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(policy.target_duration).count(), 1);
    long double per_iter_ns = static_cast<long double>(elapsed_ns) / static_cast<long double>(baseline);
    if (per_iter_ns <= 0.0L) {
      return kDefaultPbkdfIterations;
    }
    const long double raw_iterations = static_cast<long double>(target_ns) / per_iter_ns;
    uint64_t computed = 0;                                                   // TSK141_Integer_Overflow_And_Wraparound_Issues
    if (!std::isfinite(raw_iterations) || raw_iterations <= 0.0L) {          // TSK141_Integer_Overflow_And_Wraparound_Issues
      computed = kMinPbkdfIterations;                                        // TSK141_Integer_Overflow_And_Wraparound_Issues
    } else {
      const long double max_uint64 =                                         // TSK141_Integer_Overflow_And_Wraparound_Issues
          static_cast<long double>(std::numeric_limits<uint64_t>::max());    // TSK141_Integer_Overflow_And_Wraparound_Issues
      const long double bounded = std::min(raw_iterations, max_uint64);      // TSK141_Integer_Overflow_And_Wraparound_Issues
      computed = static_cast<uint64_t>(bounded);                             // TSK141_Integer_Overflow_And_Wraparound_Issues
    }
    if (computed == 0) {
      computed = kMinPbkdfIterations;                                        // TSK141_Integer_Overflow_And_Wraparound_Issues
    }
    computed = std::clamp<uint64_t>(computed, kMinPbkdfIterations, kMaxPbkdfIterations);
    return CheckedCast<uint32_t>(computed);
  }

  ParsedHeader
  ParseHeader(const std::vector<uint8_t>& blob) { // TSK111_Code_Duplication_and_Maintainability
    if (blob.size() <
        sizeof(VolumeHeader) +
            qv::crypto::HMAC_SHA256::TAG_SIZE) { // TSK111_Code_Duplication_and_Maintainability
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      std::string(qv::errors::msg::kInvalidContainerHeader)};
    }

    ParsedHeader parsed{};
    std::memcpy(&parsed.header, blob.data(), sizeof(VolumeHeader));
    parsed.header_version = qv::ToLittleEndian(parsed.header.version);
    if (parsed.header.magic != kVolumeMagic) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Unrecognized volume magic"};
    }

    const size_t mac_size = qv::crypto::HMAC_SHA256::TAG_SIZE;
    const size_t payload_size = blob.size() - mac_size;
    parsed.payload.assign(blob.begin(), blob.begin() + payload_size);
    std::copy(blob.begin() + payload_size, blob.end(), parsed.mac.begin());

    const auto header_span =
        std::span<const uint8_t>(parsed.payload.data(), parsed.payload.size());
    if (header_span.size() < sizeof(VolumeHeader)) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      std::string(qv::errors::msg::kVolumeHeaderTruncated)};
    }
    const auto tlv_span = header_span.subspan(sizeof(VolumeHeader));
    qv::tlv::Parser parser(tlv_span);
    if (!parser.valid()) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      std::string(qv::errors::msg::kVolumeHeaderTruncated)};
    }

    bool have_pbkdf = false;
    bool have_hybrid = false;
    bool have_epoch = false;
    bool have_pqc = false;

    for (const auto& record : parser) {
      switch (record.type) {
        case kTlvTypePbkdf2: {
          const size_t expected = sizeof(uint32_t) + kPbkdfSaltSize;
          if (record.value.size() != expected) {
            throw qv::Error{qv::ErrorDomain::Validation, 0,
                            std::string(qv::errors::msg::kPbkdf2Malformed)};
          }
          uint32_t iter_le = 0;
          std::memcpy(&iter_le, record.value.data(), sizeof(iter_le));
          parsed.pbkdf_iterations = qv::FromLittleEndian32(iter_le);
          std::copy_n(record.value.data() + sizeof(uint32_t), kPbkdfSaltSize,
                      parsed.pbkdf_salt.begin());
          have_pbkdf = true;
          parsed.algorithm = PasswordKdf::kPbkdf2;
          break;
        }
        case kTlvTypeArgon2: {
          constexpr size_t expected = sizeof(uint32_t) * 6 + kPbkdfSaltSize;
          if (record.value.size() != expected) {
            throw qv::Error{qv::ErrorDomain::Validation, 0,
                            std::string(qv::errors::msg::kArgon2Malformed)};
          }
          Argon2Config cfg{};
          std::memcpy(&cfg.version, record.value.data(), sizeof(uint32_t));
          std::memcpy(&cfg.time_cost, record.value.data() + sizeof(uint32_t), sizeof(uint32_t));
          std::memcpy(&cfg.memory_cost_kib,
                      record.value.data() + sizeof(uint32_t) * 2, sizeof(uint32_t));
          std::memcpy(&cfg.parallelism,
                      record.value.data() + sizeof(uint32_t) * 3, sizeof(uint32_t));
          std::memcpy(&cfg.hash_length,
                      record.value.data() + sizeof(uint32_t) * 4, sizeof(uint32_t));
          std::memcpy(&cfg.target_ms,
                      record.value.data() + sizeof(uint32_t) * 5, sizeof(uint32_t));
          std::memcpy(cfg.salt.data(),
                      record.value.data() + sizeof(uint32_t) * 6, cfg.salt.size());
          cfg.version = qv::ToLittleEndian(cfg.version);
          cfg.time_cost = qv::ToLittleEndian(cfg.time_cost);
          cfg.memory_cost_kib = qv::ToLittleEndian(cfg.memory_cost_kib);
          cfg.parallelism = qv::ToLittleEndian(cfg.parallelism);
          cfg.hash_length = qv::ToLittleEndian(cfg.hash_length);
          cfg.target_ms = qv::ToLittleEndian(cfg.target_ms);
          parsed.argon2 = cfg;
          parsed.have_argon2 = true;
          parsed.algorithm = PasswordKdf::kArgon2id; // TSK148_Cryptographic_Implementation_Weaknesses keep Argon2 salt isolated
          break;
        }
        case kTlvTypeHybridSalt: {
          if (record.value.size() != kHybridSaltSize) {
            throw qv::Error{qv::ErrorDomain::Validation, 0,
                            std::string(qv::errors::msg::kHybridSaltMalformed)};
          }
          std::copy_n(record.value.data(), kHybridSaltSize, parsed.hybrid_salt.begin());
          have_hybrid = true;
          break;
        }
        case kTlvTypeEpoch: {
          if (record.value.size() != sizeof(parsed.epoch_tlv.epoch)) {
            throw qv::Error{qv::ErrorDomain::Validation, 0,
                            std::string(qv::errors::msg::kEpochMalformed)};
          }
          parsed.epoch_tlv.type = qv::ToLittleEndian16(kTlvTypeEpoch);
          parsed.epoch_tlv.length =
              qv::ToLittleEndian(CheckedCast<uint16_t>(record.value.size()));
          std::memcpy(&parsed.epoch_tlv.epoch, record.value.data(),
                      sizeof(parsed.epoch_tlv.epoch));
          parsed.epoch_value = qv::FromLittleEndian32(parsed.epoch_tlv.epoch);
          have_epoch = true;
          break;
        }
        case kTlvTypePqcKem: {
          const size_t expected = sizeof(qv::core::PQC_KEM_TLV) - sizeof(uint16_t) * 2;
          if (record.value.size() != expected) {
            throw qv::Error{qv::ErrorDomain::Validation, 0,
                            std::string(qv::errors::msg::kPqcMalformed)};
          }
          parsed.kem_blob.type = qv::ToLittleEndian16(kTlvTypePqcKem);
          parsed.kem_blob.length = qv::ToLittleEndian16(CheckedCast<uint16_t>(expected));
          std::memcpy(reinterpret_cast<uint8_t*>(&parsed.kem_blob) + sizeof(uint16_t) * 2,
                      record.value.data(), expected);
          parsed.kem_blob.version = qv::ToLittleEndian16(parsed.kem_blob.version);
          parsed.kem_blob.kem_id = qv::ToLittleEndian16(parsed.kem_blob.kem_id);
          have_pqc = true;
          break;
        }
        case kTlvTypeReservedV2: {
          if (record.value.size() > parsed.reserved_v2.payload.size()) {
            throw qv::Error{qv::ErrorDomain::Validation, 0,
                            std::string(qv::errors::msg::kReservedMalformed)};
          }
          parsed.reserved_v2_present = record.value.size() > 0;
          parsed.reserved_v2.type = qv::ToLittleEndian16(kTlvTypeReservedV2);
          parsed.reserved_v2.length = CheckedCast<uint16_t>(record.value.size());
          std::fill(parsed.reserved_v2.payload.begin(), parsed.reserved_v2.payload.end(), 0);
          if (!record.value.empty()) {
            std::copy(record.value.begin(), record.value.end(),
                      parsed.reserved_v2.payload.begin());
          }
          break;
        }
        default:
          break;
      }
    }

    if ((!have_pbkdf && !parsed.have_argon2) || !have_hybrid || !have_epoch || !have_pqc) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      std::string(qv::errors::msg::kRequiredTlvMissing)};
    }

    return parsed;
  }

  std::filesystem::path MetadataDirFor(
      const std::filesystem::path& container) { // TSK024_Key_Rotation_and_Lifecycle_Management
    auto sanitized = SanitizeContainerPath(container); // TSK149_Path_Traversal_And_Injection
    auto parent = sanitized.parent_path();              // TSK024_Key_Rotation_and_Lifecycle_Management
    auto name_component = sanitized.filename();         // TSK149_Path_Traversal_And_Injection
    if (name_component.empty() || name_component == "." ||
        name_component == "..") { // TSK149_Path_Traversal_And_Injection
      name_component = std::filesystem::path{"volume"};
    }
    std::string base = qv::PathToUtf8String(name_component); // TSK149_Path_Traversal_And_Injection
    if (base.empty() || base == "." || base == ".." ||
        base.find_first_of("/\\") != std::string::npos ||
        CheckUtf8Safety(base) != Utf8ValidationResult::kOk) { // TSK149_Path_Traversal_And_Injection
      base = "volume";
    }
    std::filesystem::path metadata = parent / std::filesystem::path(base + ".meta");
    return metadata.lexically_normal(); // TSK149_Path_Traversal_And_Injection
  }

#pragma pack(push, 1)
  struct KeyBackupRecord { // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<char, 8> magic{'Q', 'V', 'B',  'A',
                              'C', 'K', '\0', '\0'}; // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t version =
        qv::ToLittleEndian(0x00010000u); // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 16> uuid{};      // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t epoch{0};                   // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::core::PQC::CIPHERTEXT_SIZE>
        kem_ct{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>
        nonce{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>
        tag{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, sizeof(DerivedKeyset)>
        encrypted_keys{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE>
        hmac{}; // TSK137_Backup_Security_And_Integrity_Gaps integrity binding
  };
#pragma pack(pop)

  std::optional<std::filesystem::path>
  PerformKeyBackup(const std::filesystem::path& container, uint32_t epoch,
                   const std::array<uint8_t, 16>& uuid, DerivedKeyset& keyset,
                   const std::filesystem::path&
                       backup_public_key) { // TSK024_Key_Rotation_and_Lifecycle_Management
    std::ifstream in(backup_public_key,
                     std::ios::binary); // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!in) {                          // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;            // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to open backup key: " + backup_public_key.string()};
    }
    std::vector<uint8_t> pk_bytes((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());
    VectorWipeGuard pk_guard(pk_bytes); // TSK028_Secure_Deletion_and_Data_Remanence
    if (pk_bytes.size() !=
        qv::core::PQC::PUBLIC_KEY_SIZE) { // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Backup key size mismatch"};
    }
    std::array<uint8_t, qv::core::PQC::PUBLIC_KEY_SIZE>
        pk{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::copy(pk_bytes.begin(), pk_bytes.end(),
              pk.begin()); // TSK024_Key_Rotation_and_Lifecycle_Management

    qv::core::PQCKeyEncapsulation kem; // TSK024_Key_Rotation_and_Lifecycle_Management
    auto enc = kem.Encapsulate(pk);    // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::security::Zeroizer::ScopeWiper secret_guard(enc.shared_secret.data(),
                                                    enc.shared_secret.size());

    std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>
        nonce{};       // TSK024_Key_Rotation_and_Lifecycle_Management
    FillRandom(nonce); // TSK024_Key_Rotation_and_Lifecycle_Management

    static constexpr std::string_view kBackupContext{
        "QV-BACKUP/v1"};            // TSK024_Key_Rotation_and_Lifecycle_Management
    std::vector<uint8_t> aad;       // TSK024_Key_Rotation_and_Lifecycle_Management
    VectorWipeGuard aad_guard(aad); // TSK028_Secure_Deletion_and_Data_Remanence
    aad.insert(aad.end(), kBackupContext.begin(),
               kBackupContext.end());                // TSK024_Key_Rotation_and_Lifecycle_Management
    aad.insert(aad.end(), uuid.begin(), uuid.end()); // TSK024_Key_Rotation_and_Lifecycle_Management
    const uint32_t epoch_le =
        qv::ToLittleEndian(epoch); // TSK024_Key_Rotation_and_Lifecycle_Management
    const uint8_t* epoch_bytes =
        reinterpret_cast<const uint8_t*>(&epoch_le); // TSK024_Key_Rotation_and_Lifecycle_Management
    aad.insert(aad.end(), epoch_bytes,
               epoch_bytes + sizeof(epoch_le)); // TSK024_Key_Rotation_and_Lifecycle_Management

    static constexpr std::string_view kBackupNonceInfo{
        "QV-BACKUP-NONCE/v1"}; // TSK148_Cryptographic_Implementation_Weaknesses bind nonce to shared secret
    auto nonce_mask = qv::crypto::HKDF_SHA256(
        std::span<const uint8_t>(enc.shared_secret.data(), enc.shared_secret.size()),
        std::span<const uint8_t>(aad.data(), aad.size()),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(kBackupNonceInfo.data()),
                                 kBackupNonceInfo.size()));
    qv::security::Zeroizer::ScopeWiper nonce_mask_guard(nonce_mask.data(), nonce_mask.size());
    for (size_t i = 0; i < nonce.size(); ++i) { // TSK148_Cryptographic_Implementation_Weaknesses harden IV derivation
      nonce[i] ^= nonce_mask[i];
    }

    static constexpr std::string_view kBackupEncInfo{
        "QV-BACKUP-ENC/v1"}; // TSK148_Cryptographic_Implementation_Weaknesses stretch backup key material
    auto backup_key = qv::crypto::HKDF_SHA256(
        std::span<const uint8_t>(enc.shared_secret.data(), enc.shared_secret.size()),
        std::span<const uint8_t>(aad.data(), aad.size()),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(kBackupEncInfo.data()),
                                 kBackupEncInfo.size()));
    qv::security::Zeroizer::ScopeWiper backup_key_guard(backup_key.data(), backup_key.size());

    auto keyset_bytes = qv::AsBytesConst(keyset); // TSK024_Key_Rotation_and_Lifecycle_Management
    auto enc_result =
        qv::crypto::AES256_GCM_Encrypt( // TSK024_Key_Rotation_and_Lifecycle_Management
            keyset_bytes, std::span<const uint8_t>(aad.data(), aad.size()),
            std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce.data(),
                                                                         nonce.size()),
            std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(backup_key.data(),
                                                                       backup_key.size()));
    VectorWipeGuard ciphertext_guard(
        enc_result.ciphertext); // TSK028_Secure_Deletion_and_Data_Remanence
    qv::security::Zeroizer::ScopeWiper tag_guard(enc_result.tag.data(), enc_result.tag.size());
    if (enc_result.ciphertext.size() !=
        sizeof(DerivedKeyset)) { // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Crypto, 0, "Unexpected backup ciphertext length"};
    }

    KeyBackupRecord record{};                 // TSK024_Key_Rotation_and_Lifecycle_Management
    record.uuid = uuid;                       // TSK024_Key_Rotation_and_Lifecycle_Management
    record.epoch = qv::ToLittleEndian(epoch); // TSK024_Key_Rotation_and_Lifecycle_Management
    record.kem_ct = enc.ciphertext;           // TSK024_Key_Rotation_and_Lifecycle_Management
    record.nonce = nonce;                     // TSK024_Key_Rotation_and_Lifecycle_Management
    record.tag = enc_result.tag;              // TSK024_Key_Rotation_and_Lifecycle_Management
    std::copy(enc_result.ciphertext.begin(),
              enc_result.ciphertext.end(), // TSK024_Key_Rotation_and_Lifecycle_Management
              record.encrypted_keys.begin());

    static constexpr std::string_view kBackupHmacInfo{
        "QV-BACKUP-HMAC/v1"}; // TSK137_Backup_Security_And_Integrity_Gaps context binding
    auto hmac_key = qv::crypto::HKDF_SHA256(
        std::span<const uint8_t>(enc.shared_secret.data(), enc.shared_secret.size()),
        std::span<const uint8_t>(aad.data(), aad.size()),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(kBackupHmacInfo.data()),
                                 kBackupHmacInfo.size())); // TSK137_Backup_Security_And_Integrity_Gaps
    const auto record_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&record),
        sizeof(record) - record.hmac.size()); // TSK137_Backup_Security_And_Integrity_Gaps exclude MAC field
    record.hmac = qv::crypto::HMAC_SHA256::Compute(
        std::span<const uint8_t>(hmac_key.data(), hmac_key.size()),
        record_bytes); // TSK137_Backup_Security_And_Integrity_Gaps protect backup contents
    qv::security::Zeroizer::Wipe(
        std::span<uint8_t>(hmac_key.data(), hmac_key.size())); // TSK137_Backup_Security_And_Integrity_Gaps

    auto metadata_dir = MetadataDirFor(container); // TSK024_Key_Rotation_and_Lifecycle_Management
    EnsureSecureParentDirectory(metadata_dir);     // TSK146_Permission_And_Ownership_Issues validate hierarchy
    try {
      std::filesystem::create_directories(metadata_dir);
    } catch (const std::filesystem::filesystem_error& err) {
      throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(err.code().value()),
                      "Failed to prepare metadata directory: " + metadata_dir.string()};
    }
    HardenPrivateDirectory(metadata_dir); // TSK146_Permission_And_Ownership_Issues ensure 0700 metadata
    EnsureDirectorySecure(metadata_dir);  // TSK146_Permission_And_Ownership_Issues re-validate metadata security
    auto backup_path = metadata_dir / // TSK024_Key_Rotation_and_Lifecycle_Management
                       ("key_backup.epoch_" + std::to_string(epoch) +
                        ".bin"); // TSK024_Key_Rotation_and_Lifecycle_Management

    EnsureSecureParentDirectory(backup_path); // TSK146_Permission_And_Ownership_Issues refuse weak parent perms
    std::ofstream out(backup_path,
                      std::ios::binary |
                          std::ios::trunc); // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!out) {                             // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;                // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to write backup file: " + backup_path.string()};
    }
    out.write(reinterpret_cast<const char*>(&record),
              sizeof(record)); // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!out) {                // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;   // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to persist backup file: " + backup_path.string()};
    }
    out.flush(); // TSK137_Backup_Security_And_Integrity_Gaps ensure durability
    if (!out) {
      const int err = errno; // TSK137_Backup_Security_And_Integrity_Gaps
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to finalize backup file: " + backup_path.string()};
    }
    out.close();

    HardenPrivateFile(backup_path); // TSK146_Permission_And_Ownership_Issues enforce 0600 backup

    qv::security::Zeroizer::Wipe(
        std::span<uint8_t>(enc.shared_secret.data(), enc.shared_secret.size()));
    qv::security::Zeroizer::Wipe(
        std::span<uint8_t>(enc_result.ciphertext.data(), enc_result.ciphertext.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(aad.data(), aad.size()));

    return backup_path; // TSK024_Key_Rotation_and_Lifecycle_Management
  }
} // namespace

VolumeManager::VolumeManager() { // TSK036_PBKDF2_Argon2_Migration_Path
#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2
  kdf_policy_.algorithm = PasswordKdf::kArgon2id;
#else
  kdf_policy_.algorithm = PasswordKdf::kPbkdf2;
#endif
  kdf_policy_.target_duration = kDefaultTargetDuration;
}

VolumeManager::VolumeManager(KdfPolicy policy) : kdf_policy_(policy) { // TSK036_PBKDF2_Argon2_Migration_Path
  if (kdf_policy_.target_duration.count() <= 0) {
    kdf_policy_.target_duration = kDefaultTargetDuration;
  }
}

void VolumeManager::SetKdfPolicy(const KdfPolicy& policy) { // TSK036_PBKDF2_Argon2_Migration_Path
  kdf_policy_ = policy;
  if (kdf_policy_.target_duration.count() <= 0) {
    kdf_policy_.target_duration = kDefaultTargetDuration;
  }
}

const VolumeManager::KdfPolicy& VolumeManager::GetKdfPolicy() const { // TSK036_PBKDF2_Argon2_Migration_Path
  return kdf_policy_;
}

VolumeManager::ChunkEncryptionResult VolumeManager::EncryptChunk(
    std::span<const uint8_t> plaintext, uint32_t epoch, int64_t chunk_index,
    uint64_t logical_offset, uint32_t chunk_size, qv::core::NonceGenerator& nonce_gen,
    std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE> data_key) { // TSK040_AAD_Binding_and_Chunk_Authentication
  if (chunk_index < 0) {                                                   // TSK141_Integer_Overflow_And_Wraparound_Issues
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Negative chunk index"}; // TSK141_Integer_Overflow_And_Wraparound_Issues
  }
  auto chunk_hash = qv::crypto::SHA256_Hash(plaintext);                    // TSK128_Missing_AAD_Validation_in_Chunks
  qv::security::Zeroizer::ScopeWiper chunk_hash_guard(chunk_hash.data(), chunk_hash.size());
  auto nonce_record = nonce_gen.NextAuthenticated(
      chunk_index, std::span<const uint8_t>(chunk_hash.data(), chunk_hash.size())); // TSK040, TSK128_Missing_AAD_Validation_in_Chunks
  if (nonce_record.counter == std::numeric_limits<uint64_t>::max()) {       // TSK141_Integer_Overflow_And_Wraparound_Issues
    throw qv::Error{qv::ErrorDomain::State, 0, "Nonce counter overflow"};   // TSK141_Integer_Overflow_And_Wraparound_Issues
  }
  auto envelope = MakeChunkEnvelope(epoch, chunk_index, logical_offset,
                                    chunk_size, nonce_record.mac, nonce_record.counter);          // TSK083_AAD_Recompute_and_Binding, TSK128_Missing_AAD_Validation_in_Chunks
  auto enc_result = qv::crypto::AES256_GCM_Encrypt(                         // TSK040
      plaintext, qv::AsBytesConst(envelope),
      std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(
          nonce_record.nonce.data(), nonce_record.nonce.size()),
      data_key);
  return ChunkEncryptionResult(epoch, chunk_index, logical_offset, chunk_size,
                               nonce_record.nonce, enc_result.tag,
                               nonce_record.mac, std::move(enc_result.ciphertext)); // TSK083
}

std::vector<uint8_t> VolumeManager::DecryptChunk(
    const ChunkEncryptionResult& sealed_chunk, uint32_t epoch, int64_t chunk_index,
    uint64_t logical_offset, uint32_t chunk_size,
    std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE> data_key) { // TSK040_AAD_Binding_and_Chunk_Authentication
  if (chunk_index < 0 || sealed_chunk.chunk_index < 0) {                    // TSK141_Integer_Overflow_And_Wraparound_Issues
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Negative chunk index"}; // TSK141_Integer_Overflow_And_Wraparound_Issues
  }
  if (sealed_chunk.epoch != epoch || sealed_chunk.chunk_index != chunk_index ||         // TSK083
      sealed_chunk.logical_offset != logical_offset || sealed_chunk.chunk_size != chunk_size) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Sealed chunk metadata mismatch"}; // TSK083
  }
  auto nonce_counter = qv::core::ExtractNonceCounter(
      std::span<const uint8_t>(sealed_chunk.nonce.data(), sealed_chunk.nonce.size())); // TSK128_Missing_AAD_Validation_in_Chunks
  auto envelope =
      MakeChunkEnvelope(sealed_chunk.epoch, sealed_chunk.chunk_index, sealed_chunk.logical_offset,
                        sealed_chunk.chunk_size, sealed_chunk.nonce_chain_mac, nonce_counter); // TSK083, TSK128_Missing_AAD_Validation_in_Chunks
  return qv::crypto::AES256_GCM_Decrypt(                                            // TSK040
      std::span<const uint8_t>(sealed_chunk.ciphertext.data(), sealed_chunk.ciphertext.size()),
      qv::AsBytesConst(envelope),
      std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(sealed_chunk.nonce.data(),
                                                                   sealed_chunk.nonce.size()),
      std::span<const uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>(sealed_chunk.tag.data(),
                                                                 sealed_chunk.tag.size()),
      data_key);
}

QV_SENSITIVE_BEGIN
QV_SENSITIVE_FUNCTION std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Create(const std::filesystem::path& container, const std::string& password) {
  ValidatePassword(password);                                                 // TSK099_Input_Validation_and_Sanitization
  auto sanitized_container = SanitizeContainerPath(container);               // TSK099_Input_Validation_and_Sanitization
  if (std::filesystem::exists(sanitized_container)) {
    throw qv::Error{qv::ErrorDomain::Validation,
                    qv::errors::validation::kVolumeExists, // TSK020
                    "Container already exists: " + sanitized_container.string()};
  }

  if (sanitized_container.has_parent_path()) {
    auto parent = sanitized_container.parent_path();
    std::error_code status_ec;
    auto status = std::filesystem::symlink_status(parent, status_ec);
    if (status_ec) {
      throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(status_ec.value()),
                      "Failed to inspect container parent: " + qv::PathToUtf8String(parent)};
    }
    if (!std::filesystem::exists(status)) {
      try {
        std::filesystem::create_directories(parent);
      } catch (const std::filesystem::filesystem_error& err) {
        throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(err.code().value()),
                        "Failed to prepare container directory: " + qv::PathToUtf8String(parent)};
      }
      HardenPrivateDirectory(parent); // TSK146_Permission_And_Ownership_Issues secure newly created parent
      EnsureDirectorySecure(parent);  // TSK146_Permission_And_Ownership_Issues validate ownership
    } else {
      EnsureDirectorySecure(parent);  // TSK146_Permission_And_Ownership_Issues reject unsafe existing parent
      HardenPrivateDirectory(parent); // TSK146_Permission_And_Ownership_Issues enforce owner-only permissions
    }
  }

  VolumeHeader header{}; // TSK013
  header.uuid = GenerateUuidV4();

  std::array<uint8_t, kPbkdfSaltSize> password_salt{};
  FillRandom(password_salt);

  std::array<uint8_t, kHybridSaltSize> hybrid_salt{};
  FillRandom(hybrid_salt);

  std::optional<Argon2Config> argon2_config; // TSK036_PBKDF2_Argon2_Migration_Path
  uint32_t pbkdf_iterations = 0;             // TSK036_PBKDF2_Argon2_Migration_Path
  std::array<uint8_t, 32> classical_key{};   // TSK036_PBKDF2_Argon2_Migration_Path
  {
    qv::security::SecureBuffer<uint8_t> password_bytes(password.size()); // TSK097_Cryptographic_Key_Management secure password copy
    if (password_bytes.size() > 0) {
      std::memcpy(password_bytes.data(), reinterpret_cast<const uint8_t*>(password.data()), password.size());
    }
    qv::security::Zeroizer::ScopeWiper<uint8_t> password_guard(password_bytes.AsSpan()); // TSK097_Cryptographic_Key_Management scoped wipe
    std::span<const uint8_t> password_span(password_bytes.AsSpan());
    if (kdf_policy_.algorithm == PasswordKdf::kArgon2id) {
      Argon2Config cfg{};
      cfg.target_ms = CheckedCast<uint32_t>(kdf_policy_.target_duration.count());
      FillRandom(std::span<uint8_t>(cfg.salt.data(), cfg.salt.size())); // TSK148_Cryptographic_Implementation_Weaknesses dedicated Argon2 salt
      classical_key = DerivePasswordKeyArgon2id(password_span, cfg);
      argon2_config = cfg;
    } else {
      pbkdf_iterations = DeterminePbkdfIterations(password_span, password_salt, kdf_policy_);
      classical_key = DerivePasswordKey(password_span, password_salt, pbkdf_iterations, kdf_policy_.progress);
    }
  }
  qv::security::Zeroizer::ScopeWiper<uint8_t> classical_guard(classical_key.data(), classical_key.size());

  qv::core::EpochTLV epoch{};
  epoch.type = qv::ToLittleEndian16(kTlvTypeEpoch);
  epoch.length = qv::ToLittleEndian16(CheckedCast<uint16_t>(sizeof(epoch.epoch)));
  const uint32_t initial_epoch = 1;                                             // TSK099_Input_Validation_and_Sanitization
  if (initial_epoch >= qv::core::EpochOverflowWarningThreshold()) {             // TSK099_Input_Validation_and_Sanitization
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Initial epoch too large"};                                // TSK099_Input_Validation_and_Sanitization
  }
  epoch.epoch = qv::ToLittleEndian(initial_epoch);
  const auto epoch_bytes = qv::AsBytesConst(epoch);

  auto creation = qv::core::PQCHybridKDF::Create(
      std::span<const uint8_t, 32>(classical_key),
      std::span<const uint8_t>(hybrid_salt.data(), hybrid_salt.size()),
      std::span<const uint8_t, 16>(header.uuid), kHeaderVersion, epoch_bytes);
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size())); // TSK097_Cryptographic_Key_Management wipe immediately after last use
  qv::security::Zeroizer::ScopeWiper creation_guard(creation.hybrid_key.data(),
                                                    creation.hybrid_key.size());

  auto mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()),
      header.uuid); // TSK024_Key_Rotation_and_Lifecycle_Management
  qv::security::Zeroizer::ScopeWiper mac_guard(
      mac_key.data(), mac_key.size()); // TSK028_Secure_Deletion_and_Data_Remanence

  ReservedV2Tlv reserved_v2{};
  auto payload = SerializeHeaderPayload(
      header, kdf_policy_.algorithm, pbkdf_iterations, password_salt, argon2_config, hybrid_salt,
      epoch, creation.kem_blob,
      reserved_v2); // TSK024_Key_Rotation_and_Lifecycle_Management

  auto mac =
      qv::crypto::HMAC_SHA256::Compute(std::span<const uint8_t>(mac_key.data(), mac_key.size()),
                                       std::span<const uint8_t>(payload.data(), payload.size()));
  payload.insert(payload.end(), mac.begin(), mac.end());

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(creation.hybrid_key.data(), creation.hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  try {
    AtomicReplace(sanitized_container, std::span<const uint8_t>(payload.data(), payload.size()));
  } catch (const qv::Error& err) {
    throw qv::Error{err.domain(), err.code(),
                    "Failed to finalize container header update"}; // TSK068_Atomic_Header_Writes uniform messaging
  }
  HardenPrivateFile(sanitized_container); // TSK146_Permission_And_Ownership_Issues enforce 0600 container

  auto history = LoadPasswordHistory(sanitized_container); // TSK135_Password_Complexity_Enforcement seed history
  AppendHistoryEntry(history, HashPasswordForHistory(sanitized_container, password));
  PersistPasswordHistory(sanitized_container, history);

  qv::orchestrator::Event created{}; // TSK029
  created.category = EventCategory::kLifecycle;
  created.severity = EventSeverity::kInfo;
  created.event_id = "volume_created";
  created.message = "New encrypted volume created";
  created.fields.emplace_back("container", qv::PathToUtf8String(sanitized_container), FieldPrivacy::kRedact);
  created.fields.emplace_back("uuid", FormatUuid(header.uuid), FieldPrivacy::kPublic);
  if (kdf_policy_.algorithm == PasswordKdf::kPbkdf2) {
    created.fields.emplace_back("pbkdf_iterations", std::to_string(pbkdf_iterations),
                                FieldPrivacy::kPublic, true);
  } else {
    created.fields.emplace_back("kdf", "argon2id", FieldPrivacy::kPublic, true);
    created.fields.emplace_back("argon2_memory_kib", std::to_string(argon2_config->memory_cost_kib),
                                FieldPrivacy::kPublic, true);
  }
  qv::orchestrator::EventBus::Instance().Publish(created);

  ConstantTimeMount::VolumeHandle handle{};
  handle.dummy = 1;
  return handle;
}
QV_SENSITIVE_END

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Mount(const std::filesystem::path& container, const std::string& password) {
  ValidatePassword(password);                                                 // TSK099_Input_Validation_and_Sanitization
  auto sanitized_container = SanitizeContainerPath(container);               // TSK099_Input_Validation_and_Sanitization
  auto handle = ctm_.Mount(sanitized_container, password); // TSK029
  if (handle) {
    qv::orchestrator::Event mounted{}; // TSK029
    mounted.category = EventCategory::kLifecycle;
    mounted.severity = EventSeverity::kInfo;
    mounted.event_id = "volume_mounted";
    mounted.message = "Encrypted volume mounted";
    mounted.fields.emplace_back("container", qv::PathToUtf8String(sanitized_container),
                                FieldPrivacy::kRedact);
    qv::orchestrator::EventBus::Instance().Publish(mounted);
  }
  return handle;
}

void VolumeManager::ValidateHeaderForBackup(
    const std::filesystem::path& container) { // TSK082_Backup_Verification_and_Schema
  auto sanitized_container = SanitizeContainerPath(container);               // TSK099_Input_Validation_and_Sanitization
  std::ifstream in(sanitized_container, std::ios::binary);
  if (!in) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open backup container for validation: " +
                        sanitized_container.string()};
  }

  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
  if (blob.empty()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Backup container is empty"};
  }

  (void)ParseHeader(blob); // TSK082_Backup_Verification_and_Schema reuse existing parser
}

QV_SENSITIVE_BEGIN
QV_SENSITIVE_FUNCTION std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Rekey(const std::filesystem::path& container, const std::string& current_password,
                     const std::string& new_password,
                     std::optional<std::filesystem::path> backup_public_key) {
  ValidatePassword(current_password);                                           // TSK099_Input_Validation_and_Sanitization
  ValidatePassword(new_password);                                              // TSK099_Input_Validation_and_Sanitization
  auto sanitized_container = SanitizeContainerPath(container);                 // TSK099_Input_Validation_and_Sanitization
  if (!std::filesystem::exists(sanitized_container)) { // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::IO, qv::errors::io::kContainerMissing,
                    "Container not found: " + sanitized_container.string()};
  }

  qv::orchestrator::Event initiated{}; // TSK029
  initiated.category = EventCategory::kLifecycle;
  initiated.severity = EventSeverity::kInfo;
  initiated.event_id = "rekey_initiated";
  initiated.message = "Volume rekey operation started";
  initiated.fields.emplace_back("container", qv::PathToUtf8String(sanitized_container),
                                FieldPrivacy::kRedact);
  qv::orchestrator::EventBus::Instance().Publish(initiated);

  std::ifstream in(sanitized_container, std::ios::binary); // TSK024_Key_Rotation_and_Lifecycle_Management
  if (!in) {                                     // TSK024_Key_Rotation_and_Lifecycle_Management
    const int err = errno;                       // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open container for rekey: " + sanitized_container.string()};
  }

  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto parsed = ParseHeader(blob); // TSK024_Key_Rotation_and_Lifecycle_Management

  std::array<uint8_t, 32> classical_key{}; // TSK036_PBKDF2_Argon2_Migration_Path
  {
    qv::security::SecureBuffer<uint8_t> current_bytes(current_password.size()); // TSK097_Cryptographic_Key_Management secure current password copy
    if (current_bytes.size() > 0) {
      std::memcpy(current_bytes.data(), reinterpret_cast<const uint8_t*>(current_password.data()), current_password.size());
    }
    qv::security::Zeroizer::ScopeWiper<uint8_t> current_guard(current_bytes.AsSpan()); // TSK097_Cryptographic_Key_Management scoped wipe
    std::span<const uint8_t> current_span(current_bytes.AsSpan());
    if (parsed.algorithm == PasswordKdf::kArgon2id) {
      classical_key = DerivePasswordKeyArgon2id(current_span, parsed.argon2);
    } else {
      classical_key = DerivePasswordKey(current_span, parsed.pbkdf_salt, parsed.pbkdf_iterations);
    }
  }
  qv::security::Zeroizer::ScopeWiper<uint8_t> classical_guard(classical_key.data(), classical_key.size());

  auto hybrid_key = qv::core::PQCHybridKDF::Mount(
      std::span<const uint8_t, 32>(classical_key.data(), classical_key.size()), parsed.kem_blob,
      std::span<const uint8_t>(parsed.hybrid_salt.data(), parsed.hybrid_salt.size()),
      std::span<const uint8_t, 16>(parsed.header.uuid), parsed.header_version,
      qv::AsBytesConst(parsed.epoch_tlv)); // TSK024_Key_Rotation_and_Lifecycle_Management
  qv::security::Zeroizer::ScopeWiper hybrid_guard(hybrid_key.data(), hybrid_key.size());
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size())); // TSK097_Cryptographic_Key_Management wipe after PQC mount

  auto mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(hybrid_key.data(), hybrid_key.size()), parsed.header.uuid);
  qv::security::Zeroizer::ScopeWiper mac_guard(mac_key.data(), mac_key.size());

  auto expected_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(parsed.payload.data(), parsed.payload.size()));

  if (expected_mac != parsed.mac) { // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::AuthenticationFailureError("Header authentication failed");
  }

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  auto history = LoadPasswordHistory(sanitized_container); // TSK135_Password_Complexity_Enforcement maintain rotation ledger
  AppendHistoryEntry(history, HashPasswordForHistory(sanitized_container, current_password));
  PersistPasswordHistory(sanitized_container, history);
  const auto new_history_entry =
      EnsurePasswordNotReused(sanitized_container, history, new_password); // TSK135_Password_Complexity_Enforcement reuse guard

  const uint32_t old_epoch = parsed.epoch_value; // TSK024_Key_Rotation_and_Lifecycle_Management
  const uint32_t warning_threshold = qv::core::EpochOverflowWarningThreshold(); // TSK071_Epoch_Overflow_Safety shared policy
  const uint32_t unsafe_threshold = qv::core::EpochOverflowUnsafeThreshold();   // TSK071_Epoch_Overflow_Safety shared policy
  if (qv::core::EpochRekeyWouldBeUnsafe(old_epoch)) {                           // TSK071_Epoch_Overflow_Safety guard unsafe increment
    qv::orchestrator::Event refused{};                                          // TSK071_Epoch_Overflow_Safety refusal telemetry
    refused.category = EventCategory::kSecurity;
    refused.severity = EventSeverity::kError;
    refused.event_id = "volume_epoch_rekey_refused";
    refused.message = "Epoch counter too close to overflow";
    refused.fields.emplace_back("container", qv::PathToUtf8String(sanitized_container), FieldPrivacy::kRedact);
    refused.fields.emplace_back("epoch", std::to_string(old_epoch), FieldPrivacy::kPublic, true);
    refused.fields.emplace_back("unsafe_threshold", std::to_string(unsafe_threshold), FieldPrivacy::kPublic, true);
    refused.fields.emplace_back(
        "remaining_epochs",
        std::to_string(qv::core::kEpochOverflowHardLimit - old_epoch), FieldPrivacy::kPublic, true);
    qv::orchestrator::EventBus::Instance().Publish(refused);
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    throw qv::Error{qv::ErrorDomain::State, 0, "Epoch counter overflow risk"};
  }

  if (qv::core::EpochRequiresOverflowWarning(old_epoch)) { // TSK071_Epoch_Overflow_Safety proactive telemetry
    qv::orchestrator::Event warning{};                     // TSK071_Epoch_Overflow_Safety proactive telemetry
    warning.category = EventCategory::kSecurity;
    warning.severity = EventSeverity::kWarning;
    warning.event_id = "volume_epoch_near_overflow";
    warning.message = "Epoch counter approaching overflow margin";
    warning.fields.emplace_back("container", qv::PathToUtf8String(sanitized_container), FieldPrivacy::kRedact);
    warning.fields.emplace_back("epoch", std::to_string(old_epoch), FieldPrivacy::kPublic, true);
    warning.fields.emplace_back("warning_threshold", std::to_string(warning_threshold), FieldPrivacy::kPublic, true);
    warning.fields.emplace_back(
        "remaining_epochs",
        std::to_string(qv::core::kEpochOverflowHardLimit - old_epoch), FieldPrivacy::kPublic, true);
    qv::orchestrator::EventBus::Instance().Publish(warning);
  }

  if (old_epoch == std::numeric_limits<uint32_t>::max()) {                   // TSK141_Integer_Overflow_And_Wraparound_Issues
    throw qv::Error{qv::ErrorDomain::State, 0, "Epoch counter overflow"};   // TSK141_Integer_Overflow_And_Wraparound_Issues
  }
  const uint32_t new_epoch = old_epoch + 1; // TSK024_Key_Rotation_and_Lifecycle_Management, TSK141_Integer_Overflow_And_Wraparound_Issues

  std::array<uint8_t, kPbkdfSaltSize>
      new_password_salt{}; // TSK036_PBKDF2_Argon2_Migration_Path
  std::array<uint8_t, kHybridSaltSize>
      new_hybrid_salt{}; // TSK024_Key_Rotation_and_Lifecycle_Management
  FillRandom(new_password_salt);
  FillRandom(new_hybrid_salt);

  std::optional<Argon2Config> new_argon2; // TSK036_PBKDF2_Argon2_Migration_Path
  uint32_t new_iterations = 0;            // TSK036_PBKDF2_Argon2_Migration_Path
  std::array<uint8_t, 32> new_classical_key{};
  {
    qv::security::SecureBuffer<uint8_t> new_bytes(new_password.size()); // TSK097_Cryptographic_Key_Management secure new password copy
    if (new_bytes.size() > 0) {
      std::memcpy(new_bytes.data(), reinterpret_cast<const uint8_t*>(new_password.data()), new_password.size());
    }
    qv::security::Zeroizer::ScopeWiper<uint8_t> new_guard(new_bytes.AsSpan()); // TSK097_Cryptographic_Key_Management scoped wipe
    std::span<const uint8_t> new_span(new_bytes.AsSpan());
    if (kdf_policy_.algorithm == PasswordKdf::kArgon2id) {
      Argon2Config cfg{};
      cfg.target_ms = CheckedCast<uint32_t>(kdf_policy_.target_duration.count());
      FillRandom(std::span<uint8_t>(cfg.salt.data(), cfg.salt.size())); // TSK148_Cryptographic_Implementation_Weaknesses renew Argon2 salt on rekey
      new_classical_key = DerivePasswordKeyArgon2id(new_span, cfg);
      new_argon2 = cfg;
    } else {
      new_iterations = DeterminePbkdfIterations(new_span, new_password_salt, kdf_policy_);
      new_classical_key = DerivePasswordKey(new_span, new_password_salt, new_iterations, kdf_policy_.progress);
    }
  }
  qv::security::Zeroizer::ScopeWiper<uint8_t> new_classical_guard(new_classical_key.data(),
                                                                  new_classical_key.size());

  auto new_epoch_tlv =
      qv::core::MakeEpochTlv(new_epoch); // TSK024_Key_Rotation_and_Lifecycle_Management
  auto creation = qv::core::PQCHybridKDF::Create(
      std::span<const uint8_t, 32>(new_classical_key.data(), new_classical_key.size()),
      std::span<const uint8_t>(new_hybrid_salt.data(), new_hybrid_salt.size()),
      std::span<const uint8_t, 16>(parsed.header.uuid), parsed.header_version,
      qv::AsBytesConst(new_epoch_tlv));
  qv::security::Zeroizer::ScopeWiper creation_guard(creation.hybrid_key.data(),
                                                    creation.hybrid_key.size());

  auto new_mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()),
      parsed.header.uuid);
  qv::security::Zeroizer::ScopeWiper new_mac_guard(new_mac_key.data(), new_mac_key.size());

  auto derived_keys = MakeDerivedKeyset(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()));
  qv::security::Zeroizer::ScopeWiper derived_data_guard(derived_keys.data.data(),
                                                        derived_keys.data.size());
  qv::security::Zeroizer::ScopeWiper derived_metadata_guard(derived_keys.metadata.data(),
                                                            derived_keys.metadata.size());
  qv::security::Zeroizer::ScopeWiper derived_index_guard(derived_keys.index.data(),
                                                         derived_keys.index.size());

  auto payload = SerializeHeaderPayload(parsed.header, kdf_policy_.algorithm, new_iterations,
                                        new_password_salt, new_argon2, new_hybrid_salt,
                                        new_epoch_tlv, creation.kem_blob,
                                        parsed.reserved_v2); // TSK024_Key_Rotation_and_Lifecycle_Management

  auto new_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(new_mac_key.data(), new_mac_key.size()),
      std::span<const uint8_t>(payload.data(), payload.size()));
  payload.insert(payload.end(), new_mac.begin(), new_mac.end());

  if (payload.size() !=
      parsed.payload.size() + parsed.mac.size()) { // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::Internal, 0, "Header size changed unexpectedly"};
  }

  try {
    AtomicReplace(sanitized_container, std::span<const uint8_t>(payload.data(), payload.size()));
  } catch (const qv::Error& err) {
    throw qv::Error{err.domain(), err.code(),
                    "Failed to finalize container header update"}; // TSK068_Atomic_Header_Writes uniform messaging
  }
  HardenPrivateFile(sanitized_container); // TSK146_Permission_And_Ownership_Issues ensure owner-only container perms

  AppendHistoryEntry(history, new_history_entry); // TSK135_Password_Complexity_Enforcement record new credential
  PersistPasswordHistory(sanitized_container, history);

  std::optional<std::filesystem::path> backup_path; // TSK024_Key_Rotation_and_Lifecycle_Management
  if (backup_public_key) {
    backup_path = PerformKeyBackup(sanitized_container, new_epoch, parsed.header.uuid, derived_keys,
                                   *backup_public_key);
  }

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(new_classical_key.data(), new_classical_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(creation.hybrid_key.data(), creation.hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(new_mac_key.data(), new_mac_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(derived_keys.data.data(), derived_keys.data.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(derived_keys.metadata.data(), derived_keys.metadata.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(derived_keys.index.data(), derived_keys.index.size()));

  qv::orchestrator::Event event{}; // TSK024_Key_Rotation_and_Lifecycle_Management
  event.category = EventCategory::kSecurity;
  event.severity = EventSeverity::kInfo;
  event.event_id = "volume_rekeyed";
  event.message = "Volume encryption keys rotated";
  event.fields.emplace_back("container", qv::PathToUtf8String(sanitized_container), FieldPrivacy::kRedact);
  event.fields.emplace_back("old_epoch", std::to_string(old_epoch), FieldPrivacy::kPublic, true);
  event.fields.emplace_back("new_epoch", std::to_string(new_epoch), FieldPrivacy::kPublic, true);
  if (kdf_policy_.algorithm == PasswordKdf::kPbkdf2) {
    event.fields.emplace_back("pbkdf_iterations", std::to_string(new_iterations), FieldPrivacy::kPublic, true);
  } else {
    event.fields.emplace_back("kdf", "argon2id", FieldPrivacy::kPublic, true);
    if (new_argon2) {
      event.fields.emplace_back("argon2_memory_kib", std::to_string(new_argon2->memory_cost_kib),
                                FieldPrivacy::kPublic, true);
    }
  }
  event.fields.emplace_back("key_material_destroyed", "true", FieldPrivacy::kPublic);
  if (backup_public_key) {
    event.fields.emplace_back("backup_escrow",
                              backup_path ? qv::PathToUtf8String(*backup_path)
                                          : qv::PathToUtf8String(*backup_public_key),
                              FieldPrivacy::kRedact);
  }
  qv::orchestrator::EventBus::Instance().Publish(event);

  ConstantTimeMount::VolumeHandle handle{}; // TSK024_Key_Rotation_and_Lifecycle_Management
  handle.dummy = 1; // TSK024_Key_Rotation_and_Lifecycle_Management
  return handle; // TSK024_Key_Rotation_and_Lifecycle_Management
}
QV_SENSITIVE_END

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Migrate(const std::filesystem::path& container, uint32_t target_version,
                       const std::string& password) { // TSK033
  ValidatePassword(password);                                                 // TSK099_Input_Validation_and_Sanitization
  auto sanitized_container = SanitizeContainerPath(container);               // TSK099_Input_Validation_and_Sanitization
  if (!std::filesystem::exists(sanitized_container)) { // TSK033
    throw qv::Error{qv::ErrorDomain::IO, qv::errors::io::kContainerMissing,
                    "Container not found: " + sanitized_container.string()};
  }

  if (target_version == 0) { // TSK033 treat zero as request for latest
    target_version = VolumeManager::kLatestHeaderVersion;
  }

  std::ifstream in(sanitized_container, std::ios::binary); // TSK033
  if (!in) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open container for migration: " + sanitized_container.string()};
  }
  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto parsed = ParseHeader(blob); // TSK033 reuse validated parser

  std::array<uint8_t, 32> classical_key{}; // TSK036_PBKDF2_Argon2_Migration_Path
  {
    qv::security::SecureBuffer<uint8_t> password_bytes(password.size()); // TSK097_Cryptographic_Key_Management secure password copy
    if (password_bytes.size() > 0) {
      std::memcpy(password_bytes.data(), reinterpret_cast<const uint8_t*>(password.data()), password.size());
    }
    qv::security::Zeroizer::ScopeWiper<uint8_t> password_guard(password_bytes.AsSpan()); // TSK097_Cryptographic_Key_Management scoped wipe
    std::span<const uint8_t> password_span(password_bytes.AsSpan());
    if (parsed.algorithm == PasswordKdf::kArgon2id) {
      classical_key = DerivePasswordKeyArgon2id(password_span, parsed.argon2);
    } else {
      classical_key = DerivePasswordKey(password_span, parsed.pbkdf_salt, parsed.pbkdf_iterations);
    }
  }
  qv::security::Zeroizer::ScopeWiper<uint8_t> classical_guard(classical_key.data(), classical_key.size());

  auto hybrid_key = qv::core::PQCHybridKDF::Mount(
      std::span<const uint8_t, 32>(classical_key.data(), classical_key.size()), parsed.kem_blob,
      std::span<const uint8_t>(parsed.hybrid_salt.data(), parsed.hybrid_salt.size()),
      std::span<const uint8_t, 16>(parsed.header.uuid), parsed.header_version,
      qv::AsBytesConst(parsed.epoch_tlv)); // TSK033 authenticate existing header state
  qv::security::Zeroizer::ScopeWiper hybrid_guard(hybrid_key.data(), hybrid_key.size());
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size())); // TSK097_Cryptographic_Key_Management wipe after PQC mount

  auto mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(hybrid_key.data(), hybrid_key.size()), parsed.header.uuid); // TSK033
  qv::security::Zeroizer::ScopeWiper mac_guard(mac_key.data(), mac_key.size());

  auto expected_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(parsed.payload.data(), parsed.payload.size()));
  if (expected_mac != parsed.mac) { // TSK033 enforce password correctness
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::AuthenticationFailureError("Header authentication failed");
  }

  const uint32_t current_version = parsed.header_version; // TSK033
  if (current_version == target_version) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    return std::nullopt;
  }

  if (current_version > target_version) { // TSK033 block downgrades
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Cannot downgrade volume header version"};
  }

  constexpr uint32_t kVersionV4_0 = 0x00040000u; // TSK033 legacy baseline
  if (!(current_version == kVersionV4_0 &&
        target_version == VolumeManager::kLatestHeaderVersion)) { // TSK033 supported path
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{qv::ErrorDomain::Validation, 0, "No migration path available"};
  }

  ReservedV2Tlv reserved = parsed.reserved_v2_present ? parsed.reserved_v2 : ReservedV2Tlv{}; // TSK033
  if (!parsed.reserved_v2_present) { // TSK033 add ACL staging TLV for new version
    reserved.length = CheckedCast<uint16_t>(reserved.payload.size());
  }

  parsed.header.version = qv::ToLittleEndian(target_version); // TSK033 bump version field
  std::optional<Argon2Config> existing_argon2;
  if (parsed.have_argon2) {
    existing_argon2 = parsed.argon2;
  }
  auto payload = SerializeHeaderPayload(parsed.header, parsed.algorithm, parsed.pbkdf_iterations,
                                        parsed.pbkdf_salt, existing_argon2, parsed.hybrid_salt,
                                        parsed.epoch_tlv, parsed.kem_blob,
                                        reserved); // TSK033 rebuild header TLVs
  auto new_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(payload.data(), payload.size()));
  payload.insert(payload.end(), new_mac.begin(), new_mac.end());

  auto payload_span =
      std::span<const uint8_t>(payload.data(), payload.size()); // TSK074_Migration_Rollback_and_Backup reuse views

  auto migration_temp = MakeMigrationTempPath(sanitized_container); // TSK140_Temporary_File_Security_Vulnerabilities staged header checkpoint
  std::error_code temp_ec;
  std::filesystem::remove(migration_temp, temp_ec); // TSK074_Migration_Rollback_and_Backup clear stale stage
  ScopedPathRemoval staged_guard(migration_temp);    // TSK074_Migration_Rollback_and_Backup ensure cleanup

  try {
    AtomicReplace(migration_temp, payload_span);
  } catch (const qv::Error& err) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{err.domain(), err.code(),
                    "Failed to stage migrated container header"}; // TSK074_Migration_Rollback_and_Backup
  }
  HardenPrivateFile(migration_temp); // TSK146_Permission_And_Ownership_Issues protect staged header

  std::vector<uint8_t> staged_blob; // TSK074_Migration_Rollback_and_Backup
  {
    std::ifstream staged_in(migration_temp, std::ios::binary);
    if (!staged_in) {
      const int err = errno;
      qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
      qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
      qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to open staged migration header"}; // TSK074_Migration_Rollback_and_Backup
    }
    staged_blob.assign(std::istreambuf_iterator<char>(staged_in),
                       std::istreambuf_iterator<char>());
    if (staged_in.bad()) {
      const int err = errno;
      qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
      qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
      qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to read staged migration header"}; // TSK074_Migration_Rollback_and_Backup
    }
  }
  if (staged_blob != payload) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Staged migration header mismatch"}; // TSK074_Migration_Rollback_and_Backup
  }

  try {
    auto staged_parsed = ParseHeader(staged_blob);
    if (staged_parsed.header_version != target_version) {
      qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
      qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
      qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Staged migration header version mismatch"}; // TSK074_Migration_Rollback_and_Backup
    }
  } catch (const qv::Error& err) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{err.domain(), err.code(),
                    "Failed to validate staged migration header"}; // TSK074_Migration_Rollback_and_Backup
  }

  auto version_hex = [](uint32_t version) { // TSK074_Migration_Rollback_and_Backup reusable hex formatter
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << version;
    return oss.str();
  };
  auto format_version = [&](uint32_t version) {
    return std::string("0x") + version_hex(version);
  }; // TSK074_Migration_Rollback_and_Backup unify reporting

  auto metadata_dir = MetadataDirFor(sanitized_container); // TSK074_Migration_Rollback_and_Backup backup location
  EnsureSecureParentDirectory(metadata_dir); // TSK146_Permission_And_Ownership_Issues validate metadata hierarchy
  std::error_code metadata_ec;
  std::filesystem::create_directories(metadata_dir, metadata_ec);
  if (metadata_ec) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{qv::ErrorDomain::IO, metadata_ec.value(),
                    "Failed to prepare metadata directory: " + metadata_dir.string()};
  }
  HardenPrivateDirectory(metadata_dir); // TSK146_Permission_And_Ownership_Issues enforce 0700 metadata root
  EnsureDirectorySecure(metadata_dir);  // TSK146_Permission_And_Ownership_Issues re-check metadata directory

  auto container_name = sanitized_container.filename().string();
  if (container_name.empty()) {
    container_name = "volume";
  }
  std::ostringstream backup_name;
  backup_name << container_name << ".pre_migration.v" << version_hex(current_version) << ".bin";
  auto backup_path = metadata_dir / backup_name.str();

  EnsureSecureParentDirectory(backup_path); // TSK146_Permission_And_Ownership_Issues refuse weak parent perms
  try {
    AtomicReplace(backup_path, std::span<const uint8_t>(blob.data(), blob.size()));
    HardenPrivateFile(backup_path); // TSK146_Permission_And_Ownership_Issues enforce 0600 backup payload
  } catch (const qv::Error& err) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{err.domain(), err.code(),
                    "Failed to persist migration backup"}; // TSK074_Migration_Rollback_and_Backup
  }

  try {
    AtomicReplace(sanitized_container, payload_span);
  } catch (const qv::Error& err) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{err.domain(), err.code(),
                    "Failed to finalize container header update"}; // TSK068_Atomic_Header_Writes uniform messaging
  }
  HardenPrivateFile(sanitized_container); // TSK146_Permission_And_Ownership_Issues keep container private

  std::filesystem::remove(migration_temp, temp_ec); // TSK074_Migration_Rollback_and_Backup best-effort cleanup
  staged_guard.Release();                            // TSK074_Migration_Rollback_and_Backup prevent double remove

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  qv::orchestrator::Event event{}; // TSK033
  event.category = EventCategory::kLifecycle;
  event.severity = EventSeverity::kInfo;
  event.event_id = "volume_migrated";
  event.message = "Volume header format upgraded";
  event.fields.emplace_back("container", qv::PathToUtf8String(sanitized_container), FieldPrivacy::kRedact);
  event.fields.emplace_back("from_version", format_version(current_version), FieldPrivacy::kPublic,
                            true);
  event.fields.emplace_back("to_version", format_version(target_version), FieldPrivacy::kPublic,
                            true);
  qv::orchestrator::EventBus::Instance().Publish(event);

  ConstantTimeMount::VolumeHandle handle{};
  handle.dummy = 1;
  return handle;
}
