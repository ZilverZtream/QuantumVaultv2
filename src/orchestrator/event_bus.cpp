#include "qv/orchestrator/event_bus.h"

#include "qv/common.h"                // TSK029
#include "qv/crypto/hmac_sha256.h"     // TSK029

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <chrono>
#include <cstddef> // TSK081_EventBus_Throughput_and_Batching iterator math
#include <cstdlib>
#include <cstdio> // TSK069_DoS_Resource_Exhaustion_Guards bounded escaping helpers
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator> // TSK079_Audit_Log_Integrity_Chain stream buffer helpers
#include <limits>
#include <memory> // TSK079_Audit_Log_Integrity_Chain smart pointer guards
#include <mutex>
#include <optional> // TSK069_DoS_Resource_Exhaustion_Guards enforce bounded serialization
#include <random>
#include <sstream>
#include <string>
#include <system_error>
#include <span>
#include <vector>

#if defined(_WIN32)
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>   // TSK079_Audit_Log_Integrity_Chain secure DPAPI storage
#include <wincrypt.h>   // TSK079_Audit_Log_Integrity_Chain secure DPAPI storage
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <Security/Security.h> // TSK079_Audit_Log_Integrity_Chain secure keychain usage
#else
#include <sys/utsname.h>       // TSK079_Audit_Log_Integrity_Chain host identity derivation
#endif
#endif

namespace qv::orchestrator {
namespace {

struct EventBusSingletonStorage { // TSK110_Initialization_and_Cleanup_Order manage singleton lifetime
  std::once_flag once;
  std::unique_ptr<EventBus> instance;

  void Reset() { // TSK110_Initialization_and_Cleanup_Order allow deterministic teardown
    instance.reset();
    this->~EventBusSingletonStorage();
    new (this) EventBusSingletonStorage();
  }
};

std::mutex& EventBusSingletonMutex() {
  static std::mutex mutex; // TSK110_Initialization_and_Cleanup_Order synchronize init/reset
  return mutex;
}

EventBusSingletonStorage& EventBusSingleton() {
  static EventBusSingletonStorage storage; // TSK110_Initialization_and_Cleanup_Order lazy container
  return storage;
}

struct PublishReentrancyGuard {  // TSK104_Concurrency_Deadlock_and_Lock_Ordering suppress recursive publish deadlocks
  explicit PublishReentrancyGuard(bool& flag) : flag_(flag) { flag_ = true; }
  ~PublishReentrancyGuard() { flag_ = false; }
  PublishReentrancyGuard(const PublishReentrancyGuard&) = delete;
  PublishReentrancyGuard& operator=(const PublishReentrancyGuard&) = delete;

 private:
  bool& flag_;
};

constexpr size_t kHmacSize = qv::crypto::HMAC_SHA256::TAG_SIZE; // TSK029
constexpr int kSyslogFacility = 10;                             // LOG_AUTHPRIV // TSK029
constexpr size_t kMaxEventBytes = 16 * 1024;                    // TSK069_DoS_Resource_Exhaustion_Guards cap serialized size
constexpr auto kSyslogBackoffBase = std::chrono::milliseconds(200); // TSK069_DoS_Resource_Exhaustion_Guards
constexpr auto kSyslogBackoffMax = std::chrono::seconds(30);        // TSK069_DoS_Resource_Exhaustion_Guards
constexpr uint32_t kStateVersion = 1;                               // TSK079_Audit_Log_Integrity_Chain
constexpr uint32_t kDerivedKeyVersion = 1;                           // TSK079_Audit_Log_Integrity_Chain
constexpr size_t kDerivedSaltSize = 32;                              // TSK079_Audit_Log_Integrity_Chain
constexpr size_t kMaxSyslogDatagramBytes = 8 * 1024;                 // TSK081_EventBus_Throughput_and_Batching UDP safety margin

uint32_t ToBigEndian32(uint32_t value) { // TSK079_Audit_Log_Integrity_Chain portable state encoding
  if (qv::kIsLittleEndian) {
    return qv::detail::ByteSwap32(value);
  }
  return value;
}

uint32_t FromBigEndian32(uint32_t value) { // TSK079_Audit_Log_Integrity_Chain portable state decoding
  if (qv::kIsLittleEndian) {
    return qv::detail::ByteSwap32(value);
  }
  return value;
}

bool AppendWithLimit(std::string& out, std::string_view chunk, size_t limit) { // TSK069_DoS_Resource_Exhaustion_Guards
  if (chunk.size() > limit - out.size()) {
    return false;
  }
  out.append(chunk.data(), chunk.size());
  return true;
}

std::chrono::steady_clock::duration ComputeBackoff(uint32_t exponent) { // TSK069_DoS_Resource_Exhaustion_Guards
  auto clamped = std::min<uint32_t>(exponent, 10u);
  auto scaled = kSyslogBackoffBase * (1u << clamped);
  auto max_ms = std::chrono::duration_cast<std::chrono::milliseconds>(kSyslogBackoffMax);
  auto bounded = std::min(scaled, max_ms);
  return std::chrono::duration_cast<std::chrono::steady_clock::duration>(bounded);
}

struct LoggerStateDisk { // TSK079_Audit_Log_Integrity_Chain durable counter persistence
  uint32_t version_be{0};
  uint32_t reserved{0};
  uint64_t entry_counter_be{0};
  uint64_t dropped_streak_be{0};
  std::array<uint8_t, kHmacSize> last_mac{};
  std::array<uint8_t, kHmacSize> mac{};
};

struct DerivedKeyDisk { // TSK079_Audit_Log_Integrity_Chain derived key salt persistence
  uint32_t version_be{0};
  std::array<uint8_t, kDerivedSaltSize> salt{};
};

std::array<uint8_t, kHmacSize> ComputeStateMac(const std::array<uint8_t, kHmacSize>& key,
                                               uint32_t version, uint64_t entry_counter,
                                               uint64_t dropped_streak,
                                               const std::array<uint8_t, kHmacSize>& last_mac) { // TSK079_Audit_Log_Integrity_Chain
  constexpr std::string_view kLabel = "QV_AUDIT_STATE_V1";
  std::vector<uint8_t> buffer;
  buffer.reserve(kLabel.size() + sizeof(version) + sizeof(entry_counter) + sizeof(dropped_streak) +
                 last_mac.size());
  buffer.insert(buffer.end(), kLabel.begin(), kLabel.end());
  auto version_be = ToBigEndian32(version);
  const auto* version_bytes = reinterpret_cast<const uint8_t*>(&version_be);
  buffer.insert(buffer.end(), version_bytes, version_bytes + sizeof(version_be));
  auto counter_be = qv::ToBigEndian(entry_counter);
  const auto* counter_bytes = reinterpret_cast<const uint8_t*>(&counter_be);
  buffer.insert(buffer.end(), counter_bytes, counter_bytes + sizeof(counter_be));
  auto dropped_be = qv::ToBigEndian(dropped_streak);
  const auto* dropped_bytes = reinterpret_cast<const uint8_t*>(&dropped_be);
  buffer.insert(buffer.end(), dropped_bytes, dropped_bytes + sizeof(dropped_be));
  buffer.insert(buffer.end(), last_mac.begin(), last_mac.end());
  return qv::crypto::HMAC_SHA256::Compute(std::span<const uint8_t>(key.data(), key.size()),
                                          std::span<const uint8_t>(buffer.data(), buffer.size()));
}

#if defined(_WIN32)
bool LoadDpapiProtectedKey(const std::filesystem::path& path,
                           std::array<uint8_t, kHmacSize>& key) { // TSK079_Audit_Log_Integrity_Chain
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  if (blob.empty()) {
    return false;
  }
  DATA_BLOB input{static_cast<DWORD>(blob.size()), blob.data()};
  DATA_BLOB output{};
  if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"dpapi unprotect failed\"}"
              << std::endl;
    return false;
  }
  std::unique_ptr<BYTE, decltype(&LocalFree)> guard(output.pbData, &LocalFree);
  if (output.cbData != key.size()) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"dpapi key length mismatch\"}"
              << std::endl;
    return false;
  }
  std::memcpy(key.data(), output.pbData, key.size());
  return true;
}

bool StoreDpapiProtectedKey(const std::filesystem::path& path,
                            const std::array<uint8_t, kHmacSize>& key) { // TSK079_Audit_Log_Integrity_Chain
  DATA_BLOB input{static_cast<DWORD>(key.size()), const_cast<BYTE*>(key.data())};
  DATA_BLOB output{};
  if (!CryptProtectData(&input, L"QuantumVault Audit", nullptr, nullptr, nullptr, 0, &output)) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"dpapi protect failed\"}"
              << std::endl;
    return false;
  }
  std::unique_ptr<BYTE, decltype(&LocalFree)> guard(output.pbData, &LocalFree);
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"dpapi key write failed\"}"
              << std::endl;
    return false;
  }
  out.write(reinterpret_cast<const char*>(output.pbData), static_cast<std::streamsize>(output.cbData));
  out.flush();
  return static_cast<bool>(out);
}
#elif defined(__APPLE__)
bool LoadKeychainKey(const std::string& service, const std::string& account,
                     std::array<uint8_t, kHmacSize>& key) { // TSK079_Audit_Log_Integrity_Chain
  void* data = nullptr;
  UInt32 length = 0;
  SecKeychainItemRef item = nullptr;
  OSStatus status =
      SecKeychainFindGenericPassword(nullptr, static_cast<UInt32>(service.size()), service.c_str(),
                                     static_cast<UInt32>(account.size()), account.c_str(), &length, &data, &item);
  if (status != errSecSuccess) {
    if (item) {
      CFRelease(item);
    }
    return false;
  }
  std::unique_ptr<char, decltype(&SecKeychainItemFreeContent)> guard(
      reinterpret_cast<char*>(data), [](void* ptr) { SecKeychainItemFreeContent(nullptr, ptr); });
  if (length != key.size()) {
    if (item) {
      CFRelease(item);
    }
    std::clog << "{\"event\":\"logger_error\",\"message\":\"keychain key length mismatch\"}"
              << std::endl;
    return false;
  }
  std::memcpy(key.data(), data, key.size());
  if (item) {
    CFRelease(item);
  }
  return true;
}

bool StoreKeychainKey(const std::string& service, const std::string& account,
                      const std::array<uint8_t, kHmacSize>& key) { // TSK079_Audit_Log_Integrity_Chain
  SecKeychainItemRef item = nullptr;
  OSStatus status =
      SecKeychainFindGenericPassword(nullptr, static_cast<UInt32>(service.size()), service.c_str(),
                                     static_cast<UInt32>(account.size()), account.c_str(), nullptr, nullptr, &item);
  if (status == errSecSuccess && item != nullptr) {
    status = SecKeychainItemModifyAttributesAndData(item, nullptr, static_cast<UInt32>(key.size()), key.data());
    CFRelease(item);
    return status == errSecSuccess;
  }
  if (item) {
    CFRelease(item);
  }
  status = SecKeychainAddGenericPassword(nullptr, static_cast<UInt32>(service.size()), service.c_str(),
                                         static_cast<UInt32>(account.size()), account.c_str(),
                                         static_cast<UInt32>(key.size()), key.data(), nullptr);
  if (status != errSecSuccess) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"keychain store failed\"}"
              << std::endl;
  }
  return status == errSecSuccess;
}
#else
std::optional<std::vector<uint8_t>> ReadMachineSecret() { // TSK079_Audit_Log_Integrity_Chain derived key seed
  constexpr const char* kCandidates[] = {"/etc/machine-id", "/var/lib/dbus/machine-id"};
  for (const char* path : kCandidates) {
    std::ifstream in(path);
    if (!in) {
      continue;
    }
    std::string value;
    std::getline(in, value);
    if (!value.empty()) {
      return std::vector<uint8_t>(value.begin(), value.end());
    }
  }
  struct utsname info {
  };
  if (uname(&info) == 0) {
    std::string node(info.nodename);
    if (!node.empty()) {
      return std::vector<uint8_t>(node.begin(), node.end());
    }
  }
  return std::nullopt;
}

bool DeriveKeyMaterial(const std::array<uint8_t, kDerivedSaltSize>& salt,
                       std::array<uint8_t, kHmacSize>& key) { // TSK079_Audit_Log_Integrity_Chain
  auto secret = ReadMachineSecret();
  if (!secret) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"unable to derive machine secret\"}"
              << std::endl;
    return false;
  }
  constexpr std::string_view kLabel = "QV_AUDIT_DERIVE";
  std::vector<uint8_t> buffer;
  buffer.reserve(kLabel.size() + secret->size() + salt.size());
  buffer.insert(buffer.end(), kLabel.begin(), kLabel.end());
  buffer.insert(buffer.end(), secret->begin(), secret->end());
  buffer.insert(buffer.end(), salt.begin(), salt.end());
  auto digest = qv::crypto::SHA256_Hash(std::span<const uint8_t>(buffer.data(), buffer.size()));
  std::copy(digest.begin(), digest.end(), key.begin());
  return true;
}

bool LoadDerivedKey(const std::filesystem::path& path,
                    std::array<uint8_t, kHmacSize>& key) { // TSK079_Audit_Log_Integrity_Chain
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  DerivedKeyDisk disk{};
  in.read(reinterpret_cast<char*>(&disk), sizeof(disk));
  if (in.gcount() != static_cast<std::streamsize>(sizeof(disk))) {
    return false;
  }
  if (FromBigEndian32(disk.version_be) != kDerivedKeyVersion) {
    return false;
  }
  return DeriveKeyMaterial(disk.salt, key);
}

bool StoreDerivedKey(const std::filesystem::path& path,
                     std::array<uint8_t, kHmacSize>& key) { // TSK079_Audit_Log_Integrity_Chain
  std::random_device rd;
  std::array<uint8_t, kDerivedSaltSize> salt{};
  std::uniform_int_distribution<int> dist(0, 255);
  for (auto& byte : salt) {
    byte = static_cast<uint8_t>(dist(rd));
  }
  if (!DeriveKeyMaterial(salt, key)) {
    return false;
  }
  DerivedKeyDisk disk{};
  disk.version_be = ToBigEndian32(kDerivedKeyVersion);
  disk.salt = salt;
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(&disk), sizeof(disk));
  out.flush();
  return static_cast<bool>(out);
}
#endif

bool AppendEscapedWithLimit(std::string& out, std::string_view text, size_t limit) { // TSK069_DoS_Resource_Exhaustion_Guards
  for (unsigned char c : text) {
    switch (c) {
    case '\\':
      if (!AppendWithLimit(out, "\\\\", limit)) {
        return false;
      }
      break;
    case '"':
      if (!AppendWithLimit(out, "\\\"", limit)) {
        return false;
      }
      break;
    case '\b':
      if (!AppendWithLimit(out, "\\b", limit)) {
        return false;
      }
      break;
    case '\f':
      if (!AppendWithLimit(out, "\\f", limit)) {
        return false;
      }
      break;
    case '\n':
      if (!AppendWithLimit(out, "\\n", limit)) {
        return false;
      }
      break;
    case '\r':
      if (!AppendWithLimit(out, "\\r", limit)) {
        return false;
      }
      break;
    case '\t':
      if (!AppendWithLimit(out, "\\t", limit)) {
        return false;
      }
      break;
    default:
      if (c < 0x20) {
        char buffer[7];
        std::snprintf(buffer, sizeof(buffer), "\\u%04x", static_cast<int>(c));
        if (!AppendWithLimit(out, buffer, limit)) {
          return false;
        }
      } else {
        char plain = static_cast<char>(c);
        if (!AppendWithLimit(out, std::string_view(&plain, 1), limit)) {
          return false;
        }
      }
      break;
    }
  }
  return true;
}

Event BuildOversizeEvent(const Event& original) { // TSK069_DoS_Resource_Exhaustion_Guards redacted fallback
  Event replacement;
  replacement.category = EventCategory::kDiagnostics;
  replacement.severity = EventSeverity::kWarning;
  replacement.event_id = "event_too_large";
  replacement.message = "Event payload exceeded logger limits";
  if (!original.event_id.empty()) {
    replacement.fields.emplace_back("original_event_id", original.event_id, FieldPrivacy::kHash);
  }
  replacement.fields.emplace_back("limit_bytes", std::to_string(kMaxEventBytes), FieldPrivacy::kPublic, true);
  return replacement;
}

std::string EscapeJson(std::string_view text) { // TSK029
  std::string out;
  out.reserve(text.size() + 8);
  for (unsigned char c : text) {
    switch (c) {
    case '\\':
      out += "\\\\";
      break;
    case '"':
      out += "\\\"";
      break;
    case '\b':
      out += "\\b";
      break;
    case '\f':
      out += "\\f";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (c < 0x20) {
        std::ostringstream hex;
        hex << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
        out += hex.str();
      } else {
        out.push_back(static_cast<char>(c));
      }
      break;
    }
  }
  return out;
}

const char* SeverityToString(EventSeverity severity) { // TSK029
  switch (severity) {
  case EventSeverity::kDebug:
    return "debug";
  case EventSeverity::kInfo:
    return "info";
  case EventSeverity::kWarning:
    return "warning";
  case EventSeverity::kError:
    return "error";
  case EventSeverity::kCritical:
    return "critical";
  }
  return "info";
}

const char* CategoryToString(EventCategory category) { // TSK029
  switch (category) {
  case EventCategory::kTelemetry:
    return "telemetry";
  case EventCategory::kLifecycle:
    return "lifecycle";
  case EventCategory::kSecurity:
    return "security";
  case EventCategory::kDiagnostics:
    return "diagnostics";
  }
  return "diagnostics";
}

std::string HexEncode(std::span<const uint8_t> bytes) { // TSK029
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (uint8_t byte : bytes) {
    oss << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

bool HexDecode(std::string_view text, std::span<uint8_t> out) { // TSK029
  if (text.size() != out.size() * 2) {
    return false;
  }
  auto nibble = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
      return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
      return 10 + (ch - 'A');
    }
    return -1;
  };
  for (size_t i = 0; i < out.size(); ++i) {
    const int high = nibble(text[i * 2]);
    const int low = nibble(text[i * 2 + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    out[i] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

std::array<uint8_t, kHmacSize>
ComputeChainedMac(const std::array<uint8_t, kHmacSize>& key,
                  const std::array<uint8_t, kHmacSize>& previous, uint64_t previous_count,
                  uint64_t sequence, std::string_view canonical) { // TSK079_Audit_Log_Integrity_Chain strengthened chaining
  uint64_t sequence_be = qv::ToBigEndian(sequence);
  uint64_t previous_be = qv::ToBigEndian(previous_count);
  std::vector<uint8_t> buffer;
  buffer.reserve(previous.size() + sizeof(sequence_be) + sizeof(previous_be) + canonical.size());
  buffer.insert(buffer.end(), previous.begin(), previous.end());
  const auto* previous_bytes = reinterpret_cast<const uint8_t*>(&previous_be);
  buffer.insert(buffer.end(), previous_bytes, previous_bytes + sizeof(previous_be));
  const auto* seq_bytes = reinterpret_cast<const uint8_t*>(&sequence_be);
  buffer.insert(buffer.end(), seq_bytes, seq_bytes + sizeof(sequence_be));
  const auto* canonical_bytes = reinterpret_cast<const uint8_t*>(canonical.data());
  buffer.insert(buffer.end(), canonical_bytes, canonical_bytes + canonical.size());
  return qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(key.data(), key.size()),
      std::span<const uint8_t>(buffer.data(), buffer.size()));
}

std::optional<std::string> BuildEventJson(const Event& event, const std::string& timestamp, // TSK069_DoS_Resource_Exhaustion_Guards
                                          size_t max_bytes) {
  std::string payload;
  payload.reserve(std::min<size_t>(max_bytes, 256));
  if (!AppendWithLimit(payload, "{\"ts\":\"", max_bytes) ||
      !AppendEscapedWithLimit(payload, timestamp, max_bytes) ||
      !AppendWithLimit(payload, "\"", max_bytes) ||
      !AppendWithLimit(payload, ",\"severity\":\"", max_bytes) ||
      !AppendWithLimit(payload, SeverityToString(event.severity), max_bytes) ||
      !AppendWithLimit(payload, "\"", max_bytes) ||
      !AppendWithLimit(payload, ",\"category\":\"", max_bytes) ||
      !AppendWithLimit(payload, CategoryToString(event.category), max_bytes) ||
      !AppendWithLimit(payload, "\"", max_bytes)) {
    return std::nullopt;
  }
  if (!event.event_id.empty()) {
    if (!AppendWithLimit(payload, ",\"event_id\":\"", max_bytes) ||
        !AppendEscapedWithLimit(payload, event.event_id, max_bytes) ||
        !AppendWithLimit(payload, "\"", max_bytes)) {
      return std::nullopt;
    }
  }
  if (!event.message.empty()) {
    if (!AppendWithLimit(payload, ",\"message\":\"", max_bytes) ||
        !AppendEscapedWithLimit(payload, event.message, max_bytes) ||
        !AppendWithLimit(payload, "\"", max_bytes)) {
      return std::nullopt;
    }
  }
  for (const auto& field : event.fields) {
    auto privacy = field.privacy;
    if (privacy == FieldPrivacy::kPublic) {
      const bool is_sensitive_path =
          (field.key == "container_path" || field.key == "container" ||
           field.key == "plugin_path");
      if (is_sensitive_path) {
        privacy = FieldPrivacy::kHash; // TSK103_Logging_and_Information_Disclosure enforce hashed paths
      }
    }
    if (!AppendWithLimit(payload, ",\"", max_bytes) ||
        !AppendEscapedWithLimit(payload, field.key, max_bytes) ||
        !AppendWithLimit(payload, "\":", max_bytes)) {
      return std::nullopt;
    }
    std::string sanitized = field.value;
    if (privacy == FieldPrivacy::kRedact) {
      sanitized = "[REDACTED]"; // TSK029 ensure sensitive data is masked
    } else if (privacy == FieldPrivacy::kHash) {
      sanitized = HashForTelemetry(sanitized);
    }
    if (field.numeric && privacy == FieldPrivacy::kPublic) {
      if (!AppendWithLimit(payload, sanitized, max_bytes)) {
        return std::nullopt;
      }
    } else {
      if (!AppendWithLimit(payload, "\"", max_bytes) ||
          !AppendEscapedWithLimit(payload, sanitized, max_bytes) ||
          !AppendWithLimit(payload, "\"", max_bytes)) {
        return std::nullopt;
      }
    }
  }
  if (!AppendWithLimit(payload, "}", max_bytes)) {
    return std::nullopt;
  }
  return payload;
}

int SeverityToSyslog(EventSeverity severity) { // TSK029
  switch (severity) {
  case EventSeverity::kDebug:
    return 7;
  case EventSeverity::kInfo:
    return 6;
  case EventSeverity::kWarning:
    return 4;
  case EventSeverity::kError:
    return 3;
  case EventSeverity::kCritical:
    return 2;
  }
  return 6;
}

#if defined(_WIN32)
void EnsureWinsock() { // TSK029
  static std::once_flag once;
  std::call_once(once, []() {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
      std::clog << "{\"event\":\"syslog_error\",\"message\":\"WSAStartup failed\"}"
                << std::endl;
    }
  });
}
#endif

std::string DetectHostname() { // TSK029
#if defined(_WIN32)
  EnsureWinsock();
#endif
  std::array<char, 256> buffer{};
  if (::gethostname(buffer.data(), static_cast<int>(buffer.size())) == 0) {
    buffer.back() = '\0';
    return std::string(buffer.data());
  }
  return "quantumvault";
}

    std::string DetectProcessId() { // TSK029
#if defined(_WIN32)
      return std::to_string(_getpid());
#else
      return std::to_string(static_cast<long long>(::getpid()));
#endif
    }

    std::string FormatSyslogTimestamp(std::chrono::system_clock::time_point tp) { // TSK035_Platform_Specific_Security_Integration
      auto tt = std::chrono::system_clock::to_time_t(tp);
      std::tm tm{};
#if defined(_WIN32)
      gmtime_s(&tm, &tt);
#else
      gmtime_r(&tt, &tm);
#endif
      auto fractional = std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()) %
                        std::chrono::seconds(1);
      std::ostringstream oss;
      oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
      oss << '.' << std::setw(6) << std::setfill('0') << fractional.count() << 'Z';
      return oss.str();
    }

} // namespace

JsonLineLogger::JsonLineLogger()
    : log_path_(LogPath()),
      key_path_(log_path_.string() + ".key"),
      state_path_(log_path_.string() + ".state"),
      max_bytes_(ResolveMaxBytes()) { // TSK079_Audit_Log_Integrity_Chain
  last_mac_.fill(0);
  EnsureKey();
  {
    std::lock_guard<std::mutex> guard(mutex_);
    LoadStateLocked();
  }
  std::array<uint8_t, kHmacSize> existing_mac{};
  uint64_t existing_seq = 0;
  if (ParseLog(existing_mac, existing_seq)) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (state_loaded_) {
      if (existing_seq != entry_counter_ || existing_mac != last_mac_) {
        std::clog << "{\"event\":\"logger_integrity_failure\",\"message\":\"audit chain mismatch\"}"
                  << std::endl;
        integrity_ok_ = false;
      }
    } else {
      last_mac_ = existing_mac;
      entry_counter_ = existing_seq;
      dropped_streak_ = 0;
      state_loaded_ = true;
      PersistStateLocked();
    }
  } else {
    std::clog << "{\"event\":\"logger_integrity_failure\",\"message\":\"unable to verify existing audit log\"}"
              << std::endl;
    std::lock_guard<std::mutex> guard(mutex_);
    integrity_ok_ = false;
    ResetStateLocked();
  }
}

std::filesystem::path JsonLineLogger::LogPath() const { // TSK029
  std::filesystem::path logs_dir = std::filesystem::current_path() / "logs";
  std::error_code ec;
  const bool exists = std::filesystem::exists(logs_dir, ec);
  if (ec) {
    throw Error{ErrorDomain::IO, ec.value(),
                "Failed to query audit log directory " + qv::PathToUtf8String(logs_dir) +
                    ": " + ec.message(),
                ec.value(), qv::Retryability::kTransient}; // TSK109_Error_Code_Handling surface filesystem failure
  }
  if (!exists) {
    std::filesystem::create_directories(logs_dir, ec);
    if (ec) {
      throw Error{ErrorDomain::IO, ec.value(),
                  "Failed to create audit log directory " + qv::PathToUtf8String(logs_dir) +
                      ": " + ec.message(),
                  ec.value(), qv::Retryability::kRetryable}; // TSK109_Error_Code_Handling propagate mkdir errors
    }
  }
  return logs_dir / "orchestrator.log";
}

std::string JsonLineLogger::FormatTimestamp(std::chrono::system_clock::time_point tp) { // TSK029
  auto tt = std::chrono::system_clock::to_time_t(tp);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &tt);
#else
  gmtime_r(&tt, &tm);
#endif
  auto fractional = std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()) %
                    std::chrono::seconds(1);
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
  oss << '.' << std::setw(6) << std::setfill('0') << fractional.count() << 'Z';
  return oss.str();
}

size_t JsonLineLogger::ResolveMaxBytes() const { // TSK029
  const char* env = std::getenv("QV_AUDIT_LOG_MAX_SIZE");
  if (!env || *env == '\0') {
    return 10 * 1024 * 1024; // 10 MiB default
  }
  unsigned long long value = 0;
  auto [ptr, ec] = std::from_chars(env, env + std::strlen(env), value);
  if (ec != std::errc() || ptr != env + std::strlen(env) || value == 0) {
    return 10 * 1024 * 1024;
  }
  return static_cast<size_t>(std::min<unsigned long long>(value, std::numeric_limits<size_t>::max()));
}

void JsonLineLogger::EnsureKey() { // TSK079_Audit_Log_Integrity_Chain hardened key storage
  if (key_loaded_) {
    return;
  }
  std::error_code ec;
  auto parent = key_path_.parent_path();
  if (!parent.empty()) {
    const bool parent_exists = std::filesystem::exists(parent, ec);
    if (ec) {
      std::clog << "{\"event\":\"logger_error\",\"message\":\"audit key directory stat failed\",\"error_code\":"
                << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling surface filesystem error
      integrity_ok_ = false;
      return;
    }
    if (!parent_exists) {
      std::filesystem::create_directories(parent, ec);
      if (ec) {
        std::clog << "{\"event\":\"logger_error\",\"message\":\"audit key directory create failed\",\"error_code\":"
                  << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
        integrity_ok_ = false;
        return;
      }
    }
  }
#if defined(__APPLE__)
  const std::string service = "com.quantumvault.audit";
  const std::string account = qv::PathToUtf8String(log_path_);
#endif
#if defined(_WIN32)
  if (LoadDpapiProtectedKey(key_path_, hmac_key_)) {
    key_loaded_ = true;
    return;
  }
#elif defined(__APPLE__)
  if (LoadKeychainKey(service, account, hmac_key_)) {
    key_loaded_ = true;
    return;
  }
#else
  if (LoadDerivedKey(key_path_, hmac_key_)) {
    key_loaded_ = true;
    return;
  }
#endif

#if defined(_WIN32)
  std::random_device rd;
  std::uniform_int_distribution<int> dist(0, 255);
  for (auto& byte : hmac_key_) {
    byte = static_cast<uint8_t>(dist(rd));
  }
  if (!StoreDpapiProtectedKey(key_path_, hmac_key_)) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"failed to persist audit key\"}"
              << std::endl;
    integrity_ok_ = false;
    return;
  }
#elif defined(__APPLE__)
  std::random_device rd;
  std::uniform_int_distribution<int> dist(0, 255);
  for (auto& byte : hmac_key_) {
    byte = static_cast<uint8_t>(dist(rd));
  }
  if (!StoreKeychainKey(service, account, hmac_key_)) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"failed to store audit key\"}"
              << std::endl;
    integrity_ok_ = false;
    return;
  }
#else
  if (!StoreDerivedKey(key_path_, hmac_key_)) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"failed to persist derived audit key\"}"
              << std::endl;
    integrity_ok_ = false;
    return;
  }
#endif
  key_loaded_ = true;
}

void JsonLineLogger::EnsureOpen() { // TSK029
  if (stream_.is_open()) {
    return;
  }
  std::error_code ec;
  auto parent = log_path_.parent_path();
  if (!parent.empty()) {
    const bool parent_exists = std::filesystem::exists(parent, ec);
    if (ec) {
      std::clog << "{\"event\":\"logger_error\",\"message\":\"audit log directory stat failed\",\"error_code\":"
                << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
      integrity_ok_ = false;
      return;
    }
    if (!parent_exists) {
      std::filesystem::create_directories(parent, ec);
      if (ec) {
        std::clog << "{\"event\":\"logger_error\",\"message\":\"audit log directory create failed\",\"error_code\":"
                  << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
        integrity_ok_ = false;
        return;
      }
    }
  }
  stream_.open(log_path_, std::ios::out | std::ios::app);
}

bool JsonLineLogger::LoadStateLocked() { // TSK079_Audit_Log_Integrity_Chain
  if (!key_loaded_) {
    return false;
  }
  std::ifstream in(state_path_, std::ios::binary);
  if (!in) {
    return false;
  }
  LoggerStateDisk disk{};
  in.read(reinterpret_cast<char*>(&disk), sizeof(disk));
  if (in.gcount() != static_cast<std::streamsize>(sizeof(disk))) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"state file truncated\"}"
              << std::endl;
    integrity_ok_ = false;
    return false;
  }
  const uint32_t version = FromBigEndian32(disk.version_be);
  if (version != kStateVersion) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"state version mismatch\"}"
              << std::endl;
    integrity_ok_ = false;
    return false;
  }
  const uint64_t entry_counter = qv::ToBigEndian(disk.entry_counter_be);
  const uint64_t dropped_streak = qv::ToBigEndian(disk.dropped_streak_be);
  auto expected = ComputeStateMac(hmac_key_, version, entry_counter, dropped_streak, disk.last_mac);
  if (expected != disk.mac) {
    std::clog << "{\"event\":\"logger_integrity_failure\",\"message\":\"state mac mismatch\"}"
              << std::endl;
    integrity_ok_ = false;
    return false;
  }
  entry_counter_ = entry_counter;
  dropped_streak_ = dropped_streak;
  last_mac_ = disk.last_mac;
  state_loaded_ = true;
  return true;
}

void JsonLineLogger::PersistStateLocked() { // TSK079_Audit_Log_Integrity_Chain
  if (!key_loaded_) {
    return;
  }
  LoggerStateDisk disk{};
  disk.version_be = ToBigEndian32(kStateVersion);
  disk.entry_counter_be = qv::ToBigEndian(entry_counter_);
  disk.dropped_streak_be = qv::ToBigEndian(dropped_streak_);
  disk.last_mac = last_mac_;
  disk.mac = ComputeStateMac(hmac_key_, kStateVersion, entry_counter_, dropped_streak_, last_mac_);
  auto parent = state_path_.parent_path();
  std::error_code ec;
  if (!parent.empty()) {
    const bool parent_exists = std::filesystem::exists(parent, ec);
    if (ec) {
      std::clog << "{\"event\":\"logger_error\",\"message\":\"state directory stat failed\",\"error_code\":"
                << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
      return;
    }
    if (!parent_exists) {
      std::filesystem::create_directories(parent, ec);
      if (ec) {
        std::clog << "{\"event\":\"logger_error\",\"message\":\"state directory create failed\",\"error_code\":"
                  << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
        return;
      }
    }
  }
  auto temp = state_path_;
  temp += ".tmp";
  std::ofstream out(temp, std::ios::binary | std::ios::trunc);
  if (!out) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"state write failed\"}"
              << std::endl;
    return;
  }
  out.write(reinterpret_cast<const char*>(&disk), sizeof(disk));
  out.flush();
  if (!out) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"state flush failed\"}"
              << std::endl;
    return;
  }
  std::filesystem::rename(temp, state_path_, ec);
  if (ec) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"state rename failed\",\"error_code\":"
              << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling first rename failure
    std::error_code remove_ec;
    std::filesystem::remove(state_path_, remove_ec);
    if (remove_ec) {
      std::clog << "{\"event\":\"logger_error\",\"message\":\"state remove failed\",\"error_code\":"
                << remove_ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
    }
    ec.clear();
    std::filesystem::rename(temp, state_path_, ec);
    if (ec) {
      std::clog << "{\"event\":\"logger_error\",\"message\":\"state rename failed\",\"error_code\":"
                << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling second rename failure
      std::error_code cleanup_ec;
      std::filesystem::remove(temp, cleanup_ec);
      if (cleanup_ec) {
        std::clog << "{\"event\":\"logger_error\",\"message\":\"state temp cleanup failed\",\"error_code\":"
                  << cleanup_ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling cleanup failure
      }
    }
  }
}

void JsonLineLogger::ResetStateLocked() { // TSK079_Audit_Log_Integrity_Chain
  entry_counter_ = 0;
  dropped_streak_ = 0;
  last_mac_.fill(0);
  state_loaded_ = false;
  std::error_code ec;
  std::filesystem::remove(state_path_, ec);
  if (ec) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"state reset failed\",\"error_code\":"
              << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
  }
}

bool JsonLineLogger::ParseLog(std::array<uint8_t, kHmacSize>& mac, uint64_t& sequence) { // TSK029
  EnsureKey();
  if (!key_loaded_) {
    return false;
  }
  std::ifstream in(log_path_);
  if (!in) {
    mac.fill(0);
    sequence = 0;
    return true;
  }
  std::array<uint8_t, kHmacSize> previous{};
  uint64_t seq = 0;
  std::string line;
  line.reserve(kMaxEventBytes); // TSK069_DoS_Resource_Exhaustion_Guards
  while (true) {
    line.clear();
    bool truncated = false;
    bool saw_char = false;
    bool eof_reached = false;
    while (true) {
      int ch = in.get();
      if (ch == std::char_traits<char>::eof()) {
        if (in.bad()) {
          return false;
        }
        eof_reached = true;
        break;
      }
      saw_char = true;
      if (ch == '\n') {
        break;
      }
      if (!truncated) {
        if (line.size() >= kMaxEventBytes) {
          truncated = true;
        } else {
          line.push_back(static_cast<char>(ch));
        }
      }
    }
    if (!saw_char && eof_reached) {
      break;
    }
    if (truncated) { // TSK069_DoS_Resource_Exhaustion_Guards
      return false;
    }
    if (line.empty()) {
      if (eof_reached) {
        break;
      }
      continue;
    }
    std::string_view line_view(line);
    constexpr std::string_view kMacMarker = ",\"audit_mac\":\"";
    constexpr std::string_view kSeqMarker = "\"audit_seq\":";
    constexpr std::string_view kPrevMarker = "\"audit_prev_count\":";
    auto mac_pos = line_view.find(kMacMarker.data(), 0, kMacMarker.size());
    if (mac_pos == std::string::npos) {
      return false;
    }
    auto mac_start = mac_pos + kMacMarker.size();
    auto mac_end = line_view.find('"', mac_start);
    if (mac_end == std::string::npos) {
      return false;
    }
    std::array<uint8_t, kHmacSize> parsed{};
    if (!HexDecode(line_view.substr(mac_start, mac_end - mac_start), parsed)) {
      return false;
    }
    auto prev_pos = line_view.find(kPrevMarker.data(), 0, kPrevMarker.size());
    if (prev_pos == std::string::npos) {
      return false;
    }
    prev_pos += kPrevMarker.size();
    size_t prev_end = prev_pos;
    while (prev_end < line_view.size() &&
           std::isdigit(static_cast<unsigned char>(line_view[prev_end]))) {
      ++prev_end;
    }
    if (prev_end == prev_pos) {
      return false;
    }
    uint64_t parsed_prev = 0;
    auto [prev_ptr, prev_ec] =
        std::from_chars(line_view.data() + prev_pos, line_view.data() + prev_end, parsed_prev);
    if (prev_ec != std::errc() || prev_ptr != line_view.data() + prev_end) {
      return false;
    }

    auto seq_pos = line_view.find(kSeqMarker.data(), prev_end, kSeqMarker.size());
    if (seq_pos == std::string::npos) {
      return false;
    }
    seq_pos += kSeqMarker.size();
    size_t seq_end = seq_pos;
    while (seq_end < line_view.size() &&
           std::isdigit(static_cast<unsigned char>(line_view[seq_end]))) {
      ++seq_end;
    }
    if (seq_end == seq_pos) {
      return false;
    }
    uint64_t parsed_seq = 0;
    auto [ptr, ec] = std::from_chars(line_view.data() + seq_pos, line_view.data() + seq_end, parsed_seq);
    if (ec != std::errc() || ptr != line_view.data() + seq_end) {
      return false;
    }
    if (parsed_prev != seq) {
      return false;
    }
    uint64_t expected_seq = seq + 1;
    if (parsed_seq != expected_seq) {
      return false;
    }
    std::string canonical(line_view.substr(0, mac_pos));
    canonical.push_back('}');
    auto expected_mac = ComputeChainedMac(hmac_key_, previous, seq, expected_seq, canonical);
    if (expected_mac != parsed) {
      return false;
    }
    previous = expected_mac;
    seq = expected_seq;
    if (eof_reached) {
      break;
    }
  }
  mac = previous;
  sequence = seq;
  return true;
}

bool JsonLineLogger::VerifyLogFile() { // TSK029
  if (!integrity_ok_) {
    return false;
  }
  std::array<uint8_t, kHmacSize> mac{};
  uint64_t sequence = 0;
  if (!ParseLog(mac, sequence)) {
    return false;
  }
  return sequence == entry_counter_ && mac == last_mac_;
}

void JsonLineLogger::RotateIfNeeded(size_t incoming_bytes) { // TSK029
  if (!integrity_ok_) {
    return;
  }
  std::error_code ec;
  auto current_size = std::filesystem::file_size(log_path_, ec);
  if (ec) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"audit log size query failed\",\"error_code\":"
              << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
    current_size = 0;
    ec.clear();
  }
  if (current_size + incoming_bytes <= max_bytes_) {
    return;
  }
  if (!VerifyLogFile()) {
    std::clog << "{\"event\":\"logger_integrity_failure\",\"message\":\"audit chain verification failed\"}"
              << std::endl;
    integrity_ok_ = false;
    ResetStateLocked();
    return;
  }
  if (stream_.is_open()) {
    stream_.close();
  }
  for (size_t idx = max_files_; idx > 0; --idx) {
    std::filesystem::path src =
        idx == 1 ? log_path_ : std::filesystem::path(log_path_.string() + "." + std::to_string(idx - 1));
    std::filesystem::path dst =
        std::filesystem::path(log_path_.string() + "." + std::to_string(idx));
    std::error_code rotate_ec;
    const bool source_exists = std::filesystem::exists(src, rotate_ec);
    if (rotate_ec) {
      std::clog << "{\"event\":\"logger_error\",\"message\":\"audit log rotation stat failed\",\"error_code\":"
                << rotate_ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
      continue;
    }
    if (!source_exists) {
      continue;
    }
    std::filesystem::remove(dst, rotate_ec);
    if (rotate_ec) {
      std::clog << "{\"event\":\"logger_error\",\"message\":\"audit log rotation cleanup failed\",\"error_code\":"
                << rotate_ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
      rotate_ec.clear();
    }
    std::filesystem::rename(src, dst, rotate_ec);
    if (rotate_ec) {
      std::clog << "{\"event\":\"logger_error\",\"message\":\"audit log rotate rename failed\",\"error_code\":"
                << rotate_ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
    }
  }
  std::filesystem::remove(log_path_, ec);
  if (ec) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"audit log truncate failed\",\"error_code\":"
              << ec.value() << "}" << std::endl; // TSK109_Error_Code_Handling
  }
  stream_.open(log_path_, std::ios::out | std::ios::trunc);
  stream_.close();
}

void JsonLineLogger::Log(const Event& event) { // TSK079_Audit_Log_Integrity_Chain synchronized logging
  std::unique_lock<std::mutex> guard(mutex_);
  if (!integrity_ok_) {
    return;
  }
  EnsureKey();
  if (!key_loaded_) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"audit key unavailable\"}"
              << std::endl;
    integrity_ok_ = false;
    return;
  }
  auto timestamp = FormatTimestamp(std::chrono::system_clock::now());
  auto base = BuildEventJson(event, timestamp, kMaxEventBytes); // TSK069_DoS_Resource_Exhaustion_Guards
  if (!base) {
    Event replacement = BuildOversizeEvent(event); // TSK069_DoS_Resource_Exhaustion_Guards
    base = BuildEventJson(replacement, timestamp, kMaxEventBytes);
    if (!base) {
      return;
    }
  }
  const uint64_t previous_count = entry_counter_;
  const uint64_t next_sequence = previous_count + 1;
  std::string prefix = base->substr(0, base->size() - 1);
  prefix.append(",\"audit_prev_count\":");
  prefix.append(std::to_string(previous_count));
  prefix.append(",\"audit_seq\":");
  prefix.append(std::to_string(next_sequence));
  std::string canonical = prefix;
  canonical.push_back('}');
  auto mac = ComputeChainedMac(hmac_key_, last_mac_, previous_count, next_sequence, canonical);
  std::string line = prefix;
  line.append(",\"audit_mac\":\"");
  line.append(HexEncode(std::span<const uint8_t>(mac.data(), mac.size())));
  line.append("\"}");

  RotateIfNeeded(line.size() + 1);
  EnsureOpen();
  if (!stream_.is_open()) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"failed to open log file\"}"
              << std::endl;
    return;
  }

  std::error_code size_ec;
  auto current_size = std::filesystem::file_size(log_path_, size_ec);
  if (!size_ec && current_size > max_bytes_) {
    ++dropped_streak_;
    PersistStateLocked();
    if (dropped_streak_ == 1) {
      std::clog << "{\"event\":\"logger_backpressure\",\"dropped\":" << dropped_streak_ << "}"
                << std::endl;
    }
    return;
  }

  stream_ << line << '\n';
  stream_.flush();
  last_mac_ = mac;
  entry_counter_ = next_sequence;
  dropped_streak_ = 0;
  state_loaded_ = true;
  PersistStateLocked();
}

class SyslogPublisher { // TSK029
 public:
  SyslogPublisher() = default;
  ~SyslogPublisher();

  bool Configure(const std::string& host, uint16_t port, std::string* error);
  void Publish(const Event& event);
  struct PublishStats { // TSK081_EventBus_Throughput_and_Batching batching result
    size_t sent{0};
    std::vector<size_t> unsent_indices; // indices of events needing retry
  };
  PublishStats PublishBatch(std::span<const Event> events); // TSK081_EventBus_Throughput_and_Batching batched sends

 private:
  std::optional<std::string> BuildMessage(const Event& event); // TSK081_EventBus_Throughput_and_Batching serialization helper
  bool SendDatagram(const std::string& payload,
                    std::chrono::steady_clock::time_point attempt_time); // TSK081_EventBus_Throughput_and_Batching IO helper
#if defined(_WIN32)
  SOCKET socket_{INVALID_SOCKET};
#else
  int socket_{-1};
#endif
  sockaddr_storage remote_{};
  socklen_t remote_len_{0};
  bool configured_{false};
  std::string hostname_ = DetectHostname();
  std::string app_name_ = "quantumvault";
  std::string procid_ = DetectProcessId();
  std::chrono::steady_clock::time_point next_allowed_send_{}; // TSK069_DoS_Resource_Exhaustion_Guards
  uint32_t backoff_exp_{0};                                   // TSK069_DoS_Resource_Exhaustion_Guards
};

SyslogPublisher::~SyslogPublisher() { // TSK029
#if defined(_WIN32)
  if (socket_ != INVALID_SOCKET) {
    closesocket(socket_);
    socket_ = INVALID_SOCKET;
  }
#else
  if (socket_ >= 0) {
    ::close(socket_);
    socket_ = -1;
  }
#endif
}

bool SyslogPublisher::Configure(const std::string& host, uint16_t port, std::string* error) { // TSK029
#if defined(_WIN32)
  EnsureWinsock();
#endif
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  auto service = std::to_string(port);
  addrinfo* result = nullptr;
  const int rc = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &result);
  if (rc != 0 || result == nullptr) {
    if (error) {
#if defined(_WIN32)
      *error = "getaddrinfo failed: " + std::to_string(rc);
#else
      *error = std::string("getaddrinfo failed: ") + gai_strerror(rc);
#endif
    }
    return false;
  }
  bool success = false;
  for (addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
#if defined(_WIN32)
    SOCKET sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock == INVALID_SOCKET) {
      continue;
    }
    if (ai->ai_addrlen > sizeof(remote_)) {
      closesocket(sock);
      continue;
    }
    if (socket_ != INVALID_SOCKET) {
      closesocket(socket_);
    }
    socket_ = sock;
#else
    int sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) {
      continue;
    }
    if (ai->ai_addrlen > sizeof(remote_)) {
      ::close(sock);
      continue;
    }
    if (socket_ >= 0) {
      ::close(socket_);
    }
    socket_ = sock;
#endif
    std::memcpy(&remote_, ai->ai_addr, ai->ai_addrlen);
    remote_len_ = static_cast<socklen_t>(ai->ai_addrlen);
    success = true;
    break;
  }
  ::freeaddrinfo(result);
  if (!success) {
    if (error) {
      *error = "failed to initialize syslog endpoint";
    }
#if defined(_WIN32)
    if (socket_ != INVALID_SOCKET) {
      closesocket(socket_);
      socket_ = INVALID_SOCKET;
    }
#else
    if (socket_ >= 0) {
      ::close(socket_);
      socket_ = -1;
    }
#endif
    return false;
  }
  configured_ = true;
  hostname_ = DetectHostname();
  procid_ = DetectProcessId();
  return true;
}

void SyslogPublisher::Publish(const Event& event) { // TSK029
  std::array<Event, 1> single{event}; // TSK081_EventBus_Throughput_and_Batching reuse batching path
  PublishBatch(std::span<const Event>(single.data(), single.size()));
}

std::optional<std::string> SyslogPublisher::BuildMessage(const Event& event) { // TSK081_EventBus_Throughput_and_Batching
  if (!configured_) {
    return std::nullopt;
  }
  const auto timestamp = FormatSyslogTimestamp(std::chrono::system_clock::now()); // TSK035_Platform_Specific_Security_Integration
  auto payload = BuildEventJson(event, timestamp, kMaxEventBytes);                // TSK069_DoS_Resource_Exhaustion_Guards
  if (!payload) {
    auto replacement = BuildOversizeEvent(event); // TSK069_DoS_Resource_Exhaustion_Guards
    payload = BuildEventJson(replacement, timestamp, kMaxEventBytes);
    if (!payload) {
      return std::nullopt;
    }
  }
  const int pri = kSyslogFacility * 8 + SeverityToSyslog(event.severity);
  std::ostringstream oss;
  oss << '<' << pri << ">1 " << timestamp << ' ' << hostname_ << ' ' << app_name_ << ' '
      << procid_ << ' ' << (event.event_id.empty() ? "-" : event.event_id) << " - " << *payload;
  return oss.str();
}

bool SyslogPublisher::SendDatagram(const std::string& payload,
                                   std::chrono::steady_clock::time_point attempt_time) { // TSK081_EventBus_Throughput_and_Batching
#if defined(_WIN32)
  if (socket_ == INVALID_SOCKET) {
    return false;
  }
  int sent = ::sendto(socket_, payload.c_str(), static_cast<int>(payload.size()), 0,
                      reinterpret_cast<const sockaddr*>(&remote_), remote_len_);
  if (sent == SOCKET_ERROR) {
    std::clog << "{\"event\":\"syslog_error\",\"message\":\"sendto failed\"}" << std::endl;
    next_allowed_send_ = attempt_time + ComputeBackoff(backoff_exp_);
    backoff_exp_ = std::min<uint32_t>(backoff_exp_ + 1, 16u);
    return false;
  }
#else
  if (socket_ < 0) {
    return false;
  }
  auto sent = ::sendto(socket_, payload.c_str(), payload.size(), 0,
                       reinterpret_cast<const sockaddr*>(&remote_), remote_len_);
  if (sent < 0) {
    std::clog << "{\"event\":\"syslog_error\",\"message\":\"sendto failed\"}" << std::endl;
    next_allowed_send_ = attempt_time + ComputeBackoff(backoff_exp_);
    backoff_exp_ = std::min<uint32_t>(backoff_exp_ + 1, 16u);
    return false;
  }
#endif
  backoff_exp_ = 0;
  next_allowed_send_ = attempt_time;
  return true;
}

SyslogPublisher::PublishStats SyslogPublisher::PublishBatch(std::span<const Event> events) { // TSK081_EventBus_Throughput_and_Batching
  PublishStats stats;
  if (!configured_ || events.empty()) {
    return stats;
  }

  struct Datagram { // TSK081_EventBus_Throughput_and_Batching buffered packet
    std::string payload;
    std::vector<size_t> indices;
  };

  std::vector<Datagram> datagrams;
  datagrams.reserve(events.size());
  Datagram current;

  for (size_t idx = 0; idx < events.size(); ++idx) {
    auto message = BuildMessage(events[idx]);
    if (!message || message->empty()) {
      continue;
    }
    if (message->size() >= kMaxSyslogDatagramBytes) {
      if (!current.payload.empty()) {
        datagrams.push_back(std::move(current));
        current = Datagram{};
      }
      Datagram single;
      single.payload = std::move(*message);
      single.indices.push_back(idx);
      datagrams.push_back(std::move(single));
      continue;
    }
    if (!current.payload.empty() && current.payload.size() + 1 + message->size() > kMaxSyslogDatagramBytes) {
      datagrams.push_back(std::move(current));
      current = Datagram{};
    }
    if (current.payload.empty()) {
      current.payload = std::move(*message);
    } else {
      current.payload.push_back('\n');
      current.payload.append(*message);
    }
    current.indices.push_back(idx);
  }

  if (!current.payload.empty()) {
    datagrams.push_back(std::move(current));
  }

  if (datagrams.empty()) {
    return stats;
  }

  size_t i = 0;
  for (; i < datagrams.size(); ++i) {
    auto now = std::chrono::steady_clock::now();
    if (now < next_allowed_send_) { // TSK069_DoS_Resource_Exhaustion_Guards reuse backoff
      break;
    }
    if (!SendDatagram(datagrams[i].payload, now)) {
      break;
    }
    stats.sent += datagrams[i].indices.size();
  }

  for (; i < datagrams.size(); ++i) {
    stats.unsent_indices.insert(stats.unsent_indices.end(), datagrams[i].indices.begin(), datagrams[i].indices.end());
  }

  return stats;
}

EventBus::EventBus() { // TSK029
  subs_.push_back([](const Event& e) { DefaultJsonLogger().Log(e); });
  StartDispatcher(); // TSK081_EventBus_Throughput_and_Batching begin async handling
}

EventBus::~EventBus() { // TSK081_EventBus_Throughput_and_Batching
  {
    std::lock_guard<std::mutex> guard(mutex_);
    stop_dispatcher_ = true;
    subs_.clear();                              // TSK110_Initialization_and_Cleanup_Order drop subscribers before join
    pending_syslog_.clear();                    // TSK110_Initialization_and_Cleanup_Order clear queued work
    syslog_client_.reset();                     // TSK110_Initialization_and_Cleanup_Order release transport
  }
  syslog_cv_.notify_all();
  if (dispatcher_thread_.joinable()) {
    dispatcher_thread_.join();
  }
}

void EventBus::StartDispatcher() { // TSK081_EventBus_Throughput_and_Batching
  std::lock_guard<std::mutex> guard(mutex_);
  if (dispatcher_thread_.joinable()) {
    return;
  }
  stop_dispatcher_ = false;
  dispatcher_thread_ = std::thread([this]() { DispatchLoop(); });
}

void EventBus::DispatchLoop() { // TSK081_EventBus_Throughput_and_Batching
  std::unique_lock<std::mutex> lock(mutex_);
  for (;;) {
    syslog_cv_.wait(lock, [this]() {
      return stop_dispatcher_ || (!pending_syslog_.empty() && syslog_client_);
    });
    if (stop_dispatcher_) {
      break;
    }

    auto client = syslog_client_;
    std::vector<Event> batch;
    batch.reserve(kMaxSyslogBatchSize);
    while (!pending_syslog_.empty() && batch.size() < kMaxSyslogBatchSize) {
      batch.push_back(pending_syslog_.front());
      pending_syslog_.pop_front();
    }

    lock.unlock();
    SyslogPublisher::PublishStats stats;
    if (client && !batch.empty()) {
      stats = client->PublishBatch(std::span<const Event>(batch.data(), batch.size()));
    }

    if (!stats.unsent_indices.empty()) {
      std::lock_guard<std::mutex> requeue_lock(mutex_);
      for (auto it = stats.unsent_indices.rbegin(); it != stats.unsent_indices.rend(); ++it) {
        if (*it < batch.size()) {
          pending_syslog_.push_front(batch[*it]);
        }
      }
      if (!stop_dispatcher_) {
        syslog_cv_.notify_one();
      }
    }

    lock.lock();
  }
}

EventBus& EventBus::Instance() { // TSK029
  auto& storage = EventBusSingleton();
  {
    std::lock_guard<std::mutex> guard(EventBusSingletonMutex());
    std::call_once(storage.once, [&storage]() {
      storage.instance = std::make_unique<EventBus>(); // TSK110_Initialization_and_Cleanup_Order lazy init
    });
  }
  return *storage.instance;
}

void EventBus::Publish(const Event& event) { // TSK029
  static thread_local bool in_publish = false;  // TSK104_Concurrency_Deadlock_and_Lock_Ordering detect recursion
  if (in_publish) {
    std::clog << "{\"event\":\"event_bus_reentrancy\",\"message\":\"recursive publish suppressed\"}"
              << std::endl;  // TSK104_Concurrency_Deadlock_and_Lock_Ordering
    return;
  }
  PublishReentrancyGuard guard(in_publish);
  std::vector<Subscriber> targets;
  bool notify_dispatcher = false;                       // TSK081_EventBus_Throughput_and_Batching
  {
    std::lock_guard<std::mutex> guard(mutex_);
    targets = subs_;
    if (syslog_client_) { // TSK081_EventBus_Throughput_and_Batching enqueue for async dispatch
      if (pending_syslog_.size() >= kMaxSyslogQueueDepth) {
        ++dropped_syslog_streak_;
        if (dropped_syslog_streak_ == 1) {
          std::clog << "{\"event\":\"syslog_backpressure\",\"state\":\"drop\",\"count\":"
                    << dropped_syslog_streak_ << "}" << std::endl;
        }
      } else {
        if (dropped_syslog_streak_ > 0) {
          std::clog << "{\"event\":\"syslog_backpressure\",\"state\":\"recover\",\"count\":"
                    << dropped_syslog_streak_ << "}" << std::endl;
        }
        pending_syslog_.push_back(event);
        dropped_syslog_streak_ = 0;
        notify_dispatcher = true;
      }
    }
  }
  for (auto& subscriber : targets) {
    if (subscriber) {
      subscriber(event);
    }
  }
  if (notify_dispatcher) { // TSK081_EventBus_Throughput_and_Batching
    syslog_cv_.notify_one();
  }
}

void EventBus::Subscribe(Subscriber fn) { // TSK029
  std::lock_guard<std::mutex> guard(mutex_);
  subs_.push_back(std::move(fn));
}

bool EventBus::ConfigureSyslog(const std::string& host, uint16_t port, std::string* error) { // TSK029
  auto client = std::make_shared<SyslogPublisher>();
  if (!client->Configure(host, port, error)) {
    return false;
  }
  {
    std::lock_guard<std::mutex> guard(mutex_);
    syslog_client_ = std::move(client);
  }
  StartDispatcher(); // TSK081_EventBus_Throughput_and_Batching ensure worker active
  syslog_cv_.notify_one();
  return true;
}

void ResetEventBusForTesting() { // TSK110_Initialization_and_Cleanup_Order expose deterministic teardown
  auto& storage = EventBusSingleton();
  std::lock_guard<std::mutex> guard(EventBusSingletonMutex());
  storage.Reset();
}

} // namespace qv::orchestrator
