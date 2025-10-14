#include "qv/orchestrator/event_bus.h"

#include "qv/common.h"                // TSK029
#include "qv/crypto/hmac_sha256.h"     // TSK029

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstdio> // TSK069_DoS_Resource_Exhaustion_Guards bounded escaping helpers
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
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
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace qv::orchestrator {
namespace {

constexpr size_t kHmacSize = qv::crypto::HMAC_SHA256::TAG_SIZE; // TSK029
constexpr int kSyslogFacility = 10;                             // LOG_AUTHPRIV // TSK029
constexpr size_t kMaxEventBytes = 16 * 1024;                    // TSK069_DoS_Resource_Exhaustion_Guards cap serialized size
constexpr auto kSyslogBackoffBase = std::chrono::milliseconds(200); // TSK069_DoS_Resource_Exhaustion_Guards
constexpr auto kSyslogBackoffMax = std::chrono::seconds(30);        // TSK069_DoS_Resource_Exhaustion_Guards

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
                  const std::array<uint8_t, kHmacSize>& previous, uint64_t sequence,
                  std::string_view canonical) { // TSK029
  uint64_t sequence_be = qv::ToBigEndian(sequence);
  std::vector<uint8_t> buffer;
  buffer.reserve(previous.size() + sizeof(sequence_be) + canonical.size());
  buffer.insert(buffer.end(), previous.begin(), previous.end());
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
    if (!AppendWithLimit(payload, ",\"", max_bytes) ||
        !AppendEscapedWithLimit(payload, field.key, max_bytes) ||
        !AppendWithLimit(payload, "\":", max_bytes)) {
      return std::nullopt;
    }
    std::string sanitized = field.value;
    if (field.privacy == FieldPrivacy::kRedact) {
      sanitized = "[REDACTED]"; // TSK029 ensure sensitive data is masked
    } else if (field.privacy == FieldPrivacy::kHash) {
      sanitized = HashForTelemetry(sanitized);
    }
    if (field.numeric && field.privacy == FieldPrivacy::kPublic) {
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
      max_bytes_(ResolveMaxBytes()) { // TSK029
  last_mac_.fill(0);
  EnsureKey();
  std::array<uint8_t, kHmacSize> existing_mac{};
  uint64_t existing_seq = 0;
  if (ParseLog(existing_mac, existing_seq)) {
    last_mac_ = existing_mac;
    entry_counter_ = existing_seq;
  } else {
    std::clog << "{\"event\":\"logger_integrity_failure\",\"message\":\"unable to verify existing audit log\"}"
              << std::endl;
    last_mac_.fill(0);
    entry_counter_ = 0;
  }
}

std::filesystem::path JsonLineLogger::LogPath() const { // TSK029
  std::filesystem::path logs_dir = std::filesystem::current_path() / "logs";
  std::error_code ec;
  if (!std::filesystem::exists(logs_dir, ec)) {
    std::filesystem::create_directories(logs_dir, ec);
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

void JsonLineLogger::EnsureKey() { // TSK029
  if (key_loaded_) {
    return;
  }
  std::error_code ec;
  auto parent = key_path_.parent_path();
  if (!parent.empty() && !std::filesystem::exists(parent, ec)) {
    std::filesystem::create_directories(parent, ec);
  }
  std::ifstream in(key_path_, std::ios::binary);
  if (in) {
    in.read(reinterpret_cast<char*>(hmac_key_.data()), static_cast<std::streamsize>(hmac_key_.size()));
    if (in.gcount() == static_cast<std::streamsize>(hmac_key_.size())) {
      key_loaded_ = true;
      return;
    }
  }
  std::random_device rd;
  std::uniform_int_distribution<int> dist(0, 255);
  for (auto& byte : hmac_key_) {
    byte = static_cast<uint8_t>(dist(rd));
  }
  std::ofstream out(key_path_, std::ios::binary | std::ios::trunc);
  if (!out) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"failed to persist audit key\"}"
              << std::endl;
  } else {
    out.write(reinterpret_cast<const char*>(hmac_key_.data()),
              static_cast<std::streamsize>(hmac_key_.size()));
    out.flush();
  }
  key_loaded_ = true;
}

void JsonLineLogger::EnsureOpen() { // TSK029
  if (stream_.is_open()) {
    return;
  }
  std::error_code ec;
  auto parent = log_path_.parent_path();
  if (!parent.empty() && !std::filesystem::exists(parent, ec)) {
    std::filesystem::create_directories(parent, ec);
  }
  stream_.open(log_path_, std::ios::out | std::ios::app);
}

bool JsonLineLogger::ParseLog(std::array<uint8_t, kHmacSize>& mac, uint64_t& sequence) { // TSK029
  EnsureKey();
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
    auto seq_pos = line_view.find(kSeqMarker.data(), 0, kSeqMarker.size());
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
    uint64_t expected_seq = seq + 1;
    if (parsed_seq != expected_seq) {
      return false;
    }
    std::string canonical(line_view.substr(0, mac_pos));
    canonical.push_back('}');
    auto expected_mac = ComputeChainedMac(hmac_key_, previous, expected_seq, canonical);
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
  std::array<uint8_t, kHmacSize> mac{};
  uint64_t sequence = 0;
  if (!ParseLog(mac, sequence)) {
    return false;
  }
  return sequence == entry_counter_ && mac == last_mac_;
}

void JsonLineLogger::RotateIfNeeded(size_t incoming_bytes) { // TSK029
  std::error_code ec;
  auto current_size = std::filesystem::file_size(log_path_, ec);
  if (ec) {
    current_size = 0;
  }
  if (current_size + incoming_bytes <= max_bytes_) {
    return;
  }
  if (!VerifyLogFile()) {
    std::clog << "{\"event\":\"logger_integrity_failure\",\"message\":\"audit chain verification failed\"}"
              << std::endl;
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
    if (std::filesystem::exists(src, rotate_ec)) {
      std::filesystem::remove(dst, rotate_ec);
      std::filesystem::rename(src, dst, rotate_ec);
    }
  }
  std::filesystem::remove(log_path_, ec);
  stream_.open(log_path_, std::ios::out | std::ios::trunc);
  stream_.close();
}

void JsonLineLogger::Log(const Event& event) { // TSK029
  std::lock_guard<std::mutex> guard(mutex_);
  EnsureKey();
  auto timestamp = FormatTimestamp(std::chrono::system_clock::now());
  auto base = BuildEventJson(event, timestamp, kMaxEventBytes); // TSK069_DoS_Resource_Exhaustion_Guards
  if (!base) {
    Event replacement = BuildOversizeEvent(event); // TSK069_DoS_Resource_Exhaustion_Guards
    base = BuildEventJson(replacement, timestamp, kMaxEventBytes);
    if (!base) {
      return;
    }
  }
  const uint64_t next_sequence = entry_counter_ + 1;
  std::string prefix = base->substr(0, base->size() - 1);
  prefix.append(",\"audit_seq\":");
  prefix.append(std::to_string(next_sequence));
  std::string canonical = prefix;
  canonical.push_back('}');
  auto mac = ComputeChainedMac(hmac_key_, last_mac_, next_sequence, canonical);
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
    ++dropped_;
    if (dropped_ == 1) {
      std::clog << "{\"event\":\"logger_backpressure\",\"dropped\":" << dropped_ << "}"
                << std::endl;
    }
    return;
  }

  stream_ << line << '\n';
  stream_.flush();
  last_mac_ = mac;
  entry_counter_ = next_sequence;
  dropped_ = 0;
}

class SyslogPublisher { // TSK029
 public:
  SyslogPublisher() = default;
  ~SyslogPublisher();

  bool Configure(const std::string& host, uint16_t port, std::string* error);
  void Publish(const Event& event);

 private:
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
  if (!configured_) {
    return;
  }
  const auto timestamp = FormatSyslogTimestamp(std::chrono::system_clock::now()); // TSK035_Platform_Specific_Security_Integration
  auto payload = BuildEventJson(event, timestamp, kMaxEventBytes);                // TSK069_DoS_Resource_Exhaustion_Guards
  if (!payload) {
    auto replacement = BuildOversizeEvent(event); // TSK069_DoS_Resource_Exhaustion_Guards
    payload = BuildEventJson(replacement, timestamp, kMaxEventBytes);
    if (!payload) {
      return;
    }
  }
  auto now = std::chrono::steady_clock::now();
  if (now < next_allowed_send_) { // TSK069_DoS_Resource_Exhaustion_Guards
    return;
  }
  const int pri = kSyslogFacility * 8 + SeverityToSyslog(event.severity);
  std::ostringstream oss;
  oss << '<' << pri << ">1 " << timestamp << ' ' << hostname_ << ' ' << app_name_ << ' '
      << procid_ << ' ' << (event.event_id.empty() ? "-" : event.event_id) << " - " << *payload;
  auto message = oss.str();
#if defined(_WIN32)
  if (socket_ == INVALID_SOCKET) {
    return;
  }
  int sent = ::sendto(socket_, message.c_str(), static_cast<int>(message.size()), 0,
                      reinterpret_cast<const sockaddr*>(&remote_), remote_len_);
  if (sent == SOCKET_ERROR) {
    std::clog << "{\"event\":\"syslog_error\",\"message\":\"sendto failed\"}" << std::endl;
    next_allowed_send_ = now + ComputeBackoff(backoff_exp_);
    backoff_exp_ = std::min<uint32_t>(backoff_exp_ + 1, 16u);
  } else {
    backoff_exp_ = 0;
    next_allowed_send_ = now;
  }
#else
  if (socket_ < 0) {
    return;
  }
  auto sent = ::sendto(socket_, message.c_str(), message.size(), 0,
                       reinterpret_cast<const sockaddr*>(&remote_), remote_len_);
  if (sent < 0) {
    std::clog << "{\"event\":\"syslog_error\",\"message\":\"sendto failed\"}" << std::endl;
    next_allowed_send_ = now + ComputeBackoff(backoff_exp_);
    backoff_exp_ = std::min<uint32_t>(backoff_exp_ + 1, 16u);
  } else {
    backoff_exp_ = 0;
    next_allowed_send_ = now;
  }
#endif
}

EventBus::EventBus() { // TSK029
  subs_.push_back([](const Event& e) { DefaultJsonLogger().Log(e); });
}

EventBus& EventBus::Instance() { // TSK029
  static EventBus instance;
  return instance;
}

void EventBus::Publish(const Event& event) { // TSK029
  std::vector<Subscriber> targets;
  std::shared_ptr<SyslogPublisher> syslog_client;
  {
    std::lock_guard<std::mutex> guard(mutex_);
    targets = subs_;
    syslog_client = syslog_client_;
  }
  for (auto& subscriber : targets) {
    if (subscriber) {
      subscriber(event);
    }
  }
  if (syslog_client) {
    syslog_client->Publish(event);
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
  std::lock_guard<std::mutex> guard(mutex_);
  syslog_client_ = std::move(client);
  return true;
}

} // namespace qv::orchestrator
