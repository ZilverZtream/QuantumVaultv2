#pragma once
// TSK019

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

#include "qv/crypto/sha256.h"

namespace qv::orchestrator {

// TSK019 structured logging primitives
enum class EventSeverity { kDebug, kInfo, kWarning, kError, kCritical };

enum class EventCategory {
  kTelemetry,
  kLifecycle,
  kSecurity,
  kDiagnostics
};

enum class FieldPrivacy { kPublic, kRedact, kHash };

struct EventField {
  std::string key;
  std::string value;
  FieldPrivacy privacy{FieldPrivacy::kPublic};
  bool numeric{false};

  EventField(std::string k, std::string v,
             FieldPrivacy p = FieldPrivacy::kPublic,
             bool is_numeric = false)
      : key(std::move(k)), value(std::move(v)), privacy(p), numeric(is_numeric) {}
};

struct Event {
  EventCategory category{EventCategory::kDiagnostics};
  EventSeverity severity{EventSeverity::kInfo};
  std::string event_id;
  std::string message;
  std::vector<EventField> fields;
};

inline std::string HashForTelemetry(std::string_view input) { // TSK019
  if (input.empty()) {
    return "";
  }
  const auto* data = reinterpret_cast<const uint8_t*>(input.data());
  auto digest = qv::crypto::SHA256_Hash(std::span<const uint8_t>(data, input.size()));
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (uint8_t byte : digest) {
    oss << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

class JsonLineLogger { // TSK019
public:
  JsonLineLogger();
  void Log(const Event& event);

private:
  std::string FormatTimestamp(std::chrono::system_clock::time_point tp);
  std::string Escape(std::string_view text);
  void EnsureOpen();
  void RotateIfNeeded(size_t incoming_bytes);
  std::filesystem::path LogPath() const;

  std::mutex mutex_;
  std::ofstream stream_;
  std::filesystem::path log_path_;
  const size_t max_bytes_ = 512 * 1024; // 512KiB cap for rotation
  const size_t max_files_ = 3;
  size_t dropped_{0};
};

inline JsonLineLogger& DefaultJsonLogger() { // TSK019
  static JsonLineLogger logger;
  return logger;
}

class EventBus { // TSK019
public:
  using Subscriber = std::function<void(const Event&)>;

  static EventBus& Instance();

  void Publish(const Event& event);
  void Subscribe(Subscriber fn);

private:
  EventBus();

  std::vector<Subscriber> subs_;
  std::mutex mutex_;
};

inline JsonLineLogger::JsonLineLogger() { // TSK019
  log_path_ = LogPath();
}

inline std::filesystem::path JsonLineLogger::LogPath() const { // TSK019
  std::filesystem::path logs_dir = std::filesystem::current_path() / "logs";
  std::error_code ec;
  if (!std::filesystem::exists(logs_dir, ec)) {
    std::filesystem::create_directories(logs_dir, ec);
  }
  return logs_dir / "orchestrator.log";
}

inline std::string JsonLineLogger::FormatTimestamp(
    std::chrono::system_clock::time_point tp) { // TSK019
  auto tt = std::chrono::system_clock::to_time_t(tp);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &tt);
#else
  gmtime_r(&tt, &tm);
#endif
  auto fractional =
      std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()) %
      std::chrono::seconds(1);
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
  oss << '.' << std::setw(6) << std::setfill('0') << fractional.count() << 'Z';
  return oss.str();
}

inline std::string JsonLineLogger::Escape(std::string_view text) { // TSK019
  std::string out;
  out.reserve(text.size() + 8);
  for (unsigned char c : text) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          std::ostringstream hex;
          hex << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(c);
          out += hex.str();
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return out;
}

inline void JsonLineLogger::EnsureOpen() { // TSK019
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

inline void JsonLineLogger::RotateIfNeeded(size_t incoming_bytes) { // TSK019
  std::error_code ec;
  auto current_size = std::filesystem::file_size(log_path_, ec);
  if (ec) {
    current_size = 0;
  }
  if (current_size + incoming_bytes <= max_bytes_) {
    return;
  }

  if (stream_.is_open()) {
    stream_.close();
  }

  for (size_t idx = max_files_; idx > 0; --idx) {
    std::filesystem::path src = idx == 1
                                    ? log_path_
                                    : std::filesystem::path(log_path_.string() +
                                                           "." + std::to_string(idx - 1));
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
  stream_.open(log_path_, std::ios::out | std::ios::app);
}

inline void JsonLineLogger::Log(const Event& event) { // TSK019
  std::lock_guard<std::mutex> guard(mutex_);
  EnsureOpen();
  if (!stream_.is_open()) {
    std::clog << "{\"event\":\"logger_error\",\"message\":\"failed to open log file\"}"
              << std::endl;
    return;
  }

  std::ostringstream payload;
  payload << '{';
  payload << "\"ts\":\"" << Escape(FormatTimestamp(std::chrono::system_clock::now()))
          << "\",";
  auto severity_to_string = [](EventSeverity sev) {
    switch (sev) {
      case EventSeverity::kDebug: return "debug";
      case EventSeverity::kInfo: return "info";
      case EventSeverity::kWarning: return "warning";
      case EventSeverity::kError: return "error";
      case EventSeverity::kCritical: return "critical";
    }
    return "info";
  };
  auto category_to_string = [](EventCategory category) {
    switch (category) {
      case EventCategory::kTelemetry: return "telemetry";
      case EventCategory::kLifecycle: return "lifecycle";
      case EventCategory::kSecurity: return "security";
      case EventCategory::kDiagnostics: return "diagnostics";
    }
    return "diagnostics";
  };

  payload << "\"severity\":\"" << severity_to_string(event.severity) << "\",";
  payload << "\"category\":\"" << category_to_string(event.category) << "\"";
  if (!event.event_id.empty()) {
    payload << ",\"event_id\":\"" << Escape(event.event_id) << "\"";
  }
  if (!event.message.empty()) {
    payload << ",\"message\":\"" << Escape(event.message) << "\"";
  }

  for (const auto& field : event.fields) {
    payload << ",\"" << Escape(field.key) << "\":";
    std::string sanitized = field.value;
    if (field.privacy == FieldPrivacy::kRedact) {
      sanitized = "[REDACTED]";
    } else if (field.privacy == FieldPrivacy::kHash) {
      sanitized = HashForTelemetry(sanitized);
    }
    bool numeric = field.numeric && field.privacy == FieldPrivacy::kPublic;
    if (numeric) {
      payload << sanitized;
    } else {
      payload << "\"" << Escape(sanitized) << "\"";
    }
  }
  payload << '}';

  auto line = payload.str();
  RotateIfNeeded(line.size() + 1);
  EnsureOpen();

  std::error_code size_ec;
  auto current_size = std::filesystem::file_size(log_path_, size_ec);
  if (!size_ec && current_size > max_bytes_) {
    ++dropped_;
    if (dropped_ == 1) {
      std::clog << "{\"event\":\"logger_backpressure\",\"dropped\":" << dropped_
                << "}" << std::endl;
    }
    return;
  }

  stream_ << line << '\n';
  stream_.flush();
  dropped_ = 0;
}

inline EventBus::EventBus() = default; // TSK019

inline EventBus& EventBus::Instance() { // TSK019
  static EventBus instance;
  {
    std::lock_guard<std::mutex> guard(instance.mutex_);
    if (instance.subs_.empty()) {
      instance.subs_.push_back([](const Event& e) { DefaultJsonLogger().Log(e); });
    }
  }
  return instance;
}

inline void EventBus::Publish(const Event& event) { // TSK019
  std::vector<Subscriber> targets;
  {
    std::lock_guard<std::mutex> guard(mutex_);
    targets = subs_;
  }
  for (auto& subscriber : targets) {
    if (subscriber) {
      subscriber(event);
    }
  }
}

inline void EventBus::Subscribe(Subscriber fn) { // TSK019
  std::lock_guard<std::mutex> guard(mutex_);
  subs_.push_back(std::move(fn));
}

} // namespace qv::orchestrator
