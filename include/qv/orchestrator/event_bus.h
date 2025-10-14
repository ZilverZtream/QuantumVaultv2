#pragma once
// TSK019

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory> // TSK029
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "qv/crypto/hmac_sha256.h" // TSK033 migration tooling reuse
#include "qv/crypto/sha256.h"

namespace qv::orchestrator {

  // TSK019 structured logging primitives
  enum class EventSeverity { kDebug, kInfo, kWarning, kError, kCritical };

  enum class EventCategory { kTelemetry, kLifecycle, kSecurity, kDiagnostics };

  enum class FieldPrivacy { kPublic, kRedact, kHash };

  struct EventField {
    std::string key;
    std::string value;
    FieldPrivacy privacy{FieldPrivacy::kPublic};
    bool numeric{false};

    EventField(std::string k, std::string v, FieldPrivacy p = FieldPrivacy::kPublic,
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
    void EnsureOpen();
    void RotateIfNeeded(size_t incoming_bytes);
    std::filesystem::path LogPath() const;
    void EnsureKey();               // TSK029
    bool VerifyLogFile();           // TSK029
    size_t ResolveMaxBytes() const; // TSK029
    bool ParseLog(std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE>& mac,
                  uint64_t& sequence); // TSK029
    bool LoadStateLocked();                              // TSK079_Audit_Log_Integrity_Chain
    void PersistStateLocked();                           // TSK079_Audit_Log_Integrity_Chain
    void ResetStateLocked();                             // TSK079_Audit_Log_Integrity_Chain

    std::mutex mutex_;
    std::ofstream stream_;
    std::filesystem::path log_path_;
    std::filesystem::path key_path_; // TSK029
    std::filesystem::path state_path_;                   // TSK079_Audit_Log_Integrity_Chain
    size_t max_bytes_;               // TSK029
    const size_t max_files_ = 3;
    uint64_t dropped_streak_{0};                         // TSK079_Audit_Log_Integrity_Chain
    std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> hmac_key_{}; // TSK029
    std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> last_mac_{}; // TSK029
    uint64_t entry_counter_{0};                                         // TSK029
    bool key_loaded_{false};                                            // TSK029
    bool state_loaded_{false};                                          // TSK079_Audit_Log_Integrity_Chain
    bool integrity_ok_{true};                                           // TSK079_Audit_Log_Integrity_Chain
  };

  inline JsonLineLogger& DefaultJsonLogger() { // TSK019
    static JsonLineLogger logger;
    return logger;
  }

  class SyslogPublisher; // TSK029 forward declaration

  class EventBus { // TSK019
  public:
    using Subscriber = std::function<void(const Event&)>;

    static EventBus& Instance();

    void Publish(const Event& event);
    void Subscribe(Subscriber fn);
    bool ConfigureSyslog(const std::string& host, uint16_t port,
                         std::string* error); // TSK029

  private:
    EventBus();

    std::vector<Subscriber> subs_;
    std::mutex mutex_;
    std::shared_ptr<SyslogPublisher> syslog_client_; // TSK029
  };

} // namespace qv::orchestrator
