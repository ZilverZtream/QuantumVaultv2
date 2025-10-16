#pragma once
// TSK019

#include <array>
#include <atomic>             // TSK113_Performance_and_Scalability lock-free subscriber snapshot
#include <chrono>
#include <cstdint>
#include <condition_variable> // TSK081_EventBus_Throughput_and_Batching dispatcher coordination
#include <deque>               // TSK081_EventBus_Throughput_and_Batching queued events
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
#include <thread>             // TSK081_EventBus_Throughput_and_Batching background dispatcher
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

    ~EventBus(); // TSK081_EventBus_Throughput_and_Batching graceful shutdown

  private:
    EventBus();
    void DispatchLoop(); // TSK081_EventBus_Throughput_and_Batching async publisher
    void StartDispatcher(); // TSK081_EventBus_Throughput_and_Batching ensure background thread
    void RefillSyslogTokensLocked(std::chrono::steady_clock::time_point now);      // TSK138_Rate_Limiting_And_DoS_Vulnerabilities token bucket refill
    bool ConsumeSyslogTokenLocked(std::chrono::steady_clock::time_point now);      // TSK138_Rate_Limiting_And_DoS_Vulnerabilities rate limit enforcement

    using SubscriberList = std::vector<Subscriber>;

    std::shared_ptr<const SubscriberList> subscribers_snapshot_;
    std::mutex subscribers_mutex_;
    std::mutex syslog_mutex_;
    std::shared_ptr<SyslogPublisher> syslog_client_; // TSK029
    std::condition_variable syslog_cv_;              // TSK081_EventBus_Throughput_and_Batching queue signaling
    std::deque<Event> pending_syslog_;               // TSK081_EventBus_Throughput_and_Batching buffered events
    std::deque<uint8_t> pending_syslog_attempts_;    // TSK147_Resource_Exhaustion_Attacks retry counters
    std::thread dispatcher_thread_;                  // TSK081_EventBus_Throughput_and_Batching background worker
    bool stop_dispatcher_{false};                    // TSK081_EventBus_Throughput_and_Batching lifecycle guard
    uint64_t dropped_syslog_streak_{0};              // TSK081_EventBus_Throughput_and_Batching backpressure logging
    uint64_t syslog_tokens_{0};                      // TSK138_Rate_Limiting_And_DoS_Vulnerabilities rate bucket state
    std::chrono::steady_clock::time_point syslog_last_token_refill_{}; // TSK138_Rate_Limiting_And_DoS_Vulnerabilities refill watermark
    uint64_t throttled_syslog_streak_{0};            // TSK138_Rate_Limiting_And_DoS_Vulnerabilities throttle logging

    static constexpr size_t kMaxSyslogQueueDepth = 1024; // TSK081_EventBus_Throughput_and_Batching backpressure limit
    static constexpr uint8_t kMaxSyslogRetryAttempts = 6; // TSK147_Resource_Exhaustion_Attacks drop after repeated failures
    static constexpr size_t kMaxSyslogBatchSize = 32;     // TSK081_EventBus_Throughput_and_Batching batch size
  };

  void ResetEventBusForTesting(); // TSK110_Initialization_and_Cleanup_Order test-only teardown

} // namespace qv::orchestrator
