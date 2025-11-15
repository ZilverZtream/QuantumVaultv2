#include "qv/orchestrator/constant_time_mount.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype> // TSK136_Missing_Rate_Limiting_Mount_Attempts client IP normalization
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <semaphore> // TSK236_Mount_Timeout_Bypass_Vulnerability global concurrency guard
#include <iostream>
#include <cstdio>  // TSK901_Security_Hardening FILE handle bridging
#include <limits>   // TSK099_Input_Validation_and_Sanitization checked casts
#include <mutex>
#include <optional> // TSK036_PBKDF2_Argon2_Migration_Path Argon2 TLV tracking
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits> // TSK099_Input_Validation_and_Sanitization checked casts
#include <unordered_map>
#include <vector>
#include <cstdlib> // TSK099_Input_Validation_and_Sanitization container root policy
#if defined(_WIN32)
#include <winsock2.h> // TSK901_Security_Hardening kernel peer fingerprint
#include <ws2tcpip.h> // TSK901_Security_Hardening peer IP decode
#include <io.h>       // TSK901_Security_Hardening descriptor bridge
#else
#include <arpa/inet.h>   // TSK901_Security_Hardening peer IP decode
#include <netinet/in.h>  // TSK901_Security_Hardening peer family
#include <sys/socket.h>  // TSK901_Security_Hardening peer discovery
#include <unistd.h>      // TSK901_Security_Hardening stdio file descriptors
#endif

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX // TSK236_Mount_Timeout_Bypass_Vulnerability prevent macro collisions
#endif
#include <psapi.h>    // TSK236_Mount_Timeout_Bypass_Vulnerability process memory query
#include <windows.h>  // TSK236_Mount_Timeout_Bypass_Vulnerability process timing query
#else
#include <sys/resource.h> // TSK236_Mount_Timeout_Bypass_Vulnerability process usage query
#include <sys/time.h>     // TSK236_Mount_Timeout_Bypass_Vulnerability timeval helpers
#include <sys/stat.h>     // TSK_CRIT_07 hard link aware failure tracking
#endif

#if defined(__SSE2__) || defined(_M_X64) || defined(_M_IX86)
#include <immintrin.h>
#endif

#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/core/nonce.h"
#include "qv/common.h"
#include "qv/crypto/aegis.h"
#include "qv/crypto/ct.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/crypto/pbkdf2.h"  // TSK111_Code_Duplication_and_Maintainability shared PBKDF2
#include "qv/orchestrator/event_bus.h"  // TSK019
#include "qv/orchestrator/ipc_lock.h"   // TSK075_Lockout_Persistence_and_IPC
#include "qv/orchestrator/password_policy.h" // TSK135_Password_Complexity_Enforcement shared policy
#include "qv/errors.h"  // TSK111_Code_Duplication_and_Maintainability centralized errors
#include "qv/tlv/parser.h"  // TSK111_Code_Duplication_and_Maintainability TLV iteration
#include "qv/security/zeroizer.h"
#include "qv/storage/block_device.h"

#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2 // TSK036_PBKDF2_Argon2_Migration_Path
#include <argon2.h>
#endif

using namespace qv::orchestrator;

namespace {

struct HybridKdfResult {                  // TSK070, TSK_CRIT_08_Resource_Leak_DoS_via_Detached_KDF_Thread
  std::array<uint8_t, 32> key{};          // TSK070
  bool success{false};                    // TSK070
};                                        // TSK070

std::string TrimWhitespace(std::string_view input) { // TSK136_Missing_Rate_Limiting_Mount_Attempts
  const auto begin = input.find_first_not_of(" \t\r\n");
  if (begin == std::string_view::npos) {
    return {};
  }
  const auto end = input.find_last_not_of(" \t\r\n");
  return std::string(input.substr(begin, end - begin + 1));
}

std::optional<std::string> NormalizeClientIp(std::string_view raw) { // TSK136_Missing_Rate_Limiting_Mount_Attempts
  auto trimmed = TrimWhitespace(raw);
  if (trimmed.empty()) {
    return std::nullopt;
  }
  if (trimmed.size() > 64) {
    return std::nullopt;
  }
  for (char& ch : trimmed) {
    const unsigned char uch = static_cast<unsigned char>(ch);
    if (std::isdigit(uch) || ch == '.' || ch == ':' || ch == '%' || ch == '-' || ch == '[' ||
        ch == ']') {
      ch = static_cast<char>(std::tolower(uch));
      continue;
    }
    if ((uch >= static_cast<unsigned char>('a') && uch <= static_cast<unsigned char>('f')) ||
        (uch >= static_cast<unsigned char>('A') && uch <= static_cast<unsigned char>('F'))) {
      ch = static_cast<char>(std::tolower(uch));
      continue;
    }
    return std::nullopt;
  }
  return trimmed;
}

std::string HexEncode(std::span<const uint8_t> bytes) { // TSK136_Missing_Rate_Limiting_Mount_Attempts
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output(bytes.size() * 2, '0');
  for (size_t i = 0; i < bytes.size(); ++i) {
    const auto value = bytes[i];
    output[i * 2] = kHex[(value >> 4) & 0xF];
    output[i * 2 + 1] = kHex[value & 0xF];
  }
  return output;
}

std::string HashClientIdentifier(std::string_view normalized) { // TSK136_Missing_Rate_Limiting_Mount_Attempts
  static constexpr std::array<uint8_t, 16> kClientIpSalt = {
      'Q', 'V', 'M', 'O', 'U', 'N', 'T', '_', 'I', 'P', '_', 'H', 'A', 'S', 'H', '1'};
  auto mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(kClientIpSalt.data(), kClientIpSalt.size()),
      std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(normalized.data()),
                               normalized.size()));
  return HexEncode(std::span<const uint8_t>(mac.data(), mac.size()));
}

std::optional<std::string> FingerprintFromSockaddr(const sockaddr_storage& storage) { // TSK901_Security_Hardening
  char buffer[INET6_ADDRSTRLEN] = {};
  std::string literal;
  if (storage.ss_family == AF_INET) {
    auto addr4 = reinterpret_cast<const sockaddr_in*>(&storage);
    if (::inet_ntop(AF_INET, &addr4->sin_addr, buffer, sizeof(buffer)) == nullptr) {
      return std::nullopt;
    }
    literal.assign(buffer);
  } else if (storage.ss_family == AF_INET6) {
    auto addr6 = reinterpret_cast<const sockaddr_in6*>(&storage);
    if (::inet_ntop(AF_INET6, &addr6->sin6_addr, buffer, sizeof(buffer)) == nullptr) {
      return std::nullopt;
    }
    literal.push_back('[');
    literal.append(buffer);
    if (addr6->sin6_scope_id != 0) {
      literal.push_back('%');
      literal.append(std::to_string(addr6->sin6_scope_id));
    }
    literal.push_back(']');
  } else {
    return std::nullopt;
  }
  auto normalized = NormalizeClientIp(literal);
  if (!normalized) {
    return std::nullopt;
  }
  return HashClientIdentifier(*normalized);
}

#if defined(_WIN32)
bool EnsureWinsockInitialized() { // TSK901_Security_Hardening
  static std::once_flag once;
  static bool ready = false;
  std::call_once(once, []() {
    WSADATA data{};
    ready = (::WSAStartup(MAKEWORD(2, 2), &data) == 0);
  });
  return ready;
}

std::optional<std::string> FingerprintFromDescriptor(int fd) { // TSK901_Security_Hardening
  if (fd < 0) {
    return std::nullopt;
  }
  intptr_t handle = _get_osfhandle(fd);
  if (handle == -1) {
    return std::nullopt;
  }
  SOCKET socket_handle = reinterpret_cast<SOCKET>(handle);
  if (socket_handle == INVALID_SOCKET) {
    return std::nullopt;
  }
  sockaddr_storage storage{};
  int length = static_cast<int>(sizeof(storage));
  if (::getpeername(socket_handle, reinterpret_cast<sockaddr*>(&storage), &length) == SOCKET_ERROR) {
    return std::nullopt;
  }
  return FingerprintFromSockaddr(storage);
}
#else
std::optional<std::string> FingerprintFromDescriptor(int fd) { // TSK901_Security_Hardening
  if (fd < 0) {
    return std::nullopt;
  }
  sockaddr_storage storage{};
  socklen_t length = sizeof(storage);
  if (::getpeername(fd, reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
    return std::nullopt;
  }
  return FingerprintFromSockaddr(storage);
}
#endif

std::optional<std::string> ResolveClientFingerprint() { // TSK136_Missing_Rate_Limiting_Mount_Attempts
#if defined(_WIN32)
  if (!EnsureWinsockInitialized()) { // TSK901_Security_Hardening
    return std::nullopt;
  }
  std::array<int, 3> fds = {_fileno(stdin), _fileno(stdout), _fileno(stderr)};
#else
  std::array<int, 3> fds = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
#endif
  for (int fd : fds) {
    auto fingerprint = FingerprintFromDescriptor(fd);
    if (fingerprint) {
      return fingerprint;
    }
  }
  return std::nullopt;
}

void ConstantTimeDelay(std::chrono::nanoseconds duration) { // TSK102_Timing_Side_Channels
  if (duration <= std::chrono::nanoseconds::zero()) {
    std::atomic_signal_fence(std::memory_order_seq_cst);
    return;
  }
  const auto deadline = std::chrono::steady_clock::now() + duration;
  while (std::chrono::steady_clock::now() < deadline) {
#if defined(__SSE2__) || defined(_M_X64) || defined(_M_IX86)
    _mm_pause();
#else
    std::this_thread::yield();
#endif
  }
  std::atomic_signal_fence(std::memory_order_seq_cst);
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
  } else { // destination signed
    if constexpr (std::is_signed_v<From>) {
      const auto promoted = static_cast<long long>(value);
      const auto min_value = static_cast<long long>(ToLimits::min());
      const auto max_value = static_cast<long long>(ToLimits::max());
      if (promoted < min_value || promoted > max_value) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Integer overflow during checked_cast"};
      }
    } else {
      const auto promoted = static_cast<unsigned long long>(value);
      if (promoted > static_cast<unsigned long long>(ToLimits::max())) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Integer overflow during checked_cast"};
      }
    }
  }

  return static_cast<To>(value);
}

void ValidatePassword(const std::string& password) { // TSK135_Password_Complexity_Enforcement centralized enforcement
  EnforcePasswordPolicy(password);
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

std::filesystem::path SanitizeContainerPath(const std::filesystem::path& path) { // TSK099_Input_Validation_and_Sanitization
  std::error_code ec;
  auto canonical = std::filesystem::weakly_canonical(path, ec);
  if (ec) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(qv::errors::msg::kFailedToCanonicalizeContainerPath)};
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
  }
  return canonical;
}

std::filesystem::path LockFilePath(const std::filesystem::path& container) { // TSK026
  auto lock_path = container;
  lock_path += ".locked";
  return lock_path;
}

std::shared_ptr<qv::storage::BlockDevice> MakeBlockDevice(
    const std::filesystem::path& container) { // TSK062_FUSE_Filesystem_Integration_Linux
  std::array<uint8_t, 32> master_key{};
  return std::make_shared<qv::storage::BlockDevice>(
      container, master_key, 0, 0, qv::crypto::CipherType::AES_256_GCM);
}

class WallClockDeadline { // TSK236_Mount_Timeout_Bypass_Vulnerability suspend-aware timeout
public:
  explicit WallClockDeadline(std::chrono::nanoseconds duration)
      : duration_(duration),
        steady_start_(std::chrono::steady_clock::now()),
        system_start_(std::chrono::system_clock::now()),
        first_steady_start_(steady_start_),
        first_system_start_(system_start_),
        deadline_(steady_start_ + duration_) {}

  std::chrono::steady_clock::time_point Deadline() {
    auto steady_now = std::chrono::steady_clock::now();
    auto system_now = std::chrono::system_clock::now();
    AdjustBaseline(steady_now, system_now);
    return deadline_;
  }

  bool Expired() {
    auto steady_now = std::chrono::steady_clock::now();
    auto system_now = std::chrono::system_clock::now();
    AdjustBaseline(steady_now, system_now);
    return steady_now >= deadline_;
  }

  std::chrono::nanoseconds ActiveElapsed() const {
    return std::chrono::steady_clock::now() - steady_start_;
  }

  std::chrono::nanoseconds TotalWallElapsed() const {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now() - first_system_start_);
  }

  std::chrono::steady_clock::time_point Start() const { return first_steady_start_; }

  bool ConsumeSuspendEvent() {
    if (!suspend_detected_) {
      return false;
    }
    suspend_detected_ = false;
    return true;
  }

  std::chrono::nanoseconds LastSuspendGap() const { return last_suspend_gap_; }

private:
  void AdjustBaseline(std::chrono::steady_clock::time_point steady_now,
                      std::chrono::system_clock::time_point system_now) {
    if (system_now < system_start_) {
      Reset(steady_now, system_now, std::chrono::nanoseconds::zero());
      return;
    }
    auto steady_elapsed = steady_now - steady_start_;
    auto system_elapsed = system_now - system_start_;
    if (system_elapsed - steady_elapsed > kSuspendThreshold) {
      Reset(steady_now, system_now, system_elapsed - steady_elapsed);
    }
  }

  void Reset(std::chrono::steady_clock::time_point steady_now,
             std::chrono::system_clock::time_point system_now,
             std::chrono::nanoseconds gap) {
    steady_start_ = steady_now;
    system_start_ = system_now;
    deadline_ = steady_now + duration_;
    suspend_detected_ = gap > std::chrono::nanoseconds::zero();
    last_suspend_gap_ = gap;
  }

  static constexpr std::chrono::nanoseconds kSuspendThreshold{std::chrono::seconds(1)};

  const std::chrono::nanoseconds duration_;
  std::chrono::steady_clock::time_point steady_start_;
  std::chrono::system_clock::time_point system_start_;
  const std::chrono::steady_clock::time_point first_steady_start_;
  const std::chrono::system_clock::time_point first_system_start_;
  std::chrono::steady_clock::time_point deadline_;
  bool suspend_detected_{false};
  std::chrono::nanoseconds last_suspend_gap_{std::chrono::nanoseconds::zero()};
};

constexpr ptrdiff_t kMountConcurrencyLimit = 4; // TSK236_Mount_Timeout_Bypass_Vulnerability global limit

std::counting_semaphore<kMountConcurrencyLimit>& MountConcurrencySemaphore() { // TSK236_Mount_Timeout_Bypass_Vulnerability
  static std::counting_semaphore<kMountConcurrencyLimit> semaphore(kMountConcurrencyLimit);
  return semaphore;
}

class MountConcurrencyGuard { // TSK236_Mount_Timeout_Bypass_Vulnerability enforce concurrency
public:
  explicit MountConcurrencyGuard(WallClockDeadline& deadline) { Acquire(deadline); }

  MountConcurrencyGuard(const MountConcurrencyGuard&) = delete;
  MountConcurrencyGuard& operator=(const MountConcurrencyGuard&) = delete;

  ~MountConcurrencyGuard() {
    if (acquired_) {
      MountConcurrencySemaphore().release();
    }
  }

  bool acquired() const { return acquired_; }

private:
  void Acquire(WallClockDeadline& deadline) {
    auto& semaphore = MountConcurrencySemaphore();
    while (true) {
      auto until = deadline.Deadline();
      if (semaphore.try_acquire_until(until)) {
        acquired_ = true;
        return;
      }
      if (deadline.Expired()) {
        return;
      }
    }
  }

  bool acquired_{false};
};

struct ProcessUsage { // TSK236_Mount_Timeout_Bypass_Vulnerability process resource snapshot
  std::chrono::nanoseconds cpu_time{std::chrono::nanoseconds::zero()};
  uint64_t rss_bytes{0};
};

std::optional<ProcessUsage> QueryProcessUsage() { // TSK236_Mount_Timeout_Bypass_Vulnerability resource monitoring
#if defined(_WIN32)
  FILETIME creation{}, exit{}, kernel{}, user{};
  if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
    return std::nullopt;
  }
  ULARGE_INTEGER kernel_ticks{};
  kernel_ticks.LowPart = kernel.dwLowDateTime;
  kernel_ticks.HighPart = kernel.dwHighDateTime;
  ULARGE_INTEGER user_ticks{};
  user_ticks.LowPart = user.dwLowDateTime;
  user_ticks.HighPart = user.dwHighDateTime;
  auto cpu_duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::duration<long long, std::ratio<1, 10000000>>(kernel_ticks.QuadPart + user_ticks.QuadPart));
  ProcessUsage usage{};
  usage.cpu_time = cpu_duration;
  PROCESS_MEMORY_COUNTERS_EX counters{};
  if (GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
                           sizeof(counters))) {
    usage.rss_bytes = static_cast<uint64_t>(counters.WorkingSetSize);
  }
  return usage;
#else
  struct rusage usage {};
  if (getrusage(RUSAGE_SELF, &usage) != 0) {
    return std::nullopt;
  }
  auto user = std::chrono::seconds(usage.ru_utime.tv_sec) +
              std::chrono::microseconds(usage.ru_utime.tv_usec);
  auto system = std::chrono::seconds(usage.ru_stime.tv_sec) +
                std::chrono::microseconds(usage.ru_stime.tv_usec);
  ProcessUsage result{};
  result.cpu_time = std::chrono::duration_cast<std::chrono::nanoseconds>(user + system);
#if defined(__APPLE__)
  result.rss_bytes = static_cast<uint64_t>(usage.ru_maxrss);
#else
  result.rss_bytes = static_cast<uint64_t>(usage.ru_maxrss) * 1024ull;
#endif
  return result;
#endif
}

class MountResourceMonitor { // TSK236_Mount_Timeout_Bypass_Vulnerability CPU/memory guard
public:
  MountResourceMonitor() : baseline_(QueryProcessUsage()) {
    if (baseline_) {
      last_snapshot_ = *baseline_;
    }
  }

  bool CheckBudget() {
    if (!baseline_) {
      return true;
    }
    auto usage = QueryProcessUsage();
    if (!usage) {
      return true;
    }
    last_snapshot_ = *usage;
    auto cpu_delta = last_snapshot_.cpu_time - baseline_->cpu_time;
    uint64_t memory_delta = 0;
    if (last_snapshot_.rss_bytes > baseline_->rss_bytes) {
      memory_delta = last_snapshot_.rss_bytes - baseline_->rss_bytes;
    }
    cpu_delta_ = cpu_delta;
    memory_delta_ = memory_delta;
    exceeded_ = (cpu_delta_ > kMaxCpuBudget) || (memory_delta_ > kMaxMemoryBudgetBytes);
    return !exceeded_;
  }

  bool exceeded() const { return exceeded_; }
  std::chrono::nanoseconds cpu_delta() const { return cpu_delta_; }
  uint64_t memory_delta() const { return memory_delta_; }
  bool available() const { return baseline_.has_value(); }
  const ProcessUsage& snapshot() const { return last_snapshot_; }

private:
  static constexpr std::chrono::nanoseconds kMaxCpuBudget{std::chrono::seconds(3)};
  static constexpr uint64_t kMaxMemoryBudgetBytes = 256ull * 1024ull * 1024ull; // TSK901_Security_Hardening Argon2 headroom

  std::optional<ProcessUsage> baseline_{};
  ProcessUsage last_snapshot_{};
  bool exceeded_{false};
  std::chrono::nanoseconds cpu_delta_{std::chrono::nanoseconds::zero()};
  uint64_t memory_delta_{0};
};

void PublishMountTimeoutEvent(const std::filesystem::path& container, // TSK236_Mount_Timeout_Bypass_Vulnerability timeout log
                              const WallClockDeadline& deadline,
                              std::string_view stage) {
  qv::orchestrator::Event timeout_event{};
  timeout_event.category = qv::orchestrator::EventCategory::kSecurity;
  timeout_event.severity = qv::orchestrator::EventSeverity::kWarning;
  timeout_event.event_id = "mount_timeout_exceeded";
  timeout_event.message = std::string(qv::errors::msg::kMountAttemptTimeout);
  timeout_event.fields.emplace_back("container_path", qv::PathToUtf8String(container),
                                    qv::orchestrator::FieldPrivacy::kHash);
  timeout_event.fields.emplace_back("stage", std::string(stage),
                                    qv::orchestrator::FieldPrivacy::kPublic, true);
  timeout_event.fields.emplace_back("active_ns", std::to_string(deadline.ActiveElapsed().count()),
                                    qv::orchestrator::FieldPrivacy::kPublic, true);
  timeout_event.fields.emplace_back("wall_ns", std::to_string(deadline.TotalWallElapsed().count()),
                                    qv::orchestrator::FieldPrivacy::kPublic, true);
  qv::orchestrator::EventBus::Instance().Publish(timeout_event);
}

void PublishSuspendEvent(const std::filesystem::path& container, // TSK236_Mount_Timeout_Bypass_Vulnerability suspend log
                         std::chrono::nanoseconds gap) {
  qv::orchestrator::Event suspend_event{};
  suspend_event.category = qv::orchestrator::EventCategory::kTelemetry;
  suspend_event.severity = qv::orchestrator::EventSeverity::kInfo;
  suspend_event.event_id = "mount_timer_reset";
  suspend_event.message = "Mount timeout baseline reset after suspend";
  suspend_event.fields.emplace_back("container_path", qv::PathToUtf8String(container),
                                    qv::orchestrator::FieldPrivacy::kHash);
  suspend_event.fields.emplace_back("suspend_gap_ns", std::to_string(gap.count()),
                                    qv::orchestrator::FieldPrivacy::kPublic, true);
  qv::orchestrator::EventBus::Instance().Publish(suspend_event);
}

void PublishResourceBudgetEvent(const std::filesystem::path& container, // TSK236_Mount_Timeout_Bypass_Vulnerability resource log
                                const MountResourceMonitor& monitor,
                                std::string_view stage) {
  qv::orchestrator::Event resource_event{};
  resource_event.category = qv::orchestrator::EventCategory::kSecurity;
  resource_event.severity = qv::orchestrator::EventSeverity::kWarning;
  resource_event.event_id = "mount_resource_budget_exceeded";
  resource_event.message = "Mount attempt exceeded resource budget";
  resource_event.fields.emplace_back("container_path", qv::PathToUtf8String(container),
                                     qv::orchestrator::FieldPrivacy::kHash);
  resource_event.fields.emplace_back("stage", std::string(stage),
                                     qv::orchestrator::FieldPrivacy::kPublic, true);
  resource_event.fields.emplace_back("cpu_delta_ns", std::to_string(monitor.cpu_delta().count()),
                                     qv::orchestrator::FieldPrivacy::kPublic, true);
  resource_event.fields.emplace_back("memory_delta_bytes", std::to_string(monitor.memory_delta()),
                                     qv::orchestrator::FieldPrivacy::kPublic, true);
  if (monitor.available()) {
    resource_event.fields.emplace_back("rss_bytes", std::to_string(monitor.snapshot().rss_bytes),
                                       qv::orchestrator::FieldPrivacy::kPublic, true);
  }
  qv::orchestrator::EventBus::Instance().Publish(resource_event);
}

void PublishConcurrencyThrottleEvent(const std::filesystem::path& container) { // TSK236_Mount_Timeout_Bypass_Vulnerability concurrency log
  qv::orchestrator::Event throttle_event{};
  throttle_event.category = qv::orchestrator::EventCategory::kSecurity;
  throttle_event.severity = qv::orchestrator::EventSeverity::kWarning;
  throttle_event.event_id = "mount_concurrency_throttled";
  throttle_event.message = "Mount attempt throttled due to concurrency limit";
  throttle_event.fields.emplace_back("container_path", qv::PathToUtf8String(container),
                                     qv::orchestrator::FieldPrivacy::kHash);
  throttle_event.fields.emplace_back("limit", std::to_string(kMountConcurrencyLimit),
                                     qv::orchestrator::FieldPrivacy::kPublic, true);
  qv::orchestrator::EventBus::Instance().Publish(throttle_event);
}

using VolumeUuid = std::array<uint8_t, 16>;                                     // TSK075_Lockout_Persistence_and_IPC

#pragma pack(push, 1)
struct LockFileHeader { // TSK075_Lockout_Persistence_and_IPC
  uint32_t version_le{0};
  uint32_t failures_le{0};
  uint64_t last_attempt_le{0};
  uint32_t locked_le{0};
};
#pragma pack(pop)

static_assert(sizeof(LockFileHeader) == 20, "lock file header layout mismatch"); // TSK075_Lockout_Persistence_and_IPC

#pragma pack(push, 1)
struct GlobalLockFile { // TSK136_Missing_Rate_Limiting_Mount_Attempts
  uint32_t version_le{0};
  uint32_t failures_le{0};
  uint64_t last_attempt_le{0};
  uint32_t locked_le{0};
  uint64_t total_failures_le{0};
};
#pragma pack(pop)

static_assert(sizeof(GlobalLockFile) == 28, "global lock file layout mismatch"); // TSK136

class FailureTracker { // TSK026
public:
  struct FailureState {
    int failures{0};
    bool locked{false};
    std::chrono::seconds enforced_delay{std::chrono::seconds::zero()};
    int global_failures{0};                                             // TSK136_Missing_Rate_Limiting_Mount_Attempts
    std::chrono::seconds global_enforced_delay{std::chrono::seconds::zero()}; // TSK136_Missing_Rate_Limiting_Mount_Attempts
    uint64_t global_total_failures{0};                                  // TSK136_Missing_Rate_Limiting_Mount_Attempts
    int client_failures{0};                                             // TSK136_Missing_Rate_Limiting_Mount_Attempts
    std::chrono::seconds client_enforced_delay{std::chrono::seconds::zero()};  // TSK136
    std::string client_fingerprint;                                     // TSK136
  };

  static FailureTracker& Instance() {
    static FailureTracker tracker;
    return tracker;
  }

  void EnforceDelay(const std::filesystem::path& container,
                    const std::optional<VolumeUuid>& volume_uuid,
                    const std::optional<std::string>& client_fingerprint) {
    const bool have_uuid = volume_uuid.has_value();                               // TSK901_Security_Hardening
    const VolumeUuid uuid = NormalizeUuid(volume_uuid);                           // TSK075_Lockout_Persistence_and_IPC
    auto gate = qv::orchestrator::ScopedIpcLock::ForPath(container);              // TSK075_Lockout_Persistence_and_IPC
    const bool have_gate = gate.locked();                                         // TSK075_Lockout_Persistence_and_IPC
    auto global_gate = qv::orchestrator::ScopedIpcLock::Acquire("qv_mount_global_rate"); // TSK136_Missing_Rate_Limiting_Mount_Attempts
    const bool have_global_gate = global_gate.locked();                           // TSK136
    const auto now = SystemClock::now();

    AttemptState state;
    GlobalState global_snapshot;
    AttemptState client_snapshot;
    bool have_client = false;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      const auto key = BuildAttemptKey(container, uuid, have_uuid); // TSK901_Security_Hardening
      state = LoadAttemptStateLocked(key, container, uuid, now, have_gate);
      global_snapshot = LoadGlobalStateLocked(now, have_global_gate);
      if (client_fingerprint) {
        client_snapshot = LoadClientStateLocked(*client_fingerprint, now);
        have_client = true;
      }
    }

    if (state.locked || global_snapshot.state.locked || (have_client && client_snapshot.locked)) {
      throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                    std::string(qv::errors::msg::kVolumeLocked)}; // TSK026
    }

    if ((!state.have_last_attempt || state.failures <= 0) &&
        (!global_snapshot.state.have_last_attempt || global_snapshot.state.failures <= 0) &&
        (!have_client || !client_snapshot.have_last_attempt || client_snapshot.failures <= 0)) {
      return;
    }

    const auto required_delay = RequiredDelay(state.failures);
    const auto global_delay = RequiredDelay(global_snapshot.state.failures);
    const auto client_delay = have_client ? RequiredDelay(client_snapshot.failures)
                                          : std::chrono::seconds::zero();
    const auto enforced_delay = std::max({required_delay, global_delay, client_delay});
    const auto required_duration = std::chrono::duration_cast<SystemClock::duration>(enforced_delay);
    auto last_attempt = state.have_last_attempt ? state.last_attempt : now;
    if (global_snapshot.state.have_last_attempt &&
        global_snapshot.state.last_attempt > last_attempt) {
      last_attempt = global_snapshot.state.last_attempt;
    }
    if (have_client && client_snapshot.have_last_attempt && client_snapshot.last_attempt > last_attempt) {
      last_attempt = client_snapshot.last_attempt;
    }
    const auto elapsed = now - last_attempt;
    if (elapsed >= required_duration) {
      return;
    }

    const auto remaining_delay = required_duration - elapsed;
    auto message = std::string(qv::errors::msg::kMountRateLimited);                // TSK_CRIT_16
    const auto remaining_seconds =
        std::chrono::duration_cast<std::chrono::seconds>(remaining_delay).count();
    if (remaining_seconds > 0) {
      message.append(" Retry after ");
      message.append(std::to_string(remaining_seconds));
      message.append(" seconds.");
    }
    throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                    std::move(message)};                                          // TSK_CRIT_16
  }

  FailureState RecordAttempt(const std::filesystem::path& container,
                             const std::optional<VolumeUuid>& volume_uuid,
                             bool success,
                             const std::optional<std::string>& client_fingerprint) {
    const bool have_uuid = volume_uuid.has_value();                               // TSK901_Security_Hardening
    const VolumeUuid uuid = NormalizeUuid(volume_uuid);                           // TSK075_Lockout_Persistence_and_IPC
    auto gate = qv::orchestrator::ScopedIpcLock::ForPath(container);              // TSK075_Lockout_Persistence_and_IPC
    const bool have_gate = gate.locked();                                         // TSK075_Lockout_Persistence_and_IPC
    auto global_gate = qv::orchestrator::ScopedIpcLock::Acquire("qv_mount_global_rate"); // TSK136
    const bool have_global_gate = global_gate.locked();                           // TSK136
    const auto now = SystemClock::now();

    FailureState result{};
    AttemptState snapshot{};
    GlobalState global_snapshot{};
    AttemptState client_snapshot{};
    bool have_client_snapshot = false;
    bool should_persist = false;
    bool should_remove = false;
    bool should_persist_global = false;

    {
      std::unique_lock<std::mutex> lock(mutex_);
      const auto key = BuildAttemptKey(container, uuid, have_uuid); // TSK901_Security_Hardening canonical keying
      auto& entry = attempts_[key];
      snapshot = LoadAttemptStateLocked(key, container, uuid, now, have_gate);
      global_snapshot = LoadGlobalStateLocked(now, have_global_gate);
      if (client_fingerprint) {
        client_snapshot = LoadClientStateLocked(*client_fingerprint, now);
        have_client_snapshot = true;
      }

      if (success) {
        attempts_.erase(key);
        if (have_client_snapshot) {
          client_attempts_.erase(*client_fingerprint);
        }
        global_snapshot = ResetGlobalStateLocked(now);
        should_remove = true;
        should_persist_global = have_global_gate;
      } else {
        snapshot.have_last_attempt = true;
        snapshot.last_attempt = now;
        if (snapshot.failures < kMaxAttempts) {
          snapshot.failures += 1;
        }
        if (snapshot.failures >= kMaxAttempts) {
          snapshot.locked = true;
        }
        entry = snapshot;
        IncrementGlobalFailureLocked(now, global_snapshot);
        if (have_client_snapshot) {
          UpdateClientStateLocked(*client_fingerprint, now, client_snapshot);
        }
        result = BuildFailureState(snapshot, global_snapshot,
                                   have_client_snapshot ? std::optional<AttemptState>(client_snapshot)
                                                        : std::nullopt,
                                   client_fingerprint ? *client_fingerprint : std::string{});
        should_persist = true;
        should_persist_global = have_global_gate;
      }
    }

    if (should_remove) {
      if (have_gate) {
        RemovePersistentState(container);
      } else {
        std::error_code ec;
        std::filesystem::remove(LockFilePath(container), ec);
      }
      if (should_persist_global && have_global_gate) {
        PersistGlobalState(global_snapshot);
      }
      return {};
    }

    if (should_persist && have_gate) {
      WritePersistentState(container, uuid, snapshot);
    }

    if (should_persist_global && have_global_gate) {
      PersistGlobalState(global_snapshot);
    }

    return result;
  }

private:
  using SystemClock = std::chrono::system_clock;                                  // TSK075_Lockout_Persistence_and_IPC

  struct AttemptState {
    int failures{0};
    bool locked{false};
    bool have_last_attempt{false};
    SystemClock::time_point last_attempt{};
  };

  struct GlobalState { // TSK136_Missing_Rate_Limiting_Mount_Attempts
    AttemptState state;
    uint64_t total_failures{0};
  };

  struct PersistLoadResult {
    std::optional<AttemptState> state;
    bool tampered{false};
  };

  static constexpr auto kMinDelay = std::chrono::seconds(3);
  static constexpr auto kMaxDelay = std::chrono::hours(4); // TSK138_Rate_Limiting_And_DoS_Vulnerabilities extended backoff horizon
  static constexpr int kMaxAttempts = 5;
  static constexpr uint32_t kLockFileVersion = 1;                                   // TSK075_Lockout_Persistence_and_IPC
  static constexpr uint32_t kGlobalLockFileVersion = 1;                             // TSK136

  AttemptState LoadAttemptStateLocked(const std::string& key,
                                      const std::filesystem::path& container,
                                      const VolumeUuid& uuid,
                                      SystemClock::time_point now,
                                      bool have_gate);
  GlobalState LoadGlobalStateLocked(SystemClock::time_point now, bool have_gate);
  AttemptState LoadClientStateLocked(const std::string& fingerprint, SystemClock::time_point now);
    void IncrementGlobalFailureLocked(SystemClock::time_point now, GlobalState& snapshot);
    GlobalState ResetGlobalStateLocked(SystemClock::time_point now);
  void UpdateClientStateLocked(const std::string& fingerprint, SystemClock::time_point now,
                               AttemptState& snapshot);
  FailureState BuildFailureState(const AttemptState& container_state,
                                 const GlobalState& global_state,
                                 std::optional<AttemptState> client_state,
                                 std::string client_fingerprint) const;
  PersistLoadResult ReadPersistentState(const std::filesystem::path& container,
                                        const VolumeUuid& uuid) const;
  void WritePersistentState(const std::filesystem::path& container,
                            const VolumeUuid& uuid,
                            const AttemptState& state) const;
  void RemovePersistentState(const std::filesystem::path& container) const;
  struct GlobalPersistResult { // TSK136_Missing_Rate_Limiting_Mount_Attempts
    std::optional<GlobalState> state;
    bool tampered{false};
  };
  GlobalPersistResult ReadGlobalState() const;
  void PersistGlobalState(const GlobalState& state) const;
  std::filesystem::path GlobalStatePath() const;

  static VolumeUuid NormalizeUuid(const std::optional<VolumeUuid>& uuid);
  static std::optional<std::string> BuildFileIdentityKey(const std::filesystem::path& container); // TSK_CRIT_07
  static std::string BuildAttemptKey(const std::filesystem::path& container,
                                     const VolumeUuid& uuid,
                                     bool uuid_available); // TSK901_Security_Hardening stable per-volume keys
  static std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> DeriveMacKey(const VolumeUuid& uuid);
  static std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> ComputeLockMac(const LockFileHeader& header,
                                                                               const VolumeUuid& uuid);
  static std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> ComputeGlobalLockMac(
      const GlobalLockFile& header);

  std::chrono::seconds RequiredDelay(int failures) const {
    if (failures <= 0) {
      return kMinDelay;
    }
    auto multiplier = static_cast<int>(1u << std::min(failures, 10));
    auto delay = kMinDelay * multiplier;
    return delay > kMaxDelay ? kMaxDelay : delay;
  }

  std::mutex mutex_;
  std::unordered_map<std::string, AttemptState> attempts_;
  std::unordered_map<std::string, AttemptState> client_attempts_; // TSK136_Missing_Rate_Limiting_Mount_Attempts
  GlobalState global_state_{};                                   // TSK136
  bool global_loaded_{false};                                    // TSK136
};

FailureTracker::AttemptState FailureTracker::LoadAttemptStateLocked(
    const std::string& key, const std::filesystem::path& container, const VolumeUuid& uuid,
    SystemClock::time_point now, bool have_gate) {
  auto& entry = attempts_[key];
  if (have_gate) {
    auto persisted = ReadPersistentState(container, uuid);                       // TSK075_Lockout_Persistence_and_IPC
    if (persisted.tampered) {
      entry.failures = kMaxAttempts;
      entry.locked = true;
      entry.have_last_attempt = true;
      entry.last_attempt = now;
    } else if (persisted.state) {
      entry = *persisted.state;
    }
  }
  if (!entry.have_last_attempt) {
    entry.last_attempt = now;
  }
  return entry;
}

FailureTracker::GlobalState FailureTracker::LoadGlobalStateLocked(SystemClock::time_point now,
                                                                 bool have_gate) {
  if (have_gate) {                                                                  // TSK136_Missing_Rate_Limiting_Mount_Attempts
    auto persisted = ReadGlobalState();
    if (persisted.tampered) {
      global_state_.state.failures = kMaxAttempts;
      global_state_.state.locked = true;
      global_state_.state.have_last_attempt = true;
      global_state_.state.last_attempt = now;
    } else if (persisted.state) {
      global_state_ = *persisted.state;
    } else {
      global_state_ = {};
    }
    global_loaded_ = true;
  } else if (!global_loaded_) {
    global_state_ = {};
    global_loaded_ = true;
  }

  if (!global_state_.state.have_last_attempt) {
    global_state_.state.last_attempt = now;
  }
  return global_state_;
}

FailureTracker::AttemptState FailureTracker::LoadClientStateLocked(const std::string& fingerprint,
                                                                  SystemClock::time_point now) {
  auto& entry = client_attempts_[fingerprint];                                      // TSK136
  if (!entry.have_last_attempt) {
    entry.last_attempt = now;
  }
  return entry;
}

void FailureTracker::IncrementGlobalFailureLocked(SystemClock::time_point now,
                                                  GlobalState& snapshot) {
  global_state_.state.have_last_attempt = true;                                     // TSK136
  global_state_.state.last_attempt = now;
  if (global_state_.state.failures < kMaxAttempts) {
    global_state_.state.failures += 1;
  }
  if (global_state_.state.failures >= kMaxAttempts) {
    global_state_.state.locked = true;
  }
  global_state_.total_failures += 1;
  global_loaded_ = true;
  snapshot = global_state_;
}

FailureTracker::GlobalState FailureTracker::ResetGlobalStateLocked(SystemClock::time_point now) {
  global_state_.state.failures = 0;                                                 // TSK136
  global_state_.state.locked = false;
  global_state_.state.have_last_attempt = true;
  global_state_.state.last_attempt = now;
  global_loaded_ = true;
  return global_state_;
}

void FailureTracker::UpdateClientStateLocked(const std::string& fingerprint,
                                             SystemClock::time_point now,
                                             AttemptState& snapshot) {
  snapshot.have_last_attempt = true;                                                // TSK136
  snapshot.last_attempt = now;
  if (snapshot.failures < kMaxAttempts) {
    snapshot.failures += 1;
  }
  if (snapshot.failures >= kMaxAttempts) {
    snapshot.locked = true;
  }
  client_attempts_[fingerprint] = snapshot;
}

FailureTracker::FailureState FailureTracker::BuildFailureState(const AttemptState& container_state,
                                                              const GlobalState& global_state,
                                                              std::optional<AttemptState> client_state,
                                                              std::string client_fingerprint) const {
  FailureState result{};                                                          // TSK136_Missing_Rate_Limiting_Mount_Attempts
  const auto container_delay =
      (container_state.have_last_attempt && container_state.failures > 0)
          ? RequiredDelay(container_state.failures)
          : std::chrono::seconds::zero();
  const auto global_delay =
      (global_state.state.have_last_attempt && global_state.state.failures > 0)
          ? RequiredDelay(global_state.state.failures)
          : std::chrono::seconds::zero();
  const auto client_delay =
      (client_state && client_state->have_last_attempt && client_state->failures > 0)
          ? RequiredDelay(client_state->failures)
          : std::chrono::seconds::zero();

  result.failures = container_state.failures;
  result.locked = container_state.locked || global_state.state.locked ||
                  (client_state && client_state->locked);
  result.enforced_delay = std::max({container_delay, global_delay, client_delay});
  result.global_failures = global_state.state.failures;
  result.global_enforced_delay = global_delay;
  result.global_total_failures = global_state.total_failures;
  if (client_state) {
    result.client_failures = client_state->failures;
    result.client_enforced_delay = client_delay;
  }
  result.client_fingerprint = std::move(client_fingerprint);
  return result;
}

FailureTracker::PersistLoadResult FailureTracker::ReadPersistentState(
    const std::filesystem::path& container, const VolumeUuid& uuid) const {
  PersistLoadResult result{};
  auto lock_path = LockFilePath(container);
  std::ifstream in(lock_path, std::ios::binary);
  if (!in) {
    return result;
  }

  LockFileHeader header{};
  in.read(reinterpret_cast<char*>(&header), sizeof(header));
  if (static_cast<size_t>(in.gcount()) != sizeof(header)) {
    result.tampered = true;
    return result;
  }

  std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> stored_mac{};
  in.read(reinterpret_cast<char*>(stored_mac.data()), stored_mac.size());
  if (static_cast<size_t>(in.gcount()) != stored_mac.size()) {
    result.tampered = true;
    return result;
  }

  if (qv::FromLittleEndian32(header.version_le) != kLockFileVersion) {
    result.tampered = true;
    return result;
  }

  auto expected_mac = ComputeLockMac(header, uuid);
  if (!std::equal(stored_mac.begin(), stored_mac.end(), expected_mac.begin(), expected_mac.end())) {
    result.tampered = true;
    return result;
  }

  AttemptState state{};
  uint32_t failures = qv::FromLittleEndian32(header.failures_le);
  if (failures > static_cast<uint32_t>(kMaxAttempts)) {
    failures = static_cast<uint32_t>(kMaxAttempts);
  }
  state.failures = static_cast<int>(failures);
  state.locked = qv::FromLittleEndian32(header.locked_le) != 0;
  if (state.locked && state.failures < kMaxAttempts) {
    state.failures = kMaxAttempts;
  }
  uint64_t last_epoch = qv::FromLittleEndian64(header.last_attempt_le);
  if (last_epoch != 0) {
    state.have_last_attempt = true;
    state.last_attempt = SystemClock::time_point(std::chrono::seconds(last_epoch));
  }
  result.state = state;
  return result;
}

void FailureTracker::WritePersistentState(const std::filesystem::path& container,
                                          const VolumeUuid& uuid,
                                          const AttemptState& state) const {
  auto lock_path = LockFilePath(container);
  LockFileHeader header{};
  header.version_le = qv::ToLittleEndian(kLockFileVersion);
  auto failures = static_cast<uint32_t>(std::min(state.failures, kMaxAttempts));
  header.failures_le = qv::ToLittleEndian(failures);
  uint64_t last_epoch = 0;
  if (state.have_last_attempt) {
    last_epoch = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                    state.last_attempt.time_since_epoch())
                    .count());
  }
  header.last_attempt_le = qv::ToLittleEndian64(last_epoch);
  header.locked_le = qv::ToLittleEndian(state.locked ? 1u : 0u);

  auto mac = ComputeLockMac(header, uuid);

  std::ofstream out(lock_path, std::ios::binary | std::ios::trunc);
  if (!out) {
    throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                    std::string(qv::errors::msg::kPersistLockFileFailed)}; // TSK026
  }
  out.write(reinterpret_cast<const char*>(&header), sizeof(header));
  out.write(reinterpret_cast<const char*>(mac.data()), mac.size());
  if (!out) {
    throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                    std::string(qv::errors::msg::kPersistLockFileFailed)}; // TSK026
  }
}

void FailureTracker::RemovePersistentState(const std::filesystem::path& container) const {
  auto lock_path = LockFilePath(container);
  std::error_code ec;
  std::filesystem::remove(lock_path, ec);
}

FailureTracker::GlobalPersistResult FailureTracker::ReadGlobalState() const {
  GlobalPersistResult result{};                                                    // TSK136_Missing_Rate_Limiting_Mount_Attempts
  auto path = GlobalStatePath();
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return result;
  }

  GlobalLockFile header{};
  in.read(reinterpret_cast<char*>(&header), sizeof(header));
  if (static_cast<size_t>(in.gcount()) != sizeof(header)) {
    result.tampered = true;
    return result;
  }

  std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> stored_mac{};
  in.read(reinterpret_cast<char*>(stored_mac.data()), stored_mac.size());
  if (static_cast<size_t>(in.gcount()) != stored_mac.size()) {
    result.tampered = true;
    return result;
  }

  if (qv::FromLittleEndian32(header.version_le) != kGlobalLockFileVersion) {
    result.tampered = true;
    return result;
  }

  auto expected_mac = ComputeGlobalLockMac(header);
  if (!std::equal(stored_mac.begin(), stored_mac.end(), expected_mac.begin(), expected_mac.end())) {
    result.tampered = true;
    return result;
  }

  GlobalState state{};
  uint32_t failures = qv::FromLittleEndian32(header.failures_le);
  if (failures > static_cast<uint32_t>(kMaxAttempts)) {
    failures = static_cast<uint32_t>(kMaxAttempts);
  }
  state.state.failures = static_cast<int>(failures);
  state.state.locked = qv::FromLittleEndian32(header.locked_le) != 0;
  if (state.state.locked && state.state.failures < kMaxAttempts) {
    state.state.failures = kMaxAttempts;
  }
  uint64_t last_epoch = qv::FromLittleEndian64(header.last_attempt_le);
  if (last_epoch != 0) {
    state.state.have_last_attempt = true;
    state.state.last_attempt = SystemClock::time_point(std::chrono::seconds(last_epoch));
  }
  state.total_failures = qv::FromLittleEndian64(header.total_failures_le);
  result.state = state;
  return result;
}

void FailureTracker::PersistGlobalState(const GlobalState& state) const {
  GlobalLockFile header{};                                                         // TSK136_Missing_Rate_Limiting_Mount_Attempts
  header.version_le = qv::ToLittleEndian(kGlobalLockFileVersion);
  header.failures_le = qv::ToLittleEndian(static_cast<uint32_t>(std::min(state.state.failures, kMaxAttempts)));
  uint64_t last_epoch = 0;
  if (state.state.have_last_attempt) {
    last_epoch = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                         state.state.last_attempt.time_since_epoch())
                         .count());
  }
  header.last_attempt_le = qv::ToLittleEndian64(last_epoch);
  header.locked_le = qv::ToLittleEndian(state.state.locked ? 1u : 0u);
  header.total_failures_le = qv::ToLittleEndian64(state.total_failures);

  auto mac = ComputeGlobalLockMac(header);
  auto path = GlobalStatePath();
  auto dir = path.parent_path();                                                   // TSK901_Security_Hardening
  if (!dir.empty()) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
  }
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                    std::string(qv::errors::msg::kPersistLockFileFailed)}; // TSK026, TSK136
  }
  out.write(reinterpret_cast<const char*>(&header), sizeof(header));
  out.write(reinterpret_cast<const char*>(mac.data()), mac.size());
  if (!out) {
    throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                    std::string(qv::errors::msg::kPersistLockFileFailed)}; // TSK026, TSK136
  }
}

std::filesystem::path FailureTracker::GlobalStatePath() const {
#if defined(_WIN32)
  std::filesystem::path base = std::filesystem::path{L"C:\\ProgramData\\QuantumVault"};
#else
  std::filesystem::path base{"/var/run/quantumvault"};
#endif
  return base / ".qv_global_mount.lock";                                          // TSK901_Security_Hardening fixed system path
}

VolumeUuid FailureTracker::NormalizeUuid(const std::optional<VolumeUuid>& uuid) {
  VolumeUuid normalized{};
  if (uuid) {
    normalized = *uuid;
  }
  return normalized;
}

std::optional<std::string> FailureTracker::BuildFileIdentityKey(
    const std::filesystem::path& container) { // TSK_CRIT_07
#if defined(_WIN32)
  HANDLE handle = ::CreateFileW(container.c_str(), 0,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return std::nullopt;
  }
  BY_HANDLE_FILE_INFORMATION info{};
  const BOOL ok = ::GetFileInformationByHandle(handle, &info);
  ::CloseHandle(handle);
  if (!ok) {
    return std::nullopt;
  }
  const uint64_t file_index =
      (static_cast<uint64_t>(info.nFileIndexHigh) << 32) | static_cast<uint64_t>(info.nFileIndexLow);
  std::string key = "fidw:";
  key.append(std::to_string(static_cast<uint64_t>(info.dwVolumeSerialNumber)));
  key.push_back(':');
  key.append(std::to_string(file_index));
  return key;
#else
  struct stat st {
  };
  if (::stat(container.c_str(), &st) != 0) {
    return std::nullopt;
  }
  std::string key = "fid:";
  key.append(std::to_string(static_cast<uint64_t>(st.st_dev)));
  key.push_back(':');
  key.append(std::to_string(static_cast<uint64_t>(st.st_ino)));
  return key;
#endif
}

std::string FailureTracker::BuildAttemptKey(const std::filesystem::path& container,
                                            const VolumeUuid& uuid,
                                            bool uuid_available) {
  const bool usable_uuid = uuid_available &&
                           std::any_of(uuid.begin(), uuid.end(), [](uint8_t byte) { return byte != 0; });
  if (usable_uuid) { // TSK901_Security_Hardening prefer immutable volume identity
    std::string key{"uuid:"};
    key.append(HexEncode(std::span<const uint8_t>(uuid.data(), uuid.size())));
    return key;
  }
  auto identity_key = BuildFileIdentityKey(container);                             // TSK901_Security_Hardening fallback
  if (!identity_key) {
    throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                    std::string(qv::errors::msg::kContainerIdentityUnavailable)}; // TSK901_Security_Hardening
  }
  return *identity_key;
}

std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> FailureTracker::DeriveMacKey(
    const VolumeUuid& uuid) {
  static constexpr std::array<uint8_t, 16> kMacSalt = {'Q', 'V', 'L', 'O', 'C', 'K', '_', 'H',
                                                       'M', 'A', 'C', '_', 'S', 'A', 'L', 'T'}; // TSK075_Lockout_Persistence_and_IPC
  return qv::crypto::HMAC_SHA256::Compute(std::span<const uint8_t>(kMacSalt.data(), kMacSalt.size()),
                                          std::span<const uint8_t>(uuid.data(), uuid.size()));
}

std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> FailureTracker::ComputeLockMac(
    const LockFileHeader& header, const VolumeUuid& uuid) {
  auto key = DeriveMacKey(uuid);
  auto header_bytes = qv::AsBytesConst(header);
  std::vector<uint8_t> message;
  message.reserve(header_bytes.size() + uuid.size());
  message.insert(message.end(), header_bytes.begin(), header_bytes.end());
  message.insert(message.end(), uuid.begin(), uuid.end());
  return qv::crypto::HMAC_SHA256::Compute(std::span<const uint8_t>(key.data(), key.size()),
                                          std::span<const uint8_t>(message.data(), message.size()));
}

std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> FailureTracker::ComputeGlobalLockMac(
    const GlobalLockFile& header) {
  static constexpr std::array<uint8_t, 16> kGlobalMacSalt = {
      'Q', 'V', 'G', 'L', 'O', 'B', 'A', 'L', '_', 'L', 'O', 'C', 'K', '_', 'M', '1'}; // TSK136
  return qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(kGlobalMacSalt.data(), kGlobalMacSalt.size()),
      qv::AsBytesConst(header));
}

// TSK004, TSK013
constexpr std::array<uint8_t, 8> kHeaderMagic = {'Q','V','A','U','L','T','\0','\0'};
constexpr uint32_t kHeaderVersion = 0x00040101;   // TSK013, TSK068_Atomic_Header_Writes durability bump
constexpr uint32_t kFallbackIterations = 4096;
constexpr uint64_t kMinTargetNs = std::chrono::milliseconds(75).count();
constexpr uint64_t kConfiguredP99Ns = std::chrono::milliseconds(160).count();
constexpr uint64_t kPaddingSlackNs = std::chrono::milliseconds(2).count();
constexpr uint64_t kHistogramBucketNs = 1'000'000; // 1ms buckets
constexpr size_t kHistogramBuckets = 512;
constexpr uint64_t kLogIntervalNs = std::chrono::seconds(2).count();
// TSK112_Documentation_and_Code_Clarity: TLV type identifiers (little-endian) mirror the
// serialized header layout. The inline notes record the semantic payload each tag carries to
// avoid treating these values as unexplained magic numbers.
constexpr uint16_t kTlvTypePbkdf2 = 0x1001;                                     // Password-based KDF parameters // TSK112
constexpr uint16_t kTlvTypeHybridSalt = 0x1002;                                 // PQC hybrid KDF salt // TSK112
constexpr uint16_t kTlvTypeArgon2 = 0x1003;                                     // Argon2id KDF parameters // TSK112
constexpr uint16_t kTlvTypeEpoch = 0x4E4F;                                      // 'NO' nonce/epoch counter // TSK112
constexpr uint16_t kTlvTypePqc = 0x7051;                                        // 'pQ' post-quantum KEM blob // TSK112
constexpr uint16_t kTlvTypeReservedV2 = 0x7F02;                                 // Reserved V2 payload slot // TSK112
constexpr size_t kPbkdfSaltSize = 16;
constexpr size_t kHybridSaltSize = 32;
constexpr size_t kHeaderMacSize = qv::crypto::HMAC_SHA256::TAG_SIZE;
constexpr size_t kMaxTlvPayloadBytes = 64 * 1024 - 1;                           // TSK095_Memory_Safety_and_Buffer_Bounds
static_assert(kMaxTlvPayloadBytes < 64 * 1024, "TLV payload limit too large"); // TSK095_Memory_Safety_and_Buffer_Bounds
constexpr size_t kMaxHeaderTlvs = 16;                                            // TSK138_Rate_Limiting_And_DoS_Vulnerabilities bound parsing fan-out

#pragma pack(push, 1)
struct VolumeHeader { // TSK013
  std::array<uint8_t, 8> magic{};
  uint32_t version{};
  std::array<uint8_t, 16> uuid{};
  uint32_t flags{};
};

struct ReservedV2Tlv { // TSK013
  uint16_t type = qv::ToLittleEndian16(kTlvTypeReservedV2);
  uint16_t length = qv::ToLittleEndian16(32);
  std::array<uint8_t, 32> payload{};
};
#pragma pack(pop)

static_assert(sizeof(VolumeHeader) == 32, "unexpected volume header size");        // TSK013
static_assert(sizeof(ReservedV2Tlv) == 36, "reserved TLV size mismatch");          // TSK013

constexpr size_t kPasswordTlvBytes =
    4 + std::max<size_t>(4 + kPbkdfSaltSize, sizeof(uint32_t) * 6 + kPbkdfSaltSize); // TSK036_PBKDF2_Argon2_Migration_Path

constexpr size_t kSerializedHeaderBytes = sizeof(VolumeHeader) + kPasswordTlvBytes +
                                          4 + kHybridSaltSize + sizeof(qv::core::EpochTLV) +
                                          sizeof(qv::core::PQC_KEM_TLV) + sizeof(ReservedV2Tlv); // TSK013
constexpr size_t kTotalHeaderBytes = kSerializedHeaderBytes + kHeaderMacSize;       // TSK013

enum class PasswordKdf { // TSK036_PBKDF2_Argon2_Migration_Path, TSK220
  kPbkdf2,
  kArgon2id
};

struct Argon2Config { // TSK036_PBKDF2_Argon2_Migration_Path
  uint32_t version{1};
  uint32_t time_cost{3};
  uint32_t memory_cost_kib{64u * 1024u};
  uint32_t parallelism{4};
  uint32_t hash_length{32};
  uint32_t target_ms{500};
  std::array<uint8_t, kPbkdfSaltSize> salt{};
};

struct ParsedHeader { // TSK013
  VolumeHeader header{};
  uint32_t version{0};
  uint32_t flags{0};
  std::array<uint8_t, kPbkdfSaltSize> pbkdf_salt{};
  uint32_t pbkdf_iterations{kFallbackIterations};
  std::array<uint8_t, kHybridSaltSize> hybrid_salt{};
  uint32_t epoch{0};
  std::array<uint8_t, sizeof(qv::core::EpochTLV)> epoch_tlv_bytes{};
  qv::core::PQC_KEM_TLV pqc{};
  Argon2Config argon2{};                 // TSK036_PBKDF2_Argon2_Migration_Path
  PasswordKdf algorithm{PasswordKdf::kPbkdf2}; // TSK036_PBKDF2_Argon2_Migration_Path
  bool have_pbkdf{false};
  bool have_argon2{false};              // TSK036_PBKDF2_Argon2_Migration_Path
  bool have_hybrid{false};
  bool have_epoch{false};
  bool have_pqc{false};
  bool valid{false};
};

ParsedHeader ParseHeader(std::span<const uint8_t> bytes) { // TSK013
  ParsedHeader parsed{};
  if (bytes.size() < sizeof(VolumeHeader)) {
    return parsed;
  }

  std::memcpy(&parsed.header, bytes.data(), sizeof(VolumeHeader));

  bool magic_ok = qv::crypto::ct::CompareEqual(parsed.header.magic, kHeaderMagic);
  parsed.version = qv::FromLittleEndian32(parsed.header.version);
  parsed.flags = qv::FromLittleEndian32(parsed.header.flags);
  bool version_ok = parsed.version == kHeaderVersion;

  const size_t offset = sizeof(VolumeHeader);
  bool parse_ok = offset <= bytes.size();
  if (!parse_ok) {
    parsed.valid = false;
    return parsed;
  }

  qv::tlv::Parser parser(bytes.subspan(offset), kMaxHeaderTlvs, kMaxTlvPayloadBytes); // TSK138_Rate_Limiting_And_DoS_Vulnerabilities tighten TLV bound
  if (!parser.valid()) {
    parsed.valid = false;
    return parsed;
  }

  size_t processed_records = 0;                                                   // TSK138_Rate_Limiting_And_DoS_Vulnerabilities
  for (const auto& record : parser) {
    if (++processed_records > kMaxHeaderTlvs) {
      parse_ok = false;
      break;
    }
    switch (record.type) {
      case kTlvTypePbkdf2: {
        const size_t expected = sizeof(uint32_t) + kPbkdfSaltSize;
        if (record.value.size() != expected) {
          parse_ok = false;
          break;
        }
        uint32_t iter_le = 0;
        std::memcpy(&iter_le, record.value.data(), sizeof(iter_le));
        parsed.pbkdf_iterations = qv::FromLittleEndian32(iter_le);
        std::copy_n(record.value.data() + sizeof(uint32_t), kPbkdfSaltSize,
                    parsed.pbkdf_salt.begin());
        if (parsed.pbkdf_iterations == 0 || parsed.pbkdf_iterations >= (1u << 24)) {
          parsed.pbkdf_iterations = kFallbackIterations;
        } else {
          parsed.have_pbkdf = true;
        }
        parsed.algorithm = PasswordKdf::kPbkdf2;
        break;
      }
      case kTlvTypeArgon2: {
        constexpr size_t expected = sizeof(uint32_t) * 6 + kPbkdfSaltSize;
        if (record.value.size() != expected) {
          parse_ok = false;
          break;
        }
        std::memcpy(&parsed.argon2.version, record.value.data(), sizeof(uint32_t));
        std::memcpy(&parsed.argon2.time_cost, record.value.data() + sizeof(uint32_t), sizeof(uint32_t));
        std::memcpy(&parsed.argon2.memory_cost_kib,
                    record.value.data() + sizeof(uint32_t) * 2, sizeof(uint32_t));
        std::memcpy(&parsed.argon2.parallelism,
                    record.value.data() + sizeof(uint32_t) * 3, sizeof(uint32_t));
        std::memcpy(&parsed.argon2.hash_length,
                    record.value.data() + sizeof(uint32_t) * 4, sizeof(uint32_t));
        std::memcpy(&parsed.argon2.target_ms,
                    record.value.data() + sizeof(uint32_t) * 5, sizeof(uint32_t));
        std::memcpy(parsed.argon2.salt.data(),
                    record.value.data() + sizeof(uint32_t) * 6, parsed.argon2.salt.size());
        parsed.argon2.version = qv::FromLittleEndian32(parsed.argon2.version);
        parsed.argon2.time_cost = qv::FromLittleEndian32(parsed.argon2.time_cost);
        parsed.argon2.memory_cost_kib = qv::FromLittleEndian32(parsed.argon2.memory_cost_kib);
        parsed.argon2.parallelism = qv::FromLittleEndian32(parsed.argon2.parallelism);
        parsed.argon2.hash_length = qv::FromLittleEndian32(parsed.argon2.hash_length);
        parsed.argon2.target_ms = qv::FromLittleEndian32(parsed.argon2.target_ms);
        std::copy(parsed.argon2.salt.begin(), parsed.argon2.salt.end(), parsed.pbkdf_salt.begin());
        parsed.have_argon2 = true;
        parsed.algorithm = PasswordKdf::kArgon2id;
        break;
      }
      case kTlvTypeHybridSalt: {
        if (record.value.size() != kHybridSaltSize) {
          parse_ok = false;
          break;
        }
        std::copy_n(record.value.data(), kHybridSaltSize, parsed.hybrid_salt.begin());
        parsed.have_hybrid = true;
        break;
      }
      case kTlvTypeEpoch: {
        if (record.value.size() != sizeof(uint32_t)) {
          parse_ok = false;
          break;
        }
        uint32_t epoch_le = 0;
        std::memcpy(&epoch_le, record.value.data(), sizeof(epoch_le));
        parsed.epoch = qv::FromLittleEndian32(epoch_le);
        parsed.have_epoch = true;
        qv::core::EpochTLV epoch_tlv{};
        epoch_tlv.type = qv::ToLittleEndian16(kTlvTypeEpoch);
        epoch_tlv.length = qv::ToLittleEndian16(static_cast<uint16_t>(record.value.size()));
        std::memcpy(&epoch_tlv.epoch, record.value.data(), sizeof(epoch_tlv.epoch));
        std::memcpy(parsed.epoch_tlv_bytes.data(), &epoch_tlv, sizeof(epoch_tlv));
        break;
      }
      case kTlvTypePqc: {
        const size_t expected = sizeof(qv::core::PQC_KEM_TLV) - sizeof(uint16_t) * 2;
        if (record.value.size() != expected) {
          parse_ok = false;
          break;
        }
        parsed.pqc.type = qv::ToLittleEndian16(kTlvTypePqc);
        parsed.pqc.length = qv::ToLittleEndian16(CheckedCast<uint16_t>(expected));
        std::memcpy(reinterpret_cast<uint8_t*>(&parsed.pqc) + sizeof(uint16_t) * 2,
                    record.value.data(), expected);
        parsed.pqc.type = qv::FromLittleEndian16(parsed.pqc.type);
        parsed.pqc.version = qv::FromLittleEndian16(parsed.pqc.version);
        parsed.pqc.kem_id = qv::FromLittleEndian16(parsed.pqc.kem_id);
        parsed.have_pqc = true;
        break;
      }
      case kTlvTypeReservedV2: {
        if (record.value.size() > parsed.reserved_v2.payload.size()) {
          parse_ok = false;
          break;
        }
        parsed.reserved_v2.type = qv::ToLittleEndian16(kTlvTypeReservedV2);
        parsed.reserved_v2.length = static_cast<uint16_t>(record.value.size());
        std::fill(parsed.reserved_v2.payload.begin(), parsed.reserved_v2.payload.end(), 0);
        if (!record.value.empty()) {
          std::copy(record.value.begin(), record.value.end(), parsed.reserved_v2.payload.begin());
          parsed.have_reserved = true;
        }
        break;
      }
      default:
        break;
    }
    if (!parse_ok) {
      break;
    }
  }

  parsed.valid = parse_ok && magic_ok && version_ok &&
                 (parsed.have_pbkdf || parsed.have_argon2) && parsed.have_hybrid &&
                 parsed.have_pqc;
  return parsed;
}

std::optional<VolumeUuid> ReadVolumeUuid(const std::filesystem::path& container) { // TSK075_Lockout_Persistence_and_IPC
  std::ifstream in(container, std::ios::binary);
  if (!in) {
    return std::nullopt;
  }
  VolumeHeader header{};
  in.read(reinterpret_cast<char*>(&header), sizeof(header));
  if (static_cast<size_t>(in.gcount()) != sizeof(header)) {
    return std::nullopt;
  }
  bool magic_ok = qv::crypto::ct::CompareEqual(header.magic, kHeaderMagic);
  auto version = qv::FromLittleEndian32(header.version);
  bool version_ok = version == kHeaderVersion;                     // TSK102_Timing_Side_Channels
  uint32_t error_mask = 0;                                         // TSK102_Timing_Side_Channels
  error_mask |= magic_ok ? 0u : 1u;                                // TSK102_Timing_Side_Channels
  error_mask |= version_ok ? 0u : 2u;                              // TSK102_Timing_Side_Channels
  bool all_ok = error_mask == 0;                                   // TSK102_Timing_Side_Channels
  VolumeUuid uuid{};
  for (size_t i = 0; i < uuid.size(); ++i) {                       // TSK102_Timing_Side_Channels
    uuid[i] = qv::crypto::ct::Select<uint8_t>(0u, header.uuid[i], all_ok);
  }
  std::atomic_signal_fence(std::memory_order_seq_cst);             // TSK102_Timing_Side_Channels
  if (!all_ok) {
    return std::nullopt;
  }
  return uuid;
}

std::array<uint8_t, 32> DerivePasswordKey(const std::string& password,
                                          const ParsedHeader& parsed) { // TSK013
  ValidatePassword(password); // TSK099_Input_Validation_and_Sanitization
  std::vector<uint8_t> pass_bytes(password.begin(), password.end());
  std::array<uint8_t, 32> output{};
  std::span<const uint8_t> password_span(pass_bytes.data(), pass_bytes.size());
  const auto kdf_start = std::chrono::steady_clock::now();            // TSK102_Timing_Side_Channels
  const uint32_t target_ms =                                         // TSK102_Timing_Side_Channels
      (parsed.have_argon2 && parsed.argon2.target_ms != 0) ? parsed.argon2.target_ms : 150u;
  const auto target_duration = std::chrono::milliseconds(target_ms); // TSK102_Timing_Side_Channels

  if (parsed.algorithm == PasswordKdf::kArgon2id) { // TSK036_PBKDF2_Argon2_Migration_Path
#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2
    if (parsed.argon2.hash_length != output.size()) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      std::string(qv::errors::msg::kUnsupportedArgon2HashLength)};
    }
    int rc = argon2id_hash_raw(parsed.argon2.time_cost, parsed.argon2.memory_cost_kib,
                               parsed.argon2.parallelism, password_span.data(), password_span.size(),
                               parsed.argon2.salt.data(), parsed.argon2.salt.size(), output.data(),
                               output.size());
    if (rc != ARGON2_OK) {
      throw qv::Error{qv::ErrorDomain::Crypto, rc,
                      std::string(qv::errors::msg::kArgon2DerivationFailed)};
    }
#else
    throw qv::Error{qv::ErrorDomain::Dependency, 0,
                    std::string(qv::errors::msg::kArgon2Unavailable)};
#endif
  } else {
    auto derived = qv::crypto::PBKDF2_HMAC_SHA256(
        password_span,
        std::span<const uint8_t>(parsed.pbkdf_salt.data(), parsed.pbkdf_salt.size()),
        parsed.pbkdf_iterations);
    output = derived;
  }
  const auto elapsed = std::chrono::steady_clock::now() - kdf_start; // TSK102_Timing_Side_Channels
  if (elapsed < target_duration) {                                   // TSK102_Timing_Side_Channels
    ConstantTimeDelay(target_duration - elapsed);                    // TSK102_Timing_Side_Channels
  } else {
    std::atomic_signal_fence(std::memory_order_seq_cst);             // TSK102_Timing_Side_Channels
  }
  if (!pass_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(pass_bytes.data(), pass_bytes.size()));
  }
  return output;
}

std::array<uint8_t, 32> DeriveHeaderMacKey(const std::array<uint8_t, 32>& hybrid_key,
                                           const ParsedHeader& parsed) { // TSK013
  auto prk = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(parsed.header.uuid.data(), parsed.header.uuid.size()),
      std::span<const uint8_t>(hybrid_key.data(), hybrid_key.size()));
  static constexpr std::string_view kInfo{"QV-HEADER-MAC/v1"};
  std::array<uint8_t, kInfo.size() + 1> info_block{};
  std::memcpy(info_block.data(), kInfo.data(), kInfo.size());
  info_block[kInfo.size()] = 0x01;
  auto okm = qv::crypto::HMAC_SHA256::Compute(std::span<const uint8_t>(prk.data(), prk.size()),
                                              std::span<const uint8_t>(info_block.data(), info_block.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(prk.data(), prk.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(info_block.data(), info_block.size()));
  return okm;
}

struct TimingSnapshot {
  uint64_t target_ns{0};
  uint64_t p95_ns{0};
  uint64_t p99_ns{0};
  uint64_t samples{0};
};

struct TimingState {
  enum class Mode { Calibrating, Production }; // TSK022

  std::atomic<uint64_t> target_ns{120'000'000};
  std::atomic<uint64_t> last_log_ns{0};
  std::atomic<Mode> mode{Mode::Calibrating};       // TSK022
  std::atomic<uint64_t> fixed_target_ns{kConfiguredP99Ns}; // TSK022
  std::mutex mutex;
  std::array<uint64_t, kHistogramBuckets> histogram{};
  uint64_t total_samples{0};
  uint64_t last_p95{0};
  uint64_t last_p99{0};
};

constexpr uint64_t kCalibrationSamples = 8192; // TSK022

TimingState& GetTimingState() {
  static TimingState state;
  return state;
}

void RecordSample(std::chrono::nanoseconds duration) {
  auto& state = GetTimingState();
  uint64_t ns = static_cast<uint64_t>(duration.count());
  size_t bucket = std::min<size_t>(ns / kHistogramBucketNs, kHistogramBuckets - 1);
  std::lock_guard<std::mutex> guard(state.mutex);
  for (size_t i = 0; i < kHistogramBuckets; ++i) { // TSK022
    bool is_bucket = (i == bucket);
    uint64_t increment = qv::crypto::ct::Select<uint64_t>(0, 1, is_bucket); // TSK022
    state.histogram[i] += increment;
  }
  state.total_samples += 1;

  if (state.total_samples < 8) {
    return;
  }

  auto threshold95 = std::max<uint64_t>(1, (state.total_samples * 95 + 99) / 100);
  auto threshold99 = std::max<uint64_t>(1, (state.total_samples * 99 + 99) / 100);
  uint64_t cumulative = 0;
  uint64_t p95_bucket = 0;
  uint64_t p99_bucket = 0;
  for (size_t i = 0; i < kHistogramBuckets; ++i) {
    cumulative += state.histogram[i];
    if (p95_bucket == 0 && cumulative >= threshold95) {
      p95_bucket = i + 1;
    }
    if (p99_bucket == 0 && cumulative >= threshold99) {
      p99_bucket = i + 1;
      break;
    }
  }
  if (p95_bucket == 0) {
    p95_bucket = kHistogramBuckets;
  }
  if (p99_bucket == 0) {
    p99_bucket = kHistogramBuckets;
  }

  state.last_p95 = p95_bucket * kHistogramBucketNs;
  state.last_p99 = p99_bucket * kHistogramBucketNs;

  uint64_t desired = state.last_p99 + kPaddingSlackNs;
  desired = std::max<uint64_t>(desired, kMinTargetNs);   // TSK022
  desired = std::min<uint64_t>(desired, kConfiguredP99Ns); // TSK022

  auto mode = state.mode.load(std::memory_order_acquire); // TSK022
  if (mode == TimingState::Mode::Calibrating) {           // TSK022
    state.target_ns.store(desired, std::memory_order_relaxed);
    state.fixed_target_ns.store(desired, std::memory_order_relaxed);
    if (state.total_samples >= kCalibrationSamples) {
      state.mode.store(TimingState::Mode::Production, std::memory_order_release);
    }
  }
}

TimingSnapshot SnapshotTiming() {
  TimingSnapshot snap{};
  auto& state = GetTimingState();
  std::lock_guard<std::mutex> guard(state.mutex);
  auto mode = state.mode.load(std::memory_order_acquire);                // TSK022
  snap.target_ns = (mode == TimingState::Mode::Production)
                       ? state.fixed_target_ns.load(std::memory_order_relaxed)
                       : state.target_ns.load(std::memory_order_relaxed); // TSK022
  snap.p95_ns = state.last_p95;
  snap.p99_ns = state.last_p99;
  snap.samples = state.total_samples;
  return snap;
}

// TSK112_Documentation_and_Code_Clarity: ComputePadding measures how much additional delay
// is needed so every attempt meets the calibrated target duration. By clamping to the target
// when the actual runtime exceeds it we avoid underflow, and callers feed the result into the
// constant-time delay so observable timings converge.
std::chrono::nanoseconds ComputePadding(std::chrono::nanoseconds actual) {
  auto& state = GetTimingState();
  auto mode = state.mode.load(std::memory_order_acquire); // TSK022
  uint64_t target = (mode == TimingState::Mode::Production)
                        ? state.fixed_target_ns.load(std::memory_order_relaxed)
                        : state.target_ns.load(std::memory_order_relaxed); // TSK022
  uint64_t actual_ns = static_cast<uint64_t>(actual.count());
  bool over_target = actual_ns > target;
  uint64_t clamped = qv::crypto::ct::Select<uint64_t>(actual_ns, target, over_target); // TSK022
  uint64_t diff = target - clamped;
  return std::chrono::nanoseconds(diff);
}

} // namespace

namespace qv::orchestrator::fuzz {
bool ParseHeaderHarness(std::span<const uint8_t> bytes) { // TSK030
  (void)::ParseHeader(bytes);                              // TSK030
  return true;                                             // TSK030
}
} // namespace qv::orchestrator::fuzz

std::optional<ConstantTimeMount::VolumeHandle>
ConstantTimeMount::Mount(const std::filesystem::path& container,
                         const std::string& password) {
  ValidatePassword(password);                                                 // TSK099_Input_Validation_and_Sanitization
  auto sanitized_container = SanitizeContainerPath(container);                // TSK099_Input_Validation_and_Sanitization
  auto& tracker = FailureTracker::Instance();                                 // TSK026
  auto volume_uuid = ReadVolumeUuid(sanitized_container);                     // TSK075_Lockout_Persistence_and_IPC
  auto client_fingerprint = ResolveClientFingerprint();                       // TSK136_Missing_Rate_Limiting_Mount_Attempts
  tracker.EnforceDelay(sanitized_container, volume_uuid, client_fingerprint); // TSK026, TSK075, TSK136

  Attempt attempt{};
  attempt.start = std::chrono::steady_clock::now();                      // TSK901_Security_Hardening
  auto mount_result = AttemptMount(sanitized_container, password);
  attempt.duration = std::chrono::steady_clock::now() - attempt.start;
  attempt.pad = ComputePadding(attempt.duration);
  ConstantTimePadding(attempt.pad);
  RecordSample(attempt.duration);

  LogTiming(attempt);

  bool any_success = mount_result.has_value();

  auto state = tracker.RecordAttempt(sanitized_container, volume_uuid, any_success,
                                     client_fingerprint); // TSK026, TSK075, TSK136
  if (!any_success) {
    Event event{};                                                // TSK026
    event.category = EventCategory::kSecurity;                    // TSK026
    event.severity = EventSeverity::kWarning;                     // TSK026
    event.event_id = state.locked ? "volume_mount_locked" : "volume_mount_failure"; // TSK026
    event.message = state.locked ? std::string(qv::errors::msg::kMountLockedMessage)
                                 : std::string(qv::errors::msg::kMountAuthFailed); // TSK026
    event.fields.emplace_back("container_path",                                    // TSK026
                              qv::PathToUtf8String(sanitized_container),
                              FieldPrivacy::kHash);                                 // TSK103_Logging_and_Information_Disclosure hashed path
    event.fields.emplace_back("consecutive_failures", std::to_string(state.failures),
                              FieldPrivacy::kPublic, true); // TSK026
    event.fields.emplace_back("cooldown_seconds", std::to_string(state.enforced_delay.count()),
                              FieldPrivacy::kPublic, true); // TSK026
    event.fields.emplace_back("global_consecutive_failures",
                              std::to_string(state.global_failures), FieldPrivacy::kPublic,
                              true); // TSK136_Missing_Rate_Limiting_Mount_Attempts
    event.fields.emplace_back("global_cooldown_seconds",
                              std::to_string(state.global_enforced_delay.count()),
                              FieldPrivacy::kPublic, true); // TSK136
    event.fields.emplace_back("global_total_failures",
                              std::to_string(state.global_total_failures), FieldPrivacy::kPublic,
                              true); // TSK136
    if (!state.client_fingerprint.empty()) {
      event.fields.emplace_back("client_fingerprint", state.client_fingerprint,
                                FieldPrivacy::kHash, true); // TSK136
    }
    if (state.client_failures > 0) {
      event.fields.emplace_back("client_failures", std::to_string(state.client_failures),
                                FieldPrivacy::kPublic, true); // TSK136
      event.fields.emplace_back("client_cooldown_seconds",
                                std::to_string(state.client_enforced_delay.count()),
                                FieldPrivacy::kPublic, true); // TSK136
    }
    event.fields.emplace_back("locked", state.locked ? "true" : "false", FieldPrivacy::kPublic);
    EventBus::Instance().Publish(event); // TSK026
  }

  if (any_success) {
    return mount_result;
  }
  return std::nullopt;
}

void ConstantTimeMount::ConstantTimePadding(std::chrono::nanoseconds duration) {
  ConstantTimeDelay(duration); // TSK102_Timing_Side_Channels reuse shared padding helper
}

std::optional<ConstantTimeMount::VolumeHandle>
ConstantTimeMount::AttemptMount(const std::filesystem::path& container,
                                const std::string& password) {
  constexpr auto kMaxAttemptDuration = std::chrono::seconds(5); // TSK038_Resource_Limits_and_DoS_Prevention
  constexpr uintmax_t kMaxContainerSize = 100ull * 1024ull * 1024ull; // TSK038_Resource_Limits_and_DoS_Prevention
  constexpr uintmax_t kHeaderBytesRequired =                           // TSK141_Integer_Overflow_And_Wraparound_Issues
      static_cast<uintmax_t>(kTotalHeaderBytes);                        // TSK141_Integer_Overflow_And_Wraparound_Issues

  WallClockDeadline attempt_deadline(kMaxAttemptDuration);             // TSK236_Mount_Timeout_Bypass_Vulnerability
  MountConcurrencyGuard concurrency_guard(attempt_deadline);           // TSK236_Mount_Timeout_Bypass_Vulnerability
  if (attempt_deadline.ConsumeSuspendEvent()) {                        // TSK236_Mount_Timeout_Bypass_Vulnerability
    PublishSuspendEvent(container, attempt_deadline.LastSuspendGap()); // TSK236_Mount_Timeout_Bypass_Vulnerability
  }
  if (!concurrency_guard.acquired()) {                                 // TSK236_Mount_Timeout_Bypass_Vulnerability
    PublishConcurrencyThrottleEvent(container);                        // TSK236_Mount_Timeout_Bypass_Vulnerability
    PublishMountTimeoutEvent(container, attempt_deadline, "concurrency_wait");
    return std::nullopt;
  }

  MountResourceMonitor resource_monitor; // TSK236_Mount_Timeout_Bypass_Vulnerability

  auto check_deadline = [&](std::string_view stage) -> bool { // TSK236_Mount_Timeout_Bypass_Vulnerability
    if (attempt_deadline.Expired()) {
      PublishMountTimeoutEvent(container, attempt_deadline, stage);
      return false;
    }
    if (attempt_deadline.ConsumeSuspendEvent()) {
      PublishSuspendEvent(container, attempt_deadline.LastSuspendGap());
    }
    return true;
  };

  auto check_resource = [&](std::string_view stage) -> bool { // TSK236_Mount_Timeout_Bypass_Vulnerability
    if (!resource_monitor.CheckBudget()) {
      PublishResourceBudgetEvent(container, resource_monitor, stage);
      return false;
    }
    return true;
  };

  if (!check_deadline("initial") || !check_resource("initial")) {
    return std::nullopt;
  }

  std::error_code size_ec; // TSK038_Resource_Limits_and_DoS_Prevention
  auto container_size = std::filesystem::file_size(container, size_ec); // TSK038_Resource_Limits_and_DoS_Prevention
  bool size_known = !size_ec;                                           // TSK070
  bool within_limit = size_known && container_size <= kMaxContainerSize; // TSK070
  bool header_sized = within_limit && container_size >= kHeaderBytesRequired; // TSK070, TSK141_Integer_Overflow_And_Wraparound_Issues

  std::array<uint8_t, kTotalHeaderBytes> buf{}; // TSK013
  bool io_ok = false;                           // TSK070
  {
    std::ifstream in(container, std::ios::binary);
    if (in) {
      in.read(reinterpret_cast<char*>(buf.data()), buf.size());
      io_ok = static_cast<size_t>(in.gcount()) == buf.size();
    }
  }

  if (!check_deadline("header_read") || !check_resource("header_read")) {
    return std::nullopt;
  }

  std::array<uint8_t, kSerializedHeaderBytes> header_bytes{};
  std::copy_n(buf.begin(), header_bytes.size(), header_bytes.begin());

  std::array<uint8_t, kHeaderMacSize> stored_mac{};
  std::copy_n(buf.begin() + header_bytes.size(), stored_mac.size(), stored_mac.begin());

  auto parsed = ParseHeader(std::span<const uint8_t>(header_bytes.data(), header_bytes.size()));

  if (!check_deadline("header_parse") || !check_resource("header_parse")) {
    return std::nullopt;
  }

  struct PasswordAttempt {                                           // TSK_CRIT_11
    std::array<uint8_t, 32> key{};
    bool success{false};
  };

  const bool prefer_pbkdf = parsed.algorithm == PasswordKdf::kPbkdf2;      // TSK901_Security_Hardening
  const bool prefer_argon2 = parsed.algorithm == PasswordKdf::kArgon2id;   // TSK901_Security_Hardening

  auto run_password_attempt = [&](const ParsedHeader& variant, bool should_run) {
    PasswordAttempt attempt{};                                       // TSK_CRIT_11
    if (!should_run) {
      return attempt;                                                // TSK901_Security_Hardening avoid redundant derivation
    }
    try {
      attempt.key = DerivePasswordKey(password, variant);            // TSK_CRIT_11
      attempt.success = true;                                        // TSK_CRIT_11
    } catch (const std::exception&) {
      attempt.success = false;                                       // TSK_CRIT_11
    }
    return attempt;
  };

  auto pbkdf_variant = parsed;                                      // TSK_CRIT_11
  pbkdf_variant.algorithm = PasswordKdf::kPbkdf2;                   // TSK_CRIT_11
  auto argon2_variant = parsed;                                     // TSK_CRIT_11
  argon2_variant.algorithm = PasswordKdf::kArgon2id;                // TSK_CRIT_11

  auto pbkdf_attempt = run_password_attempt(pbkdf_variant, prefer_pbkdf);   // TSK901_Security_Hardening
  auto argon2_attempt = run_password_attempt(argon2_variant, prefer_argon2); // TSK901_Security_Hardening

  if (!check_deadline("password_kdf") || !check_resource("password_kdf")) {
    return std::nullopt;
  }


  auto publish_kdf_timeout = [&]() {                                        // TSK_CRIT_13_KDF_Resource_Budget_Bypass
    qv::orchestrator::Event kdf_timeout{};                                  // TSK_CRIT_13_KDF_Resource_Budget_Bypass
    kdf_timeout.category = qv::orchestrator::EventCategory::kSecurity;       // TSK_CRIT_13_KDF_Resource_Budget_Bypass
    kdf_timeout.severity = qv::orchestrator::EventSeverity::kWarning;        // TSK_CRIT_13_KDF_Resource_Budget_Bypass
    kdf_timeout.event_id = "mount_key_timeout";                             // TSK_CRIT_13_KDF_Resource_Budget_Bypass
    kdf_timeout.message = std::string(qv::errors::msg::kKeyAgreementTimeout); // TSK_CRIT_13
    kdf_timeout.fields.emplace_back("container_path", qv::PathToUtf8String(container),
                                    qv::orchestrator::FieldPrivacy::kHash);  // TSK_CRIT_13
    qv::orchestrator::EventBus::Instance().Publish(kdf_timeout);             // TSK_CRIT_13
  };

  auto run_hybrid_kdf = [&](const std::array<uint8_t, 32>& classical_key) {  // TSK_CRIT_13
    auto parsed_for_kdf = parsed;                                            // TSK_CRIT_13
    auto classical_copy = classical_key;                                     // TSK_CRIT_13
    HybridKdfResult result{};                                                // TSK_CRIT_13
    std::span<const uint8_t> hybrid_salt(parsed_for_kdf.hybrid_salt.data(),  // TSK_CRIT_13
                                         parsed_for_kdf.hybrid_salt.size()); // TSK_CRIT_13
    std::span<const uint8_t> epoch_span;                                     // TSK_CRIT_13
    if (parsed_for_kdf.have_epoch) {                                         // TSK_CRIT_13
      epoch_span = std::span<const uint8_t>(parsed_for_kdf.epoch_tlv_bytes.data(),
                                            parsed_for_kdf.epoch_tlv_bytes.size());
    }
    try {
      result.key = qv::core::PQCHybridKDF::Mount(                            // TSK_CRIT_13
          std::span<const uint8_t, 32>(classical_copy), parsed_for_kdf.pqc, hybrid_salt,
          std::span<const uint8_t, 16>(parsed_for_kdf.header.uuid), parsed_for_kdf.version,
          epoch_span);
      result.success = true;                                                 // TSK_CRIT_13
    } catch (const qv::AuthenticationFailureError&) {
      result.success = false;                                                // TSK_CRIT_13
    } catch (const std::exception&) {
      result.success = false;                                                // TSK_CRIT_13
    }
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_copy.data(),  // TSK_CRIT_13
                                                    classical_copy.size()));
    return result;                                                           // TSK_CRIT_13
  };

  auto run_selected_hybrid = [&](const std::array<uint8_t, 32>& classical_key, bool should_run,
                                 std::string_view start_stage, std::string_view finish_stage,
                                 HybridKdfResult& output) -> bool { // TSK901_Security_Hardening
    if (!should_run) {
      output.success = false;
      return true;
    }
    if (!check_deadline(start_stage) || !check_resource(start_stage)) {
      return false;
    }
    output = run_hybrid_kdf(classical_key);
    if (!check_deadline(finish_stage)) {
      publish_kdf_timeout();
      return false;
    }
    if (!check_resource(finish_stage)) {
      return false;
    }
    return true;
  };

  HybridKdfResult pbkdf_hybrid{};
  HybridKdfResult argon2_hybrid{};
  if (!run_selected_hybrid(pbkdf_attempt.key, prefer_pbkdf && pbkdf_attempt.success,
                           "hybrid_kdf_pbkdf2_start", "hybrid_kdf_pbkdf2_finish", pbkdf_hybrid)) {
    return std::nullopt;
  }
  if (!run_selected_hybrid(argon2_attempt.key, prefer_argon2 && argon2_attempt.success,
                           "hybrid_kdf_argon2_start", "hybrid_kdf_argon2_finish", argon2_hybrid)) {
    return std::nullopt;
  }

  if (!check_deadline("hybrid_kdf_result") || !check_resource("hybrid_kdf_result")) {
    return std::nullopt;
  }

  std::array<uint8_t, 32> mac_key_pbkdf{};
  std::array<uint8_t, 32> mac_key_argon2{};
  bool mac_ok_pbkdf = false;
  bool mac_ok_argon2 = false;
  if (prefer_pbkdf && pbkdf_hybrid.success) {
    mac_key_pbkdf = DeriveHeaderMacKey(pbkdf_hybrid.key, parsed);               // TSK_CRIT_11
    auto mac_pbkdf = qv::crypto::HMAC_SHA256::Compute(
        std::span<const uint8_t>(mac_key_pbkdf.data(), mac_key_pbkdf.size()),
        std::span<const uint8_t>(header_bytes.data(), header_bytes.size()));
    mac_ok_pbkdf = qv::crypto::ct::CompareEqual(stored_mac, mac_pbkdf);         // TSK_CRIT_11
  }
  if (prefer_argon2 && argon2_hybrid.success) {
    mac_key_argon2 = DeriveHeaderMacKey(argon2_hybrid.key, parsed);             // TSK_CRIT_11
    auto mac_argon2 = qv::crypto::HMAC_SHA256::Compute(
        std::span<const uint8_t>(mac_key_argon2.data(), mac_key_argon2.size()),
        std::span<const uint8_t>(header_bytes.data(), header_bytes.size()));
    mac_ok_argon2 = qv::crypto::ct::CompareEqual(stored_mac, mac_argon2);       // TSK_CRIT_11
  }

  if (!check_deadline("mac_verify") || !check_resource("mac_verify")) {
    return std::nullopt;
  }


  auto variant_mask = [](bool prefer_variant, bool condition) -> uint32_t { // TSK_CRIT_11
    uint32_t prefer_mask = qv::crypto::ct::Select<uint32_t>(0u, 1u, prefer_variant);
    uint32_t condition_mask = qv::crypto::ct::Select<uint32_t>(0u, 1u, condition);
    return prefer_mask & condition_mask;
  };

  uint32_t integrity_mask = 1u; // TSK102_Timing_Side_Channels
  integrity_mask &= qv::crypto::ct::Select<uint32_t>(0u, 1u, size_known);
  integrity_mask &= qv::crypto::ct::Select<uint32_t>(0u, 1u, within_limit);
  integrity_mask &= qv::crypto::ct::Select<uint32_t>(0u, 1u, header_sized);
  integrity_mask &= qv::crypto::ct::Select<uint32_t>(0u, 1u, io_ok);
  integrity_mask &= qv::crypto::ct::Select<uint32_t>(0u, 1u, parsed.valid);
  uint32_t algorithm_mask = variant_mask(prefer_pbkdf, true) | variant_mask(prefer_argon2, true);
  uint32_t classical_mask = variant_mask(prefer_pbkdf, pbkdf_attempt.success) |
                            variant_mask(prefer_argon2, argon2_attempt.success);
  uint32_t pqc_mask = variant_mask(prefer_pbkdf, pbkdf_hybrid.success) |
                      variant_mask(prefer_argon2, argon2_hybrid.success);
  uint32_t mac_mask = variant_mask(prefer_pbkdf, mac_ok_pbkdf) |
                      variant_mask(prefer_argon2, mac_ok_argon2);
  integrity_mask &= algorithm_mask;
  integrity_mask &= classical_mask;
  integrity_mask &= pqc_mask;
  integrity_mask &= mac_mask;
  bool result = integrity_mask != 0u;                                             // TSK102_Timing_Side_Channels
  uint32_t mask = qv::crypto::ct::Select<uint32_t>(0u, 1u, result);              // TSK022, TSK070
  std::atomic_signal_fence(std::memory_order_seq_cst);                   // TSK022
  volatile uint32_t guard_mask = mask;                                   // TSK022
  (void)guard_mask;                                                      // TSK022

  auto wipe_array = [](auto& arr) {                                     // TSK_CRIT_11
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(arr.data(), arr.size()));
  };
  wipe_array(pbkdf_attempt.key);
  wipe_array(argon2_attempt.key);
  wipe_array(pbkdf_hybrid.key);
  wipe_array(argon2_hybrid.key);
  wipe_array(mac_key_pbkdf);
  wipe_array(mac_key_argon2);

  if (!check_deadline("finalize") || !check_resource("finalize")) {
    return std::nullopt;
  }

  if (mask != 0u) {
    VolumeHandle handle{};
    handle.dummy = 1;
    handle.device = MakeBlockDevice(container);
    handle.hidden_region = std::nullopt; // TSK710_Implement_Hidden_Volumes default outer layout
    return handle;
  }
  return std::nullopt;
}



void ConstantTimeMount::LogTiming(const Attempt& attempt) { // TSK901_Security_Hardening consolidated attempts
  (void)attempt;
  auto now_ns = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
  auto& state = GetTimingState();
  auto last = state.last_log_ns.load(std::memory_order_relaxed);
  if (now_ns - last < kLogIntervalNs) {
    return;
  }
  if (!state.last_log_ns.compare_exchange_strong(last, now_ns)) {
    return;
  }

  auto snap = SnapshotTiming();

  qv::orchestrator::Event event;  // TSK019
  event.category = qv::orchestrator::EventCategory::kTelemetry;
  event.severity = qv::orchestrator::EventSeverity::kInfo;
  event.event_id = "ct_mount_timing";
  event.message = "Constant-time mount timing statistics"; // TSK103_Logging_and_Information_Disclosure aggregate only
  event.fields.emplace_back("target_ns", std::to_string(snap.target_ns),
                            qv::orchestrator::FieldPrivacy::kPublic, true);
  event.fields.emplace_back("p95_ns", std::to_string(snap.p95_ns),
                            qv::orchestrator::FieldPrivacy::kPublic, true);
  event.fields.emplace_back("p99_ns", std::to_string(snap.p99_ns),
                            qv::orchestrator::FieldPrivacy::kPublic, true);
  event.fields.emplace_back("samples", std::to_string(snap.samples),
                            qv::orchestrator::FieldPrivacy::kPublic, true);

  qv::orchestrator::EventBus::Instance().Publish(event);
}
