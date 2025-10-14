#include "qv/orchestrator/plugin_manager.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#if defined(__linux__)
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

#include "qv/orchestrator/event_bus.h" // TSK019
#include "qv/orchestrator/plugin_abi.h"

using namespace qv::orchestrator;

namespace {

#if !defined(_WIN32)
  constexpr size_t kMaxPluginStringLength = 4096;            // TSK025_Plugin_Sandboxing_and_Resource_Limits
  constexpr uint32_t kPluginHandshakeMessageType = 0x51565048u; // "QVPH"
  constexpr uint32_t kPluginCommandMessageType = 0x5156434du;   // "QVCM"
  constexpr uint32_t kPluginResultMessageType = 0x51565253u;    // "QVRS"
  constexpr rlim_t kPluginMemoryLimitBytes = 64ull * 1024ull * 1024ull; // 64 MiB cap.
  constexpr rlim_t kPluginCpuLimitSeconds = 5;                                // 5s CPU.
  constexpr std::chrono::milliseconds kPluginHandshakeTimeout{5000}; // TSK077
  constexpr std::chrono::milliseconds kPluginInitTimeout{5000};       // TSK077
#endif
  constexpr size_t kMaxLoadedPlugins = 32; // TSK038_Resource_Limits_and_DoS_Prevention
#if !defined(_WIN32)

  enum class PluginCommand : uint32_t {
    kInit = 1u,
    kShutdown = 2u,
  };

  struct PluginHandshakePacket {
    uint32_t type;
    int32_t status;
    uint32_t abi_version;
    uint32_t capability_schema;
    uint64_t capabilities;
    uint32_t name_size;
    uint32_t version_size;
  };

  struct PluginCommandPacket {
    uint32_t type;
    uint32_t command;
  };

  struct PluginCommandResultPacket {
    uint32_t type;
    uint32_t command;
    int32_t status;
  };

  bool WriteAll(int fd, const void* data, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    size_t written = 0;
    while (written < size) {
      ssize_t rc = ::write(fd, bytes + written, size - written);
      if (rc < 0) {
        if (errno == EINTR)
          continue;
        return false;
      }
      if (rc == 0)
        return false;
      written += static_cast<size_t>(rc);
    }
    return true;
  }

  bool ReadAll(int fd, void* data, size_t size) {
    auto* bytes = static_cast<uint8_t*>(data);
    size_t read = 0;
    while (read < size) {
      ssize_t rc = ::read(fd, bytes + read, size - read);
      if (rc < 0) {
        if (errno == EINTR)
          continue;
        return false;
      }
      if (rc == 0)
        return false;
      read += static_cast<size_t>(rc);
    }
    return true;
  }

  class PluginDeadline { // TSK077
   public:
    explicit PluginDeadline(std::chrono::milliseconds timeout) {
      if (timeout.count() > 0) {
        deadline_ = std::chrono::steady_clock::now() + timeout;
      }
    }

    bool WaitReadable(int fd) {
      while (true) {
        const int timeout_ms = RemainingMillis();
        struct pollfd pfd {
          fd, POLLIN, 0
        };
        int rc = ::poll(&pfd, 1, timeout_ms);
        if (rc == 0) {
          return false;
        }
        if (rc < 0) {
          if (errno == EINTR)
            continue;
          return false;
        }
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
          return false;
        }
        return (pfd.revents & POLLIN) != 0;
      }
    }

   private:
    int RemainingMillis() const {
      if (!deadline_) {
        return -1;
      }
      const auto now = std::chrono::steady_clock::now();
      if (now >= *deadline_) {
        return 0;
      }
      const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(*deadline_ - now);
      return static_cast<int>(remaining.count());
    }

    std::optional<std::chrono::steady_clock::time_point> deadline_;
  };

  bool ReadAllWithDeadline(int fd, void* data, size_t size, PluginDeadline* deadline) {
    if (!deadline) {
      return ReadAll(fd, data, size);
    }
    auto* bytes = static_cast<uint8_t*>(data);
    size_t read = 0;
    while (read < size) {
      if (!deadline->WaitReadable(fd)) {
        return false;
      }
      ssize_t rc = ::read(fd, bytes + read, size - read);
      if (rc < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
          continue;
        return false;
      }
      if (rc == 0)
        return false;
      read += static_cast<size_t>(rc);
    }
    return true;
  }

  void SetPluginResourceLimits() {
    struct rlimit mem_limit {
      kPluginMemoryLimitBytes, kPluginMemoryLimitBytes
    };
    ::setrlimit(RLIMIT_AS, &mem_limit);

    struct rlimit cpu_limit {
      kPluginCpuLimitSeconds, kPluginCpuLimitSeconds
    };
    ::setrlimit(RLIMIT_CPU, &cpu_limit);
  }

#if defined(__linux__)
  void InstallPluginSeccompFilter(bool allow_filesystem) { // TSK077
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      return;
    }

    std::vector<sock_filter> filter;
    filter.reserve(32);
    filter.push_back({static_cast<uint16_t>(BPF_LD | BPF_W | BPF_ABS), 0, 0,
                     static_cast<uint32_t>(offsetof(struct seccomp_data, nr))});

    auto allow_syscall = [&filter](int syscall_number) {
      filter.push_back({static_cast<uint16_t>(BPF_JMP | BPF_JEQ | BPF_K), 0, 1,
                        static_cast<uint32_t>(syscall_number)});
      filter.push_back({static_cast<uint16_t>(BPF_RET | BPF_K), 0, 0, SECCOMP_RET_ALLOW});
    };

    allow_syscall(__NR_read);
    allow_syscall(__NR_write);
    allow_syscall(__NR_close);
    allow_syscall(__NR_exit);
    allow_syscall(__NR_exit_group);
    allow_syscall(__NR_futex);
    allow_syscall(__NR_clock_gettime);
    allow_syscall(__NR_nanosleep);
    allow_syscall(__NR_getrandom);
    allow_syscall(__NR_rt_sigreturn);
    allow_syscall(__NR_rt_sigaction);
    allow_syscall(__NR_rt_sigprocmask);
    allow_syscall(__NR_mmap);
    allow_syscall(__NR_munmap);
    allow_syscall(__NR_mprotect);
    allow_syscall(__NR_brk);

    if (allow_filesystem) {
#if defined(__NR_openat)
      allow_syscall(__NR_openat);
#endif
#if defined(__NR_newfstatat)
      allow_syscall(__NR_newfstatat);
#endif
#if defined(__NR_fstat)
      allow_syscall(__NR_fstat);
#endif
#if defined(__NR_pread64)
      allow_syscall(__NR_pread64);
#endif
    }

    filter.push_back({static_cast<uint16_t>(BPF_RET | BPF_K), 0, 0, SECCOMP_RET_KILL_PROCESS});

    struct sock_fprog program {
      static_cast<unsigned short>(filter.size()), filter.data()
    };

    ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
  }

  void ApplyPluginSandboxBeforeLoad() {
    InstallPluginSeccompFilter(true);
  }

  void ApplyPluginSandbox() {
    InstallPluginSeccompFilter(false);
  }
#else
  void ApplyPluginSandboxBeforeLoad() {}
  void ApplyPluginSandbox() {}
#endif

#endif // !_WIN32

  std::string ToHex(uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << value;
    return oss.str();
  }

  bool ValidateCapabilities(uint64_t capabilities, const PluginVerification& verification,
                            const std::filesystem::path& canonical_path,
                            std::string_view plugin_name) {
    const uint64_t unknown = capabilities & ~QV_PLUGIN_CAP_KNOWN_MASK;
    if (unknown != 0) {
      PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError,
                              "plugin_capability_violation",
                              "Plugin requested unsupported capabilities", canonical_path,
                              {qv::orchestrator::EventField("requested_capabilities",
                                                            ToHex(capabilities),
                                                            qv::orchestrator::FieldPrivacy::kPublic, true),
                               qv::orchestrator::EventField("unknown_capabilities",
                                                            ToHex(unknown),
                                                            qv::orchestrator::FieldPrivacy::kPublic, true)});
      return false;
    }

    if (verification.trust_policy &&
        verification.trust_policy->capability_schema_version != QV_PLUGIN_CAPABILITY_SCHEMA_VERSION) {
      PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError,
                              "plugin_capability_schema_mismatch",
                              "Plugin capability schema version mismatch", canonical_path,
                              {qv::orchestrator::EventField(
                                  "schema_version",
                                  std::to_string(verification.trust_policy->capability_schema_version),
                                  qv::orchestrator::FieldPrivacy::kPublic, true)});
      return false;
    }

    if (verification.trust_policy && !verification.plugin_id.empty()) {
      auto it = verification.trust_policy->plugin_abi_ranges.find(verification.plugin_id);
      if (it == verification.trust_policy->plugin_abi_ranges.end()) {
        // Trust policy covers ABI ranges only in current skeleton; capability enforcement
        // beyond schema verification is deferred to policy extensions.
      }
    }

    (void)plugin_name;
    return true;
  }

#if !defined(_WIN32)
  bool SendHandshake(int fd, int status, const QV_PluginInfo* info) {
    PluginHandshakePacket packet{};
    packet.type = kPluginHandshakeMessageType;
    packet.status = status;
    if (status == 0 && info) {
      packet.abi_version = info->abi_version;
      packet.capability_schema = QV_PLUGIN_CAPABILITY_SCHEMA_VERSION;
      packet.capabilities = info->capabilities;
      const size_t name_len = info->name ? std::min(strlen(info->name), kMaxPluginStringLength) : 0;
      const size_t version_len = info->version ? std::min(strlen(info->version), kMaxPluginStringLength) : 0;
      packet.name_size = static_cast<uint32_t>(name_len);
      packet.version_size = static_cast<uint32_t>(version_len);
    } else {
      packet.abi_version = 0;
      packet.capability_schema = 0;
      packet.capabilities = 0;
      packet.name_size = 0;
      packet.version_size = 0;
    }

    if (!WriteAll(fd, &packet, sizeof(packet)))
      return false;

    if (status == 0 && info) {
      if (packet.name_size > 0 && info->name) {
        if (!WriteAll(fd, info->name, packet.name_size))
          return false;
      }
      if (packet.version_size > 0 && info->version) {
        if (!WriteAll(fd, info->version, packet.version_size))
          return false;
      }
    }
    return true;
  }

  bool ReceiveHandshake(int fd, PluginHandshakePacket* packet, std::string& name,
                        std::string& version, std::chrono::milliseconds timeout) {
    PluginDeadline deadline(timeout);
    if (!ReadAllWithDeadline(fd, packet, sizeof(*packet), &deadline))
      return false;
    if (packet->type != kPluginHandshakeMessageType)
      return false;

    if (packet->status != 0) {
      return true;
    }

    if (packet->name_size > kMaxPluginStringLength || packet->version_size > kMaxPluginStringLength) {
      return false;
    }

    name.clear();
    version.clear();
    if (packet->name_size > 0) {
      name.resize(packet->name_size);
      if (!ReadAllWithDeadline(fd, name.data(), packet->name_size, &deadline))
        return false;
    }
    if (packet->version_size > 0) {
      version.resize(packet->version_size);
      if (!ReadAllWithDeadline(fd, version.data(), packet->version_size, &deadline))
        return false;
    }
    return true;
  }

  bool SendCommandMessage(int fd, PluginCommand command) {
    PluginCommandPacket packet{};
    packet.type = kPluginCommandMessageType;
    packet.command = static_cast<uint32_t>(command);
    return WriteAll(fd, &packet, sizeof(packet));
  }

  bool AwaitCommandResult(int fd, PluginCommand expected, int* status_out,
                          std::chrono::milliseconds timeout = std::chrono::milliseconds::zero()) {
    PluginDeadline deadline(timeout);
    PluginCommandResultPacket packet{};
    if (!ReadAllWithDeadline(fd, &packet, sizeof(packet), timeout.count() > 0 ? &deadline : nullptr))
      return false;
    if (packet.type != kPluginResultMessageType)
      return false;
    if (packet.command != static_cast<uint32_t>(expected))
      return false;
    if (status_out)
      *status_out = packet.status;
    return true;
  }

  [[noreturn]] void PluginSubprocess(int channel, const std::filesystem::path& path) {
    SetPluginResourceLimits();

#if defined(__linux__)
    ::prctl(PR_SET_PDEATHSIG, SIGKILL); // TSK077
    if (::getppid() == 1) {
      ::kill(::getpid(), SIGKILL);
    }
#endif

    ApplyPluginSandboxBeforeLoad(); // TSK077

    DynLib library;
    if (!library.Open(path)) {
      SendHandshake(channel, -1, nullptr);
      _exit(EXIT_FAILURE);
    }

    auto init = reinterpret_cast<QV_Plugin_Init>(library.Symbol("qv_plugin_init"));
    auto shutdown = reinterpret_cast<QV_Plugin_Shutdown>(library.Symbol("qv_plugin_shutdown"));
    auto get_info = reinterpret_cast<QV_Plugin_GetInfo>(library.Symbol("qv_plugin_get_info"));

    if (!init || !shutdown || !get_info) {
      SendHandshake(channel, -2, nullptr);
      _exit(EXIT_FAILURE);
    }

    QV_PluginInfo info = get_info();
    if (!SendHandshake(channel, 0, &info)) {
      _exit(EXIT_FAILURE);
    }

    ApplyPluginSandbox();

    bool init_complete = false;
    bool running = true;
    while (running) {
      PluginCommandPacket packet{};
      if (!ReadAll(channel, &packet, sizeof(packet)))
        break;
      if (packet.type != kPluginCommandMessageType)
        break;

      const auto command = static_cast<PluginCommand>(packet.command);
      int command_status = 0;

      switch (command) {
        case PluginCommand::kInit:
          if (!init_complete) {
            command_status = init ? init() : -1;
            if (command_status == 0) {
              init_complete = true;
            }
          }
          break;
        case PluginCommand::kShutdown:
          if (init_complete && shutdown) {
            shutdown();
          }
          running = false;
          break;
        default:
          command_status = -1;
          running = false;
          break;
      }

      PluginCommandResultPacket result{};
      result.type = kPluginResultMessageType;
      result.command = static_cast<uint32_t>(command);
      result.status = command_status;
      if (!WriteAll(channel, &result, sizeof(result))) {
        break;
      }
    }

    _exit(EXIT_SUCCESS);
  }
#endif
  // TSK010 cross-platform dynamic loader wrapper.
  struct DynLib {
#if defined(_WIN32)
    using handle_type = HMODULE;
#else
    using handle_type = void*;
#endif

    DynLib() = default;
    DynLib(const DynLib&) = delete;
    DynLib& operator=(const DynLib&) = delete;
    DynLib(DynLib&& other) noexcept {
      *this = std::move(other);
    }
    DynLib& operator=(DynLib&& other) noexcept {
      if (this != &other) {
        Close();
        handle_ = other.handle_;
        other.handle_ = nullptr;
      }
      return *this;
    }
    ~DynLib() {
      Close();
    }

    bool Open(const std::filesystem::path& library_path) {
      Close();
#if defined(_WIN32)
      std::wstring wide = library_path.wstring();
      handle_ = ::LoadLibraryW(wide.c_str());
#else
      const std::string utf8 = library_path.string();
      handle_ = ::dlopen(utf8.c_str(), RTLD_NOW);
#endif
      return handle_ != nullptr;
    }

    void* Symbol(const char* name) const {
      if (!handle_)
        return nullptr;
#if defined(_WIN32)
      return reinterpret_cast<void*>(::GetProcAddress(handle_, name));
#else
      return ::dlsym(handle_, name);
#endif
    }

    void Close() {
      if (!handle_)
        return;
#if defined(_WIN32)
      ::FreeLibrary(handle_);
#else
      ::dlclose(handle_);
#endif
      handle_ = nullptr;
    }

    bool IsOpen() const {
      return handle_ != nullptr;
    }

  private:
    handle_type handle_{nullptr};
  };

  std::filesystem::path Canonicalize(const std::filesystem::path& path) {
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(path, ec);
    if (!ec)
      return canonical;
    auto absolute = std::filesystem::absolute(path, ec);
    if (!ec)
      return absolute;
    return path;
  }

  void AppendUnique(std::vector<std::filesystem::path>& paths, std::filesystem::path candidate) {
    candidate = Canonicalize(candidate);
    if (candidate.empty())
      return;
    for (const auto& existing : paths) {
      if (existing == candidate)
        return;
    }
    paths.push_back(std::move(candidate));
  }

  std::vector<std::filesystem::path> ParseEnvPaths() {
    std::vector<std::filesystem::path> paths;
    if (const char* raw = std::getenv("QV_PLUGIN_PATHS")) {
      std::string value(raw);
      const char delimiter =
#if defined(_WIN32)
          ';';
#else
          ':';
#endif
      std::string::size_type start = 0;
      while (start <= value.size()) {
        auto end = value.find(delimiter, start);
        auto segment =
            value.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!segment.empty()) {
          AppendUnique(paths, std::filesystem::path(segment));
        }
        if (end == std::string::npos)
          break;
        start = end + 1;
      }
    }
    return paths;
  }

  std::filesystem::path DefaultPluginDir() {
    return Canonicalize(std::filesystem::current_path() / "plugins");
  }

  std::vector<std::filesystem::path> ResolveDefaultSearchPaths() {
    auto paths = ParseEnvPaths();
    AppendUnique(paths, DefaultPluginDir());
    return paths;
  }

  std::string_view PluginExtension() {
#if defined(_WIN32)
    return ".dll";
#elif defined(__APPLE__)
    return ".dylib";
#else
    return ".so";
#endif
  }

  bool ShouldVerify(const PluginVerification& verification) {
    for (uint8_t byte : verification.expected_hash) {
      if (byte != 0)
        return true;
    }
    if (verification.enforce_signature)
      return true;
    for (uint8_t byte : verification.signature) {
      if (byte != 0)
        return true;
    }
    return false;
  }

  void
  PublishPluginDiagnostic(qv::orchestrator::EventSeverity severity, std::string_view event_id,
                          std::string_view message, const std::filesystem::path& path,
                          std::vector<qv::orchestrator::EventField> extra_fields = {}) { // TSK019
    qv::orchestrator::Event event;
    event.category = qv::orchestrator::EventCategory::kLifecycle;
    event.severity = severity;
    event.event_id = std::string(event_id);
    event.message = std::string(message);
    auto normalized = path.generic_string();
    if (!normalized.empty()) {
      event.fields.emplace_back("plugin_path_hash", normalized,
                                qv::orchestrator::FieldPrivacy::kHash);
    }
    for (auto& field : extra_fields) {
      event.fields.push_back(std::move(field));
    }
    qv::orchestrator::EventBus::Instance().Publish(event);
  }

} // namespace

struct PluginManager::LoadedPlugin {
  std::filesystem::path path;
  uint64_t capabilities{0};
  std::string name;
  std::string version;
#if defined(_WIN32)
  QV_PluginInfo info{};
  QV_Plugin_Shutdown shutdown{nullptr};
  DynLib library;
#else
  pid_t pid{-1};
  int channel{-1};
#endif
};

PluginManager::PluginManager() : search_paths_(ResolveDefaultSearchPaths()) {}

PluginManager::PluginManager(std::vector<std::filesystem::path> search_paths) : search_paths_() {
  for (auto& path : search_paths) {
    AddSearchPath(std::move(path));
  }
}

PluginManager::~PluginManager() {
  UnloadAll();
}

void PluginManager::AddSearchPath(std::filesystem::path path) {
  AppendUnique(search_paths_, std::move(path));
}

const std::vector<std::filesystem::path>& PluginManager::SearchPaths() const noexcept {
  return search_paths_;
}

size_t PluginManager::LoadFromSearchPaths(const PluginVerification& policy) {
  size_t loaded_before = loaded_.size();
  for (const auto& directory : search_paths_) {
    std::error_code ec;
    if (!std::filesystem::exists(directory, ec) || !std::filesystem::is_directory(directory, ec)) {
      continue;
    }

    for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
      if (ec)
        break;
      const auto& path = entry.path();
      if (!entry.is_regular_file(ec))
        continue;
      if (path.extension() != PluginExtension())
        continue;
      LoadPlugin(path, policy);
    }
  }
  return loaded_.size() - loaded_before;
}

bool PluginManager::LoadPlugin(const std::filesystem::path& so_path,
                               const PluginVerification& policy) {
  std::error_code ec;
  auto canonical_path = std::filesystem::weakly_canonical(so_path, ec);
  if (ec) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError,                  // TSK030
                            "plugin_path_resolution_failure",                       // TSK030
                            "Unable to resolve plugin path", so_path);             // TSK030
    return false;                                                                     // TSK030
  }

  if (loaded_.size() >= kMaxLoadedPlugins) { // TSK038_Resource_Limits_and_DoS_Prevention
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, // TSK038_Resource_Limits_and_DoS_Prevention
                            "plugin_limit_reached", // TSK038_Resource_Limits_and_DoS_Prevention
                            "Maximum plugin capacity reached", canonical_path, // TSK038_Resource_Limits_and_DoS_Prevention
                            {qv::orchestrator::EventField("plugin_limit", std::to_string(kMaxLoadedPlugins),
                                                          qv::orchestrator::FieldPrivacy::kPublic, true)}); // TSK038_Resource_Limits_and_DoS_Prevention
    return false; // TSK038_Resource_Limits_and_DoS_Prevention
  }

  bool within_allowed_root = false;                                                  // TSK030
  for (const auto& root : search_paths_) {                                            // TSK030
    std::error_code root_ec;                                                          // TSK030
    auto canonical_root = std::filesystem::weakly_canonical(root, root_ec);           // TSK030
    if (root_ec) {                                                                    // TSK030
      canonical_root = std::filesystem::absolute(root, root_ec);                      // TSK030
    }
    if (root_ec) {                                                                    // TSK030
      continue;                                                                       // TSK030
    }
    std::error_code rel_ec;                                                           // TSK030
    auto relative = std::filesystem::relative(canonical_path, canonical_root, rel_ec); // TSK030
    if (!rel_ec) {                                                                    // TSK030
      bool escapes = false;                                                           // TSK030
      for (const auto& part : relative) {                                             // TSK030
        if (part == "..") {                                                          // TSK030
          escapes = true;                                                             // TSK030
          break;                                                                      // TSK030
        }
      }
      if (!escapes) {                                                                 // TSK030
        within_allowed_root = true;                                                   // TSK030
        break;                                                                        // TSK030
      }
    }
  }

  if (!within_allowed_root) {                                                         // TSK030
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError,
                            "plugin_path_outside_search_path",                      // TSK030
                            "Plugin path escapes configured search paths",          // TSK030
                            canonical_path);                                          // TSK030
    return false;
  }

  for (const auto& plugin : loaded_) {
    if (plugin->path == canonical_path) {
      PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kWarning, "plugin_already_loaded",
                              "Plugin already loaded", canonical_path);
      return false;
    }
  }

  if (!std::filesystem::is_regular_file(canonical_path, ec)) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, "plugin_not_regular_file",
                            "Plugin candidate is not a regular file", canonical_path);
    return false;
  }

  if (ShouldVerify(policy)) {
    if (!VerifyPlugin(canonical_path, policy)) {
      PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, "plugin_verification_failed",
                              "Plugin verification failed", canonical_path);
      return false;
    }
  }

#if defined(_WIN32)
  DynLib library;
  if (!library.Open(canonical_path)) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, "plugin_library_load_failure",
                            "Failed to load plugin library", canonical_path);
    return false;
  }

  auto init = reinterpret_cast<QV_Plugin_Init>(library.Symbol("qv_plugin_init"));
  auto shutdown = reinterpret_cast<QV_Plugin_Shutdown>(library.Symbol("qv_plugin_shutdown"));
  auto get_info = reinterpret_cast<QV_Plugin_GetInfo>(library.Symbol("qv_plugin_get_info"));

  if (!init || !shutdown || !get_info) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, "plugin_missing_entry_points",
                            "Plugin missing required entry points", canonical_path);
    return false;
  }

  QV_PluginInfo info = get_info();
  if (info.abi_version < policy.min_abi_version || info.abi_version > policy.max_abi_version ||
      info.abi_version != QV_PLUGIN_ABI_VERSION) {
    PublishPluginDiagnostic(
        qv::orchestrator::EventSeverity::kError, "plugin_abi_mismatch",
        "Plugin ABI version outside allowed range", canonical_path,
        {qv::orchestrator::EventField("reported_abi_version", std::to_string(info.abi_version),
                                      qv::orchestrator::FieldPrivacy::kPublic, true)});
    return false;
  }

  if (!ValidateCapabilities(info.capabilities, policy, canonical_path,
                            info.name ? std::string_view(info.name) : std::string_view())) {
    return false;
  }

  if (!policy.plugin_id.empty() && info.name && policy.plugin_id != std::string(info.name)) {
    std::vector<qv::orchestrator::EventField> identity_fields;
    if (!policy.plugin_id.empty()) {
      identity_fields.emplace_back("expected_plugin_id_hash", policy.plugin_id,
                                   qv::orchestrator::FieldPrivacy::kHash);
    }
    if (info.name && *info.name) {
      identity_fields.emplace_back("reported_plugin_id_hash", std::string(info.name),
                                   qv::orchestrator::FieldPrivacy::kHash);
    }
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kWarning, "plugin_identity_mismatch",
                            "Plugin identifier does not match verification policy", canonical_path,
                            std::move(identity_fields));
    return false;
  }

  if (init() != 0) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, "plugin_initialization_failed",
                            "Plugin initialization routine failed", canonical_path);
    return false;
  }

  auto stored = std::make_unique<LoadedPlugin>();
  stored->path = std::move(canonical_path);
  stored->info = info;
  stored->shutdown = shutdown;
  stored->library = std::move(library);
  stored->capabilities = info.capabilities;
  if (info.name)
    stored->name = info.name;
  if (info.version)
    stored->version = info.version;
  loaded_.push_back(std::move(stored));
  qv::orchestrator::Event plugin_loaded{};       // TSK029
  plugin_loaded.category = EventCategory::kLifecycle;
  plugin_loaded.severity = EventSeverity::kInfo;
  plugin_loaded.event_id = "plugin_loaded";
  plugin_loaded.message = "Plugin loaded";
  plugin_loaded.fields.emplace_back("plugin_path", canonical_path.generic_string(),
                                    qv::orchestrator::FieldPrivacy::kHash);
  if (info.name) {
    plugin_loaded.fields.emplace_back("plugin_name", info.name,
                                      qv::orchestrator::FieldPrivacy::kHash);
  }
  if (info.version) {
    plugin_loaded.fields.emplace_back("plugin_version", info.version,
                                      qv::orchestrator::FieldPrivacy::kPublic);
  }
  qv::orchestrator::EventBus::Instance().Publish(plugin_loaded);
  return true;
#else
  int sockets[2];
#if defined(SOCK_CLOEXEC)
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
#else
  if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
#endif
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, "plugin_ipc_failure",
                            "Failed to create plugin IPC channel", canonical_path);
    return false;
  }

#if !defined(SOCK_CLOEXEC)
  for (int fd : sockets) {
    int flags = ::fcntl(fd, F_GETFD);
    if (flags >= 0) {
      ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
  }
#endif

  pid_t pid = ::fork();
  if (pid < 0) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, "plugin_fork_failure",
                            "Failed to fork plugin sandbox", canonical_path);
    ::close(sockets[0]);
    ::close(sockets[1]);
    return false;
  }

  if (pid == 0) {
    ::close(sockets[0]);
    PluginSubprocess(sockets[1], canonical_path);
  }

  ::close(sockets[1]);

  auto cleanup_child = [&](int signal) {
    if (pid > 0) {
      if (signal != 0) {
        ::kill(pid, signal);
      }
      ::waitpid(pid, nullptr, 0);
    }
  };

  PluginHandshakePacket handshake{};
  std::string plugin_name;
  std::string plugin_version;
  if (!ReceiveHandshake(sockets[0], &handshake, plugin_name, plugin_version,
                        kPluginHandshakeTimeout)) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, "plugin_handshake_failure",
                            "Failed to negotiate plugin handshake", canonical_path);
    ::close(sockets[0]);
    cleanup_child(SIGKILL);
    return false;
  }

  if (handshake.status != 0) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, "plugin_child_error",
                            "Sandboxed plugin reported initialization error", canonical_path);
    ::close(sockets[0]);
    cleanup_child(0);
    return false;
  }

  if (handshake.abi_version < policy.min_abi_version || handshake.abi_version > policy.max_abi_version ||
      handshake.abi_version != QV_PLUGIN_ABI_VERSION) {
    PublishPluginDiagnostic(
        qv::orchestrator::EventSeverity::kError, "plugin_abi_mismatch",
        "Plugin ABI version outside allowed range", canonical_path,
        {qv::orchestrator::EventField("reported_abi_version", std::to_string(handshake.abi_version),
                                      qv::orchestrator::FieldPrivacy::kPublic, true)});
    ::close(sockets[0]);
    cleanup_child(SIGKILL);
    return false;
  }

  if (handshake.capability_schema != QV_PLUGIN_CAPABILITY_SCHEMA_VERSION) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError,
                            "plugin_capability_schema_mismatch",
                            "Sandboxed plugin reported incompatible capability schema", canonical_path);
    ::close(sockets[0]);
    cleanup_child(SIGKILL);
    return false;
  }

  if (!ValidateCapabilities(handshake.capabilities, policy, canonical_path, plugin_name)) {
    ::close(sockets[0]);
    cleanup_child(SIGKILL);
    return false;
  }

  if (!policy.plugin_id.empty() && !plugin_name.empty() && policy.plugin_id != plugin_name) {
    std::vector<qv::orchestrator::EventField> identity_fields;
    if (!policy.plugin_id.empty()) {
      identity_fields.emplace_back("expected_plugin_id_hash", policy.plugin_id,
                                   qv::orchestrator::FieldPrivacy::kHash);
    }
    if (!plugin_name.empty()) {
      identity_fields.emplace_back("reported_plugin_id_hash", plugin_name,
                                   qv::orchestrator::FieldPrivacy::kHash);
    }
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kWarning, "plugin_identity_mismatch",
                            "Plugin identifier does not match verification policy", canonical_path,
                            std::move(identity_fields));
    ::close(sockets[0]);
    cleanup_child(SIGKILL);
    return false;
  }

  if (!SendCommandMessage(sockets[0], PluginCommand::kInit)) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, "plugin_init_ipc_failure",
                            "Failed to send plugin init command", canonical_path);
    ::close(sockets[0]);
    cleanup_child(SIGKILL);
    return false;
  }

  int init_status = 0;
  if (!AwaitCommandResult(sockets[0], PluginCommand::kInit, &init_status, kPluginInitTimeout) ||
      init_status != 0) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError, "plugin_initialization_failed",
                            "Plugin initialization routine failed", canonical_path);
    ::close(sockets[0]);
    cleanup_child(SIGKILL);
    return false;
  }

  auto stored = std::make_unique<LoadedPlugin>();
  stored->path = std::move(canonical_path);
  stored->capabilities = handshake.capabilities;
  stored->name = std::move(plugin_name);
  stored->version = std::move(plugin_version);
  stored->pid = pid;
  stored->channel = sockets[0];
  loaded_.push_back(std::move(stored));
  qv::orchestrator::Event plugin_loaded{};       // TSK029
  plugin_loaded.category = EventCategory::kLifecycle;
  plugin_loaded.severity = EventSeverity::kInfo;
  plugin_loaded.event_id = "plugin_loaded";
  plugin_loaded.message = "Plugin loaded";
  plugin_loaded.fields.emplace_back("plugin_path", canonical_path.generic_string(),
                                    qv::orchestrator::FieldPrivacy::kHash);
  if (!loaded_.back()->name.empty()) {
    plugin_loaded.fields.emplace_back("plugin_name", loaded_.back()->name,
                                      qv::orchestrator::FieldPrivacy::kHash);
  }
  if (!loaded_.back()->version.empty()) {
    plugin_loaded.fields.emplace_back("plugin_version", loaded_.back()->version,
                                      qv::orchestrator::FieldPrivacy::kPublic);
  }
  qv::orchestrator::EventBus::Instance().Publish(plugin_loaded);
  return true;
#endif
}

void PluginManager::UnloadAll() {
  while (!loaded_.empty()) {
    auto plugin = std::move(loaded_.back());
    loaded_.pop_back();
#if defined(_WIN32)
    if (plugin->shutdown) {
      plugin->shutdown();
    }
    // library closes when DynLib destructor runs.
#else
    if (plugin->channel >= 0) {
      SendCommandMessage(plugin->channel, PluginCommand::kShutdown);
      AwaitCommandResult(plugin->channel, PluginCommand::kShutdown, nullptr);
      ::close(plugin->channel);
      plugin->channel = -1;
    }
    if (plugin->pid > 0) {
      ::waitpid(plugin->pid, nullptr, 0);
      plugin->pid = -1;
    }
#endif
  }
}
