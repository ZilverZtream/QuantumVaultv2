#include "qv/orchestrator/plugin_manager.h"

#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <dlfcn.h>
#endif

#include "qv/orchestrator/event_bus.h"  // TSK019
#include "qv/orchestrator/plugin_abi.h"

using namespace qv::orchestrator;

namespace {

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
  DynLib(DynLib&& other) noexcept { *this = std::move(other); }
  DynLib& operator=(DynLib&& other) noexcept {
    if (this != &other) {
      Close();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  ~DynLib() { Close(); }

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
    if (!handle_) return nullptr;
#if defined(_WIN32)
    return reinterpret_cast<void*>(::GetProcAddress(handle_, name));
#else
    return ::dlsym(handle_, name);
#endif
  }

  void Close() {
    if (!handle_) return;
#if defined(_WIN32)
    ::FreeLibrary(handle_);
#else
    ::dlclose(handle_);
#endif
    handle_ = nullptr;
  }

  bool IsOpen() const { return handle_ != nullptr; }

private:
  handle_type handle_{nullptr};
};

std::filesystem::path Canonicalize(const std::filesystem::path& path) {
  std::error_code ec;
  auto canonical = std::filesystem::weakly_canonical(path, ec);
  if (!ec) return canonical;
  auto absolute = std::filesystem::absolute(path, ec);
  if (!ec) return absolute;
  return path;
}

void AppendUnique(std::vector<std::filesystem::path>& paths,
                  std::filesystem::path candidate) {
  candidate = Canonicalize(candidate);
  if (candidate.empty()) return;
  for (const auto& existing : paths) {
    if (existing == candidate) return;
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
      auto segment = value.substr(start, end == std::string::npos ? std::string::npos
                                                                  : end - start);
      if (!segment.empty()) {
        AppendUnique(paths, std::filesystem::path(segment));
      }
      if (end == std::string::npos) break;
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
    if (byte != 0) return true;
  }
  if (verification.enforce_signature) return true;
  for (uint8_t byte : verification.signature) {
    if (byte != 0) return true;
  }
  return false;
}

void PublishPluginDiagnostic(
    qv::orchestrator::EventSeverity severity, std::string_view event_id,
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
  QV_PluginInfo info{};
  QV_Plugin_Shutdown shutdown{nullptr};
  DynLib library;
};

PluginManager::PluginManager()
    : search_paths_(ResolveDefaultSearchPaths()) {}

PluginManager::PluginManager(std::vector<std::filesystem::path> search_paths)
    : search_paths_() {
  for (auto& path : search_paths) {
    AddSearchPath(std::move(path));
  }
}

PluginManager::~PluginManager() { UnloadAll(); }

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
    if (!std::filesystem::exists(directory, ec) ||
        !std::filesystem::is_directory(directory, ec)) {
      continue;
    }

    for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
      if (ec) break;
      const auto& path = entry.path();
      if (!entry.is_regular_file(ec)) continue;
      if (path.extension() != PluginExtension()) continue;
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
    canonical_path = std::filesystem::absolute(so_path, ec);
  }
  if (ec) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError,
                            "plugin_path_resolution_failure",
                            "Unable to resolve plugin path", so_path);
    return false;
  }

  for (const auto& plugin : loaded_) {
    if (plugin->path == canonical_path) {
      PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kWarning,
                              "plugin_already_loaded",
                              "Plugin already loaded", canonical_path);
      return false;
    }
  }

  if (!std::filesystem::is_regular_file(canonical_path, ec)) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError,
                            "plugin_not_regular_file",
                            "Plugin candidate is not a regular file", canonical_path);
    return false;
  }

  if (ShouldVerify(policy)) {
    if (!VerifyPlugin(canonical_path, policy)) {
      PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError,
                              "plugin_verification_failed",
                              "Plugin verification failed", canonical_path);
      return false;
    }
  }

  DynLib library;
  if (!library.Open(canonical_path)) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError,
                            "plugin_library_load_failure",
                            "Failed to load plugin library", canonical_path);
    return false;
  }

  auto init = reinterpret_cast<QV_Plugin_Init>(library.Symbol("qv_plugin_init"));
  auto shutdown =
      reinterpret_cast<QV_Plugin_Shutdown>(library.Symbol("qv_plugin_shutdown"));
  auto get_info = reinterpret_cast<QV_Plugin_GetInfo>(library.Symbol("qv_plugin_get_info"));

  if (!init || !shutdown || !get_info) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError,
                            "plugin_missing_entry_points",
                            "Plugin missing required entry points", canonical_path);
    return false;
  }

  QV_PluginInfo info = get_info();
  if (info.abi_version < policy.min_abi_version ||
      info.abi_version > policy.max_abi_version ||
      info.abi_version != QV_PLUGIN_ABI_VERSION) {
    PublishPluginDiagnostic(
        qv::orchestrator::EventSeverity::kError, "plugin_abi_mismatch",
        "Plugin ABI version outside allowed range", canonical_path,
        {qv::orchestrator::EventField("reported_abi_version",
                                      std::to_string(info.abi_version),
                                      qv::orchestrator::FieldPrivacy::kPublic, true)});
    return false;
  }

  if (!policy.plugin_id.empty() && info.name &&
      policy.plugin_id != std::string(info.name)) {
    std::vector<qv::orchestrator::EventField> identity_fields;
    if (!policy.plugin_id.empty()) {
      identity_fields.emplace_back("expected_plugin_id_hash", policy.plugin_id,
                                   qv::orchestrator::FieldPrivacy::kHash);
    }
    if (info.name && *info.name) {
      identity_fields.emplace_back("reported_plugin_id_hash", std::string(info.name),
                                   qv::orchestrator::FieldPrivacy::kHash);
    }
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kWarning,
                            "plugin_identity_mismatch",
                            "Plugin identifier does not match verification policy",
                            canonical_path, std::move(identity_fields));
    return false;
  }

  if (init() != 0) {
    PublishPluginDiagnostic(qv::orchestrator::EventSeverity::kError,
                            "plugin_initialization_failed",
                            "Plugin initialization routine failed", canonical_path);
    return false;
  }

  auto stored = std::make_unique<LoadedPlugin>();
  stored->path = std::move(canonical_path);
  stored->info = info;
  stored->shutdown = shutdown;
  stored->library = std::move(library);
  loaded_.push_back(std::move(stored));
  return true;
}

void PluginManager::UnloadAll() {
  while (!loaded_.empty()) {
    auto plugin = std::move(loaded_.back());
    loaded_.pop_back();
    if (plugin->shutdown) {
      plugin->shutdown();
    }
    // library closes when DynLib destructor runs.
  }
}
