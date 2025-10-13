#include "qv/orchestrator/plugin_manager.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <dlfcn.h>
#endif

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
    std::cerr << "[PluginManager] Unable to resolve path for " << so_path << "\n";
    return false;
  }

  for (const auto& plugin : loaded_) {
    if (plugin->path == canonical_path) {
      std::cerr << "[PluginManager] Plugin already loaded: " << canonical_path << "\n";
      return false;
    }
  }

  if (!std::filesystem::is_regular_file(canonical_path, ec)) {
    std::cerr << "[PluginManager] Not a regular file: " << canonical_path << "\n";
    return false;
  }

  if (ShouldVerify(policy)) {
    if (!VerifyPlugin(canonical_path, policy)) {
      std::cerr << "[PluginManager] Verification failed for " << canonical_path << "\n";
      return false;
    }
  }

  DynLib library;
  if (!library.Open(canonical_path)) {
    std::cerr << "[PluginManager] Failed to load library: " << canonical_path << "\n";
    return false;
  }

  auto init = reinterpret_cast<QV_Plugin_Init>(library.Symbol("qv_plugin_init"));
  auto shutdown =
      reinterpret_cast<QV_Plugin_Shutdown>(library.Symbol("qv_plugin_shutdown"));
  auto get_info = reinterpret_cast<QV_Plugin_GetInfo>(library.Symbol("qv_plugin_get_info"));

  if (!init || !shutdown || !get_info) {
    std::cerr << "[PluginManager] Missing required entry points in " << canonical_path
              << "\n";
    return false;
  }

  QV_PluginInfo info = get_info();
  if (info.abi_version < policy.min_abi_version ||
      info.abi_version > policy.max_abi_version ||
      info.abi_version != QV_PLUGIN_ABI_VERSION) {
    std::cerr << "[PluginManager] ABI mismatch for " << canonical_path << " (got "
              << info.abi_version << ")\n";
    return false;
  }

  if (!policy.plugin_id.empty() && info.name &&
      policy.plugin_id != std::string(info.name)) {
    std::cerr << "[PluginManager] Plugin identity mismatch for " << canonical_path << "\n";
    return false;
  }

  if (init() != 0) {
    std::cerr << "[PluginManager] Initialization failed for " << canonical_path << "\n";
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
