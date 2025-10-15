#pragma once
#include <filesystem>
#include <memory>
#include <optional>
#include <vector>
#include "qv/orchestrator/plugin_verification.h"

namespace qv::orchestrator {
class PluginManager {
public:
  // TSK010 dynamic loading & lifecycle management.
  PluginManager();
  explicit PluginManager(std::vector<std::filesystem::path> search_paths);

  void AddSearchPath(std::filesystem::path path);
  const std::vector<std::filesystem::path>& SearchPaths() const noexcept;

  size_t LoadFromSearchPaths(const PluginVerification& policy);
  bool LoadPlugin(const std::filesystem::path& so_path,
                  const PluginVerification& policy);
  void UnloadAll();

  ~PluginManager();

private:
  struct LoadedPlugin;
  std::vector<std::filesystem::path> search_paths_;
  std::vector<std::unique_ptr<LoadedPlugin>> loaded_;
};

void ResetPluginSubsystemForTesting(); // TSK110_Initialization_and_Cleanup_Order orchestrator reset hook
} // namespace qv::orchestrator
