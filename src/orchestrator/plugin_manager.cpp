#include "qv/orchestrator/plugin_manager.h"
#include <iostream>

using namespace qv::orchestrator;

bool PluginManager::LoadPlugin(const std::filesystem::path& so_path,
                               const PluginVerification& policy) {
  std::cout << "Loading plugin: " << so_path << "\n";
  // STUB: accept always.
  (void)policy;
  return true;
}
