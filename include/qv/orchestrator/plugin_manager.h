#pragma once
#include <filesystem>
#include <vector>
#include <optional>
#include "qv/orchestrator/plugin_verification.h"

namespace qv::orchestrator {
class PluginManager {
public:
  bool LoadPlugin(const std::filesystem::path& so_path,
                  const PluginVerification& policy);
};
} // namespace qv::orchestrator
