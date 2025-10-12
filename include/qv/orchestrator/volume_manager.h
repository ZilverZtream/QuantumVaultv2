#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include "qv/orchestrator/constant_time_mount.h"

namespace qv::orchestrator {
class VolumeManager {
  ConstantTimeMount ctm_;
public:
  std::optional<ConstantTimeMount::VolumeHandle> Create(const std::filesystem::path& container,
                                                       const std::string& password);
  std::optional<ConstantTimeMount::VolumeHandle> Mount(const std::filesystem::path& container,
                                                      const std::string& password);
};
} // namespace qv::orchestrator
