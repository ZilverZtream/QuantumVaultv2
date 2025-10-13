#pragma once
#include "qv/orchestrator/constant_time_mount.h"
#include <filesystem>
#include <optional>
#include <string>

namespace qv::orchestrator {
  class VolumeManager {
    ConstantTimeMount ctm_;

  public:
    std::optional<ConstantTimeMount::VolumeHandle> Create(const std::filesystem::path& container,
                                                          const std::string& password);
    std::optional<ConstantTimeMount::VolumeHandle> Mount(const std::filesystem::path& container,
                                                         const std::string& password);
    std::optional<ConstantTimeMount::VolumeHandle>
    Rekey(const std::filesystem::path& container, const std::string& current_password,
          const std::string& new_password,
          std::optional<std::filesystem::path> backup_public_key = std::nullopt); // TSK024_Key_Rotation_and_Lifecycle_Management
  };
} // namespace qv::orchestrator
