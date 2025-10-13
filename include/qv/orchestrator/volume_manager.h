#pragma once
#include "qv/orchestrator/constant_time_mount.h"
#include <cstdint> // TSK033 header version constants
#include <filesystem>
#include <optional>
#include <string>

namespace qv::orchestrator {
  class VolumeManager {
  public:
    static constexpr uint32_t kLatestHeaderVersion = 0x00040100u; // TSK033 expose canonical header target

  private:
    ConstantTimeMount ctm_;

  public:
    // TSK032_Backup_Recovery_and_Disaster_Recovery enforce metadata compatibility during lifecycle
    std::optional<ConstantTimeMount::VolumeHandle> Create(const std::filesystem::path& container,
                                                          const std::string& password);
    std::optional<ConstantTimeMount::VolumeHandle> Mount(const std::filesystem::path& container,
                                                         const std::string& password);
    std::optional<ConstantTimeMount::VolumeHandle>
    Rekey(const std::filesystem::path& container, const std::string& current_password,
          const std::string& new_password,
          std::optional<std::filesystem::path> backup_public_key =
              std::nullopt); // TSK024_Key_Rotation_and_Lifecycle_Management
    std::optional<ConstantTimeMount::VolumeHandle>
    Migrate(const std::filesystem::path& container, uint32_t target_version,
            const std::string& password); // TSK033 header migration entrypoint
  };
} // namespace qv::orchestrator
