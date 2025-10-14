#pragma once
#include "qv/orchestrator/constant_time_mount.h"
#include <chrono>    // TSK036_PBKDF2_Argon2_Migration_Path progress configuration
#include <cstdint>   // TSK033 header version constants
#include <filesystem>
#include <functional> // TSK036_PBKDF2_Argon2_Migration_Path progress callbacks
#include <optional>
#include <string>

namespace qv::orchestrator {
  class VolumeManager {
  public:
    static constexpr uint32_t kLatestHeaderVersion = 0x00040100u; // TSK033 expose canonical header target

    enum class PasswordKdf { // TSK036_PBKDF2_Argon2_Migration_Path
      kPbkdf2,
      kArgon2id
    };

    using ProgressCallback = std::function<void(uint32_t current, uint32_t total)>; // TSK036_PBKDF2_Argon2_Migration_Path

    struct KdfPolicy { // TSK036_PBKDF2_Argon2_Migration_Path
      PasswordKdf algorithm{PasswordKdf::kPbkdf2};
      std::optional<uint32_t> iteration_override{};
      std::chrono::milliseconds target_duration{std::chrono::milliseconds(500)};
      ProgressCallback progress{};
    };

  private:
    ConstantTimeMount ctm_;
    KdfPolicy kdf_policy_{}; // TSK036_PBKDF2_Argon2_Migration_Path

  public:
    VolumeManager();                           // TSK036_PBKDF2_Argon2_Migration_Path initialize default policy
    explicit VolumeManager(KdfPolicy policy);  // TSK036_PBKDF2_Argon2_Migration_Path explicit configuration
    void SetKdfPolicy(const KdfPolicy& policy); // TSK036_PBKDF2_Argon2_Migration_Path update policy at runtime
    [[nodiscard]] const KdfPolicy& GetKdfPolicy() const; // TSK036_PBKDF2_Argon2_Migration_Path expose effective policy

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
