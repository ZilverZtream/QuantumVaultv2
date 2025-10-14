#pragma once
#include "qv/core/nonce.h"                                 // TSK040_AAD_Binding_and_Chunk_Authentication nonce binding
#include "qv/crypto/aes_gcm.h"                              // TSK040_AAD_Binding_and_Chunk_Authentication GCM sizes
#include "qv/orchestrator/constant_time_mount.h"
#include <array>      // TSK040_AAD_Binding_and_Chunk_Authentication chunk sealing
#include <chrono>     // TSK036_PBKDF2_Argon2_Migration_Path progress configuration
#include <cstdint>    // TSK033 header version constants
#include <filesystem>
#include <functional> // TSK036_PBKDF2_Argon2_Migration_Path progress callbacks
#include <optional>
#include <span>       // TSK040_AAD_Binding_and_Chunk_Authentication keyed spans
#include <string>
#include <vector>     // TSK040_AAD_Binding_and_Chunk_Authentication ciphertext storage

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

    struct ChunkEncryptionResult { // TSK040_AAD_Binding_and_Chunk_Authentication bundle integrity inputs
      std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE> nonce{};          // TSK040
      std::array<uint8_t, qv::crypto::AES256_GCM::TAG_SIZE> tag{};              // TSK040
      std::array<uint8_t, 32> nonce_chain_mac{};                                // TSK040
      std::vector<uint8_t> ciphertext;                                         // TSK040
    };

    static ChunkEncryptionResult EncryptChunk(std::span<const uint8_t> plaintext,
                                              uint32_t epoch, int64_t chunk_index,
                                              uint64_t logical_offset, uint32_t chunk_size,
                                              qv::core::NonceGenerator& nonce_gen,
                                              std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>
                                                  data_key); // TSK040

    static std::vector<uint8_t>
    DecryptChunk(const ChunkEncryptionResult& sealed_chunk, uint32_t epoch,
                 int64_t chunk_index, uint64_t logical_offset, uint32_t chunk_size,
                 std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>
                     data_key); // TSK040
  };
} // namespace qv::orchestrator
