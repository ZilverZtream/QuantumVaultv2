#pragma once

// TSK712_Header_Backup_and_Restore_Tooling header backup interfaces

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <vector>

#include "qv/crypto/aes_gcm.h"
#include "qv/security/secure_buffer.h"

namespace qv::core {

// Metadata describing the password-based recovery key derivation used to seal
// the backup bundle. // TSK712_Header_Backup_and_Restore_Tooling KDF description
enum class RecoveryKdfAlgorithm { // TSK712_Header_Backup_and_Restore_Tooling algorithm id
  kArgon2id = 1,
};

struct RecoveryKdfParams { // TSK712_Header_Backup_and_Restore_Tooling KDF params
  uint32_t time_cost{3};
  uint32_t memory_cost_kib{64u * 1024u};
  uint32_t parallelism{4};
};

struct RecoveryKdfMetadata { // TSK712_Header_Backup_and_Restore_Tooling metadata blob
  RecoveryKdfAlgorithm algorithm{RecoveryKdfAlgorithm::kArgon2id};
  RecoveryKdfParams params{};
  std::array<uint8_t, 16> salt{};
};

struct RecoveryKeyDescriptor { // TSK712_Header_Backup_and_Restore_Tooling runtime KDF context
  qv::security::SecureBuffer<uint8_t> key{qv::crypto::AES256_GCM::KEY_SIZE};
  RecoveryKdfMetadata metadata{};
};

struct ContainerKdfMetadata { // TSK712_Header_Backup_and_Restore_Tooling container KDF description
  bool have_pbkdf2{false};
  uint32_t pbkdf_iterations{0};
  std::array<uint8_t, 16> pbkdf_salt{};
  bool have_argon2{false};
  uint32_t argon2_version{0};
  RecoveryKdfParams argon2_params{};
  uint32_t argon2_hash_length{0};
  uint32_t argon2_target_ms{0};
  std::array<uint8_t, 16> argon2_salt{};
};

struct ContainerHeaderMetadata { // TSK712_Header_Backup_and_Restore_Tooling exposed fields
  std::array<uint8_t, 16> uuid{};
  uint32_t version{0};
  uint32_t flags{0};
  ContainerKdfMetadata kdf{};
};

struct HeaderBackupMetadata { // TSK712_Header_Backup_and_Restore_Tooling backup manifest
  uint16_t format_version{0};
  ContainerHeaderMetadata container{};
  RecoveryKdfMetadata recovery{};
};

// Serialize the container header located at |container| into an encrypted
// backup bundle written to |out| using the supplied recovery key. Returns true
// on success and throws qv::Error on failure. // TSK712_Header_Backup_and_Restore_Tooling entrypoint
bool BackupHeader(const std::filesystem::path& container,
                  const std::filesystem::path& out,
                  const RecoveryKeyDescriptor& recovery);

// Restore the encrypted header stored in |in| back into |container| using the
// caller-provided recovery key. Returns true on success and throws
// qv::Error/qv::AuthenticationFailureError on failure. // TSK712_Header_Backup_and_Restore_Tooling entrypoint
bool RestoreHeader(const std::filesystem::path& container,
                   const std::filesystem::path& in,
                   const RecoveryKeyDescriptor& recovery);

// Inspect the container header without performing I/O writes. Used to surface
// human-readable metadata for warnings and documentation. // TSK712_Header_Backup_and_Restore_Tooling helper
ContainerHeaderMetadata ReadContainerHeaderMetadata(
    const std::filesystem::path& container);

// Inspect a backup bundle and return the parsed metadata without attempting to
// decrypt the payload. // TSK712_Header_Backup_and_Restore_Tooling helper
HeaderBackupMetadata InspectHeaderBackup(const std::filesystem::path& backup);

}  // namespace qv::core

