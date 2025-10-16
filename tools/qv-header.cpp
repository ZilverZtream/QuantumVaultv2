#include <algorithm>
#include <array>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <span>

// TSK712_Header_Backup_and_Restore_Tooling standalone header tool

#include "qv/core/header_io.h"
#include "qv/crypto/random.h"
#include "qv/error.h"
#include "qv/security/secure_buffer.h"
#include "qv/security/zeroizer.h"

#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2
#include <argon2.h>
#endif

namespace {

void PrintUsage() { // TSK712_Header_Backup_and_Restore_Tooling usage banner
  std::cout << "Usage:\n"
            << "  qv-header backup --container=<path> --out=<file> [--password-file=<file>]\n"
            << "  qv-header restore --container=<path> --in=<file> [--password-file=<file>]\n"
            << "  qv-header inspect --in=<file>\n";
}

void SecureZero(std::string& value) { // TSK712_Header_Backup_and_Restore_Tooling wipe helper
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(reinterpret_cast<uint8_t*>(value.data()), value.size()));
}

std::string HexEncode(std::span<const uint8_t> data) { // TSK712_Header_Backup_and_Restore_Tooling hex formatting
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (auto byte : data) {
    oss << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

std::string FormatUuid(const std::array<uint8_t, 16>& uuid) { // TSK712_Header_Backup_and_Restore_Tooling uuid formatting
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < uuid.size(); ++i) {
    oss << std::setw(2) << static_cast<int>(uuid[i]);
    if (i == 3 || i == 5 || i == 7 || i == 9) {
      oss << '-';
    }
  }
  return oss.str();
}

const char* RecoveryAlgorithmToString(qv::core::RecoveryKdfAlgorithm algo) { // TSK712
  switch (algo) {
    case qv::core::RecoveryKdfAlgorithm::kArgon2id:
      return "argon2id";
  }
  return "unknown";
}

qv::core::RecoveryKdfMetadata MakeDefaultRecoveryMetadata() { // TSK712 default Argon2 tuning
  qv::core::RecoveryKdfMetadata metadata{};
  metadata.params.time_cost = 4;
  metadata.params.memory_cost_kib = 128u * 1024u;
  metadata.params.parallelism = 4;
  qv::crypto::SystemRandomBytes(std::span<uint8_t>(metadata.salt)); // TSK712_Header_Backup_and_Restore_Tooling random salt source
  return metadata;
}

qv::security::SecureBuffer<uint8_t>
DeriveRecoveryKey(const std::string& password, const qv::core::RecoveryKdfMetadata& metadata) { // TSK712
#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2
  if (metadata.algorithm != qv::core::RecoveryKdfAlgorithm::kArgon2id) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Unsupported recovery KDF"};
  }
  qv::security::SecureBuffer<uint8_t> key(qv::crypto::AES256_GCM::KEY_SIZE);
  auto span = key.AsSpan();
  int rc = argon2id_hash_raw(metadata.params.time_cost, metadata.params.memory_cost_kib,
                             metadata.params.parallelism,
                             reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                             metadata.salt.data(), metadata.salt.size(), span.data(), span.size());
  if (rc != ARGON2_OK) {
    throw qv::Error{qv::ErrorDomain::Crypto, rc,
                    std::string("Recovery key derivation failed: ") + argon2_error_message(rc)};
  }
  return key;
#else
  (void)password;
  (void)metadata;
  throw qv::Error{qv::ErrorDomain::Dependency, 0, "Argon2 support unavailable"};
#endif
}

std::string ReadPasswordInteractive(const std::string& prompt) { // TSK712 simple password reader
  std::cout << prompt << std::flush;
  std::string password;
  std::getline(std::cin, password);
  return password;
}

std::string ReadPasswordFromFile(const std::filesystem::path& path) { // TSK712 file password helper
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open password file: " + path.string()};
  }
  std::string password;
  std::getline(in, password);
  return password;
}

std::string AcquirePassword(const std::optional<std::filesystem::path>& file,
                            const std::string& prompt) { // TSK712
  if (file) {
    return ReadPasswordFromFile(*file);
  }
  return ReadPasswordInteractive(prompt);
}

void PrintHeaderInfo(const qv::core::HeaderBackupMetadata& metadata) { // TSK712 metadata display
  std::cout << "Backup format version: " << metadata.format_version << '\n';
  std::cout << "Container UUID: " << FormatUuid(metadata.container.uuid) << '\n';
  std::cout << "Container header version: 0x" << std::hex << std::setw(8) << std::setfill('0')
            << metadata.container.version << std::dec << '\n';
  std::cout << "Container flags: 0x" << std::hex << std::setw(8) << std::setfill('0')
            << metadata.container.flags << std::dec << '\n';
  if (metadata.container.kdf.have_pbkdf2) {
    std::cout << "  PBKDF2 iterations: " << metadata.container.kdf.pbkdf_iterations << '\n';
    std::cout << "  PBKDF2 salt: "
              << HexEncode(std::span<const uint8_t>(metadata.container.kdf.pbkdf_salt.data(),
                                                    metadata.container.kdf.pbkdf_salt.size()))
              << '\n';
  }
  if (metadata.container.kdf.have_argon2) {
    std::cout << "  Argon2id time=" << metadata.container.kdf.argon2_params.time_cost
              << " memory KiB=" << metadata.container.kdf.argon2_params.memory_cost_kib
              << " parallelism=" << metadata.container.kdf.argon2_params.parallelism << '\n';
    std::cout << "  Argon2 salt: "
              << HexEncode(std::span<const uint8_t>(metadata.container.kdf.argon2_salt.data(),
                                                    metadata.container.kdf.argon2_salt.size()))
              << '\n';
  }
  std::cout << "Recovery KDF: " << RecoveryAlgorithmToString(metadata.recovery.algorithm) << '\n';
  std::cout << "  Time cost: " << metadata.recovery.params.time_cost
            << "  Memory KiB: " << metadata.recovery.params.memory_cost_kib
            << "  Parallelism: " << metadata.recovery.params.parallelism << '\n';
  std::cout << "  Salt: "
            << HexEncode(std::span<const uint8_t>(metadata.recovery.salt.data(),
                                                  metadata.recovery.salt.size()))
            << '\n';
}

}  // namespace

int main(int argc, char** argv) { // TSK712 command dispatcher
  if (argc < 2) {
    PrintUsage();
    return 64;
  }
  try {
    const std::string command = argv[1];
    if (command == "backup") {
      std::optional<std::filesystem::path> container;
      std::optional<std::filesystem::path> backup;
      std::optional<std::filesystem::path> password_file;
      for (int i = 2; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg.rfind("--container=", 0) == 0) {
          container = std::filesystem::path(std::string(arg.substr(12)));
          continue;
        }
        if (arg.rfind("--out=", 0) == 0) {
          backup = std::filesystem::path(std::string(arg.substr(6)));
          continue;
        }
        if (arg.rfind("--password-file=", 0) == 0) {
          password_file = std::filesystem::path(std::string(arg.substr(16)));
          continue;
        }
        PrintUsage();
        return 64;
      }
      if (!container || !backup) {
        PrintUsage();
        return 64;
      }
      auto password = AcquirePassword(password_file, "Recovery password: ");
      std::string confirm;
      if (!password_file) {
        confirm = AcquirePassword(std::nullopt, "Confirm recovery password: ");
        if (password != confirm) {
          SecureZero(password);
          SecureZero(confirm);
          std::cerr << "Validation error: Recovery passwords do not match." << std::endl;
          return 64;
        }
      }
      auto metadata = MakeDefaultRecoveryMetadata();
      qv::security::SecureBuffer<uint8_t> key(0);
      try {
        key = DeriveRecoveryKey(password, metadata);
      } catch (...) {
        SecureZero(password);
        SecureZero(confirm);
        throw;
      }
      SecureZero(password);
      SecureZero(confirm);

      qv::core::RecoveryKeyDescriptor descriptor;
      descriptor.key = std::move(key);
      descriptor.metadata = metadata;
      qv::core::BackupHeader(*container, *backup, descriptor);
      std::cout << "Header backup written to " << backup->string() << '\n';
      std::cout << "Store the backup file and recovery password separately." << std::endl;
      return 0;
    }
    if (command == "restore") {
      std::optional<std::filesystem::path> container;
      std::optional<std::filesystem::path> backup;
      std::optional<std::filesystem::path> password_file;
      for (int i = 2; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg.rfind("--container=", 0) == 0) {
          container = std::filesystem::path(std::string(arg.substr(12)));
          continue;
        }
        if (arg.rfind("--in=", 0) == 0) {
          backup = std::filesystem::path(std::string(arg.substr(5)));
          continue;
        }
        if (arg.rfind("--password-file=", 0) == 0) {
          password_file = std::filesystem::path(std::string(arg.substr(16)));
          continue;
        }
        PrintUsage();
        return 64;
      }
      if (!container || !backup) {
        PrintUsage();
        return 64;
      }
      auto metadata = qv::core::InspectHeaderBackup(*backup);
      auto password = AcquirePassword(password_file, "Recovery password: ");
      qv::security::SecureBuffer<uint8_t> key(0);
      try {
        key = DeriveRecoveryKey(password, metadata.recovery);
      } catch (...) {
        SecureZero(password);
        throw;
      }
      SecureZero(password);
      qv::core::RecoveryKeyDescriptor descriptor;
      descriptor.key = std::move(key);
      descriptor.metadata = metadata.recovery;
      qv::core::RestoreHeader(*container, *backup, descriptor);
      std::cout << "Header restored." << std::endl;
      return 0;
    }
    if (command == "inspect") {
      std::optional<std::filesystem::path> backup;
      for (int i = 2; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg.rfind("--in=", 0) == 0) {
          backup = std::filesystem::path(std::string(arg.substr(5)));
          continue;
        }
        PrintUsage();
        return 64;
      }
      if (!backup) {
        PrintUsage();
        return 64;
      }
      auto metadata = qv::core::InspectHeaderBackup(*backup);
      PrintHeaderInfo(metadata);
      return 0;
    }
    PrintUsage();
    return 64;
  } catch (const qv::Error& err) {
    std::cerr << "Error: " << err.message << std::endl;
    return 74;
  } catch (const std::exception& err) {
    std::cerr << "Fatal: " << err.what() << std::endl;
    return 74;
  }
}

