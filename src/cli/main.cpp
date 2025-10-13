#include <algorithm>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "qv/core/nonce.h"
#include "qv/error.h"
#include "qv/orchestrator/volume_manager.h"

#ifdef _WIN32
#include <windows.h>
#else // _WIN32
#include <cerrno>
#include <termios.h>
#include <unistd.h>
#endif // _WIN32

namespace {

  // TSK009
  constexpr int kExitOk = 0;
  constexpr int kExitUsage = 64;
  constexpr int kExitIO = 74;
  constexpr int kExitAuth = 77;

  void PrintUsage() {
    std::cerr << "QuantumVault (skeleton)\n";
    std::cerr << "Usage:\n";
    std::cerr << "  qv create <container>\n";
    std::cerr << "  qv mount  <container>\n";
    std::cerr << "  qv rekey  [--backup-key=<path>] <container>\n"; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::cerr << "  qv migrate-nonces <container>\n";
  }

  std::filesystem::path MetadataDirFor(const std::filesystem::path& container) {
    auto parent = container.parent_path();
    auto name = container.filename().string();
    if (name.empty()) {
      name = "volume";
    }
    return parent / (name + ".meta");
  }

  std::filesystem::path MetadataNonceLogPath(const std::filesystem::path& container) {
    return MetadataDirFor(container) / "nonce.log";
  }

  void SecureZero(std::string& s) {
    std::fill(s.begin(), s.end(), '\0');
    s.clear();
  }

#ifdef _WIN32
  class ConsoleModeGuard {
  public:
    ConsoleModeGuard(HANDLE handle, DWORD mode) : handle_(handle), mode_(mode), restored_(false) {}
    ~ConsoleModeGuard() {
      Restore();
    }
    void Restore() {
      if (!restored_ && handle_ != INVALID_HANDLE_VALUE) {
        SetConsoleMode(handle_, mode_);
        restored_ = true;
      }
    }

  private:
    HANDLE handle_;
    DWORD mode_;
    bool restored_;
  };

  std::string ReadPassword(const std::string& prompt) {
    HANDLE h_in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE h_out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h_in == INVALID_HANDLE_VALUE || h_out == INVALID_HANDLE_VALUE) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kConsoleUnavailable, // TSK020
                      std::string("Console unavailable for password entry (Win32 error ") +
                          std::to_string(GetLastError()) + ")"};
    }
    DWORD mode = 0;
    if (!GetConsoleMode(h_in, &mode)) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kConsoleModeQueryFailed, // TSK020
                      std::string("Failed to query console mode (Win32 error ") +
                          std::to_string(GetLastError()) + ")"};
    }
    ConsoleModeGuard guard(h_in, mode);
    DWORD silent_mode = mode & ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(h_in, silent_mode)) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kConsoleEchoDisableFailed, // TSK020
                      std::string("Failed to disable console echo (Win32 error ") +
                          std::to_string(GetLastError()) + ")"};
    }

    DWORD written = 0;
    WriteConsoleA(h_out, prompt.c_str(), static_cast<DWORD>(prompt.size()), &written, nullptr);

    std::wstring buffer;
    buffer.reserve(128);
    while (true) {
      wchar_t ch = 0;
      DWORD read = 0;
      if (!ReadConsoleW(h_in, &ch, 1, &read, nullptr)) {
        throw qv::Error{qv::ErrorDomain::IO,
                        qv::errors::io::kPasswordReadFailed, // TSK020
                        std::string("Failed to read password (Win32 error ") +
                            std::to_string(GetLastError()) + ")"};
      }
      if (read == 0) {
        continue;
      }
      if (ch == L'\r') {
        continue;
      }
      if (ch == L'\n') {
        break;
      }
      if (ch == L'\b') {
        if (!buffer.empty()) {
          buffer.pop_back();
        }
        continue;
      }
      buffer.push_back(ch);
    }

    guard.Restore();
    WriteConsoleA(h_out, "\n", 1, &written, nullptr);

    if (buffer.empty()) {
      return std::string{};
    }

    int needed = WideCharToMultiByte(CP_UTF8, 0, buffer.data(), static_cast<int>(buffer.size()),
                                     nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kPasswordReadFailed, // TSK020
                      std::string("Failed to convert password encoding (Win32 error ") +
                          std::to_string(GetLastError()) + ")"};
    }
    std::string password(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, buffer.data(), static_cast<int>(buffer.size()), password.data(),
                        needed, nullptr, nullptr);
    return password;
  }
#else  // _WIN32

  class TermiosGuard {
  public:
    TermiosGuard(int fd, const termios& state) : fd_(fd), state_(state), restored_(false) {}
    ~TermiosGuard() {
      Restore();
    }
    void Restore() {
      if (!restored_) {
        tcsetattr(fd_, TCSAFLUSH, &state_);
        restored_ = true;
      }
    }

  private:
    int fd_;
    termios state_;
    bool restored_;
  };

  std::string ReadPassword(const std::string& prompt) {
    if (!isatty(STDIN_FILENO)) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kPasswordPromptNeedsTty, // TSK020
                      "Password prompt requires a TTY"};
    }
    termios original{};
    if (tcgetattr(STDIN_FILENO, &original) != 0) {
      const int err = errno;
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kConsoleModeQueryFailed, // TSK020
                      std::string("Failed to query terminal attributes (errno ") +
                          std::to_string(err) + ")"};
    }
    TermiosGuard guard(STDIN_FILENO, original);
    termios silent = original;
    silent.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent) != 0) {
      const int err = errno;
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kConsoleEchoDisableFailed, // TSK020
                      std::string("Failed to disable terminal echo (errno ") + std::to_string(err) +
                          ")"};
    }

    std::cout << prompt << std::flush;
    std::string password;
    if (!std::getline(std::cin, password)) {
      const int err = errno;
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kPasswordReadFailed, // TSK020
                      std::string("Failed to read password (errno ") + std::to_string(err) + ")"};
    }
    guard.Restore();
    std::cout << std::endl;
    return password;
  }
#endif // _WIN32

  std::string_view DomainPrefix(qv::ErrorDomain domain) {
    switch (domain) {
    case qv::ErrorDomain::IO:
      return "I/O error"; // TSK020
    case qv::ErrorDomain::Security:
      return "Security error"; // TSK020
    case qv::ErrorDomain::Crypto:
      return "Cryptography error"; // TSK020
    case qv::ErrorDomain::Validation:
      return "Validation error"; // TSK020
    case qv::ErrorDomain::Config:
      return "Configuration error"; // TSK020
    case qv::ErrorDomain::Dependency:
      return "Dependency error"; // TSK020
    case qv::ErrorDomain::State:
      return "State error"; // TSK020
    case qv::ErrorDomain::Internal:
      return "Internal error"; // TSK020
    }
    return "Error";
  }

  std::string DescribeError(const qv::Error& err) {
    if (!qv::IsFrameworkErrorCode(err.domain, err.code)) {
      return std::string(err.what());
    }

    switch (err.domain) {
    case qv::ErrorDomain::IO:
      switch (err.code) {
      case qv::errors::io::kConsoleUnavailable:
        return "Console unavailable for secure password entry. Details: " + std::string(err.what());
      case qv::errors::io::kConsoleModeQueryFailed:
        return "Unable to query terminal settings. Details: " + std::string(err.what());
      case qv::errors::io::kConsoleEchoDisableFailed:
        return "Unable to disable terminal echo before password entry. Details: " +
               std::string(err.what());
      case qv::errors::io::kPasswordReadFailed:
        return "Failed to read password input securely. Details: " + std::string(err.what());
      case qv::errors::io::kPasswordPromptNeedsTty:
        return "Password prompt requires an interactive terminal. Details: " +
               std::string(err.what());
      case qv::errors::io::kContainerMissing:
        return "Container file not found. Details: " + std::string(err.what());
      case qv::errors::io::kLegacyNonceMissing:
        return "Legacy nonce log was not found. Details: " + std::string(err.what());
      case qv::errors::io::kLegacyNonceWriteFailed:
        return "Failed to write nonce log to metadata directory. Details: " +
               std::string(err.what());
      default:
        return std::string(err.what());
      }
    case qv::ErrorDomain::Security:
      if (err.code == qv::errors::security::kAuthenticationRejected) {
        return "Credentials rejected by security policy. Details: " + std::string(err.what());
      }
      return std::string(err.what());
    case qv::ErrorDomain::Crypto:
      return "Cryptographic provider failure. Details: " + std::string(err.what());
    case qv::ErrorDomain::Validation:
      if (err.code == qv::errors::validation::kVolumeExists) {
        return "A container already exists at the requested path. Details: " +
               std::string(err.what());
      }
      return std::string(err.what());
    case qv::ErrorDomain::Config:
    case qv::ErrorDomain::Dependency:
    case qv::ErrorDomain::State:
    case qv::ErrorDomain::Internal:
      return std::string(err.what());
    }

    return std::string(err.what());
  }

  void ReportError(const qv::Error& err) {
    std::cerr << DomainPrefix(err.domain) << ": " << DescribeError(err) << '\n';
  }

  int ExitCodeFor(const qv::Error& err) {
    switch (err.domain) {
    case qv::ErrorDomain::IO:
      return kExitIO;
    case qv::ErrorDomain::Security:
    case qv::ErrorDomain::Crypto:
      return kExitAuth;
    case qv::ErrorDomain::Validation:
      return kExitUsage;
    case qv::ErrorDomain::Config:
      return kExitUsage; // TSK020
    case qv::ErrorDomain::Dependency:
    case qv::ErrorDomain::State:
    case qv::ErrorDomain::Internal:
    default:
      return kExitIO;
    }
  }

  int HandleCreate(const std::filesystem::path& container, qv::orchestrator::VolumeManager& vm) {
    auto password = ReadPassword("Password: ");
    auto confirm = ReadPassword("Confirm password: ");
    if (password != confirm) {
      SecureZero(password);
      SecureZero(confirm);
      std::cerr << "Validation error: Passwords do not match." << std::endl;
      return kExitUsage;
    }
    auto handle = vm.Create(container, password);
    SecureZero(password);
    SecureZero(confirm);
    if (!handle) {
      std::cerr << "I/O error: Failed to create volume." << std::endl;
      return kExitIO;
    }
    std::cout << "Created." << std::endl;
    return kExitOk;
  }

  int HandleMount(const std::filesystem::path& container, qv::orchestrator::VolumeManager& vm) {
    if (!std::filesystem::exists(container)) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kContainerMissing, // TSK020
                      "Container not found: " + container.string()};
    }
    auto lock_path = container;
    lock_path += ".locked"; // TSK026
    std::error_code lock_ec;
    if (std::filesystem::exists(lock_path, lock_ec)) {
      throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                      "Volume is locked due to repeated authentication failures"}; // TSK026
    }
    auto password = ReadPassword("Password: ");
    auto handle = vm.Mount(container, password);
    SecureZero(password);
    if (!handle) {
      std::cerr << "Authentication failed." << std::endl;
      return kExitAuth;
    }
    std::cout << "Mounted." << std::endl;
    return kExitOk;
  }

  int HandleRekey(const std::filesystem::path& container,
                  std::optional<std::filesystem::path> backup_key,
                  qv::orchestrator::VolumeManager& vm) { // TSK024_Key_Rotation_and_Lifecycle_Management
    auto current = ReadPassword("Current password: ");
    auto next = ReadPassword("New password: ");
    auto confirm = ReadPassword("Confirm new password: ");
    if (next != confirm) {
      SecureZero(current);
      SecureZero(next);
      SecureZero(confirm);
      std::cerr << "Validation error: Passwords do not match." << std::endl;
      return kExitUsage;
    }
    auto handle = vm.Rekey(container, current, next, std::move(backup_key));
    SecureZero(current);
    SecureZero(next);
    SecureZero(confirm);
    if (!handle) {
      std::cerr << "I/O error: Failed to rekey volume." << std::endl;
      return kExitIO;
    }
    std::cout << "Rekeyed." << std::endl;
    return kExitOk;
  }

  int HandleMigrateNonces(const std::filesystem::path& container) {
    auto legacy = std::filesystem::current_path() / "qv_nonce.log";
    if (!std::filesystem::exists(legacy)) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kLegacyNonceMissing, // TSK020
                      "Legacy nonce log not found at " + legacy.string()};
    }

    qv::core::NonceLog legacy_log(legacy);
    (void)legacy_log; // ensures verification during construction

    auto metadata_dir = MetadataDirFor(container);
    std::filesystem::create_directories(metadata_dir);
    auto target = MetadataNonceLogPath(container);

    std::error_code ec;
    std::filesystem::copy_file(legacy, target, std::filesystem::copy_options::overwrite_existing,
                               ec);
    if (ec) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kLegacyNonceWriteFailed, // TSK020
                      "Failed to write nonce log to " + target.string() + " (errno " +
                          std::to_string(ec.value()) + ")"};
    }

    qv::core::NonceLog migrated(target);
    (void)migrated;

    std::cout << "Nonce log migrated to " << target << "." << std::endl;
    return kExitOk;
  }

} // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2) {
      PrintUsage();
      return kExitUsage;
    }

    std::string cmd = argv[1];
    qv::orchestrator::VolumeManager vm;

    if (cmd == "create") {
      if (argc != 3) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleCreate(argv[2], vm);
    }
    if (cmd == "mount") {
      if (argc != 3) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleMount(argv[2], vm);
    }
    if (cmd == "rekey") {
      if (argc < 3 || argc > 4) {
        PrintUsage();
        return kExitUsage;
      }
      std::optional<std::filesystem::path> backup_path; // TSK024_Key_Rotation_and_Lifecycle_Management
      std::filesystem::path container_path;
      for (int i = 2; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg.rfind("--backup-key=", 0) == 0) {
          auto value = arg.substr(std::string_view("--backup-key=").size());
          if (value.empty()) {
            PrintUsage();
            return kExitUsage;
          }
          backup_path = std::filesystem::path(std::string(value));
          continue;
        }
        if (container_path.empty()) {
          container_path = argv[i];
        } else {
          PrintUsage();
          return kExitUsage;
        }
      }
      if (container_path.empty()) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleRekey(container_path, backup_path, vm);
    }
    if (cmd == "migrate-nonces") {
      if (argc != 3) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleMigrateNonces(argv[2]);
    }

    PrintUsage();
    return kExitUsage;
  } catch (const qv::AuthenticationFailureError& err) {
    std::cerr << "Authentication failed: " << err.what() << std::endl;
    return kExitAuth;
  } catch (const qv::Error& err) {
    ReportError(err);
    return ExitCodeFor(err);
  } catch (const std::exception& err) {
    std::cerr << "I/O error: " << err.what() << std::endl;
    return kExitIO;
  }
}
