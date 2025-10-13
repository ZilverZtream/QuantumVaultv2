#include <algorithm>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include "qv/core/nonce.h"
#include "qv/error.h"
#include "qv/orchestrator/volume_manager.h"

#ifdef _WIN32
#include <windows.h>
#else  // _WIN32
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
  ~ConsoleModeGuard() { Restore(); }
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
    throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(GetLastError()),
                    "Console unavailable for password entry"};
  }
  DWORD mode = 0;
  if (!GetConsoleMode(h_in, &mode)) {
    throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(GetLastError()),
                    "Failed to query console mode"};
  }
  ConsoleModeGuard guard(h_in, mode);
  DWORD silent_mode = mode & ~ENABLE_ECHO_INPUT;
  if (!SetConsoleMode(h_in, silent_mode)) {
    throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(GetLastError()),
                    "Failed to disable console echo"};
  }

  DWORD written = 0;
  WriteConsoleA(h_out, prompt.c_str(), static_cast<DWORD>(prompt.size()), &written, nullptr);

  std::wstring buffer;
  buffer.reserve(128);
  while (true) {
    wchar_t ch = 0;
    DWORD read = 0;
    if (!ReadConsoleW(h_in, &ch, 1, &read, nullptr)) {
      throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(GetLastError()),
                      "Failed to read password"};
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
    throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(GetLastError()),
                    "Failed to convert password encoding"};
  }
  std::string password(static_cast<size_t>(needed), '\0');
  WideCharToMultiByte(CP_UTF8, 0, buffer.data(), static_cast<int>(buffer.size()),
                      password.data(), needed, nullptr, nullptr);
  return password;
}
#else  // _WIN32

class TermiosGuard {
 public:
  TermiosGuard(int fd, const termios& state) : fd_(fd), state_(state), restored_(false) {}
  ~TermiosGuard() { Restore(); }
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
    throw qv::Error{qv::ErrorDomain::IO, 0, "Password prompt requires a TTY"};
  }
  termios original{};
  if (tcgetattr(STDIN_FILENO, &original) != 0) {
    throw qv::Error{qv::ErrorDomain::IO, errno, "Failed to query terminal attributes"};
  }
  TermiosGuard guard(STDIN_FILENO, original);
  termios silent = original;
  silent.c_lflag &= ~ECHO;
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent) != 0) {
    throw qv::Error{qv::ErrorDomain::IO, errno, "Failed to disable terminal echo"};
  }

  std::cout << prompt << std::flush;
  std::string password;
  if (!std::getline(std::cin, password)) {
    throw qv::Error{qv::ErrorDomain::IO, errno, "Failed to read password"};
  }
  guard.Restore();
  std::cout << std::endl;
  return password;
}
#endif // _WIN32

void ReportError(const qv::Error& err) {
  const char* prefix = "Error";
  switch (err.domain) {
    case qv::ErrorDomain::IO: prefix = "I/O error"; break;
    case qv::ErrorDomain::Security: prefix = "Security error"; break;
    case qv::ErrorDomain::Crypto: prefix = "Cryptography error"; break;
    case qv::ErrorDomain::Validation: prefix = "Validation error"; break;
    case qv::ErrorDomain::Internal: prefix = "Internal error"; break;
  }
  std::cerr << prefix << ": " << err.what() << '\n';
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
    throw qv::Error{qv::ErrorDomain::IO, 0, "Container not found: " + container.string()};
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

int HandleMigrateNonces(const std::filesystem::path& container) {
  auto legacy = std::filesystem::current_path() / "qv_nonce.log";
  if (!std::filesystem::exists(legacy)) {
    throw qv::Error{qv::ErrorDomain::IO, 0,
                    "Legacy nonce log not found at " + legacy.string()};
  }

  qv::core::NonceLog legacy_log(legacy);
  (void)legacy_log; // ensures verification during construction

  auto metadata_dir = MetadataDirFor(container);
  std::filesystem::create_directories(metadata_dir);
  auto target = MetadataNonceLogPath(container);

  std::error_code ec;
  std::filesystem::copy_file(legacy, target, std::filesystem::copy_options::overwrite_existing, ec);
  if (ec) {
    throw qv::Error{qv::ErrorDomain::IO, ec.value(),
                    "Failed to write nonce log to " + target.string()};
  }

  qv::core::NonceLog migrated(target);
  (void)migrated;

  std::cout << "Nonce log migrated to " << target << "." << std::endl;
  return kExitOk;
}

}  // namespace

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
