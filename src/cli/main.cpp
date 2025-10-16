#include <algorithm>
#include <atomic>
#include <array>     // TSK035_Platform_Specific_Security_Integration
#include <cerrno>    // TSK028_Secure_Deletion_and_Data_Remanence
#include <charconv>  // TSK029
#include <chrono>    // TSK032_Backup_Recovery_and_Disaster_Recovery
#include <csignal>
#include <cctype>   // TSK129_Unvalidated_User_Input_in_CLI lowercase system path guards
#include <cstddef>   // TSK028_Secure_Deletion_and_Data_Remanence
#include <cstring>   // TSK035_Platform_Specific_Security_Integration
#include <ctime>     // TSK032_Backup_Recovery_and_Disaster_Recovery
#include <filesystem>
#include <fstream> // TSK028_Secure_Deletion_and_Data_Remanence
#include <iomanip> // TSK032_Backup_Recovery_and_Disaster_Recovery
#include <exception> // TSK116_Incorrect_Error_Propagation suppress diagnostics fanout
#include <iostream>
#include <memory>   // TSK082_Backup_Verification_and_Schema
#include <optional>
#include <span>    // TSK028_Secure_Deletion_and_Data_Remanence
#include <sstream> // TSK028_Secure_Deletion_and_Data_Remanence
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <openssl/evp.h> // TSK082_Backup_Verification_and_Schema

#include "qv/crypto/random.h" // TSK124_Insecure_Randomness_Usage use platform RNG for secure overwrite
#ifndef QV_SENSITIVE_FUNCTION  // TSK028A_Memory_Wiping_Gaps
#if defined(_MSC_VER)
#define QV_SENSITIVE_BEGIN __pragma(optimize("", off))
#define QV_SENSITIVE_END __pragma(optimize("", on))
#define QV_SENSITIVE_FUNCTION __declspec(noinline)
#elif defined(__clang__)
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION [[clang::optnone]] __attribute__((noinline))
#elif defined(__GNUC__)
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION __attribute__((noinline, optimize("O0")))
#else
#define QV_SENSITIVE_BEGIN
#define QV_SENSITIVE_END
#define QV_SENSITIVE_FUNCTION
#endif
#endif  // QV_SENSITIVE_FUNCTION TSK028A_Memory_Wiping_Gaps

#if defined(__linux__)
#include <thread>
#endif

#include "qv/common.h" // TSK029
#include "qv/core/nonce.h"
#include "qv/crypto/sha256.h" // TSK032_Backup_Recovery_and_Disaster_Recovery
#include "qv/error.h"
#include "qv/orchestrator/constant_time_mount.h" // TSK032_Backup_Recovery_and_Disaster_Recovery
#include "qv/orchestrator/event_bus.h"           // TSK027
#include "qv/orchestrator/volume_manager.h"
#include "qv/security/zeroizer.h" // TSK125_Missing_Secure_Deletion_for_Keys scoped wiping
#if defined(__linux__)
#include "qv/platform/fuse_adapter.h" // TSK062_FUSE_Filesystem_Integration_Linux
#endif

#ifdef _WIN32
#include <fcntl.h>    // TSK028_Secure_Deletion_and_Data_Remanence
#include <io.h>       // TSK028_Secure_Deletion_and_Data_Remanence
#include <windows.h>
#include <wincrypt.h> // TSK035_Platform_Specific_Security_Integration
#include "qv/platform/winfsp_adapter.h"  // TSK063_WinFsp_Windows_Driver_Integration
#else // _WIN32
#include <cerrno>
#include <fcntl.h>    // TSK028_Secure_Deletion_and_Data_Remanence
#include <signal.h>   // TSK132_Weak_Password_Handling scoped signal handlers
#include <sys/stat.h> // TSK028_Secure_Deletion_and_Data_Remanence
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#endif // _WIN32

#if defined(__APPLE__)
#include <Security/Security.h> // TSK035_Platform_Specific_Security_Integration
#endif

#if defined(QV_HAVE_LIBSECRET) && QV_HAVE_LIBSECRET
#include <libsecret/secret.h> // TSK035_Platform_Specific_Security_Integration
#endif

#if defined(QV_ENABLE_TPM_SEALING) && QV_ENABLE_TPM_SEALING
#include <tss2/tss2_esys.h> // TSK035_Platform_Specific_Security_Integration
#include <tss2/tss2_mu.h>   // TSK035_Platform_Specific_Security_Integration
#endif

namespace {

  constexpr size_t kMaxPasswordLen = 1024; // TSK132_Weak_Password_Handling enforce password size ceiling

  std::atomic<uint8_t*> g_signal_buffer{nullptr};      // TSK132_Weak_Password_Handling signal wipe state
  std::atomic<size_t> g_signal_length{0};              // TSK132_Weak_Password_Handling signal wipe state

  class SensitiveDataRegistration { // TSK132_Weak_Password_Handling signal wipe integration
   public:
    SensitiveDataRegistration(uint8_t* ptr, size_t len) noexcept
        : previous_ptr_(g_signal_buffer.exchange(ptr, std::memory_order_acq_rel)),
          previous_len_(g_signal_length.exchange(len, std::memory_order_acq_rel)) {}

    ~SensitiveDataRegistration() {
      g_signal_buffer.store(previous_ptr_, std::memory_order_release);
      g_signal_length.store(previous_len_, std::memory_order_release);
    }

    void Update(uint8_t* ptr, size_t len) noexcept {
      g_signal_buffer.store(ptr, std::memory_order_release);
      g_signal_length.store(len, std::memory_order_release);
    }

   private:
    uint8_t* previous_ptr_;
    size_t previous_len_;
  };

  constexpr const char kGenericAuthFailureMessage[] =
      "Authentication failed or volume unavailable."; // TSK080_Error_Info_Redaction_in_Release

  struct SecurityIntegrationFlags { // TSK035_Platform_Specific_Security_Integration
    bool use_os_store = false;
    bool use_tpm_seal = false;
  };

#if defined(__linux__)
  std::atomic_bool g_fuse_running{true};                                   // TSK062_FUSE_Filesystem_Integration_Linux
  qv::platform::FUSEAdapter* g_active_fuse_adapter = nullptr;              // TSK062_FUSE_Filesystem_Integration_Linux

  void FuseSignalHandler(int) {                                            // TSK062_FUSE_Filesystem_Integration_Linux
    g_fuse_running.store(false);                                           // TSK062_FUSE_Filesystem_Integration_Linux
    if (g_active_fuse_adapter) {                                           // TSK062_FUSE_Filesystem_Integration_Linux
      g_active_fuse_adapter->RequestUnmount();                             // TSK062_FUSE_Filesystem_Integration_Linux
    }
  }
#elif defined(_WIN32) && defined(QV_HAVE_WINFSP)
  std::atomic_bool g_winfsp_running{true};                                 // TSK063_WinFsp_Windows_Driver_Integration

  BOOL WINAPI WinFspSignalHandler(DWORD signal) {                          // TSK063_WinFsp_Windows_Driver_Integration
    switch (signal) {
      case CTRL_C_EVENT:
      case CTRL_BREAK_EVENT:
      case CTRL_CLOSE_EVENT:
        g_winfsp_running.store(false);
        return TRUE;
      default:
        return FALSE;
    }
  }
#endif

#if defined(_WIN32) || defined(__APPLE__) || (defined(QV_HAVE_LIBSECRET) && QV_HAVE_LIBSECRET)
  constexpr bool kSupportsOsCredentialStore = true; // TSK035_Platform_Specific_Security_Integration
#else
  constexpr bool kSupportsOsCredentialStore = false; // TSK035_Platform_Specific_Security_Integration
#endif

#if defined(QV_ENABLE_TPM_SEALING) && QV_ENABLE_TPM_SEALING
  constexpr bool kSupportsTpmSealing = true; // TSK035_Platform_Specific_Security_Integration
#else
  constexpr bool kSupportsTpmSealing = false; // TSK035_Platform_Specific_Security_Integration
#endif

  constexpr int kCredentialPersistFailed = // TSK035_Platform_Specific_Security_Integration
      qv::errors::Make(qv::ErrorDomain::Security, 0x10);
  constexpr int kCredentialLoadFailed = // TSK035_Platform_Specific_Security_Integration
      qv::errors::Make(qv::ErrorDomain::Security, 0x11);

  std::string CredentialAccountName(const std::filesystem::path& container); // TSK035_Platform_Specific_Security_Integration
  void PersistCredential(const std::filesystem::path& container, std::string_view password,
                         const SecurityIntegrationFlags& flags); // TSK035_Platform_Specific_Security_Integration
  std::optional<std::string>
  LoadPersistedCredential(const std::filesystem::path& container,
                          const SecurityIntegrationFlags& flags); // TSK035_Platform_Specific_Security_Integration

  std::string SanitizePath(const std::filesystem::path& path) { // TSK027
#ifdef NDEBUG
    auto normalized = path;
    if (normalized.empty()) {
      return std::string{"[path]"};
    }
    if (!normalized.has_filename()) {
      normalized = normalized.lexically_normal();
    }
    if (normalized.has_filename()) {
      return normalized.filename().string();
    }
    auto fallback = normalized.string();
    return fallback.empty() ? std::string{"[path]"} : fallback;
#else
    return path.string();
#endif
  }

  bool ValidateNoEmbeddedNull(std::string_view value,
                               std::string_view description) { // TSK129_Unvalidated_User_Input_in_CLI
    if (value.find('\0') != std::string_view::npos) {
      std::cerr << "Validation error: " << description
                << " contains embedded NUL byte." << std::endl;
      return false;
    }
    return true;
  }

  bool TryParsePathArgument(std::string_view raw,
                            std::filesystem::path& out,
                            std::string_view description) { // TSK129_Unvalidated_User_Input_in_CLI
    if (!ValidateNoEmbeddedNull(raw, description)) {
      return false;
    }
    if (raw.empty()) {
      std::cerr << "Validation error: " << description << " is required." << std::endl;
      return false;
    }
    out = std::filesystem::path(std::string(raw));
    return true;
  }

  bool PasswordsEqual(std::string_view lhs,
                      std::string_view rhs) noexcept { // TSK132_Weak_Password_Handling constant-time compare
    volatile uint8_t diff = static_cast<uint8_t>((lhs.size() ^ rhs.size()) & 0xFFu);
    for (size_t i = 0; i < kMaxPasswordLen; ++i) {
      const uint8_t a = i < lhs.size() ? static_cast<uint8_t>(lhs[i]) : 0u;
      const uint8_t b = i < rhs.size() ? static_cast<uint8_t>(rhs[i]) : 0u;
      diff |= static_cast<uint8_t>(a ^ b);
    }
    diff |= static_cast<uint8_t>((lhs.size() > kMaxPasswordLen) | (rhs.size() > kMaxPasswordLen));
    std::atomic_signal_fence(std::memory_order_seq_cst);
    return diff == 0;
  }

  // TSK009
  constexpr int kExitOk = 0;
  constexpr int kExitUsage = 64;
  constexpr int kExitIO = 74;
  constexpr int kExitAuth = 77;

  void PrintUsage() {
    std::cerr << "QuantumVault (skeleton)\n";
    std::cerr << "Usage:\n";
    std::cerr << "  qv create <container>\n";
    std::cerr << "  qv mount  <container> <mountpoint>\n";
    std::cerr
        << "  qv rekey  [--backup-key=<path>] <container>\n"; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::cerr << "  qv migrate [--migrate-to=<version>] <container>\n"; // TSK033
    std::cerr << "  qv migrate-nonces <container>\n";
    std::cerr
        << "  qv backup --output=<dir> <container>\n"; // TSK032_Backup_Recovery_and_Disaster_Recovery
    std::cerr << "  qv fsck <container>\n";    // TSK032_Backup_Recovery_and_Disaster_Recovery
    std::cerr << "  qv destroy <container>\n"; // TSK028_Secure_Deletion_and_Data_Remanence
    std::cerr << "\nGlobal flags:\n"; // TSK035_Platform_Specific_Security_Integration
    std::cerr << "  --syslog=host:port   Forward audit logs to syslog collector\n";
    std::cerr << "  --keychain           Persist credentials in OS key store\n"; // TSK035_Platform_Specific_Security_Integration
    std::cerr << "  --tpm-seal           Seal credentials with TPM PCR policy\n"; // TSK035_Platform_Specific_Security_Integration
    std::cerr << "  --kdf-iterations=N   Override PBKDF2 iteration count for new headers\n"; // TSK036_PBKDF2_Argon2_Migration_Path
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

  std::string CredentialAccountName(const std::filesystem::path& container) { // TSK035_Platform_Specific_Security_Integration
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(container, ec);
    if (ec) {
      canonical = std::filesystem::absolute(container, ec);
    }
    if (ec) {
      canonical = container;
    }
    return qv::PathToUtf8String(canonical);
  }

  [[maybe_unused]] void EnsureCredentialDir(const std::filesystem::path& container) { // TSK035_Platform_Specific_Security_Integration
    auto metadata = MetadataDirFor(container);
    std::error_code ec;
    std::filesystem::create_directories(metadata, ec);
    if (ec) {
      throw qv::Error{qv::ErrorDomain::IO, kCredentialPersistFailed,
                      "Failed to prepare credential metadata directory: " +
                          SanitizePath(metadata),
                      static_cast<int>(ec.value())};
    }
  }

  [[maybe_unused]] void WriteBinaryFile(const std::filesystem::path& path, // TSK035_Platform_Specific_Security_Integration
                                        std::span<const uint8_t> data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
      throw qv::Error{qv::ErrorDomain::IO, kCredentialPersistFailed,
                      "Failed to persist credential: " + SanitizePath(path)};
    }
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!out) {
      throw qv::Error{qv::ErrorDomain::IO, kCredentialPersistFailed,
                      "Failed to write credential blob: " + SanitizePath(path)};
    }
  }

  [[maybe_unused]] std::vector<uint8_t> ReadBinaryFile(const std::filesystem::path& path) { // TSK035_Platform_Specific_Security_Integration
    std::vector<uint8_t> data;
    if (!std::filesystem::exists(path)) {
      return data;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
      throw qv::Error{qv::ErrorDomain::IO, kCredentialLoadFailed,
                      "Failed to open credential cache: " + SanitizePath(path)};
    }
    in.seekg(0, std::ios::end);
    auto size = in.tellg();
    in.seekg(0, std::ios::beg);
    if (size < 0) {
      throw qv::Error{qv::ErrorDomain::IO, kCredentialLoadFailed,
                      "Failed to determine credential blob size: " + SanitizePath(path)};
    }
    data.resize(static_cast<size_t>(size));
    in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!in) {
      throw qv::Error{qv::ErrorDomain::IO, kCredentialLoadFailed,
                      "Failed to read credential blob: " + SanitizePath(path)};
    }
    return data;
  }

#if defined(_WIN32)
  std::filesystem::path DpapiCredentialPath(const std::filesystem::path& container) { // TSK035_Platform_Specific_Security_Integration
    return MetadataDirFor(container) / "credential.dpapi";
  }

  std::vector<uint8_t> ProtectPasswordWithDpapi(std::string_view password) { // TSK035_Platform_Specific_Security_Integration
    DATA_BLOB input{static_cast<DWORD>(password.size()),
                   reinterpret_cast<BYTE*>(const_cast<char*>(password.data()))};
    DATA_BLOB output{};
    if (!CryptProtectData(&input, L"QuantumVault Password", nullptr, nullptr, nullptr, 0, &output)) {
      throw qv::Error{qv::ErrorDomain::Security, kCredentialPersistFailed,
                      "CryptProtectData failed", static_cast<int>(GetLastError())};
    }
    std::vector<uint8_t> result(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return result;
  }

  std::string UnprotectPasswordWithDpapi(std::span<const uint8_t> blob) { // TSK035_Platform_Specific_Security_Integration
    if (blob.empty()) {
      return {};
    }
    DATA_BLOB input{static_cast<DWORD>(blob.size()), const_cast<BYTE*>(blob.data())};
    DATA_BLOB output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
      throw qv::Error{qv::ErrorDomain::Security, kCredentialLoadFailed,
                      "CryptUnprotectData failed", static_cast<int>(GetLastError())};
    }
    std::string password(reinterpret_cast<char*>(output.pbData),
                         reinterpret_cast<char*>(output.pbData) + output.cbData);
    LocalFree(output.pbData);
    return password;
  }

  void StoreWithDpapi(const std::filesystem::path& container, std::string_view password) { // TSK035_Platform_Specific_Security_Integration
    EnsureCredentialDir(container);
    auto blob = ProtectPasswordWithDpapi(password);
    auto path = DpapiCredentialPath(container);
    WriteBinaryFile(path, std::span<const uint8_t>(blob.data(), blob.size()));
  }

  std::optional<std::string> LoadWithDpapi(const std::filesystem::path& container) { // TSK035_Platform_Specific_Security_Integration
    auto path = DpapiCredentialPath(container);
    if (!std::filesystem::exists(path)) {
      return std::nullopt;
    }
    auto blob = ReadBinaryFile(path);
    return UnprotectPasswordWithDpapi(std::span<const uint8_t>(blob.data(), blob.size()));
  }
#endif

#if defined(__APPLE__)
  bool StoreInKeychain(const std::string& service, const std::string& account,
                       std::string_view password) { // TSK035_Platform_Specific_Security_Integration
    SecKeychainItemRef item = nullptr;
    OSStatus status = SecKeychainFindGenericPassword(nullptr, static_cast<UInt32>(service.size()),
                                                     service.data(), static_cast<UInt32>(account.size()),
                                                     account.data(), nullptr, nullptr, &item);
    if (status == errSecSuccess && item != nullptr) {
      status = SecKeychainItemModifyAttributesAndData(item, nullptr, password.size(), password.data());
      CFRelease(item);
      return status == errSecSuccess;
    }
    if (item) {
      CFRelease(item);
    }
    status = SecKeychainAddGenericPassword(nullptr, static_cast<UInt32>(service.size()), service.data(),
                                           static_cast<UInt32>(account.size()), account.data(),
                                           static_cast<UInt32>(password.size()), password.data(), nullptr);
    return status == errSecSuccess;
  }

  std::optional<std::string> LoadFromKeychain(const std::string& service, const std::string& account) { // TSK035_Platform_Specific_Security_Integration
    void* data = nullptr;
    UInt32 length = 0;
    SecKeychainItemRef item = nullptr;
    OSStatus status = SecKeychainFindGenericPassword(nullptr, static_cast<UInt32>(service.size()),
                                                     service.data(), static_cast<UInt32>(account.size()),
                                                     account.data(), &length, &data, &item);
    if (status != errSecSuccess) {
      if (item) {
        CFRelease(item);
      }
      return std::nullopt;
    }
    std::string password(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data) + length);
    SecKeychainItemFreeContent(nullptr, data);
    if (item) {
      CFRelease(item);
    }
    return password;
  }
#endif

#if defined(QV_HAVE_LIBSECRET) && QV_HAVE_LIBSECRET
  const SecretSchema* CredentialSchema() { // TSK035_Platform_Specific_Security_Integration
    static const SecretSchema schema = {"com.quantumvault.Password", SECRET_SCHEMA_NONE,
                                        {{"container", SECRET_SCHEMA_ATTRIBUTE_STRING},
                                         {"service", SECRET_SCHEMA_ATTRIBUTE_STRING},
                                         {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}}};
    return &schema;
  }

  bool StoreWithSecretService(const std::string& service, const std::string& account,
                              std::string_view password) { // TSK035_Platform_Specific_Security_Integration
    GError* error = nullptr;
    secret_password_store_sync(CredentialSchema(), SECRET_COLLECTION_DEFAULT, account.c_str(),
                               password.data(), nullptr, &error, "container", account.c_str(), "service",
                               service.c_str(), nullptr);
    if (error) {
      g_error_free(error);
      return false;
    }
    return true;
  }

  std::optional<std::string> LoadFromSecretService(const std::string& service,
                                                   const std::string& account) { // TSK035_Platform_Specific_Security_Integration
    GError* error = nullptr;
    gchar* secret = secret_password_lookup_sync(CredentialSchema(), nullptr, &error, "container",
                                                account.c_str(), "service", service.c_str(), nullptr);
    if (error) {
      g_error_free(error);
      return std::nullopt;
    }
    if (!secret) {
      return std::nullopt;
    }
    std::string password(secret);
    secret_password_free(secret);
    return password;
  }
#endif

#if defined(QV_ENABLE_TPM_SEALING) && QV_ENABLE_TPM_SEALING
  std::filesystem::path TpmSealPath(const std::filesystem::path& container) { // TSK035_Platform_Specific_Security_Integration
    return MetadataDirFor(container) / "credential.tpm";
  }

  ESYS_CONTEXT* InitializeTpmContext() { // TSK035_Platform_Specific_Security_Integration
    ESYS_CONTEXT* ctx = nullptr;
    TSS2_RC rc = Esys_Initialize(&ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
      throw qv::Error{qv::ErrorDomain::Security, kCredentialPersistFailed,
                      "Failed to initialize TPM context", static_cast<int>(rc)};
    }
    return ctx;
  }

  void FinalizeTpmContext(ESYS_CONTEXT* ctx, ESYS_TR primary) { // TSK035_Platform_Specific_Security_Integration
    if (primary != ESYS_TR_NONE) {
      Esys_FlushContext(ctx, primary);
    }
    Esys_Finalize(&ctx);
  }

  ESYS_TR CreatePrimarySealingParent(ESYS_CONTEXT* ctx) { // TSK035_Platform_Specific_Security_Integration
    TPM2B_SENSITIVE_CREATE primary_sensitive{};
    primary_sensitive.size = sizeof(TPM2B_SENSITIVE_CREATE);
    primary_sensitive.sensitive.userAuth.size = 0;
    primary_sensitive.sensitive.data.size = 0;

    TPM2B_PUBLIC primary_template{};
    primary_template.size = sizeof(TPM2B_PUBLIC);
    primary_template.publicArea.type = TPM2_ALG_RSA;
    primary_template.publicArea.nameAlg = TPM2_ALG_SHA256;
    primary_template.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                                   TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
                                                   TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
    primary_template.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    primary_template.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    primary_template.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    primary_template.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    primary_template.publicArea.parameters.rsaDetail.keyBits = 2048;
    primary_template.publicArea.parameters.rsaDetail.exponent = 0;
    primary_template.publicArea.unique.rsa.size = 0;

    TPM2B_DATA outside_info{};
    outside_info.size = 0;

    TPML_PCR_SELECTION pcr_selection{};
    pcr_selection.count = 0;

    ESYS_TR primary_handle = ESYS_TR_NONE;
    TSS2_RC rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                    &primary_sensitive, &primary_template, &outside_info, &pcr_selection,
                                    &primary_handle, nullptr, nullptr, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
      throw qv::Error{qv::ErrorDomain::Security, kCredentialPersistFailed,
                      "TPM CreatePrimary failed", static_cast<int>(rc)};
    }
    return primary_handle;
  }

  struct SealedCredential { // TSK035_Platform_Specific_Security_Integration
    std::vector<uint8_t> public_area;
    std::vector<uint8_t> private_area;
  };

  SealedCredential SealWithTpm(std::string_view password) { // TSK035_Platform_Specific_Security_Integration
    TPM2B_SENSITIVE_DATA max_buffer{};
    if (password.size() > sizeof(max_buffer.buffer)) {
      throw qv::Error{qv::ErrorDomain::Validation, kCredentialPersistFailed,
                      "Password too large for TPM sealing"};
    }
    ESYS_CONTEXT* ctx = InitializeTpmContext();
    ESYS_TR primary = ESYS_TR_NONE;
    try {
      primary = CreatePrimarySealingParent(ctx);

      TPML_PCR_SELECTION seal_pcr{};
      seal_pcr.count = 1;
      seal_pcr.pcrSelections[0].hash = TPM2_ALG_SHA256;
      seal_pcr.pcrSelections[0].sizeofSelect = 3;
      seal_pcr.pcrSelections[0].pcrSelect[0] = 0x80; // PCR 7
      seal_pcr.pcrSelections[0].pcrSelect[1] = 0x00;
      seal_pcr.pcrSelections[0].pcrSelect[2] = 0x00;

      TPM2B_SENSITIVE_CREATE in_sensitive{};
      in_sensitive.size = sizeof(TPM2B_SENSITIVE_CREATE);
      in_sensitive.sensitive.userAuth.size = 0;
      in_sensitive.sensitive.data.size = static_cast<UINT16>(password.size());
      if (!password.empty()) {
        std::memcpy(in_sensitive.sensitive.data.buffer, password.data(), password.size());
      }

      TPM2B_PUBLIC in_public{};
      in_public.size = sizeof(TPM2B_PUBLIC);
      in_public.publicArea.type = TPM2_ALG_KEYEDHASH;
      in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
      in_public.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                             TPMA_OBJECT_USERWITHAUTH;
      in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
      in_public.publicArea.unique.keyedHash.size = 0;

      TPM2B_DATA outside_info{};
      outside_info.size = 0;

      TPM2B_PRIVATE* out_private = nullptr;
      TPM2B_PUBLIC* out_public = nullptr;
      TSS2_RC rc = Esys_Create(ctx, primary, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &in_sensitive,
                               &in_public, &outside_info, &seal_pcr, &out_private, &out_public, nullptr,
                               nullptr, nullptr);
      if (rc != TSS2_RC_SUCCESS) {
        throw qv::Error{qv::ErrorDomain::Security, kCredentialPersistFailed,
                        "TPM Create failed", static_cast<int>(rc)};
      }

      size_t offset = 0;
      std::vector<uint8_t> public_data(sizeof(TPM2B_PUBLIC));
      rc = Tss2_MU_TPM2B_PUBLIC_Marshal(out_public, public_data.data(), public_data.size(), &offset);
      if (rc != TSS2_RC_SUCCESS) {
        Esys_Free(out_private);
        Esys_Free(out_public);
        throw qv::Error{qv::ErrorDomain::Security, kCredentialPersistFailed,
                        "Failed to marshal TPM public blob", static_cast<int>(rc)};
      }
      public_data.resize(offset);

      offset = 0;
      std::vector<uint8_t> private_data(sizeof(TPM2B_PRIVATE));
      rc = Tss2_MU_TPM2B_PRIVATE_Marshal(out_private, private_data.data(), private_data.size(), &offset);
      Esys_Free(out_private);
      Esys_Free(out_public);
      if (rc != TSS2_RC_SUCCESS) {
        throw qv::Error{qv::ErrorDomain::Security, kCredentialPersistFailed,
                        "Failed to marshal TPM private blob", static_cast<int>(rc)};
      }
      private_data.resize(offset);

      FinalizeTpmContext(ctx, primary);
      return SealedCredential{std::move(public_data), std::move(private_data)};
    } catch (...) {
      FinalizeTpmContext(ctx, primary);
      throw;
    }
  }

  void WriteTpmSealFile(const std::filesystem::path& container, const SealedCredential& blob) { // TSK035_Platform_Specific_Security_Integration
    EnsureCredentialDir(container);
    auto path = TpmSealPath(container);
    std::vector<uint8_t> buffer;
    buffer.reserve(sizeof(uint32_t) * 2 + blob.public_area.size() + blob.private_area.size());
    auto append_u32 = [&buffer](uint32_t value) {
      for (int i = 0; i < 4; ++i) {
        buffer.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
      }
    };
    append_u32(static_cast<uint32_t>(blob.public_area.size()));
    buffer.insert(buffer.end(), blob.public_area.begin(), blob.public_area.end());
    append_u32(static_cast<uint32_t>(blob.private_area.size()));
    buffer.insert(buffer.end(), blob.private_area.begin(), blob.private_area.end());
    WriteBinaryFile(path, std::span<const uint8_t>(buffer.data(), buffer.size()));
  }

  std::optional<SealedCredential> ReadTpmSealFile(const std::filesystem::path& container) { // TSK035_Platform_Specific_Security_Integration
    auto path = TpmSealPath(container);
    if (!std::filesystem::exists(path)) {
      return std::nullopt;
    }
    auto buffer = ReadBinaryFile(path);
    if (buffer.size() < sizeof(uint32_t) * 2) {
      throw qv::Error{qv::ErrorDomain::Security, kCredentialLoadFailed,
                      "Corrupt TPM credential blob: " + SanitizePath(path)};
    }
    auto read_u32 = [&buffer](size_t& offset) -> uint32_t {
      if (offset + 4 > buffer.size()) {
        throw qv::Error{qv::ErrorDomain::Security, kCredentialLoadFailed,
                        "Corrupt TPM credential blob length"};
      }
      uint32_t value = 0;
      for (int i = 0; i < 4; ++i) {
        value |= static_cast<uint32_t>(buffer[offset++]) << (i * 8);
      }
      return value;
    };
    size_t offset = 0;
    uint32_t public_size = read_u32(offset);
    if (offset + public_size > buffer.size()) {
      throw qv::Error{qv::ErrorDomain::Security, kCredentialLoadFailed,
                      "Corrupt TPM credential public blob"};
    }
    std::vector<uint8_t> public_blob(buffer.begin() + static_cast<std::ptrdiff_t>(offset),
                                     buffer.begin() + static_cast<std::ptrdiff_t>(offset + public_size));
    offset += public_size;
    uint32_t private_size = read_u32(offset);
    if (offset + private_size > buffer.size()) {
      throw qv::Error{qv::ErrorDomain::Security, kCredentialLoadFailed,
                      "Corrupt TPM credential private blob"};
    }
    std::vector<uint8_t> private_blob(buffer.begin() + static_cast<std::ptrdiff_t>(offset),
                                      buffer.begin() + static_cast<std::ptrdiff_t>(offset + private_size));
    return SealedCredential{std::move(public_blob), std::move(private_blob)};
  }

  std::optional<std::string> UnsealWithTpm(const SealedCredential& blob) { // TSK035_Platform_Specific_Security_Integration
    ESYS_CONTEXT* ctx = InitializeTpmContext();
    ESYS_TR primary = ESYS_TR_NONE;
    ESYS_TR sealed = ESYS_TR_NONE;
    try {
      primary = CreatePrimarySealingParent(ctx);

      size_t offset = 0;
      TPM2B_PUBLIC public_data{};
      TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(blob.public_area.data(), blob.public_area.size(), &offset,
                                                  &public_data);
      if (rc != TSS2_RC_SUCCESS) {
        throw qv::Error{qv::ErrorDomain::Security, kCredentialLoadFailed,
                        "Failed to unmarshal TPM public blob", static_cast<int>(rc)};
      }
      offset = 0;
      TPM2B_PRIVATE private_data{};
      rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(blob.private_area.data(), blob.private_area.size(), &offset,
                                           &private_data);
      if (rc != TSS2_RC_SUCCESS) {
        throw qv::Error{qv::ErrorDomain::Security, kCredentialLoadFailed,
                        "Failed to unmarshal TPM private blob", static_cast<int>(rc)};
      }

      rc = Esys_Load(ctx, primary, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &private_data, &public_data,
                     &sealed);
      if (rc != TSS2_RC_SUCCESS) {
        throw qv::Error{qv::ErrorDomain::Security, kCredentialLoadFailed,
                        "TPM Load failed", static_cast<int>(rc)};
      }

      TPM2B_SENSITIVE_DATA* unsealed = nullptr;
      rc = Esys_Unseal(ctx, sealed, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &unsealed);
      if (rc != TSS2_RC_SUCCESS) {
        throw qv::Error{qv::ErrorDomain::Security, kCredentialLoadFailed,
                        "TPM Unseal failed", static_cast<int>(rc)};
      }
      std::string password(reinterpret_cast<char*>(unsealed->buffer),
                           reinterpret_cast<char*>(unsealed->buffer) + unsealed->size);
      Esys_Free(unsealed);
      if (sealed != ESYS_TR_NONE) {
        Esys_FlushContext(ctx, sealed);
      }
      FinalizeTpmContext(ctx, primary);
      return password;
    } catch (...) {
      if (sealed != ESYS_TR_NONE) {
        Esys_FlushContext(ctx, sealed);
      }
      FinalizeTpmContext(ctx, primary);
      throw;
    }
  }
#endif

  void PersistCredential(const std::filesystem::path& container, std::string_view password,
                         const SecurityIntegrationFlags& flags) { // TSK035_Platform_Specific_Security_Integration
    if (!flags.use_os_store && !flags.use_tpm_seal) {
      return;
    }
    if (flags.use_tpm_seal) {
      if (!kSupportsTpmSealing) {
        throw qv::Error{qv::ErrorDomain::Config, kCredentialPersistFailed,
                        "TPM sealing requested but not available"};
      }
#if defined(QV_ENABLE_TPM_SEALING) && QV_ENABLE_TPM_SEALING
      auto sealed = SealWithTpm(password);
      WriteTpmSealFile(container, sealed);
#endif
    }
    if (flags.use_os_store) {
      if (!kSupportsOsCredentialStore) {
        throw qv::Error{qv::ErrorDomain::Config, kCredentialPersistFailed,
                        "OS credential store requested but not available"};
      }
      auto account = CredentialAccountName(container);
      constexpr std::string_view kService{"QuantumVault"};
#if defined(_WIN32)
      StoreWithDpapi(container, password);
#elif defined(__APPLE__)
      if (!StoreInKeychain(std::string(kService), account, password)) {
        throw qv::Error{qv::ErrorDomain::Security, kCredentialPersistFailed,
                        "Failed to store password in Keychain"};
      }
#elif defined(QV_HAVE_LIBSECRET) && QV_HAVE_LIBSECRET
      if (!StoreWithSecretService(std::string(kService), account, password)) {
        throw qv::Error{qv::ErrorDomain::Security, kCredentialPersistFailed,
                        "Failed to store password in Secret Service"};
      }
#else
      (void)account;
      (void)password;
      throw qv::Error{qv::ErrorDomain::Config, kCredentialPersistFailed,
                      "Credential store unsupported on this platform"};
#endif
    }
  }

  std::optional<std::string>
  LoadPersistedCredential(const std::filesystem::path& container,
                          const SecurityIntegrationFlags& flags) { // TSK035_Platform_Specific_Security_Integration
    try {
      if (flags.use_tpm_seal && kSupportsTpmSealing) {
#if defined(QV_ENABLE_TPM_SEALING) && QV_ENABLE_TPM_SEALING
        if (auto sealed = ReadTpmSealFile(container)) {
          auto password = UnsealWithTpm(*sealed);
          if (password) {
            return password;
          }
        }
#endif
      }
      if (flags.use_os_store && kSupportsOsCredentialStore) {
        auto account = CredentialAccountName(container);
        constexpr std::string_view kService{"QuantumVault"};
#if defined(_WIN32)
        if (auto password = LoadWithDpapi(container)) {
          return password;
        }
#elif defined(__APPLE__)
        if (auto password = LoadFromKeychain(std::string(kService), account)) {
          return password;
        }
#elif defined(QV_HAVE_LIBSECRET) && QV_HAVE_LIBSECRET
        if (auto password = LoadFromSecretService(std::string(kService), account)) {
          return password;
        }
#else
        (void)account;
#endif
      }
    } catch (const qv::Error& err) {
      std::cerr << "Credential cache unavailable: " << err.what() << std::endl;
    }
    return std::nullopt;
  }

  std::string
  BytesToHexLower(std::span<const uint8_t> bytes) { // TSK032_Backup_Recovery_and_Disaster_Recovery
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto byte : bytes) {
      oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
  }

  class ScopedPathCleanup { // TSK082_Backup_Verification_and_Schema staged file guard
  public:
    explicit ScopedPathCleanup(std::filesystem::path path) noexcept
        : path_(std::move(path)) {}

    ScopedPathCleanup(const ScopedPathCleanup&) = delete;
    ScopedPathCleanup& operator=(const ScopedPathCleanup&) = delete;

    ScopedPathCleanup(ScopedPathCleanup&& other) noexcept
        : path_(std::move(other.path_)) {
      other.path_.clear();
    }

    ScopedPathCleanup& operator=(ScopedPathCleanup&& other) noexcept {
      if (this != &other) {
        if (!path_.empty()) {
          std::error_code ec;
          std::filesystem::remove(path_, ec);
        }
        path_ = std::move(other.path_);
        other.path_.clear();
      }
      return *this;
    }

    ~ScopedPathCleanup() {
      if (!path_.empty()) {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
      }
    }

    void Release() noexcept { path_.clear(); }

  private:
    std::filesystem::path path_;
  };

  std::array<uint8_t, 32> CopyFileWithSha256(
      const std::filesystem::path& source, const std::filesystem::path& destination) {
    std::ifstream in(source, std::ios::binary);
    if (!in.is_open()) {
      const int err = errno;
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to open file for backup: " + SanitizePath(source)};
    }

    std::ofstream out(destination, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
      const int err = errno;
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to create staged backup file: " + SanitizePath(destination)};
    }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free); // TSK082_Backup_Verification_and_Schema
    if (!ctx) {
      throw qv::Error{qv::ErrorDomain::Crypto, 0,
                      "Failed to initialize hashing context"};
    }
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
      throw qv::Error{qv::ErrorDomain::Crypto, 0,
                      "Failed to initialize SHA-256 context"};
    }

    std::array<char, 1 << 15> buffer{}; // 32 KiB chunks // TSK082_Backup_Verification_and_Schema
    while (in) {
      in.read(buffer.data(), buffer.size());
      std::streamsize read = in.gcount();
      if (read > 0) {
        if (EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(read)) != 1) {
          throw qv::Error{qv::ErrorDomain::Crypto, 0,
                          "Failed while computing SHA-256"};
        }
        out.write(buffer.data(), read);
        if (!out) {
          const int err = errno;
          throw qv::Error{qv::ErrorDomain::IO, err,
                          "Failed to write staged backup file: " +
                              SanitizePath(destination)};
        }
      }
    }

    if (!in.eof()) {
      const int err = errno;
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed while reading source for backup: " + SanitizePath(source)};
    }

    out.flush();
    if (!out) {
      const int err = errno;
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to flush staged backup file: " + SanitizePath(destination)};
    }

    std::array<uint8_t, 32> digest{};
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &digest_len) != 1) {
      throw qv::Error{qv::ErrorDomain::Crypto, 0,
                      "Failed to finalize SHA-256"};
    }
    if (digest_len != digest.size()) {
      throw qv::Error{qv::ErrorDomain::Crypto, 0,
                      "Unexpected SHA-256 length"};
    }

    return digest;
  }


  std::string CurrentISO8601() { // TSK032_Backup_Recovery_and_Disaster_Recovery
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
  }

  std::string FormatHeaderVersion(uint32_t version) { // TSK082_Backup_Verification_and_Schema
    std::ostringstream oss;
    const uint32_t major = (version >> 16) & 0xFFFFu;
    const uint32_t minor = (version >> 8) & 0xFFu;
    const uint32_t patch = version & 0xFFu;
    oss << major << '.' << minor << '.' << patch;
    return oss.str();
  }

  std::string AppVersionString() { // TSK082_Backup_Verification_and_Schema align with header schema
    return FormatHeaderVersion(qv::orchestrator::VolumeManager::kLatestHeaderVersion);
  }

  void SecureZero(std::string& s) {
    std::fill(s.begin(), s.end(), '\0');
    s.clear();
  }

  std::optional<uint32_t>
  ParseVersionFlag(std::string_view value) { // TSK033 parse migration target
    if (value.empty()) {
      return std::nullopt;
    }
    constexpr uint32_t kMaxMigrationVersion = 0x040100u; // TSK129_Unvalidated_User_Input_in_CLI
    if (value.find('.') != std::string_view::npos) {      // TSK129_Unvalidated_User_Input_in_CLI
      std::array<uint64_t, 3> components{0, 0, 0};
      std::string_view remaining = value;
      for (size_t idx = 0; idx < components.size(); ++idx) { // TSK129_Unvalidated_User_Input_in_CLI
        auto dot = remaining.find('.');
        auto token = remaining.substr(0, dot);
        if (token.empty()) {
          return std::nullopt;
        }
        if (idx < components.size() - 1 && dot == std::string_view::npos) {
          return std::nullopt;
        }
        if (idx == components.size() - 1 && dot != std::string_view::npos) {
          return std::nullopt;
        }
        std::from_chars_result parsed{
            std::from_chars(token.data(), token.data() + token.size(), components[idx])};
        if (parsed.ec != std::errc() || parsed.ptr != token.data() + token.size()) {
          return std::nullopt;
        }
        if (dot == std::string_view::npos) {
          remaining = std::string_view{};
        } else {
          remaining = remaining.substr(dot + 1);
        }
      }
      if (!remaining.empty()) {
        return std::nullopt;
      }
      const uint64_t major = components[0];
      const uint64_t minor = components[1];
      const uint64_t patch = components[2];
      const uint64_t version = (major << 16) | (minor << 8) | patch;
      if (major > 0xFFFFull || minor > 0xFFull || patch > 0xFFull || version > kMaxMigrationVersion) {
        return std::nullopt;
      }
      return static_cast<uint32_t>(version);
    }

    uint32_t version = 0;
    std::from_chars_result result{};
    if (value.size() > 2 && (value[0] == '0') && (value[1] == 'x' || value[1] == 'X')) {
      result = std::from_chars(value.data() + 2, value.data() + value.size(), version, 16);
    } else {
      result = std::from_chars(value.data(), value.data() + value.size(), version, 10);
    }
    if (result.ec != std::errc() || result.ptr != value.data() + value.size() || version > kMaxMigrationVersion) {
      return std::nullopt;
    }
    return version;
  }

#ifdef _WIN32
  int NativeOpen(const std::filesystem::path& path) { // TSK028_Secure_Deletion_and_Data_Remanence
    return _wopen(path.c_str(), _O_RDWR | _O_BINARY, _S_IREAD | _S_IWRITE);
  }

  int NativeClose(int fd) { // TSK028_Secure_Deletion_and_Data_Remanence
    return _close(fd);
  }

  int NativeFsync(int fd) { // TSK028_Secure_Deletion_and_Data_Remanence
    return _commit(fd);
  }

  bool NativeSeek(int fd, std::uintmax_t offset) { // TSK028_Secure_Deletion_and_Data_Remanence
    return _lseeki64(fd, static_cast<__int64>(offset), SEEK_SET) != -1;
  }

  std::ptrdiff_t NativeWrite(int fd, const uint8_t* data,
                             size_t size) { // TSK028_Secure_Deletion_and_Data_Remanence
    return _write(fd, data, static_cast<unsigned int>(size));
  }
#else
  int NativeOpen(const std::filesystem::path& path) { // TSK028_Secure_Deletion_and_Data_Remanence
    return ::open(path.c_str(), O_RDWR | O_CLOEXEC);
  }

  int NativeClose(int fd) { // TSK028_Secure_Deletion_and_Data_Remanence
    return ::close(fd);
  }

  int NativeFsync(int fd) { // TSK028_Secure_Deletion_and_Data_Remanence
    return ::fsync(fd);
  }

  bool NativeSeek(int fd, std::uintmax_t offset) { // TSK028_Secure_Deletion_and_Data_Remanence
    return ::lseek(fd, static_cast<off_t>(offset), SEEK_SET) != static_cast<off_t>(-1);
  }

  std::ptrdiff_t NativeWrite(int fd, const uint8_t* data,
                             size_t size) { // TSK028_Secure_Deletion_and_Data_Remanence
    return ::write(fd, data, size);
  }
#endif

  void OverwriteSecure(int fd, std::uintmax_t size,
                       const std::filesystem::path& container) { // TSK124_Insecure_Randomness_Usage
    std::vector<uint8_t> buffer(4096);
    constexpr int kOverwritePasses = 7;
    for (int pass = 0; pass < kOverwritePasses; ++pass) {
      if (!NativeSeek(fd, 0)) {
        throw qv::Error{qv::ErrorDomain::IO, errno,
                        "Failed to seek during destruction: " + SanitizePath(container)};
      }
      std::uintmax_t remaining = size;
      while (remaining > 0) {
        const size_t chunk =
            static_cast<size_t>(std::min<std::uintmax_t>(remaining, buffer.size()));
        qv::crypto::SystemRandomBytes(
            std::span<uint8_t>(buffer.data(), chunk)); // TSK124_Insecure_Randomness_Usage fresh entropy per chunk
        size_t written_total = 0;
        while (written_total < chunk) {
          const std::ptrdiff_t wrote =
              NativeWrite(fd, buffer.data() + written_total, chunk - written_total);
          if (wrote <= 0) {
            throw qv::Error{qv::ErrorDomain::IO, errno,
                            "Failed to overwrite container: " + SanitizePath(container)};
          }
          written_total += static_cast<size_t>(wrote);
        }
        remaining -= chunk;
      }
      if (NativeFsync(fd) != 0) {
        throw qv::Error{qv::ErrorDomain::IO, errno,
                        "Failed to flush overwrite pass: " + SanitizePath(container)};
      }
    }
  }

#if defined(__linux__)
  void WarnIfSwapUnencrypted() { // TSK028_Secure_Deletion_and_Data_Remanence
    std::ifstream swaps("/proc/swaps");
    if (!swaps) {
      return;
    }
    std::string header;
    std::getline(swaps, header);
    std::string line;
    bool found_swap = false;
    bool encrypted = true;
    while (std::getline(swaps, line)) {
      if (line.empty()) {
        continue;
      }
      found_swap = true;
      std::istringstream iss(line);
      std::string device;
      iss >> device;
      if (device.empty()) {
        continue;
      }
      if (device.find("crypt") == std::string::npos &&
          device.find("/dev/dm-") == std::string::npos &&
          device.find("/dev/mapper/") == std::string::npos) {
        encrypted = false;
      }
    }
    if (found_swap && !encrypted) {
      std::cerr << "WARNING: Swap appears to be unencrypted; plaintext keys may persist. Configure "
                   "dm-crypt swap." // TSK028_Secure_Deletion_and_Data_Remanence
                << std::endl;
    }
  }
#else
  void WarnIfSwapUnencrypted() {} // TSK028_Secure_Deletion_and_Data_Remanence
#endif

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

  BOOL WINAPI PasswordConsoleHandler(DWORD control_type) { // TSK132_Weak_Password_Handling wipe on signal
    switch (control_type) {
      case CTRL_C_EVENT:
      case CTRL_BREAK_EVENT:
      case CTRL_CLOSE_EVENT: {
        auto* buffer = g_signal_buffer.load(std::memory_order_acquire);
        const size_t len = g_signal_length.load(std::memory_order_acquire);
        if (buffer && len > 0) {
          volatile uint8_t* wipe = buffer;
          for (size_t i = 0; i < len; ++i) {
            wipe[i] = 0;
          }
          g_signal_buffer.store(nullptr, std::memory_order_release);
          g_signal_length.store(0, std::memory_order_release);
        }
        break;
      }
      default:
        break;
    }
    return FALSE;
  }

  class PasswordSignalGuard { // TSK132_Weak_Password_Handling ensure handler scoped
   public:
    PasswordSignalGuard() { SetConsoleCtrlHandler(PasswordConsoleHandler, TRUE); }
    ~PasswordSignalGuard() { SetConsoleCtrlHandler(PasswordConsoleHandler, FALSE); }
  };

  std::string ReadPassword(const std::string& prompt) {
    HANDLE h_in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE h_out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h_in == INVALID_HANDLE_VALUE || h_out == INVALID_HANDLE_VALUE) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kConsoleUnavailable, // TSK020
                      "Console unavailable for password entry.", GetLastError()};
    }
    DWORD mode = 0;
    if (!GetConsoleMode(h_in, &mode)) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kConsoleModeQueryFailed, // TSK020
                      "Failed to query console mode.", GetLastError()};
    }
    ConsoleModeGuard guard(h_in, mode);
    DWORD silent_mode = mode & ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(h_in, silent_mode)) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kConsoleEchoDisableFailed, // TSK020
                      "Failed to disable console echo.", GetLastError()};
    }

    DWORD written = 0;
    WriteConsoleA(h_out, prompt.c_str(), static_cast<DWORD>(prompt.size()), &written, nullptr);

    PasswordSignalGuard signal_guard; // TSK132_Weak_Password_Handling scope handler

    std::array<wchar_t, kMaxPasswordLen + 1> buffer{}; // TSK132_Weak_Password_Handling fixed buffer
    qv::security::Zeroizer::ScopeWiper<wchar_t> buf_guard(buffer.data(), buffer.size());
    SensitiveDataRegistration registration(reinterpret_cast<uint8_t*>(buffer.data()), 0);

    size_t pos = 0;
    bool overflow = false;
    while (true) {
      wchar_t ch = 0;
      DWORD read = 0;
      if (!ReadConsoleW(h_in, &ch, 1, &read, nullptr)) {
        throw qv::Error{qv::ErrorDomain::IO,
                        qv::errors::io::kPasswordReadFailed, // TSK020
                        "Failed to read password input.", GetLastError()};
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
        if (pos > 0) {
          --pos;
          buffer[pos] = 0;
          registration.Update(reinterpret_cast<uint8_t*>(buffer.data()), pos * sizeof(wchar_t));
        }
        continue;
      }
      if (pos >= kMaxPasswordLen) {
        overflow = true;
        continue;
      }
      buffer[pos++] = ch;
      registration.Update(reinterpret_cast<uint8_t*>(buffer.data()), pos * sizeof(wchar_t));
    }

    guard.Restore();
    WriteConsoleA(h_out, "\n", 1, &written, nullptr);

    if (overflow) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Password exceeds maximum length (1024 bytes)."}; // TSK132_Weak_Password_Handling
    }

    if (pos == 0) {
      return std::string{};
    }

    int needed =
        WideCharToMultiByte(CP_UTF8, 0, buffer.data(), static_cast<int>(pos), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kPasswordReadFailed, // TSK020
                      "Failed to convert password encoding.", GetLastError()};
    }
    if (needed > static_cast<int>(kMaxPasswordLen)) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Password exceeds maximum length (1024 bytes)."}; // TSK132_Weak_Password_Handling
    }
    std::string password(static_cast<size_t>(needed), '\0');
    registration.Update(reinterpret_cast<uint8_t*>(password.data()), password.size());
    qv::security::Zeroizer::ScopeWiper<char> password_guard(password.data(), password.size());
    const int written =
        WideCharToMultiByte(CP_UTF8, 0, buffer.data(), static_cast<int>(pos), password.data(), needed, nullptr,
                             nullptr);
    if (written != needed) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kPasswordReadFailed, // TSK020
                      "Failed to convert password encoding.", GetLastError()};
    }
    password_guard.Release();
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

  void PasswordSignalHandler(int sig) { // TSK132_Weak_Password_Handling wipe on interrupt
    auto* buffer = g_signal_buffer.load(std::memory_order_acquire);
    const size_t len = g_signal_length.load(std::memory_order_acquire);
    if (buffer && len > 0) {
      volatile uint8_t* wipe = buffer;
      for (size_t i = 0; i < len; ++i) {
        wipe[i] = 0;
      }
      g_signal_buffer.store(nullptr, std::memory_order_release);
      g_signal_length.store(0, std::memory_order_release);
    }
    _exit(128 + sig);
  }

  class PasswordSignalGuard { // TSK132_Weak_Password_Handling scoped handler
   public:
    PasswordSignalGuard() {
      struct sigaction sa {};
      sa.sa_handler = PasswordSignalHandler;
      sigemptyset(&sa.sa_mask);
      sa.sa_flags = 0;
      sigaction(SIGINT, &sa, &old_int_);
      sigaction(SIGTERM, &sa, &old_term_);
    }
    ~PasswordSignalGuard() {
      sigaction(SIGINT, &old_int_, nullptr);
      sigaction(SIGTERM, &old_term_, nullptr);
    }

   private:
    struct sigaction old_int_ {};
    struct sigaction old_term_ {};
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
                      "Failed to query terminal attributes.", err};
    }
    TermiosGuard guard(STDIN_FILENO, original);
    termios silent = original;
    silent.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent) != 0) {
      const int err = errno;
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kConsoleEchoDisableFailed, // TSK020
                      "Failed to disable terminal echo.", err};
    }

    std::cout << prompt << std::flush;

    PasswordSignalGuard signal_guard; // TSK132_Weak_Password_Handling scope handler

    std::array<char, kMaxPasswordLen + 1> buffer{}; // TSK132_Weak_Password_Handling fixed buffer
    qv::security::Zeroizer::ScopeWiper<char> buf_guard(buffer.data(), buffer.size());
    SensitiveDataRegistration registration(reinterpret_cast<uint8_t*>(buffer.data()), 0);

    size_t pos = 0;
    bool overflow = false;
    while (true) {
      char ch = 0;
      ssize_t n = ::read(STDIN_FILENO, &ch, 1);
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        const int err = errno;
        throw qv::Error{qv::ErrorDomain::IO,
                        qv::errors::io::kPasswordReadFailed, // TSK020
                        "Failed to read password input.", err};
      }
      if (n == 0) {
        break;
      }
      if (ch == '\r') {
        continue;
      }
      if (ch == '\n') {
        break;
      }
      if (ch == '\b') {
        if (pos > 0) {
          --pos;
          buffer[pos] = 0;
          registration.Update(reinterpret_cast<uint8_t*>(buffer.data()), pos);
        }
        continue;
      }
      if (pos >= kMaxPasswordLen) {
        overflow = true;
        continue;
      }
      buffer[pos++] = ch;
      registration.Update(reinterpret_cast<uint8_t*>(buffer.data()), pos);
    }

    guard.Restore();
    std::cout << std::endl;

    if (overflow) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Password exceeds maximum length (1024 bytes)."}; // TSK132_Weak_Password_Handling
    }

    std::string password(buffer.data(), pos);
    registration.Update(reinterpret_cast<uint8_t*>(password.data()), password.size());
    qv::security::Zeroizer::ScopeWiper<char> password_guard(password.data(), password.size());
    password_guard.Release();
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

  std::string DescribeErrorDetailed(const qv::Error& err) { // TSK080_Error_Info_Redaction_in_Release
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

  std::string_view GenericDomainMessage(qv::ErrorDomain domain) { // TSK080_Error_Info_Redaction_in_Release
    switch (domain) {
    case qv::ErrorDomain::Security:
      return kGenericAuthFailureMessage;
    case qv::ErrorDomain::Validation:
      return "Request could not be processed.";
    case qv::ErrorDomain::IO:
      return "I/O operation failed.";
    case qv::ErrorDomain::Config:
    case qv::ErrorDomain::Dependency:
    case qv::ErrorDomain::State:
    case qv::ErrorDomain::Internal:
    case qv::ErrorDomain::Crypto:
    default:
      return "Operation failed.";
    }
  }

  std::string MakeReferenceTag(std::string_view detail) { // TSK080_Error_Info_Redaction_in_Release
    if (detail.empty()) {
      return {};
    }
    std::vector<uint8_t> bytes(detail.begin(), detail.end());
    auto digest = qv::crypto::SHA256_Hash(bytes);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    constexpr size_t kPrefixBytes = 6;
    for (size_t i = 0; i < kPrefixBytes && i < digest.size(); ++i) {
      oss << std::setw(2) << static_cast<int>(digest[i]);
    }
    return oss.str();
  }

  std::string DescribeErrorRedacted(const qv::Error& err) { // TSK080_Error_Info_Redaction_in_Release
    std::string_view base = GenericDomainMessage(err.domain);
    std::string result(base);
    std::string_view detail = std::string_view(err.what());
    if (!detail.empty()) {
      auto ref = MakeReferenceTag(detail);
      if (!ref.empty()) {
        result.append(" [ref:#");
        result.append(ref);
        result.push_back(']');
      }
    }
    return result;
  }

  std::string DescribeError(const qv::Error& err) { // TSK080_Error_Info_Redaction_in_Release
#ifdef NDEBUG
    return DescribeErrorRedacted(err);
#else
    return DescribeErrorDetailed(err);
#endif
  }

  std::string UserFacingMessage(const qv::Error& err) { // TSK027
#ifdef NDEBUG
    return std::string(GenericDomainMessage(err.domain));
#else
    return DescribeError(err);
#endif
  }

  void ReportError(const qv::Error& err) {
    const std::string detail = DescribeError(err);
#ifdef NDEBUG
    const std::string user = UserFacingMessage(err);
#else
    const std::string user = detail;
#endif
    std::cerr << DomainPrefix(err.domain) << ": " << user << '\n';

    qv::orchestrator::Event event; // TSK027
    event.category = qv::orchestrator::EventCategory::kDiagnostics;
    event.severity = qv::orchestrator::EventSeverity::kError;
    event.event_id = "cli_error";
    event.message = detail;
    event.fields.emplace_back("domain", std::string(DomainPrefix(err.domain)));
    event.fields.emplace_back("code", std::to_string(err.code),
                              qv::orchestrator::FieldPrivacy::kPublic, true);
    if (err.native_code.has_value()) {
      event.fields.emplace_back("native_code", std::to_string(*err.native_code),
                                qv::orchestrator::FieldPrivacy::kHash, true);
    }
    try {
      qv::orchestrator::EventBus::Instance().Publish(event);
    } catch (const std::exception& publish_error) {
      std::clog << "{\"event\":\"eventbus_error\",\"message\":\"error report publish failed\",\"detail\":\""
                << publish_error.what() << "\"}" << std::endl; // TSK116_Incorrect_Error_Propagation do not terminate on diagnostics
    } catch (...) {
      std::clog << "{\"event\":\"eventbus_error\",\"message\":\"error report publish failed\",\"detail\":\"unknown\"}"
                << std::endl; // TSK116_Incorrect_Error_Propagation suppress unexpected exceptions
    }
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

  int HandleCreate(const std::filesystem::path& container, qv::orchestrator::VolumeManager& vm,
                   const SecurityIntegrationFlags& security_flags) { // TSK035_Platform_Specific_Security_Integration
    auto password = ReadPassword("Password: ");
    qv::security::Zeroizer::ScopeWiper<char> password_guard(password.data(), password.size());
    auto confirm = ReadPassword("Confirm password: ");
    qv::security::Zeroizer::ScopeWiper<char> confirm_guard(confirm.data(), confirm.size());
    if (!PasswordsEqual(password, confirm)) { // TSK132_Weak_Password_Handling constant-time mismatch check
      std::cerr << "Validation error: Passwords do not match." << std::endl;
      return kExitUsage; // TSK125_Missing_Secure_Deletion_for_Keys guards zero on scope exit
    }
    try {
      auto handle = vm.Create(container, password);
      if (!handle) {
        std::cerr << "I/O error: Failed to create volume." << std::endl;
        return kExitIO;
      }
      if (security_flags.use_os_store || security_flags.use_tpm_seal) {
        PersistCredential(container, password, security_flags);
      }
    } catch (...) {
      throw;
    }
    std::cout << "Created." << std::endl;
    return kExitOk;
  }

#if defined(__linux__)
  QV_SENSITIVE_BEGIN
  QV_SENSITIVE_FUNCTION int HandleMount(const std::filesystem::path& container,
                                        const std::filesystem::path& mountpoint,
                                        qv::orchestrator::VolumeManager& vm,
                                        const SecurityIntegrationFlags& security_flags) {
    if (!std::filesystem::exists(container)) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kContainerMissing, // TSK020
                      "Container not found: " + SanitizePath(container)};
    }
    std::error_code mount_ec;
    auto status = std::filesystem::status(mountpoint, mount_ec); // TSK129_Unvalidated_User_Input_in_CLI
    if (mount_ec || !std::filesystem::exists(status) || !std::filesystem::is_directory(status)) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Mount point unavailable: " + SanitizePath(mountpoint)};
    }
    std::error_code empty_ec;
    const bool is_empty_mount = std::filesystem::is_empty(mountpoint, empty_ec); // TSK129_Unvalidated_User_Input_in_CLI
    if (empty_ec) {
      throw qv::Error{qv::ErrorDomain::Validation, empty_ec.value(),
                      "Unable to inspect mount point: " + SanitizePath(mountpoint)};
    }
    if (!is_empty_mount) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Mount point must be empty: " + SanitizePath(mountpoint)};
    }
    if (::access(mountpoint.c_str(), R_OK | W_OK | X_OK) != 0) { // TSK129_Unvalidated_User_Input_in_CLI
      throw qv::Error{qv::ErrorDomain::Validation, errno,
                      "Insufficient permissions for mount point: " + SanitizePath(mountpoint)};
    }
    auto lock_path = container;
    lock_path += ".locked"; // TSK026
    std::error_code lock_ec;
    if (std::filesystem::exists(lock_path, lock_ec)) {
      throw qv::Error{qv::ErrorDomain::Security, qv::errors::security::kAuthenticationRejected,
                      "Volume is locked due to repeated authentication failures"}; // TSK026
    }
    bool cached = false; // TSK035_Platform_Specific_Security_Integration
    std::string password;
    if ((security_flags.use_os_store || security_flags.use_tpm_seal)) {
      if (auto persisted = LoadPersistedCredential(container, security_flags)) {
        password = *persisted;
        cached = true;
      }
    }
    if (!cached) {
      password = ReadPassword("Password: ");
    }
    try {
      auto handle = vm.Mount(container, password);
      if (!handle) {
        SecureZero(password);  // TSK028A_Memory_Wiping_Gaps
        std::cerr << kGenericAuthFailureMessage << std::endl; // TSK080_Error_Info_Redaction_in_Release
        return kExitAuth;
      }
      SecureZero(password);  // TSK028A_Memory_Wiping_Gaps
      if (!handle->device) {
        throw qv::Error{qv::ErrorDomain::State, 0, "Block device unavailable for mounted volume"};
      }

      qv::platform::FUSEAdapter adapter(handle->device);
      adapter.Mount(mountpoint);
      g_active_fuse_adapter = &adapter;
      g_fuse_running.store(true);
      std::signal(SIGINT, FuseSignalHandler);
      std::signal(SIGTERM, FuseSignalHandler);

      std::cout << "Mounted " << SanitizePath(container) << " at " << SanitizePath(mountpoint) << std::endl;
      std::cout << "Press Ctrl+C to unmount..." << std::endl;

      while (g_fuse_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }

      g_active_fuse_adapter = nullptr;
      adapter.Unmount();
      return kExitOk;
    } catch (...) {
      SecureZero(password);  // TSK028A_Memory_Wiping_Gaps
      throw;
    }
  }
  QV_SENSITIVE_END
#elif defined(_WIN32) && defined(QV_HAVE_WINFSP)
  QV_SENSITIVE_BEGIN
  QV_SENSITIVE_FUNCTION int HandleMount(const std::filesystem::path& container,
                                        const std::filesystem::path& mountpoint,
                                        qv::orchestrator::VolumeManager& vm,
                                        const SecurityIntegrationFlags& security_flags) {
    if (!std::filesystem::exists(container)) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kContainerMissing,  // TSK020
                      "Container not found: " + SanitizePath(container)};
    }

    std::wstring mount_target = mountpoint.wstring();
    if (mount_target.empty()) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Mount point must specify a drive letter or share"};
    }

    bool cached = false;
    std::string password;
    if ((security_flags.use_os_store || security_flags.use_tpm_seal)) {
      if (auto persisted = LoadPersistedCredential(container, security_flags)) {
        password = *persisted;
        cached = true;
      }
    }
    if (!cached) {
      password = ReadPassword("Password: ");
    }

    try {
      auto handle = vm.Mount(container, password);
      if (!handle) {
        SecureZero(password);  // TSK028A_Memory_Wiping_Gaps
        std::cerr << kGenericAuthFailureMessage << std::endl; // TSK080_Error_Info_Redaction_in_Release
        return kExitAuth;
      }
      SecureZero(password);  // TSK028A_Memory_Wiping_Gaps
      if (!handle->device) {
        throw qv::Error{qv::ErrorDomain::State, 0, "Block device unavailable for mounted volume"};
      }

      qv::platform::WinFspAdapter adapter(handle->device);
      adapter.Mount(mount_target);
      g_winfsp_running.store(true);
      SetConsoleCtrlHandler(WinFspSignalHandler, TRUE);

      std::wcout << L"Mounted at " << mount_target << std::endl;
      std::wcout << L"Press Ctrl+C to unmount..." << std::endl;

      while (g_winfsp_running.load()) {
        Sleep(200);
      }

      SetConsoleCtrlHandler(WinFspSignalHandler, FALSE);
      adapter.Unmount();
      return kExitOk;
    } catch (...) {
      SecureZero(password);  // TSK028A_Memory_Wiping_Gaps
      throw;
    }
  }
  QV_SENSITIVE_END
#elif defined(_WIN32)
  int HandleMount(const std::filesystem::path& container, const std::filesystem::path& mountpoint,
                  qv::orchestrator::VolumeManager& vm,
                  const SecurityIntegrationFlags& security_flags) {
    (void)container;
    (void)mountpoint;
    (void)vm;
    (void)security_flags;
    std::cerr << "WinFsp integration not available in this build." << std::endl;
    return kExitUsage;
  }
#else
  int HandleMount(const std::filesystem::path& container, const std::filesystem::path& mountpoint,
                  qv::orchestrator::VolumeManager& vm,
                  const SecurityIntegrationFlags& security_flags) {
    (void)container;
    (void)mountpoint;
    (void)vm;
    (void)security_flags;
    std::cerr << "Mount is only supported on Linux builds." << std::endl;
    return kExitUsage;
  }
#endif

  QV_SENSITIVE_BEGIN
  QV_SENSITIVE_FUNCTION int HandleRekey(
      const std::filesystem::path& container, std::optional<std::filesystem::path> backup_key,
      qv::orchestrator::VolumeManager& vm,
      const SecurityIntegrationFlags& security_flags) { // TSK024_Key_Rotation_and_Lifecycle_Management, TSK035_Platform_Specific_Security_Integration
    if (backup_key) { // TSK129_Unvalidated_User_Input_in_CLI
      std::filesystem::path& backup_target = *backup_key;
      auto parent = backup_target.parent_path();
      std::error_code parent_ec;
      if (!parent.empty()) {
        auto parent_status = std::filesystem::status(parent, parent_ec);
        if (parent_ec) {
          std::cerr << "Validation error: Unable to access backup key directory." << std::endl;
          return kExitUsage;
        }
        if (!std::filesystem::exists(parent_status)) {
          parent_ec.clear();
          if (!std::filesystem::create_directories(parent, parent_ec) || parent_ec) {
            std::cerr << "I/O error: Cannot prepare backup key directory." << std::endl;
            return kExitIO;
          }
        } else if (!std::filesystem::is_directory(parent_status)) {
          std::cerr << "Validation error: Backup key parent is not a directory." << std::endl;
          return kExitUsage;
        }
      }
      std::error_code target_status_ec;
      auto target_status = std::filesystem::status(backup_target, target_status_ec);
      if (target_status_ec && target_status_ec.value() != ENOENT) {
        std::cerr << "Validation error: Unable to inspect backup key path." << std::endl;
        return kExitUsage;
      }
      const bool target_exists = std::filesystem::exists(target_status);
      if (target_exists && !std::filesystem::is_regular_file(target_status)) {
        std::cerr << "Validation error: Backup key path must be a file." << std::endl;
        return kExitUsage;
      }
      bool remove_probe = false;
      {
        std::ofstream probe;
        if (!target_exists) {
          probe.open(backup_target, std::ios::binary | std::ios::trunc);
          remove_probe = true;
        } else {
          probe.open(backup_target, std::ios::binary | std::ios::app);
        }
        if (!probe.is_open()) {
          std::cerr << "I/O error: Backup key path not writable." << std::endl;
          return kExitIO;
        }
      }
      if (remove_probe) {
        std::error_code remove_ec;
        std::filesystem::remove(backup_target, remove_ec);
      }
    }

    auto current = ReadPassword("Current password: ");
    qv::security::Zeroizer::ScopeWiper<char> current_guard(current.data(), current.size());
    auto next = ReadPassword("New password: ");
    qv::security::Zeroizer::ScopeWiper<char> next_guard(next.data(), next.size());
    auto confirm = ReadPassword("Confirm new password: ");
    qv::security::Zeroizer::ScopeWiper<char> confirm_guard(confirm.data(), confirm.size());
    const auto wipe_passwords = [&]() noexcept {
      SecureZero(current);   // TSK125_Missing_Secure_Deletion_for_Keys ensure buffer length cleared
      SecureZero(next);      // TSK125_Missing_Secure_Deletion_for_Keys ensure buffer length cleared
      SecureZero(confirm);   // TSK125_Missing_Secure_Deletion_for_Keys ensure buffer length cleared
    };
    if (next != confirm) {
      wipe_passwords();
      std::cerr << "Validation error: Passwords do not match." << std::endl;
      return kExitUsage;
    }
    try {
      auto handle = vm.Rekey(container, current, next, std::move(backup_key));
      if (!handle) {
        wipe_passwords();
        std::cerr << "I/O error: Failed to rekey volume." << std::endl;
        return kExitIO;
      }
      if (security_flags.use_os_store || security_flags.use_tpm_seal) {
        PersistCredential(container, next, security_flags);
      }
    } catch (...) {
      wipe_passwords();
      throw;
    }
    wipe_passwords();
    std::cout << "Rekeyed." << std::endl;
    return kExitOk;
  }
  QV_SENSITIVE_END

  int HandleMigrate(const std::filesystem::path& container, std::optional<uint32_t> target_version,
                    qv::orchestrator::VolumeManager& vm) { // TSK033
    auto password = ReadPassword("Password: ");
    const uint32_t version =
        target_version.value_or(qv::orchestrator::VolumeManager::kLatestHeaderVersion);
    auto handle = vm.Migrate(container, version, password);
    SecureZero(password);
    if (!handle) {
      std::cout << "Already at requested version." << std::endl; // TSK033
    } else {
      std::cout << "Migrated." << std::endl; // TSK033
    }
    return kExitOk;
  }

  int HandleMigrateNonces(const std::filesystem::path& container) {
    auto legacy = std::filesystem::current_path() / "qv_nonce.log";
    if (!std::filesystem::exists(legacy)) {
      throw qv::Error{qv::ErrorDomain::IO,
                      qv::errors::io::kLegacyNonceMissing, // TSK020
                      "Legacy nonce log not found at " + SanitizePath(legacy)};
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
                      "Failed to write nonce log to " + SanitizePath(target), ec.value()};
    }

    qv::core::NonceLog migrated(target);
    (void)migrated;

    std::cout << "Nonce log migrated to " << SanitizePath(target) << "." << std::endl;
    return kExitOk;
  }

  int HandleBackup(
      const std::filesystem::path& container,
      const std::filesystem::path& output_dir) { // TSK032_Backup_Recovery_and_Disaster_Recovery
    if (!std::filesystem::exists(container)) {
      std::cerr << "Container not found." << std::endl;
      return kExitIO;
    }

    if (output_dir.empty()) { // TSK129_Unvalidated_User_Input_in_CLI
      std::cerr << "Validation error: Backup directory not specified." << std::endl;
      return kExitUsage;
    }

    std::error_code canonical_ec;
    auto canonical = std::filesystem::weakly_canonical(output_dir, canonical_ec); // TSK129_Unvalidated_User_Input_in_CLI
    if (canonical_ec) {
      canonical = std::filesystem::absolute(output_dir, canonical_ec);
    }
    if (canonical_ec) {
      std::cerr << "Validation error: Backup directory is invalid." << std::endl;
      return kExitUsage;
    }

    if (canonical == canonical.root_path()) { // TSK129_Unvalidated_User_Input_in_CLI
      std::cerr << "Validation error: Refusing to back up to filesystem root." << std::endl;
      return kExitUsage;
    }

#if defined(_WIN32)
    auto canonical_str = canonical.generic_string();
    std::transform(canonical_str.begin(), canonical_str.end(), canonical_str.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    if (canonical_str == "c:/" || canonical_str.rfind("c:/windows", 0) == 0) { // TSK129_Unvalidated_User_Input_in_CLI
      std::cerr << "Validation error: Refusing to back up to system directory." << std::endl;
      return kExitUsage;
    }
#else
    auto canonical_str = canonical.generic_string();
    if (canonical_str == "/" || canonical_str.rfind("/etc", 0) == 0 ||
        canonical_str.rfind("/sys", 0) == 0 || canonical_str.rfind("/proc", 0) == 0) { // TSK129_Unvalidated_User_Input_in_CLI
      std::cerr << "Validation error: Refusing to back up to system directory." << std::endl;
      return kExitUsage;
    }
#endif

    try {
      std::filesystem::create_directories(output_dir);
    } catch (const std::filesystem::filesystem_error& err) {
      throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(err.code().value()),
                      "Failed to prepare backup directory: " + SanitizePath(output_dir)};
    }

    const auto probe_path = output_dir / ".qv_backup_write_test"; // TSK129_Unvalidated_User_Input_in_CLI
    {
      std::error_code remove_ec;
      std::filesystem::remove(probe_path, remove_ec);
    }
    {
      std::ofstream probe(probe_path, std::ios::binary | std::ios::trunc);
      if (!probe.is_open()) {
        std::cerr << "I/O error: Output directory not writable." << std::endl;
        return kExitIO;
      }
    }
    {
      std::error_code remove_ec;
      std::filesystem::remove(probe_path, remove_ec);
    }

#if !defined(_WIN32)
    try {
      std::filesystem::permissions(
          output_dir,
          std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
              std::filesystem::perms::owner_exec,
          std::filesystem::perm_options::replace);
    } catch (const std::filesystem::filesystem_error& err) {
      throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(err.code().value()),
                      "Failed to secure backup directory: " + SanitizePath(output_dir)};
    }
#endif

    auto container_backup = output_dir / container.filename();
    auto staged_container = container_backup;
    staged_container += ".tmp";
    {
      std::error_code ec;
      std::filesystem::remove(staged_container, ec);
    }
    ScopedPathCleanup container_guard(staged_container);
    const auto container_digest = CopyFileWithSha256(container, staged_container);
    qv::orchestrator::VolumeManager::ValidateHeaderForBackup(staged_container);

    std::optional<std::filesystem::path> nonce_backup;
    std::optional<std::array<uint8_t, 32>> nonce_digest;
    std::optional<ScopedPathCleanup> nonce_guard;
    std::filesystem::path staged_nonce;

    auto nonce_log_path = MetadataNonceLogPath(container);
    if (std::filesystem::exists(nonce_log_path)) {
      nonce_backup = output_dir / "nonce.log";
      staged_nonce = output_dir / "nonce.log.tmp";
      {
        std::error_code ec;
        std::filesystem::remove(staged_nonce, ec);
      }
      nonce_guard.emplace(staged_nonce);
      nonce_digest = CopyFileWithSha256(nonce_log_path, staged_nonce);
    }

    {
      std::error_code ec;
      std::filesystem::remove(container_backup, ec);
    }
    std::filesystem::rename(staged_container, container_backup);
    container_guard.Release();

    if (nonce_backup && nonce_guard) {
      {
        std::error_code ec;
        std::filesystem::remove(*nonce_backup, ec);
      }
      std::filesystem::rename(staged_nonce, *nonce_backup);
      nonce_guard->Release();
    }

    auto manifest_path = output_dir / "manifest.json";
    auto manifest_tmp = manifest_path;
    manifest_tmp += ".tmp";
    {
      std::error_code ec;
      std::filesystem::remove(manifest_tmp, ec);
    }
    ScopedPathCleanup manifest_guard(manifest_tmp);
    std::ofstream manifest(manifest_tmp, std::ios::binary | std::ios::trunc);
    if (!manifest.is_open()) {
      throw qv::Error{qv::ErrorDomain::IO, errno,
                      "Failed to write manifest: " + SanitizePath(manifest_tmp)};
    }
    constexpr int kManifestVersion = 1; // TSK082_Backup_Verification_and_Schema schema marker
    const auto container_hash_hex =
        BytesToHexLower(std::span<const uint8_t>(container_digest.data(), container_digest.size()));
    manifest << "{\n";
    manifest << "  \"manifest_version\": " << kManifestVersion << ",\n";
    manifest << "  \"app_version\": \"" << AppVersionString() << "\",\n";
    manifest << "  \"container_path\": \"" << container_backup.filename().string() << "\",\n";
    manifest << "  \"container_sha256\": \"" << container_hash_hex << "\",\n";
    if (nonce_backup && nonce_digest) {
      const auto nonce_hash_hex = BytesToHexLower(
          std::span<const uint8_t>(nonce_digest->data(), nonce_digest->size()));
      manifest << "  \"nonce_log_path\": \"" << nonce_backup->filename().string() << "\",\n";
      manifest << "  \"nonce_log_sha256\": \"" << nonce_hash_hex << "\",\n";
    } else {
      manifest << "  \"nonce_log_path\": null,\n";
      manifest << "  \"nonce_log_sha256\": null,\n";
    }
    manifest << "  \"created_at\": \"" << CurrentISO8601() << "\"\n";
    manifest << "}\n";
    manifest.flush();
    if (!manifest) {
      const int err = errno;
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to finalize manifest: " + SanitizePath(manifest_tmp)};
    }
    manifest.close();

    {
      std::error_code ec;
      std::filesystem::remove(manifest_path, ec);
    }
    std::filesystem::rename(manifest_tmp, manifest_path);
    manifest_guard.Release();

    std::cout << "Backup created at " << SanitizePath(output_dir) << std::endl;
    return kExitOk;
  }

  int HandleFsck(
      const std::filesystem::path& container) { // TSK032_Backup_Recovery_and_Disaster_Recovery
    if (!std::filesystem::exists(container)) {
      std::cerr << "Container not found." << std::endl;
      return kExitIO;
    }

    auto password = ReadPassword("Password (for verification): ");
    qv::orchestrator::ConstantTimeMount ctm;
    auto handle = ctm.Mount(container, password);
    SecureZero(password);
    if (!handle) {
      std::cerr << "Validation error: Header MAC verification failed." << std::endl;
      return kExitAuth;
    }

    bool nonce_ok = true;
    size_t repaired_entries = 0;
    auto nonce_path = MetadataNonceLogPath(container);
    if (std::filesystem::exists(nonce_path)) {
      try {
        qv::core::NonceLog log(nonce_path, std::nothrow_t{});
        repaired_entries = log.Repair();
        if (!log.VerifyChain()) {
          nonce_ok = false;
        }
      } catch (const qv::Error& err) {
        std::cerr << "Nonce log error: " << DescribeError(err) << std::endl;
        nonce_ok = false;
      }
    }

    if (!nonce_ok) {
      std::cerr << "Nonce log integrity check failed." << std::endl;
      return kExitIO;
    }

    std::cout << "Header MAC verified." << std::endl;
    if (repaired_entries > 0) {
      std::cout << "Nonce log repaired: truncated " << repaired_entries << ' '
                << (repaired_entries == 1 ? "entry." : "entries.") << std::endl;
    } else if (std::filesystem::exists(nonce_path)) {
      std::cout << "Nonce log chain verified." << std::endl;
    }
    std::cout << "Integrity check complete." << std::endl;
    return kExitOk;
  }

  int HandleDestroy(
      const std::filesystem::path& container) { // TSK028_Secure_Deletion_and_Data_Remanence
    if (!std::filesystem::exists(container)) {
      std::cerr << "Container not found." << std::endl;
      return kExitIO;
    }

    std::cout << "WARNING: This will irrecoverably destroy " << SanitizePath(container)
              << ". Continue? (yes/no): " << std::flush;
    std::string confirm;
    if (!std::getline(std::cin, confirm)) {
      return kExitIO;
    }
    const bool approved = (confirm == "yes");
    SecureZero(confirm);
    if (!approved) {
      std::cout << "Aborted." << std::endl;
      return kExitOk;
    }

    WarnIfSwapUnencrypted();

    std::uintmax_t size = 0;
    try {
      size = std::filesystem::file_size(container);
    } catch (const std::filesystem::filesystem_error& err) {
      throw qv::Error{qv::ErrorDomain::IO, err.code().value(),
                      "Failed to query container size: " + SanitizePath(container)};
    }

    int fd = NativeOpen(container);
    if (fd < 0) {
      throw qv::Error{qv::ErrorDomain::IO, errno,
                      "Failed to open container for destruction: " + SanitizePath(container)};
    }
    struct FileGuard { // TSK028_Secure_Deletion_and_Data_Remanence
      int fd;
      ~FileGuard() noexcept {
        if (fd >= 0) {
          (void)NativeClose(fd);
          fd = -1; // TSK116_Incorrect_Error_Propagation guarantee fd released during unwinding
        }
      }
    } guard{fd};

    OverwriteSecure(fd, size, container); // TSK124_Insecure_Randomness_Usage centralized secure wipe

    if (NativeClose(fd) != 0) {
      throw qv::Error{qv::ErrorDomain::IO, errno,
                      "Failed to close container after overwrite: " + SanitizePath(container)};
    }
    guard.fd = -1;

    std::error_code remove_ec;
    if (!std::filesystem::remove(container, remove_ec) || remove_ec) {
      throw qv::Error{qv::ErrorDomain::IO, static_cast<int>(remove_ec.value()),
                      "Failed to remove container after overwrite: " + SanitizePath(container)};
    }

    std::cout << "Destroyed." << std::endl;
    qv::orchestrator::Event destroyed{}; // TSK029
    destroyed.category = qv::orchestrator::EventCategory::kLifecycle;
    destroyed.severity = qv::orchestrator::EventSeverity::kInfo;
    destroyed.event_id = "volume_destroyed";
    destroyed.message = "Encrypted volume destroyed";
    destroyed.fields.emplace_back("container", qv::PathToUtf8String(container),
                                  qv::orchestrator::FieldPrivacy::kRedact);
    qv::orchestrator::EventBus::Instance().Publish(destroyed);
#if defined(__linux__)
    std::cout << "NOTE: Complete secure deletion requires SSD TRIM support and running blkdiscard "
                 "on freed space." // TSK028_Secure_Deletion_and_Data_Remanence
              << std::endl;
#else
    std::cout << "NOTE: SSD wear-leveling can retain remnants; ensure drive secure erase/TRIM "
                 "procedures are followed." // TSK028_Secure_Deletion_and_Data_Remanence
              << std::endl;
#endif
    return kExitOk;
  }

} // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2) {
      PrintUsage();
      return kExitUsage;
    }

    SecurityIntegrationFlags security_flags{}; // TSK035_Platform_Specific_Security_Integration
    int index = 1;                             // TSK029 parse global flags
    std::optional<uint32_t> kdf_iterations_override; // TSK036_PBKDF2_Argon2_Migration_Path
    for (; index < argc; ++index) {
      std::string_view arg = argv[index];
      if (arg.rfind("--", 0) != 0) {
        break;
      }
      if (arg == "--keychain") { // TSK035_Platform_Specific_Security_Integration
        if (!kSupportsOsCredentialStore) {
          std::cerr << "Configuration error: CLI not built with OS credential store support." << std::endl;
          return kExitUsage;
        }
        security_flags.use_os_store = true;
        continue;
      }
      if (arg == "--tpm-seal") { // TSK035_Platform_Specific_Security_Integration
        if (!kSupportsTpmSealing) {
          std::cerr << "Configuration error: TPM sealing support not available." << std::endl;
          return kExitUsage;
        }
        security_flags.use_tpm_seal = true;
        continue;
      }
      if (arg.rfind("--syslog=", 0) == 0) {
        std::string value(arg.substr(std::string_view("--syslog=").size()));
        if (value.empty()) {
          PrintUsage();
          return kExitUsage;
        }
        std::string host;
        std::string port;
        if (!value.empty() && value.front() == '[') {
          auto closing = value.find(']');
          if (closing == std::string::npos || closing + 1 >= value.size() ||
              value[closing + 1] != ':') {
            PrintUsage();
            return kExitUsage;
          }
          host = value.substr(1, closing - 1);
          port = value.substr(closing + 2);
        } else {
          auto colon = value.rfind(':');
          if (colon == std::string::npos) {
            PrintUsage();
            return kExitUsage;
          }
          host = value.substr(0, colon);
          port = value.substr(colon + 1);
        }
        if (host.empty() || port.empty()) {
          PrintUsage();
          return kExitUsage;
        }
        unsigned long parsed_port = 0;
        auto [ptr, ec] = std::from_chars(port.data(), port.data() + port.size(), parsed_port);
        if (ec != std::errc() || parsed_port == 0 || parsed_port > 65535) {
          PrintUsage();
          return kExitUsage;
        }
        std::string syslog_error; // TSK029
        if (!qv::orchestrator::EventBus::Instance().ConfigureSyslog(
                host, static_cast<uint16_t>(parsed_port), &syslog_error)) {
          if (!syslog_error.empty()) {
            std::cerr << "Configuration error: " << syslog_error << '\n';
          }
          return kExitUsage;
        }
        continue;
      }
      if (arg.rfind("--kdf-iterations=", 0) == 0) { // TSK036_PBKDF2_Argon2_Migration_Path
        auto value = arg.substr(std::string_view("--kdf-iterations=").size());
        if (value.empty()) {
          PrintUsage();
          return kExitUsage;
        }
        unsigned long long parsed_iterations = 0;
        auto [endptr, ec] = std::from_chars(value.data(), value.data() + value.size(), parsed_iterations);
        if (ec != std::errc() || endptr != value.data() + value.size() || parsed_iterations == 0 ||
            parsed_iterations > 0x00FFFFFFull) {
          PrintUsage();
          return kExitUsage;
        }
        kdf_iterations_override = static_cast<uint32_t>(parsed_iterations);
        continue;
      }

      PrintUsage();
      return kExitUsage;
    }

    if (index >= argc) {
      PrintUsage();
      return kExitUsage;
    }

    std::string cmd = argv[index++];
    qv::orchestrator::VolumeManager vm;
    auto policy = vm.GetKdfPolicy(); // TSK036_PBKDF2_Argon2_Migration_Path
    if (kdf_iterations_override) {
      policy.algorithm = qv::orchestrator::VolumeManager::PasswordKdf::kPbkdf2;
      policy.iteration_override = kdf_iterations_override;
    }
    policy.progress = [](uint32_t current, uint32_t total) { // TSK036_PBKDF2_Argon2_Migration_Path
      if (total == 0) {
        return;
      }
      auto percent = static_cast<uint32_t>((static_cast<uint64_t>(current) * 100u) / total);
      std::cerr << "\rDeriving password key... " << percent << "%" << std::flush;
      if (current >= total) {
        std::cerr << std::endl;
      }
    };
    vm.SetKdfPolicy(policy);

    if (cmd == "create") {
      if (argc - index != 1) {
        PrintUsage();
        return kExitUsage;
      }
      std::filesystem::path container_path; // TSK129_Unvalidated_User_Input_in_CLI
      if (!TryParsePathArgument(std::string_view(argv[index]), container_path, "container path")) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleCreate(container_path, vm, security_flags);
    }
    if (cmd == "mount") {
      if (argc - index != 2) {
        PrintUsage();
        return kExitUsage;
      }
      std::filesystem::path container_path; // TSK129_Unvalidated_User_Input_in_CLI
      std::filesystem::path mount_path;     // TSK129_Unvalidated_User_Input_in_CLI
      if (!TryParsePathArgument(std::string_view(argv[index]), container_path, "container path") ||
          !TryParsePathArgument(std::string_view(argv[index + 1]), mount_path, "mount point")) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleMount(container_path, mount_path, vm, security_flags);
    }
    if (cmd == "rekey") {
      if (argc - index < 1 || argc - index > 2) {
        PrintUsage();
        return kExitUsage;
      }
      std::optional<std::filesystem::path>
          backup_path; // TSK024_Key_Rotation_and_Lifecycle_Management
      std::optional<std::filesystem::path> container_path; // TSK129_Unvalidated_User_Input_in_CLI
      for (int i = index; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg.rfind("--backup-key=", 0) == 0) {
          auto value = arg.substr(std::string_view("--backup-key=").size());
          if (value.empty()) {
            PrintUsage();
            return kExitUsage;
          }
          std::filesystem::path parsed_backup;
          if (!TryParsePathArgument(value, parsed_backup, "backup key path")) { // TSK129_Unvalidated_User_Input_in_CLI
            PrintUsage();
            return kExitUsage;
          }
          backup_path = parsed_backup;
          continue;
        }
        if (!container_path) {
          std::filesystem::path parsed_container;
          if (!TryParsePathArgument(arg, parsed_container, "container path")) { // TSK129_Unvalidated_User_Input_in_CLI
            PrintUsage();
            return kExitUsage;
          }
          container_path = parsed_container;
        } else {
          PrintUsage();
          return kExitUsage;
        }
      }
      if (!container_path) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleRekey(*container_path, backup_path, vm, security_flags);
    }
    if (cmd == "migrate") { // TSK033
      if (argc - index < 1 || argc - index > 2) {
        PrintUsage();
        return kExitUsage;
      }
      std::optional<uint32_t> target_version;
      std::optional<std::filesystem::path> container_path;
      for (int i = index; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg.rfind("--migrate-to=", 0) == 0) {
          auto value = arg.substr(std::string_view("--migrate-to=").size());
          if (!ValidateNoEmbeddedNull(value, "migration target")) { // TSK129_Unvalidated_User_Input_in_CLI
            PrintUsage();
            return kExitUsage;
          }
          auto parsed = ParseVersionFlag(value);
          if (!parsed) {
            PrintUsage();
            return kExitUsage;
          }
          target_version = *parsed;
          continue;
        }
        if (!container_path) {
          std::filesystem::path parsed_container;
          if (!TryParsePathArgument(arg, parsed_container, "container path")) { // TSK129_Unvalidated_User_Input_in_CLI
            PrintUsage();
            return kExitUsage;
          }
          container_path = parsed_container;
        } else {
          PrintUsage();
          return kExitUsage;
        }
      }
      if (!container_path) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleMigrate(*container_path, target_version, vm);
    }
    if (cmd == "migrate-nonces") {
      if (argc - index != 1) {
        PrintUsage();
        return kExitUsage;
      }
      std::filesystem::path container_path; // TSK129_Unvalidated_User_Input_in_CLI
      if (!TryParsePathArgument(std::string_view(argv[index]), container_path, "container path")) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleMigrateNonces(container_path);
    }
    if (cmd == "backup") { // TSK032_Backup_Recovery_and_Disaster_Recovery
      std::optional<std::filesystem::path> output_dir;
      std::optional<std::filesystem::path> container_path;
      for (int i = index; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg.rfind("--output=", 0) == 0) {
          auto value = arg.substr(std::string_view("--output=").size());
          if (value.empty()) {
            PrintUsage();
            return kExitUsage;
          }
          std::filesystem::path parsed_output;
          if (!TryParsePathArgument(value, parsed_output, "backup directory")) { // TSK129_Unvalidated_User_Input_in_CLI
            PrintUsage();
            return kExitUsage;
          }
          output_dir = parsed_output;
          continue;
        }
        if (!container_path) {
          std::filesystem::path parsed_container;
          if (!TryParsePathArgument(arg, parsed_container, "container path")) { // TSK129_Unvalidated_User_Input_in_CLI
            PrintUsage();
            return kExitUsage;
          }
          container_path = parsed_container;
        } else {
          PrintUsage();
          return kExitUsage;
        }
      }
      if (!output_dir || !container_path) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleBackup(*container_path, *output_dir);
    }
    if (cmd == "fsck") { // TSK032_Backup_Recovery_and_Disaster_Recovery
      if (argc - index != 1) {
        PrintUsage();
        return kExitUsage;
      }
      std::filesystem::path container_path; // TSK129_Unvalidated_User_Input_in_CLI
      if (!TryParsePathArgument(std::string_view(argv[index]), container_path, "container path")) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleFsck(container_path);
    }
    if (cmd == "destroy") { // TSK028_Secure_Deletion_and_Data_Remanence
      if (argc - index != 1) {
        PrintUsage();
        return kExitUsage;
      }
      std::filesystem::path container_path; // TSK129_Unvalidated_User_Input_in_CLI
      if (!TryParsePathArgument(std::string_view(argv[index]), container_path, "container path")) {
        PrintUsage();
        return kExitUsage;
      }
      return HandleDestroy(container_path);
    }

    PrintUsage();
    return kExitUsage;
  } catch (const qv::AuthenticationFailureError& err) {
    (void)err;
    std::cerr << kGenericAuthFailureMessage << std::endl; // TSK080_Error_Info_Redaction_in_Release
    return kExitAuth;
  } catch (const qv::Error& err) {
    ReportError(err);
    return ExitCodeFor(err);
  } catch (const std::exception& err) {
#ifdef NDEBUG
    std::cerr << "I/O error: Operation failed." << std::endl;
#else
    std::cerr << "I/O error: " << err.what() << std::endl;
#endif
    return kExitIO;
  }
}
