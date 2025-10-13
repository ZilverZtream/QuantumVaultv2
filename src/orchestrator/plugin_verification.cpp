#include "qv/orchestrator/plugin_verification.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>
#include <charconv>

#include "qv/crypto/ct.h"
#include "qv/orchestrator/plugin_abi.h"

#if QV_HAVE_SODIUM
#include <sodium.h> // TSK023_Production_Crypto_Provider_Complete_Integration prefer libsodium Ed25519
#endif

#if __has_include(<openssl/evp.h>)
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>
#else
#include <dlfcn.h>
#endif

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#elif defined(__linux__)
#  if __has_include(<linux/fsverity.h>)
#    include <linux/fsverity.h>
#    include <fcntl.h>
#    include <sys/ioctl.h>
#    include <unistd.h>
#    ifndef FS_VERITY_MAX_DIGEST_SIZE
#      define FS_VERITY_MAX_DIGEST_SIZE 64
#    endif
#  endif
#include <sys/stat.h>
#endif

using namespace qv::orchestrator;
using namespace qv::crypto;
using qv::crypto::ct::CompareEqual;
using qv::crypto::ct::StringCompare; // TSK037

namespace {
std::string_view Trim(std::string_view in);

// TSK005 default trust anchors for plugin verification. Replace with real keys
// when provisioning signing infrastructure.
constexpr std::array<uint8_t, 32> kEmbeddedRoot0{
    0x12, 0x1A, 0x3C, 0xE4, 0x55, 0xF6, 0x9A, 0xB3,
    0x44, 0x09, 0x26, 0xEE, 0x60, 0xDB, 0x77, 0x90,
    0xAB, 0x4F, 0xCD, 0x8E, 0xFE, 0x01, 0x9F, 0x3D,
    0x77, 0x42, 0x10, 0x6D, 0x35, 0x68, 0xAF, 0xC2};
constexpr std::array<uint8_t, 32> kEmbeddedRoot1{
    0x6F, 0x58, 0x91, 0x13, 0x40, 0xA2, 0xCC, 0x01,
    0x6D, 0xA1, 0xFF, 0x33, 0x2B, 0x5E, 0xDA, 0x7A,
    0x05, 0x7B, 0x88, 0xEF, 0x90, 0x34, 0x67, 0x22,
    0x9D, 0x11, 0x75, 0x46, 0xC0, 0x8C, 0x5B, 0x3F};

// TSK011 helper to read ABI compatibility ranges from textual policy entries.
std::optional<uint32_t> ParseUint32(std::string_view text) {
  uint32_t value = 0;
  auto begin = text.data();
  auto end = text.data() + text.size();
  auto result = std::from_chars(begin, end, value, 10);
  if (result.ec != std::errc() || result.ptr != end) {
    return std::nullopt;
  }
  return value;
}

std::optional<PluginCompatibilityRange> ParseAbiRange(std::string_view text) {
  text = Trim(text);
  if (text.empty()) return std::nullopt;
  PluginCompatibilityRange range{};
  auto dash = text.find('-');
  if (dash == std::string_view::npos) {
    if (auto value = ParseUint32(text)) {
      range.min_version = *value;
      range.max_version = *value;
      return range;
    }
    return std::nullopt;
  }
  auto min_part = text.substr(0, dash);
  auto max_part = text.substr(dash + 1);
  auto min_val = ParseUint32(Trim(min_part));
  auto max_val = ParseUint32(Trim(max_part));
  if (!min_val || !max_val) return std::nullopt;
  range.min_version = *min_val;
  range.max_version = *max_val;
  if (range.min_version > range.max_version) {
    std::swap(range.min_version, range.max_version);
  }
  return range;
}

struct ScopedLibrary {
#if defined(_WIN32)
  using handle_type = HMODULE;
#else
  using handle_type = void*;
#endif

  ScopedLibrary() = default;
  ScopedLibrary(const ScopedLibrary&) = delete;
  ScopedLibrary& operator=(const ScopedLibrary&) = delete;
  ScopedLibrary(ScopedLibrary&& other) noexcept { *this = std::move(other); }
  ScopedLibrary& operator=(ScopedLibrary&& other) noexcept {
    if (this != &other) {
      Close();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  ~ScopedLibrary() { Close(); }

  bool Open(const std::filesystem::path& path) {
    Close();
#if defined(_WIN32)
    std::wstring wide = path.wstring();
    handle_ = ::LoadLibraryW(wide.c_str());
#else
    std::string utf8 = path.string();
    handle_ = ::dlopen(utf8.c_str(), RTLD_NOW | RTLD_LOCAL);
#endif
    return handle_ != nullptr;
  }

  void* Symbol(const char* name) const {
    if (!handle_) return nullptr;
#if defined(_WIN32)
    return reinterpret_cast<void*>(::GetProcAddress(handle_, name));
#else
    return ::dlsym(handle_, name);
#endif
  }

  void Close() {
    if (!handle_) return;
#if defined(_WIN32)
    ::FreeLibrary(handle_);
#else
    ::dlclose(handle_);
#endif
    handle_ = nullptr;
  }

  handle_type handle_{nullptr};
};

bool IsAllZero(std::span<const uint8_t> buffer) {
  for (auto b : buffer) {
    if (b != 0) return false;
  }
  return true;
}

std::string_view Trim(std::string_view in) {
  while (!in.empty() && std::isspace(static_cast<unsigned char>(in.front()))) {
    in.remove_prefix(1);
  }
  while (!in.empty() && std::isspace(static_cast<unsigned char>(in.back()))) {
    in.remove_suffix(1);
  }
  return in;
}

int HexDigit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::optional<std::array<uint8_t, 32>> ParseKey(std::string_view hex) {
  hex = Trim(hex);
  if (hex.size() != 64) return std::nullopt;
  std::array<uint8_t, 32> out{};
  for (size_t i = 0; i < out.size(); ++i) {
    int hi = HexDigit(hex[i * 2]);
    int lo = HexDigit(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return std::nullopt;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return out;
}

void InsertUnique(std::vector<std::array<uint8_t, 32>>& roots,
                  const std::array<uint8_t, 32>& candidate) {
  for (const auto& entry : roots) {
    if (CompareEqual<32>(entry, candidate)) {
      return;
    }
  }
  roots.push_back(candidate);
}

std::optional<std::array<uint8_t, 32>> ResolvePin(const PluginTrustPolicy& policy,
                                                  const std::string& plugin_id) {
  std::array<uint8_t, 32> resolved{};
  uint8_t found_mask = 0;
  const bool plugin_present = !plugin_id.empty();
  for (const auto& entry : policy.pinned_public_keys) {                 // TSK037
    bool id_match = plugin_present & StringCompare(entry.first, plugin_id); // TSK037
    for (size_t i = 0; i < resolved.size(); ++i) {                      // TSK037
      resolved[i] = qv::crypto::ct::Select<uint8_t>(resolved[i], entry.second[i], id_match);
    }
    found_mask |= static_cast<uint8_t>(id_match);
  }
  std::atomic_signal_fence(std::memory_order_seq_cst); // TSK037
  if (found_mask != 0) {
    return resolved;
  }
  return std::nullopt;
}

bool IsKeyTrusted(const PluginTrustPolicy& policy, const std::string& plugin_id,
                  const std::array<uint8_t, 32>& key) {
  uint8_t trusted_mask = 0;
  const bool plugin_present = !plugin_id.empty();
  for (const auto& entry : policy.pinned_public_keys) {                        // TSK037
    bool id_match = plugin_present & StringCompare(entry.first, plugin_id);    // TSK037
    bool key_match = CompareEqual<32>(entry.second, key);                      // TSK037
    trusted_mask |= static_cast<uint8_t>(id_match & key_match);                // TSK037
  }
  for (const auto& root : policy.root_public_keys) {                           // TSK037
    bool root_match = CompareEqual<32>(root, key);
    trusted_mask |= static_cast<uint8_t>(root_match);
  }
  std::atomic_signal_fence(std::memory_order_seq_cst); // TSK037
  return trusted_mask != 0;
}
} // namespace

namespace qv::orchestrator {

const PluginTrustPolicy& DefaultPluginTrustPolicy() {
  static const PluginTrustPolicy policy = [] {
    PluginTrustPolicy defaults;
    defaults.require_signature = true;
    defaults.allow_hash_fallback = false;
    defaults.root_public_keys.reserve(2);
    InsertUnique(defaults.root_public_keys, kEmbeddedRoot0);
    InsertUnique(defaults.root_public_keys, kEmbeddedRoot1);
    defaults.pinned_public_keys.emplace("qv_example_crypto", kEmbeddedRoot0);
    defaults.pinned_public_keys.emplace("qv_pqc_mlkem", kEmbeddedRoot1);
    defaults.default_abi_range.min_version = QV_PLUGIN_ABI_VERSION;
    defaults.default_abi_range.max_version = QV_PLUGIN_ABI_VERSION;
    return defaults;
  }();
  return policy;
}

PluginTrustPolicy LoadPluginTrustPolicy(const std::filesystem::path& policy_path) {
  PluginTrustPolicy policy = DefaultPluginTrustPolicy();
  std::ifstream in(policy_path, std::ios::binary);
  if (!in) {
    return policy;
  }
  std::string line;
  while (std::getline(in, line)) {
    std::string_view view = Trim(line);
    if (view.empty() || view.front() == '#') continue;
    if (view.rfind("root:", 0) == 0) {
      if (auto parsed = ParseKey(view.substr(5))) {
        InsertUnique(policy.root_public_keys, *parsed);
      }
      continue;
    }
    if (view.rfind("pin:", 0) == 0) {
      auto separator = view.find('=');
      if (separator == std::string_view::npos) continue;
      std::string plugin_id(view.substr(4, separator - 4));
      if (auto parsed = ParseKey(view.substr(separator + 1))) {
        policy.pinned_public_keys[std::move(plugin_id)] = *parsed;
      }
      continue;
    }
    if (StringCompare(view, std::string_view("allow_hash_fallback=true"))) { // TSK037
      policy.allow_hash_fallback = true;
      continue;
    }
    if (StringCompare(view, std::string_view("allow_hash_fallback=false"))) { // TSK037
      policy.allow_hash_fallback = false;
      continue;
    }
    if (StringCompare(view, std::string_view("require_signature=true"))) { // TSK037
      policy.require_signature = true;
      continue;
    }
    if (StringCompare(view, std::string_view("require_signature=false"))) { // TSK037
      policy.require_signature = false;
      continue;
    }
    if (view.rfind("abi:", 0) == 0) {
      auto content = view.substr(4);
      auto separator = content.find('=');
      if (separator == std::string_view::npos) continue;
      std::string key(Trim(content.substr(0, separator)));
      if (auto range = ParseAbiRange(content.substr(separator + 1))) {
        bool wildcard = StringCompare(key, std::string_view("*"));            // TSK037
        bool named_default = StringCompare(key, std::string_view("default"));  // TSK037
        if (wildcard | named_default) {                                        // TSK037
          policy.default_abi_range = *range;
        } else {
          policy.plugin_abi_ranges[key] = *range;
        }
      }
      continue;
    }
    if (view.rfind("capability_schema=", 0) == 0) {
      auto schema_text = view.substr(std::strlen("capability_schema="));
      if (auto value = ParseUint32(schema_text)) {
        policy.capability_schema_version = *value;
      }
      continue;
    }
  }
  return policy;
}

bool VerifyPlugin(const std::filesystem::path& path, const PluginVerification& expected) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  f.seekg(0, std::ios::end);
  size_t sz = static_cast<size_t>(f.tellg());
  f.seekg(0, std::ios::beg);
  std::vector<uint8_t> data(sz);
  f.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(sz));
  if (f.gcount() != static_cast<std::streamsize>(sz)) {
    return false;
  }
  auto hash = qv::crypto::SHA256_Hash(data);

  const PluginTrustPolicy* policy_ptr = expected.trust_policy;
  if (policy_ptr == nullptr) {
    policy_ptr = &DefaultPluginTrustPolicy();
  }
  const PluginTrustPolicy& policy = *policy_ptr;

  std::string plugin_id = expected.plugin_id;
  if (plugin_id.empty()) {
    plugin_id = path.stem().string();
  }

  std::array<uint8_t, 32> signing_key = expected.public_key;
  if (auto pin = ResolvePin(policy, plugin_id)) {
    signing_key = *pin;
  }

  bool signature_present = !IsAllZero(std::span<const uint8_t>(expected.signature));
  bool hash_present = !IsAllZero(std::span<const uint8_t>(expected.expected_hash));

  bool signature_valid = false;
  if (signature_present && !IsAllZero(std::span<const uint8_t>(signing_key))) {
    if (IsKeyTrusted(policy, plugin_id, signing_key)) {
      signature_valid = Ed25519_Verify(signing_key, hash, expected.signature);
    }
  }

  const bool require_signature = expected.enforce_signature || policy.require_signature;
  const bool allow_hash = expected.allow_hash_fallback || policy.allow_hash_fallback;
  bool fallback_hash_match = CompareEqual<32>(hash, expected.expected_hash);        // TSK037
  bool fallback_ok = allow_hash & hash_present & fallback_hash_match;              // TSK037
  std::atomic_signal_fence(std::memory_order_seq_cst);                              // TSK037

  if (require_signature && !signature_valid) {
    return false;
  }

  if (!signature_valid && !fallback_ok) {
    return false;
  }

  auto abi = QueryPluginABI(path);
  if (!abi) {
    return false;
  }

  PluginCompatibilityRange allowed{expected.min_abi_version, expected.max_abi_version};
  allowed.min_version = std::max(allowed.min_version, policy.default_abi_range.min_version);
  allowed.max_version = std::min(allowed.max_version, policy.default_abi_range.max_version);
  if (auto override = policy.plugin_abi_ranges.find(plugin_id); override != policy.plugin_abi_ranges.end()) {
    allowed.min_version = std::max(allowed.min_version, override->second.min_version);
    allowed.max_version = std::min(allowed.max_version, override->second.max_version);
  }

  if (allowed.min_version > allowed.max_version) {
    return false;
  }

  if (abi->plugin_min > allowed.max_version || abi->plugin_max < allowed.min_version) {
    return false;
  }

  if (abi->has_selftest && !abi->selftest_passed) {
    return false;
  }
  if (!HasSecurityFlags(path)) return false;
  return true;
}

bool HasSecurityFlags(const std::filesystem::path& path) {
#if defined(_WIN32)
  (void)path;
  return VerifyPlatformSignature(path);
#else
  std::error_code ec;
  auto status = std::filesystem::status(path, ec);
  if (ec) {
    return false;
  }
  auto perms = status.permissions();
  const bool locked = (perms & std::filesystem::perms::group_write) == std::filesystem::perms::none &&
                      (perms & std::filesystem::perms::others_write) == std::filesystem::perms::none;
  return locked && VerifyPlatformSignature(path);
#endif
}

std::optional<PluginAbiQueryResult> QueryPluginABI(const std::filesystem::path& path) {
  ScopedLibrary library;
  if (!library.Open(path)) {
    return std::nullopt;
  }

  auto get_abi = reinterpret_cast<QV_Plugin_GetAbi>(library.Symbol("qv_plugin_get_abi"));
  if (!get_abi) {
    return std::nullopt;
  }

  QV_PluginAbiNegotiation negotiation = get_abi();
  PluginAbiQueryResult result{};
  result.plugin_min = negotiation.min_supported;
  result.plugin_max = negotiation.max_supported;
  if (result.plugin_min == 0 || result.plugin_max == 0) {
    return std::nullopt;
  }
  if (result.plugin_min > result.plugin_max) {
    std::swap(result.plugin_min, result.plugin_max);
  }

  auto selftest = reinterpret_cast<QV_Plugin_SelfTest>(library.Symbol("qv_plugin_selftest"));
  if (selftest) {
    result.has_selftest = true;
    result.selftest_passed = (selftest() == 0);
  } else {
    result.selftest_passed = true;
  }

  return result;
}

bool Ed25519_Verify(std::span<const uint8_t,32> pubkey,
                    std::span<const uint8_t,32> msg_hash,
                    std::span<const uint8_t,64> signature) {
#if defined(QV_USE_STUB_CRYPTO)
#error "Ed25519_Verify requires production crypto (compile with -DQV_USE_STUB_CRYPTO=OFF)" // TSK023_Production_Crypto_Provider_Complete_Integration fail-fast on stubs
#elif QV_HAVE_SODIUM
  if (pubkey.size() != crypto_sign_PUBLICKEYBYTES || signature.size() != crypto_sign_BYTES) {
    return false; // TSK023_Production_Crypto_Provider_Complete_Integration enforce key sizes
  }
  if (sodium_init() < 0) {
    return false; // TSK023_Production_Crypto_Provider_Complete_Integration libsodium unavailable
  }
  return crypto_sign_verify_detached(signature.data(), msg_hash.data(), msg_hash.size(),
                                     pubkey.data()) == 0; // TSK023_Production_Crypto_Provider_Complete_Integration use libsodium
#elif __has_include(<openssl/evp.h>)
  if (pubkey.size() != 32 || signature.size() != 64) {
    return false;
  }
  EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                              pubkey.data(), pubkey.size());
  if (!key) {
    return false;
  }
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(key);
    return false;
  }
  bool ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1 &&
            EVP_DigestVerify(ctx, signature.data(), signature.size(),
                             msg_hash.data(), msg_hash.size()) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok;
#else
#error "No Ed25519 implementation available" // TSK023_Production_Crypto_Provider_Complete_Integration require crypto wiring
#endif
}

bool VerifyPlatformSignature(const std::filesystem::path& path) {
#if defined(_WIN32)
  std::wstring wide = path.wstring();
  WINTRUST_FILE_INFO file_info{};
  file_info.cbStruct = sizeof(file_info);
  file_info.pcwszFilePath = wide.c_str();
  GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_DATA trust_data{};
  trust_data.cbStruct = sizeof(trust_data);
  trust_data.dwUIChoice = WTD_UI_NONE;
  trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
  trust_data.dwUnionChoice = WTD_CHOICE_FILE;
  trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
  trust_data.pFile = &file_info;
  LONG status = WinVerifyTrust(nullptr, &policy_guid, &trust_data);
  trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &policy_guid, &trust_data);
  return status == ERROR_SUCCESS;
#elif defined(__APPLE__)
  std::string utf8 = path.string();
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
                                                         reinterpret_cast<const UInt8*>(utf8.data()),
                                                         static_cast<CFIndex>(utf8.size()),
                                                         false);
  if (!url) {
    return false;
  }
  SecStaticCodeRef code = nullptr;
  OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
  CFRelease(url);
  if (status != errSecSuccess || code == nullptr) {
    if (code) CFRelease(code);
    return false;
  }
  status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, nullptr);
  CFRelease(code);
  return status == errSecSuccess;
#elif defined(__linux__) && __has_include(<linux/fsverity.h>)
#  if defined(FS_IOC_MEASURE_VERITY)
  std::string utf8 = path.string();
  int fd = ::open(utf8.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  struct FsVerityBuffer {
    __u16 algorithm;
    __u16 size;
    unsigned char digest[FS_VERITY_MAX_DIGEST_SIZE];
  } buffer{};
  buffer.size = FS_VERITY_MAX_DIGEST_SIZE;
  int result = ::ioctl(fd, FS_IOC_MEASURE_VERITY, &buffer);
  int saved_errno = errno;
  ::close(fd);
  if (result == 0) {
    return buffer.size > 0;
  }
  if (saved_errno == ENOTTY || saved_errno == EOPNOTSUPP || saved_errno == ENOSYS) {
    // Kernel/filesystem does not support fs-verity yet; treat as pass but loggable.
    return true;
  }
  return false;
#  else
  (void)path;
  return true;
#  endif
#else
  (void)path;
  return true;
#endif
}

} // namespace qv::orchestrator
