#include "qv/crypto/provider.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#if defined(QV_FIPS_MODE) && !defined(_WIN32)
#include <openssl/crypto.h> // TSK023_Production_Crypto_Provider_Complete_Integration FIPS mode toggle
#endif

#if QV_HAVE_SODIUM
#include <sodium.h> // TSK023_Production_Crypto_Provider_Complete_Integration libsodium initialization
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#include <cpuid.h>
#endif

#if defined(__linux__) && defined(__aarch64__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

#include <memory>
#include <mutex>
#include <iostream> // TSK023_Production_Crypto_Provider_Complete_Integration runtime logging
#include <stdexcept>
#include <string>
#include <utility>

#include "qv/error.h"

namespace qv::crypto {

namespace {

void ThrowCryptoError(const std::string& message, int code = 0); // TSK023_Production_Crypto_Provider_Complete_Integration forward declare

std::string BuildOpenSSLErrorMessage(const char* context) {
  unsigned long err = ERR_get_error();
  if (err == 0) {
    return std::string(context) + ": unknown OpenSSL error";
  }

  char buf[256] = {0};
  ERR_error_string_n(err, buf, sizeof(buf));
  std::string message(context);
  message.append(": ");
  message.append(buf);
  return message;
}

class EVPContextDeleter {
public:
  void operator()(EVP_CIPHER_CTX* ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
  void operator()(EVP_MD_CTX* ctx) const noexcept { EVP_MD_CTX_free(ctx); }
};

using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EVPContextDeleter>;

struct HardwareCapabilities {
  bool aesni{false};
  bool pclmul{false};
  bool sha{false};
}; // TSK023_Production_Crypto_Provider_Complete_Integration feature snapshot

HardwareCapabilities DetectHardwareCapabilities() {
  HardwareCapabilities caps{};
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
  int cpu_info[4] = {0};
  __cpuid(cpu_info, 1);
  int ecx = cpu_info[2];
  caps.aesni = (ecx & (1 << 25)) != 0;  // TSK023_Production_Crypto_Provider_Complete_Integration AES-NI bit
  caps.pclmul = (ecx & (1 << 1)) != 0;  // TSK023_Production_Crypto_Provider_Complete_Integration PCLMUL bit
  __cpuidex(cpu_info, 7, 0);
  int ebx = cpu_info[1];
  caps.sha = (ebx & (1 << 29)) != 0;    // TSK023_Production_Crypto_Provider_Complete_Integration SHA extensions
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
  unsigned int eax = 0;
  unsigned int ebx = 0;
  unsigned int ecx = 0;
  unsigned int edx = 0;
  unsigned int max_leaf = __get_cpuid_max(0, nullptr);
  if (max_leaf >= 1) {
    __cpuid(1, eax, ebx, ecx, edx);
    caps.aesni = (ecx & (1u << 25)) != 0; // TSK023_Production_Crypto_Provider_Complete_Integration AES flag
    caps.pclmul = (ecx & (1u << 1)) != 0; // TSK023_Production_Crypto_Provider_Complete_Integration PCLMUL flag
  }
  if (max_leaf >= 7) {
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    caps.sha = (ebx & (1u << 29)) != 0;   // TSK023_Production_Crypto_Provider_Complete_Integration SHA flag
  }
#elif defined(__linux__) && defined(__aarch64__)
  unsigned long hwcap = getauxval(AT_HWCAP);
#ifdef HWCAP_AES
  caps.aesni = (hwcap & HWCAP_AES) != 0;  // TSK023_Production_Crypto_Provider_Complete_Integration AES (ARM)
#endif
#ifdef HWCAP_SHA2
  caps.sha = (hwcap & HWCAP_SHA2) != 0;   // TSK023_Production_Crypto_Provider_Complete_Integration SHA (ARM)
#endif
#endif
  return caps;
}

std::mutex& ProviderMutex() {
  static std::mutex mutex;
  return mutex;
}

std::shared_ptr<CryptoProvider>& ProviderInstance() {
  static std::shared_ptr<CryptoProvider> instance;
  return instance;
}

void ThrowCryptoError(const std::string& message, int code) {
  throw qv::Error(qv::ErrorDomain::Crypto, code, message);
}

void EnsureCryptoRuntimeConfigured() {
  static std::once_flag once; // TSK023_Production_Crypto_Provider_Complete_Integration one-time init
  std::call_once(once, []() {
#if QV_HAVE_SODIUM
    if (sodium_init() < 0) {
      ThrowCryptoError("sodium_init failed");
    }
#endif
#if defined(QV_FIPS_MODE) && !defined(_WIN32)
    if (FIPS_mode_set(1) != 1) {
      ThrowCryptoError("Failed to enable FIPS mode", static_cast<int>(ERR_get_error()));
    }
    std::clog << "[crypto] OpenSSL FIPS mode enabled" << std::endl; // TSK023_Production_Crypto_Provider_Complete_Integration log FIPS
#endif
    HardwareCapabilities caps = DetectHardwareCapabilities();
    std::clog << "[crypto] AES-NI: " << (caps.aesni ? "yes" : "no")
              << ", PCLMUL: " << (caps.pclmul ? "yes" : "no")
              << ", SHA extensions: " << (caps.sha ? "yes" : "no") << std::endl; // TSK023_Production_Crypto_Provider_Complete_Integration log hardware
  });
}

}  // namespace

AES256_GCM::EncryptionResult OpenSSLCryptoProvider::EncryptAES256GCM(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad,
    std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
    std::span<const uint8_t, AES256_GCM::KEY_SIZE> key) {
  CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    ThrowCryptoError("Failed to allocate AES-GCM context");
  }

  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_EncryptInit_ex"));
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(nonce.size()), nullptr) != 1) {
    ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_CTRL_GCM_SET_IVLEN"));
  }
  if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
    ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_EncryptInit_ex key/iv"));
  }

  int len = 0;
  if (!aad.empty()) {
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                          static_cast<int>(aad.size())) != 1) {
      ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_EncryptUpdate aad"));
    }
  }

  AES256_GCM::EncryptionResult result;
  result.ciphertext.resize(plaintext.size());
  int total = 0;
  if (!plaintext.empty()) {
    if (EVP_EncryptUpdate(ctx.get(), result.ciphertext.data(), &len,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
      ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_EncryptUpdate plaintext"));
    }
    total = len;
  }

  if (EVP_EncryptFinal_ex(ctx.get(),
                          result.ciphertext.data() + total, &len) != 1) {
    ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_EncryptFinal_ex"));
  }
  total += len;
  result.ciphertext.resize(static_cast<size_t>(total));

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                           AES256_GCM::TAG_SIZE, result.tag.data()) != 1) {
    ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_CTRL_GCM_GET_TAG"));
  }

  return result;
}

std::vector<uint8_t> OpenSSLCryptoProvider::DecryptAES256GCM(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> aad,
    std::span<const uint8_t, AES256_GCM::NONCE_SIZE> nonce,
    std::span<const uint8_t, AES256_GCM::TAG_SIZE> tag,
    std::span<const uint8_t, AES256_GCM::KEY_SIZE> key) {
  CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    ThrowCryptoError("Failed to allocate AES-GCM context");
  }

  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_DecryptInit_ex"));
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(nonce.size()), nullptr) != 1) {
    ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_CTRL_GCM_SET_IVLEN"));
  }
  if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
    ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_DecryptInit_ex key/iv"));
  }

  int len = 0;
  if (!aad.empty()) {
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                          static_cast<int>(aad.size())) != 1) {
      ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_DecryptUpdate aad"));
    }
  }

  std::vector<uint8_t> plaintext(ciphertext.size());
  int total = 0;
  if (!ciphertext.empty()) {
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1) {
      ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_DecryptUpdate ciphertext"));
    }
    total = len;
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                           AES256_GCM::TAG_SIZE, const_cast<uint8_t*>(tag.data())) != 1) {
    ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_CTRL_GCM_SET_TAG"));
  }

  int final_len = 0;
  int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total, &final_len);
  if (ret <= 0) {
    throw qv::AuthenticationFailureError(
        BuildOpenSSLErrorMessage("EVP_DecryptFinal_ex (authentication failed)"));
  }
  total += final_len;
  plaintext.resize(static_cast<size_t>(total));

  return plaintext;
}

std::array<uint8_t, 32> OpenSSLCryptoProvider::HMACSHA256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> message) {
  std::array<uint8_t, 32> out{};
  unsigned int len = 0;
  if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), message.data(),
           message.size(), out.data(), &len) == nullptr) {
    ThrowCryptoError(BuildOpenSSLErrorMessage("HMAC(EVP_sha256)"));
  }
  if (len != out.size()) {
    ThrowCryptoError("Unexpected HMAC-SHA256 length", static_cast<int>(len));
  }
  return out;
}

std::array<uint8_t, 32> OpenSSLCryptoProvider::SHA256(
    std::span<const uint8_t> data) {
  std::array<uint8_t, 32> out{};
  unsigned int len = 0;
  if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr) != 1) {
    ThrowCryptoError(BuildOpenSSLErrorMessage("EVP_Digest(EVP_sha256)"));
  }
  if (len != out.size()) {
    ThrowCryptoError("Unexpected SHA-256 length", static_cast<int>(len));
  }
  return out;
}

std::shared_ptr<CryptoProvider> GetCryptoProviderShared() {
  EnsureCryptoRuntimeConfigured(); // TSK023_Production_Crypto_Provider_Complete_Integration configure runtime once
  std::lock_guard<std::mutex> lock(ProviderMutex());
  auto& provider = ProviderInstance();
  if (!provider) {
    provider = std::make_shared<OpenSSLCryptoProvider>();
  }
  return provider;
}

CryptoProvider& GetCryptoProvider() {
  return *GetCryptoProviderShared();
}

void SetCryptoProvider(std::shared_ptr<CryptoProvider> provider) {
  std::lock_guard<std::mutex> lock(ProviderMutex());
  ProviderInstance() = std::move(provider);
}

}  // namespace qv::crypto

