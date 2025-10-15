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

#include <algorithm> // TSK072_CryptoProvider_Init_and_KAT runtime KAT comparisons
#include <array>     // TSK072_CryptoProvider_Init_and_KAT AES-GCM vectors
#include <memory>
#include <mutex>
#include <iostream> // TSK023_Production_Crypto_Provider_Complete_Integration runtime logging
#include <stdexcept>
#include <string>
#include <utility>

#include "qv/crypto/ct.h" // TSK102_Timing_Side_Channels constant-time comparisons
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

struct RuntimeState { // TSK072_CryptoProvider_Init_and_KAT cache runtime metadata
  std::once_flag once;
  HardwareCapabilities caps{};
  bool kat_passed{false};
};

RuntimeState& MutableRuntimeState() {
  static RuntimeState state{}; // TSK072_CryptoProvider_Init_and_KAT global runtime guard
  return state;
}

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

void RunAESGCMKnownAnswerTest() { // TSK072_CryptoProvider_Init_and_KAT AES-GCM self-test
  static constexpr std::array<uint8_t, AES256_GCM::KEY_SIZE> kKey{
      0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
      0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
  static constexpr std::array<uint8_t, AES256_GCM::NONCE_SIZE> kNonce{
      0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
      0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
  static constexpr std::array<uint8_t, 60> kPlaintext{
      0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
      0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
      0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
      0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
      0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
  static constexpr std::array<uint8_t, 20> kAad{
      0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
      0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};
  static constexpr std::array<uint8_t, 60> kExpectedCiphertext{
      0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7,
      0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
      0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2,
      0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
      0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91};
  static constexpr std::array<uint8_t, AES256_GCM::TAG_SIZE> kExpectedTag{
      0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
      0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47};

  OpenSSLCryptoProvider provider;
  const auto enc = provider.EncryptAES256GCM(
      std::span<const uint8_t>(kPlaintext.data(), kPlaintext.size()),
      std::span<const uint8_t>(kAad.data(), kAad.size()),
      std::span<const uint8_t, AES256_GCM::NONCE_SIZE>(kNonce),
      std::span<const uint8_t, AES256_GCM::KEY_SIZE>(kKey));
  std::array<uint8_t, kExpectedCiphertext.size()> cipher_buf{};          // TSK102_Timing_Side_Channels
  const size_t cipher_copy = std::min(enc.ciphertext.size(), cipher_buf.size());
  std::copy_n(enc.ciphertext.begin(), cipher_copy, cipher_buf.begin());
  uint32_t cipher_mask = 0;                                              // TSK102_Timing_Side_Channels
  cipher_mask |= enc.ciphertext.size() == kExpectedCiphertext.size() ? 0u : 1u;
  cipher_mask |= qv::crypto::ct::CompareEqual(cipher_buf, kExpectedCiphertext) ? 0u : 2u;
  if (cipher_mask != 0u) {
    ThrowCryptoError("AES-GCM KAT ciphertext mismatch");
  }
  uint32_t tag_mask = qv::crypto::ct::CompareEqual(enc.tag, kExpectedTag) ? 0u : 1u; // TSK102_Timing_Side_Channels
  if (tag_mask != 0u) {
    ThrowCryptoError("AES-GCM KAT tag mismatch");
  }

  const auto dec = provider.DecryptAES256GCM(
      std::span<const uint8_t>(enc.ciphertext.data(), enc.ciphertext.size()),
      std::span<const uint8_t>(kAad.data(), kAad.size()),
      std::span<const uint8_t, AES256_GCM::NONCE_SIZE>(kNonce),
      std::span<const uint8_t, AES256_GCM::TAG_SIZE>(enc.tag),
      std::span<const uint8_t, AES256_GCM::KEY_SIZE>(kKey));
  std::array<uint8_t, kPlaintext.size()> plain_buf{};                     // TSK102_Timing_Side_Channels
  const size_t plain_copy = std::min(dec.size(), plain_buf.size());
  std::copy_n(dec.begin(), plain_copy, plain_buf.begin());
  uint32_t plain_mask = 0;                                                // TSK102_Timing_Side_Channels
  plain_mask |= dec.size() == kPlaintext.size() ? 0u : 1u;
  plain_mask |= qv::crypto::ct::CompareEqual(plain_buf, kPlaintext) ? 0u : 2u;
  if (plain_mask != 0u) {
    ThrowCryptoError("AES-GCM KAT decrypt mismatch");
  }
}

void EnsureCryptoRuntimeConfigured() {
  auto& state = MutableRuntimeState();
  std::call_once(state.once, [&state]() {
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
    state.caps = DetectHardwareCapabilities();
    std::clog << "[crypto] AES-NI: " << (state.caps.aesni ? "yes" : "no")
              << ", PCLMUL: " << (state.caps.pclmul ? "yes" : "no")
              << ", SHA extensions: " << (state.caps.sha ? "yes" : "no") << std::endl; // TSK023_Production_Crypto_Provider_Complete_Integration log hardware
    RunAESGCMKnownAnswerTest();
    state.kat_passed = true;
    std::clog << "[crypto] AES-GCM known-answer test passed" << std::endl; // TSK072_CryptoProvider_Init_and_KAT KAT logging
  });
}

}  // namespace

void EnsureCryptoProviderInitialized() { // TSK072_CryptoProvider_Init_and_KAT public runtime entry point
  EnsureCryptoRuntimeConfigured();
}

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

