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
  struct TestVector {
    std::array<uint8_t, AES256_GCM::KEY_SIZE> key;
    std::array<uint8_t, AES256_GCM::NONCE_SIZE> nonce;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> aad;
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, AES256_GCM::TAG_SIZE> tag;
  };

  static const std::array<TestVector, 5> kVectors = { // NIST CAVP AES-GCM vectors // TSK106_Cryptographic_Implementation_Weaknesses
      TestVector{{0x31, 0xbd, 0xad, 0xd9, 0x66, 0x98, 0xc2, 0x04, 0xaa, 0x9c, 0xe1, 0x44,
                  0x8e, 0xa9, 0x4a, 0xe1, 0xfb, 0x4a, 0x9a, 0x0b, 0x3c, 0x9d, 0x77, 0x3b,
                  0x51, 0xbb, 0x18, 0x22, 0x66, 0x6b, 0x8f, 0x22},
                 {0x0d, 0x18, 0xe0, 0x6c, 0x7c, 0x72, 0x5a, 0xc9, 0xe3, 0x62, 0xe1, 0xce},
                 {0x2d, 0xb5, 0x16, 0x8e, 0x93, 0x25, 0x56, 0xf8, 0x08, 0x9a, 0x06, 0x22,
                  0x98, 0x1d, 0x01, 0x7d},
                 {},
                 {0xfa, 0x43, 0x62, 0x18, 0x96, 0x61, 0xd1, 0x63, 0xfc, 0xd6, 0xa5, 0x6d,
                  0x8b, 0xf0, 0x40, 0x5a},
                 {0xd6, 0x36, 0xac, 0x1b, 0xbe, 0xdd, 0x5c, 0xc3, 0xee, 0x72, 0x7d, 0xc2,
                  0xab, 0x4a, 0x94, 0x89}},
      TestVector{{0x92, 0xe1, 0x1d, 0xcd, 0xaa, 0x86, 0x6f, 0x5c, 0xe7, 0x90, 0xfd, 0x24,
                  0x50, 0x1f, 0x92, 0x50, 0x9a, 0xac, 0xf4, 0xcb, 0x8b, 0x13, 0x39, 0xd5,
                  0x0c, 0x9c, 0x12, 0x40, 0x93, 0x5d, 0xd0, 0x8b},
                 {0xac, 0x93, 0xa1, 0xa6, 0x14, 0x52, 0x99, 0xbd, 0xe9, 0x02, 0xf2, 0x1a},
                 {0x2d, 0x71, 0xbc, 0xfa, 0x91, 0x4e, 0x4a, 0xc0, 0x45, 0xb2, 0xaa, 0x60,
                  0x95, 0x5f, 0xad, 0x24},
                 {0x1e, 0x08, 0x89, 0x01, 0x6f, 0x67, 0x60, 0x1c, 0x8e, 0xbe, 0xa4, 0x94,
                  0x3b, 0xc2, 0x3a, 0xd6},
                 {0x89, 0x95, 0xae, 0x2e, 0x6d, 0xf3, 0xdb, 0xf9, 0x6f, 0xac, 0x7b, 0x71,
                  0x37, 0xba, 0xe6, 0x7f},
                 {0xec, 0xa5, 0xaa, 0x77, 0xd5, 0x1d, 0x4a, 0x0a, 0x14, 0xd9, 0xc5, 0x1e,
                  0x1d, 0xa4, 0x74, 0xab}},
      TestVector{{0x83, 0x68, 0x8d, 0xeb, 0x4a, 0xf8, 0x00, 0x7f, 0x9b, 0x71, 0x3b, 0x47,
                  0xcf, 0xa6, 0xc7, 0x3e, 0x35, 0xea, 0x7a, 0x3a, 0xa4, 0xec, 0xdb, 0x41,
                  0x4d, 0xde, 0xd0, 0x3b, 0xf7, 0xa0, 0xfd, 0x3a},
                 {0x0b, 0x45, 0x97, 0x24, 0x90, 0x4e, 0x01, 0x0a, 0x46, 0x90, 0x1c, 0xf3},
                 {0x33, 0xd8, 0x93, 0xa2, 0x11, 0x4c, 0xe0, 0x6f, 0xc1, 0x5d, 0x55, 0xe4,
                  0x54, 0xcf, 0x90, 0xc3},
                 {0x79, 0x4a, 0x14, 0xcc, 0xd1, 0x78, 0xc8, 0xeb, 0xfd, 0x13, 0x79, 0xdc,
                  0x70, 0x4c, 0x5e, 0x20, 0x8f, 0x9d, 0x84, 0x24},
                 {0xcc, 0x66, 0xbe, 0xe4, 0x23, 0xe3, 0xfc, 0xd4, 0xc0, 0x86, 0x57, 0x15,
                  0xe9, 0x58, 0x66, 0x96},
                 {0x0f, 0xb2, 0x91, 0xbd, 0x3d, 0xba, 0x94, 0xa1, 0xdf, 0xd8, 0xb2, 0x86,
                  0xcf, 0xb9, 0x7a, 0xc5}},
      TestVector{{0xe4, 0xfe, 0xd3, 0x39, 0xc7, 0xb0, 0xcd, 0x26, 0x73, 0x05, 0xd1, 0x1a,
                  0xb0, 0xd5, 0xc3, 0x27, 0x36, 0x32, 0xe8, 0x87, 0x2d, 0x35, 0xbd, 0xc3,
                  0x67, 0xa1, 0x36, 0x34, 0x38, 0x23, 0x9a, 0x35},
                 {0x03, 0x65, 0x88, 0x2c, 0xf7, 0x54, 0x32, 0xcf, 0xd2, 0x3c, 0xbd, 0x42},
                 {0xff, 0xf3, 0x9a, 0x08, 0x7d, 0xe3, 0x9a, 0x03, 0x91, 0x9f, 0xbd, 0x2f,
                  0x2f, 0xa5, 0xf5, 0x13},
                 {0x8a, 0x97, 0xd2, 0xaf, 0x5d, 0x41, 0x16, 0x0a, 0xc2, 0xff, 0x7d, 0xd8,
                  0xba, 0x09, 0x8e, 0x7a, 0xa4, 0xd6, 0x18, 0xf0, 0xf4, 0x55, 0x95, 0x7d,
                  0x6a, 0x6d, 0x08, 0x01, 0x79, 0x67, 0x47, 0xba, 0x57, 0xc3, 0x2d, 0xfb,
                  0xaa, 0xaf, 0x15, 0x17, 0x65, 0x28, 0xfe, 0x3a, 0x0e, 0x45, 0x50, 0xc9},
                 {0x8d, 0x9e, 0x68, 0xf0, 0x3f, 0x7e, 0x5f, 0x4a, 0x0f, 0xfa, 0xa7, 0x65,
                  0x0d, 0x02, 0x6d, 0x08},
                 {0x35, 0x54, 0x54, 0x2c, 0x47, 0x8c, 0x06, 0x35, 0x28, 0x5a, 0x61, 0xd1,
                  0xb5, 0x1f, 0x6a, 0xfa}},
      TestVector{{0x80, 0xd7, 0x55, 0xe2, 0x4d, 0x12, 0x9e, 0x68, 0xa5, 0x25, 0x9e, 0xc2,
                  0xcf, 0x61, 0x8e, 0x39, 0x31, 0x70, 0x74, 0xa8, 0x3c, 0x89, 0x61, 0xd3,
                  0x76, 0x8c, 0xeb, 0x2e, 0xd8, 0xd5, 0xc3, 0xd7},
                 {0x75, 0x98, 0xc0, 0x7b, 0xa7, 0xb1, 0x6c, 0xd1, 0x2c, 0xf5, 0x08, 0x13},
                 {0x5e, 0x7f, 0xd1, 0x29, 0x8c, 0x4f, 0x15, 0xaa, 0x0f, 0x1c, 0x1e, 0x47,
                  0x21, 0x7a, 0xa7, 0xa9},
                 {0x0e, 0x94, 0xf4, 0xc4, 0x8f, 0xd0, 0xc9, 0x69, 0x0c, 0x85, 0x3a, 0xd2,
                  0xa5, 0xe1, 0x97, 0xc5, 0xde, 0x26, 0x21, 0x37, 0xb6, 0x9e, 0xd0, 0xcd,
                  0xfa, 0x28, 0xd8, 0xd1, 0x24, 0x13, 0xe4, 0xff, 0xff, 0x15, 0x37, 0x4e,
                  0x1c, 0xcc, 0xb0, 0x42, 0x3e, 0x8e, 0xd8, 0x29, 0xa9, 0x54, 0xa3, 0x35,
                  0xed, 0x70, 0x5a, 0x27, 0x2a, 0xd7, 0xf9, 0xab, 0xd1, 0x05, 0x7c, 0x84,
                  0x9b, 0xb0, 0xd5, 0x4b, 0x76, 0x8e, 0x9d, 0x79, 0x87, 0x9e, 0xc5, 0x52,
                  0x46, 0x1c, 0xc0, 0x4a, 0xdb, 0x6c, 0xa0, 0x04, 0x0c, 0x5d, 0xd5, 0xbc,
                  0x73, 0x3d, 0x21, 0xa9, 0x37, 0x02},
                 {0x57, 0x62, 0xa3, 0x8c, 0xf3, 0xf2, 0xfd, 0xf3, 0x64, 0x5d, 0x2f, 0x66,
                  0x96, 0xa7, 0xee, 0xad},
                 {0x8a, 0x67, 0x08, 0xe6, 0x94, 0x68, 0x91, 0x5c, 0x53, 0x67, 0x57, 0x39,
                  0x24, 0xfe, 0x1a, 0xe3}}};

  auto constant_time_equal = [](std::span<const uint8_t> lhs,
                                std::span<const uint8_t> rhs) noexcept {
    if (lhs.size() != rhs.size()) {
      return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < lhs.size(); ++i) {
      diff |= static_cast<uint8_t>(lhs[i] ^ rhs[i]);
    }
    return diff == 0;
  };

  OpenSSLCryptoProvider provider;
  for (size_t index = 0; index < kVectors.size(); ++index) {
    const auto& tv = kVectors[index];
    const auto enc = provider.EncryptAES256GCM(
        std::span<const uint8_t>(tv.plaintext.data(), tv.plaintext.size()),
        std::span<const uint8_t>(tv.aad.data(), tv.aad.size()),
        std::span<const uint8_t, AES256_GCM::NONCE_SIZE>(tv.nonce),
        std::span<const uint8_t, AES256_GCM::KEY_SIZE>(tv.key));

    if (!constant_time_equal(std::span<const uint8_t>(enc.ciphertext.data(), enc.ciphertext.size()),
                             std::span<const uint8_t>(tv.ciphertext.data(), tv.ciphertext.size()))) {
      ThrowCryptoError("AES-GCM KAT ciphertext mismatch #" + std::to_string(index));
    }
    if (!qv::crypto::ct::CompareEqual(enc.tag, tv.tag)) {
      ThrowCryptoError("AES-GCM KAT tag mismatch #" + std::to_string(index));
    }

    const auto dec = provider.DecryptAES256GCM(
        std::span<const uint8_t>(tv.ciphertext.data(), tv.ciphertext.size()),
        std::span<const uint8_t>(tv.aad.data(), tv.aad.size()),
        std::span<const uint8_t, AES256_GCM::NONCE_SIZE>(tv.nonce),
        std::span<const uint8_t, AES256_GCM::TAG_SIZE>(tv.tag),
        std::span<const uint8_t, AES256_GCM::KEY_SIZE>(tv.key));

    if (!constant_time_equal(std::span<const uint8_t>(dec.data(), dec.size()),
                             std::span<const uint8_t>(tv.plaintext.data(), tv.plaintext.size()))) {
      ThrowCryptoError("AES-GCM KAT decrypt mismatch #" + std::to_string(index));
    }

    if (!tv.ciphertext.empty()) {
      auto tampered_ct = tv.ciphertext;
      tampered_ct.front() ^= 0x01;
      try {
        (void)provider.DecryptAES256GCM(
            std::span<const uint8_t>(tampered_ct.data(), tampered_ct.size()),
            std::span<const uint8_t>(tv.aad.data(), tv.aad.size()),
            std::span<const uint8_t, AES256_GCM::NONCE_SIZE>(tv.nonce),
            std::span<const uint8_t, AES256_GCM::TAG_SIZE>(tv.tag),
            std::span<const uint8_t, AES256_GCM::KEY_SIZE>(tv.key));
        ThrowCryptoError("AES-GCM tamper (ciphertext) undetected #" + std::to_string(index));
      } catch (const qv::AuthenticationFailureError&) {
        // Expected failure
      }
    }

    auto tampered_tag = tv.tag;
    tampered_tag.front() ^= 0x01;
    try {
      (void)provider.DecryptAES256GCM(
          std::span<const uint8_t>(tv.ciphertext.data(), tv.ciphertext.size()),
          std::span<const uint8_t>(tv.aad.data(), tv.aad.size()),
          std::span<const uint8_t, AES256_GCM::NONCE_SIZE>(tv.nonce),
          std::span<const uint8_t, AES256_GCM::TAG_SIZE>(tampered_tag),
          std::span<const uint8_t, AES256_GCM::KEY_SIZE>(tv.key));
      ThrowCryptoError("AES-GCM tamper (tag) undetected #" + std::to_string(index));
    } catch (const qv::AuthenticationFailureError&) {
      // Expected failure
    }
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

