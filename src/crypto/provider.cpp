#include "qv/crypto/provider.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

#include "qv/error.h"

namespace qv::crypto {

namespace {

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

std::mutex& ProviderMutex() {
  static std::mutex mutex;
  return mutex;
}

std::shared_ptr<CryptoProvider>& ProviderInstance() {
  static std::shared_ptr<CryptoProvider> instance;
  return instance;
}

void ThrowCryptoError(const std::string& message, int code = 0) {
  throw qv::Error(qv::ErrorDomain::Crypto, code, message);
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

