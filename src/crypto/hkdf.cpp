#include "qv/crypto/hkdf.h"

#include <memory>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "qv/error.h"

namespace qv::crypto {

std::array<uint8_t, 32> HKDF_SHA256(std::span<const uint8_t> ikm,
                                    std::span<const uint8_t> salt,
                                    std::span<const uint8_t> info) { // TSK106_Cryptographic_Implementation_Weaknesses
  std::array<uint8_t, 32> out{};
  EVP_PKEY_CTX* raw_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!raw_ctx) {
    throw Error(ErrorDomain::Crypto, -1, "EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF) failed");
  }
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(raw_ctx, &EVP_PKEY_CTX_free);

  auto check = [](int status, const char* step) {
    if (status <= 0) {
      throw Error(ErrorDomain::Crypto, -1, std::string("HKDF step failed: ") + step);
    }
  };

  check(EVP_PKEY_derive_init(ctx.get()), "derive_init");
  check(EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()), "set_md");
  check(EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.empty() ? nullptr : salt.data(),
                                     static_cast<int>(salt.size())), "set_salt");
  check(EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm.data(), static_cast<int>(ikm.size())),
        "set_key");
  if (!info.empty()) {
    check(EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), static_cast<int>(info.size())),
          "set_info");
  }
  size_t len = out.size();
  check(EVP_PKEY_derive(ctx.get(), out.data(), &len), "derive");
  if (len != out.size()) {
    throw Error(ErrorDomain::Crypto, -1, "HKDF derive produced unexpected length");
  }
  return out;
}

}  // namespace qv::crypto
