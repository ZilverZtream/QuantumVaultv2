#include "qv/platform/sealed_key_registration.h"

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>

#include <memory>
#include <string>
#include <vector>

#include "qv/orchestrator/sealed_key.h"
#include "qv/error.h"
#include "qv/errors.h"

// TSK713_TPM_SecureEnclave_Key_Sealing Windows DPAPI provider

namespace {

constexpr int kSealedKeyProviderError =
    qv::errors::Make(qv::ErrorDomain::Security, 0x50); // TSK713_TPM_SecureEnclave_Key_Sealing error code

class DpapiSealedKeyProvider final : public qv::orchestrator::SealedKeyProvider { // TSK713_TPM_SecureEnclave_Key_Sealing DPAPI wiring
 public:
  std::string_view Id() const noexcept override { return "dpapi"; }
  std::string_view Description() const noexcept override {
    return "Windows DPAPI user-bound key sealing";
  }
  bool IsAvailable() const noexcept override { return true; }

  qv::orchestrator::SealedKey Seal(const qv::orchestrator::SealRequest& request) override {
    DATA_BLOB input{static_cast<DWORD>(request.key.size()),
                    const_cast<BYTE*>(request.key.data())};
    DATA_BLOB output{};
    if (!CryptProtectData(&input, L"QuantumVault", nullptr, nullptr, nullptr, 0, &output)) {
      throw qv::Error{qv::ErrorDomain::Security, kSealedKeyProviderError,
                      "CryptProtectData failed", static_cast<int>(GetLastError())};
    }
    qv::orchestrator::SealedKey sealed{};
    sealed.provider_id = std::string(Id());
    sealed.blob.assign(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    sealed.policy_tlv = request.policy_tlv;
    sealed.policy_mask = request.policy_mask;
    return sealed;
  }

  std::vector<uint8_t> Unseal(const qv::orchestrator::SealedKey& sealed) override {
    DATA_BLOB input{static_cast<DWORD>(sealed.blob.size()),
                    const_cast<BYTE*>(sealed.blob.data())};
    DATA_BLOB output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
      throw qv::Error{qv::ErrorDomain::Security, kSealedKeyProviderError,
                      "CryptUnprotectData failed", static_cast<int>(GetLastError())};
    }
    std::vector<uint8_t> plaintext(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return plaintext;
  }
};

}  // namespace

namespace qv::platform {

void RegisterPlatformSealedKeyProviders(qv::orchestrator::SealedKeyRegistry& registry) {
  registry.RegisterProvider(std::make_unique<DpapiSealedKeyProvider>());
}

}  // namespace qv::platform

#else

namespace qv::platform {

void RegisterPlatformSealedKeyProviders(qv::orchestrator::SealedKeyRegistry&) {}

}  // namespace qv::platform

#endif
