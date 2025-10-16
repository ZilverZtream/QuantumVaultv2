#include "qv/orchestrator/plugin_abi.h"
#include "qv/orchestrator/sealed_key.h"

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

// TSK713_TPM_SecureEnclave_Key_Sealing TPM2 provider plugin (stubbed for skeleton)

namespace {

class StubTpmProvider final : public qv::orchestrator::SealedKeyProvider { // TSK713_TPM_SecureEnclave_Key_Sealing stub
 public:
  std::string_view Id() const noexcept override { return "tpm2"; }
  std::string_view Description() const noexcept override {
    return "TPM 2.0 sealed key provider (stub)";
  }
  bool IsAvailable() const noexcept override {
#if defined(QV_USE_STUB_CRYPTO) && QV_USE_STUB_CRYPTO
    return true;
#else
    return false;
#endif
  }

  qv::orchestrator::SealedKey Seal(const qv::orchestrator::SealRequest& request) override {
#if defined(QV_USE_STUB_CRYPTO) && QV_USE_STUB_CRYPTO
    qv::orchestrator::SealedKey sealed{};
    sealed.provider_id = std::string(Id());
    sealed.policy_mask = request.policy_mask;
    sealed.policy_tlv = request.policy_tlv;
    sealed.blob.assign(request.key.begin(), request.key.end());
    return sealed;
#else
    throw std::runtime_error("TPM provider not implemented in skeleton build");
#endif
  }

  std::vector<uint8_t> Unseal(const qv::orchestrator::SealedKey& sealed) override {
#if defined(QV_USE_STUB_CRYPTO) && QV_USE_STUB_CRYPTO
    return sealed.blob;
#else
    throw std::runtime_error("TPM provider not implemented in skeleton build");
#endif
  }
};

StubTpmProvider g_stub_provider;  // global used for discovery

}  // namespace

extern "C" QV_PLUGIN_EXPORT qv::orchestrator::SealedKeyProvider* qv_tpm2_provider() {
  return &g_stub_provider;
}

