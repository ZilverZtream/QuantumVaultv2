#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// TSK713_TPM_SecureEnclave_Key_Sealing sealed key abstractions

namespace qv::orchestrator {

struct SealRequest final { // TSK713_TPM_SecureEnclave_Key_Sealing describe sealing inputs
  std::span<const uint8_t> key;
  std::vector<uint8_t> policy_tlv;
  uint32_t policy_mask = 0;
  std::string label;
};

struct SealedKey final { // TSK713_TPM_SecureEnclave_Key_Sealing sealed payload descriptor
  std::string provider_id;
  std::vector<uint8_t> blob;
  std::vector<uint8_t> policy_tlv;
  uint32_t policy_mask = 0;
};

class SealedKeyProvider { // TSK713_TPM_SecureEnclave_Key_Sealing provider interface
 public:
  virtual ~SealedKeyProvider() = default;
  virtual std::string_view Id() const noexcept = 0;
  virtual std::string_view Description() const noexcept = 0;
  virtual bool IsAvailable() const noexcept = 0;
  virtual SealedKey Seal(const SealRequest& request) = 0;
  virtual std::vector<uint8_t> Unseal(const SealedKey& sealed) = 0;
};

using SealedKeyProviderPtr = std::unique_ptr<SealedKeyProvider>;

class SealedKeyRegistry { // TSK713_TPM_SecureEnclave_Key_Sealing provider registry
 public:
  static SealedKeyRegistry& Instance() noexcept;

  void RegisterProvider(SealedKeyProviderPtr provider);
  SealedKeyProvider* FindProvider(std::string_view id) const;
  std::vector<std::string> ProviderIds() const;

 private:
  SealedKeyRegistry() = default;
  SealedKeyRegistry(const SealedKeyRegistry&) = delete;
  SealedKeyRegistry& operator=(const SealedKeyRegistry&) = delete;

  mutable std::mutex mutex_;
  std::vector<SealedKeyProviderPtr> providers_;
};

}  // namespace qv::orchestrator
