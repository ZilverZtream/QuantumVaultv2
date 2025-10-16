#include "qv/orchestrator/sealed_key.h"

#include <algorithm>
#include <mutex>

// TSK713_TPM_SecureEnclave_Key_Sealing registry implementation

namespace qv::orchestrator {

SealedKeyRegistry& SealedKeyRegistry::Instance() noexcept {
  static SealedKeyRegistry registry;
  return registry;
}

void SealedKeyRegistry::RegisterProvider(SealedKeyProviderPtr provider) {
  if (!provider) {
    return;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  auto id = std::string(provider->Id());
  auto it = std::find_if(providers_.begin(), providers_.end(),
                         [&id](const SealedKeyProviderPtr& existing) {
                           return existing && existing->Id() == id;
                         });
  if (it != providers_.end()) {
    *it = std::move(provider);
    return;
  }
  providers_.push_back(std::move(provider));
}

SealedKeyProvider* SealedKeyRegistry::FindProvider(std::string_view id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& provider : providers_) {
    if (provider && provider->Id() == id) {
      return provider.get();
    }
  }
  return nullptr;
}

std::vector<std::string> SealedKeyRegistry::ProviderIds() const {
  std::vector<std::string> ids;
  std::lock_guard<std::mutex> lock(mutex_);
  ids.reserve(providers_.size());
  for (const auto& provider : providers_) {
    if (provider) {
      ids.emplace_back(provider->Id());
    }
  }
  return ids;
}

}  // namespace qv::orchestrator
