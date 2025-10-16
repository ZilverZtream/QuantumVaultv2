#include "qv/platform/sealed_key_registration.h"

#if defined(__APPLE__)
#include <Security/Security.h>

#include <memory>
#include <string>
#include <vector>

#include "qv/orchestrator/sealed_key.h"
#include "qv/error.h"
#include "qv/errors.h"

// TSK713_TPM_SecureEnclave_Key_Sealing macOS Secure Enclave provider (Keychain wrapper)

constexpr int kSecureEnclaveProviderError =
    qv::errors::Make(qv::ErrorDomain::Security, 0x51); // TSK713_TPM_SecureEnclave_Key_Sealing error code

namespace {

class KeychainSealedKeyProvider final : public qv::orchestrator::SealedKeyProvider { // TSK713_TPM_SecureEnclave_Key_Sealing macOS
 public:
  std::string_view Id() const noexcept override { return "se"; }
  std::string_view Description() const noexcept override {
    return "macOS Keychain/Secure Enclave sealing";
  }
  bool IsAvailable() const noexcept override { return true; }

  qv::orchestrator::SealedKey Seal(const qv::orchestrator::SealRequest& request) override {
    if (request.key.empty()) {
      return {std::string(Id()), {}, request.policy_tlv, request.policy_mask};
    }
    CFDataRef data = CFDataCreate(nullptr, request.key.data(), request.key.size());
    if (!data) {
      throw qv::Error{qv::ErrorDomain::Security, kSecureEnclaveProviderError, "CFDataCreate failed"};
    }
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        nullptr, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlPrivateKeyUsage, nullptr);
    if (!access) {
      CFRelease(data);
      throw qv::Error{qv::ErrorDomain::Security, kSecureEnclaveProviderError,
                      "SecAccessControlCreateWithFlags failed"};
    }
    const void* keys[] = {kSecClass, kSecAttrLabel, kSecValueData, kSecAttrAccessControl};
    const void* values[] = {kSecClassGenericPassword, CFSTR("QuantumVault"), data, access};
    CFDictionaryRef dict = CFDictionaryCreate(nullptr, keys, values, 4, &kCFTypeDictionaryKeyCallBacks,
                                              &kCFTypeDictionaryValueCallBacks);
    if (!dict) {
      CFRelease(access);
      CFRelease(data);
      throw qv::Error{qv::ErrorDomain::Security, kSecureEnclaveProviderError,
                      "CFDictionaryCreate failed"};
    }
    OSStatus status = SecItemAdd(dict, nullptr);
    CFRelease(dict);
    CFRelease(access);
    CFRelease(data);
    if (status != errSecSuccess && status != errSecDuplicateItem) {
      throw qv::Error{qv::ErrorDomain::Security, kSecureEnclaveProviderError, "SecItemAdd failed"};
    }
    qv::orchestrator::SealedKey sealed{};
    sealed.provider_id = std::string(Id());
    sealed.policy_tlv = request.policy_tlv;
    sealed.policy_mask = request.policy_mask;
    // Store label as blob for retrieval
    sealed.blob.assign(request.label.begin(), request.label.end());
    return sealed;
  }

  std::vector<uint8_t> Unseal(const qv::orchestrator::SealedKey& sealed) override {
    std::string label(sealed.blob.begin(), sealed.blob.end());
    if (label.empty()) {
      label = "QuantumVault";
    }
    CFStringRef cf_label = CFStringCreateWithCString(nullptr, label.c_str(), kCFStringEncodingUTF8);
    const void* keys[] = {kSecClass, kSecAttrLabel, kSecReturnData};
    const void* values[] = {kSecClassGenericPassword, cf_label, kCFBooleanTrue};
    CFDictionaryRef query = CFDictionaryCreate(nullptr, keys, values, 3, &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFRelease(cf_label);
    if (!query) {
      throw qv::Error{qv::ErrorDomain::Security, kSecureEnclaveProviderError,
                      "CFDictionaryCreate failed"};
    }
    CFTypeRef result = nullptr;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status != errSecSuccess) {
      throw qv::Error{qv::ErrorDomain::Security, kSecureEnclaveProviderError,
                      "SecItemCopyMatching failed"};
    }
    CFDataRef data = reinterpret_cast<CFDataRef>(result);
    std::vector<uint8_t> plaintext(CFDataGetBytePtr(data), CFDataGetBytePtr(data) + CFDataGetLength(data));
    CFRelease(result);
    return plaintext;
  }
};

}  // namespace

namespace qv::platform {

void RegisterPlatformSealedKeyProviders(qv::orchestrator::SealedKeyRegistry& registry) {
  registry.RegisterProvider(std::make_unique<KeychainSealedKeyProvider>());
}

}  // namespace qv::platform

#else

namespace qv::platform {

void RegisterPlatformSealedKeyProviders(qv::orchestrator::SealedKeyRegistry&) {}

}  // namespace qv::platform

#endif
