#include "qv/orchestrator/plugin_verification.h"
#include <fstream>

using namespace qv::orchestrator;
using namespace qv::crypto;
using qv::crypto::ct::CompareEqual;

bool VerifyPlugin(const std::filesystem::path& path, const PluginVerification& expected) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  f.seekg(0, std::ios::end);
  size_t sz = (size_t)f.tellg();
  f.seekg(0, std::ios::beg);
  std::vector<uint8_t> data(sz);
  f.read(reinterpret_cast<char*>(data.data()), sz);
  auto hash = SHA256_Hash(data);
  if (!CompareEqual<32>(hash, expected.expected_hash)) return false;
  if (expected.enforce_signature) {
    if (!Ed25519_Verify(expected.public_key, hash, expected.signature)) return false;
  }
  auto abi = QueryPluginABI(path);
  if (abi < expected.min_abi_version || abi > expected.max_abi_version) return false;
  if (!HasSecurityFlags(path)) return false;
  return true;
}

bool HasSecurityFlags(const std::filesystem::path& path) {
  (void)path;
  // STUB: always true
  return true;
}
uint32_t QueryPluginABI(const std::filesystem::path& path) {
  (void)path;
  return 1; // Skeleton ABI version
}
bool Ed25519_Verify(std::span<const uint8_t,32> pubkey,
                    std::span<const uint8_t,32> msg_hash,
                    std::span<const uint8_t,64> signature) {
  (void)pubkey;(void)msg_hash;(void)signature;
  // STUB: always true.
  return true;
}
