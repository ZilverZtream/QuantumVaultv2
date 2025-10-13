#pragma once
#include <array>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>
#include "qv/crypto/ct.h"
#include "qv/crypto/sha256.h"

namespace qv::orchestrator {
// TSK005 embeds a minimal policy/primitives so orchestration can enforce plugin
// integrity across platforms.
struct PluginTrustPolicy {
  std::vector<std::array<uint8_t, 32>> root_public_keys;
  std::unordered_map<std::string, std::array<uint8_t, 32>> pinned_public_keys;
  bool require_signature{true};
  bool allow_hash_fallback{false};
};

struct PluginVerification {
  std::array<uint8_t, 32> expected_hash{};
  std::array<uint8_t, 64> signature{};
  std::array<uint8_t, 32> public_key{};
  uint32_t min_abi_version{1};
  uint32_t max_abi_version{1};
#if defined(NDEBUG)
  bool enforce_signature{true};
#else
  bool enforce_signature{false};
#endif
  std::string plugin_id;
  const PluginTrustPolicy* trust_policy{nullptr};
  bool allow_hash_fallback{false};
};

const PluginTrustPolicy& DefaultPluginTrustPolicy();
PluginTrustPolicy LoadPluginTrustPolicy(const std::filesystem::path& policy_path);

bool VerifyPlugin(const std::filesystem::path& path, const PluginVerification& expected);
bool HasSecurityFlags(const std::filesystem::path& path);
uint32_t QueryPluginABI(const std::filesystem::path& path);
bool Ed25519_Verify(std::span<const uint8_t,32> pubkey,
                    std::span<const uint8_t,32> msg_hash,
                    std::span<const uint8_t,64> signature);
bool VerifyPlatformSignature(const std::filesystem::path& path);
} // namespace qv::orchestrator
