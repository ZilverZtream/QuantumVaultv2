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
#include "qv/orchestrator/plugin_abi.h"

namespace qv::orchestrator {
// TSK005 embeds a minimal policy/primitives so orchestration can enforce plugin
// integrity across platforms.
// TSK011 extends trust policy with ABI negotiation details.
struct PluginCompatibilityRange {
  uint32_t min_version{QV_PLUGIN_ABI_VERSION};
  uint32_t max_version{QV_PLUGIN_ABI_VERSION};
};

struct PluginTrustPolicy {
  std::vector<std::array<uint8_t, 32>> root_public_keys;
  std::unordered_map<std::string, std::array<uint8_t, 32>> pinned_public_keys;
  bool require_signature{true};
  bool allow_hash_fallback{false};
  PluginCompatibilityRange default_abi_range{};
  std::unordered_map<std::string, PluginCompatibilityRange> plugin_abi_ranges;
  uint32_t capability_schema_version{QV_PLUGIN_CAPABILITY_SCHEMA_VERSION};
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

struct PluginAbiQueryResult {
  uint32_t plugin_min{0};
  uint32_t plugin_max{0};
  bool has_selftest{false};
  bool selftest_passed{false};
};

bool VerifyPlugin(const std::filesystem::path& path, const PluginVerification& expected);
bool HasSecurityFlags(const std::filesystem::path& path);
std::optional<PluginAbiQueryResult> QueryPluginABI(const std::filesystem::path& path);
bool Ed25519_Verify(std::span<const uint8_t,32> pubkey,
                    std::span<const uint8_t,32> msg_hash,
                    std::span<const uint8_t,64> signature);
bool VerifyPlatformSignature(const std::filesystem::path& path);
} // namespace qv::orchestrator
