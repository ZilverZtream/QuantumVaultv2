#pragma once
#include <array>
#include <filesystem>
#include <vector>
#include "qv/crypto/sha256.h"
#include "qv/crypto/ct.h"

namespace qv::orchestrator {
struct PluginVerification {
  std::array<uint8_t,32> expected_hash{};
  std::array<uint8_t,64> signature{};   // Ed25519 (stub)
  std::array<uint8_t,32> public_key{};  // Ed25519 (stub)
  uint32_t min_abi_version{1};
  uint32_t max_abi_version{1};
  bool enforce_signature{false};        // default false in skeleton
};

bool VerifyPlugin(const std::filesystem::path& path, const PluginVerification& expected);
bool HasSecurityFlags(const std::filesystem::path& path); // STUB
uint32_t QueryPluginABI(const std::filesystem::path& path); // STUB
bool Ed25519_Verify(std::span<const uint8_t,32> pubkey,
                    std::span<const uint8_t,32> msg_hash,
                    std::span<const uint8_t,64> signature); // STUB
} // namespace qv::orchestrator
