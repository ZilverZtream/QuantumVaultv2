#include "qv/core/integrity.h"

// TSK715_Header_Integrity_Chain_and_qv-fsck metadata integrity implementation

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "qv/crypto/sha256.h"

namespace qv::core {
namespace {

std::array<uint8_t, 32> HashLeaf(std::span<const uint8_t> bytes) { // TSK715_Header_Integrity_Chain_and_qv-fsck padded leaf hash
  if (bytes.size() > kMetadataIntegrityLeafSize) {
    throw std::invalid_argument("metadata page larger than leaf size");
  }
  std::array<uint8_t, kMetadataIntegrityLeafSize> scratch{};
  if (!bytes.empty()) {
    std::memcpy(scratch.data(), bytes.data(), bytes.size());
  }
  return qv::crypto::SHA256_Hash(
      std::span<const uint8_t>(scratch.data(), scratch.size()));
}

std::array<uint8_t, 32> HashNode(const std::array<uint8_t, 32>& left,
                                 const std::array<uint8_t, 32>& right) { // TSK715_Header_Integrity_Chain_and_qv-fsck node hash
  std::array<uint8_t, 64> buffer{};
  std::memcpy(buffer.data(), left.data(), left.size());
  std::memcpy(buffer.data() + left.size(), right.data(), right.size());
  return qv::crypto::SHA256_Hash(
      std::span<const uint8_t>(buffer.data(), buffer.size()));
}

}  // namespace

std::vector<std::array<uint8_t, 32>> ComputeMetadataLeafHashes(
    std::span<const MetadataPageView> pages) { // TSK715_Header_Integrity_Chain_and_qv-fsck exported leaf builder
  std::vector<std::array<uint8_t, 32>> leaves;
  leaves.reserve(pages.size());
  for (const auto& page : pages) {
    leaves.push_back(HashLeaf(page.bytes));
  }
  if (leaves.empty()) {
    leaves.push_back(HashLeaf(std::span<const uint8_t>()));
  }
  return leaves;
}

IntegrityRoot ComputeMetadataIntegrityRoot(
    uint64_t generation, std::span<const MetadataPageView> pages,
    bool with_parity) { // TSK715_Header_Integrity_Chain_and_qv-fsck compute tree
  IntegrityRoot root{};
  root.generation = generation;

  auto level = ComputeMetadataLeafHashes(pages);
  std::array<uint8_t, 32> parity{};
  if (with_parity) {
    for (const auto& leaf : level) {
      for (size_t i = 0; i < parity.size(); ++i) {
        parity[i] ^= leaf[i];
      }
    }
    root.parity = parity;
    root.parity_valid = true;
  }

  while (level.size() > 1) {
    if (level.size() % 2 != 0) {
      level.push_back(level.back());
    }
    std::vector<std::array<uint8_t, 32>> next;
    next.reserve(level.size() / 2);
    for (size_t i = 0; i < level.size(); i += 2) {
      next.push_back(HashNode(level[i], level[i + 1]));
    }
    level.swap(next);
  }

  root.merkle_root = level.front();
  return root;
}

IntegrityCheckResult VerifyMetadataIntegrity(
    const IntegrityRoot& expected,
    std::span<const MetadataPageView> pages) { // TSK715_Header_Integrity_Chain_and_qv-fsck verification routine
  IntegrityCheckResult result{};
  result.computed = ComputeMetadataIntegrityRoot(expected.generation, pages,
                                                 expected.parity_valid);
  const bool root_match = std::equal(result.computed.merkle_root.begin(),
                                     result.computed.merkle_root.end(),
                                     expected.merkle_root.begin(),
                                     expected.merkle_root.end());
  bool parity_match = true;
  if (expected.parity_valid) {
    parity_match = std::equal(result.computed.parity.begin(),
                              result.computed.parity.end(),
                              expected.parity.begin(),
                              expected.parity.end());
  }
  result.ok = root_match && parity_match;
  if (!result.ok) {
    auto leaves = ComputeMetadataLeafHashes(pages);
    if (!leaves.empty()) {
      result.failing_leaf = 0;
    }
  }
  return result;
}

}  // namespace qv::core

