#pragma once

// TSK715_Header_Integrity_Chain_and_qv-fsck metadata integrity interfaces

#include <array>
#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

#include "qv/core/header.h"

namespace qv::core {

constexpr size_t kMetadataIntegrityLeafSize = 4096; // TSK715_Header_Integrity_Chain_and_qv-fsck fixed leaf size

struct MetadataPageView { // TSK715_Header_Integrity_Chain_and_qv-fsck leaf descriptor
  std::span<const uint8_t> bytes;
  std::string_view label;
};

struct IntegrityCheckResult { // TSK715_Header_Integrity_Chain_and_qv-fsck verification status
  bool ok{false};
  IntegrityRoot computed{};
  size_t failing_leaf{static_cast<size_t>(-1)};
};

IntegrityRoot ComputeMetadataIntegrityRoot( // TSK715_Header_Integrity_Chain_and_qv-fsck Merkle builder
    uint64_t generation, std::span<const MetadataPageView> pages, bool with_parity);

IntegrityCheckResult VerifyMetadataIntegrity( // TSK715_Header_Integrity_Chain_and_qv-fsck root verification
    const IntegrityRoot& expected, std::span<const MetadataPageView> pages);

std::vector<std::array<uint8_t, 32>> ComputeMetadataLeafHashes( // TSK715_Header_Integrity_Chain_and_qv-fsck exposed for tests
    std::span<const MetadataPageView> pages);

}  // namespace qv::core

