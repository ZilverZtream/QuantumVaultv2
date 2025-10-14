#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>

#include "qv/error.h"

namespace qv::orchestrator {

struct AtomicReplaceHooks { // TSK068_Atomic_Header_Writes provide test seam for crash simulation
  std::function<void(const std::filesystem::path&, const std::filesystem::path&)> before_rename;
};

// Performs an atomic replace of the target file by writing the payload to a
// temporary file on the same filesystem, syncing it to disk, then renaming it
// into place. // TSK068_Atomic_Header_Writes durability helper
void AtomicReplace(const std::filesystem::path& target, std::span<const uint8_t> payload,
                   const AtomicReplaceHooks& hooks = {});

}  // namespace qv::orchestrator
