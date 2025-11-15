#pragma once
#include <array>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <vector>
#include "qv/error.h"
#include "qv/storage/chunk_layout.h" // TSK710_Implement_Hidden_Volumes propagate extent map

namespace qv::storage {
class BlockDevice;
}

namespace qv::orchestrator {

class ConstantTimeMount {
public:
  struct VolumeHandle {
    int dummy{0};
    std::shared_ptr<qv::storage::BlockDevice> device;
    std::vector<qv::storage::Extent> protected_extents; // TSK710_Implement_Hidden_Volumes optional guard map
    bool hidden_mode{false};                             // TSK710_Implement_Hidden_Volumes mount selection
    bool decoy_guard{false};                             // TSK710_Implement_Hidden_Volumes outer guard flag
    std::optional<qv::storage::Extent>
        hidden_region; // TSK710_Implement_Hidden_Volumes hidden payload bounds
  };
  std::optional<VolumeHandle> Mount(const std::filesystem::path& container,
                                    const std::string& password);
private:
  // TSK004
  struct Attempt {
    std::chrono::steady_clock::time_point start;
    std::chrono::nanoseconds duration{};
    std::chrono::nanoseconds pad{};
  };
  void ConstantTimePadding(std::chrono::nanoseconds duration);
  std::optional<VolumeHandle> AttemptMount(const std::filesystem::path& container,
                                           const std::string& password);
  void LogTiming(const Attempt& attempt);
};

} // namespace qv::orchestrator
