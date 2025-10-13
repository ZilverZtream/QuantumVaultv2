#pragma once
#include <array>
#include <chrono>
#include <filesystem>
#include <optional>
#include <vector>
#include "qv/error.h"

namespace qv::orchestrator {

class ConstantTimeMount {
public:
  struct VolumeHandle { int dummy{0}; };
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
  void LogTiming(const Attempt& a, const Attempt& b);
};

} // namespace qv::orchestrator
