#pragma once
#include <optional>
#include <chrono>
#include <filesystem>
#include <vector>
#include "qv/error.h"

namespace qv::orchestrator {

class ConstantTimeMount {
public:
  struct VolumeHandle { int dummy{0}; };
  std::optional<VolumeHandle> Mount(const std::filesystem::path& container,
                                    const std::string& password);
private:
  struct Attempt {
    std::chrono::steady_clock::time_point start;
    std::chrono::nanoseconds duration{};
  };
  void ConstantTimePadding(std::chrono::nanoseconds duration);
  std::optional<VolumeHandle> AttemptMount(const std::filesystem::path& container,
                                           const std::string& password);
  void LogTiming(const Attempt& a, const Attempt& b);
};

} // namespace qv::orchestrator
