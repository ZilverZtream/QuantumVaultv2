#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace qv::security {

class Zeroizer {
public:
  // TSK006
  static void Wipe(std::span<uint8_t> data) noexcept;

  // TSK006
  static bool MemoryLockingSupported() noexcept;

  enum class LockStatus { // TSK085
    Locked,
    BestEffort,
    Unsupported,
  };

  static LockStatus TryLockMemory(std::span<uint8_t> data) noexcept; // TSK085

  // TSK006, TSK085
  static void UnlockMemory(std::span<uint8_t> data) noexcept;

  template <typename T>
  static void WipeVector(std::vector<T>& vec) noexcept { // TSK006
    if (vec.empty()) {
      return;
    }
    const std::size_t bytes = vec.size() * sizeof(T);
    auto byte_span = std::span<uint8_t>(reinterpret_cast<uint8_t*>(vec.data()), bytes);
    Wipe(byte_span);
  }

  template <typename T>
  class ScopeWiper { // TSK006
  public:
    explicit ScopeWiper(std::span<T> span) noexcept : span_(span) {}
    ScopeWiper(T* ptr, std::size_t count) noexcept : ScopeWiper(std::span<T>(ptr, count)) {}

    ScopeWiper(const ScopeWiper&) = delete;
    ScopeWiper& operator=(const ScopeWiper&) = delete;

    ScopeWiper(ScopeWiper&&) = delete;
    ScopeWiper& operator=(ScopeWiper&&) = delete;

    ~ScopeWiper() noexcept {
      if (span_.empty()) {
        return;
      }
      const std::size_t bytes = span_.size_bytes();
      auto byte_span = std::span<uint8_t>(reinterpret_cast<uint8_t*>(span_.data()), bytes);
      Zeroizer::Wipe(byte_span);
    }

  private:
    std::span<T> span_;
  };
};

} // namespace qv::security
