#pragma once
#include <span>
#include <cstring>
#include <atomic>

namespace qv::security {
class Zeroizer {
public:
  static void Wipe(std::span<uint8_t> data) noexcept {
    if (data.empty()) return;
    // v4.1: Simplified to single, explicit wipe to avoid "zeroization theater".
#if defined(_WIN32)
    SecureZeroMemory(data.data(), data.size());
#else
    explicit_bzero(data.data(), data.size());
#endif
    std::atomic_signal_fence(std::memory_order_seq_cst);
  }
};
} // namespace qv::security
