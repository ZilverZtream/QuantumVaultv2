#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <atomic>

namespace qv::crypto::ct {

template<size_t N>
inline bool CompareEqual(const std::array<uint8_t, N>& a,
                         const std::array<uint8_t, N>& b) noexcept {
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < N; ++i) diff |= (a[i] ^ b[i]);
  return diff == 0;
}

template<typename T>
  requires std::is_unsigned_v<T> && (sizeof(T) <= 8)
inline T Select(T a, T b, bool pick_b) noexcept {
  using U = std::conditional_t<sizeof(T) <= 4, uint32_t, uint64_t>;
  U mask = static_cast<U>(0) - static_cast<U>(pick_b);
  U av, bv;
  std::memcpy(&av, &a, sizeof(T));
  std::memcpy(&bv, &b, sizeof(T));
  U rv = (av & ~mask) | (bv & mask);
  T out;
  std::memcpy(&out, &rv, sizeof(T));
  return out;
}

template<typename T>
inline void ConditionalSwap(T& a, T& b, bool do_swap) noexcept {
  T ta = a, tb = b;
  a = Select<T>(ta, tb, do_swap);
  b = Select<T>(tb, ta, do_swap);
}

inline void MemCopyConstantTime(void* dest, const void* src, size_t n) noexcept {
  volatile uint8_t* d = static_cast<volatile uint8_t*>(dest);
  const volatile uint8_t* s = static_cast<const volatile uint8_t*>(src);
  for (size_t i = 0; i < n; ++i) d[i] = s[i];
  std::atomic_signal_fence(std::memory_order_seq_cst);
}

} // namespace qv::crypto::ct
