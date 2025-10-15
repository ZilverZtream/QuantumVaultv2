#pragma once
#include <array>
#include <atomic>
#include <bit>
#include <cstdint>
#include <cstring>
#include <cstddef>
#include <filesystem>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>
#include <fstream>
#include <chrono>
#include <random>
#include <thread>
#include <iostream>
#include <type_traits>
#include <memory>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace qv {
namespace detail {
// TSK007 Portable byte swapping helpers.
template <class T>
[[nodiscard]] constexpr T ManualByteSwap(T value) noexcept {
  static_assert(std::is_trivially_copyable_v<T>, "ManualByteSwap requires trivially copyable types");
  auto source = std::bit_cast<std::array<std::uint8_t, sizeof(T)>>(value);
  std::array<std::uint8_t, sizeof(T)> reversed{};
  for (std::size_t i = 0; i < source.size(); ++i) {
    reversed[i] = source[source.size() - 1U - i];
  }
  return std::bit_cast<T>(reversed);
}

[[nodiscard]] constexpr std::uint16_t ByteSwap16(std::uint16_t value) noexcept { // TSK111_Code_Duplication_and_Maintainability
  if (std::is_constant_evaluated()) {
    return ManualByteSwap(value);
  }
#if defined(_MSC_VER)
  return _byteswap_ushort(value);
#elif defined(__clang__) || defined(__GNUC__)
  return __builtin_bswap16(value);
#else
  return ManualByteSwap(value);
#endif
}

[[nodiscard]] constexpr std::uint32_t ByteSwap32(std::uint32_t value) noexcept {
  if (std::is_constant_evaluated()) {
    return ManualByteSwap(value);
  }
#if defined(_MSC_VER)
  return _byteswap_ulong(value);
#elif defined(__clang__) || defined(__GNUC__)
  return __builtin_bswap32(value);
#else
  return ManualByteSwap(value);
#endif
}

[[nodiscard]] constexpr std::uint64_t ByteSwap64(std::uint64_t value) noexcept {
  if (std::is_constant_evaluated()) {
    return ManualByteSwap(value);
  }
#if defined(_MSC_VER)
  return _byteswap_uint64(value);
#elif defined(__clang__) || defined(__GNUC__)
  return __builtin_bswap64(value);
#else
  return ManualByteSwap(value);
#endif
}
}  // namespace detail

inline constexpr bool kIsLittleEndian = std::endian::native == std::endian::little;  // TSK007

inline constexpr std::uint16_t ToLittleEndian16(std::uint16_t value) noexcept {  // TSK111_Code_Duplication_and_Maintainability
  return kIsLittleEndian ? value : detail::ByteSwap16(value);
}

inline constexpr std::uint32_t ToLittleEndian(std::uint32_t value) noexcept {  // TSK007
  return kIsLittleEndian ? value : detail::ByteSwap32(value);
}

inline constexpr std::uint64_t ToLittleEndian64(std::uint64_t value) noexcept {  // TSK111_Code_Duplication_and_Maintainability
  return kIsLittleEndian ? value : detail::ByteSwap64(value);
}

inline constexpr std::uint64_t ToBigEndian(std::uint64_t value) noexcept {  // TSK007
  return kIsLittleEndian ? detail::ByteSwap64(value) : value;
}

inline constexpr std::uint16_t FromLittleEndian16(std::uint16_t value) noexcept {  // TSK111_Code_Duplication_and_Maintainability
  return ToLittleEndian16(value);
}

inline constexpr std::uint32_t FromLittleEndian32(std::uint32_t value) noexcept {  // TSK111_Code_Duplication_and_Maintainability
  return ToLittleEndian(value);
}

inline constexpr std::uint64_t FromLittleEndian64(std::uint64_t value) noexcept {  // TSK111_Code_Duplication_and_Maintainability
  return ToLittleEndian64(value);
}

template <class T>
  requires std::is_trivially_copyable_v<T>
inline std::span<std::uint8_t> AsBytes(T& object) noexcept {  // TSK007
  auto* data = reinterpret_cast<std::uint8_t*>(std::addressof(object));
  return {data, sizeof(T)};
}

template <class T>
  requires std::is_trivially_copyable_v<T>
inline std::span<const std::uint8_t> AsBytesConst(const T& object) noexcept {  // TSK007
  const auto* data = reinterpret_cast<const std::uint8_t*>(std::addressof(object));
  return {data, sizeof(T)};
}

inline std::string PathToUtf8String(const std::filesystem::path& path) {  // TSK016_Windows_Compatibility_Fixes
#if defined(_WIN32)
  const std::u8string u8 = path.u8string();
  std::string result;
  result.reserve(u8.size());
  for (auto ch : u8) {
    result.push_back(static_cast<char>(ch));
  }
  return result;
#else
  return path.string();
#endif
}
} // namespace qv
