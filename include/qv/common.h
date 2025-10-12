#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
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

namespace qv {
inline uint32_t ToLittleEndian(uint32_t x) {
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return x;
  #else
    return __builtin_bswap32(x);
  #endif
}
inline uint64_t ToBigEndian(uint64_t x) {
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(x);
  #else
    return x;
  #endif
}
template<typename T>
inline std::span<uint8_t> AsBytes(T& obj) {
  return {reinterpret_cast<uint8_t*>(&obj), sizeof(T)};
}
template<typename T>
inline std::span<const uint8_t> AsBytesConst(const T& obj) {
  return {reinterpret_cast<const uint8_t*>(&obj), sizeof(T)};
}
} // namespace qv
