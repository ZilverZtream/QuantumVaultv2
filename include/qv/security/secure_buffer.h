#pragma once
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#if defined(_WIN32)
#include <malloc.h>
#endif
#include "qv/common.h"
#include "qv/security/zeroizer.h"

namespace qv::security {

template<typename T>
class SecureBuffer {
  T* ptr_{nullptr};
  size_t size_{0};
  bool locked_{false};
public:
  explicit SecureBuffer(size_t n) : size_(n) { // TSK006
    if (n > 0 && n > (std::numeric_limits<size_t>::max() / sizeof(T))) {
      throw std::bad_array_new_length{};
    }
    const size_t bytes = n * sizeof(T);
    if (bytes == 0) {
      return;
    }
#if defined(_WIN32)
    ptr_ = static_cast<T*>(_aligned_malloc(bytes, alignof(T)));
#else
    ptr_ = static_cast<T*>(std::aligned_alloc(alignof(T), bytes));
#endif
    if (!ptr_) throw std::bad_alloc{};
    auto bytes_span = std::span<uint8_t>(reinterpret_cast<uint8_t*>(ptr_), bytes);
    Zeroizer::Wipe(bytes_span);
    if (Zeroizer::MemoryLockingSupported()) {
      locked_ = Zeroizer::TryLockMemory(bytes_span);
    }
  }
  ~SecureBuffer() {
    if (ptr_) {
      if (size_ > 0) {
        const size_t bytes = size_ * sizeof(T);
        auto bytes_span = std::span<uint8_t>(reinterpret_cast<uint8_t*>(ptr_), bytes); // TSK006
        Zeroizer::Wipe(bytes_span);
        if (locked_) {
          Zeroizer::UnlockMemory(bytes_span);
        }
      }
#if defined(_WIN32)
      _aligned_free(ptr_);
#else
      std::free(ptr_);
#endif
    }
  }
  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;
  SecureBuffer(SecureBuffer&& o) noexcept : ptr_(o.ptr_), size_(o.size_), locked_(o.locked_) {
    o.ptr_ = nullptr; o.size_ = 0; o.locked_ = false;
  }
  SecureBuffer& operator=(SecureBuffer&& o) noexcept {
    if (this != &o) {
      this->~SecureBuffer();
      ptr_ = o.ptr_; size_ = o.size_; locked_ = o.locked_;
      o.ptr_ = nullptr; o.size_ = 0; o.locked_ = false;
    }
    return *this;
  }
  T* data() noexcept { return ptr_; }
  const T* data() const noexcept { return ptr_; }
  size_t size() const noexcept { return size_; }
  std::span<T> AsSpan() noexcept { return {ptr_, size_}; }
  std::span<const T> AsSpan() const noexcept { return {ptr_, size_}; }
};

} // namespace qv::security
