#pragma once
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <span>
#include <new>
#include <memory>
#include "qv/common.h"

namespace qv::security {

template<typename T>
class SecureBuffer {
  T* ptr_{nullptr};
  size_t size_{0};
  bool locked_{false};
public:
  explicit SecureBuffer(size_t n) : size_(n) {
#if defined(_WIN32)
    ptr_ = static_cast<T*>(_aligned_malloc(n * sizeof(T), alignof(T)));
#else
    ptr_ = static_cast<T*>(std::aligned_alloc(alignof(T), n * sizeof(T)));
#endif
    if (!ptr_) throw std::bad_alloc{};
    std::memset(ptr_, 0, n * sizeof(T));
    // TODO: mlock/VirtualLock (omitted in skeleton to avoid perms)
  }
  ~SecureBuffer() {
    if (ptr_) {
      explicit_bzero(ptr_, size_ * sizeof(T));
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
