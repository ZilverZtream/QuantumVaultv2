#pragma once
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#include <iostream> // TSK012
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
  size_t allocation_size_{0}; // TSK012 track padded allocation size for wiping/locking
  bool locked_{false};
  bool lock_capable_{false}; // TSK012 remember platform locking capability

  void Release() noexcept { // TSK012 release and zeroize contents deterministically
    if (!ptr_) {
      size_ = 0;
      allocation_size_ = 0;
      locked_ = false;
      lock_capable_ = false;
      return;
    }

    if (allocation_size_ > 0) {
      auto bytes_span = std::span<uint8_t>(reinterpret_cast<uint8_t*>(ptr_), allocation_size_); // TSK012
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

    ptr_ = nullptr;
    size_ = 0;
    allocation_size_ = 0;
    locked_ = false;
    lock_capable_ = false;
  }

  static size_t RoundUpToAlignment(size_t value) { // TSK012
    const size_t alignment = alignof(T);
    if (alignment <= 1U) {
      return value;
    }
    const size_t remainder = value % alignment;
    if (remainder == 0U) {
      return value;
    }
    const size_t padding = alignment - remainder;
    if (value > (std::numeric_limits<size_t>::max() - padding)) {
      throw std::bad_array_new_length{};
    }
    return value + padding;
  }

public:
  explicit SecureBuffer(size_t n) : size_(n) { // TSK006, TSK012
    if (n > 0 && n > (std::numeric_limits<size_t>::max() / sizeof(T))) {
      throw std::bad_array_new_length{};
    }
    const size_t bytes = n * sizeof(T);
    if (bytes == 0) {
      return;
    }
    allocation_size_ = RoundUpToAlignment(bytes);
#if defined(_WIN32)
    ptr_ = static_cast<T*>(_aligned_malloc(allocation_size_, alignof(T)));
#else
    ptr_ = static_cast<T*>(std::aligned_alloc(alignof(T), allocation_size_));
#endif
    if (!ptr_) throw std::bad_alloc{};
    auto bytes_span = std::span<uint8_t>(reinterpret_cast<uint8_t*>(ptr_), allocation_size_); // TSK012
    Zeroizer::Wipe(bytes_span);
    lock_capable_ = Zeroizer::MemoryLockingSupported();
    if (lock_capable_) {
      locked_ = Zeroizer::TryLockMemory(bytes_span);
      if (!locked_) {
        std::cerr << "SecureBuffer warning: unable to lock sensitive memory; data may page to disk.\n"; // TSK012
      }
    }
  }
  ~SecureBuffer() {
    Release();
  }
  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;
  SecureBuffer(SecureBuffer&& o) noexcept
      : ptr_(o.ptr_), size_(o.size_), allocation_size_(o.allocation_size_), locked_(o.locked_),
        lock_capable_(o.lock_capable_) { // TSK012 move state safely
    o.ptr_ = nullptr;
    o.size_ = 0;
    o.allocation_size_ = 0;
    o.locked_ = false;
    o.lock_capable_ = false;
  }
  SecureBuffer& operator=(SecureBuffer&& o) noexcept {
    if (this != &o) {
      Release();
      ptr_ = o.ptr_;
      size_ = o.size_;
      allocation_size_ = o.allocation_size_;
      locked_ = o.locked_;
      lock_capable_ = o.lock_capable_;
      o.ptr_ = nullptr;
      o.size_ = 0;
      o.allocation_size_ = 0;
      o.locked_ = false;
      o.lock_capable_ = false;
    }
    return *this;
  }
  T* data() noexcept { return ptr_; }
  const T* data() const noexcept { return ptr_; }
  size_t size() const noexcept { return size_; }
  std::span<T> AsSpan() noexcept { return {ptr_, size_}; }
  std::span<const T> AsSpan() const noexcept { return {ptr_, size_}; }
  std::span<uint8_t> AsU8Span() noexcept { // TSK012
    return {reinterpret_cast<uint8_t*>(ptr_), size_ * sizeof(T)};
  }
  std::span<const uint8_t> AsU8Span() const noexcept { // TSK012
    return {reinterpret_cast<const uint8_t*>(ptr_), size_ * sizeof(T)};
  }
  bool IsLocked() const noexcept { return locked_; } // TSK012
  bool LockingSupported() const noexcept { return lock_capable_; } // TSK012
};

} // namespace qv::security
