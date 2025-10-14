#pragma once
#include <algorithm> // TSK031 chunk sizing
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#include <iostream> // TSK012
#include <stdexcept> // TSK031 strict locking enforcement
#include <vector> // TSK031 per-chunk lock tracking
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
  struct LockRegion { // TSK031 per-chunk bookkeeping
    uint8_t* begin{nullptr};
    size_t length{0};
    bool locked{false};
  };
  std::vector<LockRegion> lock_regions_; // TSK031 chunk statuses

  void Release() noexcept { // TSK012 release and zeroize contents deterministically
    if (!ptr_) {
      size_ = 0;
      allocation_size_ = 0;
      locked_ = false;
      lock_capable_ = false;
      lock_regions_.clear(); // TSK031
      return;
    }

    if (allocation_size_ > 0) {
      auto bytes_span = std::span<uint8_t>(reinterpret_cast<uint8_t*>(ptr_), allocation_size_); // TSK012
      Zeroizer::Wipe(bytes_span);
      for (auto& region : lock_regions_) { // TSK031 unlock only locked chunks
        if (region.locked) {
          auto chunk_span = std::span<uint8_t>(region.begin, region.length); // TSK031
          Zeroizer::UnlockMemory(chunk_span);
        }
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
    lock_regions_.clear(); // TSK031
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
    if (!ptr_)
      throw std::bad_alloc{};
    auto bytes_span = std::span<uint8_t>(reinterpret_cast<uint8_t*>(ptr_), allocation_size_); // TSK012
    Zeroizer::Wipe(bytes_span);
    lock_capable_ = Zeroizer::MemoryLockingSupported();
    if (lock_capable_) {
      auto* raw = reinterpret_cast<uint8_t*>(ptr_); // TSK031
      const size_t chunk_target = 64U * 1024U; // 64 KiB // TSK031
      size_t offset = 0;
      bool all_chunks_locked = true; // TSK031
      while (offset < allocation_size_) {
        const size_t remaining = allocation_size_ - offset;
        const size_t chunk_size = std::min(chunk_target, remaining);
        auto chunk_span = std::span<uint8_t>(raw + offset, chunk_size);
        const auto status = Zeroizer::TryLockMemory(chunk_span);             // TSK085
        const bool chunk_locked = (status == Zeroizer::LockStatus::Locked);  // TSK085
        lock_regions_.push_back(LockRegion{raw + offset, chunk_size, chunk_locked});
        all_chunks_locked = all_chunks_locked && chunk_locked;
        offset += chunk_size;
      }
      locked_ = all_chunks_locked;
      if (!locked_) {
        std::cerr << "SecureBuffer warning: unable to lock all sensitive memory chunks; data may page to disk.\n"; // TSK012, TSK031
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
        lock_capable_(o.lock_capable_), lock_regions_(std::move(o.lock_regions_)) { // TSK012 move state safely
    o.ptr_ = nullptr;
    o.size_ = 0;
    o.allocation_size_ = 0;
    o.locked_ = false;
    o.lock_capable_ = false;
    o.lock_regions_.clear(); // TSK031
  }
  SecureBuffer& operator=(SecureBuffer&& o) noexcept {
    if (this != &o) {
      Release();
      ptr_ = o.ptr_;
      size_ = o.size_;
      allocation_size_ = o.allocation_size_;
      locked_ = o.locked_;
      lock_capable_ = o.lock_capable_;
      lock_regions_ = std::move(o.lock_regions_); // TSK031
      o.ptr_ = nullptr;
      o.size_ = 0;
      o.allocation_size_ = 0;
      o.locked_ = false;
      o.lock_capable_ = false;
      o.lock_regions_.clear(); // TSK031
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

  void RequireLocking() const { // TSK031 enforce strict locking mode
    if (!lock_capable_) {
      throw std::runtime_error("SecureBuffer: memory locking not supported on this platform");
    }
    if (!locked_) {
      throw std::runtime_error(
          "SecureBuffer: memory locking required but one or more chunks are unlocked");
    }
  }
};

} // namespace qv::security
