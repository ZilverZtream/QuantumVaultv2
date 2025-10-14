#include "qv/core/nonce.h"

#include <algorithm>
#include <chrono> // TSK015
#include <cstring> // TSK014
#include <limits> // TSK015
#include <optional> // TSK015

using namespace qv;
using namespace qv::core;

namespace {
constexpr uint64_t kCounterHardLimit = std::numeric_limits<uint64_t>::max() - 1'000'000ULL; // TSK015
}

std::array<uint8_t, 12> NonceGenerator::MakeNonceBytes(uint32_t epoch, uint64_t counter) { // TSK015
  std::array<uint8_t, 12> nonce{};
  uint32_t epoch_le = qv::ToLittleEndian(epoch);
  uint64_t counter_be = qv::ToBigEndian(counter);
  std::memcpy(nonce.data(), &epoch_le, sizeof(epoch_le));
  std::memcpy(nonce.data() + sizeof(epoch_le), &counter_be, sizeof(counter_be));
  return nonce;
}

NonceGenerator::NonceGenerator(uint32_t epoch, uint64_t start_counter)
  : epoch_(epoch), counter_(start_counter), log_(std::filesystem::path("qv_nonce.log")) {
  if (!log_.VerifyChain()) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log verification failed"};
  }
  uint64_t persisted = log_.GetLastCounter();
  bool has_entries = log_.EntryCount() > 0;
  uint64_t persisted_next = (persisted == UINT64_MAX) ? UINT64_MAX : persisted + 1;
  uint64_t initial = has_entries ? std::max(start_counter, persisted_next) : start_counter;
  epoch_started_ = std::chrono::system_clock::now(); // TSK015
  counter_.store(initial, std::memory_order_release);
  base_counter_ = initial; // TSK015
  if (initial > kCounterHardLimit) { // TSK015
    throw Error{ErrorDomain::Security, 1, "Counter near overflow. Rekey required."};
  }
}

NonceGenerator::RekeyReason NonceGenerator::DetermineRekeyReason(
    uint64_t candidate,
    std::chrono::system_clock::time_point now) const { // TSK015
  if (candidate >= kCounterHardLimit) {
    return RekeyReason::kCounterLimit;
  }
  if (policy_.max_nonces != 0) {
    uint64_t emitted = candidate >= base_counter_ ? candidate - base_counter_ : 0;
    if (emitted >= policy_.max_nonces) {
      return RekeyReason::kNonceBudget;
    }
  }
  if (policy_.max_age.count() > 0) {
    auto age = now - epoch_started_;
    if (age >= policy_.max_age) {
      return RekeyReason::kEpochExpired;
    }
  }
  return RekeyReason::kNone;
}

NonceGenerator::NonceRecord NonceGenerator::NextAuthenticated() {
  std::lock_guard<std::mutex> lock(nonce_mutex_); // TSK067_Nonce_Safety
  auto now = std::chrono::system_clock::now(); // TSK015
  uint64_t next = 0;
  while (true) { // TSK015
    uint64_t current = counter_.load(std::memory_order_acquire);
    if (current == std::numeric_limits<uint64_t>::max()) { // TSK067_Nonce_Safety
      throw Error{ErrorDomain::Security, 6, "Counter exhausted. Rekey required."};
    }
    auto reason = DetermineRekeyReason(current, now); // TSK015
    if (reason != RekeyReason::kNone) {
      const char* msg = "Rekey required"; // TSK015
      int code = 2; // TSK015
      switch (reason) { // TSK015
        case RekeyReason::kNone:
          break;
        case RekeyReason::kNonceBudget:
          msg = "Nonce budget exhausted. Rekey required.";
          code = 3;
          break;
        case RekeyReason::kEpochExpired:
          msg = "Epoch lifetime exceeded. Rekey required.";
          code = 4;
          break;
        case RekeyReason::kCounterLimit:
          msg = "Counter near overflow. Rekey required.";
          code = 5;
          break;
      }
      throw Error{ErrorDomain::Security, code, msg};
    }
    uint64_t desired = current + 1;
    if (counter_.compare_exchange_weak(current, desired,
                                       std::memory_order_acq_rel,
                                       std::memory_order_acquire)) {
      next = current;
      break;
    }
  }
  auto mac = log_.Append(next); // TSK014
  NonceRecord record{}; // TSK014
  record.counter = next; // TSK014
  record.mac = mac; // TSK014
  record.nonce = MakeNonceBytes(epoch_, next); // TSK015
  return record; // TSK014
}

std::array<uint8_t, 12> NonceGenerator::Next() {
  return NextAuthenticated().nonce; // TSK014
}

bool NonceGenerator::NeedsRekey() const { // TSK015
  return GetStatus().reason != RekeyReason::kNone; // TSK015
}

NonceGenerator::Status NonceGenerator::GetStatus() const { // TSK015
  return EvaluateStatus(std::chrono::system_clock::now()); // TSK015
}

NonceGenerator::Status NonceGenerator::EvaluateStatus(
    std::chrono::system_clock::time_point now) const { // TSK015
  Status status{};
  status.now = now;
  status.epoch_started = epoch_started_;
  status.counter = counter_.load(std::memory_order_acquire);
  status.reason = DetermineRekeyReason(status.counter, now);
  status.nonces_emitted = status.counter >= base_counter_ ? status.counter - base_counter_ : 0;
  if (policy_.max_nonces != 0 && status.nonces_emitted < policy_.max_nonces) {
    status.remaining_nonce_budget = policy_.max_nonces - status.nonces_emitted;
  } else {
    status.remaining_nonce_budget = 0;
  }
  if (status.reason == RekeyReason::kCounterLimit) {
    status.remaining_nonce_budget = 0;
  }
  return status;
}

void NonceGenerator::SetEpochStart(std::chrono::system_clock::time_point start) { // TSK015
  epoch_started_ = start;
}

void NonceGenerator::SetPolicy(uint64_t max_nonces, std::chrono::hours max_age) { // TSK015
  policy_.max_nonces = max_nonces;
  policy_.max_age = max_age;
}

std::optional<NonceGenerator::NonceRecord> NonceGenerator::LastPersisted() const { // TSK015
  if (log_.EntryCount() == 0) {
    return std::nullopt;
  }
  NonceRecord record{};
  record.counter = log_.GetLastCounter();
  record.mac = log_.LastMac();
  record.nonce = MakeNonceBytes(epoch_, record.counter);
  return record;
}

static_assert(kEpochOverflowWarningMargin < kEpochOverflowHardLimit,
              "warning margin must be below hard limit"); // TSK071_Epoch_Overflow_Safety sanity guard
static_assert(kEpochOverflowUnsafeMargin < kEpochOverflowHardLimit,
              "unsafe margin must be below hard limit"); // TSK071_Epoch_Overflow_Safety sanity guard

uint32_t qv::core::EpochOverflowWarningThreshold() { // TSK071_Epoch_Overflow_Safety shared policy
  return kEpochOverflowHardLimit - kEpochOverflowWarningMargin;
}

uint32_t qv::core::EpochOverflowUnsafeThreshold() { // TSK071_Epoch_Overflow_Safety shared policy
  return kEpochOverflowHardLimit - kEpochOverflowUnsafeMargin;
}

bool qv::core::EpochRequiresOverflowWarning(uint32_t epoch) { // TSK071_Epoch_Overflow_Safety shared policy
  return epoch >= EpochOverflowWarningThreshold();
}

bool qv::core::EpochRekeyWouldBeUnsafe(uint32_t epoch) { // TSK071_Epoch_Overflow_Safety shared policy
  return epoch >= EpochOverflowUnsafeThreshold();
}
