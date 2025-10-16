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
  epoch_started_ = std::chrono::system_clock::now();                    // TSK015
  epoch_started_monotonic_ = std::chrono::steady_clock::now();          // TSK118_Nonce_Reuse_Vulnerabilities monotonic anchor
  counter_ = initial;  // TSK096_Race_Conditions_and_Thread_Safety
  base_counter_ = initial; // TSK015
  if (initial > kCounterHardLimit) { // TSK015
    throw Error{ErrorDomain::Security, 1, "Counter near overflow. Rekey required."};
  }
}

NonceGenerator::RekeyReason NonceGenerator::DetermineRekeyReason(
    uint64_t candidate,
    std::chrono::steady_clock::time_point now) const { // TSK015, TSK118_Nonce_Reuse_Vulnerabilities
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
    auto age = now - epoch_started_monotonic_;
    if (age >= policy_.max_age) {
      return RekeyReason::kEpochExpired;
    }
  }
  return RekeyReason::kNone;
}

NonceGenerator::NonceRecord NonceGenerator::NextAuthenticated(int64_t chunk_index,
                                                             std::span<const uint8_t> binding) {
  std::lock_guard<std::mutex> lock(state_mutex_); // TSK067_Nonce_Safety
  auto monotonic_now = std::chrono::steady_clock::now(); // TSK118_Nonce_Reuse_Vulnerabilities
  if (counter_ == std::numeric_limits<uint64_t>::max()) { // TSK067_Nonce_Safety
    throw Error{ErrorDomain::Security, 6, "Counter exhausted. Rekey required."};
  }
  auto reason = DetermineRekeyReason(counter_, monotonic_now); // TSK015, TSK118_Nonce_Reuse_Vulnerabilities
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
  if (chunk_index != kUnboundChunkIndex) { // TSK118_Nonce_Reuse_Vulnerabilities reuse binding
    auto recycled = recycled_.find(chunk_index);
    if (recycled != recycled_.end()) {
      NonceRecord record = recycled->second;
      record.chunk_index = chunk_index; // TSK118_Nonce_Reuse_Vulnerabilities ensure binding stays explicit
      if (binding.size() != record.binding_size ||
          !std::equal(binding.begin(), binding.end(), record.binding.begin(),
                      record.binding.begin() + record.binding_size)) {
        throw Error{ErrorDomain::Validation, 0, "Nonce binding mismatch"};
      }
      recycled_.erase(recycled);
      inflight_[record.counter] = record;
      return record;
    }
  }

  uint64_t next = counter_;
  counter_ += 1;  // TSK096_Race_Conditions_and_Thread_Safety

  NonceRecord record{}; // TSK014
  record.counter = next; // TSK014
  record.nonce = MakeNonceBytes(epoch_, next); // TSK015
  if (!binding.empty()) {
    if (binding.size() > record.binding.size()) {
      throw Error{ErrorDomain::Validation, 0, "Nonce binding too large"};
    }
    std::copy(binding.begin(), binding.end(), record.binding.begin());
    record.binding_size = static_cast<uint8_t>(binding.size());
  }
  record.chunk_index = chunk_index; // TSK118_Nonce_Reuse_Vulnerabilities
  if (chunk_index == kUnboundChunkIndex) {
    record.mac = log_.Append(next, binding); // TSK014 legacy immediate commit
    return record; // TSK014
  }

  record.mac = log_.Preview(next, binding); // TSK118_Nonce_Reuse_Vulnerabilities defer commit until success
  inflight_[record.counter] = record; // TSK118_Nonce_Reuse_Vulnerabilities
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
  auto monotonic_now = std::chrono::steady_clock::now(); // TSK118_Nonce_Reuse_Vulnerabilities
  {
    std::lock_guard<std::mutex> lock(state_mutex_);  // TSK096_Race_Conditions_and_Thread_Safety
    status.epoch_started = epoch_started_;
    status.counter = counter_;
    status.reason = DetermineRekeyReason(status.counter, monotonic_now);
    status.nonces_emitted = status.counter >= base_counter_ ? status.counter - base_counter_ : 0;
    if (policy_.max_nonces != 0 && status.nonces_emitted < policy_.max_nonces) {
      status.remaining_nonce_budget = policy_.max_nonces - status.nonces_emitted;
    } else {
      status.remaining_nonce_budget = 0;
    }
    if (status.reason == RekeyReason::kCounterLimit) {
      status.remaining_nonce_budget = 0;
    }
  }
  return status;
}

void NonceGenerator::SetEpochStart(std::chrono::system_clock::time_point start) { // TSK015
  std::lock_guard<std::mutex> lock(state_mutex_);  // TSK096_Race_Conditions_and_Thread_Safety
  epoch_started_ = start;
  epoch_started_monotonic_ = std::chrono::steady_clock::now(); // TSK118_Nonce_Reuse_Vulnerabilities
}

void NonceGenerator::SetPolicy(uint64_t max_nonces, std::chrono::hours max_age) { // TSK015
  std::lock_guard<std::mutex> lock(state_mutex_);  // TSK096_Race_Conditions_and_Thread_Safety
  policy_.max_nonces = max_nonces;
  policy_.max_age = max_age;
}

void NonceGenerator::ReleaseNonce(const NonceRecord& record) { // TSK118_Nonce_Reuse_Vulnerabilities
  if (record.chunk_index == kUnboundChunkIndex) {
    throw Error{ErrorDomain::Validation, 0, "Cannot release unbound nonce"};
  }
  std::lock_guard<std::mutex> lock(state_mutex_); // TSK067_Nonce_Safety
  auto it = inflight_.find(record.counter);
  if (it == inflight_.end()) {
    throw Error{ErrorDomain::Validation, 0, "Unknown nonce reservation"};
  }
  if (it->second.chunk_index != record.chunk_index ||
      !std::equal(it->second.mac.begin(), it->second.mac.end(), record.mac.begin(), record.mac.end())) {
    throw Error{ErrorDomain::Validation, 0, "Nonce reservation mismatch"};
  }
  if (it->second.binding_size != record.binding_size ||
      !std::equal(it->second.binding.begin(), it->second.binding.begin() + it->second.binding_size,
                  record.binding.begin(), record.binding.begin() + record.binding_size)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce binding mismatch"};
  }
  recycled_[record.chunk_index] = it->second;
  inflight_.erase(it);
}

void NonceGenerator::CommitNonce(const NonceRecord& record) { // TSK118_Nonce_Reuse_Vulnerabilities
  if (record.chunk_index == kUnboundChunkIndex) {
    throw Error{ErrorDomain::Validation, 0, "Cannot commit unbound nonce"};
  }
  std::lock_guard<std::mutex> lock(state_mutex_); // TSK067_Nonce_Safety
  auto it = inflight_.find(record.counter);
  if (it == inflight_.end()) {
    throw Error{ErrorDomain::Validation, 0, "Unknown nonce reservation"};
  }
  if (it->second.chunk_index != record.chunk_index ||
      !std::equal(it->second.mac.begin(), it->second.mac.end(), record.mac.begin(), record.mac.end())) {
    throw Error{ErrorDomain::Validation, 0, "Nonce reservation mismatch"};
  }
  if (it->second.binding_size != record.binding_size ||
      !std::equal(it->second.binding.begin(), it->second.binding.begin() + it->second.binding_size,
                  record.binding.begin(), record.binding.begin() + record.binding_size)) {
    throw Error{ErrorDomain::Validation, 0, "Nonce binding mismatch"};
  }
  log_.Commit(record.counter, record.mac,
              std::span<const uint8_t>(record.binding.data(), record.binding_size)); // TSK118_Nonce_Reuse_Vulnerabilities, TSK128_Missing_AAD_Validation_in_Chunks
  inflight_.erase(it);
}

std::optional<NonceGenerator::NonceRecord> NonceGenerator::LastPersisted() const { // TSK015
  if (log_.EntryCount() == 0) {
    return std::nullopt;
  }
  NonceRecord record{};
  record.counter = log_.GetLastCounter();
  record.mac = log_.LastMac();
  record.nonce = MakeNonceBytes(epoch_, record.counter);
  record.binding_size = 0;
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
