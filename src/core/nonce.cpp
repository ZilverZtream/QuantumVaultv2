#include "qv/core/nonce.h"

#include <algorithm>
#include <cstring> // TSK014

using namespace qv;
using namespace qv::core;

NonceGenerator::NonceGenerator(uint32_t epoch, uint64_t start_counter)
  : epoch_(epoch), counter_(start_counter), log_(std::filesystem::path("qv_nonce.log")) {
  if (!log_.VerifyChain()) {
    throw Error{ErrorDomain::Validation, 0, "Nonce log verification failed"};
  }
  uint64_t persisted = log_.GetLastCounter();
  bool has_entries = log_.EntryCount() > 0;
  uint64_t persisted_next = (persisted == UINT64_MAX) ? UINT64_MAX : persisted + 1;
  uint64_t initial = has_entries ? std::max(start_counter, persisted_next) : start_counter;
  counter_.store(initial, std::memory_order_release);
  if (initial > (UINT64_MAX - 1'000'000'000ULL)) {
    throw Error{ErrorDomain::Security, 1, "Counter near overflow. Rekey required."};
  }
}

NonceGenerator::NonceRecord NonceGenerator::NextAuthenticated() {
  uint64_t next = counter_.fetch_add(1, std::memory_order_seq_cst);
  if (next >= UINT64_MAX - 1'000'000ULL) {
    counter_.store(UINT64_MAX, std::memory_order_seq_cst);
    throw Error{ErrorDomain::Security, 2, "Counter overflow imminent! Rekey."};
  }
  auto mac = log_.Append(next); // TSK014
  NonceRecord record{}; // TSK014
  record.counter = next; // TSK014
  record.mac = mac; // TSK014
  std::array<uint8_t,12> nonce{};
  uint32_t epoch_le = qv::ToLittleEndian(epoch_);
  uint64_t counter_be = qv::ToBigEndian(next);
  std::memcpy(nonce.data()+0, &epoch_le, 4);
  std::memcpy(nonce.data()+4, &counter_be, 8);
  record.nonce = nonce; // TSK014
  return record; // TSK014
}

std::array<uint8_t, 12> NonceGenerator::Next() {
  return NextAuthenticated().nonce; // TSK014
}
