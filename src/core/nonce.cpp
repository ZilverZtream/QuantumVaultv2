#include "qv/core/nonce.h"

using namespace qv;
using namespace qv::core;

NonceGenerator::NonceGenerator(uint32_t epoch, uint64_t start_counter)
  : epoch_(epoch), counter_(start_counter), log_(std::filesystem::path("qv_nonce.log")) {
  if (start_counter > (UINT64_MAX - 1'000'000'000ULL)) {
    throw Error{ErrorDomain::Security, 1, "Counter near overflow. Rekey required."};
  }
}

std::array<uint8_t, 12> NonceGenerator::Next() {
  uint64_t next = counter_.fetch_add(1, std::memory_order_seq_cst);
  if (next >= UINT64_MAX - 1'000'000ULL) {
    counter_.store(UINT64_MAX, std::memory_order_seq_cst);
    throw Error{ErrorDomain::Security, 2, "Counter overflow imminent! Rekey."};
  }
  log_.Append(next);
  std::array<uint8_t,12> nonce{};
  uint32_t epoch_le = qv::ToLittleEndian(epoch_);
  uint64_t counter_be = qv::ToBigEndian(next);
  std::memcpy(nonce.data()+0, &epoch_le, 4);
  std::memcpy(nonce.data()+4, &counter_be, 8);
  return nonce;
}
