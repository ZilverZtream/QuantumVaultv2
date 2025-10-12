#include "qv/core/nonce.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/error.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

using namespace qv;
using namespace qv::core;
using qv::crypto::HMAC_SHA256;

NonceLog::NonceLog(const std::filesystem::path& path) : path_(path) {
  fd_ = ::open(path_.c_str(), O_CREAT | O_APPEND | O_RDWR, 0644);
  if (fd_ < 0) throw Error{ErrorDomain::IO, errno, "Failed to open nonce log"};
  // Random key stub
  for (auto& b : key_) b = static_cast<uint8_t>(rand());
}
NonceLog::~NonceLog() {
  if (fd_ >= 0) ::close(fd_);
}
void NonceLog::Append(uint64_t counter) {
  std::lock_guard<std::mutex> lock(mu_);
  struct MACInput {
    std::array<uint8_t,32> prev_mac;
    uint64_t counter_be;
  } __attribute__((packed));
  MACInput in{last_mac_, qv::ToBigEndian(counter)};
  auto mac = HMAC_SHA256::Compute(key_, qv::AsBytes(in));
  struct Entry {
    uint64_t counter_be;
    std::array<uint8_t,32> mac;
  } __attribute__((packed)) e{qv::ToBigEndian(counter), mac};
  ssize_t w = ::write(fd_, &e, sizeof(e));
  if (w != (ssize_t)sizeof(e)) throw Error{ErrorDomain::IO, errno, "Failed to write nonce log"};
  fsync(fd_);
  last_mac_ = mac;
}
bool NonceLog::VerifyChain() {
  // Minimal verification stub: always true in skeleton
  return true;
}
uint64_t NonceLog::GetLastCounter() const {
  // Naive: read last record
  struct Entry { uint64_t counter_be; uint8_t mac[32]; } e;
  off_t sz = lseek(fd_, 0, SEEK_END);
  if (sz < (off_t)sizeof(e)) return 0;
  lseek(fd_, sz - sizeof(e), SEEK_SET);
  if (read(fd_, &e, sizeof(e)) != (ssize_t)sizeof(e)) return 0;
  return qv::ToBigEndian(e.counter_be);
}
