#include "qv/crypto/random.h"

#include <cerrno>
#include <fstream>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>
#elif defined(__linux__) || defined(__ANDROID__)
#include <sys/random.h>
#include <unistd.h>
#endif

#include "qv/error.h"

namespace qv::crypto {

void SystemRandomBytes(std::span<uint8_t> out) { // TSK106_Cryptographic_Implementation_Weaknesses
  if (out.empty()) {
    return;
  }
#if defined(_WIN32)
  NTSTATUS status = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(out.data()),
                                    static_cast<ULONG>(out.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status != 0) {
    throw Error(ErrorDomain::Crypto, static_cast<int>(status), "BCryptGenRandom failed");
  }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  arc4random_buf(out.data(), out.size());
#elif defined(__linux__) || defined(__ANDROID__)
  size_t offset = 0;
  while (offset < out.size()) {
    ssize_t result = ::getrandom(out.data() + offset, out.size() - offset, 0);
    if (result < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw Error(ErrorDomain::Crypto, errno, "getrandom failed");
    }
    offset += static_cast<size_t>(result);
  }
#else
  std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
  if (!urandom) {
    throw Error(ErrorDomain::Crypto, errno, "Failed to open /dev/urandom");
  }
  urandom.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
  if (urandom.gcount() != static_cast<std::streamsize>(out.size())) {
    throw Error(ErrorDomain::Crypto, errno, "Failed to read sufficient entropy from /dev/urandom");
  }
#endif
}

}  // namespace qv::crypto
