#include "qv/crypto/random.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <span>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#include <processthreadsapi.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#endif
#if !defined(BCRYPT_SUCCESS)
#define BCRYPT_SUCCESS(status) ((status) >= 0)
#endif
extern "C" BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>
#include <unistd.h>
#elif defined(__linux__) || defined(__ANDROID__)
#include <sys/random.h>
#include <unistd.h>
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#include <immintrin.h>
#endif
#endif

#include "qv/error.h"

namespace {

void XorIntoBuffer(std::span<uint8_t> dest, const uint8_t* data,
                   size_t length) { // TSK134_Insufficient_Entropy_for_Keys mix entropy bytes
  if (dest.empty() || data == nullptr || length == 0) {
    return;
  }
  size_t index = 0;
  for (size_t i = 0; i < length; ++i) {
    dest[index] ^= data[i];
    if (++index == dest.size()) {
      index = 0;
    }
  }
}

void MixUint64(std::span<uint8_t> dest, uint64_t value) { // TSK134_Insufficient_Entropy_for_Keys convert entropy values
  uint8_t buffer[sizeof(value)];
  std::memcpy(buffer, &value, sizeof(buffer));
  XorIntoBuffer(dest, buffer, sizeof(buffer));
}

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

bool CpuSupportsRdrand() { // TSK134_Insufficient_Entropy_for_Keys runtime instruction detection
#if defined(_MSC_VER)
  return IsProcessorFeaturePresent(PF_RDRAND_INSTRUCTION_AVAILABLE) != 0;
#elif defined(__GNUC__) || defined(__clang__)
  return __builtin_cpu_supports("rdrnd");
#else
  return false;
#endif
}

bool CpuSupportsRdseed() { // TSK134_Insufficient_Entropy_for_Keys runtime instruction detection
#if defined(_MSC_VER) && defined(PF_RDSEED_INSTRUCTION_AVAILABLE)
  return IsProcessorFeaturePresent(PF_RDSEED_INSTRUCTION_AVAILABLE) != 0;
#elif defined(__GNUC__) || defined(__clang__)
  return __builtin_cpu_supports("rdseed");
#else
  return false;
#endif
}

bool Rdseed64(uint64_t& value) { // TSK134_Insufficient_Entropy_for_Keys read RDSEED
#if defined(_MSC_VER)
#if defined(_M_X64)
  return _rdseed64_step(reinterpret_cast<unsigned __int64*>(&value)) == 1;
#else
  unsigned int temp = 0;
  int ok = _rdseed32_step(&temp);
  if (ok == 1) {
    value = temp;
    return true;
  }
  return false;
#endif
#elif defined(__GNUC__) || defined(__clang__)
#if defined(__x86_64__)
  return __builtin_ia32_rdseed64_step(reinterpret_cast<unsigned long long*>(&value)) == 1;
#else
  unsigned int temp = 0;
  int ok = __builtin_ia32_rdseed32_step(&temp);
  if (ok == 1) {
    value = temp;
    return true;
  }
  return false;
#endif
#else
  (void)value;
  return false;
#endif
}

bool Rdrand64(uint64_t& value) { // TSK134_Insufficient_Entropy_for_Keys read RDRAND
#if defined(_MSC_VER)
#if defined(_M_X64)
  return _rdrand64_step(reinterpret_cast<unsigned __int64*>(&value)) == 1;
#else
  unsigned int temp = 0;
  int ok = _rdrand32_step(&temp);
  if (ok == 1) {
    value = temp;
    return true;
  }
  return false;
#endif
#elif defined(__GNUC__) || defined(__clang__)
#if defined(__x86_64__)
  return __builtin_ia32_rdrand64_step(reinterpret_cast<unsigned long long*>(&value)) == 1;
#else
  unsigned int temp = 0;
  int ok = __builtin_ia32_rdrand32_step(&temp);
  if (ok == 1) {
    value = temp;
    return true;
  }
  return false;
#endif
#else
  (void)value;
  return false;
#endif
}

#endif  // x86 entropy helpers

void MixAdditionalEntropy(std::span<uint8_t> dest) { // TSK134_Insufficient_Entropy_for_Keys combine supplemental entropy
  const auto high_res = static_cast<uint64_t>(
      std::chrono::high_resolution_clock::now().time_since_epoch().count());
  MixUint64(dest, high_res);
  const auto steady = static_cast<uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  MixUint64(dest, steady);

  const auto thread_hash = static_cast<uint64_t>(
      std::hash<std::thread::id>{}(std::this_thread::get_id()));
  MixUint64(dest, thread_hash);

#if defined(_WIN32)
  MixUint64(dest, static_cast<uint64_t>(GetCurrentProcessId()));
  MixUint64(dest, static_cast<uint64_t>(GetCurrentThreadId()));
#elif defined(__APPLE__) || defined(__linux__) || defined(__ANDROID__) ||  \
    defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  MixUint64(dest, static_cast<uint64_t>(::getpid()));
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
  if (CpuSupportsRdseed()) {
    for (int i = 0; i < 8; ++i) {
      uint64_t value = 0;
      if (Rdseed64(value)) {
        MixUint64(dest, value);
      }
    }
  } else if (CpuSupportsRdrand()) {
    for (int i = 0; i < 8; ++i) {
      uint64_t value = 0;
      if (Rdrand64(value)) {
        MixUint64(dest, value);
      }
    }
  }
#endif
}

void ReadFromUrandom(std::span<uint8_t> out) { // TSK134_Insufficient_Entropy_for_Keys POSIX fallback
  std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
  if (!urandom) {
    throw Error(ErrorDomain::Crypto, errno, "Failed to open /dev/urandom");
  }
  urandom.read(reinterpret_cast<char*>(out.data()),
               static_cast<std::streamsize>(out.size()));
  if (urandom.gcount() != static_cast<std::streamsize>(out.size())) {
    throw Error(ErrorDomain::Crypto, errno,
                "Failed to read sufficient entropy from /dev/urandom");
  }
}

}  // namespace

namespace qv::crypto {

void SystemRandomBytes(std::span<uint8_t> out) { // TSK106_Cryptographic_Implementation_Weaknesses
  if (out.empty()) {
    return;
  }
#if defined(_WIN32)
  NTSTATUS status = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(out.data()),
                                    static_cast<ULONG>(out.size()),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (!BCRYPT_SUCCESS(status)) {
    if (!RtlGenRandom(out.data(), static_cast<ULONG>(out.size()))) {
      throw Error(ErrorDomain::Crypto, static_cast<int>(status),
                  "Windows RNG failed"); // TSK134_Insufficient_Entropy_for_Keys fallback
    }
  }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  arc4random_buf(out.data(), out.size());
#elif defined(__linux__) || defined(__ANDROID__)
  size_t offset = 0;
  bool used_blocking = false;
  while (offset < out.size()) {
    const int flags = used_blocking ? 0 : GRND_NONBLOCK;
    ssize_t result = ::getrandom(out.data() + offset, out.size() - offset, flags);
    if (result < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN && !used_blocking) {
        break; // fall back to /dev/urandom below
      }
      throw Error(ErrorDomain::Crypto, errno, "getrandom failed");
    }
    if (result == 0) {
      break;
    }
    offset += static_cast<size_t>(result);
    used_blocking = true;
  }
  if (offset < out.size()) {
    ReadFromUrandom(out.subspan(offset));
  }
#else
  ReadFromUrandom(out);
#endif
  MixAdditionalEntropy(out); // TSK134_Insufficient_Entropy_for_Keys strengthen randomness
}

}  // namespace qv::crypto
