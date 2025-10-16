#include "qv/crypto/keyfiles.h"

#include <cerrno>
#include <fstream>
#include <vector>

#include "qv/crypto/sha256.h"    // TSK711_Keyfiles_and_PKCS11_FIDO2 digest primitive
#include "qv/error.h"
#include "qv/security/secure_buffer.h" // TSK711_Keyfiles_and_PKCS11_FIDO2 scoped wiping
#include "qv/security/zeroizer.h"      // TSK711_Keyfiles_and_PKCS11_FIDO2 cleanup

namespace qv::crypto {

namespace {
constexpr size_t kMaxKeyfileSize = 1024 * 1024; // 1 MiB // TSK711_Keyfiles_and_PKCS11_FIDO2 size ceiling
}

std::array<uint8_t, 32> HashKeyfile(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw qv::Error{qv::ErrorDomain::IO, errno,
                    "Failed to open keyfile: " + qv::PathToUtf8String(path)}; // TSK711_Keyfiles_and_PKCS11_FIDO2
  }

  in.seekg(0, std::ios::end);
  auto size = in.tellg();
  if (size < 0) {
    throw qv::Error{qv::ErrorDomain::IO, errno,
                    "Failed to determine keyfile size: " + qv::PathToUtf8String(path)};
  }
  if (static_cast<uint64_t>(size) > kMaxKeyfileSize) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Keyfile exceeds maximum supported size"}; // TSK711_Keyfiles_and_PKCS11_FIDO2
  }
  in.seekg(0, std::ios::beg);

  const size_t buffer_size = static_cast<size_t>(size);
  qv::security::SecureBuffer<uint8_t> buffer(buffer_size);
  if (buffer_size > 0) {
    in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer_size));
    if (in.gcount() != static_cast<std::streamsize>(buffer_size)) {
      throw qv::Error{qv::ErrorDomain::IO, errno,
                      "Failed to read keyfile contents"}; // TSK711_Keyfiles_and_PKCS11_FIDO2
    }
  }

  auto digest = qv::crypto::SHA256_Hash(buffer.AsSpan());
  qv::security::Zeroizer::Wipe(buffer.AsU8Span());
  return digest;
}

} // namespace qv::crypto

