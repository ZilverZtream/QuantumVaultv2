#include "qv/crypto/pbkdf2.h"

#include <algorithm>
#include <vector>

#include "qv/crypto/hmac_sha256.h"
#include "qv/security/zeroizer.h"

namespace qv::crypto {

std::array<uint8_t, 32> PBKDF2_HMAC_SHA256(std::span<const uint8_t> password,
                                           std::span<const uint8_t> salt,
                                           uint32_t iterations,
                                           PBKDF2ProgressCallback progress) { // TSK111_Code_Duplication_and_Maintainability
  iterations = std::max<uint32_t>(iterations, 1u);

  std::array<uint8_t, 32> output{};
  security::Zeroizer::ScopeWiper output_guard(std::span<uint8_t>(output.data(), output.size()));

  std::vector<uint8_t> block(salt.begin(), salt.end());
  block.resize(salt.size() + 4u, 0);
  const uint32_t block_index = 1u;
  block[block.size() - 4] = static_cast<uint8_t>((block_index >> 24) & 0xFF);
  block[block.size() - 3] = static_cast<uint8_t>((block_index >> 16) & 0xFF);
  block[block.size() - 2] = static_cast<uint8_t>((block_index >> 8) & 0xFF);
  block[block.size() - 1] = static_cast<uint8_t>(block_index & 0xFF);
  security::Zeroizer::ScopeWiper block_guard(std::span<uint8_t>(block.data(), block.size()));

  auto u = HMAC_SHA256::Compute(password, std::span<const uint8_t>(block.data(), block.size()));
  security::Zeroizer::ScopeWiper u_guard(std::span<uint8_t>(u.data(), u.size()));
  output = u;
  auto iter = u;
  security::Zeroizer::ScopeWiper iter_guard(std::span<uint8_t>(iter.data(), iter.size()));

  if (progress) {
    progress(1, iterations);
  }

  for (uint32_t i = 1; i < iterations; ++i) {
    iter = HMAC_SHA256::Compute(password, std::span<const uint8_t>(iter.data(), iter.size()));
    for (size_t j = 0; j < output.size(); ++j) {
      output[j] ^= iter[j];
    }

    if (progress && ((i + 1) % 10'000 == 0)) {
      progress(i + 1, iterations);
    }
  }

  if (progress && (iterations % 10'000 != 0)) {
    progress(iterations, iterations);
  }

  output_guard.Release();
  return output;
}

}  // namespace qv::crypto

