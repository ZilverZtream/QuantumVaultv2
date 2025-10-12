#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/aes_gcm.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/crypto/sha256.h"
#include <random>

using namespace qv;
using namespace qv::core;
using qv::security::SecureBuffer;
using qv::security::Zeroizer;
using namespace qv::crypto;

static void RandomBytes(std::span<uint8_t> out) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(0, 255);
  for (auto& b : out) b = static_cast<uint8_t>(dist(gen));
}

PQCKeyEncapsulation::KeyPair PQCKeyEncapsulation::GenerateKeypair() {
  KeyPair kp;
  // Random fill for skeleton; replace with real ML-KEM.
  std::span<uint8_t> sk_span = kp.sk.AsSpan();
  RandomBytes({kp.pk.data(), kp.pk.size()});
  RandomBytes(sk_span);
  return kp;
}
PQCKeyEncapsulation::EncapsulationResult
PQCKeyEncapsulation::Encapsulate(const std::array<uint8_t, PQC::PUBLIC_KEY_SIZE>& pk) {
  EncapsulationResult r;
  (void)pk;
  RandomBytes({r.ciphertext.data(), r.ciphertext.size()});
  RandomBytes({r.shared_secret.data(), r.shared_secret.size()});
  return r;
}
std::array<uint8_t, PQC::SHARED_SECRET_SIZE>
PQCKeyEncapsulation::Decapsulate(std::span<const uint8_t, PQC::SECRET_KEY_SIZE> sk,
                                 std::span<const uint8_t, PQC::CIPHERTEXT_SIZE> ct) {
  std::array<uint8_t, PQC::SHARED_SECRET_SIZE> ss{};
  // Dummy deterministic derivation for skeleton (hash of ct + first bytes of sk)
  std::vector<uint8_t> buf(ct.size() + 32);
  std::memcpy(buf.data(), ct.data(), ct.size());
  std::memcpy(buf.data()+ct.size(), sk.data(), 32);
  auto h = SHA256_Hash(buf);
  std::memcpy(ss.data(), h.data(), ss.size());
  return ss;
}

PQCHybridKDF::CreationResult
PQCHybridKDF::Create(std::span<const uint8_t,32> classical_key,
                     std::span<const uint8_t> salt) {
  PQCKeyEncapsulation kem;
  auto kp = kem.GenerateKeypair();
  auto enc = kem.Encapsulate(kp.pk);

  std::array<uint8_t,12> sk_nonce{}; RandomBytes({sk_nonce.data(), sk_nonce.size()});
  std::array<uint8_t,16> sk_tag{};
  std::vector<uint8_t> sk_enc_vec;
  AES256_GCM_Encrypt(kp.sk.AsSpan(), {}, sk_nonce, classical_key, sk_enc_vec, sk_tag);
  std::array<uint8_t, PQC::SECRET_KEY_SIZE> sk_encrypted{};
  std::memcpy(sk_encrypted.data(), sk_enc_vec.data(),
              std::min(sk_encrypted.size(), sk_enc_vec.size()));

  auto hybrid_key = DeriveHybridKey(classical_key, enc.shared_secret, salt);

  // wipe
  Zeroizer::Wipe(kp.sk.AsSpan());
  Zeroizer::Wipe({enc.shared_secret.data(), enc.shared_secret.size()});

  return CreationResult{
    .kem_ciphertext = enc.ciphertext,
    .sk_nonce = sk_nonce,
    .sk_encrypted = sk_encrypted,
    .sk_tag = sk_tag,
    .hybrid_key = hybrid_key
  };
}

std::array<uint8_t, 32>
PQCHybridKDF::Mount(std::span<const uint8_t,32> classical_key,
                    std::span<const uint8_t> kem_ct,
                    std::span<const uint8_t> sk_enc,
                    std::span<const uint8_t,12> sk_nonce,
                    std::span<const uint8_t,16> sk_tag,
                    std::span<const uint8_t> salt) {
  // 1) Decrypt secret key
  std::vector<uint8_t> sk_plain;
  if (!AES256_GCM_Decrypt(sk_enc, {}, sk_nonce, sk_tag, classical_key, sk_plain)) {
    throw AuthenticationFailureError("Failed to decrypt PQC secret key");
  }
  if (sk_plain.size() < PQC::SECRET_KEY_SIZE) {
    sk_plain.resize(PQC::SECRET_KEY_SIZE);
  }
  // 2) Decapsulate
  PQCKeyEncapsulation kem;
  auto ss = kem.Decapsulate({sk_plain.data(), PQC::SECRET_KEY_SIZE},
                            {kem_ct.data(), PQC::CIPHERTEXT_SIZE});
  // 3) HKDF-like combo (placeholder using HMAC over concatenation + salt)
  auto hybrid = DeriveHybridKey(classical_key, ss, salt);
  // wipe
  Zeroizer::Wipe({sk_plain.data(), sk_plain.size()});
  Zeroizer::Wipe({ss.data(), ss.size()});
  return hybrid;
}

std::array<uint8_t, 32>
PQCHybridKDF::DeriveHybridKey(std::span<const uint8_t,32> classical_key,
                              std::span<const uint8_t,32> pqc_shared_secret,
                              std::span<const uint8_t> salt) {
  std::array<uint8_t,64> ikm{};
  std::memcpy(ikm.data(), classical_key.data(), 32);
  std::memcpy(ikm.data()+32, pqc_shared_secret.data(), 32);
  // "HKDF-Extract": HMAC(salt, ikm)
  auto prk = HMAC_SHA256::Compute(salt, {ikm.data(), ikm.size()});
  // "HKDF-Expand": HMAC(prk, info || 0x01)
  static const char info[] = "QV-HYBRID-v4.1";
  std::vector<uint8_t> expand(sizeof(info) + 1);
  std::memcpy(expand.data()+0, info, sizeof(info));
  expand.back() = 0x01;
  auto okm = HMAC_SHA256::Compute({prk.data(), prk.size()},
                                  {expand.data(), expand.size()});
  std::array<uint8_t,32> out{};
  std::memcpy(out.data(), okm.data(), out.size());
  // wipe
  qv::security::Zeroizer::Wipe({ikm.data(), ikm.size()});
  qv::security::Zeroizer::Wipe({prk.data(), prk.size()});
  return out;
}
