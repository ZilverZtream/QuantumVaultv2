#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/aes_gcm.h"
#include "qv/error.h"
#include <algorithm>
#include <array> // TSK014
#include <cstring>
#include <iomanip>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#if !defined(QV_USE_STUB_CRYPTO) && __has_include(<oqs/oqs.h>)
#define QV_HAVE_LIBOQS 1
#include <oqs/oqs.h>
#else
#define QV_HAVE_LIBOQS 0
#endif

#include <openssl/evp.h>
#include <openssl/kdf.h>

using namespace qv;
using namespace qv::core;
using qv::security::SecureBuffer;
using qv::security::Zeroizer;
using ByteScopeWiper = Zeroizer::ScopeWiper<uint8_t>; // TSK097_Cryptographic_Key_Management unified wiping helper
using qv::crypto::AES256_GCM;
using qv::crypto::AES256_GCM_Decrypt;
using qv::crypto::AES256_GCM_Encrypt;

namespace {

static constexpr uint16_t kKemIdMlKem768 = 0x0300; // TSK003
static constexpr std::array<uint8_t, 8> kPqcSkAadContext{'Q','V','P','Q','C','S','K','1'}; // TSK014

void RandomBytes(std::span<uint8_t> out) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(0, 255);
  for (auto& b : out) {
    b = static_cast<uint8_t>(dist(gen));
  }
}

#if QV_HAVE_LIBOQS
using KemPtr = std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)>;

KemPtr MakeKem() {
  OQS_KEM* raw = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!raw) {
    throw Error(ErrorDomain::Crypto, -1, "OQS_KEM_new(ML-KEM-768) failed");
  }
  return KemPtr(raw, &OQS_KEM_free);
}
#endif

std::string FormatUuid(std::span<const uint8_t, 16> uuid) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < uuid.size(); ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) {
      oss << '-';
    }
    oss << std::setw(2) << static_cast<int>(uuid[i]);
  }
  return oss.str();
}

std::vector<uint8_t> MakeStableAad(std::span<const uint8_t, 16> volume_uuid,
                                   uint32_t header_version,
                                   std::span<const uint8_t> epoch_tlv) {
  std::vector<uint8_t> aad;
  aad.reserve(kPqcSkAadContext.size() + volume_uuid.size() + sizeof(header_version) + epoch_tlv.size()); // TSK014
  aad.insert(aad.end(), kPqcSkAadContext.begin(), kPqcSkAadContext.end()); // TSK014
  aad.insert(aad.end(), volume_uuid.begin(), volume_uuid.end());
  const uint32_t version_le = ToLittleEndian(header_version);
  const uint8_t* version_bytes = reinterpret_cast<const uint8_t*>(&version_le);
  aad.insert(aad.end(), version_bytes, version_bytes + sizeof(version_le));
  aad.insert(aad.end(), epoch_tlv.begin(), epoch_tlv.end());
  return aad;
}

std::array<uint8_t, 32> HKDF_SHA256(std::span<const uint8_t> ikm,
                                    std::span<const uint8_t> salt,
                                    std::span<const uint8_t> info) {
  std::array<uint8_t, 32> out{};
  EVP_PKEY_CTX* raw_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!raw_ctx) {
    throw Error(ErrorDomain::Crypto, -1, "EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF) failed");
  }
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(raw_ctx, &EVP_PKEY_CTX_free);

  auto check = [](int status, const char* step) {
    if (status <= 0) {
      throw Error(ErrorDomain::Crypto, -1, std::string("HKDF step failed: ") + step);
    }
  };

  check(EVP_PKEY_derive_init(ctx.get()), "derive_init");
  check(EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()), "set_md");
  check(EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.empty() ? nullptr : salt.data(),
                                     static_cast<int>(salt.size())), "set_salt");
  check(EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm.data(), static_cast<int>(ikm.size())),
        "set_key");
  if (!info.empty()) {
    check(EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), static_cast<int>(info.size())),
          "set_info");
  }
  size_t len = out.size();
  check(EVP_PKEY_derive(ctx.get(), out.data(), &len), "derive");
  if (len != out.size()) {
    throw Error(ErrorDomain::Crypto, -1, "HKDF derive produced unexpected length");
  }
  return out;
}

} // namespace

PQCKeyEncapsulation::KeyPair PQCKeyEncapsulation::GenerateKeypair() {
  KeyPair kp;
#if !QV_HAVE_LIBOQS
  RandomBytes(std::span<uint8_t>(kp.pk.data(), kp.pk.size()));
  RandomBytes(kp.sk.AsSpan());
#else
  auto kem = MakeKem();
  auto sk_span = kp.sk.AsSpan();
  if (OQS_KEM_keypair(kem.get(), kp.pk.data(), sk_span.data()) != OQS_SUCCESS) {
    throw Error(ErrorDomain::Crypto, -1, "OQS_KEM_keypair failed");
  }
#endif
  return kp;
}

PQCKeyEncapsulation::EncapsulationResult
PQCKeyEncapsulation::Encapsulate(const std::array<uint8_t, PQC::PUBLIC_KEY_SIZE>& pk) {
  EncapsulationResult r{};
#if !QV_HAVE_LIBOQS
  (void)pk;
  RandomBytes(std::span<uint8_t>(r.ciphertext.data(), r.ciphertext.size()));
  RandomBytes(std::span<uint8_t>(r.shared_secret.data(), r.shared_secret.size()));
#else
  auto kem = MakeKem();
  if (OQS_KEM_encaps(kem.get(), r.ciphertext.data(), r.shared_secret.data(), pk.data()) !=
      OQS_SUCCESS) {
    throw Error(ErrorDomain::Crypto, -1, "OQS_KEM_encaps failed");
  }
#endif
  return r;
}

std::array<uint8_t, PQC::SHARED_SECRET_SIZE>
PQCKeyEncapsulation::Decapsulate(std::span<const uint8_t, PQC::SECRET_KEY_SIZE> sk,
                                 std::span<const uint8_t, PQC::CIPHERTEXT_SIZE> ct) {
  std::array<uint8_t, PQC::SHARED_SECRET_SIZE> ss{};
#if !QV_HAVE_LIBOQS
  (void)sk;
  (void)ct;
  RandomBytes(std::span<uint8_t>(ss.data(), ss.size()));
#else
  auto kem = MakeKem();
  if (OQS_KEM_decaps(kem.get(), ss.data(), ct.data(), sk.data()) != OQS_SUCCESS) {
    throw Error(ErrorDomain::Crypto, -1, "OQS_KEM_decaps failed");
  }
#endif
  return ss;
}

PQCHybridKDF::CreationResult
PQCHybridKDF::Create(std::span<const uint8_t, 32> classical_key,
                     std::span<const uint8_t> salt,
                     std::span<const uint8_t, 16> volume_uuid,
                     uint32_t header_version,
                     std::span<const uint8_t> epoch_tlv) {
  PQCKeyEncapsulation kem;
  auto kp = kem.GenerateKeypair();
  ByteScopeWiper sk_guard(kp.sk.AsSpan());

  auto enc = kem.Encapsulate(kp.pk);
  ByteScopeWiper ss_guard(std::span<uint8_t>(enc.shared_secret.data(), enc.shared_secret.size()));

  PQC_KEM_TLV tlv{};
  tlv.type = 0x7051;
  tlv.length = static_cast<uint16_t>(sizeof(PQC_KEM_TLV) - 4);
  tlv.version = PQC::KEM_TLV_VERSION;
  tlv.kem_id = kKemIdMlKem768;
  tlv.kem_ct = enc.ciphertext;

  RandomBytes(std::span<uint8_t>(tlv.sk_nonce.data(), tlv.sk_nonce.size()));

  const auto aad = MakeStableAad(volume_uuid, header_version, epoch_tlv);
  auto enc_result = AES256_GCM_Encrypt(kp.sk.AsSpan(), aad,
      std::span<const uint8_t, AES256_GCM::NONCE_SIZE>(tlv.sk_nonce.data(), tlv.sk_nonce.size()),
      classical_key);
  if (enc_result.ciphertext.size() != PQC::SECRET_KEY_SIZE) {
    throw Error(ErrorDomain::Crypto, -1, "Unexpected PQC secret key ciphertext length");
  }
  std::copy(enc_result.ciphertext.begin(), enc_result.ciphertext.end(), tlv.sk_encrypted.begin());
  tlv.sk_tag = enc_result.tag;

  auto hybrid_key = DeriveHybridKey(classical_key,
      std::span<const uint8_t, PQC::SHARED_SECRET_SIZE>(enc.shared_secret.data(),
                                                        enc.shared_secret.size()),
      salt,
      volume_uuid);

  CreationResult result{};
  result.kem_blob = tlv;
  result.hybrid_key = hybrid_key;
  return result;
}

std::array<uint8_t, 32>
PQCHybridKDF::Mount(std::span<const uint8_t, 32> classical_key,
                    const PQC_KEM_TLV& kem_blob,
                    std::span<const uint8_t> salt,
                    std::span<const uint8_t, 16> volume_uuid,
                    uint32_t header_version,
                    std::span<const uint8_t> epoch_tlv) {
  if (kem_blob.version != PQC::KEM_TLV_VERSION) {
    throw Error(ErrorDomain::Validation, -1, "Unsupported PQC KEM TLV version");
  }
  if (kem_blob.kem_id != kKemIdMlKem768) {
    throw Error(ErrorDomain::Validation, -1, "Unsupported PQC KEM identifier");
  }

  const auto aad = MakeStableAad(volume_uuid, header_version, epoch_tlv);

  std::vector<uint8_t> sk_plain;
  try {
    sk_plain = AES256_GCM_Decrypt(
        std::span<const uint8_t>(kem_blob.sk_encrypted.data(), kem_blob.sk_encrypted.size()),
        aad,
        std::span<const uint8_t, AES256_GCM::NONCE_SIZE>(kem_blob.sk_nonce.data(), kem_blob.sk_nonce.size()),
        std::span<const uint8_t, AES256_GCM::TAG_SIZE>(kem_blob.sk_tag.data(), kem_blob.sk_tag.size()),
        classical_key);
  } catch (const AuthenticationFailureError&) {
    Zeroizer::WipeVector(sk_plain); // TSK097_Cryptographic_Key_Management wipe transient buffer on auth failure
    throw;
  } catch (const std::exception& ex) {
    Zeroizer::WipeVector(sk_plain); // TSK097_Cryptographic_Key_Management wipe transient buffer on generic failure
    throw AuthenticationFailureError(std::string("Failed to decrypt PQC secret key: ") + ex.what());
  }
  if (sk_plain.size() != PQC::SECRET_KEY_SIZE) {
    Zeroizer::WipeVector(sk_plain); // TSK097_Cryptographic_Key_Management wipe rejected plaintext
    throw Error(ErrorDomain::Validation, -1, "PQC secret key length mismatch");
  }
  SecureBuffer<uint8_t> sk_plain_secure(sk_plain.size()); // TSK097_Cryptographic_Key_Management secure PQC secret key buffer
  if (!sk_plain.empty()) {
    std::memcpy(sk_plain_secure.data(), sk_plain.data(), sk_plain.size());
    Zeroizer::WipeVector(sk_plain); // TSK097_Cryptographic_Key_Management wipe temporary decrypt buffer
  }
  ByteScopeWiper sk_plain_guard(sk_plain_secure.AsSpan());

  PQCKeyEncapsulation kem;
  auto shared_secret = kem.Decapsulate(
      std::span<const uint8_t, PQC::SECRET_KEY_SIZE>(sk_plain_secure.data(), PQC::SECRET_KEY_SIZE),
      std::span<const uint8_t, PQC::CIPHERTEXT_SIZE>(kem_blob.kem_ct.data(),
                                                     PQC::CIPHERTEXT_SIZE));
  ByteScopeWiper ss_guard(std::span<uint8_t>(shared_secret.data(), shared_secret.size()));

  return DeriveHybridKey(classical_key, shared_secret, salt, volume_uuid);
}

std::array<uint8_t, 32>
PQCHybridKDF::DeriveHybridKey(std::span<const uint8_t, 32> classical_key,
                              std::span<const uint8_t, 32> pqc_shared_secret,
                              std::span<const uint8_t> salt,
                              std::span<const uint8_t, 16> volume_uuid) {
  std::array<uint8_t, 64> ikm{};
  std::memcpy(ikm.data(), classical_key.data(), classical_key.size());
  std::memcpy(ikm.data() + classical_key.size(), pqc_shared_secret.data(),
              pqc_shared_secret.size());
  ByteScopeWiper ikm_guard(ikm.data(), ikm.size());

  const std::string info_label = std::string("QV-HYBRID/v4.1|") + FormatUuid(volume_uuid);
  const std::span<const uint8_t> info_span(
      reinterpret_cast<const uint8_t*>(info_label.data()), info_label.size());

  return HKDF_SHA256(std::span<const uint8_t>(ikm.data(), ikm.size()), salt, info_span);
}
