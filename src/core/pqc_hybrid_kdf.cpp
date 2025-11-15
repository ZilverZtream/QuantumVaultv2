#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/aes_gcm.h"
#include "qv/error.h"
#include <algorithm>
#include <array> // TSK014
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <string_view> // TSK432_Crypto_Hybrid_KDF labeled HKDF helper
#include <vector>

#include "qv/crypto/hkdf.h" // TSK106_Cryptographic_Implementation_Weaknesses
#include "qv/crypto/random.h" // TSK106_Cryptographic_Implementation_Weaknesses

// TSK_CRIT_10: liboqs is now a required dependency for PQC security
#if !defined(QV_USE_STUB_CRYPTO) && __has_include(<oqs/oqs.h>)
#define QV_HAVE_LIBOQS 1
#include <oqs/oqs.h>
#else
#define QV_HAVE_LIBOQS 0
// TSK_CRIT_10: Fail build if liboqs is not available
#error "liboqs is required for PQC security. Install liboqs and configure with -DQV_HAVE_LIBOQS=1 or disable PQC entirely."
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
constexpr std::string_view kClassicalLabel = "QV-HYBRID-CLASSICAL/v1"; // TSK432_Crypto_Hybrid_KDF labeled HKDF inputs
constexpr std::string_view kPqcLabel = "QV-HYBRID-PQC/v1";             // TSK432_Crypto_Hybrid_KDF labeled HKDF inputs

void RandomBytes(std::span<uint8_t> out) {
  qv::crypto::SystemRandomBytes(out); // TSK106_Cryptographic_Implementation_Weaknesses
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

void AppendContribution(std::vector<uint8_t>& buffer, std::string_view label,
                        std::span<const uint8_t> data) { // TSK432_Crypto_Hybrid_KDF length-delimited contributions
  const uint16_t length = static_cast<uint16_t>(data.size());
  buffer.insert(buffer.end(), label.begin(), label.end());
  buffer.push_back(static_cast<uint8_t>(length >> 8));
  buffer.push_back(static_cast<uint8_t>(length & 0xFF));
  buffer.insert(buffer.end(), data.begin(), data.end());
}

} // namespace

PQCKeyEncapsulation::KeyPair PQCKeyEncapsulation::GenerateKeypair() {
  KeyPair kp;
  // TSK_CRIT_04: Enforce strict locking for PQC secret keys
  kp.sk.RequireLocking();
  // TSK_CRIT_10: No fallback - liboqs is required
  auto kem = MakeKem();
  auto sk_span = kp.sk.AsSpan();
  if (OQS_KEM_keypair(kem.get(), kp.pk.data(), sk_span.data()) != OQS_SUCCESS) {
    throw Error(ErrorDomain::Crypto, -1, "OQS_KEM_keypair failed");
  }
  return kp;
}

PQCKeyEncapsulation::EncapsulationResult
PQCKeyEncapsulation::Encapsulate(const std::array<uint8_t, PQC::PUBLIC_KEY_SIZE>& pk) {
  EncapsulationResult r{};
  // TSK_CRIT_10: No fallback - liboqs is required
  auto kem = MakeKem();
  if (OQS_KEM_encaps(kem.get(), r.ciphertext.data(), r.shared_secret.data(), pk.data()) !=
      OQS_SUCCESS) {
    throw Error(ErrorDomain::Crypto, -1, "OQS_KEM_encaps failed");
  }
  return r;
}

std::array<uint8_t, PQC::SHARED_SECRET_SIZE>
PQCKeyEncapsulation::Decapsulate(std::span<const uint8_t, PQC::SECRET_KEY_SIZE> sk,
                                 std::span<const uint8_t, PQC::CIPHERTEXT_SIZE> ct) {
  std::array<uint8_t, PQC::SHARED_SECRET_SIZE> ss{};
  // TSK_CRIT_10: No fallback - liboqs is required
  auto kem = MakeKem();
  if (OQS_KEM_decaps(kem.get(), ss.data(), ct.data(), sk.data()) != OQS_SUCCESS) {
    throw AuthenticationFailureError(
        "Failed to authenticate PQC secret key"); // TSK719_Crypto_Side_Channel_KEM_Failure ensure indistinguishable failure
  }
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

  auto aad = MakeStableAad(volume_uuid, header_version, epoch_tlv);
  ByteScopeWiper aad_guard(std::span<uint8_t>(aad.data(), aad.size())); // TSK125_Missing_Secure_Deletion_for_Keys scoped AAD wipe

  // TSK_CRIT_03: Decrypt directly into SecureBuffer to avoid PQC key in pageable memory
  SecureBuffer<uint8_t> sk_plain_secure(PQC::SECRET_KEY_SIZE);
  // TSK_CRIT_04: Enforce strict locking for PQC secret key
  sk_plain_secure.RequireLocking();

  try {
    AES256_GCM_Decrypt_Secure(
        std::span<const uint8_t>(kem_blob.sk_encrypted.data(), kem_blob.sk_encrypted.size()),
        aad,
        std::span<const uint8_t, AES256_GCM::NONCE_SIZE>(kem_blob.sk_nonce.data(), kem_blob.sk_nonce.size()),
        std::span<const uint8_t, AES256_GCM::TAG_SIZE>(kem_blob.sk_tag.data(), kem_blob.sk_tag.size()),
        classical_key,
        sk_plain_secure);
  } catch (const AuthenticationFailureError&) {
    throw;
  } catch (const std::exception& ex) {
    throw AuthenticationFailureError(std::string("Failed to decrypt PQC secret key: ") + ex.what());
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
  std::vector<uint8_t> labeled_ikm; // TSK432_Crypto_Hybrid_KDF
  labeled_ikm.reserve(kClassicalLabel.size() + kPqcLabel.size() + 4 +
                      classical_key.size() + pqc_shared_secret.size());

  AppendContribution(labeled_ikm, kClassicalLabel,
                     std::span<const uint8_t>(classical_key.data(), classical_key.size()));
  AppendContribution(labeled_ikm, kPqcLabel,
                     std::span<const uint8_t>(pqc_shared_secret.data(), pqc_shared_secret.size()));
  ByteScopeWiper ikm_guard(labeled_ikm.data(), labeled_ikm.size());

  const std::string info_label = std::string("QV-HYBRID/v4.1|") + FormatUuid(volume_uuid);
  const std::span<const uint8_t> info_span(
      reinterpret_cast<const uint8_t*>(info_label.data()), info_label.size());

  return qv::crypto::HKDF_SHA256(
      std::span<const uint8_t>(labeled_ikm.data(), labeled_ikm.size()), salt,
      info_span); // TSK106_Cryptographic_Implementation_Weaknesses
}
