#include "qv/core/header_io.h"

// TSK712_Header_Backup_and_Restore_Tooling header IO regression tests

#include <cassert>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "qv/common.h"
#include "qv/core/nonce.h"
#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/aes_gcm.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/crypto/random.h"
#include "qv/error.h"
#include "qv/security/secure_buffer.h"
#include "qv/security/zeroizer.h"

#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2
#include <argon2.h>
#endif

namespace {

constexpr std::array<uint8_t, 8> kHeaderMagic = {'Q', 'V', 'A', 'U', 'L', 'T', '\0', '\0'}; // TSK712
constexpr uint32_t kHeaderVersion = 0x00040101u;                                             // TSK712
constexpr uint16_t kTlvTypeArgon2 = 0x1003;                                                  // TSK712
constexpr uint16_t kTlvTypeHybridSalt = 0x1002;                                              // TSK712
constexpr uint16_t kTlvTypePqc = 0x7051;                                                     // TSK712
constexpr uint16_t kTlvTypeReservedV2 = 0x7F02;                                              // TSK712
constexpr size_t kPbkdfSaltSize = 16;                                                        // TSK712
constexpr size_t kHybridSaltSize = 32;                                                       // TSK712
constexpr size_t kPasswordTlvBytes =
    4 + std::max<size_t>(4 + kPbkdfSaltSize, sizeof(uint32_t) * 6 + kPbkdfSaltSize);         // TSK712
constexpr size_t kSerializedHeaderBytes = sizeof(std::array<uint8_t, 8>) + sizeof(uint32_t) * 2 + 16 +
                                          kPasswordTlvBytes + 4 + kHybridSaltSize +
                                          sizeof(qv::core::EpochTLV) + sizeof(qv::core::PQC_KEM_TLV) +
                                          sizeof(uint16_t) * 2 + 32;                                                             // TSK712
constexpr size_t kHeaderMacSize = qv::crypto::HMAC_SHA256::TAG_SIZE;                         // TSK712
constexpr size_t kTotalHeaderBytes = kSerializedHeaderBytes + kHeaderMacSize;                // TSK712

struct VolumeHeader { // TSK712 local packed view
  std::array<uint8_t, 8> magic{};
  uint32_t version{0};
  std::array<uint8_t, 16> uuid{};
  uint32_t flags{0};
};

std::vector<uint8_t> BuildTestHeader(const std::array<uint8_t, 16>& uuid) { // TSK712 header constructor
  VolumeHeader header{};
  header.magic = kHeaderMagic;
  header.version = qv::ToLittleEndian(kHeaderVersion); // TSK712 test header little endian
  header.uuid = uuid;
  header.flags = qv::ToLittleEndian(0); // TSK712 test header little endian

  std::array<uint8_t, kHybridSaltSize> hybrid_salt{};
  qv::crypto::SystemRandomBytes(std::span<uint8_t>(hybrid_salt)); // TSK712 test harness entropy

  std::array<uint8_t, sizeof(uint32_t) * 6 + kPbkdfSaltSize> argon_payload{};
  auto write_field = [&](size_t index, uint32_t value) {
    const uint32_t le = qv::ToLittleEndian32(value);
    std::memcpy(argon_payload.data() + index * sizeof(uint32_t), &le, sizeof(le));
  };
  write_field(0, 1);
  write_field(1, 4);
  write_field(2, 128u * 1024u);
  write_field(3, 4);
  write_field(4, 32);
  write_field(5, 500);
  qv::crypto::SystemRandomBytes(std::span<uint8_t>(argon_payload.data() + sizeof(uint32_t) * 6, kPbkdfSaltSize)); // TSK712 test harness entropy

  auto epoch = qv::core::MakeEpochTlv(1);

  qv::core::PQC_KEM_TLV pqc{};
  pqc.type = qv::ToLittleEndian16(kTlvTypePqc);
  pqc.length = qv::ToLittleEndian16(static_cast<uint16_t>(sizeof(qv::core::PQC_KEM_TLV) - sizeof(uint16_t) * 2));
  pqc.version = qv::ToLittleEndian16(qv::core::PQC::KEM_TLV_VERSION);
  pqc.kem_id = qv::ToLittleEndian16(0x0300);

  std::array<uint8_t, sizeof(uint16_t) * 2 + kHybridSaltSize> hybrid_tlv{};
  const uint16_t hybrid_len = qv::ToLittleEndian16(static_cast<uint16_t>(kHybridSaltSize));
  const uint16_t hybrid_type = qv::ToLittleEndian16(kTlvTypeHybridSalt);
  std::memcpy(hybrid_tlv.data(), &hybrid_type, sizeof(hybrid_type));
  std::memcpy(hybrid_tlv.data() + sizeof(uint16_t), &hybrid_len, sizeof(hybrid_len));
  std::memcpy(hybrid_tlv.data() + sizeof(uint16_t) * 2, hybrid_salt.data(), hybrid_salt.size());

  std::vector<uint8_t> serialized;
  serialized.reserve(kSerializedHeaderBytes + kHeaderMacSize);
  serialized.insert(serialized.end(), reinterpret_cast<uint8_t*>(&header),
                    reinterpret_cast<uint8_t*>(&header) + sizeof(header));

  const uint16_t argon_type = qv::ToLittleEndian16(kTlvTypeArgon2);
  const uint16_t argon_length = qv::ToLittleEndian16(static_cast<uint16_t>(argon_payload.size()));
  serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&argon_type),
                    reinterpret_cast<const uint8_t*>(&argon_type) + sizeof(argon_type));
  serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&argon_length),
                    reinterpret_cast<const uint8_t*>(&argon_length) + sizeof(argon_length));
  serialized.insert(serialized.end(), argon_payload.begin(), argon_payload.end());

  serialized.insert(serialized.end(), hybrid_tlv.begin(), hybrid_tlv.end());
  const auto epoch_bytes = qv::AsBytesConst(epoch);
  serialized.insert(serialized.end(), epoch_bytes.begin(), epoch_bytes.end());

  serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&pqc),
                    reinterpret_cast<const uint8_t*>(&pqc) + sizeof(pqc));

  uint16_t reserved_type = qv::ToLittleEndian16(kTlvTypeReservedV2);
  uint16_t reserved_length = qv::ToLittleEndian16(32);
  std::array<uint8_t, 32> reserved_payload{};
  serialized.insert(serialized.end(), reinterpret_cast<uint8_t*>(&reserved_type),
                    reinterpret_cast<uint8_t*>(&reserved_type) + sizeof(reserved_type));
  serialized.insert(serialized.end(), reinterpret_cast<uint8_t*>(&reserved_length),
                    reinterpret_cast<uint8_t*>(&reserved_length) + sizeof(reserved_length));
  serialized.insert(serialized.end(), reserved_payload.begin(), reserved_payload.end());

  serialized.resize(kSerializedHeaderBytes, 0);
  serialized.resize(kTotalHeaderBytes, 0);
  return serialized;
}

qv::core::RecoveryKdfMetadata MakeRecoveryMetadata() { // TSK712 Argon2 params for tests
  qv::core::RecoveryKdfMetadata metadata{};
  metadata.params.time_cost = 4;
  metadata.params.memory_cost_kib = 128u * 1024u;
  metadata.params.parallelism = 4;
  qv::crypto::SystemRandomBytes(std::span<uint8_t>(metadata.salt)); // TSK712 test harness entropy
  return metadata;
}

qv::security::SecureBuffer<uint8_t> DeriveRecoveryKey(const std::string& password,
                                                     const qv::core::RecoveryKdfMetadata& metadata) { // TSK712
#if defined(QV_HAVE_ARGON2) && QV_HAVE_ARGON2
  qv::security::SecureBuffer<uint8_t> key(qv::crypto::AES256_GCM::KEY_SIZE);
  auto span = key.AsSpan();
  int rc = argon2id_hash_raw(metadata.params.time_cost, metadata.params.memory_cost_kib,
                             metadata.params.parallelism,
                             reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                             metadata.salt.data(), metadata.salt.size(), span.data(), span.size());
  if (rc != ARGON2_OK) {
    throw qv::Error{qv::ErrorDomain::Crypto, rc, "argon2id failed"};
  }
  return key;
#else
  (void)password;
  (void)metadata;
  throw qv::Error{qv::ErrorDomain::Dependency, 0, "Argon2 not available"};
#endif
}

std::filesystem::path TempDirectory() { // TSK712 scratch space helper
  auto base = std::filesystem::temp_directory_path() / "qv_header_io_test";
  std::filesystem::create_directories(base);
  return base;
}

void TestRoundTrip() { // TSK712
  auto temp = TempDirectory();
  auto container = temp / "container.bin";
  auto backup = temp / "container.bak";

  std::array<uint8_t, 16> uuid{};
  qv::crypto::SystemRandomBytes(std::span<uint8_t>(uuid)); // TSK712 test harness entropy
  auto header = BuildTestHeader(uuid);
  {
    std::ofstream out(container, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(header.data()), header.size());
  }

  std::string password = "recovery-secret";
  auto metadata = MakeRecoveryMetadata();
  auto key = DeriveRecoveryKey(password, metadata);
  qv::core::RecoveryKeyDescriptor descriptor;
  descriptor.key = std::move(key);
  descriptor.metadata = metadata;
  qv::core::BackupHeader(container, backup, descriptor);

  // Inspect metadata and ensure UUID matches.
  auto parsed = qv::core::InspectHeaderBackup(backup);
  assert(parsed.container.version == kHeaderVersion);
  assert(parsed.container.uuid == uuid);

  // Overwrite container to simulate loss.
  {
    std::ofstream out(container, std::ios::binary | std::ios::trunc);
    std::vector<uint8_t> zeros(header.size(), 0);
    out.write(reinterpret_cast<const char*>(zeros.data()), zeros.size());
  }

  auto restore_key = DeriveRecoveryKey(password, parsed.recovery);
  qv::core::RecoveryKeyDescriptor restore_desc;
  restore_desc.key = std::move(restore_key);
  restore_desc.metadata = parsed.recovery;
  qv::core::RestoreHeader(container, backup, restore_desc);

  std::vector<uint8_t> restored(header.size());
  {
    std::ifstream in(container, std::ios::binary);
    in.read(reinterpret_cast<char*>(restored.data()), restored.size());
  }
  assert(restored == header);

  std::filesystem::remove(container);
  std::filesystem::remove(backup);
}

void TestCorruptedTagFails() { // TSK712
  auto temp = TempDirectory();
  auto container = temp / "container_corrupt.bin";
  auto backup = temp / "container_corrupt.bak";

  std::array<uint8_t, 16> uuid{};
  qv::crypto::SystemRandomBytes(std::span<uint8_t>(uuid)); // TSK712 test harness entropy
  auto header = BuildTestHeader(uuid);
  {
    std::ofstream out(container, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(header.data()), header.size());
  }

  std::string password = "recovery-secret";
  auto metadata = MakeRecoveryMetadata();
  auto key = DeriveRecoveryKey(password, metadata);
  qv::core::RecoveryKeyDescriptor descriptor;
  descriptor.key = std::move(key);
  descriptor.metadata = metadata;
  qv::core::BackupHeader(container, backup, descriptor);

  // Corrupt the backup tag.
  {
    std::fstream io(backup, std::ios::in | std::ios::out | std::ios::binary);
    io.seekp(-1, std::ios::end);
    char byte = 0;
    io.get(byte);
    io.seekp(-1, std::ios::end);
    byte ^= 0xFF;
    io.put(byte);
  }

  auto parsed = qv::core::InspectHeaderBackup(backup);
  auto restore_key = DeriveRecoveryKey(password, parsed.recovery);
  qv::core::RecoveryKeyDescriptor restore_desc;
  restore_desc.key = std::move(restore_key);
  restore_desc.metadata = parsed.recovery;

  bool failed = false;
  try {
    qv::core::RestoreHeader(container, backup, restore_desc);
  } catch (const qv::AuthenticationFailureError&) {
    failed = true;
  }
  assert(failed && "Corrupted backup must fail authentication");

  std::filesystem::remove(container);
  std::filesystem::remove(backup);
}

}  // namespace

int main() { // TSK712
  TestRoundTrip();
  TestCorruptedTagFails();
  std::filesystem::remove_all(TempDirectory());
  return 0;
}

