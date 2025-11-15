#include "qv/orchestrator/volume_manager.h"
#include "qv/orchestrator/event_bus.h"
#include "qv/core/nonce.h"
#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/common.h"
#include "qv/error.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if defined(QV_USE_STUB_CRYPTO) || !QV_HAVE_LIBOQS
int main() {
  std::cout << "qv_volume_rekey_test skipped: PQC backend unavailable\n"; // TSK942_PQC_Liboqs_Optional_Build skip message
  return 0;
}
#else

namespace {
constexpr std::array<uint8_t, 8> kMagic = {'Q', 'V', 'A', 'U', 'L', 'T', '\0', '\0'}; // TSK071_Epoch_Overflow_Safety
constexpr uint16_t kTlvTypePbkdf2 = 0x1001;
constexpr uint16_t kTlvTypeHybridSalt = 0x1002;
constexpr uint16_t kTlvTypeEpoch = 0x4E4F;
constexpr uint16_t kTlvTypePqc = 0x7051;
constexpr uint16_t kTlvTypeReservedV2 = 0x7F02;
constexpr size_t kPbkdfSaltSize = 16;
constexpr size_t kHybridSaltSize = 32;
constexpr uint32_t kPbkdfIterations = 2000; // TSK071_Epoch_Overflow_Safety deterministic workload

#if defined(_MSC_VER)
constexpr uint16_t ToLittleEndian16(uint16_t value) {
  return qv::kIsLittleEndian ? value : _byteswap_ushort(value);
}
#elif defined(__clang__) || defined(__GNUC__)
constexpr uint16_t ToLittleEndian16(uint16_t value) {
  return qv::kIsLittleEndian ? value : __builtin_bswap16(value);
}
#else
constexpr uint16_t ToLittleEndian16(uint16_t value) {
  if (qv::kIsLittleEndian) {
    return value;
  }
  return static_cast<uint16_t>(((value & 0xFF) << 8) | ((value >> 8) & 0xFF));
}
#endif

#pragma pack(push, 1)
struct VolumeHeader {
  std::array<uint8_t, 8> magic{};
  uint32_t version{};
  std::array<uint8_t, 16> uuid{};
  uint32_t flags{};
};

struct ReservedV2Tlv {
  uint16_t type = ToLittleEndian16(kTlvTypeReservedV2);
  uint16_t length = ToLittleEndian16(32);
  std::array<uint8_t, 32> payload{};
};
#pragma pack(pop)

std::array<uint8_t, 32> DeriveKey(const std::string& password,
                                  uint32_t iterations,
                                  const std::array<uint8_t, kPbkdfSaltSize>& salt) {
  std::vector<uint8_t> pw(password.begin(), password.end());
  std::array<uint8_t, 32> out{};
  std::array<uint8_t, 20> block{};
  std::memcpy(block.data(), salt.data(), salt.size());
  block[16] = 0;
  block[17] = 0;
  block[18] = 0;
  block[19] = 1;
  auto u = qv::crypto::HMAC_SHA256::Compute(pw, std::span<const uint8_t>(block.data(), block.size()));
  out = u;
  auto iter = u;
  for (uint32_t i = 1; i < iterations; ++i) {
    iter = qv::crypto::HMAC_SHA256::Compute(pw, std::span<const uint8_t>(iter.data(), iter.size()));
    for (size_t j = 0; j < out.size(); ++j) {
      out[j] ^= iter[j];
    }
  }
  return out;
}

void AppendRaw(std::vector<uint8_t>& out, const void* data, size_t size) {
  const auto* bytes = static_cast<const uint8_t*>(data);
  out.insert(out.end(), bytes, bytes + size);
}

void AppendRaw(std::vector<uint8_t>& out, std::span<const uint8_t> bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}

void AppendUint16(std::vector<uint8_t>& out, uint16_t value) {
  const uint16_t le = ToLittleEndian16(value);
  AppendRaw(out, &le, sizeof(le));
}

void AppendUint32(std::vector<uint8_t>& out, uint32_t value) {
  const uint32_t le = qv::ToLittleEndian(value);
  AppendRaw(out, &le, sizeof(le));
}

std::array<uint8_t, 32> DeriveHeaderMacKey(const std::array<uint8_t, 32>& hybrid_key,
                                           const VolumeHeader& header) {
  auto prk = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(header.uuid.data(), header.uuid.size()),
      std::span<const uint8_t>(hybrid_key.data(), hybrid_key.size()));
  static constexpr std::string_view kInfo{"QV-HEADER-MAC/v1"};
  std::array<uint8_t, kInfo.size() + 1> info_block{};
  std::memcpy(info_block.data(), kInfo.data(), kInfo.size());
  info_block[kInfo.size()] = 0x01;
  auto okm = qv::crypto::HMAC_SHA256::Compute(std::span<const uint8_t>(prk.data(), prk.size()),
                                              std::span<const uint8_t>(info_block.data(), info_block.size()));
  return okm;
}

void WriteContainerWithEpoch(const std::filesystem::path& p,
                             const std::string& password,
                             uint32_t epoch_value) { // TSK071_Epoch_Overflow_Safety controlled epoch
  VolumeHeader header{};
  header.magic = kMagic;
  header.version = qv::ToLittleEndian(qv::orchestrator::VolumeManager::kLatestHeaderVersion);
  header.flags = qv::ToLittleEndian(0);
  for (size_t i = 0; i < header.uuid.size(); ++i) {
    header.uuid[i] = static_cast<uint8_t>(0xA0 + i);
  }

  std::array<uint8_t, kPbkdfSaltSize> pbkdf_salt{};
  for (size_t i = 0; i < pbkdf_salt.size(); ++i) {
    pbkdf_salt[i] = static_cast<uint8_t>(i + 1);
  }

  std::array<uint8_t, kHybridSaltSize> hybrid_salt{};
  for (size_t i = 0; i < hybrid_salt.size(); ++i) {
    hybrid_salt[i] = static_cast<uint8_t>(i ^ 0x5A);
  }

  auto classical = DeriveKey(password, kPbkdfIterations, pbkdf_salt);

  auto epoch_tlv = qv::core::MakeEpochTlv(epoch_value);
  auto hybrid = qv::core::PQCHybridKDF::Create(
      std::span<const uint8_t, 32>(classical.data(), classical.size()),
      std::span<const uint8_t>(hybrid_salt.data(), hybrid_salt.size()),
      std::span<const uint8_t, 16>(header.uuid),
      qv::orchestrator::VolumeManager::kLatestHeaderVersion,
      qv::AsBytesConst(epoch_tlv));

  auto pqc_blob = hybrid.kem_blob;
  pqc_blob.type = ToLittleEndian16(kTlvTypePqc);
  pqc_blob.length = ToLittleEndian16(static_cast<uint16_t>(sizeof(qv::core::PQC_KEM_TLV) - 4));
  pqc_blob.version = ToLittleEndian16(pqc_blob.version);
  pqc_blob.kem_id = ToLittleEndian16(pqc_blob.kem_id);

  std::vector<uint8_t> serialized;
  serialized.reserve(512);
  AppendRaw(serialized, &header, sizeof(header));

  AppendUint16(serialized, kTlvTypePbkdf2);
  AppendUint16(serialized, static_cast<uint16_t>(4 + pbkdf_salt.size()));
  AppendUint32(serialized, kPbkdfIterations);
  AppendRaw(serialized, pbkdf_salt.data(), pbkdf_salt.size());

  AppendUint16(serialized, kTlvTypeHybridSalt);
  AppendUint16(serialized, static_cast<uint16_t>(hybrid_salt.size()));
  AppendRaw(serialized, hybrid_salt.data(), hybrid_salt.size());

  AppendRaw(serialized, qv::AsBytesConst(epoch_tlv));
  AppendRaw(serialized, &pqc_blob, sizeof(pqc_blob));

  ReservedV2Tlv reserved{};
  AppendRaw(serialized, &reserved, sizeof(reserved));

  auto mac_key = DeriveHeaderMacKey(hybrid.hybrid_key, header);
  auto mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(serialized.data(), serialized.size()));
  AppendRaw(serialized, mac.data(), mac.size());

  std::ofstream out(p, std::ios::binary);
  out.write(reinterpret_cast<const char*>(serialized.data()), static_cast<std::streamsize>(serialized.size()));
}

uint32_t ExtractEpoch(const std::filesystem::path& p) { // TSK071_Epoch_Overflow_Safety validate increment
  std::ifstream in(p, std::ios::binary);
  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  if (blob.size() < sizeof(VolumeHeader) + qv::crypto::HMAC_SHA256::TAG_SIZE) {
    return 0;
  }
  size_t mac_offset = blob.size() - qv::crypto::HMAC_SHA256::TAG_SIZE;
  size_t offset = sizeof(VolumeHeader);
  while (offset + sizeof(uint16_t) * 2 <= mac_offset) {
    uint16_t type_le;
    std::memcpy(&type_le, blob.data() + offset, sizeof(type_le));
    offset += sizeof(type_le);
    uint16_t type = qv::ToLittleEndian(type_le);
    uint16_t length_le;
    std::memcpy(&length_le, blob.data() + offset, sizeof(length_le));
    offset += sizeof(length_le);
    uint16_t length = qv::ToLittleEndian(length_le);
    if (type == kTlvTypeEpoch) {
      assert(length == sizeof(uint32_t) && "epoch TLV length mismatch");
      uint32_t epoch_le;
      std::memcpy(&epoch_le, blob.data() + offset, sizeof(epoch_le));
      return qv::ToLittleEndian(epoch_le);
    }
    offset += length;
  }
  return 0;
}

void TestWarnOnOverflowMargin() { // TSK071_Epoch_Overflow_Safety warning path
  const std::string password = "correct horse battery staple";
  auto container = std::filesystem::temp_directory_path() / "qv_volume_rekey_warn.vol";
  WriteContainerWithEpoch(container, password, qv::core::EpochOverflowWarningThreshold());

  qv::orchestrator::VolumeManager::KdfPolicy policy{};
  policy.algorithm = qv::orchestrator::VolumeManager::PasswordKdf::kPbkdf2;
  policy.iteration_override = kPbkdfIterations;
  qv::orchestrator::VolumeManager manager(policy);

  std::vector<qv::orchestrator::Event> events;
  qv::orchestrator::EventBus::Instance().Subscribe(
      [&](const qv::orchestrator::Event& event) { events.push_back(event); });

  auto handle = manager.Rekey(container, password, password);
  assert(handle.has_value() && "rekey should succeed under warning threshold");
  auto updated_epoch = ExtractEpoch(container);
  assert(updated_epoch == qv::core::EpochOverflowWarningThreshold() + 1 &&
         "epoch must increment after rekey");

  bool saw_warning = false;
  bool saw_rekey = false;
  for (const auto& event : events) {
    if (event.event_id == "volume_epoch_near_overflow") {
      saw_warning = true;
      assert(event.severity == qv::orchestrator::EventSeverity::kWarning &&
             "warning severity expected");
    }
    if (event.event_id == "volume_rekeyed") {
      saw_rekey = true;
    }
  }
  assert(saw_warning && "warning event must be emitted near overflow margin");
  assert(saw_rekey && "rekey event must be emitted on success");

  std::filesystem::remove(container);
}

void TestRefuseUnsafeRekey() { // TSK071_Epoch_Overflow_Safety refusal path
  const std::string password = "correct horse battery staple";
  auto container = std::filesystem::temp_directory_path() / "qv_volume_rekey_refuse.vol";
  WriteContainerWithEpoch(container, password, qv::core::EpochOverflowUnsafeThreshold());

  qv::orchestrator::VolumeManager::KdfPolicy policy{};
  policy.algorithm = qv::orchestrator::VolumeManager::PasswordKdf::kPbkdf2;
  policy.iteration_override = kPbkdfIterations;
  qv::orchestrator::VolumeManager manager(policy);

  std::vector<qv::orchestrator::Event> events;
  qv::orchestrator::EventBus::Instance().Subscribe(
      [&](const qv::orchestrator::Event& event) { events.push_back(event); });

  bool threw = false;
  try {
    auto handle = manager.Rekey(container, password, password);
    (void)handle;
  } catch (const qv::Error& err) {
    threw = (err.domain == qv::ErrorDomain::State);
  }
  assert(threw && "rekey must fail when epoch is unsafe to increment");

  bool saw_refusal = false;
  for (const auto& event : events) {
    if (event.event_id == "volume_epoch_rekey_refused") {
      saw_refusal = true;
      assert(event.severity == qv::orchestrator::EventSeverity::kError &&
             "refusal must be reported as error");
    }
  }
  assert(saw_refusal && "refusal telemetry must be emitted");

  std::filesystem::remove(container);
}

} // namespace

int main() {
  TestWarnOnOverflowMargin();
  TestRefuseUnsafeRekey();
  std::cout << "volume rekey tests ok\n";
  return 0;
}

#endif // TSK942_PQC_Liboqs_Optional_Build conditional PQC test
