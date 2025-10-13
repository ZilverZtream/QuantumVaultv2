#include "qv/orchestrator/constant_time_mount.h"
#include "qv/common.h"
#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/core/nonce.h"
#include "qv/crypto/hmac_sha256.h"
#include <array>
#include <cassert>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include <span>

namespace {
// TSK004 / TSK013
constexpr std::array<uint8_t, 8> kMagic = {'Q','V','A','U','L','T','\0','\0'};
constexpr uint32_t kVersion = 0x00040100;
constexpr uint16_t kTlvTypePbkdf2 = 0x1001;
constexpr uint16_t kTlvTypeHybridSalt = 0x1002;
constexpr uint16_t kTlvTypeEpoch = 0x4E4F;
constexpr uint16_t kTlvTypePqc = 0x7051;
constexpr uint16_t kTlvTypeReservedV2 = 0x7F02;
constexpr size_t kPbkdfSaltSize = 16;
constexpr size_t kHybridSaltSize = 32;

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

static_assert(sizeof(VolumeHeader) == 32, "unexpected header size");
static_assert(sizeof(ReservedV2Tlv) == 36, "reserved TLV size");

constexpr size_t kSerializedHeaderBytes = sizeof(VolumeHeader) + 4 + (4 + kPbkdfSaltSize) +
                                          4 + kHybridSaltSize + sizeof(qv::core::EpochTLV) +
                                          sizeof(qv::core::PQC_KEM_TLV) + sizeof(ReservedV2Tlv);
constexpr size_t kTotalHeaderBytes = kSerializedHeaderBytes + qv::crypto::HMAC_SHA256::TAG_SIZE;

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

void WriteValidContainer(const std::filesystem::path& p, const std::string& password) {
  VolumeHeader header{};
  header.magic = kMagic;
  header.version = qv::ToLittleEndian(kVersion);
  header.flags = qv::ToLittleEndian(0);
  for (size_t i = 0; i < header.uuid.size(); ++i) {
    header.uuid[i] = static_cast<uint8_t>(0xA0 + i);
  }

  const uint32_t iterations = 2000;
  std::array<uint8_t, kPbkdfSaltSize> pbkdf_salt{};
  for (size_t i = 0; i < pbkdf_salt.size(); ++i) {
    pbkdf_salt[i] = static_cast<uint8_t>(i + 1);
  }

  std::array<uint8_t, kHybridSaltSize> hybrid_salt{};
  for (size_t i = 0; i < hybrid_salt.size(); ++i) {
    hybrid_salt[i] = static_cast<uint8_t>(i ^ 0x5A);
  }

  auto classical = DeriveKey(password, iterations, pbkdf_salt);

  qv::core::EpochTLV epoch{};
  epoch.type = ToLittleEndian16(kTlvTypeEpoch);
  epoch.length = ToLittleEndian16(static_cast<uint16_t>(sizeof(epoch.epoch)));
  epoch.epoch = qv::ToLittleEndian(static_cast<uint32_t>(1));
  const auto epoch_bytes = qv::AsBytesConst(epoch);

  auto hybrid = qv::core::PQCHybridKDF::Create(std::span<const uint8_t, 32>(classical),
                                               std::span<const uint8_t>(hybrid_salt.data(), hybrid_salt.size()),
                                               std::span<const uint8_t, 16>(header.uuid),
                                               kVersion,
                                               epoch_bytes);

  auto pqc_blob = hybrid.kem_blob;
  pqc_blob.type = ToLittleEndian16(kTlvTypePqc);
  pqc_blob.length = ToLittleEndian16(static_cast<uint16_t>(sizeof(qv::core::PQC_KEM_TLV) - 4));
  pqc_blob.version = ToLittleEndian16(pqc_blob.version);
  pqc_blob.kem_id = ToLittleEndian16(pqc_blob.kem_id);

  std::vector<uint8_t> serialized;
  serialized.reserve(kSerializedHeaderBytes);
  AppendRaw(serialized, &header, sizeof(header));

  AppendUint16(serialized, kTlvTypePbkdf2);
  AppendUint16(serialized, static_cast<uint16_t>(4 + pbkdf_salt.size()));
  AppendUint32(serialized, iterations);
  AppendRaw(serialized, pbkdf_salt.data(), pbkdf_salt.size());

  AppendUint16(serialized, kTlvTypeHybridSalt);
  AppendUint16(serialized, static_cast<uint16_t>(hybrid_salt.size()));
  AppendRaw(serialized, hybrid_salt.data(), hybrid_salt.size());

  AppendRaw(serialized, epoch_bytes);

  AppendRaw(serialized, &pqc_blob, sizeof(pqc_blob));

  ReservedV2Tlv reserved{};
  AppendRaw(serialized, &reserved, sizeof(reserved));

  assert(serialized.size() == kSerializedHeaderBytes);

  auto mac_key = DeriveHeaderMacKey(hybrid.hybrid_key, header);
  auto mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(serialized.data(), serialized.size()));
  AppendRaw(serialized, mac.data(), mac.size());

  std::ofstream out(p, std::ios::binary);
  out.write(reinterpret_cast<const char*>(serialized.data()), static_cast<std::streamsize>(serialized.size()));
}

} // namespace

int main() {
  using qv::orchestrator::ConstantTimeMount;
  const std::string password = "correct horse battery staple";
  auto temp_dir = std::filesystem::temp_directory_path();
  auto container = temp_dir / "qv_ct_mount_test.vol";

  WriteValidContainer(container, password);

  ConstantTimeMount ctm;
  auto ok = ctm.Mount(container, password);
  (void)ok;
  assert(ok.has_value() && "expected mount to succeed with correct password");

  auto wrong = ctm.Mount(container, "wrong password");
  (void)wrong;
  assert(!wrong.has_value() && "mount should fail with incorrect password");

  auto tampered = container;
  {
    std::fstream f(tampered, std::ios::in | std::ios::out | std::ios::binary);
    auto pos = static_cast<std::streamoff>(kSerializedHeaderBytes / 2);
    f.seekp(pos);
    char flip;
    f.read(&flip, 1);
    flip ^= 0xFF;
    f.seekp(pos);
    f.write(&flip, 1);
  }
  auto tamper_result = ctm.Mount(container, password);
  (void)tamper_result;
  assert(!tamper_result.has_value() && "tampered container should not mount");

  std::filesystem::remove(container);
  auto missing = ctm.Mount(container, password);
  (void)missing;
  assert(!missing.has_value() && "missing container should fail to mount");

  std::cout << "constant-time mount tests ok\n";
  return 0;
}
