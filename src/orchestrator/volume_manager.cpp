#include "qv/orchestrator/volume_manager.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <random>
#include <span>
#include <string_view>
#include <vector>

#include "qv/common.h"
#include "qv/core/nonce.h"
#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/error.h"
#include "qv/security/zeroizer.h"

using namespace qv::orchestrator;

namespace {

constexpr std::array<char, 8> kVolumeMagic = {'Q','V','A','U','L','T','\0','\0'}; // TSK013
constexpr uint32_t kHeaderVersion = 0x00040100;                                      // TSK013
constexpr uint16_t kTlvTypePbkdf2 = 0x1001;                                          // TSK013
constexpr uint16_t kTlvTypeHybridSalt = 0x1002;                                      // TSK013
constexpr uint16_t kTlvTypeEpoch = 0x4E4F;                                           // matches EpochTLV
constexpr uint16_t kTlvTypePqcKem = 0x7051;
constexpr uint16_t kTlvTypeReservedV2 = 0x7F02;                                      // TSK013 reserved slot
constexpr uint32_t kDefaultFlags = 0;
constexpr uint32_t kDefaultPbkdfIterations = 200'000;                                // TSK013
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

struct VolumeHeader { // TSK013
  std::array<char, 8> magic = kVolumeMagic;
  uint32_t version = qv::ToLittleEndian(kHeaderVersion);
  std::array<uint8_t, 16> uuid{};
  uint32_t flags = qv::ToLittleEndian(kDefaultFlags);
};

#pragma pack(push, 1)
struct ReservedV2Tlv { // TSK013 migration shim
  uint16_t type = ToLittleEndian16(kTlvTypeReservedV2);
  uint16_t length = ToLittleEndian16(32);
  std::array<uint8_t, 32> payload{};
};
#pragma pack(pop)

static_assert(sizeof(VolumeHeader) == 32, "volume header must be 32 bytes");       // TSK013
static_assert(sizeof(ReservedV2Tlv) == 36, "reserved TLV layout unexpected");       // TSK013

void FillRandom(std::span<uint8_t> out) { // TSK013
  std::random_device rd;
  std::mt19937_64 gen(rd());
  for (size_t i = 0; i < out.size();) {
    auto value = gen();
    for (size_t j = 0; j < sizeof(value) && i < out.size(); ++j, ++i) {
      out[i] = static_cast<uint8_t>((value >> (j * 8)) & 0xFF);
    }
  }
}

std::array<uint8_t, 16> GenerateUuidV4() { // TSK013
  std::array<uint8_t, 16> uuid{};
  FillRandom(uuid);
  uuid[6] = static_cast<uint8_t>((uuid[6] & 0x0F) | 0x40);
  uuid[8] = static_cast<uint8_t>((uuid[8] & 0x3F) | 0x80);
  return uuid;
}

std::array<uint8_t, 32> DerivePasswordKey(std::span<const uint8_t> password,
                                          const std::array<uint8_t, kPbkdfSaltSize>& salt,
                                          uint32_t iterations) { // TSK013
  std::array<uint8_t, 32> output{};
  std::array<uint8_t, 20> block{};
  std::memcpy(block.data(), salt.data(), salt.size());
  block[16] = 0;
  block[17] = 0;
  block[18] = 0;
  block[19] = 1;

  auto u = qv::crypto::HMAC_SHA256::Compute(password,
                                            std::span<const uint8_t>(block.data(), block.size()));
  output = u;
  auto iter = u;
  for (uint32_t i = 1; i < iterations; ++i) {
    iter = qv::crypto::HMAC_SHA256::Compute(password,
                                            std::span<const uint8_t>(iter.data(), iter.size()));
    for (size_t j = 0; j < output.size(); ++j) {
      output[j] ^= iter[j];
    }
  }

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(iter.data(), iter.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(u.data(), u.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(block.data(), block.size()));
  return output;
}

std::array<uint8_t, 32> DeriveHeaderMacKey(const std::array<uint8_t, 32>& hybrid_key,
                                           const std::array<uint8_t, 16>& uuid) { // TSK013
  auto prk = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(uuid.data(), uuid.size()),
      std::span<const uint8_t>(hybrid_key.data(), hybrid_key.size()));
  static constexpr std::string_view kInfo{"QV-HEADER-MAC/v1"};
  std::array<uint8_t, kInfo.size() + 1> info_block{};
  std::memcpy(info_block.data(), kInfo.data(), kInfo.size());
  info_block[kInfo.size()] = 0x01;
  auto okm = qv::crypto::HMAC_SHA256::Compute(std::span<const uint8_t>(prk.data(), prk.size()),
                                              std::span<const uint8_t>(info_block.data(), info_block.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(prk.data(), prk.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(info_block.data(), info_block.size()));
  return okm;
}

template <typename T>
void AppendRaw(std::vector<uint8_t>& out, const T& value) {
  auto bytes = qv::AsBytesConst(value);
  out.insert(out.end(), bytes.begin(), bytes.end());
}

void AppendUint16(std::vector<uint8_t>& out, uint16_t value) {
  const uint16_t le = ToLittleEndian16(value);
  AppendRaw(out, le);
}

void AppendUint32(std::vector<uint8_t>& out, uint32_t value) {
  const uint32_t le = qv::ToLittleEndian(value);
  AppendRaw(out, le);
}

} // namespace

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Create(const std::filesystem::path& container,
                      const std::string& password) {
  if (std::filesystem::exists(container)) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Container already exists: " + container.string()};
  }

  if (container.has_parent_path()) {
    std::filesystem::create_directories(container.parent_path());
  }

  VolumeHeader header{}; // TSK013
  header.uuid = GenerateUuidV4();

  std::array<uint8_t, kPbkdfSaltSize> pbkdf_salt{};
  FillRandom(pbkdf_salt);

  std::array<uint8_t, kHybridSaltSize> hybrid_salt{};
  FillRandom(hybrid_salt);

  std::vector<uint8_t> password_bytes(password.begin(), password.end());
  auto classical_key = DerivePasswordKey({password_bytes.data(), password_bytes.size()},
                                         pbkdf_salt,
                                         kDefaultPbkdfIterations);
  if (!password_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(password_bytes.data(), password_bytes.size()));
  }

  qv::core::EpochTLV epoch{};
  epoch.type = ToLittleEndian16(kTlvTypeEpoch);
  epoch.length = ToLittleEndian16(static_cast<uint16_t>(sizeof(epoch.epoch)));
  epoch.epoch = qv::ToLittleEndian(static_cast<uint32_t>(1));
  const auto epoch_bytes = qv::AsBytesConst(epoch);

  auto creation = qv::core::PQCHybridKDF::Create(std::span<const uint8_t, 32>(classical_key),
                                                 std::span<const uint8_t>(hybrid_salt.data(), hybrid_salt.size()),
                                                 std::span<const uint8_t, 16>(header.uuid),
                                                 kHeaderVersion,
                                                 epoch_bytes);

  auto mac_key = DeriveHeaderMacKey(creation.hybrid_key, header.uuid);

  std::vector<uint8_t> serialized;
  serialized.reserve(1024);

  AppendRaw(serialized, header);

  // PBKDF2 parameters TLV
  AppendUint16(serialized, kTlvTypePbkdf2);
  AppendUint16(serialized, static_cast<uint16_t>(4 + pbkdf_salt.size()));
  AppendUint32(serialized, kDefaultPbkdfIterations);
  serialized.insert(serialized.end(), pbkdf_salt.begin(), pbkdf_salt.end());

  // Hybrid salt TLV
  AppendUint16(serialized, kTlvTypeHybridSalt);
  AppendUint16(serialized, static_cast<uint16_t>(hybrid_salt.size()));
  serialized.insert(serialized.end(), hybrid_salt.begin(), hybrid_salt.end());

  // Epoch TLV
  AppendRaw(serialized, epoch);

  // PQC KEM TLV
  auto pqc_blob = creation.kem_blob;
  pqc_blob.type = ToLittleEndian16(kTlvTypePqcKem);
  pqc_blob.length = ToLittleEndian16(static_cast<uint16_t>(sizeof(qv::core::PQC_KEM_TLV) - sizeof(uint16_t) * 2));
  pqc_blob.version = ToLittleEndian16(pqc_blob.version);
  pqc_blob.kem_id = ToLittleEndian16(pqc_blob.kem_id);
  AppendRaw(serialized, pqc_blob);

  // Reserved V2 TLV placeholder
  ReservedV2Tlv reserved_v2{};
  AppendRaw(serialized, reserved_v2);

  auto mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(serialized.data(), serialized.size()));
  serialized.insert(serialized.end(), mac.begin(), mac.end());

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(creation.hybrid_key.data(), creation.hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  std::ofstream out(container, std::ios::binary | std::ios::trunc);
  if (!out) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to create container: " + container.string()};
  }

  out.write(reinterpret_cast<const char*>(serialized.data()), static_cast<std::streamsize>(serialized.size()));
  if (!out) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to write container header: " + container.string()};
  }

  return ConstantTimeMount::VolumeHandle{1};
}

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Mount(const std::filesystem::path& container,
                     const std::string& password) {
  return ctm_.Mount(container, password);
}
