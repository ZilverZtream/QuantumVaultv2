#include "qv/core/header_io.h"

// TSK712_Header_Backup_and_Restore_Tooling header backup implementation

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#include "qv/common.h"
#include "qv/core/nonce.h"
#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/aes_gcm.h"
#include "qv/crypto/ct.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/crypto/random.h"
#include "qv/error.h"
#include "qv/security/zeroizer.h"
#include "qv/tlv/parser.h"

#if defined(_WIN32)
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace qv::core {
namespace {

// --- Container header constants -------------------------------------------------
constexpr std::array<uint8_t, 8> kHeaderMagic = {'Q', 'V', 'A', 'U', 'L', 'T', '\0', '\0'}; // TSK712
constexpr uint32_t kSupportedHeaderVersion = 0x00040101u;                                   // TSK712
constexpr size_t kPbkdfSaltSize = 16;                                                       // TSK712
constexpr size_t kHybridSaltSize = 32;                                                      // TSK712
constexpr uint16_t kTlvTypePbkdf2 = 0x1001;                                                 // TSK712
constexpr uint16_t kTlvTypeHybridSalt = 0x1002;                                             // TSK712
constexpr uint16_t kTlvTypeArgon2 = 0x1003;                                                 // TSK712
constexpr uint16_t kTlvTypeEpoch = 0x4E4Fu;                                                 // TSK712
constexpr uint16_t kTlvTypePqc = 0x7051u;                                                   // TSK712
constexpr uint16_t kTlvTypeReservedV2 = 0x7F02u;                                            // TSK712
constexpr uint16_t kTlvTypeHiddenDescriptor = 0x4844u;                                      // 'HD' // TSK712

#pragma pack(push, 1)
struct VolumeHeader { // TSK712
  std::array<uint8_t, 8> magic{};
  uint32_t version{0};
  std::array<uint8_t, 16> uuid{};
  uint32_t flags{0};
};

struct ReservedV2Tlv { // TSK712
  uint16_t type = qv::ToLittleEndian16(kTlvTypeReservedV2);
  uint16_t length = qv::ToLittleEndian16(32);
  std::array<uint8_t, 32> payload{};
};
#pragma pack(pop)

static_assert(sizeof(VolumeHeader) == 32, "unexpected volume header size");
static_assert(sizeof(ReservedV2Tlv) == 36, "reserved TLV size mismatch");

constexpr size_t kPasswordTlvBytes =
    4 + std::max<size_t>(4 + kPbkdfSaltSize, sizeof(uint32_t) * 6 + kPbkdfSaltSize); // TSK712
constexpr size_t kSerializedHeaderBytes = sizeof(VolumeHeader) + kPasswordTlvBytes + 4 + kHybridSaltSize +
                                          sizeof(qv::core::EpochTLV) + sizeof(qv::core::PQC_KEM_TLV) +
                                          sizeof(ReservedV2Tlv); // TSK712
constexpr size_t kHeaderMacSize = qv::crypto::HMAC_SHA256::TAG_SIZE;                 // TSK712
constexpr size_t kTotalHeaderBytes = kSerializedHeaderBytes + kHeaderMacSize;        // TSK712

// --- Backup TLV constants -------------------------------------------------------
constexpr uint16_t kBackupFormatVersion = 0x0001u;                                      // TSK712
constexpr uint16_t kBackupTlvMetadata = 0x5100u;                                        // TSK712
constexpr uint16_t kBackupTlvCiphertext = 0x51F0u;                                      // TSK712
constexpr uint16_t kMetaTlvFormatVersion = 0x0101u;                                     // TSK712
constexpr uint16_t kMetaTlvContainerUuid = 0x0102u;                                     // TSK712
constexpr uint16_t kMetaTlvContainerVersion = 0x0103u;                                  // TSK712
constexpr uint16_t kMetaTlvContainerFlags = 0x0104u;                                    // TSK712
constexpr uint16_t kMetaTlvContainerKdfPbkdf2 = 0x0110u;                                // TSK712
constexpr uint16_t kMetaTlvContainerKdfArgon2 = 0x0111u;                                // TSK712
constexpr uint16_t kMetaTlvRecoveryKdf = 0x0120u;                                       // TSK712

// --- File utilities -------------------------------------------------------------

int NativeOpenWrite(const std::filesystem::path& path) { // TSK712
#if defined(_WIN32)
  return _wopen(path.c_str(), _O_CREAT | _O_WRONLY | _O_TRUNC | _O_BINARY | _O_SEQUENTIAL,
                _S_IREAD | _S_IWRITE);
#else
  return ::open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
#endif
}

void NativeClose(int fd) { // TSK712
  if (fd < 0) {
    return;
  }
#if defined(_WIN32)
  _close(fd);
#else
  ::close(fd);
#endif
}

bool NativeFlush(int fd) { // TSK712
#if defined(_WIN32)
  HANDLE handle = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
  if (handle == INVALID_HANDLE_VALUE) {
    return false;
  }
  return FlushFileBuffers(handle) != 0;
#else
  return ::fsync(fd) == 0;
#endif
}

bool SyncDirectory(const std::filesystem::path& dir) { // TSK712
#if defined(_WIN32)
  HANDLE handle = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return false;
  }
  const bool ok = FlushFileBuffers(handle) != 0;
  CloseHandle(handle);
  return ok;
#else
  int fd = ::open(dir.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  bool ok = ::fsync(fd) == 0;
  ::close(fd);
  return ok;
#endif
}

bool AtomicReplace(const std::filesystem::path& from, const std::filesystem::path& to) { // TSK712
#if defined(_WIN32)
  return MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
  return ::rename(from.c_str(), to.c_str()) == 0;
#endif
}

std::filesystem::path MakeTemporaryPath(const std::filesystem::path& target) { // TSK712
  std::array<uint8_t, 8> random{};
  qv::crypto::SystemRandomBytes(std::span<uint8_t>(random)); // TSK712 random suffix for temp files
  std::ostringstream oss;
  oss << target.string() << ".tmp";
  for (auto byte : random) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
  }
  return std::filesystem::path(oss.str());
}

void WriteAll(int fd, std::span<const uint8_t> bytes, const std::filesystem::path& destination) { // TSK712
  size_t written = 0;
  while (written < bytes.size()) {
#if defined(_WIN32)
    const auto chunk = _write(fd, reinterpret_cast<const char*>(bytes.data() + written),
                              static_cast<unsigned int>(bytes.size() - written));
#else
    const auto chunk = ::write(fd, bytes.data() + written, bytes.size() - written);
#endif
    if (chunk < 0) {
      const int err = errno;
      if (err == EINTR) {
        continue;
      }
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to write header backup: " + destination.string()};
    }
    written += static_cast<size_t>(chunk);
  }
}

// --- Helpers for TLV serialization ---------------------------------------------

void Append(std::vector<uint8_t>& buffer, std::span<const uint8_t> bytes) { // TSK712
  buffer.insert(buffer.end(), bytes.begin(), bytes.end());
}

void AppendU16(std::vector<uint8_t>& buffer, uint16_t value) { // TSK712
  const uint16_t le = qv::ToLittleEndian16(value);
  Append(buffer, qv::AsBytesConst(le));
}

void AppendU32(std::vector<uint8_t>& buffer, uint32_t value) { // TSK712
  const uint32_t le = qv::ToLittleEndian(value);
  Append(buffer, qv::AsBytesConst(le));
}

void AppendTlv(std::vector<uint8_t>& buffer, uint16_t type, std::span<const uint8_t> payload) { // TSK712
  AppendU16(buffer, type);
  AppendU16(buffer, static_cast<uint16_t>(payload.size()));
  Append(buffer, payload);
}

std::vector<uint8_t> MakeMetadataInner(const ContainerHeaderMetadata& header,
                                       const RecoveryKdfMetadata& recovery) { // TSK712
  std::vector<uint8_t> inner;
  inner.reserve(256);

  const uint16_t format_version_le = qv::ToLittleEndian16(kBackupFormatVersion);
  AppendTlv(inner, kMetaTlvFormatVersion,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&format_version_le), sizeof(format_version_le)));
  AppendTlv(inner, kMetaTlvContainerUuid,
            std::span<const uint8_t>(header.uuid.data(), header.uuid.size()));

  AppendTlv(inner, kMetaTlvContainerVersion, qv::AsBytesConst(qv::ToLittleEndian(header.version)));
  AppendTlv(inner, kMetaTlvContainerFlags, qv::AsBytesConst(qv::ToLittleEndian(header.flags)));

  if (header.kdf.have_pbkdf2) {
    std::array<uint8_t, sizeof(uint32_t) + kPbkdfSaltSize> payload{};
    const uint32_t iter_le = qv::ToLittleEndian(header.kdf.pbkdf_iterations);
    std::memcpy(payload.data(), &iter_le, sizeof(iter_le));
    std::copy(header.kdf.pbkdf_salt.begin(), header.kdf.pbkdf_salt.end(),
              payload.begin() + sizeof(iter_le));
    AppendTlv(inner, kMetaTlvContainerKdfPbkdf2,
              std::span<const uint8_t>(payload.data(), payload.size()));
  }

  if (header.kdf.have_argon2) {
    std::array<uint8_t, sizeof(uint32_t) * 6 + kPbkdfSaltSize> payload{};
    auto write_field = [&](size_t index, uint32_t value) {
      const uint32_t le = qv::ToLittleEndian(value);
      std::memcpy(payload.data() + index * sizeof(uint32_t), &le, sizeof(le));
    };
    write_field(0, header.kdf.argon2_version);
    write_field(1, header.kdf.argon2_params.time_cost);
    write_field(2, header.kdf.argon2_params.memory_cost_kib);
    write_field(3, header.kdf.argon2_params.parallelism);
    write_field(4, header.kdf.argon2_hash_length);
    write_field(5, header.kdf.argon2_target_ms);
    std::copy(header.kdf.argon2_salt.begin(), header.kdf.argon2_salt.end(),
              payload.begin() + sizeof(uint32_t) * 6);
    AppendTlv(inner, kMetaTlvContainerKdfArgon2,
              std::span<const uint8_t>(payload.data(), payload.size()));
  }

  std::array<uint8_t, sizeof(uint16_t) + sizeof(uint32_t) * 3 + sizeof(uint16_t) + 16> recovery_payload{};
  const uint16_t algorithm = qv::ToLittleEndian16(static_cast<uint16_t>(recovery.algorithm));
  std::memcpy(recovery_payload.data(), &algorithm, sizeof(algorithm));
  size_t offset = sizeof(uint16_t);
  const auto write_recovery_field = [&](uint32_t value) {
    const uint32_t le = qv::ToLittleEndian(value);
    std::memcpy(recovery_payload.data() + offset, &le, sizeof(le));
    offset += sizeof(uint32_t);
  };
  write_recovery_field(recovery.params.time_cost);
  write_recovery_field(recovery.params.memory_cost_kib);
  write_recovery_field(recovery.params.parallelism);
  const uint16_t salt_length = qv::ToLittleEndian16(static_cast<uint16_t>(recovery.salt.size()));
  std::memcpy(recovery_payload.data() + offset, &salt_length, sizeof(salt_length));
  offset += sizeof(uint16_t);
  std::copy(recovery.salt.begin(), recovery.salt.end(), recovery_payload.begin() + offset);
  AppendTlv(inner, kMetaTlvRecoveryKdf,
            std::span<const uint8_t>(recovery_payload.data(), offset + recovery.salt.size()));

  return inner;
}

HeaderBackupMetadata ParseMetadataInner(std::span<const uint8_t> payload) { // TSK712
  HeaderBackupMetadata meta{};
  qv::tlv::Parser parser(payload, 32, 4 * 1024);
  if (!parser.valid()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Backup metadata TLV invalid"};
  }
  for (const auto& record : parser) {
    switch (record.type) {
      case kMetaTlvFormatVersion: {
        if (record.value.size() != sizeof(uint16_t)) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Metadata format version malformed"};
        }
        uint16_t version_le = 0;
        std::memcpy(&version_le, record.value.data(), sizeof(version_le));
        meta.format_version = qv::FromLittleEndian16(version_le);
        break;
      }
      case kMetaTlvContainerUuid: {
        if (record.value.size() != meta.container.uuid.size()) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Metadata UUID length invalid"};
        }
        std::copy(record.value.begin(), record.value.end(), meta.container.uuid.begin());
        break;
      }
      case kMetaTlvContainerVersion: {
        if (record.value.size() != sizeof(uint32_t)) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Metadata version malformed"};
        }
        uint32_t version_le = 0;
        std::memcpy(&version_le, record.value.data(), sizeof(version_le));
        meta.container.version = qv::FromLittleEndian32(version_le);
        break;
      }
      case kMetaTlvContainerFlags: {
        if (record.value.size() != sizeof(uint32_t)) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Metadata flags malformed"};
        }
        uint32_t flags_le = 0;
        std::memcpy(&flags_le, record.value.data(), sizeof(flags_le));
        meta.container.flags = qv::FromLittleEndian32(flags_le);
        break;
      }
      case kMetaTlvContainerKdfPbkdf2: {
        if (record.value.size() != sizeof(uint32_t) + kPbkdfSaltSize) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Metadata PBKDF2 malformed"};
        }
        uint32_t iter_le = 0;
        std::memcpy(&iter_le, record.value.data(), sizeof(iter_le));
        meta.container.kdf.pbkdf_iterations = qv::FromLittleEndian32(iter_le);
        std::copy(record.value.begin() + sizeof(uint32_t), record.value.end(),
                  meta.container.kdf.pbkdf_salt.begin());
        meta.container.kdf.have_pbkdf2 = meta.container.kdf.pbkdf_iterations != 0;
        break;
      }
      case kMetaTlvContainerKdfArgon2: {
        if (record.value.size() != sizeof(uint32_t) * 6 + kPbkdfSaltSize) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Metadata Argon2 malformed"};
        }
        auto read_field = [&](size_t index) {
          uint32_t le = 0;
          std::memcpy(&le, record.value.data() + index * sizeof(uint32_t), sizeof(uint32_t));
          return qv::FromLittleEndian32(le);
        };
        meta.container.kdf.argon2_version = read_field(0);
        meta.container.kdf.argon2_params.time_cost = read_field(1);
        meta.container.kdf.argon2_params.memory_cost_kib = read_field(2);
        meta.container.kdf.argon2_params.parallelism = read_field(3);
        meta.container.kdf.argon2_hash_length = read_field(4);
        meta.container.kdf.argon2_target_ms = read_field(5);
        std::copy(record.value.begin() + sizeof(uint32_t) * 6,
                  record.value.begin() + sizeof(uint32_t) * 6 + kPbkdfSaltSize,
                  meta.container.kdf.argon2_salt.begin());
        meta.container.kdf.have_argon2 = true;
        break;
      }
      case kMetaTlvRecoveryKdf: {
        if (record.value.size() < sizeof(uint16_t) + sizeof(uint32_t) * 3 + sizeof(uint16_t)) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Recovery KDF TLV malformed"};
        }
        size_t offset = 0;
        uint16_t algo_le = 0;
        std::memcpy(&algo_le, record.value.data(), sizeof(algo_le));
        offset += sizeof(uint16_t);
        meta.recovery.algorithm = static_cast<RecoveryKdfAlgorithm>(qv::FromLittleEndian16(algo_le));
        auto read32 = [&]() {
          uint32_t le = 0;
          std::memcpy(&le, record.value.data() + offset, sizeof(le));
          offset += sizeof(uint32_t);
          return qv::FromLittleEndian32(le);
        };
        meta.recovery.params.time_cost = read32();
        meta.recovery.params.memory_cost_kib = read32();
        meta.recovery.params.parallelism = read32();
        uint16_t salt_len_le = 0;
        std::memcpy(&salt_len_le, record.value.data() + offset, sizeof(salt_len_le));
        offset += sizeof(uint16_t);
        const uint16_t salt_len = qv::FromLittleEndian16(salt_len_le);
        if (salt_len != meta.recovery.salt.size() ||
            offset + salt_len > record.value.size()) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Recovery salt length mismatch"};
        }
        std::copy(record.value.begin() + offset, record.value.begin() + offset + salt_len,
                  meta.recovery.salt.begin());
        break;
      }
      default:
        break;
    }
  }
  if (meta.format_version == 0) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Backup metadata missing format version"};
  }
  return meta;
}

struct BackupParseResult { // TSK712
  HeaderBackupMetadata metadata;
  std::span<const uint8_t> metadata_tlv;
  std::span<const uint8_t> ciphertext_payload;
};

BackupParseResult ParseBackup(std::span<const uint8_t> blob) { // TSK712
  size_t offset = 0;
  std::span<const uint8_t> metadata_tlv;
  std::span<const uint8_t> ciphertext_tlv;
  while (offset + sizeof(uint16_t) * 2 <= blob.size()) {
    uint16_t type_le = 0;
    uint16_t length_le = 0;
    std::memcpy(&type_le, blob.data() + offset, sizeof(type_le));
    std::memcpy(&length_le, blob.data() + offset + sizeof(type_le), sizeof(length_le));
    const uint16_t type = qv::FromLittleEndian16(type_le);
    const uint16_t length = qv::FromLittleEndian16(length_le);
    offset += sizeof(uint16_t) * 2;
    if (offset + length > blob.size()) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Backup TLV truncated"};
    }
    auto tlv_span = blob.subspan(offset - sizeof(uint16_t) * 2, length + sizeof(uint16_t) * 2);
    if (type == kBackupTlvMetadata) {
      metadata_tlv = tlv_span;
    } else if (type == kBackupTlvCiphertext) {
      ciphertext_tlv = blob.subspan(offset, length);
    }
    offset += length;
  }
  if (metadata_tlv.empty() || ciphertext_tlv.empty()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Backup file missing required TLVs"};
  }
  // metadata payload excludes TLV header
  auto metadata_payload = metadata_tlv.subspan(sizeof(uint16_t) * 2);
  HeaderBackupMetadata parsed = ParseMetadataInner(metadata_payload);
  if (parsed.format_version != kBackupFormatVersion) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Unsupported backup format version"};
  }
  return BackupParseResult{parsed, metadata_tlv, ciphertext_tlv};
}

std::vector<uint8_t> ReadHeaderBytes(const std::filesystem::path& container) { // TSK712
  std::ifstream in(container, std::ios::binary);
  if (!in) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open container for header backup: " + container.string()};
  }
  std::vector<uint8_t> buffer(kTotalHeaderBytes, 0);
  in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
  if (static_cast<size_t>(in.gcount()) != buffer.size()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Container header truncated: " + container.string()};
  }
  return buffer;
}

ContainerHeaderMetadata ParseContainerHeader(std::span<const uint8_t> bytes) { // TSK712
  if (bytes.size() < sizeof(VolumeHeader)) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Container header too small"};
  }
  VolumeHeader header{};
  std::memcpy(&header, bytes.data(), sizeof(header));
  if (!qv::crypto::ct::CompareEqual(header.magic, kHeaderMagic)) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Container magic mismatch"};
  }
  const uint32_t version = qv::FromLittleEndian32(header.version);
  if (version > kSupportedHeaderVersion) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Unsupported container header version"};
  }

  ContainerHeaderMetadata meta{};
  std::copy(header.uuid.begin(), header.uuid.end(), meta.uuid.begin());
  meta.version = version;
  meta.flags = qv::FromLittleEndian32(header.flags);

  const size_t offset = sizeof(VolumeHeader);
  if (offset > bytes.size()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Container header layout overflow"};
  }

  qv::tlv::Parser parser(bytes.subspan(offset), 32, 64 * 1024);
  if (!parser.valid()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Container TLV parse failed"};
  }

  for (const auto& record : parser) {
    switch (record.type) {
      case kTlvTypePbkdf2: {
        if (record.value.size() != sizeof(uint32_t) + kPbkdfSaltSize) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "PBKDF2 TLV malformed"};
        }
        uint32_t iter_le = 0;
        std::memcpy(&iter_le, record.value.data(), sizeof(iter_le));
        meta.kdf.pbkdf_iterations = qv::FromLittleEndian32(iter_le);
        std::copy_n(record.value.data() + sizeof(uint32_t), kPbkdfSaltSize,
                    meta.kdf.pbkdf_salt.begin());
        meta.kdf.have_pbkdf2 = meta.kdf.pbkdf_iterations != 0;
        break;
      }
      case kTlvTypeArgon2: {
        constexpr size_t expected = sizeof(uint32_t) * 6 + kPbkdfSaltSize;
        if (record.value.size() != expected) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Argon2 TLV malformed"};
        }
        auto field = [&](size_t index) {
          uint32_t value = 0;
          std::memcpy(&value, record.value.data() + index * sizeof(uint32_t), sizeof(uint32_t));
          return qv::FromLittleEndian32(value);
        };
        meta.kdf.argon2_version = field(0);
        meta.kdf.argon2_params.time_cost = field(1);
        meta.kdf.argon2_params.memory_cost_kib = field(2);
        meta.kdf.argon2_params.parallelism = field(3);
        meta.kdf.argon2_hash_length = field(4);
        meta.kdf.argon2_target_ms = field(5);
        std::copy(record.value.begin() + sizeof(uint32_t) * 6,
                  record.value.begin() + sizeof(uint32_t) * 6 + kPbkdfSaltSize,
                  meta.kdf.argon2_salt.begin());
        meta.kdf.have_argon2 = true;
        break;
      }
      case kTlvTypeHybridSalt:
      case kTlvTypeEpoch:
      case kTlvTypePqc:
      case kTlvTypeReservedV2:
      case kTlvTypeHiddenDescriptor:
        break;
      default:
        break;
    }
  }

  if (!meta.kdf.have_pbkdf2 && !meta.kdf.have_argon2) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Container missing password KDF TLV"};
  }

  return meta;
}

}  // namespace

ContainerHeaderMetadata ReadContainerHeaderMetadata(const std::filesystem::path& container) { // TSK712
  auto bytes = ReadHeaderBytes(container);
  return ParseContainerHeader(std::span<const uint8_t>(bytes.data(), kSerializedHeaderBytes));
}

HeaderBackupMetadata InspectHeaderBackup(const std::filesystem::path& backup) { // TSK712
  std::ifstream in(backup, std::ios::binary);
  if (!in) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open header backup: " + backup.string()};
  }
  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  if (blob.empty()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Header backup empty"};
  }
  auto parsed = ParseBackup(blob);
  return parsed.metadata;
}

bool BackupHeader(const std::filesystem::path& container, const std::filesystem::path& out,
                  const RecoveryKeyDescriptor& recovery) { // TSK712
  auto bytes = ReadHeaderBytes(container);
  auto header_meta = ParseContainerHeader(std::span<const uint8_t>(bytes.data(), kSerializedHeaderBytes));

  auto metadata_inner = MakeMetadataInner(header_meta, recovery.metadata);
  auto metadata_tlv = std::vector<uint8_t>{};
  metadata_tlv.reserve(metadata_inner.size() + sizeof(uint16_t) * 2);
  AppendTlv(metadata_tlv, kBackupTlvMetadata, std::span<const uint8_t>(metadata_inner.data(), metadata_inner.size()));

  std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE> nonce{};
  qv::crypto::SystemRandomBytes(std::span<uint8_t>(nonce)); // TSK712 generate backup nonce

  auto key_span = recovery.key.AsSpan();
  if (key_span.size() != qv::crypto::AES256_GCM::KEY_SIZE) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Recovery key length invalid"};
  }

  auto enc = qv::crypto::AES256_GCM_Encrypt(
      std::span<const uint8_t>(bytes.data(), bytes.size()),
      std::span<const uint8_t>(metadata_tlv.data(), metadata_tlv.size()),
      std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce.data(), nonce.size()),
      std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(key_span.data(), key_span.size()));

  std::vector<uint8_t> ciphertext_payload;
  ciphertext_payload.reserve(sizeof(uint32_t) + nonce.size() + enc.ciphertext.size() + enc.tag.size());
  AppendU32(ciphertext_payload, static_cast<uint32_t>(bytes.size()));
  Append(ciphertext_payload, std::span<const uint8_t>(nonce.data(), nonce.size()));
  Append(ciphertext_payload, std::span<const uint8_t>(enc.ciphertext.data(), enc.ciphertext.size()));
  Append(ciphertext_payload, std::span<const uint8_t>(enc.tag.data(), enc.tag.size()));

  std::vector<uint8_t> ciphertext_tlv;
  ciphertext_tlv.reserve(ciphertext_payload.size() + sizeof(uint16_t) * 2);
  AppendTlv(ciphertext_tlv, kBackupTlvCiphertext,
            std::span<const uint8_t>(ciphertext_payload.data(), ciphertext_payload.size()));

  std::vector<uint8_t> backup_blob;
  backup_blob.reserve(metadata_tlv.size() + ciphertext_tlv.size());
  Append(backup_blob, std::span<const uint8_t>(metadata_tlv.data(), metadata_tlv.size()));
  Append(backup_blob, std::span<const uint8_t>(ciphertext_tlv.data(), ciphertext_tlv.size()));

  auto tmp = MakeTemporaryPath(out);
  int fd = NativeOpenWrite(tmp);
  if (fd < 0) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open temporary backup path: " + tmp.string()};
  }
  try {
    WriteAll(fd, std::span<const uint8_t>(backup_blob.data(), backup_blob.size()), tmp);
    if (!NativeFlush(fd)) {
      throw qv::Error{qv::ErrorDomain::IO, errno,
                      "Failed to flush header backup: " + tmp.string()};
    }
    NativeClose(fd);
    fd = -1;
    if (!AtomicReplace(tmp, out)) {
      throw qv::Error{qv::ErrorDomain::IO, errno,
                      "Failed to finalize header backup: " + out.string()};
    }
    if (!SyncDirectory(out.parent_path().empty() ? std::filesystem::current_path() : out.parent_path())) {
      throw qv::Error{qv::ErrorDomain::IO, errno,
                      "Failed to sync backup directory: " + out.parent_path().string()};
    }
  } catch (...) {
    if (fd >= 0) {
      NativeClose(fd);
    }
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    throw;
  }

  return true;
}

bool RestoreHeader(const std::filesystem::path& container, const std::filesystem::path& in,
                   const RecoveryKeyDescriptor& recovery) { // TSK712
  std::ifstream file(in, std::ios::binary);
  if (!file) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open header backup: " + in.string()};
  }
  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  if (blob.empty()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Header backup empty"};
  }

  auto parsed = ParseBackup(blob);
  auto key_span = recovery.key.AsSpan();
  if (key_span.size() != qv::crypto::AES256_GCM::KEY_SIZE) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Recovery key length invalid"};
  }
  if (parsed.metadata.recovery.algorithm != recovery.metadata.algorithm ||
      parsed.metadata.recovery.params.time_cost != recovery.metadata.params.time_cost ||
      parsed.metadata.recovery.params.memory_cost_kib != recovery.metadata.params.memory_cost_kib ||
      parsed.metadata.recovery.params.parallelism != recovery.metadata.params.parallelism ||
      parsed.metadata.recovery.salt != recovery.metadata.salt) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Recovery key parameters mismatch"};
  }

  if (parsed.ciphertext_payload.size() < sizeof(uint32_t) + qv::crypto::AES256_GCM::NONCE_SIZE +
                                           qv::crypto::AES256_GCM::TAG_SIZE) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Ciphertext payload truncated"};
  }

  uint32_t length_le = 0;
  std::memcpy(&length_le, parsed.ciphertext_payload.data(), sizeof(length_le));
  const uint32_t plaintext_len = qv::FromLittleEndian32(length_le);
  if (plaintext_len != kTotalHeaderBytes) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Unexpected header length in backup"};
  }

  size_t offset = sizeof(uint32_t);
  std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE> nonce{};
  std::memcpy(nonce.data(), parsed.ciphertext_payload.data() + offset, nonce.size());
  offset += nonce.size();
  const size_t remaining = parsed.ciphertext_payload.size() - offset;
  if (remaining < qv::crypto::AES256_GCM::TAG_SIZE) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Ciphertext payload malformed"};
  }
  const size_t ciphertext_len = remaining - qv::crypto::AES256_GCM::TAG_SIZE;
  auto ciphertext = parsed.ciphertext_payload.subspan(offset, ciphertext_len);
  auto tag_span = parsed.ciphertext_payload.subspan(offset + ciphertext_len, qv::crypto::AES256_GCM::TAG_SIZE);

  auto plaintext = qv::crypto::AES256_GCM_Decrypt(
      ciphertext,
      parsed.metadata_tlv,
      std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce.data(), nonce.size()),
      std::span<const uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>(tag_span.data(), tag_span.size()),
      std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(key_span.data(), key_span.size()));

  if (plaintext.size() != kTotalHeaderBytes) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Decrypted header length mismatch"};
  }

  auto tmp = MakeTemporaryPath(container);
  int fd = NativeOpenWrite(tmp);
  if (fd < 0) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open temporary container path: " + tmp.string()};
  }
  try {
    WriteAll(fd, std::span<const uint8_t>(plaintext.data(), plaintext.size()), tmp);
    if (!NativeFlush(fd)) {
      throw qv::Error{qv::ErrorDomain::IO, errno,
                      "Failed to flush restored header: " + tmp.string()};
    }
    NativeClose(fd);
    fd = -1;
    if (!AtomicReplace(tmp, container)) {
      throw qv::Error{qv::ErrorDomain::IO, errno,
                      "Failed to atomically replace container header: " + container.string()};
    }
    if (!SyncDirectory(container.parent_path().empty() ? std::filesystem::current_path()
                                                      : container.parent_path())) {
      throw qv::Error{qv::ErrorDomain::IO, errno,
                      "Failed to sync container directory: " + container.parent_path().string()};
    }
  } catch (...) {
    if (fd >= 0) {
      NativeClose(fd);
    }
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    throw;
  }

  // Validate restored header by reparsing.
  auto restored = ReadHeaderBytes(container);
  (void)ParseContainerHeader(std::span<const uint8_t>(restored.data(), kSerializedHeaderBytes));

  return true;
}

}  // namespace qv::core

