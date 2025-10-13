#include "qv/orchestrator/volume_manager.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iterator> // TSK024_Key_Rotation_and_Lifecycle_Management
#include <limits>  // TSK024_Key_Rotation_and_Lifecycle_Management
#include <random>
#include <span>
#include <string_view>
#include <vector>

#include "qv/common.h"
#include "qv/core/nonce.h"
#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/aes_gcm.h"              // TSK024_Key_Rotation_and_Lifecycle_Management
#include "qv/crypto/hmac_sha256.h"
#include "qv/error.h"
#include "qv/orchestrator/event_bus.h"      // TSK024_Key_Rotation_and_Lifecycle_Management
#include "qv/security/zeroizer.h"

using namespace qv::orchestrator;

namespace {

  constexpr std::array<char, 8> kVolumeMagic = {'Q', 'V', 'A', 'U', 'L', 'T', '\0', '\0'}; // TSK013
  constexpr uint32_t kHeaderVersion = 0x00040100;                                          // TSK013
  constexpr uint16_t kTlvTypePbkdf2 = 0x1001;                                              // TSK013
  constexpr uint16_t kTlvTypeHybridSalt = 0x1002;                                          // TSK013
  constexpr uint16_t kTlvTypeEpoch = 0x4E4F; // matches EpochTLV
  constexpr uint16_t kTlvTypePqcKem = 0x7051;
  constexpr uint16_t kTlvTypeReservedV2 = 0x7F02; // TSK013 reserved slot
  constexpr uint32_t kDefaultFlags = 0;
  constexpr uint32_t kDefaultPbkdfIterations = 200'000; // TSK013
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

  static_assert(sizeof(VolumeHeader) == 32, "volume header must be 32 bytes");  // TSK013
  static_assert(sizeof(ReservedV2Tlv) == 36, "reserved TLV layout unexpected"); // TSK013

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

  std::array<uint8_t, 32>
  DeriveHeaderMacKey(std::span<const uint8_t, 32> hybrid_key,
                     const std::array<uint8_t, 16>& uuid) { // TSK024_Key_Rotation_and_Lifecycle_Management
    auto metadata_root = qv::core::DeriveMetadataKey(hybrid_key);                                  // TSK024_Key_Rotation_and_Lifecycle_Management
    auto prk = qv::crypto::HMAC_SHA256::Compute(                                                   // TSK024_Key_Rotation_and_Lifecycle_Management
        std::span<const uint8_t>(uuid.data(), uuid.size()),                                        // TSK024_Key_Rotation_and_Lifecycle_Management
        std::span<const uint8_t>(metadata_root.data(), metadata_root.size()));                     // TSK024_Key_Rotation_and_Lifecycle_Management
    static constexpr std::string_view kInfo{"QV-HEADER-MAC/v1"};
    std::array<uint8_t, kInfo.size() + 1> info_block{};
    std::memcpy(info_block.data(), kInfo.data(), kInfo.size());
    info_block[kInfo.size()] = 0x01;
    auto okm = qv::crypto::HMAC_SHA256::Compute(
        std::span<const uint8_t>(prk.data(), prk.size()),
        std::span<const uint8_t>(info_block.data(), info_block.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(prk.data(), prk.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(info_block.data(), info_block.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(metadata_root.data(), metadata_root.size()));   // TSK024_Key_Rotation_and_Lifecycle_Management
    return okm;
  }

  template <typename T> void AppendRaw(std::vector<uint8_t>& out, const T& value) {
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

  struct ParsedHeader {                                                            // TSK024_Key_Rotation_and_Lifecycle_Management
    VolumeHeader header{};                                                         // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t header_version{0};                                                    // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t pbkdf_iterations{0};                                                  // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, kPbkdfSaltSize> pbkdf_salt{};                              // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, kHybridSaltSize> hybrid_salt{};                            // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::core::EpochTLV epoch_tlv{};                                                // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t epoch_value{0};                                                       // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::core::PQC_KEM_TLV kem_blob{};                                              // TSK024_Key_Rotation_and_Lifecycle_Management
    ReservedV2Tlv reserved_v2{};                                                   // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE> mac{};                  // TSK024_Key_Rotation_and_Lifecycle_Management
    std::vector<uint8_t> payload;                                                  // TSK024_Key_Rotation_and_Lifecycle_Management
  };

  struct DerivedKeyset {                                                           // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> data{};                                                // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> metadata{};                                            // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> index{};                                               // TSK024_Key_Rotation_and_Lifecycle_Management
  };

  DerivedKeyset MakeDerivedKeyset(std::span<const uint8_t, 32> master) {            // TSK024_Key_Rotation_and_Lifecycle_Management
    DerivedKeyset keys{};                                                          // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.data = qv::core::DeriveDataKey(master);                                   // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.metadata = qv::core::DeriveMetadataKey(master);                           // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.index = qv::core::DeriveIndexKey(master);                                 // TSK024_Key_Rotation_and_Lifecycle_Management
    return keys;                                                                   // TSK024_Key_Rotation_and_Lifecycle_Management
  }

  std::vector<uint8_t>
  SerializeHeaderPayload(const VolumeHeader& header, uint32_t pbkdf_iterations,
                         const std::array<uint8_t, kPbkdfSaltSize>& pbkdf_salt,
                         const std::array<uint8_t, kHybridSaltSize>& hybrid_salt,
                         const qv::core::EpochTLV& epoch, const qv::core::PQC_KEM_TLV& kem_blob,
                         const ReservedV2Tlv& reserved) {                          // TSK024_Key_Rotation_and_Lifecycle_Management
    std::vector<uint8_t> serialized;                                               // TSK024_Key_Rotation_and_Lifecycle_Management
    serialized.reserve(1024);                                                      // TSK024_Key_Rotation_and_Lifecycle_Management

    AppendRaw(serialized, header);                                                 // TSK024_Key_Rotation_and_Lifecycle_Management

    AppendUint16(serialized, kTlvTypePbkdf2);                                      // TSK024_Key_Rotation_and_Lifecycle_Management
    AppendUint16(serialized, static_cast<uint16_t>(4 + pbkdf_salt.size()));        // TSK024_Key_Rotation_and_Lifecycle_Management
    AppendUint32(serialized, pbkdf_iterations);                                    // TSK024_Key_Rotation_and_Lifecycle_Management
    serialized.insert(serialized.end(), pbkdf_salt.begin(), pbkdf_salt.end());     // TSK024_Key_Rotation_and_Lifecycle_Management

    AppendUint16(serialized, kTlvTypeHybridSalt);                                  // TSK024_Key_Rotation_and_Lifecycle_Management
    AppendUint16(serialized, static_cast<uint16_t>(hybrid_salt.size()));           // TSK024_Key_Rotation_and_Lifecycle_Management
    serialized.insert(serialized.end(), hybrid_salt.begin(), hybrid_salt.end());   // TSK024_Key_Rotation_and_Lifecycle_Management

    AppendRaw(serialized, epoch);                                                  // TSK024_Key_Rotation_and_Lifecycle_Management

    auto pqc_blob = kem_blob;                                                      // TSK024_Key_Rotation_and_Lifecycle_Management
    pqc_blob.type = ToLittleEndian16(kTlvTypePqcKem);                              // TSK024_Key_Rotation_and_Lifecycle_Management
    pqc_blob.length = ToLittleEndian16(static_cast<uint16_t>(sizeof(qv::core::PQC_KEM_TLV) - sizeof(uint16_t) * 2));
    pqc_blob.version = ToLittleEndian16(pqc_blob.version);                         // TSK024_Key_Rotation_and_Lifecycle_Management
    pqc_blob.kem_id = ToLittleEndian16(pqc_blob.kem_id);                           // TSK024_Key_Rotation_and_Lifecycle_Management
    AppendRaw(serialized, pqc_blob);                                               // TSK024_Key_Rotation_and_Lifecycle_Management

    auto reserved_copy = reserved;                                                 // TSK024_Key_Rotation_and_Lifecycle_Management
    uint16_t reserved_length = ToLittleEndian16(reserved_copy.length);             // TSK024_Key_Rotation_and_Lifecycle_Management
    if (reserved_length == 0 || reserved_length > reserved_copy.payload.size()) {  // TSK024_Key_Rotation_and_Lifecycle_Management
      reserved_length = static_cast<uint16_t>(reserved_copy.payload.size());       // TSK024_Key_Rotation_and_Lifecycle_Management
    }
    reserved_copy.type = ToLittleEndian16(kTlvTypeReservedV2);                     // TSK024_Key_Rotation_and_Lifecycle_Management
    reserved_copy.length = ToLittleEndian16(reserved_length);                      // TSK024_Key_Rotation_and_Lifecycle_Management
    AppendRaw(serialized, reserved_copy);                                          // TSK024_Key_Rotation_and_Lifecycle_Management

    return serialized;                                                             // TSK024_Key_Rotation_and_Lifecycle_Management
  }

  ParsedHeader ParseHeader(const std::vector<uint8_t>& blob) {                     // TSK024_Key_Rotation_and_Lifecycle_Management
    if (blob.size() < sizeof(VolumeHeader) + qv::crypto::HMAC_SHA256::TAG_SIZE) {   // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Invalid container header"};
    }

    ParsedHeader parsed{};                                                         // TSK024_Key_Rotation_and_Lifecycle_Management
    std::memcpy(&parsed.header, blob.data(), sizeof(VolumeHeader));                // TSK024_Key_Rotation_and_Lifecycle_Management
    parsed.header_version = qv::ToLittleEndian(parsed.header.version);             // TSK024_Key_Rotation_and_Lifecycle_Management
    if (parsed.header.magic != kVolumeMagic) {                                     // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Unrecognized volume magic"};
    }

    const size_t mac_size = qv::crypto::HMAC_SHA256::TAG_SIZE;                     // TSK024_Key_Rotation_and_Lifecycle_Management
    const size_t payload_size = blob.size() - mac_size;                            // TSK024_Key_Rotation_and_Lifecycle_Management
    parsed.payload.assign(blob.begin(), blob.begin() + payload_size);              // TSK024_Key_Rotation_and_Lifecycle_Management
    std::copy(blob.begin() + payload_size, blob.end(), parsed.mac.begin());        // TSK024_Key_Rotation_and_Lifecycle_Management

    size_t offset = sizeof(VolumeHeader);                                          // TSK024_Key_Rotation_and_Lifecycle_Management
    auto require = [&](size_t needed) {                                            // TSK024_Key_Rotation_and_Lifecycle_Management
      if (offset + needed > payload_size) {                                        // TSK024_Key_Rotation_and_Lifecycle_Management
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Volume header truncated"};
      }
    };

    require(4);                                                                    // TSK024_Key_Rotation_and_Lifecycle_Management
    uint16_t pbkdf_type = 0;                                                       // TSK024_Key_Rotation_and_Lifecycle_Management
    std::memcpy(&pbkdf_type, parsed.payload.data() + offset, sizeof(pbkdf_type));  // TSK024_Key_Rotation_and_Lifecycle_Management
    pbkdf_type = ToLittleEndian16(pbkdf_type);                                     // TSK024_Key_Rotation_and_Lifecycle_Management
    uint16_t pbkdf_length = 0;                                                     // TSK024_Key_Rotation_and_Lifecycle_Management
    std::memcpy(&pbkdf_length, parsed.payload.data() + offset + sizeof(uint16_t), sizeof(pbkdf_length));
    pbkdf_length = ToLittleEndian16(pbkdf_length);                                 // TSK024_Key_Rotation_and_Lifecycle_Management
    if (pbkdf_type != kTlvTypePbkdf2 || pbkdf_length < 4) {                        // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "PBKDF2 TLV malformed"};
    }
    require(4 + pbkdf_length);                                                     // TSK024_Key_Rotation_and_Lifecycle_Management
    offset += 4;                                                                   // skip type+len
    std::memcpy(&parsed.pbkdf_iterations, parsed.payload.data() + offset, sizeof(parsed.pbkdf_iterations));
    parsed.pbkdf_iterations = qv::ToLittleEndian(parsed.pbkdf_iterations);         // TSK024_Key_Rotation_and_Lifecycle_Management
    offset += sizeof(parsed.pbkdf_iterations);                                     // TSK024_Key_Rotation_and_Lifecycle_Management
    size_t salt_bytes = pbkdf_length - 4;                                          // TSK024_Key_Rotation_and_Lifecycle_Management
    if (salt_bytes != parsed.pbkdf_salt.size()) {                                  // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "PBKDF2 salt length unexpected"};
    }
    std::memcpy(parsed.pbkdf_salt.data(), parsed.payload.data() + offset, salt_bytes);
    offset += salt_bytes;                                                          // TSK024_Key_Rotation_and_Lifecycle_Management

    require(4);                                                                    // TSK024_Key_Rotation_and_Lifecycle_Management
    uint16_t hybrid_type = 0;                                                      // TSK024_Key_Rotation_and_Lifecycle_Management
    std::memcpy(&hybrid_type, parsed.payload.data() + offset, sizeof(hybrid_type));
    hybrid_type = ToLittleEndian16(hybrid_type);                                   // TSK024_Key_Rotation_and_Lifecycle_Management
    uint16_t hybrid_length = 0;                                                    // TSK024_Key_Rotation_and_Lifecycle_Management
    std::memcpy(&hybrid_length, parsed.payload.data() + offset + sizeof(uint16_t), sizeof(hybrid_length));
    hybrid_length = ToLittleEndian16(hybrid_length);                               // TSK024_Key_Rotation_and_Lifecycle_Management
    if (hybrid_type != kTlvTypeHybridSalt || hybrid_length != parsed.hybrid_salt.size()) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Hybrid salt TLV malformed"};
    }
    require(4 + hybrid_length);                                                   // TSK024_Key_Rotation_and_Lifecycle_Management
    offset += 4;                                                                   // skip type+len
    std::memcpy(parsed.hybrid_salt.data(), parsed.payload.data() + offset, parsed.hybrid_salt.size());
    offset += parsed.hybrid_salt.size();                                           // TSK024_Key_Rotation_and_Lifecycle_Management

    require(sizeof(qv::core::EpochTLV));                                           // TSK024_Key_Rotation_and_Lifecycle_Management
    std::memcpy(&parsed.epoch_tlv, parsed.payload.data() + offset, sizeof(parsed.epoch_tlv));
    offset += sizeof(parsed.epoch_tlv);                                            // TSK024_Key_Rotation_and_Lifecycle_Management
    parsed.epoch_value = qv::ToLittleEndian(parsed.epoch_tlv.epoch);               // TSK024_Key_Rotation_and_Lifecycle_Management

    require(sizeof(qv::core::PQC_KEM_TLV));                                        // TSK024_Key_Rotation_and_Lifecycle_Management
    std::memcpy(&parsed.kem_blob, parsed.payload.data() + offset, sizeof(parsed.kem_blob));
    offset += sizeof(parsed.kem_blob);                                             // TSK024_Key_Rotation_and_Lifecycle_Management
    if (ToLittleEndian16(parsed.kem_blob.type) != kTlvTypePqcKem ||                // TSK024_Key_Rotation_and_Lifecycle_Management
        ToLittleEndian16(parsed.kem_blob.length) !=
            sizeof(qv::core::PQC_KEM_TLV) - sizeof(uint16_t) * 2) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "PQC TLV malformed"};
    }
    parsed.kem_blob.version = ToLittleEndian16(parsed.kem_blob.version);           // TSK024_Key_Rotation_and_Lifecycle_Management
    parsed.kem_blob.kem_id = ToLittleEndian16(parsed.kem_blob.kem_id);             // TSK024_Key_Rotation_and_Lifecycle_Management

    require(sizeof(ReservedV2Tlv));                                                // TSK024_Key_Rotation_and_Lifecycle_Management
    std::memcpy(&parsed.reserved_v2, parsed.payload.data() + offset, sizeof(parsed.reserved_v2));
    offset += sizeof(parsed.reserved_v2);                                          // TSK024_Key_Rotation_and_Lifecycle_Management
    if (ToLittleEndian16(parsed.reserved_v2.type) != kTlvTypeReservedV2) {          // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Reserved TLV malformed"};
    }
    parsed.reserved_v2.type = ToLittleEndian16(parsed.reserved_v2.type);           // TSK024_Key_Rotation_and_Lifecycle_Management
    parsed.reserved_v2.length = ToLittleEndian16(parsed.reserved_v2.length);       // TSK024_Key_Rotation_and_Lifecycle_Management

    if (offset != payload_size) {                                                  // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Unexpected trailing bytes in header"};
    }

    return parsed;                                                                 // TSK024_Key_Rotation_and_Lifecycle_Management
  }

  std::filesystem::path MetadataDirFor(const std::filesystem::path& container) {   // TSK024_Key_Rotation_and_Lifecycle_Management
    auto parent = container.parent_path();                                         // TSK024_Key_Rotation_and_Lifecycle_Management
    auto name = container.filename().string();                                     // TSK024_Key_Rotation_and_Lifecycle_Management
    if (name.empty()) {                                                            // TSK024_Key_Rotation_and_Lifecycle_Management
      name = "volume";                                                            // TSK024_Key_Rotation_and_Lifecycle_Management
    }
    return parent / (name + ".meta");                                             // TSK024_Key_Rotation_and_Lifecycle_Management
  }

#pragma pack(push, 1)
  struct KeyBackupRecord {                                                         // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<char, 8> magic{'Q', 'V', 'B', 'A', 'C', 'K', '\0', '\0'};         // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t version = qv::ToLittleEndian(0x00010000u);                            // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 16> uuid{};                                                // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t epoch{0};                                                             // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::core::PQC::CIPHERTEXT_SIZE> kem_ct{};                  // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE> nonce{};               // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::crypto::AES256_GCM::TAG_SIZE> tag{};                   // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, sizeof(DerivedKeyset)> encrypted_keys{};                   // TSK024_Key_Rotation_and_Lifecycle_Management
  };
#pragma pack(pop)

  std::optional<std::filesystem::path>
  PerformKeyBackup(const std::filesystem::path& container, uint32_t epoch,
                   const std::array<uint8_t, 16>& uuid, DerivedKeyset& keyset,
                   const std::filesystem::path& backup_public_key) {               // TSK024_Key_Rotation_and_Lifecycle_Management
    std::ifstream in(backup_public_key, std::ios::binary);                         // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!in) {                                                                     // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;                                                       // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to open backup key: " + backup_public_key.string()};
    }
    std::vector<uint8_t> pk_bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (pk_bytes.size() != qv::core::PQC::PUBLIC_KEY_SIZE) {                       // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Backup key size mismatch"};
    }
    std::array<uint8_t, qv::core::PQC::PUBLIC_KEY_SIZE> pk{};                      // TSK024_Key_Rotation_and_Lifecycle_Management
    std::copy(pk_bytes.begin(), pk_bytes.end(), pk.begin());                       // TSK024_Key_Rotation_and_Lifecycle_Management

    qv::core::PQCKeyEncapsulation kem;                                            // TSK024_Key_Rotation_and_Lifecycle_Management
    auto enc = kem.Encapsulate(pk);                                                // TSK024_Key_Rotation_and_Lifecycle_Management

    std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE> nonce{};               // TSK024_Key_Rotation_and_Lifecycle_Management
    FillRandom(nonce);                                                             // TSK024_Key_Rotation_and_Lifecycle_Management

    static constexpr std::string_view kBackupContext{"QV-BACKUP/v1"};             // TSK024_Key_Rotation_and_Lifecycle_Management
    std::vector<uint8_t> aad;                                                      // TSK024_Key_Rotation_and_Lifecycle_Management
    aad.insert(aad.end(), kBackupContext.begin(), kBackupContext.end());           // TSK024_Key_Rotation_and_Lifecycle_Management
    aad.insert(aad.end(), uuid.begin(), uuid.end());                               // TSK024_Key_Rotation_and_Lifecycle_Management
    const uint32_t epoch_le = qv::ToLittleEndian(epoch);                           // TSK024_Key_Rotation_and_Lifecycle_Management
    const uint8_t* epoch_bytes = reinterpret_cast<const uint8_t*>(&epoch_le);      // TSK024_Key_Rotation_and_Lifecycle_Management
    aad.insert(aad.end(), epoch_bytes, epoch_bytes + sizeof(epoch_le));            // TSK024_Key_Rotation_and_Lifecycle_Management

    auto keyset_bytes = qv::AsBytesConst(keyset);                                  // TSK024_Key_Rotation_and_Lifecycle_Management
    auto enc_result = qv::crypto::AES256_GCM_Encrypt(                              // TSK024_Key_Rotation_and_Lifecycle_Management
        keyset_bytes, std::span<const uint8_t>(aad.data(), aad.size()),
        std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce.data(), nonce.size()),
        std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(enc.shared_secret.data(),
                                                                   enc.shared_secret.size()));
    if (enc_result.ciphertext.size() != sizeof(DerivedKeyset)) {                   // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Crypto, 0, "Unexpected backup ciphertext length"};
    }

    KeyBackupRecord record{};                                                     // TSK024_Key_Rotation_and_Lifecycle_Management
    record.uuid = uuid;                                                           // TSK024_Key_Rotation_and_Lifecycle_Management
    record.epoch = qv::ToLittleEndian(epoch);                                     // TSK024_Key_Rotation_and_Lifecycle_Management
    record.kem_ct = enc.ciphertext;                                               // TSK024_Key_Rotation_and_Lifecycle_Management
    record.nonce = nonce;                                                         // TSK024_Key_Rotation_and_Lifecycle_Management
    record.tag = enc_result.tag;                                                  // TSK024_Key_Rotation_and_Lifecycle_Management
    std::copy(enc_result.ciphertext.begin(), enc_result.ciphertext.end(),          // TSK024_Key_Rotation_and_Lifecycle_Management
              record.encrypted_keys.begin());

    auto metadata_dir = MetadataDirFor(container);                                // TSK024_Key_Rotation_and_Lifecycle_Management
    std::filesystem::create_directories(metadata_dir);                            // TSK024_Key_Rotation_and_Lifecycle_Management
    auto backup_path = metadata_dir /                                            // TSK024_Key_Rotation_and_Lifecycle_Management
                       ("key_backup.epoch_" + std::to_string(epoch) + ".bin"); // TSK024_Key_Rotation_and_Lifecycle_Management

    std::ofstream out(backup_path, std::ios::binary | std::ios::trunc);           // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!out) {                                                                   // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;                                                      // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to write backup file: " + backup_path.string()};
    }
    out.write(reinterpret_cast<const char*>(&record), sizeof(record));            // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!out) {                                                                   // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;                                                      // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to persist backup file: " + backup_path.string()};
    }

    qv::security::Zeroizer::Wipe(std::span<uint8_t>(enc.shared_secret.data(), enc.shared_secret.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(enc_result.ciphertext.data(), enc_result.ciphertext.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(aad.data(), aad.size()));

    return backup_path;                                                          // TSK024_Key_Rotation_and_Lifecycle_Management
  }
} // namespace

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Create(const std::filesystem::path& container, const std::string& password) {
  if (std::filesystem::exists(container)) {
    throw qv::Error{qv::ErrorDomain::Validation,
                    qv::errors::validation::kVolumeExists, // TSK020
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
  auto classical_key = DerivePasswordKey({password_bytes.data(), password_bytes.size()}, pbkdf_salt,
                                         kDefaultPbkdfIterations);
  if (!password_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(password_bytes.data(), password_bytes.size()));
  }

  qv::core::EpochTLV epoch{};
  epoch.type = ToLittleEndian16(kTlvTypeEpoch);
  epoch.length = ToLittleEndian16(static_cast<uint16_t>(sizeof(epoch.epoch)));
  epoch.epoch = qv::ToLittleEndian(static_cast<uint32_t>(1));
  const auto epoch_bytes = qv::AsBytesConst(epoch);

  auto creation = qv::core::PQCHybridKDF::Create(
      std::span<const uint8_t, 32>(classical_key),
      std::span<const uint8_t>(hybrid_salt.data(), hybrid_salt.size()),
      std::span<const uint8_t, 16>(header.uuid), kHeaderVersion, epoch_bytes);

  auto mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()),
      header.uuid); // TSK024_Key_Rotation_and_Lifecycle_Management

  ReservedV2Tlv reserved_v2{};
  auto payload = SerializeHeaderPayload(header, kDefaultPbkdfIterations, pbkdf_salt, hybrid_salt,
                                        epoch, creation.kem_blob, reserved_v2); // TSK024_Key_Rotation_and_Lifecycle_Management

  auto mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(payload.data(), payload.size()));
  payload.insert(payload.end(), mac.begin(), mac.end());

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(creation.hybrid_key.data(), creation.hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  std::ofstream out(container, std::ios::binary | std::ios::trunc);
  if (!out) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err, "Failed to create container: " + container.string()};
  }

  out.write(reinterpret_cast<const char*>(payload.data()),
            static_cast<std::streamsize>(payload.size()));
  if (!out) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to write container header: " + container.string()};
  }

  return ConstantTimeMount::VolumeHandle{1};
}

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Mount(const std::filesystem::path& container, const std::string& password) {
  return ctm_.Mount(container, password);
}

std::optional<ConstantTimeMount::VolumeHandle> VolumeManager::Rekey(
    const std::filesystem::path& container, const std::string& current_password,
    const std::string& new_password, std::optional<std::filesystem::path> backup_public_key) {
  if (!std::filesystem::exists(container)) { // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::IO, qv::errors::io::kContainerMissing,
                    "Container not found: " + container.string()};
  }

  std::ifstream in(container, std::ios::binary);                                   // TSK024_Key_Rotation_and_Lifecycle_Management
  if (!in) {                                                                       // TSK024_Key_Rotation_and_Lifecycle_Management
    const int err = errno;                                                         // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open container for rekey: " + container.string()};
  }

  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto parsed = ParseHeader(blob);                                                 // TSK024_Key_Rotation_and_Lifecycle_Management

  std::vector<uint8_t> current_bytes(current_password.begin(), current_password.end());
  auto classical_key = DerivePasswordKey(
      {current_bytes.data(), current_bytes.size()}, parsed.pbkdf_salt, parsed.pbkdf_iterations);
  if (!current_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(current_bytes.data(), current_bytes.size()));
  }

  auto hybrid_key = qv::core::PQCHybridKDF::Mount(
      std::span<const uint8_t, 32>(classical_key.data(), classical_key.size()), parsed.kem_blob,
      std::span<const uint8_t>(parsed.hybrid_salt.data(), parsed.hybrid_salt.size()),
      std::span<const uint8_t, 16>(parsed.header.uuid), parsed.header_version,
      qv::AsBytesConst(parsed.epoch_tlv)); // TSK024_Key_Rotation_and_Lifecycle_Management

  auto mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(hybrid_key.data(), hybrid_key.size()), parsed.header.uuid);

  auto expected_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(parsed.payload.data(), parsed.payload.size()));

  if (expected_mac != parsed.mac) {                                                // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::AuthenticationFailureError("Header authentication failed");
  }

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  if (parsed.epoch_value == std::numeric_limits<uint32_t>::max()) {                // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    throw qv::Error{qv::ErrorDomain::State, 0, "Epoch counter overflow"};
  }

  const uint32_t old_epoch = parsed.epoch_value;                                   // TSK024_Key_Rotation_and_Lifecycle_Management
  const uint32_t new_epoch = old_epoch + 1;                                        // TSK024_Key_Rotation_and_Lifecycle_Management

  std::array<uint8_t, kPbkdfSaltSize> new_pbkdf_salt{};                            // TSK024_Key_Rotation_and_Lifecycle_Management
  std::array<uint8_t, kHybridSaltSize> new_hybrid_salt{};                          // TSK024_Key_Rotation_and_Lifecycle_Management
  FillRandom(new_pbkdf_salt);
  FillRandom(new_hybrid_salt);

  std::vector<uint8_t> new_bytes(new_password.begin(), new_password.end());
  auto new_classical_key = DerivePasswordKey(
      {new_bytes.data(), new_bytes.size()}, new_pbkdf_salt, kDefaultPbkdfIterations);
  if (!new_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(new_bytes.data(), new_bytes.size()));
  }

  auto new_epoch_tlv = qv::core::MakeEpochTlv(new_epoch);                          // TSK024_Key_Rotation_and_Lifecycle_Management
  auto creation = qv::core::PQCHybridKDF::Create(
      std::span<const uint8_t, 32>(new_classical_key.data(), new_classical_key.size()),
      std::span<const uint8_t>(new_hybrid_salt.data(), new_hybrid_salt.size()),
      std::span<const uint8_t, 16>(parsed.header.uuid), parsed.header_version,
      qv::AsBytesConst(new_epoch_tlv));

  auto new_mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()),
      parsed.header.uuid);

  auto derived_keys = MakeDerivedKeyset(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()));

  auto payload = SerializeHeaderPayload(parsed.header, kDefaultPbkdfIterations, new_pbkdf_salt,
                                        new_hybrid_salt, new_epoch_tlv, creation.kem_blob,
                                        parsed.reserved_v2); // TSK024_Key_Rotation_and_Lifecycle_Management

  auto new_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(new_mac_key.data(), new_mac_key.size()),
      std::span<const uint8_t>(payload.data(), payload.size()));
  payload.insert(payload.end(), new_mac.begin(), new_mac.end());

  if (payload.size() != parsed.payload.size() + parsed.mac.size()) {               // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::Internal, 0, "Header size changed unexpectedly"};
  }

  std::fstream out(container, std::ios::binary | std::ios::in | std::ios::out);   // TSK024_Key_Rotation_and_Lifecycle_Management
  if (!out) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open container for update: " + container.string()};
  }
  out.seekp(0);
  out.write(reinterpret_cast<const char*>(payload.data()),
            static_cast<std::streamsize>(payload.size()));
  if (!out) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to write updated header: " + container.string()};
  }
  out.flush();

  std::optional<std::filesystem::path> backup_path;                                // TSK024_Key_Rotation_and_Lifecycle_Management
  if (backup_public_key) {
    backup_path = PerformKeyBackup(container, new_epoch, parsed.header.uuid, derived_keys,
                                   *backup_public_key);
  }

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(new_classical_key.data(), new_classical_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(creation.hybrid_key.data(), creation.hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(new_mac_key.data(), new_mac_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(derived_keys.data.data(), derived_keys.data.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(derived_keys.metadata.data(), derived_keys.metadata.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(derived_keys.index.data(), derived_keys.index.size()));

  qv::orchestrator::Event event{};                                                 // TSK024_Key_Rotation_and_Lifecycle_Management
  event.category = EventCategory::kSecurity;
  event.severity = EventSeverity::kInfo;
  event.event_id = "volume_rekeyed";
  event.message = "Volume encryption keys rotated";
  event.fields.emplace_back("container", qv::PathToUtf8String(container), FieldPrivacy::kRedact);
  event.fields.emplace_back("old_epoch", std::to_string(old_epoch), FieldPrivacy::kPublic, true);
  event.fields.emplace_back("new_epoch", std::to_string(new_epoch), FieldPrivacy::kPublic, true);
  event.fields.emplace_back("key_material_destroyed", "true", FieldPrivacy::kPublic);
  if (backup_public_key) {
    event.fields.emplace_back(
        "backup_escrow",
        backup_path ? qv::PathToUtf8String(*backup_path) : qv::PathToUtf8String(*backup_public_key),
        FieldPrivacy::kRedact);
  }
  qv::orchestrator::EventBus::Instance().Publish(event);

  return ConstantTimeMount::VolumeHandle{1};                                       // TSK024_Key_Rotation_and_Lifecycle_Management
}
