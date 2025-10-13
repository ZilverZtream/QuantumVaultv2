#include "qv/orchestrator/volume_manager.h"

#include <algorithm> // TSK033 skip/zero TLV payloads
#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iomanip>  // TSK029
#include <iterator> // TSK024_Key_Rotation_and_Lifecycle_Management
#include <limits>   // TSK024_Key_Rotation_and_Lifecycle_Management
#include <random>
#include <span>
#include <sstream>    // TSK033 version formatting
#include <string_view>
#include <vector>

#include "qv/common.h"
#include "qv/core/nonce.h"
#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/aes_gcm.h" // TSK024_Key_Rotation_and_Lifecycle_Management
#include "qv/crypto/hmac_sha256.h"
#include "qv/error.h"
#include "qv/orchestrator/event_bus.h" // TSK024_Key_Rotation_and_Lifecycle_Management
#include "qv/security/zeroizer.h"

using namespace qv::orchestrator;

namespace {

  constexpr std::array<char, 8> kVolumeMagic = {'Q', 'V', 'A', 'U', 'L', 'T', '\0', '\0'}; // TSK013
  constexpr uint32_t kHeaderVersion = VolumeManager::kLatestHeaderVersion;                  // TSK033 align serialization with published target
  constexpr uint16_t kTlvTypePbkdf2 = 0x1001;                                              // TSK013
  constexpr uint16_t kTlvTypeHybridSalt = 0x1002;                                          // TSK013
  constexpr uint16_t kTlvTypeEpoch = 0x4E4F; // matches EpochTLV
  constexpr uint16_t kTlvTypePqcKem = 0x7051;
  constexpr uint16_t kTlvTypeReservedV2 = 0x7F02; // TSK033 reserved for ACL metadata staging
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
  struct ReservedV2Tlv { // TSK033 future ACL metadata placeholder
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

  std::string FormatUuid(const std::array<uint8_t, 16>& uuid) { // TSK029
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < uuid.size(); ++i) {
      oss << std::setw(2) << static_cast<int>(uuid[i]);
      if (i == 3 || i == 5 || i == 7 || i == 9) {
        oss << '-';
      }
    }
    return oss.str();
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

  std::array<uint8_t, 32> DeriveHeaderMacKey(
      std::span<const uint8_t, 32> hybrid_key,
      const std::array<uint8_t, 16>& uuid) { // TSK024_Key_Rotation_and_Lifecycle_Management
    auto metadata_root =
        qv::core::DeriveMetadataKey(hybrid_key); // TSK024_Key_Rotation_and_Lifecycle_Management
    auto prk = qv::crypto::HMAC_SHA256::Compute( // TSK024_Key_Rotation_and_Lifecycle_Management
        std::span<const uint8_t>(uuid.data(),
                                 uuid.size()), // TSK024_Key_Rotation_and_Lifecycle_Management
        std::span<const uint8_t>(
            metadata_root.data(),
            metadata_root.size())); // TSK024_Key_Rotation_and_Lifecycle_Management
    static constexpr std::string_view kInfo{"QV-HEADER-MAC/v1"};
    std::array<uint8_t, kInfo.size() + 1> info_block{};
    std::memcpy(info_block.data(), kInfo.data(), kInfo.size());
    info_block[kInfo.size()] = 0x01;
    auto okm = qv::crypto::HMAC_SHA256::Compute(
        std::span<const uint8_t>(prk.data(), prk.size()),
        std::span<const uint8_t>(info_block.data(), info_block.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(prk.data(), prk.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(info_block.data(), info_block.size()));
    qv::security::Zeroizer::Wipe(
        std::span<uint8_t>(metadata_root.data(),
                           metadata_root.size())); // TSK024_Key_Rotation_and_Lifecycle_Management
    return okm;
  }

  template <typename T> void AppendRaw(std::vector<uint8_t>& out, const T& value) {
    auto bytes = qv::AsBytesConst(value);
    out.insert(out.end(), bytes.begin(), bytes.end());
  }

  class VectorWipeGuard { // TSK028_Secure_Deletion_and_Data_Remanence
  public:
    explicit VectorWipeGuard(std::vector<uint8_t>& vec) noexcept : vec_(vec) {}
    VectorWipeGuard(const VectorWipeGuard&) = delete;
    VectorWipeGuard& operator=(const VectorWipeGuard&) = delete;
    VectorWipeGuard(VectorWipeGuard&& other) noexcept : vec_(other.vec_), active_(other.active_) {
      other.active_ = false;
    }
    VectorWipeGuard& operator=(VectorWipeGuard&&) = delete;
    ~VectorWipeGuard() { Release(); }

    void Release() noexcept {
      if (!active_) {
        return;
      }
      qv::security::Zeroizer::WipeVector(vec_);
      vec_.clear();
      active_ = false;
    }

  private:
    std::vector<uint8_t>& vec_;
    bool active_{true};
  };

  void AppendUint16(std::vector<uint8_t>& out, uint16_t value) {
    const uint16_t le = ToLittleEndian16(value);
    AppendRaw(out, le);
  }

  void AppendUint32(std::vector<uint8_t>& out, uint32_t value) {
    const uint32_t le = qv::ToLittleEndian(value);
    AppendRaw(out, le);
  }

  struct ParsedHeader {               // TSK024_Key_Rotation_and_Lifecycle_Management
    VolumeHeader header{};            // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t header_version{0};       // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t pbkdf_iterations{0};     // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, kPbkdfSaltSize>
        pbkdf_salt{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, kHybridSaltSize>
        hybrid_salt{};                      // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::core::EpochTLV epoch_tlv{};         // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t epoch_value{0};                // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::core::PQC_KEM_TLV kem_blob{};       // TSK024_Key_Rotation_and_Lifecycle_Management
    ReservedV2Tlv reserved_v2{};            // TSK024_Key_Rotation_and_Lifecycle_Management
    bool reserved_v2_present{false};        // TSK033 optional TLV tracking
    std::array<uint8_t, qv::crypto::HMAC_SHA256::TAG_SIZE>
        mac{};                        // TSK024_Key_Rotation_and_Lifecycle_Management
    std::vector<uint8_t> payload;     // TSK024_Key_Rotation_and_Lifecycle_Management
  };

  struct DerivedKeyset {                // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> data{};     // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> metadata{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 32> index{};    // TSK024_Key_Rotation_and_Lifecycle_Management
  };

  DerivedKeyset MakeDerivedKeyset(
      std::span<const uint8_t, 32> master) {     // TSK024_Key_Rotation_and_Lifecycle_Management
    DerivedKeyset keys{};                        // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.data = qv::core::DeriveDataKey(master); // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.metadata =
        qv::core::DeriveMetadataKey(master);       // TSK024_Key_Rotation_and_Lifecycle_Management
    keys.index = qv::core::DeriveIndexKey(master); // TSK024_Key_Rotation_and_Lifecycle_Management
    return keys;                                   // TSK024_Key_Rotation_and_Lifecycle_Management
  }

  std::vector<uint8_t> SerializeHeaderPayload(
      const VolumeHeader& header, uint32_t pbkdf_iterations,
      const std::array<uint8_t, kPbkdfSaltSize>& pbkdf_salt,
      const std::array<uint8_t, kHybridSaltSize>& hybrid_salt, const qv::core::EpochTLV& epoch,
      const qv::core::PQC_KEM_TLV& kem_blob,
      const ReservedV2Tlv& reserved) { // TSK024_Key_Rotation_and_Lifecycle_Management
    std::vector<uint8_t> serialized;   // TSK024_Key_Rotation_and_Lifecycle_Management
    serialized.reserve(1024);          // TSK024_Key_Rotation_and_Lifecycle_Management

    AppendRaw(serialized, header); // TSK024_Key_Rotation_and_Lifecycle_Management

    AppendUint16(serialized, kTlvTypePbkdf2); // TSK024_Key_Rotation_and_Lifecycle_Management
    AppendUint16(serialized,
                 static_cast<uint16_t>(
                     4 + pbkdf_salt.size()));   // TSK024_Key_Rotation_and_Lifecycle_Management
    AppendUint32(serialized, pbkdf_iterations); // TSK024_Key_Rotation_and_Lifecycle_Management
    serialized.insert(serialized.end(), pbkdf_salt.begin(),
                      pbkdf_salt.end()); // TSK024_Key_Rotation_and_Lifecycle_Management

    AppendUint16(serialized, kTlvTypeHybridSalt); // TSK024_Key_Rotation_and_Lifecycle_Management
    AppendUint16(
        serialized,
        static_cast<uint16_t>(hybrid_salt.size())); // TSK024_Key_Rotation_and_Lifecycle_Management
    serialized.insert(serialized.end(), hybrid_salt.begin(),
                      hybrid_salt.end()); // TSK024_Key_Rotation_and_Lifecycle_Management

    AppendRaw(serialized, epoch); // TSK024_Key_Rotation_and_Lifecycle_Management

    auto pqc_blob = kem_blob; // TSK024_Key_Rotation_and_Lifecycle_Management
    pqc_blob.type =
        ToLittleEndian16(kTlvTypePqcKem); // TSK024_Key_Rotation_and_Lifecycle_Management
    pqc_blob.length = ToLittleEndian16(
        static_cast<uint16_t>(sizeof(qv::core::PQC_KEM_TLV) - sizeof(uint16_t) * 2));
    pqc_blob.version =
        ToLittleEndian16(pqc_blob.version); // TSK024_Key_Rotation_and_Lifecycle_Management
    pqc_blob.kem_id =
        ToLittleEndian16(pqc_blob.kem_id); // TSK024_Key_Rotation_and_Lifecycle_Management
    AppendRaw(serialized, pqc_blob);       // TSK024_Key_Rotation_and_Lifecycle_Management

    if (reserved.length > 0) {                         // TSK033 only emit when present
      auto reserved_copy = reserved;                   // TSK024_Key_Rotation_and_Lifecycle_Management
      uint16_t reserved_length = reserved_copy.length; // TSK033 clamp payload
      if (reserved_length > reserved_copy.payload.size()) { // TSK033 clamp payload
        reserved_length = static_cast<uint16_t>(reserved_copy.payload.size());
      }
      reserved_copy.type =
          ToLittleEndian16(kTlvTypeReservedV2); // TSK024_Key_Rotation_and_Lifecycle_Management
      reserved_copy.length =
          ToLittleEndian16(reserved_length); // TSK024_Key_Rotation_and_Lifecycle_Management
      AppendRaw(serialized, reserved_copy);  // TSK024_Key_Rotation_and_Lifecycle_Management
    }

    return serialized; // TSK024_Key_Rotation_and_Lifecycle_Management
  }

  ParsedHeader
  ParseHeader(const std::vector<uint8_t>& blob) { // TSK024_Key_Rotation_and_Lifecycle_Management
    if (blob.size() <
        sizeof(VolumeHeader) +
            qv::crypto::HMAC_SHA256::TAG_SIZE) { // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Invalid container header"};
    }

    ParsedHeader parsed{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::memcpy(&parsed.header, blob.data(),
                sizeof(VolumeHeader)); // TSK024_Key_Rotation_and_Lifecycle_Management
    parsed.header_version =
        qv::ToLittleEndian(parsed.header.version); // TSK024_Key_Rotation_and_Lifecycle_Management
    if (parsed.header.magic != kVolumeMagic) {     // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Unrecognized volume magic"};
    }

    const size_t mac_size =
        qv::crypto::HMAC_SHA256::TAG_SIZE; // TSK024_Key_Rotation_and_Lifecycle_Management
    const size_t payload_size =
        blob.size() - mac_size; // TSK024_Key_Rotation_and_Lifecycle_Management
    parsed.payload.assign(
        blob.begin(), blob.begin() + payload_size); // TSK024_Key_Rotation_and_Lifecycle_Management
    std::copy(blob.begin() + payload_size, blob.end(),
              parsed.mac.begin()); // TSK024_Key_Rotation_and_Lifecycle_Management

    size_t offset = sizeof(VolumeHeader); // TSK024_Key_Rotation_and_Lifecycle_Management
    bool have_pbkdf = false;
    bool have_hybrid = false;
    bool have_epoch = false;
    bool have_pqc = false;

    while (offset < payload_size) {
      if (payload_size - offset < sizeof(uint16_t) * 2) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Volume header truncated"};
      }
      uint16_t type_le = 0;
      uint16_t length_le = 0;
      std::memcpy(&type_le, parsed.payload.data() + offset, sizeof(type_le));
      std::memcpy(&length_le, parsed.payload.data() + offset + sizeof(uint16_t), sizeof(length_le));
      const uint16_t type = ToLittleEndian16(type_le);
      const uint16_t length = ToLittleEndian16(length_le);
      const size_t value_offset = offset + sizeof(uint16_t) * 2;
      if (value_offset + length > payload_size) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Volume header truncated"};
      }

      const uint8_t* value = parsed.payload.data() + value_offset;

      switch (type) {
      case kTlvTypePbkdf2: {
        if (length < sizeof(uint32_t)) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "PBKDF2 TLV malformed"};
        }
        std::memcpy(&parsed.pbkdf_iterations, value, sizeof(parsed.pbkdf_iterations));
        parsed.pbkdf_iterations =
            qv::ToLittleEndian(parsed.pbkdf_iterations); // TSK024_Key_Rotation_and_Lifecycle_Management
        const size_t salt_bytes = length - sizeof(uint32_t);
        if (salt_bytes != parsed.pbkdf_salt.size()) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "PBKDF2 salt length unexpected"};
        }
        std::memcpy(parsed.pbkdf_salt.data(), value + sizeof(uint32_t), salt_bytes);
        have_pbkdf = true;
        break;
      }
      case kTlvTypeHybridSalt: {
        if (length != parsed.hybrid_salt.size()) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Hybrid salt TLV malformed"};
        }
        std::memcpy(parsed.hybrid_salt.data(), value, parsed.hybrid_salt.size());
        have_hybrid = true;
        break;
      }
      case kTlvTypeEpoch: {
        if (length != sizeof(parsed.epoch_tlv.epoch)) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Epoch TLV malformed"};
        }
        parsed.epoch_tlv.type = ToLittleEndian16(kTlvTypeEpoch);
        parsed.epoch_tlv.length = qv::ToLittleEndian(static_cast<uint16_t>(length));
        std::memcpy(&parsed.epoch_tlv.epoch, value, sizeof(parsed.epoch_tlv.epoch));
        parsed.epoch_value = qv::ToLittleEndian(parsed.epoch_tlv.epoch);
        have_epoch = true;
        break;
      }
      case kTlvTypePqcKem: {
        if (length != sizeof(qv::core::PQC_KEM_TLV) - sizeof(uint16_t) * 2) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "PQC TLV malformed"};
        }
        parsed.kem_blob.type = ToLittleEndian16(kTlvTypePqcKem);
        parsed.kem_blob.length =
            ToLittleEndian16(static_cast<uint16_t>(length)); // TSK024_Key_Rotation_and_Lifecycle_Management
        std::memcpy(reinterpret_cast<uint8_t*>(&parsed.kem_blob) + sizeof(uint16_t) * 2, value,
                    length);
        parsed.kem_blob.version =
            ToLittleEndian16(parsed.kem_blob.version); // TSK024_Key_Rotation_and_Lifecycle_Management
        parsed.kem_blob.kem_id =
            ToLittleEndian16(parsed.kem_blob.kem_id); // TSK024_Key_Rotation_and_Lifecycle_Management
        have_pqc = true;
        break;
      }
      case kTlvTypeReservedV2: {
        if (length > parsed.reserved_v2.payload.size()) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Reserved TLV malformed"};
        }
        parsed.reserved_v2_present = length > 0;
        parsed.reserved_v2.type = ToLittleEndian16(kTlvTypeReservedV2);
        parsed.reserved_v2.length = static_cast<uint16_t>(length);
        std::fill(parsed.reserved_v2.payload.begin(), parsed.reserved_v2.payload.end(), 0);
        if (length > 0) {
          std::memcpy(parsed.reserved_v2.payload.data(), value, length);
        }
        break;
      }
      default:
        // TSK033 readers must skip unknown TLV types for forward compatibility
        break;
      }

      offset = value_offset + length;
    }

    if (offset != payload_size) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Unexpected trailing bytes in header"};
    }
    if (!have_pbkdf || !have_hybrid || !have_epoch || !have_pqc) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Required TLV missing"};
    }

    return parsed; // TSK024_Key_Rotation_and_Lifecycle_Management
  }

  std::filesystem::path MetadataDirFor(
      const std::filesystem::path& container) { // TSK024_Key_Rotation_and_Lifecycle_Management
    auto parent = container.parent_path();      // TSK024_Key_Rotation_and_Lifecycle_Management
    auto name = container.filename().string();  // TSK024_Key_Rotation_and_Lifecycle_Management
    if (name.empty()) {                         // TSK024_Key_Rotation_and_Lifecycle_Management
      name = "volume";                          // TSK024_Key_Rotation_and_Lifecycle_Management
    }
    return parent / (name + ".meta"); // TSK024_Key_Rotation_and_Lifecycle_Management
  }

#pragma pack(push, 1)
  struct KeyBackupRecord { // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<char, 8> magic{'Q', 'V', 'B',  'A',
                              'C', 'K', '\0', '\0'}; // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t version =
        qv::ToLittleEndian(0x00010000u); // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, 16> uuid{};      // TSK024_Key_Rotation_and_Lifecycle_Management
    uint32_t epoch{0};                   // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::core::PQC::CIPHERTEXT_SIZE>
        kem_ct{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>
        nonce{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, qv::crypto::AES256_GCM::TAG_SIZE>
        tag{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::array<uint8_t, sizeof(DerivedKeyset)>
        encrypted_keys{}; // TSK024_Key_Rotation_and_Lifecycle_Management
  };
#pragma pack(pop)

  std::optional<std::filesystem::path>
  PerformKeyBackup(const std::filesystem::path& container, uint32_t epoch,
                   const std::array<uint8_t, 16>& uuid, DerivedKeyset& keyset,
                   const std::filesystem::path&
                       backup_public_key) { // TSK024_Key_Rotation_and_Lifecycle_Management
    std::ifstream in(backup_public_key,
                     std::ios::binary); // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!in) {                          // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;            // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to open backup key: " + backup_public_key.string()};
    }
    std::vector<uint8_t> pk_bytes((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());
    VectorWipeGuard pk_guard(pk_bytes); // TSK028_Secure_Deletion_and_Data_Remanence
    if (pk_bytes.size() !=
        qv::core::PQC::PUBLIC_KEY_SIZE) { // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Backup key size mismatch"};
    }
    std::array<uint8_t, qv::core::PQC::PUBLIC_KEY_SIZE>
        pk{}; // TSK024_Key_Rotation_and_Lifecycle_Management
    std::copy(pk_bytes.begin(), pk_bytes.end(),
              pk.begin()); // TSK024_Key_Rotation_and_Lifecycle_Management

    qv::core::PQCKeyEncapsulation kem; // TSK024_Key_Rotation_and_Lifecycle_Management
    auto enc = kem.Encapsulate(pk);    // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::security::Zeroizer::ScopeWiper secret_guard(enc.shared_secret.data(),
                                                    enc.shared_secret.size());

    std::array<uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>
        nonce{};       // TSK024_Key_Rotation_and_Lifecycle_Management
    FillRandom(nonce); // TSK024_Key_Rotation_and_Lifecycle_Management

    static constexpr std::string_view kBackupContext{
        "QV-BACKUP/v1"};            // TSK024_Key_Rotation_and_Lifecycle_Management
    std::vector<uint8_t> aad;       // TSK024_Key_Rotation_and_Lifecycle_Management
    VectorWipeGuard aad_guard(aad); // TSK028_Secure_Deletion_and_Data_Remanence
    aad.insert(aad.end(), kBackupContext.begin(),
               kBackupContext.end());                // TSK024_Key_Rotation_and_Lifecycle_Management
    aad.insert(aad.end(), uuid.begin(), uuid.end()); // TSK024_Key_Rotation_and_Lifecycle_Management
    const uint32_t epoch_le =
        qv::ToLittleEndian(epoch); // TSK024_Key_Rotation_and_Lifecycle_Management
    const uint8_t* epoch_bytes =
        reinterpret_cast<const uint8_t*>(&epoch_le); // TSK024_Key_Rotation_and_Lifecycle_Management
    aad.insert(aad.end(), epoch_bytes,
               epoch_bytes + sizeof(epoch_le)); // TSK024_Key_Rotation_and_Lifecycle_Management

    auto keyset_bytes = qv::AsBytesConst(keyset); // TSK024_Key_Rotation_and_Lifecycle_Management
    auto enc_result =
        qv::crypto::AES256_GCM_Encrypt( // TSK024_Key_Rotation_and_Lifecycle_Management
            keyset_bytes, std::span<const uint8_t>(aad.data(), aad.size()),
            std::span<const uint8_t, qv::crypto::AES256_GCM::NONCE_SIZE>(nonce.data(),
                                                                         nonce.size()),
            std::span<const uint8_t, qv::crypto::AES256_GCM::KEY_SIZE>(enc.shared_secret.data(),
                                                                       enc.shared_secret.size()));
    VectorWipeGuard ciphertext_guard(
        enc_result.ciphertext); // TSK028_Secure_Deletion_and_Data_Remanence
    qv::security::Zeroizer::ScopeWiper tag_guard(enc_result.tag.data(), enc_result.tag.size());
    if (enc_result.ciphertext.size() !=
        sizeof(DerivedKeyset)) { // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::Crypto, 0, "Unexpected backup ciphertext length"};
    }

    KeyBackupRecord record{};                 // TSK024_Key_Rotation_and_Lifecycle_Management
    record.uuid = uuid;                       // TSK024_Key_Rotation_and_Lifecycle_Management
    record.epoch = qv::ToLittleEndian(epoch); // TSK024_Key_Rotation_and_Lifecycle_Management
    record.kem_ct = enc.ciphertext;           // TSK024_Key_Rotation_and_Lifecycle_Management
    record.nonce = nonce;                     // TSK024_Key_Rotation_and_Lifecycle_Management
    record.tag = enc_result.tag;              // TSK024_Key_Rotation_and_Lifecycle_Management
    std::copy(enc_result.ciphertext.begin(),
              enc_result.ciphertext.end(), // TSK024_Key_Rotation_and_Lifecycle_Management
              record.encrypted_keys.begin());

    auto metadata_dir = MetadataDirFor(container); // TSK024_Key_Rotation_and_Lifecycle_Management
    std::filesystem::create_directories(
        metadata_dir);                // TSK024_Key_Rotation_and_Lifecycle_Management
    auto backup_path = metadata_dir / // TSK024_Key_Rotation_and_Lifecycle_Management
                       ("key_backup.epoch_" + std::to_string(epoch) +
                        ".bin"); // TSK024_Key_Rotation_and_Lifecycle_Management

    std::ofstream out(backup_path,
                      std::ios::binary |
                          std::ios::trunc); // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!out) {                             // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;                // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to write backup file: " + backup_path.string()};
    }
    out.write(reinterpret_cast<const char*>(&record),
              sizeof(record)); // TSK024_Key_Rotation_and_Lifecycle_Management
    if (!out) {                // TSK024_Key_Rotation_and_Lifecycle_Management
      const int err = errno;   // TSK024_Key_Rotation_and_Lifecycle_Management
      throw qv::Error{qv::ErrorDomain::IO, err,
                      "Failed to persist backup file: " + backup_path.string()};
    }

    qv::security::Zeroizer::Wipe(
        std::span<uint8_t>(enc.shared_secret.data(), enc.shared_secret.size()));
    qv::security::Zeroizer::Wipe(
        std::span<uint8_t>(enc_result.ciphertext.data(), enc_result.ciphertext.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(aad.data(), aad.size()));

    return backup_path; // TSK024_Key_Rotation_and_Lifecycle_Management
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
  VectorWipeGuard password_guard(password_bytes); // TSK028_Secure_Deletion_and_Data_Remanence
  auto classical_key = DerivePasswordKey({password_bytes.data(), password_bytes.size()}, pbkdf_salt,
                                         kDefaultPbkdfIterations);
  qv::security::Zeroizer::ScopeWiper classical_guard(classical_key.data(), classical_key.size());
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
  qv::security::Zeroizer::ScopeWiper creation_guard(creation.hybrid_key.data(),
                                                    creation.hybrid_key.size());

  auto mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()),
      header.uuid); // TSK024_Key_Rotation_and_Lifecycle_Management
  qv::security::Zeroizer::ScopeWiper mac_guard(
      mac_key.data(), mac_key.size()); // TSK028_Secure_Deletion_and_Data_Remanence

  ReservedV2Tlv reserved_v2{};
  auto payload = SerializeHeaderPayload(
      header, kDefaultPbkdfIterations, pbkdf_salt, hybrid_salt, epoch, creation.kem_blob,
      reserved_v2); // TSK024_Key_Rotation_and_Lifecycle_Management

  auto mac =
      qv::crypto::HMAC_SHA256::Compute(std::span<const uint8_t>(mac_key.data(), mac_key.size()),
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

  qv::orchestrator::Event created{}; // TSK029
  created.category = EventCategory::kLifecycle;
  created.severity = EventSeverity::kInfo;
  created.event_id = "volume_created";
  created.message = "New encrypted volume created";
  created.fields.emplace_back("container", qv::PathToUtf8String(container), FieldPrivacy::kRedact);
  created.fields.emplace_back("uuid", FormatUuid(header.uuid), FieldPrivacy::kPublic);
  created.fields.emplace_back("pbkdf_iterations", std::to_string(kDefaultPbkdfIterations),
                              FieldPrivacy::kPublic, true);
  qv::orchestrator::EventBus::Instance().Publish(created);

  return ConstantTimeMount::VolumeHandle{1};
}

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Mount(const std::filesystem::path& container, const std::string& password) {
  auto handle = ctm_.Mount(container, password); // TSK029
  if (handle) {
    qv::orchestrator::Event mounted{}; // TSK029
    mounted.category = EventCategory::kLifecycle;
    mounted.severity = EventSeverity::kInfo;
    mounted.event_id = "volume_mounted";
    mounted.message = "Encrypted volume mounted";
    mounted.fields.emplace_back("container", qv::PathToUtf8String(container),
                                FieldPrivacy::kRedact);
    qv::orchestrator::EventBus::Instance().Publish(mounted);
  }
  return handle;
}

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Rekey(const std::filesystem::path& container, const std::string& current_password,
                     const std::string& new_password,
                     std::optional<std::filesystem::path> backup_public_key) {
  if (!std::filesystem::exists(container)) { // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::IO, qv::errors::io::kContainerMissing,
                    "Container not found: " + container.string()};
  }

  qv::orchestrator::Event initiated{}; // TSK029
  initiated.category = EventCategory::kLifecycle;
  initiated.severity = EventSeverity::kInfo;
  initiated.event_id = "rekey_initiated";
  initiated.message = "Volume rekey operation started";
  initiated.fields.emplace_back("container", qv::PathToUtf8String(container),
                                FieldPrivacy::kRedact);
  qv::orchestrator::EventBus::Instance().Publish(initiated);

  std::ifstream in(container, std::ios::binary); // TSK024_Key_Rotation_and_Lifecycle_Management
  if (!in) {                                     // TSK024_Key_Rotation_and_Lifecycle_Management
    const int err = errno;                       // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open container for rekey: " + container.string()};
  }

  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto parsed = ParseHeader(blob); // TSK024_Key_Rotation_and_Lifecycle_Management

  std::vector<uint8_t> current_bytes(current_password.begin(), current_password.end());
  VectorWipeGuard current_guard(current_bytes); // TSK028_Secure_Deletion_and_Data_Remanence
  auto classical_key = DerivePasswordKey({current_bytes.data(), current_bytes.size()},
                                         parsed.pbkdf_salt, parsed.pbkdf_iterations);
  qv::security::Zeroizer::ScopeWiper classical_guard(classical_key.data(), classical_key.size());
  if (!current_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(current_bytes.data(), current_bytes.size()));
  }

  auto hybrid_key = qv::core::PQCHybridKDF::Mount(
      std::span<const uint8_t, 32>(classical_key.data(), classical_key.size()), parsed.kem_blob,
      std::span<const uint8_t>(parsed.hybrid_salt.data(), parsed.hybrid_salt.size()),
      std::span<const uint8_t, 16>(parsed.header.uuid), parsed.header_version,
      qv::AsBytesConst(parsed.epoch_tlv)); // TSK024_Key_Rotation_and_Lifecycle_Management
  qv::security::Zeroizer::ScopeWiper hybrid_guard(hybrid_key.data(), hybrid_key.size());

  auto mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(hybrid_key.data(), hybrid_key.size()), parsed.header.uuid);
  qv::security::Zeroizer::ScopeWiper mac_guard(mac_key.data(), mac_key.size());

  auto expected_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(parsed.payload.data(), parsed.payload.size()));

  if (expected_mac != parsed.mac) { // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::AuthenticationFailureError("Header authentication failed");
  }

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  if (parsed.epoch_value ==
      std::numeric_limits<uint32_t>::max()) { // TSK024_Key_Rotation_and_Lifecycle_Management
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    throw qv::Error{qv::ErrorDomain::State, 0, "Epoch counter overflow"};
  }

  const uint32_t old_epoch = parsed.epoch_value; // TSK024_Key_Rotation_and_Lifecycle_Management
  const uint32_t new_epoch = old_epoch + 1;      // TSK024_Key_Rotation_and_Lifecycle_Management

  std::array<uint8_t, kPbkdfSaltSize>
      new_pbkdf_salt{}; // TSK024_Key_Rotation_and_Lifecycle_Management
  std::array<uint8_t, kHybridSaltSize>
      new_hybrid_salt{}; // TSK024_Key_Rotation_and_Lifecycle_Management
  FillRandom(new_pbkdf_salt);
  FillRandom(new_hybrid_salt);

  std::vector<uint8_t> new_bytes(new_password.begin(), new_password.end());
  VectorWipeGuard new_guard(new_bytes); // TSK028_Secure_Deletion_and_Data_Remanence
  auto new_classical_key = DerivePasswordKey({new_bytes.data(), new_bytes.size()}, new_pbkdf_salt,
                                             kDefaultPbkdfIterations);
  qv::security::Zeroizer::ScopeWiper new_classical_guard(new_classical_key.data(),
                                                         new_classical_key.size());
  if (!new_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(new_bytes.data(), new_bytes.size()));
  }

  auto new_epoch_tlv =
      qv::core::MakeEpochTlv(new_epoch); // TSK024_Key_Rotation_and_Lifecycle_Management
  auto creation = qv::core::PQCHybridKDF::Create(
      std::span<const uint8_t, 32>(new_classical_key.data(), new_classical_key.size()),
      std::span<const uint8_t>(new_hybrid_salt.data(), new_hybrid_salt.size()),
      std::span<const uint8_t, 16>(parsed.header.uuid), parsed.header_version,
      qv::AsBytesConst(new_epoch_tlv));
  qv::security::Zeroizer::ScopeWiper creation_guard(creation.hybrid_key.data(),
                                                    creation.hybrid_key.size());

  auto new_mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()),
      parsed.header.uuid);
  qv::security::Zeroizer::ScopeWiper new_mac_guard(new_mac_key.data(), new_mac_key.size());

  auto derived_keys = MakeDerivedKeyset(
      std::span<const uint8_t, 32>(creation.hybrid_key.data(), creation.hybrid_key.size()));
  qv::security::Zeroizer::ScopeWiper derived_data_guard(derived_keys.data.data(),
                                                        derived_keys.data.size());
  qv::security::Zeroizer::ScopeWiper derived_metadata_guard(derived_keys.metadata.data(),
                                                            derived_keys.metadata.size());
  qv::security::Zeroizer::ScopeWiper derived_index_guard(derived_keys.index.data(),
                                                         derived_keys.index.size());

  auto payload =
      SerializeHeaderPayload(parsed.header, kDefaultPbkdfIterations, new_pbkdf_salt,
                             new_hybrid_salt, new_epoch_tlv, creation.kem_blob,
                             parsed.reserved_v2); // TSK024_Key_Rotation_and_Lifecycle_Management

  auto new_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(new_mac_key.data(), new_mac_key.size()),
      std::span<const uint8_t>(payload.data(), payload.size()));
  payload.insert(payload.end(), new_mac.begin(), new_mac.end());

  if (payload.size() !=
      parsed.payload.size() + parsed.mac.size()) { // TSK024_Key_Rotation_and_Lifecycle_Management
    throw qv::Error{qv::ErrorDomain::Internal, 0, "Header size changed unexpectedly"};
  }

  std::fstream out(container, std::ios::binary | std::ios::in |
                                  std::ios::out); // TSK024_Key_Rotation_and_Lifecycle_Management
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

  std::optional<std::filesystem::path> backup_path; // TSK024_Key_Rotation_and_Lifecycle_Management
  if (backup_public_key) {
    backup_path = PerformKeyBackup(container, new_epoch, parsed.header.uuid, derived_keys,
                                   *backup_public_key);
  }

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(new_classical_key.data(), new_classical_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(creation.hybrid_key.data(), creation.hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(new_mac_key.data(), new_mac_key.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(derived_keys.data.data(), derived_keys.data.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(derived_keys.metadata.data(), derived_keys.metadata.size()));
  qv::security::Zeroizer::Wipe(
      std::span<uint8_t>(derived_keys.index.data(), derived_keys.index.size()));

  qv::orchestrator::Event event{}; // TSK024_Key_Rotation_and_Lifecycle_Management
  event.category = EventCategory::kSecurity;
  event.severity = EventSeverity::kInfo;
  event.event_id = "volume_rekeyed";
  event.message = "Volume encryption keys rotated";
  event.fields.emplace_back("container", qv::PathToUtf8String(container), FieldPrivacy::kRedact);
  event.fields.emplace_back("old_epoch", std::to_string(old_epoch), FieldPrivacy::kPublic, true);
  event.fields.emplace_back("new_epoch", std::to_string(new_epoch), FieldPrivacy::kPublic, true);
  event.fields.emplace_back("key_material_destroyed", "true", FieldPrivacy::kPublic);
  if (backup_public_key) {
    event.fields.emplace_back("backup_escrow",
                              backup_path ? qv::PathToUtf8String(*backup_path)
                                          : qv::PathToUtf8String(*backup_public_key),
                              FieldPrivacy::kRedact);
  }
  qv::orchestrator::EventBus::Instance().Publish(event);

  return ConstantTimeMount::VolumeHandle{1}; // TSK024_Key_Rotation_and_Lifecycle_Management
}

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Migrate(const std::filesystem::path& container, uint32_t target_version,
                       const std::string& password) { // TSK033
  if (!std::filesystem::exists(container)) { // TSK033
    throw qv::Error{qv::ErrorDomain::IO, qv::errors::io::kContainerMissing,
                    "Container not found: " + container.string()};
  }

  if (target_version == 0) { // TSK033 treat zero as request for latest
    target_version = VolumeManager::kLatestHeaderVersion;
  }

  std::ifstream in(container, std::ios::binary); // TSK033
  if (!in) {
    const int err = errno;
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open container for migration: " + container.string()};
  }
  std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto parsed = ParseHeader(blob); // TSK033 reuse validated parser

  std::vector<uint8_t> password_bytes(password.begin(), password.end());
  VectorWipeGuard password_guard(password_bytes); // TSK028_Secure_Deletion_and_Data_Remanence
  auto classical_key = DerivePasswordKey({password_bytes.data(), password_bytes.size()},
                                         parsed.pbkdf_salt, parsed.pbkdf_iterations); // TSK033
  qv::security::Zeroizer::ScopeWiper classical_guard(classical_key.data(), classical_key.size());
  if (!password_bytes.empty()) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(password_bytes.data(), password_bytes.size()));
  }

  auto hybrid_key = qv::core::PQCHybridKDF::Mount(
      std::span<const uint8_t, 32>(classical_key.data(), classical_key.size()), parsed.kem_blob,
      std::span<const uint8_t>(parsed.hybrid_salt.data(), parsed.hybrid_salt.size()),
      std::span<const uint8_t, 16>(parsed.header.uuid), parsed.header_version,
      qv::AsBytesConst(parsed.epoch_tlv)); // TSK033 authenticate existing header state
  qv::security::Zeroizer::ScopeWiper hybrid_guard(hybrid_key.data(), hybrid_key.size());

  auto mac_key = DeriveHeaderMacKey(
      std::span<const uint8_t, 32>(hybrid_key.data(), hybrid_key.size()), parsed.header.uuid); // TSK033
  qv::security::Zeroizer::ScopeWiper mac_guard(mac_key.data(), mac_key.size());

  auto expected_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(parsed.payload.data(), parsed.payload.size()));
  if (expected_mac != parsed.mac) { // TSK033 enforce password correctness
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::AuthenticationFailureError("Header authentication failed");
  }

  const uint32_t current_version = parsed.header_version; // TSK033
  if (current_version == target_version) {
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    return std::nullopt;
  }

  if (current_version > target_version) { // TSK033 block downgrades
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Cannot downgrade volume header version"};
  }

  constexpr uint32_t kVersionV4_0 = 0x00040000u; // TSK033 legacy baseline
  if (!(current_version == kVersionV4_0 &&
        target_version == VolumeManager::kLatestHeaderVersion)) { // TSK033 supported path
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{qv::ErrorDomain::Validation, 0, "No migration path available"};
  }

  ReservedV2Tlv reserved = parsed.reserved_v2_present ? parsed.reserved_v2 : ReservedV2Tlv{}; // TSK033
  if (!parsed.reserved_v2_present) { // TSK033 add ACL staging TLV for new version
    reserved.length = static_cast<uint16_t>(reserved.payload.size());
  }

  parsed.header.version = qv::ToLittleEndian(target_version); // TSK033 bump version field
  auto payload = SerializeHeaderPayload(parsed.header, parsed.pbkdf_iterations, parsed.pbkdf_salt,
                                        parsed.hybrid_salt, parsed.epoch_tlv, parsed.kem_blob,
                                        reserved); // TSK033 rebuild header TLVs
  auto new_mac = qv::crypto::HMAC_SHA256::Compute(
      std::span<const uint8_t>(mac_key.data(), mac_key.size()),
      std::span<const uint8_t>(payload.data(), payload.size()));
  payload.insert(payload.end(), new_mac.begin(), new_mac.end());

  std::fstream out(container, std::ios::binary | std::ios::in | std::ios::out); // TSK033
  if (!out) {
    const int err = errno;
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to open container for migration write: " + container.string()};
  }
  out.seekp(0);
  out.write(reinterpret_cast<const char*>(payload.data()),
            static_cast<std::streamsize>(payload.size()));
  if (!out) {
    const int err = errno;
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
    qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));
    throw qv::Error{qv::ErrorDomain::IO, err,
                    "Failed to persist migrated header: " + container.string()};
  }
  out.flush();

  qv::security::Zeroizer::Wipe(std::span<uint8_t>(classical_key.data(), classical_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(hybrid_key.data(), hybrid_key.size()));
  qv::security::Zeroizer::Wipe(std::span<uint8_t>(mac_key.data(), mac_key.size()));

  auto format_version = [](uint32_t version) { // TSK033 helper for diagnostics
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << version;
    return oss.str();
  };

  qv::orchestrator::Event event{}; // TSK033
  event.category = EventCategory::kLifecycle;
  event.severity = EventSeverity::kInfo;
  event.event_id = "volume_migrated";
  event.message = "Volume header format upgraded";
  event.fields.emplace_back("container", qv::PathToUtf8String(container), FieldPrivacy::kRedact);
  event.fields.emplace_back("from_version", format_version(current_version), FieldPrivacy::kPublic,
                            true);
  event.fields.emplace_back("to_version", format_version(target_version), FieldPrivacy::kPublic,
                            true);
  qv::orchestrator::EventBus::Instance().Publish(event);

  return ConstantTimeMount::VolumeHandle{1};
}
