#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#include "qv/common.h"
#include "qv/core/header.h"
#include "qv/core/integrity.h"
#include "qv/core/nonce.h"
#include "qv/core/pqc_hybrid_kdf.h"
#include "qv/crypto/hmac_sha256.h"
#include "qv/error.h"
#include "qv/tlv/parser.h"

// TSK715_Header_Integrity_Chain_and_qv-fsck container audit tool

namespace {

constexpr std::array<uint8_t, 8> kHeaderMagic = {'Q', 'V', 'A', 'U', 'L', 'T', '\0', '\0'}; // TSK715_Header_Integrity_Chain_and_qv-fsck
constexpr uint32_t kSupportedHeaderVersion = 0x00040101u;                                       // TSK715_Header_Integrity_Chain_and_qv-fsck
constexpr uint16_t kTlvTypeReservedV2 = 0x7F02u;                                                // TSK715_Header_Integrity_Chain_and_qv-fsck
constexpr uint16_t kTlvTypeEpoch = 0x4E4Fu;                                                     // TSK715_Header_Integrity_Chain_and_qv-fsck
constexpr uint16_t kTlvTypeHiddenDescriptor = 0x4844u;                                          // TSK715_Header_Integrity_Chain_and_qv-fsck
constexpr size_t kPbkdfSaltSize = 16;                                                           // TSK715_Header_Integrity_Chain_and_qv-fsck
constexpr size_t kHybridSaltSize = 32;                                                          // TSK715_Header_Integrity_Chain_and_qv-fsck
constexpr size_t kReservedV2PayloadBytes = 32;                                                  // TSK715_Header_Integrity_Chain_and_qv-fsck
constexpr size_t kPasswordTlvBytes =                                                             // TSK715_Header_Integrity_Chain_and_qv-fsck
    4 + std::max<size_t>(4 + kPbkdfSaltSize, sizeof(uint32_t) * 6 + kPbkdfSaltSize);

#pragma pack(push, 1)
struct VolumeHeader { // TSK715_Header_Integrity_Chain_and_qv-fsck packed header
  std::array<uint8_t, 8> magic{};
  uint32_t version{0};
  std::array<uint8_t, 16> uuid{};
  uint32_t flags{0};
};

struct ReservedV2Tlv { // TSK715_Header_Integrity_Chain_and_qv-fsck reserved payload view
  uint16_t type = qv::ToLittleEndian16(kTlvTypeReservedV2);
  uint16_t length = qv::ToLittleEndian16(kReservedV2PayloadBytes);
  std::array<uint8_t, kReservedV2PayloadBytes> payload{};
};
#pragma pack(pop)

constexpr size_t kSerializedHeaderBytes = // TSK715_Header_Integrity_Chain_and_qv-fsck full metadata span
    sizeof(VolumeHeader) + kPasswordTlvBytes + 4 + kHybridSaltSize + sizeof(qv::core::EpochTLV) +
    sizeof(qv::core::PQC_KEM_TLV) + sizeof(ReservedV2Tlv);
constexpr size_t kHeaderMacSize = qv::crypto::HMAC_SHA256::TAG_SIZE; // TSK715_Header_Integrity_Chain_and_qv-fsck
constexpr size_t kTotalHeaderBytes = kSerializedHeaderBytes + kHeaderMacSize; // TSK715_Header_Integrity_Chain_and_qv-fsck

struct ParsedHeader { // TSK715_Header_Integrity_Chain_and_qv-fsck fsck context
  std::vector<uint8_t> bytes;
  qv::core::IntegrityRoot stored_root{};
  uint32_t epoch{0};
  std::optional<qv::core::HiddenVolumeDescriptor> hidden_descriptor;
};

std::vector<uint8_t> ReadHeaderBytes(const std::filesystem::path& container) { // TSK715_Header_Integrity_Chain_and_qv-fsck
  std::ifstream in(container, std::ios::binary);
  if (!in) {
    throw std::runtime_error("Failed to open container: " + container.string());
  }
  std::vector<uint8_t> buffer(kTotalHeaderBytes, 0);
  in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
  if (static_cast<size_t>(in.gcount()) != buffer.size()) {
    throw std::runtime_error("Container header truncated: " + container.string());
  }
  return buffer;
}

ParsedHeader ParseHeader(const std::vector<uint8_t>& header_bytes) { // TSK715_Header_Integrity_Chain_and_qv-fsck
  ParsedHeader parsed{};
  parsed.bytes = header_bytes;

  if (header_bytes.size() < sizeof(VolumeHeader)) {
    throw std::runtime_error("Container header too small");
  }
  VolumeHeader header{};
  std::memcpy(&header, header_bytes.data(), sizeof(header));
  if (!std::equal(header.magic.begin(), header.magic.end(), kHeaderMagic.begin(), kHeaderMagic.end())) {
    throw std::runtime_error("Container magic mismatch");
  }
  const uint32_t version = qv::FromLittleEndian32(header.version);
  if (version > kSupportedHeaderVersion) {
    throw std::runtime_error("Unsupported container version");
  }

  const auto tlv_region = std::span<const uint8_t>(header_bytes.data() + sizeof(VolumeHeader),
                                                   kSerializedHeaderBytes - sizeof(VolumeHeader));
  qv::tlv::Parser parser(tlv_region, 32, 64 * 1024);
  if (!parser.valid()) {
    throw std::runtime_error("Header TLV parse failed");
  }

  for (const auto& record : parser) {
    if (record.type == kTlvTypeReservedV2) {
      parsed.stored_root = qv::core::ParseIntegrityRoot(record.value);
    } else if (record.type == kTlvTypeEpoch && record.value.size() == sizeof(uint32_t)) {
      uint32_t epoch_le = 0;
      std::memcpy(&epoch_le, record.value.data(), sizeof(uint32_t));
      parsed.epoch = qv::FromLittleEndian32(epoch_le);
    } else if (record.type == kTlvTypeHiddenDescriptor &&
               record.value.size() == sizeof(qv::core::HiddenVolumeDescriptor)) {
      qv::core::HiddenVolumeDescriptor descriptor{};
      std::memcpy(&descriptor, record.value.data(), record.value.size());
      parsed.hidden_descriptor = descriptor;
    }
  }

  return parsed;
}

std::vector<qv::core::MetadataPageView> BuildMetadataPages(
    const std::vector<uint8_t>& header_bytes) { // TSK715_Header_Integrity_Chain_and_qv-fsck leaf builder
  std::vector<qv::core::MetadataPageView> pages;
  const auto metadata = std::span<const uint8_t>(header_bytes.data(), kSerializedHeaderBytes);
  size_t offset = 0;
  while (offset < metadata.size()) {
    const size_t chunk = std::min(qv::core::kMetadataIntegrityLeafSize, metadata.size() - offset);
    pages.push_back(qv::core::MetadataPageView{
        metadata.subspan(offset, chunk),
        "header"});
    offset += chunk;
  }
  return pages;
}

std::string Hex(std::span<const uint8_t> data) { // TSK715_Header_Integrity_Chain_and_qv-fsck pretty printer
  std::ostringstream oss;
  for (auto byte : data) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
  }
  return oss.str();
}

}  // namespace

int main(int argc, char** argv) { // TSK715_Header_Integrity_Chain_and_qv-fsck entrypoint
  bool repair = false;
  bool verify = false;
  std::vector<std::string> positional;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--repair") {
      repair = true;
    } else if (arg == "--verify") {
      verify = true;
    } else if (arg == "--help" || arg == "-h") {
      std::cout << "Usage: qv-fsck [--verify] [--repair] <container>\n";
      return 0;
    } else {
      positional.push_back(arg);
    }
  }
  if (positional.size() != 1) {
    std::cerr << "qv-fsck expects exactly one container path" << std::endl;
    return 1;
  }
  if (!verify && !repair) {
    verify = true;
  }

  try {
    const auto container = std::filesystem::path(positional.front());
    auto header_bytes = ReadHeaderBytes(container);
    auto parsed = ParseHeader(header_bytes);
    auto pages = BuildMetadataPages(parsed.bytes);

    const auto report = qv::core::VerifyMetadataIntegrity(parsed.stored_root, pages);
    if (verify) {
      if (report.ok) {
        std::cout << "Metadata integrity verified." << std::endl;
      } else {
        std::cout << "Metadata integrity mismatch." << std::endl;
        std::cout << "  Stored root:   "
                  << Hex(std::span<const uint8_t>(parsed.stored_root.merkle_root)) << std::endl;
        std::cout << "  Computed root: "
                  << Hex(std::span<const uint8_t>(report.computed.merkle_root)) << std::endl;
        if (parsed.stored_root.parity_valid) {
          std::cout << "  Stored parity: "
                    << Hex(std::span<const uint8_t>(parsed.stored_root.parity)) << std::endl;
          std::cout << "  Computed parity: "
                    << Hex(std::span<const uint8_t>(report.computed.parity)) << std::endl;
        }
        if (report.failing_leaf != static_cast<size_t>(-1)) {
          std::cout << "  Suspect leaf index: " << report.failing_leaf << std::endl;
        }
      }
    }

    if (parsed.hidden_descriptor) {
      const auto& descriptor = *parsed.hidden_descriptor;
      const uint64_t hidden_start = descriptor.start_offset;
      const uint64_t hidden_end = hidden_start + descriptor.length;
      if (hidden_end <= kSerializedHeaderBytes) {
        std::cout << "Warning: hidden volume descriptor overlaps metadata region" << std::endl;
      }
    }

    if (repair) {
      auto regenerated = qv::core::ComputeMetadataIntegrityRoot(parsed.epoch, pages, true);
      std::cout << "Proposed root:  "
                << Hex(std::span<const uint8_t>(regenerated.merkle_root)) << std::endl;
      if (regenerated.parity_valid) {
        std::cout << "Proposed parity: "
                  << Hex(std::span<const uint8_t>(regenerated.parity)) << std::endl;
      }
      std::cout << "Automatic header rewriting is disabled; update reserved TLV with caution." << std::endl;
    }

    return report.ok ? 0 : 2;
  } catch (const std::exception& ex) {
    std::cerr << "qv-fsck failed: " << ex.what() << std::endl;
    return 1;
  }
}

