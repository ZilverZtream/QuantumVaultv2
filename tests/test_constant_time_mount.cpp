#include "qv/orchestrator/constant_time_mount.h"
#include "qv/core/pqc_hybrid_kdf.h"
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
#include <vector>

namespace {
// TSK004
constexpr std::array<uint8_t, 8> kMagic = {'Q','V','C','T','M','T','4','1'};
constexpr uint16_t kVersion = 0x0401;

#pragma pack(push, 1)
struct HeaderFixed {
  std::array<uint8_t, 8> magic{};
  uint16_t version{};
  uint16_t reserved{};
  uint32_t header_size{};
  uint32_t pbkdf_iterations{};
  std::array<uint8_t, 16> pbkdf_salt{};
  std::array<uint8_t, 32> hybrid_salt{};
};

struct ContainerHeaderWire {
  HeaderFixed fixed;
  qv::core::PQC_KEM_TLV pqc;
  std::array<uint8_t, 32> mac{};
};
#pragma pack(pop)

static_assert(sizeof(ContainerHeaderWire) == sizeof(HeaderFixed) + sizeof(qv::core::PQC_KEM_TLV) + 32);

std::array<uint8_t, 32> DeriveKey(const std::string& password, const HeaderFixed& header) {
  std::vector<uint8_t> pw(password.begin(), password.end());
  std::array<uint8_t, 32> out{};
  std::array<uint8_t, 20> block{};
  std::memcpy(block.data(), header.pbkdf_salt.data(), header.pbkdf_salt.size());
  block[16] = 0;
  block[17] = 0;
  block[18] = 0;
  block[19] = 1;
  auto u = qv::crypto::HMAC_SHA256::Compute(pw, {block.data(), block.size()});
  out = u;
  auto iter = u;
  for (uint32_t i = 1; i < header.pbkdf_iterations; ++i) {
    iter = qv::crypto::HMAC_SHA256::Compute(pw, {iter.data(), iter.size()});
    for (size_t j = 0; j < out.size(); ++j) {
      out[j] ^= iter[j];
    }
  }
  return out;
}

std::array<uint8_t, sizeof(ContainerHeaderWire)> Serialize(const ContainerHeaderWire& header) {
  std::array<uint8_t, sizeof(ContainerHeaderWire)> bytes{};
  std::memcpy(bytes.data(), &header, sizeof(ContainerHeaderWire));
  return bytes;
}

void WriteValidContainer(const std::filesystem::path& p, const std::string& password) {
  ContainerHeaderWire header{};
  header.fixed.magic = kMagic;
  header.fixed.version = kVersion;
  header.fixed.header_size = sizeof(ContainerHeaderWire);
  header.fixed.pbkdf_iterations = 2000;
  for (size_t i = 0; i < header.fixed.pbkdf_salt.size(); ++i) {
    header.fixed.pbkdf_salt[i] = static_cast<uint8_t>(i + 1);
  }
  for (size_t i = 0; i < header.fixed.hybrid_salt.size(); ++i) {
    header.fixed.hybrid_salt[i] = static_cast<uint8_t>(i ^ 0x5A);
  }
  header.pqc.type = 0x7051;
  header.pqc.length = sizeof(qv::core::PQC_KEM_TLV) - 4;

  auto classical = DeriveKey(password, header.fixed);
  auto hybrid = qv::core::PQCHybridKDF::Create(classical, {header.fixed.hybrid_salt.data(), header.fixed.hybrid_salt.size()});

  header.pqc.kem_ct = hybrid.kem_ciphertext;
  header.pqc.sk_nonce = hybrid.sk_nonce;
  header.pqc.sk_encrypted = hybrid.sk_encrypted;
  header.pqc.sk_tag = hybrid.sk_tag;
  header.pqc.reserved.fill(0);

  auto bytes = Serialize(header);
  auto mac = qv::crypto::HMAC_SHA256::Compute({hybrid.hybrid_key.data(), hybrid.hybrid_key.size()},
                                              {bytes.data(), bytes.size() - header.mac.size()});
  header.mac = mac;
  bytes = Serialize(header);

  std::ofstream out(p, std::ios::binary);
  out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
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
  assert(ok.has_value() && "expected mount to succeed with correct password");

  auto wrong = ctm.Mount(container, "wrong password");
  assert(!wrong.has_value() && "mount should fail with incorrect password");

  auto tampered = container;
  {
    std::fstream f(tampered, std::ios::in | std::ios::out | std::ios::binary);
    auto pos = static_cast<std::streamoff>(sizeof(ContainerHeaderWire) / 2);
    f.seekp(pos);
    char flip;
    f.read(&flip, 1);
    flip ^= 0xFF;
    f.seekp(pos);
    f.write(&flip, 1);
  }
  auto tamper_result = ctm.Mount(container, password);
  assert(!tamper_result.has_value() && "tampered container should not mount");

  std::filesystem::remove(container);
  auto missing = ctm.Mount(container, password);
  assert(!missing.has_value() && "missing container should fail to mount");

  std::cout << "constant-time mount tests ok\n";
  return 0;
}
