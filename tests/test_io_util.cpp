#include "qv/orchestrator/io_util.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <vector>
#include <iterator>
#include <stdexcept>

namespace {

std::vector<uint8_t> ReadFile(const std::filesystem::path& path) { // TSK068_Atomic_Header_Writes test helper
  std::ifstream in(path, std::ios::binary);
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

}  // namespace

int main() {
  using qv::orchestrator::AtomicReplace;
  using qv::orchestrator::AtomicReplaceHooks;

  auto temp_dir = std::filesystem::temp_directory_path();
  auto target = temp_dir / "qv_atomic_replace_test.bin";

  {
    std::ofstream seed(target, std::ios::binary | std::ios::trunc);
    const std::array<uint8_t, 4> baseline{0xDE, 0xAD, 0xBE, 0xEF};
    seed.write(reinterpret_cast<const char*>(baseline.data()), static_cast<std::streamsize>(baseline.size()));
  }

  AtomicReplaceHooks hooks;
  hooks.before_rename = [](const std::filesystem::path&, const std::filesystem::path&) {
    throw std::runtime_error("simulated crash");
  };

  std::array<uint8_t, 4> update{0xBA, 0xAD, 0xF0, 0x0D};
  bool threw = false;
  try {
    AtomicReplace(target, std::span<const uint8_t>(update.data(), update.size()), hooks);
  } catch (const std::runtime_error&) {
    threw = true;
  }
  assert(threw && "Expected simulated crash before rename");

  auto bytes = ReadFile(target);
  assert(bytes.size() == 4);
  assert(bytes[0] == 0xDE && bytes[1] == 0xAD && bytes[2] == 0xBE && bytes[3] == 0xEF);

  hooks.before_rename = nullptr;
  AtomicReplace(target, std::span<const uint8_t>(update.data(), update.size()));

  bytes = ReadFile(target);
  assert(bytes.size() == 4);
  assert(bytes[0] == 0xBA && bytes[1] == 0xAD && bytes[2] == 0xF0 && bytes[3] == 0x0D);

  std::filesystem::remove(target);

  std::cout << "atomic replace tests ok\n";
  return 0;
}
