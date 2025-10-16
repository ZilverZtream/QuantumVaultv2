#include "qv/core/header_io.h"

// TSK712_Header_Backup_and_Restore_Tooling fuzz harness for backup parser

#include <filesystem>
#include <fstream>
#include <span>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) {
    return 0;
  }
  std::vector<uint8_t> blob(data, data + size);
  auto temp = std::filesystem::temp_directory_path() / "qv_header_fuzz.bin";
  std::error_code ec;
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) {
      return 0;
    }
    out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
  }
  try {
    (void)qv::core::InspectHeaderBackup(temp);
  } catch (...) {
  }
  std::filesystem::remove(temp, ec);
  return 0;
}

