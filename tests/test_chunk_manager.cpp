#include "qv/storage/chunk_manager.h"

#include <array>
#include <filesystem>
#include <iostream>
#include <vector>

#include "qv/crypto/aegis.h"

int main() {
  // TSK061_Block_Device_and_Chunk_Storage_Engine
  auto temp_dir = std::filesystem::temp_directory_path();
  auto container = temp_dir / "qv_chunk_manager_test.container";
  if (std::filesystem::exists(container)) {
    std::filesystem::remove(container);
  }

  std::array<uint8_t, 32> master_key{};
  qv::crypto::CipherType cipher = qv::crypto::CipherType::AEGIS_128X;
  if (!qv::crypto::CipherAvailable(cipher)) {
    cipher = qv::crypto::CipherType::AEGIS_128L;
  }
  if (!qv::crypto::CipherAvailable(cipher)) {
    cipher = qv::crypto::CipherType::AES_256_GCM;
  }

  qv::storage::ChunkManager manager(container, master_key, 7, cipher);

  std::vector<uint8_t> payload(qv::storage::kChunkSize / 2, 0xAB);
  manager.WriteChunk(0, payload);

  auto decrypted = manager.ReadChunk(0);
  if (decrypted != payload) {
    std::cerr << "round-trip mismatch" << std::endl;
    return 1;
  }

  std::cout << "chunk manager ok" << std::endl;
  std::filesystem::remove(container);
  return 0;
}

