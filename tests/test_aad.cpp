#include "qv/core/nonce.h"
#include "qv/common.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>

int main() {
  constexpr uint32_t kEpoch = 7; // TSK014
  constexpr int64_t kChunkIndex = 5; // TSK014
  constexpr uint64_t kOffset = 0x10000ULL; // TSK014
  constexpr uint32_t kChunkSize = 4096; // TSK014
  std::array<uint8_t, 32> mac{};
  for (size_t i = 0; i < mac.size(); ++i) {
    mac[i] = static_cast<uint8_t>(i);
  }
  auto envelope = qv::core::MakeChunkAAD(kEpoch, kChunkIndex, kOffset, kChunkSize, mac);
  auto bytes = qv::AsBytesConst(envelope);
  constexpr std::array<uint8_t, sizeof(qv::core::AADEnvelope)> expected = {
      0x07, 0x00, 0x00, 0x00, // epoch
      0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // chunk index
      0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // logical offset
      0x00, 0x10, 0x00, 0x00, // chunk size
      'Q',  'V',  'C',  'H',  'U',  'N',  'K',  'D', // context
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
  };
  assert(bytes.size() == expected.size());
  for (size_t i = 0; i < expected.size(); ++i) {
    assert(bytes[i] == expected[i] && "AAD encoding must match golden vector");
  }

  auto mutated = qv::core::MakeChunkAAD(kEpoch, kChunkIndex, kOffset + 0x10000ULL, kChunkSize, mac);
  auto mutated_bytes = qv::AsBytesConst(mutated);
  [[maybe_unused]] bool identical = true;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (bytes[i] != mutated_bytes[i]) {
      identical = false;
      break;
    }
  }
  assert(!identical && "changing offsets must change AAD"); // TSK014

  auto metadata_data = qv::core::MakeAADData(kEpoch, kChunkIndex, kOffset, kChunkSize,
                                             qv::core::kAADContextMetadata);
  [[maybe_unused]] bool context_equal = true;
  for (size_t i = 0; i < std::size(metadata_data.context); ++i) {
    if (metadata_data.context[i] != envelope.data.context[i]) {
      context_equal = false;
      break;
    }
  }
  assert(!context_equal && "contexts for different record types must differ"); // TSK014

  std::cout << "aad test ok\n";
  return 0;
}
