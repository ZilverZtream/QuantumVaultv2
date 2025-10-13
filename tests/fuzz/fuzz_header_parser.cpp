#include <cstddef>
#include <cstdint>
#include <span>

// Forward declaration for fuzzing harness. // TSK030
namespace qv::orchestrator::fuzz {
bool ParseHeaderHarness(std::span<const uint8_t> bytes); // TSK030
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) { // TSK030
  if (data == nullptr) {
    return 0;
  }
  std::span<const uint8_t> bytes(data, size);
  try {
    qv::orchestrator::fuzz::ParseHeaderHarness(bytes); // TSK030
  } catch (...) {
  }
  return 0;
}
