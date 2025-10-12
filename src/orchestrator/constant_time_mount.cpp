#include "qv/orchestrator/constant_time_mount.h"
#include <thread>
#include <atomic>
#include <random>

using namespace qv::orchestrator;

std::optional<ConstantTimeMount::VolumeHandle>
ConstantTimeMount::Mount(const std::filesystem::path& container,
                         const std::string& password) {
  Attempt a,b;
  auto start = std::chrono::steady_clock::now();
  a.start = start; b.start = start;
  auto r1 = AttemptMount(container, password);
  a.duration = std::chrono::steady_clock::now() - a.start;
  auto r2 = AttemptMount(container, password);
  b.duration = std::chrono::steady_clock::now() - b.start;
  // v4.1: relaxed padding target ±2ms (p99). Here we pad to 100ms for demo.
  auto TARGET = std::chrono::milliseconds(100);
  if (a.duration < TARGET) ConstantTimePadding(TARGET - a.duration);
  if (b.duration < TARGET) ConstantTimePadding(TARGET - b.duration);
  LogTiming(a,b);
  // Constant-time-ish select (for skeleton, choose r1 if present else r2)
  if (r1.has_value()) return r1;
  if (r2.has_value()) return r2;
  return std::nullopt;
}

void ConstantTimeMount::ConstantTimePadding(std::chrono::nanoseconds d) {
  auto end = std::chrono::steady_clock::now() + d;
  volatile uint64_t dummy = 0;
  std::vector<uint8_t> buf(4096);
  while (std::chrono::steady_clock::now() < end) {
    for (int i=0;i<100;++i) dummy += i * 17;
    for (size_t i=0;i<buf.size(); i+=64) dummy ^= buf[i];
    std::this_thread::sleep_for(std::chrono::microseconds(10));
  }
  std::atomic_signal_fence(std::memory_order_seq_cst);
}

std::optional<ConstantTimeMount::VolumeHandle>
ConstantTimeMount::AttemptMount(const std::filesystem::path& container,
                                const std::string& password) {
  (void)container; (void)password;
  // STUB: pretend the first attempt always fails, second succeeds
  static int counter = 0;
  ++counter;
  if (counter % 2 == 0) return VolumeHandle{42};
  return std::nullopt;
}

void ConstantTimeMount::LogTiming(const Attempt& a, const Attempt& b) {
  (void)a; (void)b;
  // Skeleton: no-op (wire to encrypted telemetry in real build)
}
