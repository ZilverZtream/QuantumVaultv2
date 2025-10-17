#include "qv/orchestrator/session.h"  // TSK718_AutoLock_and_MemoryLocking

#include <atomic>
#include <chrono>
#include <thread>

int main() {
  using namespace std::chrono_literals;

  qv::orchestrator::IdleLock lock;
  std::atomic<int> fired{0};
  lock.on_expire = [&]() { fired.fetch_add(1, std::memory_order_relaxed); };
  lock.Arm(50ms);
  lock.Tick();
  std::this_thread::sleep_for(20ms);
  lock.Tick();
  if (fired.load(std::memory_order_relaxed) != 0) {
    return 1;
  }
  std::this_thread::sleep_for(80ms);
  lock.Tick();
  if (fired.load(std::memory_order_relaxed) != 1) {
    return 1;
  }
  lock.Arm(40ms);
  lock.NotifyActivity();
  std::this_thread::sleep_for(20ms);
  lock.Tick();
  if (fired.load(std::memory_order_relaxed) != 1) {
    return 1;
  }
  lock.NotifyActivity();
  std::this_thread::sleep_for(60ms);
  lock.Tick();
  if (fired.load(std::memory_order_relaxed) != 2) {
    return 1;
  }
  return 0;
}
