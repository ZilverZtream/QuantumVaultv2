#pragma once
#include <functional>
#include <string>
#include <vector>
namespace qv::orchestrator {
class EventBus {
  std::vector<std::function<void(const std::string&)>> subs_;
public:
  void Publish(const std::string& msg) {
    for (auto& s : subs_) s(msg);
  }
  void Subscribe(std::function<void(const std::string&)> fn) {
    subs_.push_back(std::move(fn));
  }
};
} // namespace qv::orchestrator
