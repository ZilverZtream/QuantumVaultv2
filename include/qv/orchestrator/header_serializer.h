#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "qv/common.h"

namespace qv::orchestrator {

class HeaderSerializer { // TSK111_Code_Duplication_and_Maintainability
 public:
  template <class T>
  HeaderSerializer& AddHeader(const T& header) {
    Append(qv::AsBytesConst(header));
    return *this;
  }

  HeaderSerializer& AddTLV(uint16_t type, std::span<const uint8_t> payload) {
    AppendU16(type);
    AppendU16(static_cast<uint16_t>(payload.size()));
    Append(payload);
    return *this;
  }

  template <class T>
  HeaderSerializer& AddStruct(const T& value) {
    Append(qv::AsBytesConst(value));
    return *this;
  }

  std::vector<uint8_t> Finalize() { return std::move(buffer_); }

 private:
  void Append(std::span<const uint8_t> data) {
    buffer_.insert(buffer_.end(), data.begin(), data.end());
  }

  void AppendU16(uint16_t value) {
    const uint16_t le = qv::ToLittleEndian16(value);
    auto bytes = qv::AsBytesConst(le);
    Append(bytes);
  }

  std::vector<uint8_t> buffer_{};
};

}  // namespace qv::orchestrator

