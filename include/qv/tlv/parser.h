#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace qv::tlv {

struct Record { // TSK111_Code_Duplication_and_Maintainability
  uint16_t type{0};
  std::span<const uint8_t> value{};
};

class Parser { // TSK111_Code_Duplication_and_Maintainability
 public:
  Parser(std::span<const uint8_t> buffer, std::size_t max_records = 64,
         std::size_t max_payload = 64 * 1024 - 1);

  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] std::size_t consumed() const noexcept { return consumed_; }

  [[nodiscard]] auto begin() const noexcept { return records_.begin(); }
  [[nodiscard]] auto end() const noexcept { return records_.end(); }

 private:
  bool valid_{false};
  std::size_t consumed_{0};
  std::vector<Record> records_{};
};

}  // namespace qv::tlv

