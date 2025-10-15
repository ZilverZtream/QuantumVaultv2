#include "qv/tlv/parser.h"

#include <algorithm>
#include <cstring>

#include "qv/common.h"

// TSK111_Code_Duplication_and_Maintainability TLV parser implementation

namespace qv::tlv {

Parser::Parser(std::span<const uint8_t> buffer, std::size_t max_records, std::size_t max_payload) {
  std::size_t offset = 0;
  std::size_t count = 0;
  while ((buffer.size() - offset) >= sizeof(uint16_t) * 2) {
    if (count >= max_records) {
      valid_ = false;
      return;
    }

    uint16_t type_le = 0;
    uint16_t length_le = 0;
    std::memcpy(&type_le, buffer.data() + offset, sizeof(type_le));
    std::memcpy(&length_le, buffer.data() + offset + sizeof(type_le), sizeof(length_le));

    const uint16_t type = qv::FromLittleEndian16(type_le);
    const std::size_t length = static_cast<std::size_t>(qv::FromLittleEndian16(length_le));

    if (length > max_payload) {
      valid_ = false;
      return;
    }

    offset += sizeof(uint16_t) * 2;
    if (offset > buffer.size() || (buffer.size() - offset) < length) {
      valid_ = false;
      return;
    }

    auto payload = buffer.subspan(offset, length);
    records_.push_back(Record{type, payload});

    offset += length;
    ++count;
  }

  valid_ = offset == buffer.size();
  consumed_ = offset;
}

}  // namespace qv::tlv

