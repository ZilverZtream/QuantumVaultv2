#pragma once
#include <stdexcept>
#include <string>

namespace qv {
enum class ErrorDomain {
  Security,
  IO,
  Crypto,
  Validation,
  Internal
};
struct Error : public std::runtime_error {
  ErrorDomain domain;
  int code;
  explicit Error(ErrorDomain d, int c, const std::string& msg)
    : std::runtime_error(msg), domain(d), code(c) {}
};
struct AuthenticationFailureError : public std::runtime_error {
  explicit AuthenticationFailureError(const std::string& msg)
    : std::runtime_error(msg) {}
};
} // namespace qv
