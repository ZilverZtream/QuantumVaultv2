#pragma once
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

namespace qv {
  // TSK020
  enum class ErrorDomain : std::uint16_t {
    Security = 0x01,
    IO = 0x02,
    Crypto = 0x03,
    Validation = 0x04,
    Config = 0x05,
    Dependency = 0x06,
    State = 0x07,
    Internal = 0x7F
  };

  // Each domain reserves a span of codes to avoid collisions with propagated
  // platform error numbers. Codes inside the reserved range are guaranteed to be
  // stable across releases. // TSK020
  inline constexpr int kErrorDomainSpan = 0x0100;

  inline constexpr int ErrorDomainBase(ErrorDomain domain) {
    switch (domain) {
    case ErrorDomain::Security:
      return 0x0100;
    case ErrorDomain::IO:
      return 0x0200;
    case ErrorDomain::Crypto:
      return 0x0300;
    case ErrorDomain::Validation:
      return 0x0400;
    case ErrorDomain::Config:
      return 0x0500;
    case ErrorDomain::Dependency:
      return 0x0600;
    case ErrorDomain::State:
      return 0x0700;
    case ErrorDomain::Internal:
      return 0x7F00;
    }
    return 0; // unreachable but placates compilers without warnings enabled
  }

  inline constexpr int ErrorDomainMax(ErrorDomain domain) {
    return ErrorDomainBase(domain) + kErrorDomainSpan - 1;
  }

  inline constexpr bool IsFrameworkErrorCode(ErrorDomain domain, int code) {
    return code >= ErrorDomainBase(domain) && code <= ErrorDomainMax(domain);
  }

  namespace errors {
    // Helper to construct reserved error codes. // TSK020
    inline constexpr int Make(ErrorDomain domain, int offset) {
      return ErrorDomainBase(domain) + offset;
    }

    namespace io {
      inline constexpr int kConsoleUnavailable = Make(ErrorDomain::IO, 0x01);
      inline constexpr int kConsoleModeQueryFailed = Make(ErrorDomain::IO, 0x02);
      inline constexpr int kConsoleEchoDisableFailed = Make(ErrorDomain::IO, 0x03);
      inline constexpr int kPasswordReadFailed = Make(ErrorDomain::IO, 0x04);
      inline constexpr int kPasswordPromptNeedsTty = Make(ErrorDomain::IO, 0x05);
      inline constexpr int kContainerMissing = Make(ErrorDomain::IO, 0x06);
      inline constexpr int kLegacyNonceMissing = Make(ErrorDomain::IO, 0x07);
      inline constexpr int kLegacyNonceWriteFailed = Make(ErrorDomain::IO, 0x08);
    } // namespace io

    namespace validation {
      inline constexpr int kVolumeExists = Make(ErrorDomain::Validation, 0x01);
    } // namespace validation

    namespace security {
      inline constexpr int kAuthenticationRejected = Make(ErrorDomain::Security, 0x01);
    } // namespace security

  } // namespace errors

  struct Error : public std::runtime_error {
    ErrorDomain domain;
    int code;
    std::optional<int> native_code; // TSK027
    explicit Error(ErrorDomain d, int c, const std::string& msg,
                   std::optional<int> native = std::nullopt)
        : std::runtime_error(msg), domain(d), code(c), native_code(native) {}
  };
  struct AuthenticationFailureError : public std::runtime_error {
    explicit AuthenticationFailureError(const std::string& msg) : std::runtime_error(msg) {}
  };
} // namespace qv
