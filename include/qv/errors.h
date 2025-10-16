#pragma once

#include <string_view>

namespace qv::errors::msg {
// TSK111_Code_Duplication_and_Maintainability centralized message catalog
inline constexpr std::string_view kPasswordTooShort{"Password too short"};
inline constexpr std::string_view kPasswordTooLong{"Password too long"};
inline constexpr std::string_view kPasswordComplexityMissing{"Password must include uppercase, lowercase, numeric, and special characters"}; // TSK135_Password_Complexity_Enforcement
inline constexpr std::string_view kPasswordEntropyTooLow{"Password entropy too low"}; // TSK135_Password_Complexity_Enforcement
inline constexpr std::string_view kPasswordTooCommon{"Password appears in common password list"}; // TSK135_Password_Complexity_Enforcement
inline constexpr std::string_view kPasswordCommonListUnavailable{"Unable to load common password list"}; // TSK135_Password_Complexity_Enforcement
inline constexpr std::string_view kPasswordReused{"Password has been used previously"}; // TSK135_Password_Complexity_Enforcement
inline constexpr std::string_view kPasswordHistoryPersistFailed{"Failed to persist password history"}; // TSK135_Password_Complexity_Enforcement
inline constexpr std::string_view kUnableToResolveWorkingDirectory{"Unable to resolve working directory"};
inline constexpr std::string_view kUnableToCanonicalizeContainerRoot{"Unable to canonicalize container root"};
inline constexpr std::string_view kFailedToCanonicalizeContainerPath{"Failed to canonicalize container path"};
inline constexpr std::string_view kContainerEscapesAllowedRoot{"Container path escapes allowed root"};
inline constexpr std::string_view kPathEscapeAttemptDetected{"Path escape attempt detected"};
inline constexpr std::string_view kUnsupportedArgon2HashLength{"Unsupported Argon2 hash length"};
inline constexpr std::string_view kArgon2DerivationFailed{"Argon2id derivation failed"};
inline constexpr std::string_view kArgon2Unavailable{"Argon2id support not available in this build"};
inline constexpr std::string_view kMissingArgon2Configuration{"Missing Argon2 configuration"};
inline constexpr std::string_view kInvalidContainerHeader{"Invalid container header"};
inline constexpr std::string_view kVolumeHeaderTruncated{"Volume header truncated"};
inline constexpr std::string_view kRequiredTlvMissing{"Required TLV missing"};
inline constexpr std::string_view kUnexpectedHeaderTrailingBytes{"Unexpected trailing bytes in header"};
inline constexpr std::string_view kPbkdf2Malformed{"PBKDF2 TLV malformed"};
inline constexpr std::string_view kPbkdf2SaltLengthUnexpected{"PBKDF2 salt length unexpected"};
inline constexpr std::string_view kArgon2Malformed{"Argon2 TLV malformed"};
inline constexpr std::string_view kHybridSaltMalformed{"Hybrid salt TLV malformed"};
inline constexpr std::string_view kEpochMalformed{"Epoch TLV malformed"};
inline constexpr std::string_view kEpochTruncated{"Epoch TLV truncated"};
inline constexpr std::string_view kEpochLengthMismatch{"Epoch TLV length mismatch"};
inline constexpr std::string_view kPqcMalformed{"PQC TLV malformed"};
inline constexpr std::string_view kPqcTruncated{"PQC TLV truncated"};
inline constexpr std::string_view kPqcLengthMismatch{"PQC TLV length mismatch"};
inline constexpr std::string_view kReservedMalformed{"Reserved TLV malformed"};
inline constexpr std::string_view kVolumeLocked{"Volume locked due to repeated authentication failures"};
inline constexpr std::string_view kPersistLockFileFailed{"Failed to persist lock file for protected volume"};
inline constexpr std::string_view kMountAuthFailed{"Volume mount authentication failed"};
inline constexpr std::string_view kMountLockedMessage{"Volume locked after repeated authentication failures"};
inline constexpr std::string_view kKeyAgreementTimeout{"Key agreement exceeded timeout"};
inline constexpr std::string_view kMountAttemptTimeout{"Mount attempt exceeded time limit"};
}  // namespace qv::errors::msg

