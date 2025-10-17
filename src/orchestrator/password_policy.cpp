#include "qv/orchestrator/password_policy.h"

#include <array>
#include <span>          // TSK242_Password_History_Timing_Oracle random shuffle span helper
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "qv/error.h"
#include "qv/errors.h"
#include "qv/crypto/random.h"  // TSK242_Password_History_Timing_Oracle shuffle entropy

namespace qv::orchestrator {
namespace {

constexpr std::size_t kMinPasswordLen = 8;       // TSK135_Password_Complexity_Enforcement baseline length
constexpr std::size_t kMaxPasswordLen = 1024;    // TSK135_Password_Complexity_Enforcement baseline length
constexpr double kMinEntropyPerChar = 2.0;       // TSK135_Password_Complexity_Enforcement entropy guardrails
constexpr double kMinTotalEntropyBits = 24.0;    // TSK135_Password_Complexity_Enforcement entropy guardrails
constexpr std::string_view kDefaultCommonPasswordList =
    "contrib/passwords/pwdb_top100000.txt";      // TSK135_Password_Complexity_Enforcement vendored dictionary

enum class ValidationCheck : std::size_t { // TSK242_Password_History_Timing_Oracle randomized order ids
  kMinLength = 0,
  kMaxLength,
  kComplexity,
  kEntropy,
  kCommon,
  kCount
};

constexpr std::array<ValidationCheck, static_cast<std::size_t>(ValidationCheck::kCount)>
    kDeterministicValidationOrder = { // TSK242_Password_History_Timing_Oracle stable failure precedence
        ValidationCheck::kMinLength,
        ValidationCheck::kMaxLength,
        ValidationCheck::kComplexity,
        ValidationCheck::kEntropy,
        ValidationCheck::kCommon,
};

const std::array<std::string, static_cast<std::size_t>(ValidationCheck::kCount)>&
PasswordValidationMessages() { // TSK242_Password_History_Timing_Oracle pre-generated failures
  static const std::array<std::string, static_cast<std::size_t>(ValidationCheck::kCount)> messages = {
      std::string(qv::errors::msg::kPasswordTooShort),
      std::string(qv::errors::msg::kPasswordTooLong),
      std::string(qv::errors::msg::kPasswordComplexityMissing),
      std::string(qv::errors::msg::kPasswordEntropyTooLow),
      std::string(qv::errors::msg::kPasswordTooCommon),
  };
  return messages;
}

struct PasswordEntropy { // TSK135_Password_Complexity_Enforcement helper container
  double per_character{0.0};
  double total{0.0};
};

PasswordEntropy ComputeEntropy(const std::string& password) { // TSK135_Password_Complexity_Enforcement Shannon entropy
  if (password.empty()) {
    return {};
  }

  std::array<std::size_t, 256> counts{};
  for (unsigned char ch : password) {
    ++counts[ch];
  }

  const double length = static_cast<double>(password.size());
  double per_character = 0.0;
  for (auto count : counts) {
    if (count == 0) {
      continue;
    }
    const double probability = static_cast<double>(count) / length;
    per_character -= probability * std::log2(probability);
  }
  return PasswordEntropy{per_character, per_character * length};
}

bool HasRequiredComplexity(const std::string& password) { // TSK135_Password_Complexity_Enforcement structural rules
  bool has_upper = false;
  bool has_lower = false;
  bool has_digit = false;
  bool has_symbol = false;

  for (unsigned char ch : password) {
    if (std::isupper(ch) != 0) {
      has_upper = true;
    } else if (std::islower(ch) != 0) {
      has_lower = true;
    } else if (std::isdigit(ch) != 0) {
      has_digit = true;
    } else {
      has_symbol = true;
    }
  }
  return has_upper && has_lower && has_digit && has_symbol;
}

struct CommonPasswordCache { // TSK135_Password_Complexity_Enforcement dictionary memoization
  std::once_flag init;
  std::unordered_set<std::string> entries;
  std::optional<std::string> error;
};

CommonPasswordCache& Cache() { // TSK135_Password_Complexity_Enforcement lazy singleton
  static CommonPasswordCache cache;
  return cache;
}

std::optional<std::filesystem::path> ResolveCommonPasswordListPath() { // TSK135_Password_Complexity_Enforcement
  std::vector<std::filesystem::path> candidates;
  if (const char* env = std::getenv("QV_COMMON_PASSWORD_LIST"); env && *env) {
    candidates.emplace_back(env);
  }

  std::error_code cwd_ec;
  const auto cwd = std::filesystem::current_path(cwd_ec);
  if (!cwd_ec) {
    candidates.emplace_back(cwd / kDefaultCommonPasswordList);
    candidates.emplace_back(cwd / std::filesystem::path(kDefaultCommonPasswordList).filename());
  }

  const auto source_root = std::filesystem::path(__FILE__).parent_path().parent_path().parent_path();
  candidates.emplace_back(source_root / kDefaultCommonPasswordList);

  for (const auto& candidate : candidates) {
    std::error_code exists_ec;
    if (!candidate.empty() && std::filesystem::exists(candidate, exists_ec) && !exists_ec) {
      return candidate;
    }
  }
  return std::nullopt;
}

void LoadCommonPasswords(CommonPasswordCache& cache) { // TSK135_Password_Complexity_Enforcement dictionary loader
  auto path = ResolveCommonPasswordListPath();
  if (!path) {
    cache.error = "list not found";
    return;
  }

  std::ifstream in(*path, std::ios::binary);
  if (!in) {
    cache.error = "open failed";
    return;
  }

  cache.entries.reserve(100000);  // approximate size of vendored dictionary
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    std::size_t begin = line.find_first_not_of(" \t");
    if (begin == std::string::npos) {
      continue;
    }
    if (line[begin] == '#') {
      continue;
    }
    std::size_t end = line.find_last_not_of(" \t");
    const auto trimmed = line.substr(begin, end - begin + 1);
    if (!trimmed.empty()) {
      cache.entries.insert(trimmed);
    }
  }

  if (in.bad()) {
    cache.entries.clear();
    cache.error = "read failed";
  }
}

bool IsCommonPassword(const std::string& password) { // TSK135_Password_Complexity_Enforcement blacklist check
  auto& cache = Cache();
  std::call_once(cache.init, [&cache]() { LoadCommonPasswords(cache); });
  if (cache.error) {
    throw qv::Error{qv::ErrorDomain::Config, 0,
                    std::string(qv::errors::msg::kPasswordCommonListUnavailable) + ": " + *cache.error};
  }
  return cache.entries.find(password) != cache.entries.end();
}

}  // namespace

void EnforcePasswordPolicy(const std::string& password) { // TSK242_Password_History_Timing_Oracle constant evaluation cadence
  const auto size = password.size();
  std::array<ValidationCheck, static_cast<std::size_t>(ValidationCheck::kCount)> order =
      kDeterministicValidationOrder;
  std::array<uint8_t, static_cast<std::size_t>(ValidationCheck::kCount)> shuffle_bytes{};
  qv::crypto::SystemRandomBytes(
      std::span<uint8_t>(shuffle_bytes.data(), shuffle_bytes.size()));
  for (std::size_t i = order.size(); i > 1; --i) {
    const std::size_t j = static_cast<std::size_t>(shuffle_bytes[i - 1]) % i;
    auto temp = order[i - 1];
    order[i - 1] = order[j];
    order[j] = temp;
  }

  struct CheckState { // TSK242_Password_History_Timing_Oracle memoized outcomes
    bool evaluated{false};
    bool failed{false};
  };

  std::array<CheckState, static_cast<std::size_t>(ValidationCheck::kCount)> states{};
  PasswordEntropy entropy{};
  bool entropy_computed = false;
  bool common_password = false;
  bool common_computed = false;

  auto evaluate = [&](ValidationCheck check) -> bool {
    const auto index = static_cast<std::size_t>(check);
    auto& state = states[index];
    if (state.evaluated) {
      return state.failed;
    }
    state.evaluated = true;
    switch (check) {
      case ValidationCheck::kMinLength:
        state.failed = size < kMinPasswordLen;
        break;
      case ValidationCheck::kMaxLength:
        state.failed = size > kMaxPasswordLen;
        break;
      case ValidationCheck::kComplexity:
        state.failed = !HasRequiredComplexity(password);
        break;
      case ValidationCheck::kEntropy:
        if (!entropy_computed) {
          entropy = ComputeEntropy(password);
          entropy_computed = true;
        }
        state.failed = static_cast<bool>((entropy.per_character < kMinEntropyPerChar) |
                                         (entropy.total < kMinTotalEntropyBits));
        break;
      case ValidationCheck::kCommon:
        if (!common_computed) {
          common_password = IsCommonPassword(password);
          common_computed = true;
        }
        state.failed = common_password;
        break;
      case ValidationCheck::kCount:
        state.failed = false;
        break;
    }
    return state.failed;
  };

  for (auto check : order) {
    (void)evaluate(check);
  }

  const auto& messages = PasswordValidationMessages();
  for (auto check : kDeterministicValidationOrder) {
    if (evaluate(check)) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      messages[static_cast<std::size_t>(check)]};
    }
  }
}

}  // namespace qv::orchestrator

