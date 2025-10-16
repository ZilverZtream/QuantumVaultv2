#include "qv/orchestrator/password_policy.h"

#include <array>
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

namespace qv::orchestrator {
namespace {

constexpr std::size_t kMinPasswordLen = 8;       // TSK135_Password_Complexity_Enforcement baseline length
constexpr std::size_t kMaxPasswordLen = 1024;    // TSK135_Password_Complexity_Enforcement baseline length
constexpr double kMinEntropyPerChar = 2.0;       // TSK135_Password_Complexity_Enforcement entropy guardrails
constexpr double kMinTotalEntropyBits = 24.0;    // TSK135_Password_Complexity_Enforcement entropy guardrails
constexpr std::string_view kDefaultCommonPasswordList =
    "contrib/passwords/pwdb_top100000.txt";      // TSK135_Password_Complexity_Enforcement vendored dictionary

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

void EnforcePasswordPolicy(const std::string& password) { // TSK135_Password_Complexity_Enforcement central policy
  const auto size = password.size();
  if (size < kMinPasswordLen) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(qv::errors::msg::kPasswordTooShort)};
  }
  if (size > kMaxPasswordLen) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(qv::errors::msg::kPasswordTooLong)};
  }

  if (!HasRequiredComplexity(password)) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(qv::errors::msg::kPasswordComplexityMissing)};
  }

  const auto entropy = ComputeEntropy(password);
  if (entropy.per_character < kMinEntropyPerChar || entropy.total < kMinTotalEntropyBits) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(qv::errors::msg::kPasswordEntropyTooLow)};
  }

  if (IsCommonPassword(password)) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    std::string(qv::errors::msg::kPasswordTooCommon)};
  }
}

}  // namespace qv::orchestrator

