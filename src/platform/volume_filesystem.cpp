#include "qv/platform/volume_filesystem.h"

// TSK062_FUSE_Filesystem_Integration_Linux simple chunk-backed filesystem façade

#include <algorithm>
#include <array>     // TSK127_Incorrect_Filesystem_Metadata_Recovery base64 decoding table
#include <cassert>
#include <cerrno>   // TSK116_Incorrect_Error_Propagation propagate validation errno details
#include <charconv> // TSK121_Missing_Authentication_in_Metadata robust numeric parsing
#include <chrono>
#include <cctype>   // TSK120_Incorrect_Path_Normalization printable-path validation helpers
#include <cstring>
#include <filesystem>
#include <exception>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <string_view>
#include <vector>

#include <zstd.h>  // TSK127_Incorrect_Filesystem_Metadata_Recovery metadata compression support

#if defined(__linux__)
#include <unistd.h>
#endif

#if defined(_WIN32)
using mode_t = unsigned int;
#endif

#include "qv/error.h"
#include "qv/crypto/hmac_sha256.h"  // TSK121_Missing_Authentication_in_Metadata metadata integrity

namespace qv::platform {
namespace {
// TSK120_Incorrect_Path_Normalization centralized path policy limits for volume filesystem
constexpr size_t kMaxPathDepth = 128;
constexpr size_t kMaxPathLength = 4096;
constexpr size_t kMaxPathSegmentLength = 255;
// TSK073_FS_Races_and_Drain ensure consistent lock ordering for filesystem mutex.
class FilesystemMutexGuard {
 public:
  explicit FilesystemMutexGuard(const std::mutex& mutex)
      : mutex_(const_cast<std::mutex*>(&mutex)) {
#if !defined(NDEBUG)
    assert(!lock_held_ && "VolumeFilesystem mutex lock order violated");
    lock_held_ = true;
#endif
    mutex_->lock();
  }

  FilesystemMutexGuard(const FilesystemMutexGuard&) = delete;
  FilesystemMutexGuard& operator=(const FilesystemMutexGuard&) = delete;

  ~FilesystemMutexGuard() {
    mutex_->unlock();
#if !defined(NDEBUG)
    lock_held_ = false;
#endif
  }

 private:
  std::mutex* mutex_;
#if !defined(NDEBUG)
  inline static thread_local bool lock_held_ = false;
#endif
};

constexpr mode_t kDefaultFileMode = 0644;
constexpr mode_t kDefaultDirMode = 0755;
constexpr uint64_t kChunkPayloadSize = storage::kChunkSize;

#if defined(__linux__)
int FuseErrorFrom(const qv::Error& error) {
  // TSK116_Incorrect_Error_Propagation surface native error mapping when available
  if (error.native_code.has_value() && *error.native_code != 0) {
    const int native = *error.native_code;
    return native < 0 ? native : -native;
  }
  // TSK084_WinFSP_Normalization_and_Traversal normalize errno mapping for validation failures
  if (error.domain == qv::ErrorDomain::Validation) {
    return -EINVAL;
  }
  if (error.domain == qv::ErrorDomain::IO) {
    return -EIO;
  }
  return -EIO;
}
#endif

std::string NormalizePath(const std::string& raw_path) {
  // TSK084_WinFSP_Normalization_and_Traversal hardened normalization for shared backends
  // TSK120_Incorrect_Path_Normalization reject malformed input prior to normalization
  if (raw_path.find('\0') != std::string::npos) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Embedded null in path", EINVAL};
  }
  for (unsigned char ch : raw_path) {
    if (ch < 0x20 || !std::isprint(ch)) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Non-printable character in path", EINVAL};
    }
  }

  std::string cleaned = raw_path;
  std::replace(cleaned.begin(), cleaned.end(), '\', '/');

  if (cleaned.find(':') != std::string::npos) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Drive-qualified paths are not allowed", EINVAL};  // TSK116_Incorrect_Error_Propagation propagate validation errno details
  }
  if (cleaned.size() >= 2 && cleaned[0] == '/' && cleaned[1] == '/') {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "UNC paths are not allowed", EINVAL};
  }
  if (cleaned.find("//") != std::string::npos) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Adjacent path separators are not allowed", EINVAL};
  }

  std::filesystem::path fs_path(cleaned);
  if (fs_path.has_root_name()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Rooted paths are not allowed", EINVAL};
  }

  auto normalized = fs_path.lexically_normal();
  const bool is_root_only = normalized.empty() || normalized == std::filesystem::path("/") ||
                            normalized == std::filesystem::path(".");
  if ((normalized.has_root_name() || normalized.has_root_directory()) && !is_root_only) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Absolute paths are not allowed", EINVAL};
  }

  std::vector<std::string> segments;
  segments.reserve(kMaxPathDepth);
  for (const auto& part : normalized) {
    auto name = part.generic_string();
    if (name.empty() || name == "/") {
      continue;
    }
    if (name == ".") {
      continue;
    }
    if (name == "..") {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Path traversal outside root is not allowed", EINVAL};
    }
    if (name.size() > kMaxPathSegmentLength) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Path segment length exceeds maximum", EINVAL};
    }
    for (unsigned char ch : name) {
      if (ch < 0x20 || !std::isprint(ch)) {
        throw qv::Error{qv::ErrorDomain::Validation, 0,
                        "Non-printable character in path segment", EINVAL};
      }
    }
    segments.emplace_back(std::move(name));
    if (segments.size() > kMaxPathDepth) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Path depth exceeds maximum", EINVAL};
    }
  }

  std::string result = "/";
  for (size_t i = 0; i < segments.size(); ++i) {
    if (i > 0) {
      result.push_back('/');
    }
    result.append(segments[i]);
  }

  if (result.size() > kMaxPathLength) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Path length exceeds maximum", EINVAL};
  }

  return result;
}

timespec TimespecFrom(std::time_t sec, long nsec) {
  timespec ts{};
  ts.tv_sec = sec;
  ts.tv_nsec = nsec;
  return ts;
}
constexpr long kNanosecondsPerSecond = 1000000000L;  // TSK121_Missing_Authentication_in_Metadata normalize timespec bounds

std::string EscapeMetadataToken(std::string_view value) {  // TSK121_Missing_Authentication_in_Metadata lossless token encoding
  std::string escaped;
  escaped.reserve(value.size());
  constexpr char kHex[] = "0123456789ABCDEF";
  for (unsigned char ch : value) {
    if (ch <= 0x20 || ch == 0x7F || ch == '%') {
      escaped.push_back('%');
      escaped.push_back(kHex[(ch >> 4) & 0x0F]);
      escaped.push_back(kHex[ch & 0x0F]);
    } else {
      escaped.push_back(static_cast<char>(ch));
    }
  }
  return escaped;
}

std::optional<std::string> UnescapeMetadataToken(const std::string& token) {  // TSK121_Missing_Authentication_in_Metadata
  std::string result;
  result.reserve(token.size());
  auto HexValue = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'A' && ch <= 'F') {
      return 10 + (ch - 'A');
    }
    if (ch >= 'a' && ch <= 'f') {
      return 10 + (ch - 'a');
    }
    return -1;
  };
  for (size_t i = 0; i < token.size(); ++i) {
    char ch = token[i];
    if (ch != '%') {
      result.push_back(ch);
      continue;
    }
    if (i + 2 >= token.size()) {
      return std::nullopt;
    }
    const int hi = HexValue(token[i + 1]);
    const int lo = HexValue(token[i + 2]);
    if (hi < 0 || lo < 0) {
      return std::nullopt;
    }
    result.push_back(static_cast<char>((hi << 4) | lo));
    i += 2;
  }
  return result;
}

std::optional<std::vector<std::string>> SplitMetadataTokens(const std::string& line) {  // TSK121_Missing_Authentication_in_Metadata
  std::vector<std::string> tokens;
  std::string current;
  for (char ch : line) {
    if (ch == ' ') {
      tokens.push_back(current);
      current.clear();
      continue;
    }
    current.push_back(ch);
  }
  if (!current.empty() || (!line.empty() && line.back() == ' ')) {
    tokens.push_back(current);
  }
  if (tokens.empty()) {
    return std::vector<std::string>{};
  }
  return tokens;
}

std::string HexEncode(std::span<const uint8_t> data) {  // TSK121_Missing_Authentication_in_Metadata metadata MAC encoding
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string encoded(data.size() * 2, '\0');
  for (size_t i = 0; i < data.size(); ++i) {
    encoded[2 * i] = kHexDigits[(data[i] >> 4) & 0x0F];
    encoded[2 * i + 1] = kHexDigits[data[i] & 0x0F];
  }
  return encoded;
}

std::optional<std::vector<uint8_t>> HexDecode(const std::string& hex) {  // TSK121_Missing_Authentication_in_Metadata
  if (hex.size() % 2 != 0) {
    return std::nullopt;
  }
  std::vector<uint8_t> decoded(hex.size() / 2);
  auto HexValue = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'A' && ch <= 'F') {
      return 10 + (ch - 'A');
    }
    if (ch >= 'a' && ch <= 'f') {
      return 10 + (ch - 'a');
    }
    return -1;
  };
  for (size_t i = 0; i < decoded.size(); ++i) {
    const int hi = HexValue(hex[2 * i]);
    const int lo = HexValue(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      return std::nullopt;
    }
    decoded[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return decoded;
}

std::string Base64Encode(std::span<const uint8_t> data) {  // TSK127_Incorrect_Filesystem_Metadata_Recovery metadata payload encoding
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string encoded;
  encoded.reserve(((data.size() + 2) / 3) * 4);
  size_t index = 0;
  while (index + 3 <= data.size()) {
    uint32_t triple = (static_cast<uint32_t>(data[index]) << 16) |
                      (static_cast<uint32_t>(data[index + 1]) << 8) |
                      static_cast<uint32_t>(data[index + 2]);
    encoded.push_back(kAlphabet[(triple >> 18) & 0x3F]);
    encoded.push_back(kAlphabet[(triple >> 12) & 0x3F]);
    encoded.push_back(kAlphabet[(triple >> 6) & 0x3F]);
    encoded.push_back(kAlphabet[triple & 0x3F]);
    index += 3;
  }
  size_t remaining = data.size() - index;
  if (remaining == 1) {
    uint32_t triple = static_cast<uint32_t>(data[index]) << 16;
    encoded.push_back(kAlphabet[(triple >> 18) & 0x3F]);
    encoded.push_back(kAlphabet[(triple >> 12) & 0x3F]);
    encoded.push_back('=');
    encoded.push_back('=');
  } else if (remaining == 2) {
    uint32_t triple = (static_cast<uint32_t>(data[index]) << 16) |
                      (static_cast<uint32_t>(data[index + 1]) << 8);
    encoded.push_back(kAlphabet[(triple >> 18) & 0x3F]);
    encoded.push_back(kAlphabet[(triple >> 12) & 0x3F]);
    encoded.push_back(kAlphabet[(triple >> 6) & 0x3F]);
    encoded.push_back('=');
  }
  return encoded;
}

std::optional<std::vector<uint8_t>> Base64Decode(std::string_view input) {  // TSK127_Incorrect_Filesystem_Metadata_Recovery metadata payload decoding
  std::string filtered;
  filtered.reserve(input.size());
  for (char ch : input) {
    if (!std::isspace(static_cast<unsigned char>(ch))) {
      filtered.push_back(ch);
    }
  }
  if (filtered.empty() || filtered.size() % 4 != 0) {
    return std::nullopt;
  }
  static constexpr uint8_t kInvalid = 0xFF;
  static constexpr std::array<uint8_t, 256> kReverse = [] {
    std::array<uint8_t, 256> map{};
    map.fill(kInvalid);
    const std::string alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < alphabet.size(); ++i) {
      map[static_cast<uint8_t>(alphabet[i])] = static_cast<uint8_t>(i);
    }
    map[static_cast<uint8_t>('=')] = 0;
    return map;
  }();
  size_t output_length = (filtered.size() / 4) * 3;
  if (filtered.back() == '=') {
    --output_length;
    if (filtered.size() >= 2 && filtered[filtered.size() - 2] == '=') {
      --output_length;
    }
  }
  std::vector<uint8_t> decoded(output_length, 0);
  size_t out_index = 0;
  for (size_t i = 0; i < filtered.size(); i += 4) {
    uint8_t a = kReverse[static_cast<uint8_t>(filtered[i])];
    uint8_t b = kReverse[static_cast<uint8_t>(filtered[i + 1])];
    uint8_t c = kReverse[static_cast<uint8_t>(filtered[i + 2])];
    uint8_t d = kReverse[static_cast<uint8_t>(filtered[i + 3])];
    if (a == kInvalid || b == kInvalid || c == kInvalid || d == kInvalid) {
      return std::nullopt;
    }
    uint32_t triple = (static_cast<uint32_t>(a) << 18) |
                      (static_cast<uint32_t>(b) << 12) |
                      (static_cast<uint32_t>(c) << 6) |
                      static_cast<uint32_t>(d);
    decoded[out_index++] = static_cast<uint8_t>((triple >> 16) & 0xFF);
    if (filtered[i + 2] != '=') {
      decoded[out_index++] = static_cast<uint8_t>((triple >> 8) & 0xFF);
    }
    if (filtered[i + 3] != '=') {
      decoded[out_index++] = static_cast<uint8_t>(triple & 0xFF);
    }
  }
  decoded.resize(out_index);
  return decoded;
}

std::optional<std::string> CompressMetadataBody(const std::string& body) {  // TSK127_Incorrect_Filesystem_Metadata_Recovery zstd framing
  if (body.empty()) {
    return std::nullopt;
  }
  size_t bound = ZSTD_compressBound(body.size());
  std::vector<uint8_t> compressed(bound);
  size_t compressed_size = ZSTD_compress(compressed.data(), bound, body.data(), body.size(), 3);
  if (ZSTD_isError(compressed_size)) {
    return std::nullopt;
  }
  compressed.resize(compressed_size);
  if (compressed.size() >= body.size()) {
    return std::nullopt;
  }
  auto encoded = Base64Encode(std::span<const uint8_t>(compressed.data(), compressed.size()));
  std::ostringstream framed;
  framed << "ENC ZSTD " << body.size() << ' ' << compressed.size() << '\n';
  framed << encoded << '\n';
  return framed.str();
}

bool ConstantTimeEqual(std::span<const uint8_t> a, std::span<const uint8_t> b) {  // TSK121_Missing_Authentication_in_Metadata
  if (a.size() != b.size()) {
    return false;
  }
  uint8_t diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  }
  return diff == 0;
}

bool ParseUint64Token(const std::string& token, uint64_t* value) {  // TSK121_Missing_Authentication_in_Metadata
  if (!value || token.empty()) {
    return false;
  }
  uint64_t parsed = 0;
  auto result = std::from_chars(token.data(), token.data() + token.size(), parsed);
  if (result.ec != std::errc() || result.ptr != token.data() + token.size()) {
    return false;
  }
  *value = parsed;
  return true;
}

bool ParseInt64Token(const std::string& token, int64_t* value) {  // TSK121_Missing_Authentication_in_Metadata
  if (!value || token.empty()) {
    return false;
  }
  int64_t parsed = 0;
  auto result = std::from_chars(token.data(), token.data() + token.size(), parsed);
  if (result.ec != std::errc() || result.ptr != token.data() + token.size()) {
    return false;
  }
  *value = parsed;
  return true;
}

bool ValidateTimespecFields(int64_t sec, int64_t nsec) {  // TSK121_Missing_Authentication_in_Metadata
  return nsec >= 0 && nsec < kNanosecondsPerSecond &&
         sec >= std::numeric_limits<std::time_t>::min() &&
         sec <= std::numeric_limits<std::time_t>::max();
}

struct MetadataParseContext {  // TSK121_Missing_Authentication_in_Metadata incremental metadata reconstruction
  std::shared_ptr<DirectoryEntry> root;
  uint64_t next_chunk_index;
  bool next_seen;
  uint64_t data_start_chunk;
  uint64_t max_reasonable_next{0};                        // TSK127_Incorrect_Filesystem_Metadata_Recovery NEXT guardrail
  bool best_effort{false};                                // TSK127_Incorrect_Filesystem_Metadata_Recovery recovery flag
  size_t total_entries{0};                                // TSK127_Incorrect_Filesystem_Metadata_Recovery tracking
  size_t skipped_entries{0};                              // TSK127_Incorrect_Filesystem_Metadata_Recovery tracking
  size_t rescued_entries{0};                              // TSK127_Incorrect_Filesystem_Metadata_Recovery salvage stats
  std::vector<std::string> rescued_paths;                 // TSK127_Incorrect_Filesystem_Metadata_Recovery salvage audit
};

DirectoryEntry* EnsureDirectoryForMetadata(MetadataParseContext& context, const std::string& path) {
  try {
    auto normalized = NormalizePath(path);
    auto* current = context.root.get();
    if (normalized == "/") {
      return current;
    }
    std::filesystem::path fs_path(normalized);
    for (const auto& part : fs_path) {
      auto name = part.string();
      if (name.empty() || name == "/" || name == ".") {
        continue;
      }
      if (name == "..") {
        return nullptr;
      }
      auto it = std::find_if(current->subdirs.begin(), current->subdirs.end(),
                             [&](const std::shared_ptr<DirectoryEntry>& child) { return child->name == name; });
      if (it == current->subdirs.end()) {
        auto dir = std::make_shared<DirectoryEntry>();
        dir->name = name;
        dir->mtime = CurrentTimespec();
        current->subdirs.emplace_back(dir);
        current = dir.get();
      } else {
        current = it->get();
      }
    }
    return current;
  } catch (...) {
    return nullptr;
  }
}

bool ApplyNextMetadataEntry(const std::vector<std::string>& tokens, MetadataParseContext& context) {
  if (tokens.size() != 2) {
    return false;
  }
  if (context.next_seen) {
    return false;  // TSK127_Incorrect_Filesystem_Metadata_Recovery reject duplicate NEXT entries
  }
  uint64_t next = 0;
  if (!ParseUint64Token(tokens[1], &next)) {
    return false;
  }
  if (next < context.data_start_chunk) {
    return false;
  }
  if (context.max_reasonable_next != 0 && next > context.max_reasonable_next) {
    return false;  // TSK127_Incorrect_Filesystem_Metadata_Recovery clamp unreasonable cursor
  }
  context.next_chunk_index = next;
  context.next_seen = true;
  return true;
}

bool ApplyDirectoryMetadataEntry(const std::vector<std::string>& tokens, MetadataParseContext& context) {
  if (tokens.size() != 4) {
    return false;
  }
  auto path = UnescapeMetadataToken(tokens[1]);
  if (!path) {
    return false;
  }
  int64_t sec = 0;
  int64_t nsec = 0;
  if (!ParseInt64Token(tokens[2], &sec) || !ParseInt64Token(tokens[3], &nsec)) {
    return false;
  }
  if (!ValidateTimespecFields(sec, nsec)) {
    return false;
  }
  auto* dir = EnsureDirectoryForMetadata(context, *path);
  if (!dir) {
    return false;
  }
  dir->mtime = TimespecFrom(static_cast<std::time_t>(sec), static_cast<long>(nsec));
  return true;
}

bool ApplyFileMetadataEntry(const std::vector<std::string>& tokens, MetadataParseContext& context) {
  if (tokens.size() != 11) {
    return false;
  }
  auto path = UnescapeMetadataToken(tokens[1]);
  if (!path) {
    return false;
  }
  uint64_t size = 0;
  uint64_t start_chunk = 0;
  uint64_t mode_value = 0;
  int64_t msec = 0;
  int64_t mnsec = 0;
  int64_t csec = 0;
  int64_t cnsec = 0;
  uint64_t uid_value = 0;
  uint64_t gid_value = 0;
  if (!ParseUint64Token(tokens[2], &size) || !ParseUint64Token(tokens[3], &start_chunk) ||
      !ParseUint64Token(tokens[4], &mode_value) || !ParseInt64Token(tokens[5], &msec) ||
      !ParseInt64Token(tokens[6], &mnsec) || !ParseInt64Token(tokens[7], &csec) ||
      !ParseInt64Token(tokens[8], &cnsec) || !ParseUint64Token(tokens[9], &uid_value) ||
      !ParseUint64Token(tokens[10], &gid_value)) {
    return false;
  }
  if (start_chunk < context.data_start_chunk) {
    return false;
  }
  if (!ValidateTimespecFields(msec, mnsec) || !ValidateTimespecFields(csec, cnsec)) {
    return false;
  }
  if (mode_value > static_cast<uint64_t>(std::numeric_limits<mode_t>::max())) {
    return false;
  }
  if (uid_value > static_cast<uint64_t>(std::numeric_limits<uid_t>::max()) ||
      gid_value > static_cast<uint64_t>(std::numeric_limits<gid_t>::max())) {
    return false;
  }
  if (kChunkPayloadSize != 0 && start_chunk > std::numeric_limits<uint64_t>::max() / kChunkPayloadSize) {
    return false;
  }
  auto normalized = NormalizePath(*path);
  std::filesystem::path fs_path(normalized);
  auto parent_path = fs_path.parent_path().string();
  if (parent_path.empty()) {
    parent_path = "/";
  }
  auto* dir = EnsureDirectoryForMetadata(context, parent_path);
  if (!dir) {
    return false;
  }
  auto filename = fs_path.filename().string();
  if (filename.empty()) {
    return false;
  }
  FileEntry entry{};
  entry.name = filename;
  entry.size = size;
  entry.start_offset = start_chunk * kChunkPayloadSize;
  entry.mode = static_cast<mode_t>(mode_value);
  entry.mtime = TimespecFrom(static_cast<std::time_t>(msec), static_cast<long>(mnsec));
  entry.ctime = TimespecFrom(static_cast<std::time_t>(csec), static_cast<long>(cnsec));
  entry.uid = static_cast<uid_t>(uid_value);
  entry.gid = static_cast<gid_t>(gid_value);
  auto it = std::find_if(dir->files.begin(), dir->files.end(),
                         [&](const FileEntry& existing) { return existing.name == entry.name; });
  if (it != dir->files.end()) {
    *it = entry;
  } else {
    dir->files.push_back(entry);
  }
  return true;
}

bool AttemptRescueFromTokens(const std::vector<std::string>& tokens, MetadataParseContext& context) {
  if (tokens.empty()) {
    return false;
  }
  const auto& tag = tokens[0];
  if (tag == "DIR" && tokens.size() >= 2) {
    auto path = UnescapeMetadataToken(tokens[1]);
    if (!path) {
      return false;
    }
    auto* dir = EnsureDirectoryForMetadata(context, *path);
    if (!dir) {
      return false;
    }
    dir->mtime = CurrentTimespec();
    context.rescued_paths.push_back(*path);
    return true;
  }
  if (tag == "FILE" && tokens.size() >= 4) {
    auto path = UnescapeMetadataToken(tokens[1]);
    if (!path) {
      return false;
    }
    uint64_t size = 0;
    uint64_t start_chunk = 0;
    if (!ParseUint64Token(tokens[2], &size) || !ParseUint64Token(tokens[3], &start_chunk)) {
      return false;
    }
    if (start_chunk < context.data_start_chunk) {
      return false;
    }
    if (kChunkPayloadSize != 0 &&
        start_chunk > std::numeric_limits<uint64_t>::max() / kChunkPayloadSize) {
      return false;
    }
    std::filesystem::path fs_path(*path);
    auto parent_path = fs_path.parent_path().string();
    if (parent_path.empty()) {
      parent_path = "/";
    }
    auto* dir = EnsureDirectoryForMetadata(context, parent_path);
    if (!dir) {
      return false;
    }
    auto filename = fs_path.filename().string();
    if (filename.empty()) {
      return false;
    }
    FileEntry entry{};
    entry.name = filename;
    entry.size = size;
    entry.start_offset = start_chunk * kChunkPayloadSize;
    entry.mode = kDefaultFileMode;
    entry.mtime = CurrentTimespec();
    entry.ctime = entry.mtime;
    entry.uid = 0;
    entry.gid = 0;
    auto it = std::find_if(dir->files.begin(), dir->files.end(),
                           [&](const FileEntry& existing) { return existing.name == entry.name; });
    if (it != dir->files.end()) {
      *it = entry;
    } else {
      dir->files.push_back(entry);
    }
    context.rescued_paths.push_back(*path);
    return true;
  }
  return false;
}

bool ApplyMetadataTokens(const std::vector<std::string>& tokens, MetadataParseContext& context) {
  if (tokens.empty()) {
    return false;
  }
  const auto& tag = tokens[0];
  if (tag == "NEXT") {
    return ApplyNextMetadataEntry(tokens, context);
  }
  if (tag == "DIR") {
    return ApplyDirectoryMetadataEntry(tokens, context);
  }
  if (tag == "FILE") {
    return ApplyFileMetadataEntry(tokens, context);
  }
  return false;
}
}  // namespace

class VolumeFilesystem::MetadataWritebackGuard {
 public:
  explicit MetadataWritebackGuard(VolumeFilesystem& filesystem) : filesystem_(filesystem) {}

  void MarkDirty() {
    if (dirty_) {
      return;
    }
    filesystem_.MarkMetadataDirtyLocked();  // TSK117_Race_Conditions_in_Filesystem batch metadata changes
    dirty_ = true;
  }

  void Commit() {
    if (!dirty_) {
      return;
    }
    filesystem_.FlushMetadataLocked();
    dirty_ = false;
  }

  ~MetadataWritebackGuard() {
#if !defined(NDEBUG)
    if (!std::uncaught_exceptions()) {
      assert(!dirty_ && "MetadataWritebackGuard::Commit must be invoked before scope exit");
    }
#endif
  }

 private:
  VolumeFilesystem& filesystem_;
  bool dirty_ = false;
};

VolumeFilesystem::VolumeFilesystem(std::shared_ptr<storage::BlockDevice> device)
    : device_(std::move(device)),
      root_(std::make_shared<DirectoryEntry>()) {
  if (!device_) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Missing block device for volume filesystem"};
  }
  root_->name = "/";
  root_->mtime = CurrentTimespec();

  metadata_chunk_count_ = (metadata_size_ + kChunkPayloadSize - 1) / kChunkPayloadSize;
  data_start_chunk_ = metadata_chunk_start_ + metadata_chunk_count_;
  next_chunk_index_ = data_start_chunk_;
  next_file_offset_ = next_chunk_index_ * kChunkPayloadSize;

  bool metadata_loaded = false;
  try {
    metadata_loaded = LoadMetadata();
  } catch (...) {
    try {
      metadata_loaded = LoadMetadata(true);
    } catch (...) {
      InitializeFreshMetadata();
      metadata_loaded = false;
    }
  }
  if (!metadata_loaded || metadata_dirty_) {
    FilesystemMutexGuard lock(fs_mutex_);
    MetadataWritebackGuard metadata_guard(*this);
    metadata_guard.MarkDirty();
    metadata_guard.Commit();
  }
}

VolumeFilesystem::~VolumeFilesystem() {
  // TSK115_Memory_Leaks_and_Resource_Management persist pending directory updates on teardown
  try {
    FilesystemMutexGuard lock(fs_mutex_);
    FlushMetadataLocked();
  } catch (...) {
    // Destructors must not throw; metadata persistence errors are logged by callers.
  }
}

FileEntry* VolumeFilesystem::FindFile(const std::string& path) {
  auto normalized = NormalizePath(path);
  if (normalized == "/") {
    return nullptr;
  }
  auto parent_path = std::filesystem::path(normalized).parent_path().string();
  if (parent_path.empty()) {
    parent_path = "/";
  }
  auto* dir = FindDirectory(parent_path);
  if (!dir) {
    return nullptr;
  }
  auto target = std::filesystem::path(normalized).filename().string();
  for (auto& file : dir->files) {
    if (file.name == target) {
      return &file;
    }
  }
  return nullptr;
}

DirectoryEntry* VolumeFilesystem::EnsureDirectory(const std::string& path) {
  auto normalized = NormalizePath(path);
  auto* current = root_.get();
  if (normalized == "/") {
    return current;
  }
  std::filesystem::path fs_path(normalized);
  size_t depth = 0;
  for (const auto& part : fs_path) {
    auto name = part.string();
    if (name.empty() || name == "/") {
      continue;
    }
    // TSK120_Incorrect_Path_Normalization re-validate normalized directory segments before trust
    if (name == "." || name == "..") {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Relative segments are not allowed", EINVAL};
    }
    if (++depth > kMaxPathDepth) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Path depth exceeds maximum", EINVAL};
    }
    if (name.size() > kMaxPathSegmentLength) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Path segment length exceeds maximum", EINVAL};
    }
    for (unsigned char ch : name) {
      if (ch < 0x20 || !std::isprint(ch)) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Non-printable character in path segment", EINVAL};
      }
    }
    auto it = std::find_if(current->subdirs.begin(), current->subdirs.end(),
                           [&](const std::shared_ptr<DirectoryEntry>& child) { return child->name == name; });
    if (it == current->subdirs.end()) {
      auto dir = std::make_shared<DirectoryEntry>();
      dir->name = name;
      dir->mtime = CurrentTimespec();
      current->subdirs.emplace_back(dir);
      current = dir.get();
    } else {
      current = it->get();
    }
  }
  return current;
}

DirectoryEntry* VolumeFilesystem::FindDirectory(const std::string& path) {
  auto normalized = NormalizePath(path);
  if (normalized == "/") {
    return root_.get();
  }
  auto* current = root_.get();
  std::filesystem::path fs_path(normalized);
  for (const auto& part : fs_path) {
    auto name = part.string();
    if (name.empty() || name == "/") {
      continue;
    }
    auto it = std::find_if(current->subdirs.begin(), current->subdirs.end(),
                           [&](const std::shared_ptr<DirectoryEntry>& child) { return child->name == name; });
    if (it == current->subdirs.end()) {
      return nullptr;
    }
    current = it->get();
  }
  return current;
}

#if defined(__linux__)

int VolumeFilesystem::GetAttr(const char* path, struct stat* stbuf) {
  try {
    FilesystemMutexGuard lock(fs_mutex_);
    std::memset(stbuf, 0, sizeof(*stbuf));
    auto normalized = NormalizePath(path);
    if (normalized == "/") {
      stbuf->st_mode = S_IFDIR | kDefaultDirMode;
      stbuf->st_nlink = 2;
      stbuf->st_mtim = root_->mtime;
      stbuf->st_ctim = root_->mtime;
      return 0;
    }

    if (auto* dir = FindDirectory(normalized)) {
      stbuf->st_mode = S_IFDIR | kDefaultDirMode;
      stbuf->st_nlink = 2;
      stbuf->st_mtim = dir->mtime;
      stbuf->st_ctim = dir->mtime;
      return 0;
    }

    auto* file = FindFile(normalized);
    if (!file) {
      return -ENOENT;
    }
    auto mode_bits = file->mode == 0 ? kDefaultFileMode : file->mode;
    stbuf->st_mode = S_IFREG | (mode_bits & 0777);
    stbuf->st_nlink = 1;
    stbuf->st_size = static_cast<off_t>(file->size);
    stbuf->st_mtim = file->mtime;
    stbuf->st_ctim = file->ctime;
    stbuf->st_uid = file->uid;
    stbuf->st_gid = file->gid;
    return 0;
  } catch (const qv::Error& error) {
    return FuseErrorFrom(error);
  } catch (...) {
    return -EIO;
  }
}

int VolumeFilesystem::ReadDir(const char* path, void* buf, fuse_fill_dir_t filler) {
  try {
    FilesystemMutexGuard lock(fs_mutex_);
    auto* dir = FindDirectory(path);
    if (!dir) {
      return -ENOENT;
    }
    filler(buf, ".", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    filler(buf, "..", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    for (const auto& subdir : dir->subdirs) {
      filler(buf, subdir->name.c_str(), nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    }
    for (const auto& file : dir->files) {
      filler(buf, file.name.c_str(), nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    }
    return 0;
  } catch (const qv::Error& error) {
    return FuseErrorFrom(error);
  } catch (...) {
    return -EIO;
  }
}

int VolumeFilesystem::Open(const char* path, struct fuse_file_info* fi) {
  (void)fi;
  try {
    FilesystemMutexGuard lock(fs_mutex_);
    auto* file = FindFile(path);
    if (!file) {
      return -ENOENT;
    }
    return 0;
  } catch (const qv::Error& error) {
    return FuseErrorFrom(error);
  } catch (...) {
    return -EIO;
  }
}

std::vector<uint8_t> VolumeFilesystem::ReadFileContent(const FileEntry& file) {
  if (file.size == 0 || file.start_offset == 0) {
    return {};
  }
  uint64_t start_chunk = file.start_offset / kChunkPayloadSize;
  uint64_t chunk_count = (file.size + kChunkPayloadSize - 1) / kChunkPayloadSize;
  std::vector<uint8_t> data(chunk_count * kChunkPayloadSize);
  struct PartialReadGuard {  // TSK115_Memory_Leaks_and_Resource_Management clear buffers on failure
    explicit PartialReadGuard(std::vector<uint8_t>* target) : target_(target) {}
    ~PartialReadGuard() {
      if (!committed_ && target_) {
        target_->clear();
      }
    }
    void Commit() { committed_ = true; }

   private:
    std::vector<uint8_t>* target_;
    bool committed_ = false;
  } guard(&data);
  for (uint64_t i = 0; i < chunk_count; ++i) {
    auto chunk = device_->ReadChunk(static_cast<int64_t>(start_chunk + i));
    std::copy(chunk.ciphertext.begin(), chunk.ciphertext.end(),
              data.begin() + static_cast<std::ptrdiff_t>(i * kChunkPayloadSize));
  }
  guard.Commit();
  data.resize(file.size);
  return data;
}

uint64_t VolumeFilesystem::AllocateChunks(uint64_t count, uint64_t* previous_next) {
  std::lock_guard allocation_lock(allocation_mutex_);
  if (previous_next) {
    *previous_next = next_chunk_index_;
  }
  if (count == 0) {
    return 0;
  }
  if (next_chunk_index_ > std::numeric_limits<uint64_t>::max() - count) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Chunk index allocation overflow"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard addition
  }
  const auto start = next_chunk_index_;
  next_chunk_index_ += count;
  if (next_chunk_index_ > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Chunk allocation exceeds signed range"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard cast
  }
  if (kChunkPayloadSize != 0 &&
      next_chunk_index_ > std::numeric_limits<uint64_t>::max() / kChunkPayloadSize) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Chunk offset allocation overflow"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard multiply
  }
  next_file_offset_ = next_chunk_index_ * kChunkPayloadSize;
  return start;
}

void VolumeFilesystem::RestoreAllocationState(uint64_t previous_next) {
  std::lock_guard allocation_lock(allocation_mutex_);
  next_chunk_index_ = previous_next;
  if (next_chunk_index_ > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Restored chunk index exceeds signed range"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard cast
  }
  if (kChunkPayloadSize != 0 &&
      next_chunk_index_ > std::numeric_limits<uint64_t>::max() / kChunkPayloadSize) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Restored chunk offset overflow"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard multiply
  }
  next_file_offset_ = next_chunk_index_ * kChunkPayloadSize;
}

void VolumeFilesystem::WriteFileContent(FileEntry& file, const std::vector<uint8_t>& data) {
  const uint64_t chunk_payload = kChunkPayloadSize;
  if (!data.empty()) {
    if (chunk_payload == 0) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Chunk payload size is zero"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard invalid configuration
    }
    const uint64_t data_size = static_cast<uint64_t>(data.size());
    if (data_size > std::numeric_limits<uint64_t>::max() - (chunk_payload - 1)) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Chunk requirement overflow"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard ceil division
    }
  }
  const uint64_t required_chunks = data.empty()
                                      ? 0
                                      : (static_cast<uint64_t>(data.size()) + chunk_payload - 1) / chunk_payload;
  const uint64_t old_start_chunk = file.start_offset / kChunkPayloadSize;
  const uint64_t old_chunks = file.size == 0 ? 0 : (file.size + kChunkPayloadSize - 1) / kChunkPayloadSize;

  uint64_t start_chunk = old_start_chunk;
  if (required_chunks == 0) {
    file.start_offset = 0;
    return;
  }
  uint64_t previous_next_chunk = 0;
  bool allocated_new_range = false;
  if (old_chunks == 0 || start_chunk < data_start_chunk_ || required_chunks > old_chunks) {
    allocated_new_range = true;
    start_chunk = AllocateChunks(required_chunks, &previous_next_chunk);
  }

  struct ChunkAllocationGuard {  // TSK115_Memory_Leaks_and_Resource_Management rollback leaked chunks
    ChunkAllocationGuard(VolumeFilesystem& owner, FileEntry& file_ref, uint64_t original_offset,
                         bool allocated_new, uint64_t previous_next)
        : owner_(owner), file_(file_ref), original_offset_(original_offset),
          allocated_new_(allocated_new), previous_next_(previous_next) {}
    ~ChunkAllocationGuard() {
      if (!committed_) {
        file_.start_offset = original_offset_;
        if (allocated_new_) {
          owner_.RestoreAllocationState(previous_next_);
        }
      }
    }
    void Commit() { committed_ = true; }

   private:
    VolumeFilesystem& owner_;
    FileEntry& file_;
    uint64_t original_offset_;
    bool allocated_new_;
    uint64_t previous_next_;
    bool committed_ = false;
  } allocation_guard(*this, file, file.start_offset, allocated_new_range, previous_next_chunk);

  if (required_chunks > 0) {
    if (start_chunk > std::numeric_limits<uint64_t>::max() - (required_chunks - 1)) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Chunk range overflow"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard iteration bounds
    }
    const uint64_t last_chunk = start_chunk + required_chunks - 1;
    if (last_chunk > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Chunk index exceeds 64-bit signed range"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard cast
    }
    if (kChunkPayloadSize != 0 &&
        last_chunk > std::numeric_limits<uint64_t>::max() / kChunkPayloadSize) {
      throw qv::Error{qv::ErrorDomain::Validation, 0,
                      "Chunk logical offset overflow"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard multiply
    }
  }

  for (uint64_t i = 0; i < required_chunks; ++i) {
    std::vector<uint8_t> chunk_buffer(kChunkPayloadSize, 0);
    auto offset = static_cast<size_t>(i * kChunkPayloadSize);
    auto remaining = data.size() > offset ? data.size() - offset : 0;
    auto copy_size = std::min<size_t>(kChunkPayloadSize, remaining);
    if (copy_size > 0) {
      std::memcpy(chunk_buffer.data(), data.data() + offset, copy_size);
    }

    storage::ChunkHeader header{};
    header.chunk_index = static_cast<int64_t>(start_chunk + i);
    header.logical_offset = (start_chunk + i) * kChunkPayloadSize;
    header.data_size = static_cast<uint32_t>(copy_size);
    device_->WriteChunk(header, std::span<const uint8_t>(chunk_buffer.data(), chunk_buffer.size()));
  }

  if (kChunkPayloadSize != 0 &&
      start_chunk > std::numeric_limits<uint64_t>::max() / kChunkPayloadSize) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "File start offset overflow"};  // TSK119_Integer_Overflow_in_Chunk_Calculations guard multiply
  }
  file.start_offset = start_chunk * kChunkPayloadSize;
  allocation_guard.Commit();
}

#if defined(__linux__)
int VolumeFilesystem::Read(const char* path, char* buf, size_t size, off_t offset) {
  try {
    FilesystemMutexGuard lock(fs_mutex_);
    auto* file = FindFile(path);
    if (!file) {
      return -ENOENT;
    }
    if (offset < 0) {
      return -EINVAL;
    }
    auto data = ReadFileContent(*file);
    if (offset >= static_cast<off_t>(data.size())) {
      return 0;
    }
    size_t readable = std::min<size_t>(size, data.size() - static_cast<size_t>(offset));
    std::memcpy(buf, data.data() + static_cast<size_t>(offset), readable);
    return static_cast<int>(readable);
  } catch (const qv::Error& error) {
    return FuseErrorFrom(error);
  } catch (...) {
    return -EIO;
  }
}

int VolumeFilesystem::Write(const char* path, const char* buf, size_t size, off_t offset) {
  try {
    FilesystemMutexGuard lock(fs_mutex_);
    MetadataWritebackGuard metadata_guard(*this);
    auto* file = FindFile(path);
    if (!file) {
      return -ENOENT;
    }
    if (offset < 0) {
      return -EINVAL;
    }
    auto data = ReadFileContent(*file);
    if (static_cast<size_t>(offset) > data.size()) {
      data.resize(static_cast<size_t>(offset), 0);
    }
    if (offset + static_cast<off_t>(size) > static_cast<off_t>(data.size())) {
      data.resize(static_cast<size_t>(offset + static_cast<off_t>(size)), 0);
    }
    std::memcpy(data.data() + static_cast<size_t>(offset), buf, size);
    WriteFileContent(*file, data);
    file->size = data.size();
    auto now = CurrentTimespec();
    file->mtime = now;
    metadata_guard.MarkDirty();
    metadata_guard.Commit();
    return static_cast<int>(size);
  } catch (const qv::Error& error) {
    return FuseErrorFrom(error);
  } catch (...) {
    return -EIO;
  }
}

int VolumeFilesystem::Create(const char* path, mode_t mode, struct fuse_file_info* fi) {
  (void)fi;
  try {
    FilesystemMutexGuard lock(fs_mutex_);
    MetadataWritebackGuard metadata_guard(*this);
    auto normalized = NormalizePath(path);
    auto parent_path = std::filesystem::path(normalized).parent_path().string();
    if (parent_path.empty()) {
      parent_path = "/";
    }
    auto* dir = FindDirectory(parent_path);
    if (!dir) {
      return -ENOENT;
    }
    auto name = std::filesystem::path(normalized).filename().string();
    for (const auto& file : dir->files) {
      if (file.name == name) {
        return -EEXIST;
      }
    }
    FileEntry entry{};
    entry.name = name;
    entry.mode = mode;
    entry.size = 0;
    entry.start_offset = 0;
    entry.mtime = CurrentTimespec();
    entry.ctime = entry.mtime;
    entry.uid = fuse_get_context() ? fuse_get_context()->uid : getuid();
    entry.gid = fuse_get_context() ? fuse_get_context()->gid : getgid();
    dir->files.push_back(entry);
    dir->mtime = entry.mtime;
    metadata_guard.MarkDirty();
    metadata_guard.Commit();
    return 0;
  } catch (const qv::Error& error) {
    return FuseErrorFrom(error);
  } catch (...) {
    return -EIO;
  }
}
#endif  // defined(__linux__)

// TSK063_WinFsp_Windows_Driver_Integration shared helpers for WinFsp bridge
uint64_t VolumeFilesystem::TotalSizeBytes() const {
  FilesystemMutexGuard lock(fs_mutex_);
  const uint64_t metadata_bytes = metadata_chunk_count_ * kChunkPayloadSize;
  const uint64_t allocated_chunks = next_chunk_index_ > data_start_chunk_
                                        ? next_chunk_index_ - data_start_chunk_
                                        : 0;
  const uint64_t data_bytes = allocated_chunks * kChunkPayloadSize;
  return metadata_bytes + data_bytes;
}

uint64_t VolumeFilesystem::FreeSpaceBytes() const {
  constexpr uint64_t kAssumedCapacity = 512ull * 1024ull * 1024ull * 1024ull;  // 512 GiB
  auto used = TotalSizeBytes();
  if (used >= kAssumedCapacity) {
    return 0;
  }
  return kAssumedCapacity - used;
}

std::optional<NodeMetadata> VolumeFilesystem::StatPath(const std::string& path) {
  FilesystemMutexGuard lock(fs_mutex_);
  auto normalized = NormalizePath(path);
  NodeMetadata metadata{};
  if (normalized == "/") {
    metadata.is_directory = true;
    metadata.mode = kDefaultDirMode;
    metadata.modification_time = root_->mtime;
    metadata.change_time = root_->mtime;
    return metadata;
  }

  if (auto* dir = FindDirectory(normalized)) {
    metadata.is_directory = true;
    metadata.mode = kDefaultDirMode;
    metadata.modification_time = dir->mtime;
    metadata.change_time = dir->mtime;
    return metadata;
  }

  if (auto* file = FindFile(normalized)) {
    metadata.is_directory = false;
    metadata.size = file->size;
    metadata.mode = file->mode == 0 ? kDefaultFileMode : file->mode;
    metadata.modification_time = file->mtime;
    metadata.change_time = file->ctime;
    metadata.uid = file->uid;
    metadata.gid = file->gid;
    return metadata;
  }

  return std::nullopt;
}

std::vector<DirectoryListingEntry> VolumeFilesystem::ListDirectoryEntries(
    const std::string& path) {
  FilesystemMutexGuard lock(fs_mutex_);
  auto* dir = FindDirectory(path);
  if (!dir) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Directory not found: " + path};
  }

  std::vector<DirectoryListingEntry> entries;
  entries.reserve(dir->subdirs.size() + dir->files.size());
  for (const auto& subdir : dir->subdirs) {
    DirectoryListingEntry entry{};
    entry.name = subdir->name;
    entry.is_directory = true;
    entry.metadata.is_directory = true;
    entry.metadata.mode = kDefaultDirMode;
    entry.metadata.modification_time = subdir->mtime;
    entry.metadata.change_time = subdir->mtime;
    entries.emplace_back(entry);
  }
  for (const auto& file : dir->files) {
    DirectoryListingEntry entry{};
    entry.name = file.name;
    entry.is_directory = false;
    entry.metadata.is_directory = false;
    entry.metadata.size = file.size;
    entry.metadata.mode = file.mode == 0 ? kDefaultFileMode : file.mode;
    entry.metadata.modification_time = file.mtime;
    entry.metadata.change_time = file.ctime;
    entry.metadata.uid = file.uid;
    entry.metadata.gid = file.gid;
    entries.emplace_back(entry);
  }
  return entries;
}

std::vector<uint8_t> VolumeFilesystem::ReadFileRange(const std::string& path, uint64_t offset,
                                                     size_t length) {
  FilesystemMutexGuard lock(fs_mutex_);
  auto* file = FindFile(path);
  if (!file) {
    throw qv::Error{qv::ErrorDomain::IO, 0, "File not found: " + path};
  }
  auto data = ReadFileContent(*file);
  if (offset >= data.size()) {
    return {};
  }
  size_t readable = std::min<size_t>(length, data.size() - static_cast<size_t>(offset));
  std::vector<uint8_t> result(readable);
  std::memcpy(result.data(), data.data() + static_cast<size_t>(offset), readable);
  return result;
}

size_t VolumeFilesystem::WriteFileRange(const std::string& path, uint64_t offset,
                                        std::span<const uint8_t> data) {
  FilesystemMutexGuard lock(fs_mutex_);
  MetadataWritebackGuard metadata_guard(*this);
  auto* file = FindFile(path);
  if (!file) {
    throw qv::Error{qv::ErrorDomain::IO, 0, "File not found: " + path};
  }
  auto existing = ReadFileContent(*file);
  if (existing.size() < offset) {
    existing.resize(static_cast<size_t>(offset), 0);
  }
  if (existing.size() < offset + data.size()) {
    existing.resize(static_cast<size_t>(offset + data.size()), 0);
  }
  std::memcpy(existing.data() + static_cast<size_t>(offset), data.data(), data.size());
  WriteFileContent(*file, existing);
  file->size = existing.size();
  file->mtime = CurrentTimespec();
  metadata_guard.MarkDirty();
  metadata_guard.Commit();
  return data.size();
}

void VolumeFilesystem::CreateFileNode(const std::string& path, uint32_t mode, uint32_t uid,
                                      uint32_t gid) {
  FilesystemMutexGuard lock(fs_mutex_);
  MetadataWritebackGuard metadata_guard(*this);
  auto normalized = NormalizePath(path);
  auto parent_path = std::filesystem::path(normalized).parent_path().string();
  if (parent_path.empty()) {
    parent_path = "/";
  }
  auto* dir = FindDirectory(parent_path);
  if (!dir) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Parent directory missing: " + parent_path};
  }
  auto name = std::filesystem::path(normalized).filename().string();
  for (const auto& file : dir->files) {
    if (file.name == name) {
      throw qv::Error{qv::ErrorDomain::State, 0, "File already exists: " + path};
    }
  }
  FileEntry entry{};
  entry.name = name;
  entry.mode = mode;
  entry.size = 0;
  entry.start_offset = 0;
  entry.mtime = CurrentTimespec();
  entry.ctime = entry.mtime;
  entry.uid = static_cast<uid_t>(uid);
  entry.gid = static_cast<gid_t>(gid);
  dir->files.push_back(entry);
  dir->mtime = entry.mtime;
  metadata_guard.MarkDirty();
  metadata_guard.Commit();
}

void VolumeFilesystem::CreateDirectoryNode(const std::string& path, uint32_t mode, uint32_t uid,
                                           uint32_t gid) {
  (void)mode;
  (void)uid;
  (void)gid;
  FilesystemMutexGuard lock(fs_mutex_);
  MetadataWritebackGuard metadata_guard(*this);
  auto normalized = NormalizePath(path);
  auto parent_path = std::filesystem::path(normalized).parent_path().string();
  if (parent_path.empty()) {
    parent_path = "/";
  }
  auto* parent = FindDirectory(parent_path);
  if (!parent) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Parent directory missing: " + parent_path};
  }
  auto name = std::filesystem::path(normalized).filename().string();
  if (FindDirectory(normalized)) {
    throw qv::Error{qv::ErrorDomain::State, 0, "Directory already exists: " + path};
  }
  auto dir = std::make_shared<DirectoryEntry>();
  dir->name = name;
  dir->mtime = CurrentTimespec();
  parent->subdirs.push_back(dir);
  parent->mtime = dir->mtime;
  metadata_guard.MarkDirty();
  metadata_guard.Commit();
}

void VolumeFilesystem::RemoveFileNode(const std::string& path) {
  FilesystemMutexGuard lock(fs_mutex_);
  MetadataWritebackGuard metadata_guard(*this);
  auto normalized = NormalizePath(path);
  auto parent_path = std::filesystem::path(normalized).parent_path().string();
  if (parent_path.empty()) {
    parent_path = "/";
  }
  auto* dir = FindDirectory(parent_path);
  if (!dir) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Parent directory missing: " + parent_path};
  }
  auto before = dir->files.size();
  auto target = std::filesystem::path(normalized).filename().string();
  dir->files.erase(std::remove_if(dir->files.begin(), dir->files.end(),
                                  [&](const FileEntry& file) { return file.name == target; }),
                   dir->files.end());
  if (dir->files.size() == before) {
    throw qv::Error{qv::ErrorDomain::IO, 0, "File not found: " + path};
  }
  dir->mtime = CurrentTimespec();
  metadata_guard.MarkDirty();
  metadata_guard.Commit();
}

void VolumeFilesystem::RemoveDirectoryNode(const std::string& path) {
  FilesystemMutexGuard lock(fs_mutex_);
  MetadataWritebackGuard metadata_guard(*this);
  auto normalized = NormalizePath(path);
  if (normalized == "/") {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Cannot remove root directory"};
  }
  auto parent_path = std::filesystem::path(normalized).parent_path().string();
  if (parent_path.empty()) {
    parent_path = "/";
  }
  auto* parent = FindDirectory(parent_path);
  if (!parent) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Parent directory missing: " + parent_path};
  }
  auto name = std::filesystem::path(normalized).filename().string();
  auto it = std::find_if(parent->subdirs.begin(), parent->subdirs.end(),
                         [&](const std::shared_ptr<DirectoryEntry>& child) { return child->name == name; });
  if (it == parent->subdirs.end()) {
    throw qv::Error{qv::ErrorDomain::IO, 0, "Directory not found: " + path};
  }
  if (!(*it)->files.empty() || !(*it)->subdirs.empty()) {
    throw qv::Error{qv::ErrorDomain::State, 0, "Directory not empty: " + path};
  }
  parent->subdirs.erase(it);
  parent->mtime = CurrentTimespec();
  metadata_guard.MarkDirty();
  metadata_guard.Commit();
}

void VolumeFilesystem::TruncateFileNode(const std::string& path, uint64_t size) {
  FilesystemMutexGuard lock(fs_mutex_);
  MetadataWritebackGuard metadata_guard(*this);
  auto* file = FindFile(path);
  if (!file) {
    throw qv::Error{qv::ErrorDomain::IO, 0, "File not found: " + path};
  }
  auto data = ReadFileContent(*file);
  if (size < data.size()) {
    data.resize(static_cast<size_t>(size));
  } else if (size > data.size()) {
    data.resize(static_cast<size_t>(size), 0);
  }
  WriteFileContent(*file, data);
  file->size = data.size();
  file->mtime = CurrentTimespec();
  metadata_guard.MarkDirty();
  metadata_guard.Commit();
}

void VolumeFilesystem::RenameNode(const std::string& from, const std::string& to,
                                  bool replace_existing) {
  FilesystemMutexGuard lock(fs_mutex_);
  MetadataWritebackGuard metadata_guard(*this);
  auto from_norm = NormalizePath(from);
  auto to_norm = NormalizePath(to);
  if (from_norm == "/" || to_norm == "/") {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Cannot rename root directory"};
  }

  auto* source_dir = FindDirectory(from_norm);
  bool is_directory = source_dir != nullptr;
  if (!is_directory && !FindFile(from_norm)) {
    throw qv::Error{qv::ErrorDomain::IO, 0, "Source not found: " + from};
  }

  auto dest_parent_path = std::filesystem::path(to_norm).parent_path().string();
  if (dest_parent_path.empty()) {
    dest_parent_path = "/";
  }
  auto* dest_parent = FindDirectory(dest_parent_path);
  if (!dest_parent) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "Destination parent missing: " + dest_parent_path};
  }
  auto dest_name = std::filesystem::path(to_norm).filename().string();

  if (is_directory) {
    // Check for conflicts
    auto existing_it = std::find_if(dest_parent->subdirs.begin(), dest_parent->subdirs.end(),
                                    [&](const std::shared_ptr<DirectoryEntry>& child) {
                                      return child->name == dest_name;
                                    });
    if (existing_it != dest_parent->subdirs.end()) {
      if (!replace_existing) {
        throw qv::Error{qv::ErrorDomain::State, 0, "Destination exists"};
      }
      if (!(*existing_it)->files.empty() || !(*existing_it)->subdirs.empty()) {
        throw qv::Error{qv::ErrorDomain::State, 0, "Destination directory not empty"};
      }
      dest_parent->subdirs.erase(existing_it);
    }
    if (std::any_of(dest_parent->files.begin(), dest_parent->files.end(),
                    [&](const FileEntry& f) { return f.name == dest_name; })) {
      throw qv::Error{qv::ErrorDomain::State, 0, "Destination exists"};
    }

    auto from_parent_path = std::filesystem::path(from_norm).parent_path().string();
    if (from_parent_path.empty()) {
      from_parent_path = "/";
    }
    auto* from_parent = FindDirectory(from_parent_path);
    auto name = std::filesystem::path(from_norm).filename().string();
    auto it = std::find_if(from_parent->subdirs.begin(), from_parent->subdirs.end(),
                           [&](const std::shared_ptr<DirectoryEntry>& child) {
                             return child->name == name;
                           });
    if (it == from_parent->subdirs.end()) {
      throw qv::Error{qv::ErrorDomain::IO, 0, "Source directory missing"};
    }
    auto moved = *it;
    from_parent->subdirs.erase(it);
    if (std::any_of(dest_parent->subdirs.begin(), dest_parent->subdirs.end(),
                    [&](const std::shared_ptr<DirectoryEntry>& child) { return child->name == dest_name; })) {
      throw qv::Error{qv::ErrorDomain::State, 0, "Destination exists"};
    }
    moved->name = dest_name;
    dest_parent->subdirs.push_back(moved);
    dest_parent->mtime = CurrentTimespec();
    from_parent->mtime = dest_parent->mtime;
  } else {
    // Handle file rename
    auto dest_file_it = std::find_if(dest_parent->files.begin(), dest_parent->files.end(),
                                     [&](const FileEntry& f) { return f.name == dest_name; });
    if (dest_file_it != dest_parent->files.end()) {
      if (!replace_existing) {
        throw qv::Error{qv::ErrorDomain::State, 0, "Destination exists"};
      }
      dest_parent->files.erase(dest_file_it);
    }
    if (std::any_of(dest_parent->subdirs.begin(), dest_parent->subdirs.end(),
                    [&](const std::shared_ptr<DirectoryEntry>& child) { return child->name == dest_name; })) {
      throw qv::Error{qv::ErrorDomain::State, 0, "Destination exists"};
    }

    auto from_parent_path = std::filesystem::path(from_norm).parent_path().string();
    if (from_parent_path.empty()) {
      from_parent_path = "/";
    }
    auto* from_parent = FindDirectory(from_parent_path);
    auto name = std::filesystem::path(from_norm).filename().string();
    auto it = std::find_if(from_parent->files.begin(), from_parent->files.end(),
                           [&](const FileEntry& file) { return file.name == name; });
    if (it == from_parent->files.end()) {
      throw qv::Error{qv::ErrorDomain::IO, 0, "Source file missing"};
    }
    FileEntry entry = *it;
    from_parent->files.erase(it);
    auto final_conflict = std::find_if(dest_parent->files.begin(), dest_parent->files.end(),
                                       [&](const FileEntry& f) { return f.name == dest_name; });
    if (final_conflict != dest_parent->files.end()) {
      throw qv::Error{qv::ErrorDomain::State, 0, "Destination exists"};
    }
    entry.name = dest_name;
    dest_parent->files.push_back(entry);
    dest_parent->mtime = CurrentTimespec();
    from_parent->mtime = dest_parent->mtime;
  }

  metadata_guard.MarkDirty();
  metadata_guard.Commit();
}

void VolumeFilesystem::UpdateTimestamps(const std::string& path, std::optional<timespec> modification,
                                        std::optional<timespec> change) {
  FilesystemMutexGuard lock(fs_mutex_);
  MetadataWritebackGuard metadata_guard(*this);
  auto normalized = NormalizePath(path);
  if (auto* dir = FindDirectory(normalized)) {
    if (modification) {
      dir->mtime = *modification;
    }
    if (change) {
      dir->mtime = *change;
    }
    metadata_guard.MarkDirty();
    metadata_guard.Commit();
    return;
  }
  if (auto* file = FindFile(normalized)) {
    if (modification) {
      file->mtime = *modification;
    }
    if (change) {
      file->ctime = *change;
    }
    metadata_guard.MarkDirty();
    metadata_guard.Commit();
  }
}


int VolumeFilesystem::Unlink(const char* path) {
  try {
    FilesystemMutexGuard lock(fs_mutex_);
    MetadataWritebackGuard metadata_guard(*this);
    auto normalized = NormalizePath(path);
    auto parent_path = std::filesystem::path(normalized).parent_path().string();
    if (parent_path.empty()) {
      parent_path = "/";
    }
    auto* dir = FindDirectory(parent_path);
    if (!dir) {
      return -ENOENT;
    }
    auto target = std::filesystem::path(normalized).filename().string();
    auto before = dir->files.size();
    dir->files.erase(std::remove_if(dir->files.begin(), dir->files.end(),
                                    [&](const FileEntry& file) { return file.name == target; }),
                     dir->files.end());
    if (dir->files.size() == before) {
      return -ENOENT;
    }
    dir->mtime = CurrentTimespec();
    metadata_guard.MarkDirty();
    metadata_guard.Commit();
    return 0;
  } catch (const qv::Error& error) {
    return FuseErrorFrom(error);
  } catch (...) {
    return -EIO;
  }
}

int VolumeFilesystem::Mkdir(const char* path, mode_t mode) {
  (void)mode;
  try {
    FilesystemMutexGuard lock(fs_mutex_);
    MetadataWritebackGuard metadata_guard(*this);
    auto normalized = NormalizePath(path);
    auto parent_path = std::filesystem::path(normalized).parent_path().string();
    if (parent_path.empty()) {
      parent_path = "/";
    }
    auto* parent = FindDirectory(parent_path);
    if (!parent) {
      return -ENOENT;
    }
    auto name = std::filesystem::path(normalized).filename().string();
    if (FindDirectory(normalized)) {
      return -EEXIST;
    }
    auto dir = std::make_shared<DirectoryEntry>();
    dir->name = name;
    dir->mtime = CurrentTimespec();
    parent->subdirs.push_back(dir);
    parent->mtime = dir->mtime;
    metadata_guard.MarkDirty();
    metadata_guard.Commit();
    return 0;
  } catch (const qv::Error& error) {
    return FuseErrorFrom(error);
  } catch (...) {
    return -EIO;
  }
}

int VolumeFilesystem::Rmdir(const char* path) {
  try {
    FilesystemMutexGuard lock(fs_mutex_);
    MetadataWritebackGuard metadata_guard(*this);
    auto normalized = NormalizePath(path);
    if (normalized == "/") {
      return -EBUSY;
    }
    auto parent_path = std::filesystem::path(normalized).parent_path().string();
    if (parent_path.empty()) {
      parent_path = "/";
    }
    auto* parent = FindDirectory(parent_path);
    if (!parent) {
      return -ENOENT;
    }
    auto name = std::filesystem::path(normalized).filename().string();
    auto it = std::find_if(parent->subdirs.begin(), parent->subdirs.end(),
                           [&](const std::shared_ptr<DirectoryEntry>& child) { return child->name == name; });
    if (it == parent->subdirs.end()) {
      return -ENOENT;
    }
    if (!(*it)->files.empty() || !(*it)->subdirs.empty()) {
      return -ENOTEMPTY;
    }
    parent->subdirs.erase(it);
    parent->mtime = CurrentTimespec();
    metadata_guard.MarkDirty();
    metadata_guard.Commit();
    return 0;
  } catch (const qv::Error& error) {
    return FuseErrorFrom(error);
  } catch (...) {
    return -EIO;
  }
}

int VolumeFilesystem::Truncate(const char* path, off_t size) {
  try {
    FilesystemMutexGuard lock(fs_mutex_);
    auto* file = FindFile(path);
    if (!file) {
      return -ENOENT;
    }
    if (size < 0) {
      return -EINVAL;
    }
    auto data = ReadFileContent(*file);
    if (size < static_cast<off_t>(data.size())) {
      data.resize(static_cast<size_t>(size));
    } else if (size > static_cast<off_t>(data.size())) {
      data.resize(static_cast<size_t>(size), 0);
    }
    WriteFileContent(*file, data);
    file->size = data.size();
    file->mtime = CurrentTimespec();
    metadata_guard.MarkDirty();
    metadata_guard.Commit();
    return 0;
  } catch (const qv::Error& error) {
    return FuseErrorFrom(error);
  } catch (...) {
    return -EIO;
  }
}

#endif  // defined(__linux__)

void VolumeFilesystem::SerializeDirectory(std::ostringstream& out, const DirectoryEntry* dir,
                                          const std::string& path) {
  out << "DIR " << EscapeMetadataToken(path) << ' ' << dir->mtime.tv_sec << ' ' << dir->mtime.tv_nsec
      << '\n';  // TSK121_Missing_Authentication_in_Metadata escape directory paths
  for (const auto& file : dir->files) {
    uint64_t start_chunk = kChunkPayloadSize == 0 ? 0 : file.start_offset / kChunkPayloadSize;
    auto mode_bits = file.mode == 0 ? kDefaultFileMode : file.mode;
    auto file_path = path == "/" ? "/" + file.name : path + "/" + file.name;
    out << "FILE " << EscapeMetadataToken(file_path) << ' ' << file.size << ' ' << start_chunk << ' '
        << file.mtime.tv_sec << ' ' << file.mtime.tv_nsec << ' ' << file.ctime.tv_sec << ' '
        << file.ctime.tv_nsec << ' ' << static_cast<uint64_t>(file.uid) << ' '
        << static_cast<uint64_t>(file.gid) << '\n';
  }
  for (const auto& child : dir->subdirs) {
    auto child_path = path == "/" ? "/" + child->name : path + "/" + child->name;
    SerializeDirectory(out, child.get(), child_path);
  }
}

void VolumeFilesystem::InitializeFreshMetadata() {  // TSK127_Incorrect_Filesystem_Metadata_Recovery shared reset helper
  root_->files.clear();
  root_->subdirs.clear();
  root_->name = "/";
  root_->mtime = CurrentTimespec();
  next_chunk_index_ = data_start_chunk_;
  next_file_offset_ = next_chunk_index_ * kChunkPayloadSize;
  metadata_dirty_ = true;
  last_metadata_total_entries_ = 0;
  last_metadata_skipped_entries_ = 0;
  last_metadata_rescued_entries_ = 0;
}

void VolumeFilesystem::SaveMetadata() {
  FilesystemMutexGuard lock(fs_mutex_);
  MarkMetadataDirtyLocked();
  FlushMetadataLocked();
}

void VolumeFilesystem::MarkMetadataDirtyLocked() {
  metadata_dirty_ = true;
}

void VolumeFilesystem::FlushMetadataLocked() {
  if (!metadata_dirty_) {
    return;
  }
  PersistMetadataLocked();
  metadata_dirty_ = false;
}

void VolumeFilesystem::PersistMetadataLocked() {
  std::ostringstream serialized;
  serialized << "NEXT " << next_chunk_index_ << '\n';
  SerializeDirectory(serialized, root_.get(), "/");
  auto body = serialized.str();
  std::string body_payload = body;
  const size_t total_bytes = metadata_chunk_count_ * kChunkPayloadSize;
  auto build_payload = [&](const std::string& body_data) {
    auto mac_key = device_->MetadataMacKey();
    auto mac = qv::crypto::HMAC_SHA256::Compute(
        std::span<const uint8_t>(mac_key.data(), mac_key.size()),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(body_data.data()), body_data.size()));
    std::ostringstream framed;
    framed << "MAC " << HexEncode(std::span<const uint8_t>(mac.data(), mac.size()))
           << '\n' << body_data;
    return framed.str();
  };

  auto payload = build_payload(body_payload);  // TSK127_Incorrect_Filesystem_Metadata_Recovery adaptive payload sizing
  if (payload.size() > total_bytes) {
    if (auto compressed = CompressMetadataBody(body)) {
      body_payload = *compressed;
      payload = build_payload(body_payload);
    }
    if (payload.size() > total_bytes) {
      throw qv::Error{qv::ErrorDomain::State, 0, "Metadata size exceeds reserved area"};
    }
  }
  std::vector<uint8_t> buffer(total_bytes, 0);
  std::memcpy(buffer.data(), payload.data(), std::min(buffer.size(), payload.size()));
  for (uint64_t i = 0; i < metadata_chunk_count_; ++i) {
    storage::ChunkHeader header{};
    header.chunk_index = static_cast<int64_t>(metadata_chunk_start_ + i);
    header.logical_offset = (metadata_chunk_start_ + i) * kChunkPayloadSize;
    size_t offset = static_cast<size_t>(i * kChunkPayloadSize);
    size_t remaining = buffer.size() > offset ? buffer.size() - offset : 0;
    header.data_size = static_cast<uint32_t>(std::min<size_t>(kChunkPayloadSize, remaining));
    device_->WriteChunk(header,
                        std::span<const uint8_t>(buffer.data() + offset, kChunkPayloadSize));
  }
}

bool VolumeFilesystem::LoadMetadata(bool best_effort) {
  last_metadata_best_effort_ = best_effort;
  last_metadata_total_entries_ = 0;
  last_metadata_skipped_entries_ = 0;
  last_metadata_rescued_entries_ = 0;

  std::vector<uint8_t> buffer(metadata_chunk_count_ * kChunkPayloadSize, 0);
  bool had_chunk_failure = false;
  size_t valid_chunks = 0;
  for (uint64_t i = 0; i < metadata_chunk_count_; ++i) {
    try {
      auto chunk = device_->ReadChunk(static_cast<int64_t>(metadata_chunk_start_ + i));
      const auto& ciphertext = chunk.ciphertext;
      const size_t offset = static_cast<size_t>(i * kChunkPayloadSize);
      const size_t copy_size = std::min(ciphertext.size(), static_cast<size_t>(kChunkPayloadSize));
      std::copy(ciphertext.begin(), ciphertext.begin() + copy_size,
                buffer.begin() + static_cast<std::ptrdiff_t>(offset));
      ++valid_chunks;
    } catch (...) {
      had_chunk_failure = true;  // TSK127_Incorrect_Filesystem_Metadata_Recovery continue best-effort read
    }
  }
  if (valid_chunks == 0) {
    InitializeFreshMetadata();
    return false;
  }

  size_t used_bytes = buffer.size();
  while (used_bytes > 0 && buffer[used_bytes - 1] == 0) {
    --used_bytes;
  }
  if (used_bytes == 0) {
    InitializeFreshMetadata();
    return false;
  }

  std::string serialized(reinterpret_cast<char*>(buffer.data()), used_bytes);
  auto newline_pos = serialized.find('\n');
  if (newline_pos == std::string::npos) {
    InitializeFreshMetadata();
    metadata_dirty_ = true;
    return false;
  }

  auto mac_line = serialized.substr(0, newline_pos);
  std::string body = serialized.substr(newline_pos + 1);

  bool mac_valid = false;
  auto mac_tokens = SplitMetadataTokens(mac_line);
  if (mac_tokens && mac_tokens->size() == 2 && (*mac_tokens)[0] == "MAC") {
    auto mac_bytes = HexDecode((*mac_tokens)[1]);
    if (mac_bytes && mac_bytes->size() == qv::crypto::HMAC_SHA256::TAG_SIZE) {
      auto mac_key = device_->MetadataMacKey();
      auto computed = qv::crypto::HMAC_SHA256::Compute(
          std::span<const uint8_t>(mac_key.data(), mac_key.size()),
          std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(body.data()), body.size()));
      mac_valid = ConstantTimeEqual(
          std::span<const uint8_t>(computed.data(), computed.size()),
          std::span<const uint8_t>(mac_bytes->data(), mac_bytes->size()));
    }
  }
  if (!mac_valid) {
    if (!best_effort) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Metadata MAC verification failed"};
    }
    metadata_dirty_ = true;
  }

  std::string metadata_text;
  bool compressed_body = false;
  if (body.rfind("ENC ", 0) == 0) {
    auto header_end = body.find('\n');
    if (header_end == std::string::npos) {
      if (!best_effort) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Compressed metadata missing terminator"};
      }
      InitializeFreshMetadata();
      return false;
    }
    auto header = body.substr(0, header_end);
    auto encoding_tokens = SplitMetadataTokens(header);
    if (!encoding_tokens || encoding_tokens->size() != 4 || (*encoding_tokens)[0] != "ENC" ||
        (*encoding_tokens)[1] != "ZSTD") {
      if (!best_effort) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Unsupported metadata encoding"};
      }
      metadata_dirty_ = true;
    } else {
      uint64_t original_size = 0;
      uint64_t compressed_size = 0;
      if (!ParseUint64Token((*encoding_tokens)[2], &original_size) ||
          !ParseUint64Token((*encoding_tokens)[3], &compressed_size)) {
        if (!best_effort) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Invalid compressed metadata lengths"};
        }
        metadata_dirty_ = true;
      } else {
        const uint64_t metadata_capacity = metadata_chunk_count_ * kChunkPayloadSize;  // TSK127
        if (original_size > metadata_capacity || metadata_capacity > std::numeric_limits<size_t>::max()) {
          if (!best_effort) {
            throw qv::Error{qv::ErrorDomain::Validation, 0, "Compressed metadata length overflow"};
          }
          metadata_dirty_ = true;
          original_size = 0;
        } else if (original_size > std::numeric_limits<size_t>::max()) {
          if (!best_effort) {
            throw qv::Error{qv::ErrorDomain::Validation, 0, "Compressed metadata length overflow"};
          }
          metadata_dirty_ = true;
          original_size = 0;
        }
        auto encoded_data = body.substr(header_end + 1);
        auto decoded = Base64Decode(encoded_data);
        if (!decoded || decoded->size() != compressed_size || original_size == 0) {
          if (!best_effort) {
            throw qv::Error{qv::ErrorDomain::Validation, 0, "Compressed metadata payload truncated"};
          }
          metadata_dirty_ = true;
        } else {
          const size_t bounded_original_size = static_cast<size_t>(original_size);
          std::string decompressed(bounded_original_size, '\0');
          size_t result = ZSTD_decompress(decompressed.data(), decompressed.size(), decoded->data(), decoded->size());
          if (ZSTD_isError(result) || result != bounded_original_size) {
            if (!best_effort) {
              throw qv::Error{qv::ErrorDomain::Validation, 0, "Metadata decompression failed"};
            }
            metadata_dirty_ = true;
          } else {
            metadata_text.assign(decompressed.begin(), decompressed.end());
            compressed_body = true;
          }
        }
      }
    }
  }
  if (!compressed_body) {
    metadata_text = body;
  }
  if (metadata_text.empty()) {
    InitializeFreshMetadata();
    metadata_dirty_ = true;
    return false;
  }

  MetadataParseContext context{};
  context.root = std::make_shared<DirectoryEntry>();
  context.root->name = "/";
  context.root->mtime = CurrentTimespec();
  context.next_chunk_index = data_start_chunk_;
  context.next_seen = false;
  context.data_start_chunk = data_start_chunk_;
  context.max_reasonable_next =
      data_start_chunk_ + static_cast<uint64_t>(storage::kChunksPerGroup) * storage::kChunksPerGroup;
  if (context.max_reasonable_next < data_start_chunk_) {
    context.max_reasonable_next = 0;
  }
  context.best_effort = best_effort;

  bool parse_error = false;
  size_t applied_lines = 0;
  std::istringstream iss(metadata_text);
  std::string line;
  while (std::getline(iss, line)) {
    if (line.empty()) {
      continue;
    }
    context.total_entries++;
    auto tokens = SplitMetadataTokens(line);
    if (!tokens) {
      parse_error = true;
      context.skipped_entries++;
      continue;
    }
    if (ApplyMetadataTokens(*tokens, context)) {
      ++applied_lines;
      continue;
    }
    parse_error = true;
    if (context.best_effort && AttemptRescueFromTokens(*tokens, context)) {
      context.rescued_entries++;
      ++applied_lines;
    } else {
      context.skipped_entries++;
    }
  }

  if (!context.next_seen) {
    parse_error = true;
    context.next_chunk_index = data_start_chunk_;
  }
  if (context.next_chunk_index > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
    parse_error = true;
    context.next_chunk_index = data_start_chunk_;
  }
  if (kChunkPayloadSize != 0 &&
      context.next_chunk_index > std::numeric_limits<uint64_t>::max() / kChunkPayloadSize) {
    parse_error = true;
    context.next_chunk_index = data_start_chunk_;
  }

  if (!context.root) {
    InitializeFreshMetadata();
    metadata_dirty_ = true;
    return false;
  }

  root_ = context.root;
  next_chunk_index_ = context.next_chunk_index;
  next_file_offset_ = next_chunk_index_ * kChunkPayloadSize;
  if (applied_lines == 0) {
    root_->mtime = CurrentTimespec();
  }

  last_metadata_total_entries_ = context.total_entries;
  last_metadata_skipped_entries_ = context.skipped_entries;
  last_metadata_rescued_entries_ = context.rescued_entries;

  if (parse_error || had_chunk_failure || !mac_valid || context.rescued_entries > 0 ||
      context.skipped_entries > 0) {
    metadata_dirty_ = true;
  }
  return applied_lines > 0;
}

timespec VolumeFilesystem::CurrentTimespec() {
  auto now = std::chrono::system_clock::now();
  auto secs = std::chrono::time_point_cast<std::chrono::seconds>(now);
  timespec ts{};
  ts.tv_sec = secs.time_since_epoch().count();
  ts.tv_nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(now - secs).count();
  return ts;
}

}  // namespace qv::platform
