#include "qv/platform/volume_filesystem.h"

// TSK062_FUSE_Filesystem_Integration_Linux simple chunk-backed filesystem façade

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <string_view>
#include <vector>

#if defined(__linux__)
#include <cerrno>
#include <unistd.h>
#endif

#if defined(_WIN32)
using mode_t = unsigned int;
#endif

#include "qv/error.h"

namespace qv::platform {
namespace {
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
  // TSK084_WinFSP_Normalization_and_Traversal normalize errno mapping for validation failures
  if (error.domain == qv::ErrorDomain::Validation) {
    return -EINVAL;
  }
  return -EIO;
}
#endif

std::string NormalizePath(const std::string& raw_path) {
  // TSK084_WinFSP_Normalization_and_Traversal hardened normalization for shared backends
  constexpr size_t kMaxPathDepth = 128;
  constexpr size_t kMaxPathLength = 4096;

  std::string cleaned = raw_path;
  std::replace(cleaned.begin(), cleaned.end(), '\\', '/');

  if (cleaned.find(':') != std::string::npos) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Drive-qualified paths are not allowed"};
  }
  if (cleaned.size() >= 2 && cleaned[0] == '/' && cleaned[1] == '/') {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "UNC paths are not allowed"};
  }

  std::filesystem::path fs_path(cleaned);
  if (fs_path.has_root_name()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Rooted paths are not allowed"};
  }

  auto normalized = fs_path.lexically_normal();
  std::string generic = normalized.generic_string();

  std::string result;
  if (generic.empty() || generic == "." || generic == "/") {
    result = "/";
  } else {
    result = std::move(generic);
    if (!normalized.has_root_directory() || result.front() != '/') {
      result.insert(result.begin(), '/');
    }
    while (result.size() > 1 && result.back() == '/') {
      result.pop_back();
    }
  }

  if (result.empty()) {
    result = "/";
  }

  size_t depth = 0;
  for (size_t pos = 1; pos < result.size();) {
    auto next = result.find('/', pos);
    size_t len = (next == std::string::npos) ? result.size() - pos : next - pos;
    if (len > 0) {
      auto segment = result.substr(pos, len);
      if (segment == "..") {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Path traversal outside root is not allowed"};
      }
      if (segment != ".") {
        ++depth;
        if (depth > kMaxPathDepth) {
          throw qv::Error{qv::ErrorDomain::Validation, 0, "Path depth exceeds maximum"};
        }
      }
    }
    if (next == std::string::npos) {
      break;
    }
    pos = next + 1;
  }

  if (result.size() > kMaxPathLength) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Path length exceeds maximum"};
  }

  return result;
}

timespec TimespecFrom(std::time_t sec, long nsec) {
  timespec ts{};
  ts.tv_sec = sec;
  ts.tv_nsec = nsec;
  return ts;
}
}  // namespace

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

  try {
    LoadMetadata();
  } catch (...) {
    SaveMetadata();
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
  for (const auto& part : fs_path) {
    auto name = part.string();
    if (name.empty() || name == "/") {
      continue;
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
  for (uint64_t i = 0; i < chunk_count; ++i) {
    auto chunk = device_->ReadChunk(static_cast<int64_t>(start_chunk + i));
    std::copy(chunk.ciphertext.begin(), chunk.ciphertext.end(),
              data.begin() + static_cast<std::ptrdiff_t>(i * kChunkPayloadSize));
  }
  data.resize(file.size);
  return data;
}

uint64_t VolumeFilesystem::AllocateChunks(uint64_t count) {
  if (count == 0) {
    return 0;
  }
  auto start = next_chunk_index_;
  next_chunk_index_ += count;
  next_file_offset_ = next_chunk_index_ * kChunkPayloadSize;
  return start;
}

void VolumeFilesystem::WriteFileContent(FileEntry& file, const std::vector<uint8_t>& data) {
  const uint64_t required_chunks = data.empty() ? 0 : (data.size() + kChunkPayloadSize - 1) / kChunkPayloadSize;
  const uint64_t old_start_chunk = file.start_offset / kChunkPayloadSize;
  const uint64_t old_chunks = file.size == 0 ? 0 : (file.size + kChunkPayloadSize - 1) / kChunkPayloadSize;

  uint64_t start_chunk = old_start_chunk;
  if (required_chunks == 0) {
    file.start_offset = 0;
    return;
  }
  if (old_chunks == 0 || start_chunk < data_start_chunk_ || required_chunks > old_chunks) {
    start_chunk = AllocateChunks(required_chunks);
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

  file.start_offset = start_chunk * kChunkPayloadSize;
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
    SaveMetadata();
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
    SaveMetadata();
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
  SaveMetadata();
  return data.size();
}

void VolumeFilesystem::CreateFileNode(const std::string& path, uint32_t mode, uint32_t uid,
                                      uint32_t gid) {
  FilesystemMutexGuard lock(fs_mutex_);
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
  SaveMetadata();
}

void VolumeFilesystem::CreateDirectoryNode(const std::string& path, uint32_t mode, uint32_t uid,
                                           uint32_t gid) {
  (void)mode;
  (void)uid;
  (void)gid;
  FilesystemMutexGuard lock(fs_mutex_);
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
  SaveMetadata();
}

void VolumeFilesystem::RemoveFileNode(const std::string& path) {
  FilesystemMutexGuard lock(fs_mutex_);
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
  SaveMetadata();
}

void VolumeFilesystem::RemoveDirectoryNode(const std::string& path) {
  FilesystemMutexGuard lock(fs_mutex_);
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
  SaveMetadata();
}

void VolumeFilesystem::TruncateFileNode(const std::string& path, uint64_t size) {
  FilesystemMutexGuard lock(fs_mutex_);
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
  SaveMetadata();
}

void VolumeFilesystem::RenameNode(const std::string& from, const std::string& to,
                                  bool replace_existing) {
  FilesystemMutexGuard lock(fs_mutex_);
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
    auto existing_dir = FindDirectory(to_norm);
    if (existing_dir) {
      if (!replace_existing) {
        throw qv::Error{qv::ErrorDomain::State, 0, "Destination exists"};
      }
      if (!existing_dir->files.empty() || !existing_dir->subdirs.empty()) {
        throw qv::Error{qv::ErrorDomain::State, 0, "Destination directory not empty"};
      }
      auto existing_it = std::find_if(dest_parent->subdirs.begin(), dest_parent->subdirs.end(),
                                      [&](const std::shared_ptr<DirectoryEntry>& child) {
                                        return child->name == dest_name;
                                      });
      if (existing_it != dest_parent->subdirs.end()) {
        dest_parent->subdirs.erase(existing_it);
      }
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
    entry.name = dest_name;
    dest_parent->files.push_back(entry);
    dest_parent->mtime = CurrentTimespec();
    from_parent->mtime = dest_parent->mtime;
  }

  SaveMetadata();
}

void VolumeFilesystem::UpdateTimestamps(const std::string& path, std::optional<timespec> modification,
                                        std::optional<timespec> change) {
  FilesystemMutexGuard lock(fs_mutex_);
  auto normalized = NormalizePath(path);
  if (auto* dir = FindDirectory(normalized)) {
    if (modification) {
      dir->mtime = *modification;
    }
    if (change) {
      dir->mtime = *change;
    }
    SaveMetadata();
    return;
  }
  if (auto* file = FindFile(normalized)) {
    if (modification) {
      file->mtime = *modification;
    }
    if (change) {
      file->ctime = *change;
    }
    SaveMetadata();
  }
}


int VolumeFilesystem::Unlink(const char* path) {
  try {
    FilesystemMutexGuard lock(fs_mutex_);
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
    SaveMetadata();
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
    SaveMetadata();
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
    SaveMetadata();
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
    SaveMetadata();
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
  out << "DIR " << path << ' ' << dir->mtime.tv_sec << ' ' << dir->mtime.tv_nsec << '\n';
  for (const auto& file : dir->files) {
    uint64_t start_chunk = kChunkPayloadSize == 0 ? 0 : file.start_offset / kChunkPayloadSize;
    auto mode_bits = file.mode == 0 ? kDefaultFileMode : file.mode;
    auto file_path = path == "/" ? "/" + file.name : path + "/" + file.name;
    out << "FILE " << file_path << ' ' << file.size << ' ' << start_chunk << ' ' << mode_bits << ' '
        << file.mtime.tv_sec << ' ' << file.mtime.tv_nsec << ' ' << file.ctime.tv_sec << ' '
        << file.ctime.tv_nsec << ' ' << static_cast<uint64_t>(file.uid) << ' '
        << static_cast<uint64_t>(file.gid) << '\n';
  }
  for (const auto& child : dir->subdirs) {
    auto child_path = path == "/" ? "/" + child->name : path + "/" + child->name;
    SerializeDirectory(out, child.get(), child_path);
  }
}

void VolumeFilesystem::SaveMetadata() {
  std::ostringstream serialized;
  serialized << "NEXT " << next_chunk_index_ << '\n';
  SerializeDirectory(serialized, root_.get(), "/");
  auto payload = serialized.str();
  const size_t total_bytes = metadata_chunk_count_ * kChunkPayloadSize;
  if (payload.size() > total_bytes) {
    throw qv::Error{qv::ErrorDomain::State, 0, "Metadata size exceeds reserved area"};
  }
  std::vector<uint8_t> buffer(total_bytes, 0);
  std::memcpy(buffer.data(), payload.data(), payload.size());
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

void VolumeFilesystem::ParseMetadataLine(const std::string& line) {
  if (line.empty()) {
    return;
  }
  std::istringstream iss(line);
  std::string tag;
  iss >> tag;
  if (tag == "NEXT") {
    uint64_t next_chunk = 0;
    iss >> next_chunk;
    if (next_chunk < data_start_chunk_) {
    next_chunk = data_start_chunk_;
    }
    next_chunk_index_ = next_chunk;
    next_file_offset_ = next_chunk_index_ * kChunkPayloadSize;
    return;
  }
  if (tag == "DIR") {
    std::string path;
    long sec = 0;
    long nsec = 0;
    iss >> path >> sec >> nsec;
    auto* dir = EnsureDirectory(path);
    dir->mtime = TimespecFrom(sec, nsec);
    return;
  }
  if (tag == "FILE") {
    std::string path;
    uint64_t size = 0;
    uint64_t start_chunk = 0;
    mode_t mode = 0;
    long msec = 0;
    long mnsec = 0;
    long csec = 0;
    long cnsec = 0;
    uint64_t uid = 0;
    uint64_t gid = 0;
    iss >> path >> size >> start_chunk >> mode >> msec >> mnsec >> csec >> cnsec >> uid >> gid;
    auto parent_path = std::filesystem::path(path).parent_path().string();
    if (parent_path.empty()) {
      parent_path = "/";
    }
    auto* dir = EnsureDirectory(parent_path);
    FileEntry entry{};
    entry.name = std::filesystem::path(path).filename().string();
    entry.size = size;
    entry.start_offset = start_chunk * kChunkPayloadSize;
    entry.mode = mode;
    entry.mtime = TimespecFrom(msec, mnsec);
    entry.ctime = TimespecFrom(csec, cnsec);
    entry.uid = static_cast<uid_t>(uid);
    entry.gid = static_cast<gid_t>(gid);
    dir->files.push_back(entry);
  }
}

void VolumeFilesystem::LoadMetadata() {
  std::vector<uint8_t> buffer(metadata_chunk_count_ * kChunkPayloadSize, 0);
  for (uint64_t i = 0; i < metadata_chunk_count_; ++i) {
    try {
      auto chunk = device_->ReadChunk(static_cast<int64_t>(metadata_chunk_start_ + i));
      std::copy(chunk.ciphertext.begin(), chunk.ciphertext.end(),
                buffer.begin() + static_cast<std::ptrdiff_t>(i * kChunkPayloadSize));
    } catch (...) {
      root_->files.clear();
      root_->subdirs.clear();
      next_chunk_index_ = data_start_chunk_;
      next_file_offset_ = next_chunk_index_ * kChunkPayloadSize;
      return;
    }
  }
  std::string serialized(reinterpret_cast<char*>(buffer.data()), buffer.size());
  auto null_pos = serialized.find('\0');
  if (null_pos != std::string::npos) {
    serialized.resize(null_pos);
  }
  if (serialized.empty()) {
    root_->files.clear();
    root_->subdirs.clear();
    next_chunk_index_ = data_start_chunk_;
    next_file_offset_ = next_chunk_index_ * kChunkPayloadSize;
    return;
  }
  root_->files.clear();
  root_->subdirs.clear();
  root_->mtime = CurrentTimespec();
  next_chunk_index_ = data_start_chunk_;
  next_file_offset_ = next_chunk_index_ * kChunkPayloadSize;
  std::istringstream iss(serialized);
  std::string line;
  while (std::getline(iss, line)) {
    ParseMetadataLine(line);
  }
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
