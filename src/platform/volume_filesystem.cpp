#include "qv/platform/volume_filesystem.h"

// TSK062_FUSE_Filesystem_Integration_Linux simple chunk-backed filesystem façade

#include <algorithm>
#include <chrono>
#include <cstring>
#include <span>
#include <sstream>
#include <string_view>
#include <vector>
#include <unistd.h>

#include "qv/error.h"

namespace qv::platform {
namespace {
constexpr mode_t kDefaultFileMode = 0644;
constexpr mode_t kDefaultDirMode = 0755;
constexpr uint64_t kChunkPayloadSize = storage::kChunkSize;

std::string NormalizePath(const std::string& raw_path) {
  if (raw_path.empty()) {
    return "/";
  }
  std::filesystem::path fs_path(raw_path);
  auto normalized = fs_path.lexically_normal();
  std::string result = normalized.string();
  if (result.empty()) {
    return "/";
  }
  if (result.front() != '/') {
    result.insert(result.begin(), '/');
  }
  if (result.size() > 1 && result.back() == '/') {
    result.pop_back();
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

int VolumeFilesystem::GetAttr(const char* path, struct stat* stbuf) {
  std::scoped_lock lock(fs_mutex_);
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
}

int VolumeFilesystem::ReadDir(const char* path, void* buf, fuse_fill_dir_t filler) {
  std::scoped_lock lock(fs_mutex_);
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
}

int VolumeFilesystem::Open(const char* path, struct fuse_file_info* fi) {
  (void)fi;
  std::scoped_lock lock(fs_mutex_);
  auto* file = FindFile(path);
  if (!file) {
    return -ENOENT;
  }
  return 0;
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

int VolumeFilesystem::Read(const char* path, char* buf, size_t size, off_t offset) {
  std::scoped_lock lock(fs_mutex_);
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
}

int VolumeFilesystem::Write(const char* path, const char* buf, size_t size, off_t offset) {
  std::scoped_lock lock(fs_mutex_);
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
}

int VolumeFilesystem::Create(const char* path, mode_t mode, struct fuse_file_info* fi) {
  (void)fi;
  std::scoped_lock lock(fs_mutex_);
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
}

int VolumeFilesystem::Unlink(const char* path) {
  std::scoped_lock lock(fs_mutex_);
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
}

int VolumeFilesystem::Mkdir(const char* path, mode_t mode) {
  (void)mode;
  std::scoped_lock lock(fs_mutex_);
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
}

int VolumeFilesystem::Rmdir(const char* path) {
  std::scoped_lock lock(fs_mutex_);
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
}

int VolumeFilesystem::Truncate(const char* path, off_t size) {
  std::scoped_lock lock(fs_mutex_);
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
}

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
