#pragma once

// TSK062_FUSE_Filesystem_Integration_Linux in-memory metadata backed by chunk storage

#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <fuse3/fuse.h>

#include "qv/storage/block_device.h"

namespace qv::platform {

struct FileEntry {
  std::string name;
  uint64_t size{0};
  uint64_t start_offset{0};  // In block device payload space
  mode_t mode{0};
  timespec mtime{};
  timespec ctime{};
  uid_t uid{0};
  gid_t gid{0};
};

struct DirectoryEntry {
  std::string name;
  std::vector<FileEntry> files;
  std::vector<std::shared_ptr<DirectoryEntry>> subdirs;
  timespec mtime{};
};

class VolumeFilesystem {
  std::shared_ptr<storage::BlockDevice> device_;
  std::shared_ptr<DirectoryEntry> root_;
  std::mutex fs_mutex_;

  // Metadata stored at start of volume
  uint64_t metadata_size_ = 1024ull * 1024ull;  // 1MB for metadata
  uint64_t next_file_offset_ = 0;
  uint64_t metadata_chunk_start_ = 1;
  uint64_t metadata_chunk_count_ = 0;
  uint64_t data_start_chunk_ = 0;
  uint64_t next_chunk_index_ = 0;

public:
  explicit VolumeFilesystem(std::shared_ptr<storage::BlockDevice> device);

  // Filesystem operations
  int GetAttr(const char* path, struct stat* stbuf);
  int ReadDir(const char* path, void* buf, fuse_fill_dir_t filler);
  int Open(const char* path, struct fuse_file_info* fi);
  int Read(const char* path, char* buf, size_t size, off_t offset);
  int Write(const char* path, const char* buf, size_t size, off_t offset);
  int Create(const char* path, mode_t mode, struct fuse_file_info* fi);
  int Unlink(const char* path);
  int Mkdir(const char* path, mode_t mode);
  int Rmdir(const char* path);
  int Truncate(const char* path, off_t size);

private:
  FileEntry* FindFile(const std::string& path);
  DirectoryEntry* FindDirectory(const std::string& path);
  DirectoryEntry* EnsureDirectory(const std::string& path);

  std::vector<uint8_t> ReadFileContent(const FileEntry& file);
  void WriteFileContent(FileEntry& file, const std::vector<uint8_t>& data);
  uint64_t AllocateChunks(uint64_t count);

  void SaveMetadata();
  void LoadMetadata();
  void SerializeDirectory(std::ostringstream& out, const DirectoryEntry* dir,
                          const std::string& path);
  void ParseMetadataLine(const std::string& line);
  static timespec CurrentTimespec();
};

}  // namespace qv::platform
