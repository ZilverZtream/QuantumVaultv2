#pragma once

// TSK062_FUSE_Filesystem_Integration_Linux in-memory metadata backed by chunk storage

#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#if defined(__linux__)
#include <sys/types.h>
#include <fuse3/fuse.h>
#endif  // defined(__linux__)

#if defined(_WIN32)
#include <cstddef>
// Provide minimal POSIX-compatible types for Windows builds.
#ifndef _TIMESPEC_DEFINED
#define _TIMESPEC_DEFINED
struct timespec {
  long long tv_sec;
  long tv_nsec;
};
#endif  // _TIMESPEC_DEFINED
using uid_t = unsigned int;
using gid_t = unsigned int;
#endif  // defined(_WIN32)

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

struct NodeMetadata {
  bool is_directory{false};
  uint64_t size{0};
  uint32_t mode{0};
  timespec modification_time{};
  timespec change_time{};
  uint32_t uid{0};
  uint32_t gid{0};
};

struct DirectoryListingEntry {
  std::string name;
  bool is_directory{false};
  NodeMetadata metadata{};
};

class VolumeFilesystem {
  std::shared_ptr<storage::BlockDevice> device_;
  std::shared_ptr<DirectoryEntry> root_;
  std::mutex fs_mutex_;
  std::mutex allocation_mutex_;  // TSK117_Race_Conditions_in_Filesystem guard chunk cursor

  // Metadata stored at start of volume
  uint64_t metadata_size_ = 1024ull * 1024ull;  // 1MB for metadata
  uint64_t next_file_offset_ = 0;
  uint64_t metadata_chunk_start_ = 1;
  uint64_t metadata_chunk_count_ = 0;
  uint64_t data_start_chunk_ = 0;
  uint64_t next_chunk_index_ = 0;
  bool metadata_dirty_ = false;  // TSK117_Race_Conditions_in_Filesystem batch metadata persistence
  size_t last_metadata_total_entries_ = 0;      // TSK127_Incorrect_Filesystem_Metadata_Recovery recovery accounting
  size_t last_metadata_skipped_entries_ = 0;    // TSK127_Incorrect_Filesystem_Metadata_Recovery recovery accounting
  size_t last_metadata_rescued_entries_ = 0;    // TSK127_Incorrect_Filesystem_Metadata_Recovery salvage accounting
  bool last_metadata_best_effort_ = false;      // TSK127_Incorrect_Filesystem_Metadata_Recovery remember recovery mode
  std::vector<qv::storage::Extent> protected_extents_; // TSK710_Implement_Hidden_Volumes protected regions
  mutable std::mutex protected_mutex_;                // TSK710_Implement_Hidden_Volumes guard map
  std::optional<qv::storage::Extent>
      layout_region_;                            // TSK710_Implement_Hidden_Volumes hidden region bounds
  bool has_payload_limit_{false};                // TSK710_Implement_Hidden_Volumes enforce region capacity
  uint64_t payload_base_chunk_{0};               // TSK710_Implement_Hidden_Volumes base chunk index
  uint64_t payload_limit_chunk_{std::numeric_limits<uint64_t>::max()}; // TSK710_Implement_Hidden_Volumes end-exclusive limit

public:
  explicit VolumeFilesystem(std::shared_ptr<storage::BlockDevice> device,
                            std::optional<qv::storage::Extent> accessible_region = std::nullopt);
  ~VolumeFilesystem();  // TSK115_Memory_Leaks_and_Resource_Management ensure metadata persisted

#if defined(__linux__)
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
  int Release(const char* path, struct fuse_file_info* fi);  // TSK131_Missing_Flush_on_Close flush chunk cache on close
#endif  // defined(__linux__)

  // Generic helpers shared by platform adapters. // TSK063_WinFsp_Windows_Driver_Integration
  uint64_t TotalSizeBytes() const;
  uint64_t FreeSpaceBytes() const;
  std::optional<NodeMetadata> StatPath(const std::string& path);
  std::vector<DirectoryListingEntry> ListDirectoryEntries(const std::string& path);
  std::vector<uint8_t> ReadFileRange(const std::string& path, uint64_t offset, size_t length);
  size_t WriteFileRange(const std::string& path, uint64_t offset,
                        std::span<const uint8_t> data);
  void CreateFileNode(const std::string& path, uint32_t mode, uint32_t uid, uint32_t gid);
  void CreateDirectoryNode(const std::string& path, uint32_t mode, uint32_t uid,
                           uint32_t gid);
  void RemoveFileNode(const std::string& path);
  void RemoveDirectoryNode(const std::string& path);
  void TruncateFileNode(const std::string& path, uint64_t size);
  void RenameNode(const std::string& from, const std::string& to, bool replace_existing);
  void UpdateTimestamps(const std::string& path, std::optional<timespec> modification,
                        std::optional<timespec> change);

  std::shared_ptr<storage::BlockDevice> BlockDeviceHandle() const { return device_; }
  void FlushStorage();  // TSK131_Missing_Flush_on_Close ensure chunk persistence coordination
  void SetProtectedExtents(std::vector<qv::storage::Extent> exts); // TSK710_Implement_Hidden_Volumes guard configuration

private:
  class MetadataWritebackGuard;  // TSK117_Race_Conditions_in_Filesystem scoped metadata batching

  FileEntry* FindFile(const std::string& path);
  DirectoryEntry* FindDirectory(const std::string& path);
  DirectoryEntry* EnsureDirectory(const std::string& path);

  std::vector<uint8_t> ReadFileContent(const FileEntry& file);
  void WriteFileContent(FileEntry& file, const std::vector<uint8_t>& data);
  uint64_t AllocateChunks(uint64_t count, uint64_t* previous_next);
  void RestoreAllocationState(uint64_t previous_next);
  bool IsProtectedRange(uint64_t offset, uint64_t length, uint64_t* next_safe) const; // TSK710_Implement_Hidden_Volumes guard helper
  void ConfigureLayout(std::optional<qv::storage::Extent> region);                    // TSK710_Implement_Hidden_Volumes layout derivation

  void MarkMetadataDirtyLocked();
  void FlushMetadataLocked();
  void SaveMetadata();
  void PersistMetadataLocked();
  bool LoadMetadata(bool best_effort = false);  // TSK121_Missing_Authentication_in_Metadata hardened metadata recovery
  void InitializeFreshMetadata();               // TSK127_Incorrect_Filesystem_Metadata_Recovery reset helper
  void SerializeDirectory(std::ostringstream& out, const DirectoryEntry* dir,
                          const std::string& path);
  static timespec CurrentTimespec();
};

}  // namespace qv::platform
