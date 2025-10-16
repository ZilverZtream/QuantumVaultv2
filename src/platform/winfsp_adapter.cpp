#include "qv/platform/winfsp_adapter.h"

// TSK063_WinFsp_Windows_Driver_Integration WinFsp-backed filesystem adapter implementation

#include "qv/error.h"
#include "qv/platform/volume_filesystem.h"

#if defined(_WIN32) && defined(QV_HAVE_WINFSP)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stringapiset.h>  // TSK120_Incorrect_Path_Normalization Unicode normalization helper

#include <winfsp/winfsp.h>

#include <algorithm>
#include <cwctype>   // TSK120_Incorrect_Path_Normalization printable-path validation helpers
#include <chrono>
#include <cstring>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#pragma comment(lib, "Normaliz.lib")  // TSK120_Incorrect_Path_Normalization ensure NFC support linkage

namespace qv::platform {

class WinFspAdapter::Impl {
 public:
  explicit Impl(std::shared_ptr<storage::BlockDevice> device)
      : volume_fs_(std::make_shared<VolumeFilesystem>(std::move(device))) {}

  ~Impl() { Unmount(); }

  void Mount(const std::wstring& mountpoint);
  void Unmount();

 private:
  struct NodeContext {
    std::string path;
    bool is_directory{false};
    bool delete_on_close{false};
  };

  static Impl* FromFs(FSP_FILE_SYSTEM* fs) {
    return static_cast<Impl*>(fs->UserContext);
  }

  static std::wstring Utf8ToWide(const std::string& value);
  static std::string WideToUtf8(const std::wstring& value);
  static std::string NormalizePath(const std::wstring& value);
  static NTSTATUS PathErrorStatus(const qv::Error& error);
  static UINT64 TimespecToFileTime(const timespec& ts);
  static timespec FileTimeToTimespec(UINT64 filetime);
  static void PopulateFileInfo(const NodeMetadata& metadata, FSP_FSCTL_FILE_INFO* info);
  static bool AppendDirectoryEntry(const NodeMetadata& metadata, const std::wstring& name,
                                   PVOID buffer, ULONG length, PULONG transferred);

  static NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM* fs, FSP_FSCTL_VOLUME_INFO* info);
  static NTSTATUS GetSecurityByName(FSP_FILE_SYSTEM* fs, PWSTR filename, PUINT32 attributes,
                                    PSECURITY_DESCRIPTOR descriptor, SIZE_T* descriptor_size);
  static NTSTATUS Open(FSP_FILE_SYSTEM* fs, PWSTR filename, UINT32 create_options,
                       UINT32 granted_access, PVOID* context, FSP_FSCTL_FILE_INFO* file_info);
  static NTSTATUS Create(FSP_FILE_SYSTEM* fs, PWSTR filename, UINT32 create_options,
                         UINT32 granted_access, UINT32 file_attributes,
                         PSECURITY_DESCRIPTOR descriptor, UINT64 allocation_size, PVOID* context,
                         FSP_FSCTL_FILE_INFO* file_info);
  static NTSTATUS Overwrite(FSP_FILE_SYSTEM* fs, PVOID context, UINT32 file_attributes,
                            BOOLEAN replace_attributes, UINT64 allocation_size,
                            FSP_FSCTL_FILE_INFO* file_info);
  static VOID Cleanup(FSP_FILE_SYSTEM* fs, PVOID context, PWSTR filename, ULONG flags);
  static VOID Close(FSP_FILE_SYSTEM* fs, PVOID context);
  static NTSTATUS Read(FSP_FILE_SYSTEM* fs, PVOID context, PVOID buffer, UINT64 offset,
                       ULONG length, PULONG transferred);
  static NTSTATUS Write(FSP_FILE_SYSTEM* fs, PVOID context, PVOID buffer, UINT64 offset,
                        ULONG length, BOOLEAN write_to_eof, BOOLEAN constrained,
                        PULONG transferred, FSP_FSCTL_FILE_INFO* file_info);
  static NTSTATUS GetFileInfo(FSP_FILE_SYSTEM* fs, PVOID context, FSP_FSCTL_FILE_INFO* file_info);
  static NTSTATUS SetFileSize(FSP_FILE_SYSTEM* fs, PVOID context, UINT64 new_size,
                              BOOLEAN set_allocation, FSP_FSCTL_FILE_INFO* file_info);
  static NTSTATUS SetBasicInfo(FSP_FILE_SYSTEM* fs, PVOID context, UINT32 file_attributes,
                               UINT64 creation_time, UINT64 access_time, UINT64 write_time,
                               UINT64 change_time, FSP_FSCTL_FILE_INFO* file_info);
  static NTSTATUS ReadDirectory(FSP_FILE_SYSTEM* fs, PVOID context, PWSTR pattern, PWSTR marker,
                                PVOID buffer, ULONG length, PULONG transferred);
  static NTSTATUS CanDelete(FSP_FILE_SYSTEM* fs, PVOID context, PWSTR filename);
  static NTSTATUS Rename(FSP_FILE_SYSTEM* fs, PVOID context, PWSTR filename, PWSTR new_filename,
                         BOOLEAN replace_existing);

  std::shared_ptr<VolumeFilesystem> volume_fs_;
  std::wstring mountpoint_;
  FSP_FILE_SYSTEM* fs_{nullptr};
};

void WinFspAdapter::Impl::Mount(const std::wstring& mountpoint) {
  if (!volume_fs_) {
    throw qv::Error{qv::ErrorDomain::State, 0, "Filesystem not initialized"};
  }
  if (fs_ != nullptr) {
    throw qv::Error{qv::ErrorDomain::State, 0, "Filesystem already mounted"};
  }

  mountpoint_ = mountpoint;

  FSP_FSCTL_VOLUME_PARAMS params{};
  params.Version = sizeof(FSP_FSCTL_VOLUME_PARAMS);
  params.SectorSize = 512;
  params.SectorsPerAllocationUnit = 8;
  FILETIME ft{};
  GetSystemTimeAsFileTime(&ft);
  params.VolumeCreationTime = (static_cast<UINT64>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
  params.VolumeSerialNumber = static_cast<UINT32>(GetTickCount64());
  params.FileInfoTimeout = 1000;
  params.CaseSensitiveSearch = 0;
  params.CasePreservedNames = 1;
  params.UnicodeOnDisk = 1;
  params.PersistentAcls = 0;
  params.PostCleanupWhenModifiedOnly = 1;
  params.PassQueryDirectoryFileName = 1;
  params.FlushAndPurgeOnCleanup = 1;
  wcscpy_s(params.FileSystemName, L"QuantumVault");
  wcscpy_s(params.Prefix, L"\\qv");

  static const FSP_FILE_SYSTEM_INTERFACE kInterface{
      GetVolumeInfo,
      nullptr,  // SetVolumeLabel
      GetSecurityByName,
      nullptr,  // CreateEx
      Open,
      Create,
      Overwrite,
      nullptr,  // Flush
      Cleanup,
      Close,
      Read,
      Write,
      nullptr,  // QueryDirectory
      ReadDirectory,
      nullptr,  // ResolveReparsePoints
      nullptr,  // GetReparsePoint
      nullptr,  // SetReparsePoint
      nullptr,  // DeleteReparsePoint
      GetFileInfo,
      SetBasicInfo,
      SetFileSize,
      nullptr,  // SetAllocationSize
      nullptr,  // CanHardLink
      CanDelete,
      Rename,
      nullptr,  // GetSecurity
      nullptr,  // SetSecurity
      nullptr,  // ReadNamedPipe
      nullptr,  // WriteNamedPipe
      nullptr,  // FlushNamedPipe
      nullptr,  // DisconnectNamedPipe
      nullptr,  // QueryNamedPipe
      nullptr,  // QueryDirectoryFile
      nullptr,  // QueryNetworkOpenInfo
      nullptr,  // Lock
      nullptr,  // Unlock
      nullptr,  // GetVolumeInfoEx
      nullptr,  // SetVolumeInfo
      nullptr,  // QueryEa
      nullptr,  // SetEa
      nullptr,  // Cold
  };

  NTSTATUS status = FspFileSystemCreate(const_cast<PWSTR>(FSP_FSCTL_DISK_DEVICE_NAME), &params,
                                        &kInterface, &fs_);
  if (!NT_SUCCESS(status)) {
    throw qv::Error{qv::ErrorDomain::IO, status, "WinFsp filesystem creation failed"};
  }

  fs_->UserContext = this;
  FspFileSystemSetOperationGuardStrategy(
      fs_, FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE);  // TSK130_Improper_WinFsp_Error_Mapping

  status = FspFileSystemSetMountPoint(fs_, mountpoint_.c_str());
  if (!NT_SUCCESS(status)) {
    FspFileSystemDelete(fs_);
    fs_ = nullptr;
    throw qv::Error{qv::ErrorDomain::IO, status, "WinFsp mount point assignment failed"};
  }

  status = FspFileSystemStartDispatcher(fs_, 0);
  if (!NT_SUCCESS(status)) {
    FspFileSystemDelete(fs_);
    fs_ = nullptr;
    throw qv::Error{qv::ErrorDomain::IO, status, "WinFsp dispatcher start failed"};
  }
}

void WinFspAdapter::Impl::Unmount() {
  if (!fs_) {
    return;
  }
  FspFileSystemStopDispatcher(fs_);
  FspFileSystemDelete(fs_);
  fs_ = nullptr;
}

std::wstring WinFspAdapter::Impl::Utf8ToWide(const std::string& value) {
  if (value.empty()) {
    return std::wstring{};
  }
  int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
  if (size <= 0) {
    return std::wstring{};
  }
  std::wstring wide(static_cast<size_t>(size - 1), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, wide.data(), size);
  return wide;
}

std::string WinFspAdapter::Impl::WideToUtf8(const std::wstring& value) {
  if (value.empty()) {
    return std::string{};
  }
  int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
  if (size <= 0) {
    return std::string{};
  }
  std::string narrow(static_cast<size_t>(size - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, narrow.data(), size, nullptr, nullptr);
  return narrow;
}

std::string WinFspAdapter::Impl::NormalizePath(const std::wstring& value) {
  // TSK084_WinFSP_Normalization_and_Traversal enforce canonical paths inside volume root
  // TSK120_Incorrect_Path_Normalization tighten wide-path normalization and validation
  constexpr size_t kMaxPathDepth = 128;
  constexpr size_t kMaxPathLength = 4096;
  constexpr size_t kMaxPathSegmentLength = 255;

  if (value.find(L' ') != std::wstring::npos) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Embedded null in path"};
  }
  for (wchar_t ch : value) {
    if (ch < 0x20 || !std::iswprint(static_cast<wint_t>(ch))) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Non-printable character in path"};
    }
  }

  std::wstring normalized_input = value;
  if (!normalized_input.empty()) {
    int required = NormalizeString(NormalizationC, normalized_input.c_str(),
                                   static_cast<int>(normalized_input.size()), nullptr, 0);
    if (required <= 0) {
      DWORD error = GetLastError();
      throw qv::Error{qv::ErrorDomain::Validation, static_cast<int>(error),
                      "Unicode normalization failed"};
    }
    std::wstring buffer(static_cast<size_t>(required), L' ');
    int written = NormalizeString(NormalizationC, normalized_input.c_str(),
                                  static_cast<int>(normalized_input.size()), buffer.data(), required);
    if (written <= 0) {
      DWORD error = GetLastError();
      throw qv::Error{qv::ErrorDomain::Validation, static_cast<int>(error),
                      "Unicode normalization failed"};
    }
    buffer.resize(static_cast<size_t>(written));
    normalized_input = std::move(buffer);
  }

  std::replace(normalized_input.begin(), normalized_input.end(), L'\', L'/');

  if (normalized_input.find(L':') != std::wstring::npos) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Drive-qualified paths are not supported"};
  }
  if (normalized_input.size() >= 2 && normalized_input[0] == L'/' && normalized_input[1] == L'/') {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "UNC paths are not supported"};
  }
  if (normalized_input.find(L"//") != std::wstring::npos) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Adjacent path separators are not supported"};
  }

  std::filesystem::path fs_path(normalized_input);
  if (fs_path.has_root_name()) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Root-qualified paths are not supported"};
  }

  auto normalized = fs_path.lexically_normal();
  const bool is_root_only = normalized.empty() || normalized == std::filesystem::path(L"/") ||
                            normalized == std::filesystem::path(L".");
  if ((normalized.has_root_name() || normalized.has_root_directory()) && !is_root_only) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Absolute paths are not supported"};
  }

  std::vector<std::wstring> segments;
  segments.reserve(kMaxPathDepth);
  for (const auto& part : normalized) {
    auto name = part.generic_wstring();
    if (name.empty() || name == L"/") {
      continue;
    }
    if (name == L".") {
      continue;
    }
    if (name == L"..") {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Path traversal outside root is not allowed"};
    }
    if (name.size() > kMaxPathSegmentLength) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Path segment length exceeds maximum"};
    }
    for (wchar_t ch : name) {
      if (ch < 0x20 || !std::iswprint(static_cast<wint_t>(ch))) {
        throw qv::Error{qv::ErrorDomain::Validation, 0, "Non-printable character in path segment"};
      }
    }
    segments.emplace_back(std::move(name));
    if (segments.size() > kMaxPathDepth) {
      throw qv::Error{qv::ErrorDomain::Validation, 0, "Path depth exceeds maximum"};
    }
  }

  std::wstring result = L"/";
  for (size_t i = 0; i < segments.size(); ++i) {
    if (i > 0) {
      result.push_back(L'/');
    }
    result.append(segments[i]);
  }

  if (result.size() > kMaxPathLength) {
    throw qv::Error{qv::ErrorDomain::Validation, 0, "Path length exceeds maximum"};
  }

  return WideToUtf8(result);
}

NTSTATUS WinFspAdapter::Impl::PathErrorStatus(const qv::Error& error) {
  // TSK084_WinFSP_Normalization_and_Traversal map validation failures to NTSTATUS codes
  // TSK130_Improper_WinFsp_Error_Mapping tighten domain-to-NTSTATUS translation for WinFsp
  const char* message = error.what();
  if (!message) {
    message = "";
  }
  const auto contains = [message](const char* needle) {
    return std::strstr(message, needle) != nullptr;
  };

  switch (error.domain) {
    case qv::ErrorDomain::Validation:
      if (contains("depth exceeds") || contains("length exceeds") ||
          contains("segment length exceeds")) {
        return STATUS_NAME_TOO_LONG;
      }
      if (contains("traversal")) {
        return STATUS_ACCESS_DENIED;
      }
      if (contains("Parent directory missing") || contains("Directory not found") ||
          contains("Destination parent missing")) {
        return STATUS_OBJECT_PATH_NOT_FOUND;
      }
      if (contains("Cannot remove root") || contains("Cannot rename root")) {
        return STATUS_ACCESS_DENIED;
      }
      if (contains("Embedded null") || contains("Drive-qualified") || contains("UNC paths") ||
          contains("Adjacent path separators") || contains("Non-printable") ||
          contains("Unicode normalization failed") || contains("syntax")) {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
      }
      return STATUS_OBJECT_PATH_SYNTAX_BAD;
    case qv::ErrorDomain::State:
      if (contains("Directory not empty") || contains("Destination directory not empty")) {
        return STATUS_DIRECTORY_NOT_EMPTY;
      }
      if (contains("Destination exists") || contains("already exists")) {
        return STATUS_OBJECT_NAME_COLLISION;
      }
      return STATUS_ACCESS_DENIED;
    case qv::ErrorDomain::IO:
      if (contains("not found")) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
      }
      return STATUS_IO_DEVICE_ERROR;
    default:
      break;
  }
  return STATUS_ACCESS_DENIED;
}

UINT64 WinFspAdapter::Impl::TimespecToFileTime(const timespec& ts) {
  constexpr int64_t kEpochDiff = 11644473600LL;  // Seconds between 1601 and 1970
  int64_t seconds = ts.tv_sec;
  if (seconds < 0) {
    seconds = 0;
  }
  int64_t total = (seconds + kEpochDiff) * 10000000LL + ts.tv_nsec / 100;
  if (total < 0) {
    total = 0;
  }
  return static_cast<UINT64>(total);
}

timespec WinFspAdapter::Impl::FileTimeToTimespec(UINT64 filetime) {
  constexpr int64_t kEpochDiff = 11644473600LL;
  timespec ts{};
  if (filetime == 0) {
    return ts;
  }
  int64_t total = static_cast<int64_t>(filetime);
  int64_t seconds = total / 10000000LL - kEpochDiff;
  int64_t remainder = total % 10000000LL;
  if (seconds < 0) {
    seconds = 0;
  }
  ts.tv_sec = seconds;
  ts.tv_nsec = static_cast<long>(remainder * 100);
  return ts;
}

void WinFspAdapter::Impl::PopulateFileInfo(const NodeMetadata& metadata,
                                           FSP_FSCTL_FILE_INFO* info) {
  std::memset(info, 0, sizeof(*info));
  if (metadata.is_directory) {
    info->FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    info->FileSize = 0;
    info->AllocationSize = 0;
  } else {
    info->FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
    info->FileSize = metadata.size;
    constexpr UINT64 kAllocationUnit = 512ULL * 8ULL;
    UINT64 rounded = (metadata.size + kAllocationUnit - 1) / kAllocationUnit * kAllocationUnit;
    info->AllocationSize = rounded;
  }
  info->CreationTime = TimespecToFileTime(metadata.change_time);
  info->LastAccessTime = TimespecToFileTime(metadata.modification_time);
  info->LastWriteTime = TimespecToFileTime(metadata.modification_time);
  info->ChangeTime = TimespecToFileTime(metadata.change_time);
  info->ReparseTag = 0;
  info->HardLinks = 1;
}

bool WinFspAdapter::Impl::AppendDirectoryEntry(const NodeMetadata& metadata, const std::wstring& name,
                                               PVOID buffer, ULONG length, PULONG transferred) {
  std::wstring entry_name = name;
  FSP_FSCTL_FILE_INFO file_info{};
  PopulateFileInfo(metadata, &file_info);

  UINT16 record_size = static_cast<UINT16>(sizeof(FSP_FSCTL_DIR_INFO) +
                                           entry_name.size() * sizeof(wchar_t));
  std::vector<uint8_t> storage(sizeof(FSP_FSCTL_DIR_INFO) + entry_name.size() * sizeof(wchar_t));
  std::fill(storage.begin(), storage.end(), 0);
  auto* dir_info = reinterpret_cast<FSP_FSCTL_DIR_INFO*>(storage.data());
  std::memset(dir_info->Padding, 0, sizeof(dir_info->Padding));
  dir_info->Size = record_size;
  dir_info->FileInfo = file_info;
  std::memcpy(dir_info->FileNameBuf, entry_name.data(), entry_name.size() * sizeof(wchar_t));
  return FspFileSystemAddDirInfo(dir_info, buffer, length, transferred);
}

NTSTATUS WinFspAdapter::Impl::GetVolumeInfo(FSP_FILE_SYSTEM* fs,
                                            FSP_FSCTL_VOLUME_INFO* info) {
  auto* self = FromFs(fs);
  info->TotalSize = self->volume_fs_->TotalSizeBytes();
  info->FreeSize = self->volume_fs_->FreeSpaceBytes();
  info->VolumeLabelLength = sizeof(L"QuantumVault") - sizeof(wchar_t);
  std::memcpy(info->VolumeLabel, L"QuantumVault", info->VolumeLabelLength);
  return STATUS_SUCCESS;
}

NTSTATUS WinFspAdapter::Impl::GetSecurityByName(FSP_FILE_SYSTEM* fs, PWSTR filename,
                                                PUINT32 attributes,
                                                PSECURITY_DESCRIPTOR descriptor,
                                                SIZE_T* descriptor_size) {
  auto* self = FromFs(fs);
  std::string path;
  try {
    path = NormalizePath(filename ? filename : L"\\");
  } catch (const qv::Error& error) {
    return PathErrorStatus(error);
  }

  std::optional<NodeMetadata> metadata;
  try {
    metadata = self->volume_fs_->StatPath(path);
  } catch (const qv::Error& error) {
    if (error.domain == qv::ErrorDomain::IO) {
      return STATUS_OBJECT_NAME_NOT_FOUND;  // TSK130_Improper_WinFsp_Error_Mapping
    }
    return PathErrorStatus(error);
  } catch (...) {
    if (attributes) {
      *attributes = FILE_ATTRIBUTE_ARCHIVE;
    }
    if (descriptor_size) {
      *descriptor_size = 0;
    }
    return STATUS_SUCCESS;  // TSK130_Improper_WinFsp_Error_Mapping surface attributes best-effort
  }
  if (!metadata) {
    return STATUS_OBJECT_NAME_NOT_FOUND;
  }
  if (attributes) {
    *attributes = metadata->is_directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
  }
  if (descriptor_size) {
    *descriptor_size = 0;
  }
  (void)descriptor;
  return STATUS_SUCCESS;
}

NTSTATUS WinFspAdapter::Impl::Open(FSP_FILE_SYSTEM* fs, PWSTR filename, UINT32 create_options,
                                   UINT32 granted_access, PVOID* context,
                                   FSP_FSCTL_FILE_INFO* file_info) {
  (void)granted_access;
  auto* self = FromFs(fs);
  std::string path;
  try {
    path = NormalizePath(filename ? filename : L"\\");
  } catch (const qv::Error& error) {
    return PathErrorStatus(error);
  }

  std::optional<NodeMetadata> metadata;
  try {
    metadata = self->volume_fs_->StatPath(path);
  } catch (const qv::Error& error) {
    return PathErrorStatus(error);
  } catch (...) {
    return STATUS_IO_DEVICE_ERROR;
  }
  if (!metadata) {
    return STATUS_OBJECT_NAME_NOT_FOUND;
  }
  if (metadata->is_directory && (create_options & FILE_NON_DIRECTORY_FILE)) {
    return STATUS_FILE_IS_A_DIRECTORY;
  }
  if (!metadata->is_directory && (create_options & FILE_DIRECTORY_FILE)) {
    return STATUS_NOT_A_DIRECTORY;
  }

  auto* node = new NodeContext{path, metadata->is_directory, false};
  *context = node;
  PopulateFileInfo(*metadata, file_info);
  return STATUS_SUCCESS;
}

NTSTATUS WinFspAdapter::Impl::Create(FSP_FILE_SYSTEM* fs, PWSTR filename, UINT32 create_options,
                                     UINT32 granted_access, UINT32 file_attributes,
                                     PSECURITY_DESCRIPTOR descriptor, UINT64 allocation_size,
                                     PVOID* context, FSP_FSCTL_FILE_INFO* file_info) {
  (void)granted_access;
  (void)descriptor;
  (void)allocation_size;
  auto* self = FromFs(fs);
  std::string path;
  try {
    path = NormalizePath(filename ? filename : L"\\");
  } catch (const qv::Error& error) {
    return PathErrorStatus(error);
  }
  bool is_directory = (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
                      (create_options & FILE_DIRECTORY_FILE) != 0;
  try {
    if (is_directory) {
      self->volume_fs_->CreateDirectoryNode(path, 0755, 0, 0);
    } else {
      self->volume_fs_->CreateFileNode(path, 0644, 0, 0);
    }
  } catch (const qv::Error& error) {
    return PathErrorStatus(error);
  }

  std::optional<NodeMetadata> metadata;
  try {
    metadata = self->volume_fs_->StatPath(path);
  } catch (const qv::Error& error) {
    return PathErrorStatus(error);
  } catch (...) {
    return STATUS_IO_DEVICE_ERROR;
  }
  if (!metadata) {
    return STATUS_OBJECT_NAME_NOT_FOUND;
  }
  auto* node = new NodeContext{path, metadata->is_directory, false};
  *context = node;
  PopulateFileInfo(*metadata, file_info);
  return STATUS_SUCCESS;
}

NTSTATUS WinFspAdapter::Impl::Overwrite(FSP_FILE_SYSTEM* fs, PVOID context, UINT32 file_attributes,
                                        BOOLEAN replace_attributes, UINT64 allocation_size,
                                        FSP_FSCTL_FILE_INFO* file_info) {
  (void)file_attributes;
  (void)replace_attributes;
  (void)allocation_size;
  auto* self = FromFs(fs);
  auto* node = static_cast<NodeContext*>(context);
  if (!node || node->is_directory) {
    return STATUS_INVALID_PARAMETER;
  }
  try {
    self->volume_fs_->TruncateFileNode(node->path, 0);
  } catch (const qv::Error&) {
    return STATUS_IO_DEVICE_ERROR;
  }
  auto metadata = self->volume_fs_->StatPath(node->path);
  if (!metadata) {
    return STATUS_OBJECT_NAME_NOT_FOUND;
  }
  PopulateFileInfo(*metadata, file_info);
  return STATUS_SUCCESS;
}

VOID WinFspAdapter::Impl::Cleanup(FSP_FILE_SYSTEM* fs, PVOID context, PWSTR filename,
                                  ULONG flags) {
  (void)filename;
  auto* self = FromFs(fs);
  auto* node = static_cast<NodeContext*>(context);
  if (!self || !node) {
    return;
  }
  if (flags & FspCleanupDelete) {
    try {
      self->volume_fs_->FlushStorage();  // TSK131_Missing_Flush_on_Close ensure dirty chunks reach the device before delete
    } catch (...) {
      // Best-effort; WinFsp will surface subsequent errors via Close.
    }
    node->delete_on_close = true;
  }
}

VOID WinFspAdapter::Impl::Close(FSP_FILE_SYSTEM* fs, PVOID context) {
  auto* self = FromFs(fs);
  auto* node = static_cast<NodeContext*>(context);
  if (!node) {
    return;
  }
  try {
    self->volume_fs_->FlushStorage();  // TSK131_Missing_Flush_on_Close persist cached chunks before metadata updates
  } catch (...) {
    // Continue with close to avoid leaking handles; metadata flush handles remaining errors.
  }
  if (node->delete_on_close) {
    try {
      if (node->is_directory) {
        self->volume_fs_->RemoveDirectoryNode(node->path);
      } else {
        self->volume_fs_->RemoveFileNode(node->path);
      }
    } catch (...) {
      // Ignore cleanup errors.
    }
  }
  delete node;
}

NTSTATUS WinFspAdapter::Impl::Read(FSP_FILE_SYSTEM* fs, PVOID context, PVOID buffer,
                                   UINT64 offset, ULONG length, PULONG transferred) {
  auto* self = FromFs(fs);
  auto* node = static_cast<NodeContext*>(context);
  if (!node || node->is_directory) {
    return STATUS_INVALID_PARAMETER;
  }
  try {
    auto data = self->volume_fs_->ReadFileRange(node->path, offset, length);
    std::memcpy(buffer, data.data(), data.size());
    *transferred = static_cast<ULONG>(data.size());
    return STATUS_SUCCESS;
  } catch (...) {
    return STATUS_IO_DEVICE_ERROR;
  }
}

NTSTATUS WinFspAdapter::Impl::Write(FSP_FILE_SYSTEM* fs, PVOID context, PVOID buffer,
                                    UINT64 offset, ULONG length, BOOLEAN write_to_eof,
                                    BOOLEAN constrained, PULONG transferred,
                                    FSP_FSCTL_FILE_INFO* file_info) {
  (void)write_to_eof;
  (void)constrained;
  auto* self = FromFs(fs);
  auto* node = static_cast<NodeContext*>(context);
  if (!node || node->is_directory) {
    return STATUS_INVALID_PARAMETER;
  }
  try {
    auto span = std::span<const uint8_t>(static_cast<const uint8_t*>(buffer), length);
    size_t written = self->volume_fs_->WriteFileRange(node->path, offset, span);
    *transferred = static_cast<ULONG>(written);
    if (file_info) {
      auto metadata = self->volume_fs_->StatPath(node->path);
      if (metadata) {
        PopulateFileInfo(*metadata, file_info);
      }
    }
    return STATUS_SUCCESS;
  } catch (...) {
    return STATUS_IO_DEVICE_ERROR;
  }
}

NTSTATUS WinFspAdapter::Impl::GetFileInfo(FSP_FILE_SYSTEM* fs, PVOID context,
                                          FSP_FSCTL_FILE_INFO* file_info) {
  auto* self = FromFs(fs);
  auto* node = static_cast<NodeContext*>(context);
  if (!node) {
    return STATUS_INVALID_PARAMETER;
  }
  auto metadata = self->volume_fs_->StatPath(node->path);
  if (!metadata) {
    return STATUS_OBJECT_NAME_NOT_FOUND;
  }
  PopulateFileInfo(*metadata, file_info);
  return STATUS_SUCCESS;
}

NTSTATUS WinFspAdapter::Impl::SetFileSize(FSP_FILE_SYSTEM* fs, PVOID context, UINT64 new_size,
                                          BOOLEAN set_allocation, FSP_FSCTL_FILE_INFO* file_info) {
  (void)set_allocation;
  auto* self = FromFs(fs);
  auto* node = static_cast<NodeContext*>(context);
  if (!node || node->is_directory) {
    return STATUS_INVALID_PARAMETER;
  }
  try {
    self->volume_fs_->TruncateFileNode(node->path, new_size);
    auto metadata = self->volume_fs_->StatPath(node->path);
    if (metadata) {
      PopulateFileInfo(*metadata, file_info);
    }
    return STATUS_SUCCESS;
  } catch (...) {
    return STATUS_IO_DEVICE_ERROR;
  }
}

NTSTATUS WinFspAdapter::Impl::SetBasicInfo(FSP_FILE_SYSTEM* fs, PVOID context,
                                           UINT32 file_attributes, UINT64 creation_time,
                                           UINT64 access_time, UINT64 write_time,
                                           UINT64 change_time, FSP_FSCTL_FILE_INFO* file_info) {
  (void)file_attributes;
  (void)access_time;
  auto* self = FromFs(fs);
  auto* node = static_cast<NodeContext*>(context);
  if (!node) {
    return STATUS_INVALID_PARAMETER;
  }
  std::optional<timespec> modified;
  std::optional<timespec> changed;
  if (write_time) {
    modified = FileTimeToTimespec(write_time);
  }
  if (change_time) {
    changed = FileTimeToTimespec(change_time);
  } else if (creation_time) {
    changed = FileTimeToTimespec(creation_time);
  }
  try {
    self->volume_fs_->UpdateTimestamps(node->path, modified, changed);
    auto metadata = self->volume_fs_->StatPath(node->path);
    if (metadata) {
      PopulateFileInfo(*metadata, file_info);
    }
    return STATUS_SUCCESS;
  } catch (...) {
    return STATUS_IO_DEVICE_ERROR;
  }
}

NTSTATUS WinFspAdapter::Impl::ReadDirectory(FSP_FILE_SYSTEM* fs, PVOID context, PWSTR pattern,
                                            PWSTR marker, PVOID buffer, ULONG length,
                                            PULONG transferred) {
  (void)pattern;
  (void)marker;
  auto* self = FromFs(fs);
  auto* node = static_cast<NodeContext*>(context);
  if (!node || !node->is_directory) {
    return STATUS_NOT_A_DIRECTORY;
  }
  try {
    auto entries = self->volume_fs_->ListDirectoryEntries(node->path);
    auto current_meta = self->volume_fs_->StatPath(node->path);
    *transferred = 0;
    NodeMetadata dot_meta{};
    dot_meta.is_directory = true;
    if (current_meta) {
      dot_meta.modification_time = current_meta->modification_time;
      dot_meta.change_time = current_meta->change_time;
    }
    if (!AppendDirectoryEntry(dot_meta, std::wstring(L"."), buffer, length, transferred)) {
      return STATUS_SUCCESS;
    }
    if (node->path != "/") {
      auto parent_path = std::filesystem::path(node->path).parent_path().string();
      if (parent_path.empty()) {
        parent_path = "/";
      }
      auto parent_meta = self->volume_fs_->StatPath(parent_path);
      NodeMetadata dotdot_meta{};
      dotdot_meta.is_directory = true;
      if (parent_meta) {
        dotdot_meta.modification_time = parent_meta->modification_time;
        dotdot_meta.change_time = parent_meta->change_time;
      }
      if (!AppendDirectoryEntry(dotdot_meta, std::wstring(L".."), buffer, length, transferred)) {
        return STATUS_SUCCESS;
      }
    }
    for (const auto& entry : entries) {
      auto wide_name = Utf8ToWide(entry.name);
      if (!AppendDirectoryEntry(entry.metadata, wide_name, buffer, length, transferred)) {
        break;
      }
    }
    FspFileSystemAddDirInfo(nullptr, buffer, length, transferred);
    return STATUS_SUCCESS;
  } catch (...) {
    return STATUS_IO_DEVICE_ERROR;
  }
}

NTSTATUS WinFspAdapter::Impl::CanDelete(FSP_FILE_SYSTEM* fs, PVOID context, PWSTR filename) {
  (void)filename;
  auto* self = FromFs(fs);
  auto* node = static_cast<NodeContext*>(context);
  if (!node) {
    return STATUS_INVALID_PARAMETER;
  }
  if (!node->is_directory) {
    return STATUS_SUCCESS;
  }
  try {
    auto entries = self->volume_fs_->ListDirectoryEntries(node->path);
    if (!entries.empty()) {
      return STATUS_DIRECTORY_NOT_EMPTY;
    }
    return STATUS_SUCCESS;
  } catch (const qv::Error& error) {
    return PathErrorStatus(error);  // TSK130_Improper_WinFsp_Error_Mapping preserve domain semantics
  } catch (...) {
    return STATUS_IO_DEVICE_ERROR;
  }
}

NTSTATUS WinFspAdapter::Impl::Rename(FSP_FILE_SYSTEM* fs, PVOID context, PWSTR filename,
                                     PWSTR new_filename, BOOLEAN replace_existing) {
  (void)filename;
  auto* self = FromFs(fs);
  auto* node = static_cast<NodeContext*>(context);
  if (!node) {
    return STATUS_INVALID_PARAMETER;
  }
  auto from_path = node->path;
  std::string to_path;
  try {
    to_path = NormalizePath(new_filename ? new_filename : L"\\");
  } catch (const qv::Error& error) {
    return PathErrorStatus(error);
  }
  if (to_path == "/") {
    return STATUS_INVALID_PARAMETER;
  }
  try {
    self->volume_fs_->RenameNode(from_path, to_path, replace_existing);
    node->path = to_path;
    return STATUS_SUCCESS;
  } catch (const qv::Error& error) {
    return PathErrorStatus(error);
  }
}

WinFspAdapter::WinFspAdapter(std::shared_ptr<storage::BlockDevice> device)
    : impl_(std::make_unique<Impl>(std::move(device))) {}

WinFspAdapter::~WinFspAdapter() = default;

void WinFspAdapter::Mount(const std::wstring& mountpoint) { impl_->Mount(mountpoint); }

void WinFspAdapter::Unmount() { impl_->Unmount(); }

}  // namespace qv::platform

#else  // defined(_WIN32) && defined(QV_HAVE_WINFSP)

namespace qv::platform {

class WinFspAdapter::Impl {
 public:
  explicit Impl(std::shared_ptr<storage::BlockDevice>) {}
  void Mount(const std::wstring&) {
    throw qv::Error{qv::ErrorDomain::Validation, 0,
                    "WinFsp is only available on Windows platforms"};
  }
  void Unmount() {}
};

WinFspAdapter::WinFspAdapter(std::shared_ptr<storage::BlockDevice> device)
    : impl_(std::make_unique<Impl>(std::move(device))) {}

WinFspAdapter::~WinFspAdapter() = default;

void WinFspAdapter::Mount(const std::wstring& mountpoint) { impl_->Mount(mountpoint); }

void WinFspAdapter::Unmount() { impl_->Unmount(); }

}  // namespace qv::platform

#endif  // defined(_WIN32) && defined(QV_HAVE_WINFSP)
