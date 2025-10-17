#pragma once

// TSK063_WinFsp_Windows_Driver_Integration WinFsp bridge for Windows drive mounting

#include <memory>
#include <optional>
#include <string>

#include "qv/platform/volume_filesystem.h" // TSK718_AutoLock_and_MemoryLocking activity hooks
#include "qv/storage/chunk_layout.h"      // TSK710_Implement_Hidden_Volumes extent wiring

namespace qv {
namespace storage {
class BlockDevice;
}  // namespace storage

namespace platform {

class WinFspAdapter {
 public:
  explicit WinFspAdapter(std::shared_ptr<storage::BlockDevice> device,
                         std::optional<qv::storage::Extent> accessible_region = std::nullopt);
  ~WinFspAdapter();

  void Mount(const std::wstring& mountpoint);
  void Unmount();
  void ConfigureProtectedExtents(const std::vector<qv::storage::Extent>& extents); // TSK710_Implement_Hidden_Volumes guard wiring
  void SetActivityCallback(VolumeFilesystem::ActivityCallback cb, void* context) noexcept; // TSK718_AutoLock_and_MemoryLocking

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace platform
}  // namespace qv
