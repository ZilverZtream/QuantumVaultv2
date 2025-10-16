#pragma once

// TSK062_FUSE_Filesystem_Integration_Linux adapter wiring for FUSE 3.x

#include <filesystem>
#include <memory>
#include <optional>
#include <thread>

#include "qv/storage/chunk_layout.h" // TSK710_Implement_Hidden_Volumes extent wiring

namespace qv::storage {
class BlockDevice;
}  // namespace qv::storage

namespace qv::platform {

class VolumeFilesystem;
struct fuse;

class FUSEAdapter {
public:
  explicit FUSEAdapter(std::shared_ptr<storage::BlockDevice> device,
                       std::optional<qv::storage::Extent> accessible_region = std::nullopt);
  ~FUSEAdapter();

  void Mount(const std::filesystem::path& mountpoint);
  void RequestUnmount();
  void Unmount();
  void ConfigureProtectedExtents(const std::vector<qv::storage::Extent>& extents); // TSK710_Implement_Hidden_Volumes guard wiring

private:
  std::unique_ptr<VolumeFilesystem> filesystem_;
  struct fuse* fuse_{nullptr};
  std::thread fuse_thread_;
};

}  // namespace qv::platform
