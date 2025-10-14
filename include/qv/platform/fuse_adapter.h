#pragma once

// TSK062_FUSE_Filesystem_Integration_Linux adapter wiring for FUSE 3.x

#include <filesystem>
#include <memory>
#include <thread>

namespace qv::storage {
class BlockDevice;
}  // namespace qv::storage

namespace qv::platform {

class VolumeFilesystem;
struct fuse;

class FUSEAdapter {
public:
  explicit FUSEAdapter(std::shared_ptr<storage::BlockDevice> device);
  ~FUSEAdapter();

  void Mount(const std::filesystem::path& mountpoint);
  void RequestUnmount();
  void Unmount();

private:
  std::unique_ptr<VolumeFilesystem> filesystem_;
  struct fuse* fuse_{nullptr};
  std::thread fuse_thread_;
};

}  // namespace qv::platform
