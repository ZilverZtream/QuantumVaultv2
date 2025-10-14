#pragma once

// TSK063_WinFsp_Windows_Driver_Integration WinFsp bridge for Windows drive mounting

#include <memory>
#include <string>

namespace qv {
namespace storage {
class BlockDevice;
}  // namespace storage

namespace platform {

class WinFspAdapter {
 public:
  explicit WinFspAdapter(std::shared_ptr<storage::BlockDevice> device);
  ~WinFspAdapter();

  void Mount(const std::wstring& mountpoint);
  void Unmount();

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace platform
}  // namespace qv
