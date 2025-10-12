#include "qv/orchestrator/volume_manager.h"

using namespace qv::orchestrator;

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Create(const std::filesystem::path& container,
                      const std::string& password) {
  // STUB: creation path would initialize headers, TLVs, PQC, etc.
  (void)container; (void)password;
  return ConstantTimeMount::VolumeHandle{1};
}

std::optional<ConstantTimeMount::VolumeHandle>
VolumeManager::Mount(const std::filesystem::path& container,
                     const std::string& password) {
  return ctm_.Mount(container, password);
}
