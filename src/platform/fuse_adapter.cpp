#include "qv/platform/fuse_adapter.h"

// TSK062_FUSE_Filesystem_Integration_Linux glue between FUSE and chunk-backed volume

#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include <thread>

#include "qv/error.h"
#include "qv/platform/volume_filesystem.h"

namespace qv::platform {

namespace {
static VolumeFilesystem* g_filesystem = nullptr;

int qv_getattr(const char* path, struct stat* stbuf, struct fuse_file_info* fi) {
  (void)fi;
  return g_filesystem->GetAttr(path, stbuf);
}

int qv_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset,
               struct fuse_file_info* fi, enum fuse_readdir_flags flags) {
  (void)offset;
  (void)fi;
  (void)flags;
  return g_filesystem->ReadDir(path, buf, filler);
}

int qv_open(const char* path, struct fuse_file_info* fi) {
  return g_filesystem->Open(path, fi);
}

int qv_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
  (void)fi;
  return g_filesystem->Read(path, buf, size, offset);
}

int qv_write(const char* path, const char* buf, size_t size, off_t offset,
             struct fuse_file_info* fi) {
  (void)fi;
  return g_filesystem->Write(path, buf, size, offset);
}

int qv_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
  return g_filesystem->Create(path, mode, fi);
}

int qv_unlink(const char* path) {
  return g_filesystem->Unlink(path);
}

int qv_mkdir(const char* path, mode_t mode) {
  return g_filesystem->Mkdir(path, mode);
}

int qv_rmdir(const char* path) {
  return g_filesystem->Rmdir(path);
}

int qv_truncate(const char* path, off_t size, struct fuse_file_info* fi) {
  (void)fi;
  return g_filesystem->Truncate(path, size);
}

const struct fuse_operations kOperations = {
    .getattr = qv_getattr,
    .mkdir = qv_mkdir,
    .unlink = qv_unlink,
    .rmdir = qv_rmdir,
    .truncate = qv_truncate,
    .open = qv_open,
    .read = qv_read,
    .write = qv_write,
    .readdir = qv_readdir,
    .create = qv_create,
};

}  // namespace

FUSEAdapter::FUSEAdapter(std::shared_ptr<storage::BlockDevice> device)
    : filesystem_(std::make_unique<VolumeFilesystem>(std::move(device))) {
  g_filesystem = filesystem_.get();
}

FUSEAdapter::~FUSEAdapter() {
  Unmount();
}

void FUSEAdapter::Mount(const std::filesystem::path& mountpoint) {
  if (!filesystem_) {
    throw qv::Error{qv::ErrorDomain::State, 0, "Filesystem not initialized"};
  }

  const char* argv[] = {"qv.fuse", mountpoint.c_str(), "-f", "-o", "direct_io", "-o", "auto_unmount", nullptr};
  int argc = 7;
  struct fuse_args args = FUSE_ARGS_INIT(argc, const_cast<char**>(argv));

  fuse_ = fuse_new(&args, &kOperations, sizeof(kOperations), nullptr);
  fuse_opt_free_args(&args);
  if (!fuse_) {
    throw qv::Error{qv::ErrorDomain::IO, 0, "FUSE initialization failed"};
  }
  if (fuse_mount(fuse_, mountpoint.c_str()) != 0) {
    fuse_destroy(fuse_);
    fuse_ = nullptr;
    throw qv::Error{qv::ErrorDomain::IO, 0, "FUSE mount failed"};
  }

  fuse_thread_ = std::thread([this]() { fuse_loop(fuse_); });
}

void FUSEAdapter::RequestUnmount() {
  if (fuse_) {
    fuse_exit(fuse_);
  }
}

void FUSEAdapter::Unmount() {
  if (!fuse_) {
    g_filesystem = nullptr;
    return;
  }
  fuse_exit(fuse_);
  if (fuse_thread_.joinable()) {
    fuse_thread_.join();
  }
  fuse_unmount(fuse_);
  fuse_destroy(fuse_);
  fuse_ = nullptr;
  g_filesystem = nullptr;
}

}  // namespace qv::platform
