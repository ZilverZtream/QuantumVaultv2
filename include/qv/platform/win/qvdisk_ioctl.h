#pragma once
// TSK714B_System_Drive_Encryption_(PreBoot_Windows_First)_Stage2_PreBoot_FullDisk

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#  include <winioctl.h>
#else
#  ifndef FILE_DEVICE_DISK
#    define FILE_DEVICE_DISK 0x00000007
#  endif
#  ifndef METHOD_BUFFERED
#    define METHOD_BUFFERED 0
#  endif
#  ifndef FILE_ANY_ACCESS
#    define FILE_ANY_ACCESS 0
#  endif
#  ifndef FILE_READ_ACCESS
#    define FILE_READ_ACCESS 0x0001
#  endif
#  ifndef FILE_WRITE_ACCESS
#    define FILE_WRITE_ACCESS 0x0002
#  endif
#  ifndef CTL_CODE
#    define CTL_CODE(DeviceType, Function, Method, Access) \
        (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#  endif
#endif

#define QVDISK_SESSION_KEY_BYTES 64u
#define QVDISK_RECOVERY_KEY_BYTES 64u

#define QVDISK_IMPORT_FLAG_NONE         0x00000000u
#define QVDISK_IMPORT_FLAG_RECOVERY_KEY 0x00000001u

// TSK_CRIT_05: Firmware-backed session key handoff metadata
#define QVDISK_FIRMWARE_VARIABLE_NAME        L"QVKey"
#define QVDISK_FIRMWARE_VARIABLE_ATTRIBUTES  0x00000002u
#define QVDISK_FIRMWARE_VARIABLE_GUID                                          \
    { 0xd16a4c54, 0x0f07, 0x4a28, { 0x9a, 0x5e, 0x5d, 0xe4, 0x1a, 0x3b, 0x92, 0x8c } }

#define IOCTL_QVDISK_IMPORT_SESSION_KEY CTL_CODE(FILE_DEVICE_DISK, 0x900, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_QVDISK_LOCK               CTL_CODE(FILE_DEVICE_DISK, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_QVDISK_STATUS             CTL_CODE(FILE_DEVICE_DISK, 0x902, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_QVDISK_ENROLL_RECOVERY    CTL_CODE(FILE_DEVICE_DISK, 0x903, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#pragma pack(push, 1)
typedef struct _QVDISK_SESSION_KEY {
    uint8_t key[QVDISK_SESSION_KEY_BYTES];
    uint32_t algorithm; /* AES-XTS-512 default */
    uint32_t flags;
} QVDISK_SESSION_KEY;

typedef struct _QVDISK_STATUS_RESPONSE {
    uint8_t keyLoaded;
    uint8_t usingRecoveryKey;
    uint8_t integrityPlaneEnabled;
    uint8_t reserved;
} QVDISK_STATUS_RESPONSE;

typedef struct _QVDISK_RECOVERY_KEY_BLOB {
    uint8_t key[QVDISK_RECOVERY_KEY_BYTES];
    uint32_t size;
    uint32_t version;
} QVDISK_RECOVERY_KEY_BLOB;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

static inline void qvdisk_zero_memory(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
}

#ifdef __cplusplus
}
#endif

