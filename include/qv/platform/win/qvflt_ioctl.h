#pragma once

// TSK714A_System_Drive_Encryption_(PreBoot_Windows_First)_Stage1_Minifilter

#include <stdint.h>

#ifdef _WIN32
#include <Windows.h>
#else
#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0u
#endif
#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0u
#endif
#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Device type chosen from user range to avoid collisions.
#define FILE_DEVICE_QVFLT 0x8342

// IOCTL function codes.
#define IOCTL_QVFLT_SET_KEY   CTL_CODE(FILE_DEVICE_QVFLT, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QVFLT_LOCK      CTL_CODE(FILE_DEVICE_QVFLT, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QVFLT_STATUS    CTL_CODE(FILE_DEVICE_QVFLT, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Supported algorithm identifiers.
#define QVFLT_ALGO_AES_XTS_256 1u

#pragma pack(push, 1)
typedef struct QVFLT_KEY_REQUEST {
    uint32_t algorithm; // QVFLT_ALGO_* value
    uint8_t key1[32];
    uint8_t key2[32];
} QVFLT_KEY_REQUEST;

typedef struct QVFLT_STATUS_RESPONSE {
    uint32_t isKeyLoaded; // non-zero when the driver has an active key
    uint32_t reserved;
} QVFLT_STATUS_RESPONSE;
#pragma pack(pop)

#ifdef __cplusplus
}
#endif

