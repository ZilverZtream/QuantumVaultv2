#pragma once
#include <cstdint>
#include <stddef.h>

// TSK011 introduce negotiated plugin ABI metadata and capability schema.

// TSK010 cross-platform plugin ABI definitions.
#if defined(_WIN32)
#  define QV_PLUGIN_EXPORT __declspec(dllexport)
#else
#  define QV_PLUGIN_EXPORT
#endif

#define QV_PLUGIN_ABI_VERSION 1u
#define QV_PLUGIN_CAPABILITY_SCHEMA_VERSION 1u

// Capability bit layout (little-endian) reserves lower 32 bits for core flags,
// bits 32-47 for experimental features, and the remaining upper bits for
// vendor-specific extensions. Plugins should only set documented bits.
#define QV_PLUGIN_CAP_CORE_CRYPTO_PROVIDER (1ull << 0)
#define QV_PLUGIN_CAP_CORE_KEY_MANAGEMENT (1ull << 1)
#define QV_PLUGIN_CAP_CORE_STORAGE_BACKEND (1ull << 2)
#define QV_PLUGIN_CAP_CORE_ANALYTICS (1ull << 3)
#define QV_PLUGIN_CAP_EXPERIMENTAL_BEGIN (1ull << 32)
#define QV_PLUGIN_CAP_EXPERIMENTAL_END (1ull << 47)
#define QV_PLUGIN_CAP_VENDOR_BEGIN (1ull << 48)

#define QV_PLUGIN_CAP_CORE_MASK 0x00000000FFFFFFFFull
#define QV_PLUGIN_CAP_EXPERIMENTAL_MASK 0x0000FFFF00000000ull
#define QV_PLUGIN_CAP_VENDOR_MASK 0xFFFF000000000000ull

#if defined(__cplusplus)
#  define QV_PLUGIN_EXTERN extern "C"
#else
#  define QV_PLUGIN_EXTERN
#endif

#define QV_PLUGIN_API QV_PLUGIN_EXTERN QV_PLUGIN_EXPORT

#if defined(__cplusplus)
extern "C" {
#endif

// Minimal ABI for plugins in this skeleton
typedef struct QV_PluginInfo {
  uint32_t abi_version;
  const char* name;
  const char* version;
  uint64_t capabilities; // bitmask using QV_PLUGIN_CAP_* definitions
} QV_PluginInfo;

typedef struct QV_PluginAbiNegotiation {
  uint32_t min_supported;
  uint32_t max_supported;
} QV_PluginAbiNegotiation;

typedef int (*QV_Plugin_Init)(void);
typedef void (*QV_Plugin_Shutdown)(void);
typedef QV_PluginInfo (*QV_Plugin_GetInfo)(void);
typedef QV_PluginAbiNegotiation (*QV_Plugin_GetAbi)(void);
typedef int (*QV_Plugin_SelfTest)(void);

// Every plugin must export these (weakly enforced in skeleton)
// QV_Plugin_Init    qv_plugin_init
// QV_Plugin_Shutdown qv_plugin_shutdown
// QV_Plugin_GetInfo  qv_plugin_get_info
// qv_plugin_get_abi negotiates supported ABI range
// qv_plugin_selftest (optional) runs lightweight health checks

QV_PLUGIN_API QV_PluginAbiNegotiation qv_plugin_get_abi(void);
QV_PLUGIN_API int qv_plugin_selftest(void);

#if INTPTR_MAX == INT64_MAX
static_assert(sizeof(QV_PluginInfo) == 32, "Unexpected QV_PluginInfo size on 64-bit");
#elif INTPTR_MAX == INT32_MAX
static_assert(sizeof(QV_PluginInfo) == 20, "Unexpected QV_PluginInfo size on 32-bit");
#else
#error "Unsupported pointer size for QV_PluginInfo layout"
#endif

#if defined(__cplusplus)
} // extern "C"
#endif
