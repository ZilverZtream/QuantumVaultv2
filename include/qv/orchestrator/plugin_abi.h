#pragma once
#include <cstdint>
#include <stddef.h>

extern "C" {
// Minimal ABI for plugins in this skeleton
typedef struct QV_PluginInfo {
  uint32_t abi_version;
  const char* name;
  const char* version;
  uint64_t capabilities; // bitmask
} QV_PluginInfo;

typedef int (*QV_Plugin_Init)(void);
typedef void (*QV_Plugin_Shutdown)(void);
typedef QV_PluginInfo (*QV_Plugin_GetInfo)(void);

// Every plugin must export these (weakly enforced in skeleton)
// QV_Plugin_Init    qv_plugin_init
// QV_Plugin_Shutdown qv_plugin_shutdown
// QV_Plugin_GetInfo  qv_plugin_get_info
}
