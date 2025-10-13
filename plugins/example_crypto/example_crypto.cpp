#include "qv/orchestrator/plugin_abi.h"

// TSK010 ensure exports across platforms.
QV_PLUGIN_API int qv_plugin_init(void) { return 0; }
QV_PLUGIN_API void qv_plugin_shutdown(void) {}
QV_PLUGIN_API QV_PluginInfo qv_plugin_get_info(void) {
  return QV_PluginInfo{QV_PLUGIN_ABI_VERSION, "example-crypto", "0.1.0", 0};
}
QV_PLUGIN_API QV_PluginAbiNegotiation qv_plugin_get_abi(void) {  // TSK016_Windows_Compatibility_Fixes
  return QV_PluginAbiNegotiation{QV_PLUGIN_ABI_VERSION, QV_PLUGIN_ABI_VERSION};
}

QV_PLUGIN_API int qv_plugin_selftest(void) { return 0; }  // TSK016_Windows_Compatibility_Fixes
