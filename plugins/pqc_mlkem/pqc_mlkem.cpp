#include "qv/orchestrator/plugin_abi.h"

// TSK010 ensure exports across platforms.
QV_PLUGIN_API int qv_plugin_init(void) { return 0; }
QV_PLUGIN_API void qv_plugin_shutdown(void) {}
QV_PLUGIN_API QV_PluginInfo qv_plugin_get_info(void) {
  // Capability bits are purely illustrative here.
  return QV_PluginInfo{QV_PLUGIN_ABI_VERSION, "pqc-mlkem-768", "0.1.0", 1ULL << 12};
}
