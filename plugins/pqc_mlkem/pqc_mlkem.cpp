#include "qv/orchestrator/plugin_abi.h"

extern "C" int qv_plugin_init(void) { return 0; }
extern "C" void qv_plugin_shutdown(void) {}
extern "C" QV_PluginInfo qv_plugin_get_info(void) {
  // Capability bits are purely illustrative here.
  return QV_PluginInfo{1, "pqc-mlkem-768", "0.1.0", 1ULL << 12};
}
