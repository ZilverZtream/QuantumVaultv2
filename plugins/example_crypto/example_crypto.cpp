#include "qv/orchestrator/plugin_abi.h"

extern "C" int qv_plugin_init(void) { return 0; }
extern "C" void qv_plugin_shutdown(void) {}
extern "C" QV_PluginInfo qv_plugin_get_info(void) {
  return QV_PluginInfo{1, "example-crypto", "0.1.0", 0};
}
