#pragma once

#include "qv/orchestrator/sealed_key.h"

// TSK713_TPM_SecureEnclave_Key_Sealing platform provider registration hook

namespace qv::platform {

void RegisterPlatformSealedKeyProviders(qv::orchestrator::SealedKeyRegistry& registry);

}  // namespace qv::platform
