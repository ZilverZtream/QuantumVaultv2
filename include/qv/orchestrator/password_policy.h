#pragma once

#include <string>

namespace qv::orchestrator {

void EnforcePasswordPolicy(const std::string& password); // TSK135_Password_Complexity_Enforcement shared password policy

}  // namespace qv::orchestrator

