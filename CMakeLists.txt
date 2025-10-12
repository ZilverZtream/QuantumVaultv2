cmake_minimum_required(VERSION 3.20)
project(QuantumVault VERSION 4.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(QV_BUILD_TESTS "Build unit tests" ON)

add_library(qv_core
    src/core/nonce.cpp
    src/core/nonce_log.cpp
    src/core/pqc_hybrid_kdf.cpp
    src/crypto/aes_gcm.cpp
    src/crypto/hmac_sha256.cpp
    src/crypto/sha256.cpp
    src/security/zeroizer.cpp
)
target_include_directories(qv_core PUBLIC include)

add_library(qv_orchestrator
    src/orchestrator/plugin_verification.cpp
    src/orchestrator/constant_time_mount.cpp
    src/orchestrator/plugin_manager.cpp
    src/orchestrator/volume_manager.cpp
    src/orchestrator/event_bus.cpp
)
target_include_directories(qv_orchestrator PUBLIC include)
target_link_libraries(qv_orchestrator PUBLIC qv_core)

add_executable(qv src/cli/main.cpp)
target_include_directories(qv PUBLIC include)
target_link_libraries(qv PRIVATE qv_core qv_orchestrator)

# Plugins (examples)
add_library(qv_example_crypto MODULE plugins/example_crypto/example_crypto.cpp)
target_include_directories(qv_example_crypto PUBLIC include)
set_target_properties(qv_example_crypto PROPERTIES
    PREFIX ""  # cross-platform friendlier
    OUTPUT_NAME "qv_example_crypto"
)

add_library(qv_pqc_mlkem MODULE plugins/pqc_mlkem/pqc_mlkem.cpp)
target_include_directories(qv_pqc_mlkem PUBLIC include)
set_target_properties(qv_pqc_mlkem PROPERTIES
    PREFIX ""
    OUTPUT_NAME "qv_pqc_mlkem"
)

# Tests
if(QV_BUILD_TESTS)
  enable_testing()
  add_executable(qv_tests tests/test_nonce.cpp)
  target_include_directories(qv_tests PUBLIC include)
  target_link_libraries(qv_tests PRIVATE qv_core)
  add_test(NAME qv_nonce_test COMMAND qv_tests)
endif()
