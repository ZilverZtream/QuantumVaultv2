cmake_minimum_required(VERSION 3.20)
project(QuantumVault VERSION 4.1.0 LANGUAGES CXX)

include(GNUInstallDirs) # TSK008_Build_System_Crypto_Wiring

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(QV_BUILD_TESTS "Build unit tests" ON)
option(QV_USE_STUB_CRYPTO "Use stub implementations for cryptography" OFF) # TSK008
option(QV_ENABLE_SANITIZERS "Enable address/undefined sanitizers" OFF) # TSK008
option(QV_FIPS_MODE "Enable FIPS 140-2/3 compliance mode" OFF) # TSK023_Production_Crypto_Provider_Complete_Integration

if (QV_FIPS_MODE AND QV_USE_STUB_CRYPTO)
  message(FATAL_ERROR "QV_FIPS_MODE requires production crypto; disable QV_USE_STUB_CRYPTO") # TSK023_Production_Crypto_Provider_Complete_Integration guard
endif()

if (MSVC)
  add_compile_options(/permissive- /W4 /EHsc /bigobj) # TSK016_Windows_Compatibility_Fixes
else()
  add_compile_options(-Wall -Wextra -Wpedantic) # TSK008
endif()

if (QV_ENABLE_SANITIZERS)
  if (MSVC)
    message(WARNING "Sanitizers are not currently supported on MSVC builds") # TSK008
  else()
    set(_qv_sanitizers "address,undefined")
    add_compile_options(-fsanitize=${_qv_sanitizers}) # TSK008
    add_link_options(-fsanitize=${_qv_sanitizers}) # TSK008
  endif()
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin) # TSK008
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib) # TSK008
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib) # TSK008

if (CMAKE_CONFIGURATION_TYPES)
  foreach(config ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${config} config_upper)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${config_upper} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${config_upper} ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${config_upper} ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})
  endforeach()
endif()

if (APPLE)
  set(CMAKE_INSTALL_RPATH "@loader_path/../${CMAKE_INSTALL_LIBDIR}") # TSK008
elseif(UNIX)
  set(CMAKE_INSTALL_RPATH "\$ORIGIN/../${CMAKE_INSTALL_LIBDIR}") # TSK008
endif()
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE) # TSK008

find_package(OpenSSL REQUIRED)
find_package(sodium QUIET) # TSK008
find_package(PkgConfig QUIET) # TSK035_Platform_Specific_Security_Integration
set(qv_have_libsecret OFF) # TSK035_Platform_Specific_Security_Integration
set(qv_have_tpm OFF)       # TSK035_Platform_Specific_Security_Integration
if (UNIX AND NOT APPLE AND PkgConfig_FOUND)
  pkg_check_modules(LIBSECRET QUIET libsecret-1)
  if (LIBSECRET_FOUND)
    set(qv_have_libsecret ON)
  endif()
  pkg_check_modules(TSS2 QUIET tss2-esys)
  if (TSS2_FOUND)
    set(qv_have_tpm ON)
  endif()
endif()

set(qv_have_sodium OFF)
set(qv_sodium_target "")
if (TARGET sodium::sodium)
  set(qv_have_sodium ON)
  set(qv_sodium_target sodium::sodium)
elseif(TARGET Sodium::Sodium)
  set(qv_have_sodium ON)
  set(qv_sodium_target Sodium::Sodium)
endif()

add_library(qv_core
    src/core/nonce.cpp
    src/core/nonce_log.cpp
    src/core/pqc_hybrid_kdf.cpp
    src/crypto/aes_gcm.cpp
    src/crypto/hmac_sha256.cpp
    src/crypto/provider.cpp
    src/crypto/sha256.cpp
    src/security/zeroizer.cpp
)
target_include_directories(qv_core
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
) # TSK008
target_link_libraries(qv_core PUBLIC OpenSSL::Crypto)
if (WIN32)
  target_link_libraries(qv_core PRIVATE bcrypt) # TSK016_Windows_Compatibility_Fixes
endif()
if (NOT QV_USE_STUB_CRYPTO AND qv_have_sodium)
  target_link_libraries(qv_core PRIVATE ${qv_sodium_target}) # TSK008
endif()
target_compile_definitions(qv_core
    PUBLIC
      QV_HAVE_OPENSSL=1 # TSK008
      $<$<BOOL:${QV_USE_STUB_CRYPTO}>:QV_USE_STUB_CRYPTO=1> # TSK008
      QV_HAVE_SODIUM=$<BOOL:$<AND:$<BOOL:${qv_have_sodium}>,$<NOT:$<BOOL:${QV_USE_STUB_CRYPTO}>>>> # TSK008
      $<$<BOOL:${QV_FIPS_MODE}>:QV_FIPS_MODE=1> # TSK023_Production_Crypto_Provider_Complete_Integration propagate FIPS mode
)

add_library(qv_orchestrator
    src/orchestrator/plugin_verification.cpp
    src/orchestrator/constant_time_mount.cpp
    src/orchestrator/plugin_manager.cpp
    src/orchestrator/volume_manager.cpp
    src/orchestrator/event_bus.cpp
)
target_include_directories(qv_orchestrator
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
) # TSK008
target_link_libraries(qv_orchestrator PUBLIC qv_core)
# TSK005 platform signature verification dependencies
if (WIN32)
  target_link_libraries(qv_orchestrator PRIVATE Wintrust Crypt32)
elseif(APPLE)
  target_link_libraries(qv_orchestrator PRIVATE "-framework Security" "-framework CoreFoundation")
endif()

add_executable(qv src/cli/main.cpp)
target_include_directories(qv
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
) # TSK008
target_link_libraries(qv PRIVATE qv_core qv_orchestrator)
if (WIN32)
  target_link_libraries(qv PRIVATE Crypt32) # TSK035_Platform_Specific_Security_Integration
elseif(APPLE)
  target_link_libraries(qv PRIVATE "-framework Security") # TSK035_Platform_Specific_Security_Integration
endif()
if (qv_have_libsecret)
  target_include_directories(qv PRIVATE ${LIBSECRET_INCLUDE_DIRS}) # TSK035_Platform_Specific_Security_Integration
  target_link_libraries(qv PRIVATE ${LIBSECRET_LIBRARIES})         # TSK035_Platform_Specific_Security_Integration
endif()
if (qv_have_tpm)
  target_include_directories(qv PRIVATE ${TSS2_INCLUDE_DIRS}) # TSK035_Platform_Specific_Security_Integration
  target_link_libraries(qv PRIVATE ${TSS2_LIBRARIES})         # TSK035_Platform_Specific_Security_Integration
endif()
target_compile_definitions(qv PRIVATE
    QV_HAVE_LIBSECRET=$<BOOL:${qv_have_libsecret}> # TSK035_Platform_Specific_Security_Integration
    QV_ENABLE_TPM_SEALING=$<BOOL:${qv_have_tpm}>   # TSK035_Platform_Specific_Security_Integration
)

# Plugins (examples)
add_library(qv_example_crypto MODULE plugins/example_crypto/example_crypto.cpp)
target_include_directories(qv_example_crypto
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
) # TSK008
target_compile_definitions(qv_example_crypto PRIVATE QV_PLUGIN_IMPLEMENTATION) # TSK016_Windows_Compatibility_Fixes
set_target_properties(qv_example_crypto PROPERTIES
    PREFIX ""  # cross-platform friendlier
    OUTPUT_NAME "qv_example_crypto"
)

add_library(qv_pqc_mlkem MODULE plugins/pqc_mlkem/pqc_mlkem.cpp)
target_include_directories(qv_pqc_mlkem
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
) # TSK008
target_compile_definitions(qv_pqc_mlkem PRIVATE QV_PLUGIN_IMPLEMENTATION) # TSK016_Windows_Compatibility_Fixes
set_target_properties(qv_pqc_mlkem PROPERTIES
    PREFIX ""
    OUTPUT_NAME "qv_pqc_mlkem"
)

# Tests
if(QV_BUILD_TESTS)
  enable_testing()
# ---------- Tests ----------
enable_testing()

  find_package(Threads REQUIRED) # TSK034

# Common test flags (TSK006)
function(qv_apply_test_opts tgt)
  if (MSVC)
    target_compile_options(${tgt} PRIVATE /O2 /GL)  # TSK006
    target_link_options(${tgt} PRIVATE /LTCG)       # TSK006
  else()
    target_compile_options(${tgt} PRIVATE -O3 -flto)  # TSK006
    target_link_options(${tgt} PRIVATE -flto)         # TSK006
  endif()
endfunction()

# Nonce test
  add_executable(qv_nonce_test_bin tests/test_nonce.cpp)
  target_include_directories(qv_nonce_test_bin PUBLIC include)
  target_link_libraries(qv_nonce_test_bin PRIVATE qv_core)
  qv_apply_test_opts(qv_nonce_test_bin)
  add_test(NAME qv_nonce_test COMMAND qv_nonce_test_bin)

  add_executable(qv_aad_test tests/test_aad.cpp) # TSK014
  target_include_directories(qv_aad_test PUBLIC include) # TSK014
  target_link_libraries(qv_aad_test PRIVATE qv_core) # TSK014
  qv_apply_test_opts(qv_aad_test) # TSK014
  add_test(NAME qv_aad_authentication COMMAND qv_aad_test) # TSK014

  add_executable(qv_error_handling_test tests/test_error_handling.cpp) # TSK034
  target_include_directories(qv_error_handling_test PUBLIC include) # TSK034
  target_link_libraries(qv_error_handling_test PRIVATE qv_core Threads::Threads) # TSK034
  if (UNIX AND NOT APPLE)
    target_link_libraries(qv_error_handling_test PRIVATE dl) # TSK034
  endif()
  qv_apply_test_opts(qv_error_handling_test) # TSK034
  add_test(NAME qv_error_handling COMMAND qv_error_handling_test) # TSK034

  add_executable(qv_concurrent_test tests/test_concurrent_mount.cpp) # TSK034
  target_include_directories(qv_concurrent_test PUBLIC include) # TSK034
  target_link_libraries(qv_concurrent_test PRIVATE qv_core Threads::Threads) # TSK034
  qv_apply_test_opts(qv_concurrent_test) # TSK034
  add_test(NAME qv_concurrent COMMAND qv_concurrent_test --threads=8) # TSK034

# Constant-time mount test (only if the source exists)
if (EXISTS "${CMAKE_SOURCE_DIR}/tests/test_constant_time_mount.cpp")
  add_executable(qv_constant_time_mount_test tests/test_constant_time_mount.cpp)
  target_include_directories(qv_constant_time_mount_test PUBLIC include)
  target_link_libraries(qv_constant_time_mount_test PRIVATE qv_core qv_orchestrator)
  qv_apply_test_opts(qv_constant_time_mount_test)
  add_test(NAME qv_constant_time_mount COMMAND qv_constant_time_mount_test)
endif()

  find_program(DUDECT_RUNNER dudect_runner)
  if (DUDECT_RUNNER)
    add_test(NAME constant_time_dudect
             COMMAND ${DUDECT_RUNNER} --test=mount_timing --samples=1000000
             WORKING_DIRECTORY ${CMAKE_BINARY_DIR}) # TSK022
  else()
    message(WARNING "dudect_runner not found; constant-time analysis skipped") # TSK022
  endif()

  add_custom_target(fuzz_tests COMMENT "Build fuzzing targets") # TSK030
  if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_executable(qv_fuzz_header tests/fuzz/fuzz_header_parser.cpp) # TSK030
    target_link_libraries(qv_fuzz_header PRIVATE qv_core qv_orchestrator) # TSK030
    target_compile_options(qv_fuzz_header PRIVATE -fsanitize=fuzzer,address) # TSK030
    target_link_options(qv_fuzz_header PRIVATE -fsanitize=fuzzer,address) # TSK030
    add_dependencies(fuzz_tests qv_fuzz_header) # TSK030
  endif()

endif()

# --- Wiring check gate ---
set(EXCLUDED_SOURCES "")
# Example whitelist:
# EXCLUDED_SOURCES += src/experimental/example.cpp

find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_custom_target(wiring-check
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/check_wiring.py
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME wiring-check COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/check_wiring.py)

install(TARGETS
    qv_core
    qv_orchestrator
    qv
    qv_example_crypto
    qv_pqc_mlkem
    EXPORT QuantumVaultTargets # TSK008
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}) # TSK008

install(EXPORT QuantumVaultTargets
    NAMESPACE qv::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/QuantumVault
) # TSK008
