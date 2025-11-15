cmake_minimum_required(VERSION 3.20)
project(QuantumVault VERSION 4.1.0 LANGUAGES CXX)

include(GNUInstallDirs) # TSK008_Build_System_Crypto_Wiring

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(QV_BUILD_TESTS "Build unit tests" ON)
option(QV_USE_STUB_CRYPTO "Use stub implementations for cryptography" OFF) # TSK008
set(_QV_ENABLE_SANITIZERS_DEFAULT OFF)
if (NOT MSVC)
  set(_QV_ENABLE_SANITIZERS_DEFAULT ON)
endif()
option(QV_ENABLE_SANITIZERS "Enable address/undefined sanitizers" ${_QV_ENABLE_SANITIZERS_DEFAULT}) # TSK039_Static_Analysis_and_CI_Quality_Gates default Linux/macOS sanitizers
option(QV_ENABLE_COVERAGE "Enable coverage instrumentation" OFF) # TSK039_Static_Analysis_and_CI_Quality_Gates
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
    message(WARNING "Sanitizers are not currently supported on MSVC builds") # TSK039_Static_Analysis_and_CI_Quality_Gates guard
  else()
    set(_qv_sanitizers "address,undefined")
    add_compile_options(-fsanitize=${_qv_sanitizers}) # TSK039_Static_Analysis_and_CI_Quality_Gates instrumentation
    add_link_options(-fsanitize=${_qv_sanitizers}) # TSK039_Static_Analysis_and_CI_Quality_Gates instrumentation
  endif()
endif()

if (QV_ENABLE_COVERAGE)
  if (MSVC)
    message(WARNING "Coverage instrumentation is not currently supported on MSVC builds; disabling") # TSK039_Static_Analysis_and_CI_Quality_Gates portability guard
    set(QV_ENABLE_COVERAGE OFF CACHE BOOL "Enable coverage instrumentation" FORCE)
  else()
    add_compile_options(--coverage) # TSK039_Static_Analysis_and_CI_Quality_Gates instrumentation
    add_link_options(--coverage) # TSK039_Static_Analysis_and_CI_Quality_Gates instrumentation
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
find_path(ZSTD_INCLUDE_DIR zstd.h) # TSK127_Incorrect_Filesystem_Metadata_Recovery locate headers
find_library(ZSTD_LIBRARY NAMES zstd libzstd zstd_static) # TSK127_Incorrect_Filesystem_Metadata_Recovery locate library
if (NOT ZSTD_INCLUDE_DIR OR NOT ZSTD_LIBRARY)
  message(FATAL_ERROR "libzstd (zstd.h) is required for TSK127_Incorrect_Filesystem_Metadata_Recovery")
endif()
if (NOT TARGET ZSTD::ZSTD)
  add_library(ZSTD::ZSTD UNKNOWN IMPORTED)
  set_target_properties(ZSTD::ZSTD PROPERTIES
      IMPORTED_LOCATION ${ZSTD_LIBRARY}
      INTERFACE_INCLUDE_DIRECTORIES ${ZSTD_INCLUDE_DIR})
endif()
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

find_path(ARGON2_INCLUDE_DIR argon2.h) # TSK036_PBKDF2_Argon2_Migration_Path locate headers
find_library(ARGON2_LIBRARY argon2)    # TSK036_PBKDF2_Argon2_Migration_Path locate library
if (NOT ARGON2_INCLUDE_DIR OR NOT ARGON2_LIBRARY)
  message(FATAL_ERROR "libargon2 (argon2.h) is required for TSK036_PBKDF2_Argon2_Migration_Path")
endif()

set(qv_have_liboqs OFF) # TSK942_PQC_Liboqs_Optional_Build
find_path(LIBOQS_INCLUDE_DIR oqs/oqs.h)
find_library(LIBOQS_LIBRARY oqs)
if (LIBOQS_INCLUDE_DIR AND LIBOQS_LIBRARY)
  set(qv_have_liboqs ON)
else()
  # TSK801_CI_Build_Integrity_Gaps: block release builds without PQC support
  if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    message(FATAL_ERROR "liboqs is required for Release and RelWithDebInfo builds to ensure PQC support; install liboqs or use Debug build type")
  else()
    message(STATUS "liboqs not found; PQC hybrid KDF will be disabled at runtime") # TSK942_PQC_Liboqs_Optional_Build status hint
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
    src/core/header_io.cpp # TSK712_Header_Backup_and_Restore_Tooling header backup plumbing
    src/core/nonce.cpp
    src/core/nonce_log.cpp
    src/core/pqc_hybrid_kdf.cpp
    src/core/header.cpp # TSK710_Implement_Hidden_Volumes hidden descriptor verification
    src/core/integrity.cpp # TSK715_Header_Integrity_Chain_and_qv-fsck metadata Merkle chain
    src/crypto/aegis.cpp
    src/crypto/aes_gcm.cpp
    src/crypto/hkdf.cpp
    src/crypto/hmac_sha256.cpp
    src/crypto/pbkdf2.cpp # TSK111_Code_Duplication_and_Maintainability shared PBKDF2 implementation
    src/crypto/random.cpp
    src/crypto/provider.cpp
    src/crypto/sha256.cpp
    src/crypto/keyfiles.cpp # TSK711_Keyfiles_and_PKCS11_FIDO2 keyfile hashing support
    src/security/zeroizer.cpp
    src/platform/memory_lock.cpp # TSK718_AutoLock_and_MemoryLocking sensitive memory wrappers
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
if (NOT QV_USE_STUB_CRYPTO AND qv_have_liboqs)
  target_include_directories(qv_core PRIVATE ${LIBOQS_INCLUDE_DIR}) # TSK942_PQC_Liboqs_Optional_Build include real PQC headers
  target_link_libraries(qv_core PRIVATE ${LIBOQS_LIBRARY}) # TSK942_PQC_Liboqs_Optional_Build link liboqs when available
endif()
target_compile_definitions(qv_core
    PUBLIC
      QV_HAVE_OPENSSL=1 # TSK008
      $<$<BOOL:${QV_USE_STUB_CRYPTO}>:QV_USE_STUB_CRYPTO=1> # TSK008
      QV_HAVE_SODIUM=$<BOOL:$<AND:$<BOOL:${qv_have_sodium}>,$<NOT:$<BOOL:${QV_USE_STUB_CRYPTO}>>>> # TSK008
      QV_HAVE_LIBOQS=$<BOOL:${qv_have_liboqs}> # TSK942_PQC_Liboqs_Optional_Build propagate PQC availability
      $<$<BOOL:${QV_FIPS_MODE}>:QV_FIPS_MODE=1> # TSK023_Production_Crypto_Provider_Complete_Integration propagate FIPS mode
)

add_library(qv_storage
    src/storage/block_device.cpp
    src/storage/chunk_cache.cpp
    src/storage/chunk_manager.cpp
    src/storage/read_ahead.cpp
)
target_include_directories(qv_storage
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(qv_storage PUBLIC qv_core)

add_library(qv_orchestrator
    src/orchestrator/plugin_verification.cpp
    src/orchestrator/constant_time_mount.cpp
    src/orchestrator/ipc_lock.cpp
    src/orchestrator/plugin_manager.cpp
    src/orchestrator/volume_manager.cpp
    src/orchestrator/password_policy.cpp
    src/orchestrator/io_util.cpp # TSK068_Atomic_Header_Writes durability helper
    src/orchestrator/event_bus.cpp
    src/orchestrator/credentials.cpp # TSK711_Keyfiles_and_PKCS11_FIDO2 credential combiner
    src/orchestrator/sealed_key.cpp # TSK713_TPM_SecureEnclave_Key_Sealing provider registry
    src/orchestrator/session.cpp # TSK718_AutoLock_and_MemoryLocking idle auto-lock session wiring
    src/tlv/parser.cpp # TSK111_Code_Duplication_and_Maintainability reusable TLV parser
)
target_include_directories(qv_orchestrator
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
) # TSK008
target_link_libraries(qv_orchestrator PUBLIC qv_core ${ARGON2_LIBRARY})
target_include_directories(qv_orchestrator PRIVATE ${ARGON2_INCLUDE_DIR}) # TSK036_PBKDF2_Argon2_Migration_Path headers
target_compile_definitions(qv_orchestrator PUBLIC QV_HAVE_ARGON2=1)       # TSK036_PBKDF2_Argon2_Migration_Path flag
# TSK005 platform signature verification dependencies
if (WIN32)
  target_link_libraries(qv_orchestrator PRIVATE Wintrust Crypt32 Dnsapi Ws2_32) # TSK901_Security_Hardening socket deps
elseif(APPLE)
  target_link_libraries(qv_orchestrator PRIVATE "-framework Security" "-framework CoreFoundation")
endif()

add_executable(qv
    src/cli/main.cpp
    src/platform/win/tpm.cpp # TSK713_TPM_SecureEnclave_Key_Sealing DPAPI provider
    src/platform/macos/se.cpp # TSK713_TPM_SecureEnclave_Key_Sealing Secure Enclave provider
)
target_include_directories(qv
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
) # TSK008
target_link_libraries(qv PRIVATE qv_core qv_orchestrator qv_storage)
target_link_libraries(qv PRIVATE ZSTD::ZSTD) # TSK127_Incorrect_Filesystem_Metadata_Recovery link compression runtime
if (WIN32)
  target_link_libraries(qv PRIVATE Crypt32) # TSK035_Platform_Specific_Security_Integration
  find_path(WINFSP_INCLUDE_DIR winfsp/winfsp.h
            PATHS "C:/Program Files (x86)/WinFsp/inc" "C:/Program Files/WinFsp/inc")
  find_library(WINFSP_LIBRARY winfsp-x64
               PATHS "C:/Program Files (x86)/WinFsp/lib" "C:/Program Files/WinFsp/lib")

  if (WINFSP_INCLUDE_DIR AND WINFSP_LIBRARY)
    target_compile_definitions(qv PRIVATE QV_HAVE_WINFSP=1)
    target_include_directories(qv PRIVATE ${WINFSP_INCLUDE_DIR})
    target_sources(qv PRIVATE
      src/platform/winfsp_adapter.cpp
      src/platform/volume_filesystem.cpp)
    target_link_libraries(qv PRIVATE ${WINFSP_LIBRARY})

    add_executable(qv.winfsp
      src/platform/winfsp_adapter.cpp
      src/platform/volume_filesystem.cpp)
    target_include_directories(qv.winfsp PRIVATE
      ${WINFSP_INCLUDE_DIR}
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)
    target_link_libraries(qv.winfsp PRIVATE
      qv_core
      qv_orchestrator
      qv_storage
      ZSTD::ZSTD # TSK127_Incorrect_Filesystem_Metadata_Recovery ensure compression available
      ${WINFSP_LIBRARY})
    target_compile_definitions(qv.winfsp PRIVATE QV_HAVE_WINFSP=1)
  else()
    message(WARNING "WinFsp SDK not found; WinFsp integration disabled")
  endif()
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

add_executable(qv-header tools/qv-header.cpp) # TSK712_Header_Backup_and_Restore_Tooling standalone helper
target_include_directories(qv-header
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(qv-header PRIVATE qv_core ${ARGON2_LIBRARY})
target_include_directories(qv-header PRIVATE ${ARGON2_INCLUDE_DIR})

add_executable(qv-fsck tools/qv-fsck.cpp) # TSK715_Header_Integrity_Chain_and_qv-fsck metadata audit CLI
target_include_directories(qv-fsck
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(qv-fsck PRIVATE qv_core)

# TSK062_FUSE_Filesystem_Integration_Linux build the Linux FUSE bridge when dependencies are present
if (UNIX)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(FUSE3 REQUIRED fuse3)

  add_executable(qv.fuse
    src/platform/fuse_adapter.cpp
    src/platform/volume_filesystem.cpp)
  target_include_directories(qv.fuse PRIVATE
    ${FUSE3_INCLUDE_DIRS}
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)
  target_compile_options(qv.fuse PRIVATE ${FUSE3_CFLAGS_OTHER})
  target_link_directories(qv.fuse PRIVATE ${FUSE3_LIBRARY_DIRS})
  target_link_libraries(qv.fuse PRIVATE
    qv_core
    qv_orchestrator
    qv_storage
    ZSTD::ZSTD # TSK127_Incorrect_Filesystem_Metadata_Recovery ensure fuse binary links zstd
    ${FUSE3_LIBRARIES})
endif()

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

  add_executable(qv_chunk_auth_test tests/test_chunk_auth.cpp) # TSK040_AAD_Binding_and_Chunk_Authentication
  target_include_directories(qv_chunk_auth_test PUBLIC include) # TSK040
  target_link_libraries(qv_chunk_auth_test PRIVATE qv_core) # TSK040
  qv_apply_test_opts(qv_chunk_auth_test) # TSK040
  add_test(NAME qv_chunk_auth COMMAND qv_chunk_auth_test) # TSK040

  add_executable(qv_chunk_manager_test tests/test_chunk_manager.cpp) # TSK061_Block_Device_and_Chunk_Storage_Engine
  target_include_directories(qv_chunk_manager_test PUBLIC include)
  target_link_libraries(qv_chunk_manager_test PRIVATE qv_storage)
  qv_apply_test_opts(qv_chunk_manager_test)
  add_test(NAME qv_chunk_manager COMMAND qv_chunk_manager_test)

  add_executable(qv_storage_bench tests/benchmark/bench_performance.cpp) # TSK064_Performance_Optimization_and_Caching
  target_include_directories(qv_storage_bench PUBLIC include)
  target_link_libraries(qv_storage_bench PRIVATE qv_storage)
  qv_apply_test_opts(qv_storage_bench)

  add_executable(qv_error_handling_test tests/test_error_handling.cpp) # TSK034
  target_include_directories(qv_error_handling_test PUBLIC include) # TSK034
  target_link_libraries(qv_error_handling_test PRIVATE qv_core Threads::Threads) # TSK034
  if (UNIX AND NOT APPLE)
    target_link_libraries(qv_error_handling_test PRIVATE dl) # TSK034
  endif()
  qv_apply_test_opts(qv_error_handling_test) # TSK034
  add_test(NAME qv_error_handling COMMAND qv_error_handling_test) # TSK034

  add_executable(qv_session_test tests/test_session.cpp) # TSK718_AutoLock_and_MemoryLocking
  target_include_directories(qv_session_test PUBLIC include)
  target_link_libraries(qv_session_test PRIVATE qv_orchestrator)
  qv_apply_test_opts(qv_session_test)
  add_test(NAME qv_session_idle COMMAND qv_session_test)

  add_executable(qv_memory_lock_test tests/test_memory_lock.cpp) # TSK718_AutoLock_and_MemoryLocking
  target_include_directories(qv_memory_lock_test PUBLIC include)
  target_link_libraries(qv_memory_lock_test PRIVATE qv_core)
  qv_apply_test_opts(qv_memory_lock_test)
  add_test(NAME qv_memory_lock COMMAND qv_memory_lock_test)

  add_executable(qv_header_io_test tests/test_header_io.cpp) # TSK712_Header_Backup_and_Restore_Tooling
  target_include_directories(qv_header_io_test PUBLIC include)
  target_link_libraries(qv_header_io_test PRIVATE qv_core ${ARGON2_LIBRARY})
  target_include_directories(qv_header_io_test PRIVATE ${ARGON2_INCLUDE_DIR})
  qv_apply_test_opts(qv_header_io_test)
  add_test(NAME qv_header_io COMMAND qv_header_io_test)

  add_executable(qv_concurrent_test tests/test_concurrent_mount.cpp) # TSK034
  target_include_directories(qv_concurrent_test PUBLIC include) # TSK034
  target_link_libraries(qv_concurrent_test PRIVATE qv_core Threads::Threads) # TSK034
  qv_apply_test_opts(qv_concurrent_test) # TSK034
  add_test(NAME qv_concurrent COMMAND qv_concurrent_test --threads=8) # TSK034

  if (UNIX)
    add_executable(qv_hidden_volume_test
      tests/test_hidden_volume.cpp
      src/platform/volume_filesystem.cpp) # TSK710_Implement_Hidden_Volumes guard regression
    target_include_directories(qv_hidden_volume_test PRIVATE
      include
      ${FUSE3_INCLUDE_DIRS})
    target_compile_options(qv_hidden_volume_test PRIVATE ${FUSE3_CFLAGS_OTHER})
    target_link_directories(qv_hidden_volume_test PRIVATE ${FUSE3_LIBRARY_DIRS})
    target_link_libraries(qv_hidden_volume_test PRIVATE
      qv_storage
      qv_core
      ZSTD::ZSTD
      ${FUSE3_LIBRARIES})
    qv_apply_test_opts(qv_hidden_volume_test)
    add_test(NAME qv_hidden_volume COMMAND qv_hidden_volume_test)
  endif()

# Constant-time mount test (only if the source exists)
if (EXISTS "${CMAKE_SOURCE_DIR}/tests/test_constant_time_mount.cpp")
  add_executable(qv_constant_time_mount_test tests/test_constant_time_mount.cpp)
  target_include_directories(qv_constant_time_mount_test PUBLIC include)
  target_link_libraries(qv_constant_time_mount_test PRIVATE qv_core qv_orchestrator)
  qv_apply_test_opts(qv_constant_time_mount_test)
  add_test(NAME qv_constant_time_mount COMMAND qv_constant_time_mount_test)
endif()

if (EXISTS "${CMAKE_SOURCE_DIR}/tests/test_volume_rekey.cpp")
  add_executable(qv_volume_rekey_test tests/test_volume_rekey.cpp) # TSK071_Epoch_Overflow_Safety coverage
  target_include_directories(qv_volume_rekey_test PUBLIC include)
  target_link_libraries(qv_volume_rekey_test PRIVATE qv_orchestrator qv_core)
  qv_apply_test_opts(qv_volume_rekey_test)
  add_test(NAME qv_volume_rekey COMMAND qv_volume_rekey_test)
endif()

if (EXISTS "${CMAKE_SOURCE_DIR}/tests/test_io_util.cpp")
  add_executable(qv_io_util_test tests/test_io_util.cpp) # TSK068_Atomic_Header_Writes durability regression
  target_include_directories(qv_io_util_test PUBLIC include)
  target_link_libraries(qv_io_util_test PRIVATE qv_orchestrator)
  qv_apply_test_opts(qv_io_util_test)
  add_test(NAME qv_io_util COMMAND qv_io_util_test)
endif()

  find_program(DUDECT_RUNNER dudect_runner)
  if (DUDECT_RUNNER)
    add_test(NAME constant_time_dudect
             COMMAND ${DUDECT_RUNNER} --test=mount_timing --samples=1000000
             WORKING_DIRECTORY ${CMAKE_BINARY_DIR}) # TSK022
  else()
    # TSK801_CI_Build_Integrity_Gaps: fail in CI/release builds to ensure constant-time validation
    if (DEFINED ENV{CI} OR CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
      message(FATAL_ERROR "dudect_runner is required for CI and release builds to validate constant-time cryptography; install dudect via pip")
    else()
      message(WARNING "dudect_runner not found; constant-time analysis skipped") # TSK022
    endif()
  endif()

  add_custom_target(fuzz_tests COMMENT "Build fuzzing targets") # TSK030
  if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_executable(qv_fuzz_header tests/fuzz/fuzz_header_parser.cpp) # TSK030
    target_link_libraries(qv_fuzz_header PRIVATE qv_core qv_orchestrator) # TSK030
    target_compile_options(qv_fuzz_header PRIVATE -fsanitize=fuzzer,address) # TSK030
    target_link_options(qv_fuzz_header PRIVATE -fsanitize=fuzzer,address) # TSK030
    add_dependencies(fuzz_tests qv_fuzz_header) # TSK030

    add_executable(qv_fuzz_header_backup tests/fuzz/fuzz_header_backup.cpp) # TSK712_Header_Backup_and_Restore_Tooling backup bundle fuzz target
    target_link_libraries(qv_fuzz_header_backup PRIVATE qv_core) # TSK712_Header_Backup_and_Restore_Tooling core-only dependency
    target_compile_options(qv_fuzz_header_backup PRIVATE -fsanitize=fuzzer,address) # TSK712_Header_Backup_and_Restore_Tooling sanitizer coverage
    target_link_options(qv_fuzz_header_backup PRIVATE -fsanitize=fuzzer,address) # TSK712_Header_Backup_and_Restore_Tooling sanitizer coverage
    add_dependencies(fuzz_tests qv_fuzz_header_backup) # TSK712_Header_Backup_and_Restore_Tooling aggregate build hook
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
    qv_storage
    qv_orchestrator
    qv
    qv-header
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
