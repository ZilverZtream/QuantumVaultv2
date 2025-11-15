# QuantumVault — C++ Edition

Security-first encrypted filesystem with plugin architecture.

This repository is an **enhanced skeleton** that wires together the major
subsystems described in the developer specification, with production-style
folder layout, build system, example code implemented, and stubs for the rest.

## Highlights

- C++20 project, CMake build
- Layered architecture: **core**, **orchestrator**, **plugins**, **SDK/ABI**
- Security-hardened fixes from v4.1:
  - Deterministic monotonic **GCM IV** construction with crash‑safe nonce log
  - Correct **PQC hybrid KEM flow** (encapsulate/decapsulate, store KEM ct)
  - Plugin verification standardized on **SHA‑256 + Ed25519** (stubs wired)
  - Constant-time targets relaxed to ±2ms (p99), timing padding included
  - Zeroization simplified to **single pass** (avoid cargo-cult multi-pass)
- CLI demo (`qv`) with `create`, `mount`, and `migrate-nonces` commands

> This codebase is intentionally **incomplete**: complex parts are implemented
> as **compilable stubs** ready to be filled in. The goal is to give you a
> strong starting point aligned to the spec with clear TODOs.

## Build

```bash
# Linux/macOS
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# Windows (MSVC)
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Dependencies: a modern compiler with C++20. Crypto primitives are **stubbed** to
keep the skeleton buildable without extra libraries; swap them with OpenSSL/libsodium
or your preferred provider when moving beyond stubs. Platform credential storage hooks
depend on native SDKs (`libsecret-1` on Linux, macOS Keychain, Windows DPAPI) and the
optional TPM sealing path uses `tpm2-tss`. These are detected automatically when the
development headers are present. <!-- TSK035_Platform_Specific_Security_Integration -->

## Production Deployment

<!-- // TSK031 -->
### Memory Locking

QuantumVault hardens in-memory key material by calling `mlock()` (or `VirtualLock` on
Windows) through `SecureBuffer`. Production deployments should ensure the process is
permitted to lock at least **128 MiB** of RAM and, when possible, pin all current and
future allocations:

```bash
# Allow 128 MiB of locked memory for the current shell
ulimit -l 131072

# Or grant the binary CAP_IPC_LOCK so it can raise RLIMIT_MEMLOCK itself
sudo setcap cap_ipc_lock=+ep /path/to/qv

# Optional: pin the entire address space once at startup
QV_USE_MLOCKALL=1 ./qv --args
```

At runtime, `SecureBuffer` emits warnings if per-chunk `mlock()` calls fail. Use
`SecureBuffer::RequireLocking()` to enforce that buffers throw on initialization if any
chunk cannot be pinned. You can confirm the amount of locked memory via:

```bash
cat /proc/$(pidof qv)/status | grep VmLck
```

<!-- TSK020 -->
### Production crypto backends

QuantumVault links against OpenSSL for classical primitives and can consume
libsodium/liboqs when the stubs are disabled. Use the following platform notes to
wire in real providers:

#### Linux

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build pkg-config \
    libssl-dev libsodium-dev liboqs-dev libsecret-1-dev tpm2-tss-dev

# Configure with real crypto
cmake -S . -B build -GNinja -DQV_USE_STUB_CRYPTO=OFF
cmake --build build
```

#### macOS

```bash
brew install cmake ninja openssl libsodium liboqs

# Optional: TPM and libsecret bindings for credential persistence <!-- TSK035_Platform_Specific_Security_Integration -->
brew install tpm2-tss libsecret

# Homebrew installs OpenSSL into /opt/homebrew/opt/openssl@3
cmake -S . -B build -GNinja -DQV_USE_STUB_CRYPTO=OFF \
      -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
cmake --build build
```

#### Windows (MSVC + vcpkg)

```powershell
vcpkg install openssl:x64-windows-static-md libsodium:x64-windows liboqs:x64-windows
vcpkg install tpm2-tss:x64-windows # optional TPM sealing support <!-- TSK035_Platform_Specific_Security_Integration -->
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
      -DQV_USE_STUB_CRYPTO=OFF `
      -DCMAKE_TOOLCHAIN_FILE="${env:VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release
```

> <!-- // TSK942_PQC_Liboqs_Optional_Build -->
> When `oqs/oqs.h` or `liboqs` are not detected, CMake emits a status line and
> compiles the tree with PQC hybrid KDFs disabled. Any attempt to create or
> mount PQC-enabled volumes at runtime fails with a configuration error so the
> rest of the codebase can still be analyzed and tested.

<!-- TSK035_Platform_Specific_Security_Integration -->
### Platform credential integration

`qv` can persist derived credentials into the host's secure storage to avoid
writing plaintext secrets to disk:

- `--keychain` stores volume secrets in the OS store (Windows DPAPI, macOS
  Keychain, or the Linux Secret Service via libsecret).
- `--tpm-seal` seals credentials to TPM PCR 7 using `tpm2-tss`, writing the
  sealed blob into the container metadata directory.

When both flags are present the TPM output is written alongside the OS
credential. The TPM flow requires a functional resource manager; on systems
without a TPM the command exits with a security error.

For SELinux deployments the policy stub at `contrib/selinux/qv.te` grants the
minimal capabilities needed for TPM access and credential caching inside user
directories.

<!-- TSK712_Header_Backup_and_Restore_Tooling -->
### Header backup and recovery tooling

QuantumVault provides dedicated commands for exporting an encrypted copy of a
container header. The primary CLI exposes a guarded workflow:

```text
qv header --container=<container> --backup=<file>
qv header --container=<container> --restore=<file>
qv header --inspect=<file>
```

Backups are sealed using a recovery password-derived key and contain KDF
parameters, header UUID, and versioning metadata so future releases can perform
strict compatibility checks during restore.

The standalone `qv-header` utility offers non-interactive flows:

```text
qv-header backup --container=<container> --out=<file> [--password-file=<file>]
qv-header restore --container=<container> --in=<file> [--password-file=<file>]
qv-header inspect --in=<file>
```

> **Warning:** Store the backup file and the recovery password separately from
> the container to avoid a single point of compromise.

## Project Layout

```text
include/           Public headers
src/               Implementations
plugins/           Example plugin scaffolding
tests/             Unit test skeleton (CTest)
cli/               Simple CLI entrypoint
.github/workflows/ CI (Linux/Windows/macOS matrix)
```

## Security Notes

- This skeleton contains real *interfaces* and *verified control flows* for:
  - Nonce generation with **epoch || counter**, durability via append-only MAC chain
  - PQC hybrid KDF using **ML-KEM-768** ciphertext stored in header TLV (stub sizes)
  - Plugin verification using **SHA-256** hashing and **Ed25519** signature check (stub)
  - Constant-time mount workflow with **timing padding**
- Replace the stub crypto with vetted implementations before production use.

## License

Apache-2.0. See `LICENSE`.
