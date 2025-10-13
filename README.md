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
or your preferred provider when moving beyond stubs.

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
    libssl-dev libsodium-dev liboqs-dev

# Configure with real crypto
cmake -S . -B build -GNinja -DQV_USE_STUB_CRYPTO=OFF
cmake --build build
```

#### macOS

```bash
brew install cmake ninja openssl libsodium liboqs

# Homebrew installs OpenSSL into /opt/homebrew/opt/openssl@3
cmake -S . -B build -GNinja -DQV_USE_STUB_CRYPTO=OFF \
      -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
cmake --build build
```

#### Windows (MSVC + vcpkg)

```powershell
vcpkg install openssl:x64-windows-static-md libsodium:x64-windows liboqs:x64-windows
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
      -DQV_USE_STUB_CRYPTO=OFF `
      -DCMAKE_TOOLCHAIN_FILE="${env:VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release
```

> liboqs is optional for now; when unavailable the build will continue with
> PQC stubs. The README's security notes call out the locations that must be
> revisited when swapping to production crypto providers.

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
