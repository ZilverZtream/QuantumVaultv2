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
