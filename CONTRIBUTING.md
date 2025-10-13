<!-- TSK020 -->
# Contributing Guide

Thanks for improving QuantumVault! This document summarizes the workflow and
house style enforced by CI.

## Development workflow

1. Fork the repository and create a topic branch per task (e.g., `TSK020_error-docs`).
2. Configure the project:
   ```bash
   cmake -S . -B build -GNinja -DQV_USE_STUB_CRYPTO=OFF # enable real crypto when available
   cmake --build build
   ```
3. Run unit tests and wiring checks before sending a PR:
   ```bash
   ctest --test-dir build
   python tools/check_wiring.py
   ```
4. Reference the tracker ID (e.g., `// TSK020`) in code comments touching the
task scope.

## Coding style

- The repository ships a `.clang-format` based on LLVM style with a 100 column
  limit. Apply it before committing:
  ```bash
  clang-format -i $(git ls-files '*.[ch]pp' '*.h' '*.cc')
  ```
- Prefer RAII helpers over raw `new/delete` and avoid exceptions for control
  flow.
- Keep code portable across MSVC, Clang, and GCC.

## Lint and CI

- `tools/check_wiring.py` validates dependency layering and must pass.
- CI runs `clang-format --dry-run` against `.clang-format`; patches that fail
  formatting will be rejected.
- Security-sensitive changes should update `SECURITY.md`/`THREATMODEL.md` with
  the rationale.

## Commit structure

- Use conventional subject lines (`Component: summary`).
- Keep commits focused; split refactors from behavioral changes.
- Include testing notes in the PR description so reviewers can reproduce.
