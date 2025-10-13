# CODEX — Rules for Code-Generating Agents

This sets **non-negotiable rules** for any AI/agent (“Codex”) generating code or patches.

## Definition of Done (DoD)
A change is **done** only if ALL are true:
1. **Wired**: New source files are referenced by a build target (CMake). No dead files.
2. **Tests**: Unit tests exist (or are explicitly marked `NO_TESTS_JUSTIFIED` with rationale) and **pass**.
3. **Docs**: Relevant docs updated (README, API headers, or ADR).
4. **Tasks**: PR title starts with `TSK###_Name` and the PR body lists issues solved.
5. **Compat**: Windows/Linux/macOS builds are green in CI.

## Patch Requirements
- **Integration/Wiring Plan** in the PR: how it compiles and is invoked.
- **CMake**: add new files to targets. If intentionally not compiled yet, mark with  
  `// TODO(INTENTIONAL_DEAD: TSK###)` and whitelist it (see wiring linter).
- **Tests**: add/extend tests in `tests/`; include at least one **negative** test for security code.
- **Changelog**: summarize externally visible changes.

## Lint & Wiring Gate
CI runs `tools/check_wiring.py`. It **fails** if any `.c/.cpp` under `src/` or `plugins/` isn’t referenced by a CMake target (unless whitelisted).

## Commit Message Format


TSK123_Component: short description

Why

What

How to verify

Risk/rollback


## Prohibited Behaviors
- Creating files without wiring them into a target.
- Skipping tests without justification.
- Silent API changes.
- Claiming “tests passed” if CI didn’t run.

## Quick Self-Check (Agent)
- [ ] Did I add files to `CMakeLists.txt`?
- [ ] Do tests cover success & failure paths?
- [ ] Did I update docs and include a Wiring Plan?
- [ ] Does `cmake --build build && ctest` pass locally?
