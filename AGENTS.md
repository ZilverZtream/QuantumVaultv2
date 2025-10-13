# AGENTS — Operating Rules for Automation

1. **Respect the Task**: Only implement issues in the task. Scope creep → new task.
2. **Traceability**: Reference `TSK###_Name` in PR title and in touched files (`// TSK###`).
3. **Wiring Required**: New code must compile in the build, or be explicitly whitelisted with rationale.
4. **Portable by Default**: Must compile on Windows/MSVC, Linux/Clang, macOS/Clang.
5. **Security Stubs**: Guard stubs with `#if QV_USE_STUB_CRYPTO` and document migration.
6. **Reproducibility**: Document deps in README and CMake.
7. **Testing Discipline**: Add tests or justify deferral; never state “Passed” if CI skipped.

## PR Checklist
- [ ] Title: `TSK###_Name: concise summary`
- [ ] **Wiring Plan** included
- [ ] CMake/CI updated
- [ ] Tests added/updated
- [ ] Docs updated (README/CODEX/AGENTS/SECURITY if relevant)

## Suggested Bot Commands
- `/wiring-check` — run wiring linter and post summary
- `/security-diff` — list touched security-sensitive files
- `/todo-scan` — list `TODO(INTENTIONAL_DEAD)` items with owners
<!-- // TSK000 -->
