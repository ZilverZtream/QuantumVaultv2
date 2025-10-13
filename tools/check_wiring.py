#!/usr/bin/env python3
# Fails if there are source files under src/ or plugins/ not referenced by CMakeLists.txt.
# Whitelist by adding a line in CMake:  EXCLUDED_SOURCES += relative/path.cpp

import sys, re, pathlib

repo = pathlib.Path(__file__).resolve().parents[1]
cmake = (repo / "CMakeLists.txt").read_text(encoding="utf-8", errors="ignore")

# Heuristic: find tokens that look like src/...cpp or plugins/...cpp in CMake
refs = re.findall(r'(src/[\w\/\.-]+\.(?:cpp|c))|(\splugins/[\w\/\.-]+\.(?:cpp|c))', cmake)
referenced = set()
for a, b in refs:
    if a: referenced.add(a.strip())
    if b: referenced.add(b.strip())

# Collect whitelisted exclusions
excluded = set(re.findall(r'EXCLUDED_SOURCES\s*\+=\s*([\w\-/\.]+)', cmake))

# Walk tree for actual sources
actual = set()
for base in ("src", "plugins"):
    for p in (repo / base).rglob("*"):
        if p.suffix.lower() in (".c", ".cpp"):
            actual.add(p.relative_to(repo).as_posix())

dead = sorted([a for a in actual if a not in referenced and a not in excluded])

if dead:
    print("ERROR: Unwired source files detected:")
    for d in dead:
        print(f"  - {d}")
    print("\nAdd them to a CMake target or whitelist via: EXCLUDED_SOURCES +=", dead[0])
    sys.exit(2)
else:
    print("WIRING OK: All source files are referenced in CMake.")
