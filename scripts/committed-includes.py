#!/usr/bin/env python3
"""Every file the build reads at compile time is committed to git.

`include_str!` and `include_bytes!` are resolved by the compiler, relative to the file
doing the including. A target that exists on the author's machine and is not in git builds
for them and for nobody else — and the failure is not subtle once it happens, it is
`couldn't read ...: No such file or directory` on a clean checkout.

That happened. `crates/uops-oui/data/assignments.tsv` is the IEEE MAC-assignment table,
1.7 MB, and its own README has a section headed *"Why this is committed rather than
downloaded"* — an air-gapped build cannot fetch it. A blanket `*.tsv` rule in `.gitignore`,
written for benchmark artefacts, quietly caught it, so it was never committed. Three CI jobs
— Clippy, the RustCrypto build, and the sqlx metadata check — failed on every push for as
long as that crate has existed, and the fourth failed for its own reason, which is how four
red jobs became scenery nobody read.

    python scripts/committed-includes.py
    python scripts/committed-includes.py --self-test

This is the cheap guard for that: it costs a `git ls-files` and it is the difference between
finding this in a second and finding it in a CI log nobody is reading.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

INCLUDE = re.compile(r'include_(?:str|bytes)!\s*\(\s*"([^"]+)"\s*\)')


def tracked_files(root: Path) -> set[str]:
    """Everything git has, as repo-relative POSIX paths."""
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {p for p in out.split("\0") if p}


def includes(root: Path) -> list[tuple[Path, int, str, Path]]:
    """Every include and where it resolves to, as (source, line, raw target, resolved)."""
    found = []
    for rs in sorted((root / "crates").rglob("*.rs")):
        text = rs.read_text(encoding="utf-8", errors="replace")
        for n, line in enumerate(text.split("\n"), 1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "///", "//!", "*")):
                continue                      # prose about an include is not one
            for m in INCLUDE.finditer(line):
                raw = m.group(1)
                # Resolved the way rustc does: relative to the including file's directory.
                resolved = (rs.parent / raw).resolve()
                found.append((rs, n, raw, resolved))
    return found


def check(root: Path) -> int:
    root = root.resolve()
    tracked = tracked_files(root)
    found = includes(root)
    if not found:
        print("no include_str!/include_bytes! found, which is itself suspicious")
        return 1

    missing, ok = [], 0
    for src, line, raw, resolved in found:
        try:
            rel = resolved.relative_to(root).as_posix()
        except ValueError:
            missing.append((src, line, raw, "resolves outside the repository"))
            continue
        if rel in tracked:
            ok += 1
        elif not resolved.exists():
            missing.append((src, line, raw, f"{rel} does not exist"))
        else:
            missing.append((src, line, raw, f"{rel} exists locally but is NOT in git"))

    for src, line, raw, why in missing:
        print(f"FAIL  {src.relative_to(root).as_posix()}:{line}  include of {raw!r}: {why}")
    if missing:
        print(
            f"\n{len(missing)} compile-time include(s) a clean checkout does not have. "
            "Commit the file, or un-ignore it — check `git check-ignore -v <path>` for the "
            "rule that caught it, which is usually a blanket pattern meant for something else."
        )
        return 1

    print(f"ok: all {ok} compile-time includes are committed")
    return 0


def self_test(root: Path) -> int:
    """The check can fail.

    It reports nothing on a healthy tree, which is what a broken regex also reports. So:
    plant an include of an uncommitted file in a temporary module and require it to be found.
    """
    root = root.resolve()
    probe = root / "crates" / "uops-core" / "src" / "_include_probe.rs"
    data = root / "crates" / "uops-core" / "_probe_data.txt"
    try:
        data.write_text("not committed\n", encoding="utf-8")
        probe.write_text(
            'pub const PROBE: &str = include_str!("../_probe_data.txt");\n',
            encoding="utf-8",
        )
        rc = check(root)
        if rc == 0:
            print("FAIL  an include of an uncommitted file was not reported")
            return 1
        print("\nok: the check catches an uncommitted include")
        return 0
    finally:
        for p in (probe, data):
            if p.exists():
                p.unlink()


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass
    here = Path(__file__).resolve().parent.parent
    os.chdir(here)
    sys.exit(self_test(here) if "--self-test" in sys.argv else check(here))
