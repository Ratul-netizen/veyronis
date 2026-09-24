"""Find public functions that no production code calls.

Kept in the repository because it has paid for itself: it found `access_entries` and
`audit_entries`, which meant the audit log the product sells could not be read through the
product. See docs/PRODUCT-STRATEGY.md §15.

    python scripts/unreached.py
    python scripts/unreached.py --self-test    # the three cases below, asserted

The pattern it hunts, which has now produced nine real defects: a component that is
correct, tested, and reached by nothing that runs. A unit test supplies the input it then
asserts on, so it can never notice.


## Rewritten 2026-09-25, because it was wrong in both directions

The first version counted `NAME(` across whole files. Triaging its fifty candidates showed
two defects in the counting, and the false negative is the one that matters.

**It missed real instances.** Production use was `pat.search(text[p])` over the *entire*
text of every file other than the definition's own — `#[cfg(test)]` was stripped from the
defining file and from nowhere else. So a function whose only callers were unit tests in a
*different* file counted as reached. `LocalVault::rotate_kek` is the proof: defined in
`vault.rs`, called from `lib.rs`'s test module and from `store-pg/tests/sealed.rs`, and by
no route, binary or job. It never appeared in the output. KEK rotation is implemented,
tested, and an operator cannot perform one — which is exactly what this script exists to
say out loud.

**And it flagged things that were fine.** `prod += len(pat.findall(own_prod)) - 1`
subtracted "the definition itself" on the assumption that a declaration matches `NAME(`.
A generic declaration does not: `pub async fn take_one<T: Transport + ?Sized>(` has a `<`
where the regex wants `(`. So for any generic function the subtraction removed a real
caller instead, and `uops_runner::take_one` — the runbook queue consumer, called by `run()`
twelve lines below it — was reported as reached by nothing. Read literally that was an
alarm about the whole of M10, and it was an artefact of the regex.

**A third thing it could not see at all.** An axum handler is passed as a value:
`post(metrics)`, `get(callback)`. It is never called with parentheses anywhere in this
repository, so every route handler looked unreached.

So this version:

* blanks `#[cfg(test)]` blocks in **every** file, by brace-counting rather than by
  splitting on the attribute, and keeps line numbers so a hit can be pointed at;
* removes the declaration by **position**, not by matching it again;
* counts a bare-name mention as reached, not only `NAME(`, so a registered handler counts;
* ignores comment lines, `mod NAME`, `NAME::` paths and same-named struct fields, none of
  which are uses of the function;
* separates *imported but never used* from *not mentioned at all*, because a `pub use` of
  something nothing calls is a deliberately surfaced dead end and reads differently.

It is still a list to read rather than a verdict. Two known blind spots remain, both
deliberate: a caller reached through a trait object is invisible to any grep, and names
shorter than six characters are skipped as too generic to reason about.
"""

from __future__ import annotations

import os
import re
import sys

# Names too generic to reason about, or trait methods implemented for many types.
SKIP = {
    "new", "default", "len", "is_empty", "as_str", "label", "from_env", "fmt", "clone",
    "get", "set", "id", "name", "kind", "value", "pool", "scope", "build", "run",
    "connect", "insert", "push", "next", "describe", "parse", "hash", "eq", "cmp",
    "into_uuid", "tenant_id", "apply", "check", "init",
}

DECL = r"^\s*pub (?:const )?(?:async )?fn {}\b"


def rust_files(root: str = "crates") -> tuple[list[str], list[str]]:
    """Every .rs file, split into production and test *files*."""
    src, test = [], []
    for base, _, files in os.walk(root):
        if os.sep + "target" in base:
            continue
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(base, f)
            is_test = (os.sep + "tests" + os.sep) in p or f.endswith("_test.rs")
            (test if is_test else src).append(p)
    return src, test


def split_cfg_test(src: str) -> tuple[str, str]:
    """Return (production, test) views of one file, both keeping the original line count.

    Brace-counted rather than `split("#[cfg(test)]")`, which gets the first block right and
    silently keeps everything after the *last* one -- including a second test module's
    contents, counted as production.
    """
    lines = src.split("\n")
    prod, test = list(lines), [""] * len(lines)
    i = 0
    while i < len(lines):
        if re.match(r"\s*#\[cfg\(test\)\]", lines[i]):
            depth, started, j = 0, False, i
            while j < len(lines):
                for ch in lines[j]:
                    if ch == "{":
                        depth += 1
                        started = True
                    elif ch == "}":
                        depth -= 1
                if started and depth <= 0:
                    break
                j += 1
            for k in range(i, min(j + 1, len(lines))):
                test[k] = lines[k]
                prod[k] = ""
            i = j + 1
            continue
        i += 1
    return "\n".join(prod), "\n".join(test)


def mention_kind(line: str, name: str) -> str | None:
    """What this line does with `name`: "use", "code", or nothing of interest."""
    t = line.strip()
    if not t or t.startswith(("//", "///", "//!", "*", "/*", "#[")):
        return None
    if re.search(rf"\bmod\s+{re.escape(name)}\b", t):
        return None                                    # a module of the same name
    if re.search(rf"\b{re.escape(name)}\s*::", t):
        return None                                    # a module path, not the fn
    if re.match(rf"^{re.escape(name)}\s*:", t):
        return None                                    # a struct field of the same name
    if t.startswith(("use ", "pub use ", "pub(crate) use ")):
        return "use"
    return "code"


def scan() -> list[tuple[str, str, int, int, bool]]:
    src_files, test_files = rust_files()

    prod_view: dict[str, str] = {}
    test_view: dict[str, str] = {}
    for p in src_files:
        text = open(p, encoding="utf-8", errors="replace").read()
        prod_view[p], test_view[p] = split_cfg_test(text)
    for p in test_files:
        # A test file is test all the way down.
        test_view[p] = open(p, encoding="utf-8", errors="replace").read()

    # name -> (defining file, declaration line number)
    defs: dict[str, tuple[str, int]] = {}
    for p in src_files:
        for n, line in enumerate(prod_view[p].split("\n"), 1):
            m = re.match(r"\s*pub (?:const )?(?:async )?fn ([a-z_][a-z0-9_]*)", line)
            if m and m.group(1) not in defs:
                defs[m.group(1)] = (p, n)

    rows = []
    for name, (where, decl_line) in defs.items():
        if name in SKIP or len(name) < 6:
            continue
        word = re.compile(rf"\b{re.escape(name)}\b")
        decl = re.compile(DECL.format(re.escape(name)))

        code_hits = uses = 0
        for p, view in prod_view.items():
            for n, line in enumerate(view.split("\n"), 1):
                if not word.search(line):
                    continue
                if p == where and n == decl_line:
                    continue                            # the declaration itself
                if decl.match(line):
                    continue                            # another crate declaring the same name
                kind = mention_kind(line, name)
                if kind == "code":
                    code_hits += 1
                elif kind == "use":
                    uses += 1

        if code_hits:
            continue

        test_files_hit = sum(
            1 for p, view in test_view.items() if view and word.search(view)
        )
        if test_files_hit:
            rows.append((name, os.path.relpath(where), test_files_hit, uses, bool(uses)))

    rows.sort(key=lambda r: (-r[2], r[0]))
    return rows


def report() -> int:
    rows = scan()
    print(f"{len(rows)} public functions referenced by tests and by no production code\n")
    print(f"  {'tests':>5}  {'exported':<9} {'name':<30} where")
    for name, where, tests, _, exported in rows:
        print(f"  {tests:>5}  {'pub use' if exported else '-':<9} {name:<30} {where}")
    print(
        "\nA list to read, not a verdict. A caller reached through a trait object is "
        "invisible to a grep, and names under six characters are skipped."
    )
    return 0


def self_test() -> int:
    """The three cases the rewrite exists for.

    Kept as code because each one was a wrong answer this script actually gave, and a
    rewrite that quietly regresses one of them is worse than the version it replaced.
    """
    rows = {r[0] for r in scan()}
    ok = True

    cases = [
        # The false negative: every caller is a test, in files other than the definition's.
        ("rotate_kek", True, "called only from test modules in other files"),
        # The false positive: called by `run()` in its own file, past a generic declaration.
        ("take_one", False, "called by run() twelve lines below it"),
        # The blind spot: an axum handler, registered as a value and never called.
        ("metrics", False, "registered with post(metrics)"),
    ]
    for name, want, why in cases:
        got = name in rows
        if got == want:
            print(f"ok    {name:<12} {'flagged' if want else 'not flagged'} — {why}")
        else:
            ok = False
            print(
                f"FAIL  {name:<12} expected {'flagged' if want else 'not flagged'} "
                f"({why}), got the opposite"
            )

    # The audit-log pair is why this script exists; both now have production callers, so
    # neither should appear. If one comes back, something was unwired.
    for name in ("access_entries", "audit_entries"):
        if name in rows:
            ok = False
            print(f"FAIL  {name} is unreached again — the audit log cannot be read")
    print("ok    access_entries / audit_entries still reached" if ok else "")

    print("\n" + ("ok: the three wrong answers stay fixed" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass
    sys.exit(self_test() if "--self-test" in sys.argv else report())
