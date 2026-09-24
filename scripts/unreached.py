"""Find public functions that no production code calls.

Kept in the repository because it has paid for itself: it found `access_entries` and
`audit_entries`, which meant the audit log the product sells could not be read through the
product. See docs/PRODUCT-STRATEGY.md §15.

    python scripts/unreached.py

It is crude and says so — trait methods, re-exports and generic names produce noise, and it
misses a caller that goes through a trait object. The output is a list to read, not a
verdict. Reading fifty names takes minutes and is the cheapest audit available for the one
defect shape this codebase keeps producing.


The pattern that has produced five real defects in two days: a component that is correct,
tested, and reached by nothing that runs. A unit test supplies the input it then asserts
on, so it can never notice.

Method: collect `pub (async) fn NAME` from every crate's src/, then count references to
NAME outside its own defining file, split by whether the referring file is production or a
test. Anything with test references and no production references is a candidate.

Crude on purpose — trait impls, re-exports and generic names will produce noise. The output
is a list to read, not a verdict.
"""
import os, re, collections

SRC = []
TEST = []
for root, _, files in os.walk("crates"):
    if os.sep + "target" in root:
        continue
    for f in files:
        if not f.endswith(".rs"):
            continue
        p = os.path.join(root, f)
        is_test = (os.sep + "tests" + os.sep) in p or f.endswith("_test.rs")
        (TEST if is_test else SRC).append(p)

text = {p: open(p, encoding="utf-8", errors="replace").read() for p in SRC + TEST}

defs = {}   # name -> defining file
for p in SRC:
    for m in re.finditer(r"^\s*pub (?:const )?(?:async )?fn ([a-z_][a-z0-9_]*)", text[p], re.M):
        defs.setdefault(m.group(1), p)

# Names too generic to reason about, or trait methods implemented for many types.
SKIP = {
    "new","default","len","is_empty","as_str","label","from_env","fmt","clone","get","set",
    "id","name","kind","value","pool","scope","build","run","connect","insert","push","next",
    "describe","parse","hash","eq","cmp","into_uuid","tenant_id","apply","check","init",
}

rows = []
for name, where in defs.items():
    if name in SKIP or len(name) < 6:
        continue
    pat = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    prod = sum(1 for p in SRC if p != where and pat.search(text[p]))
    # A call inside the defining file's own #[cfg(test)] module is not production use.
    own = text[where]
    own_prod = own.split("#[cfg(test)]")[0]
    prod += len(pat.findall(own_prod)) - 1  # minus the definition itself
    tests = sum(1 for p in TEST if pat.search(text[p]))
    if prod <= 0 and tests > 0:
        rows.append((tests, name, os.path.relpath(where)))

rows.sort(reverse=True)
print(f"{len(rows)} public functions referenced by tests and by no production file\n")
for tests, name, where in rows:
    print(f"  {tests:>2} test file(s)   {name:<38} {where}")
