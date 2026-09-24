#!/usr/bin/env python3
"""Nothing in any artefact reaches a destination the operator did not configure.

`PLAN` line 86: "No phone-home, ever. No auto-update check, no crash reporting, no
license callback." This is the half a response header cannot reach — see
`docs/packaging.md` §6.3, and `crates/uops-server/src/headers.rs` for the other half,
which is the one that constrains the browser.

Three checks, in the order of how likely each is to catch something real:

  1. dependency manifests, for a telemetry or update crate — the well-meaning dependency
  2. non-test Rust, for a routable literal destination     — the deliberate act
  3. shipped configs, for anything off-box                 — the misconfiguration we ship

The built web bundle is deliberately **not** here. `web/scripts/no-remote-assets.mjs`
already scans it, and better: it carries a documented allow-list saying why each hostname
that appears is text rather than a request — an SVG namespace, a React error link, a
three.js citation, this product's own webhook placeholder. Writing this script found that
guard, having first duplicated it. Two implementations of one rule are worse than one: the
allow-lists drift, and the copy with the poorer reasoning wins every argument by being the
one that fails the build.

Run from the repository root. Exits non-zero and prints every hit with its location.

    python scripts/no-phone-home.py
    python scripts/no-phone-home.py --self-test    # verify the checks can fail

An exemption is the marker `phone-home-exempt:` on the offending line, with a reason.
EXPECTED_EXEMPTIONS below is asserted, so a second one is a change somebody makes
deliberately and defends in review. It is 0 today, which is the number worth protecting.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

EXEMPT = "phone-home-exempt:"
EXPECTED_EXEMPTIONS = 0

# ---------------------------------------------------------------------------------------
# What counts as a destination nobody has to configure.
#
# A URL literal is not itself a phone-home. `"https://"` in a prefix check is the opposite
# of one, and this repository's tests are full of deliberately unroutable hosts. So the
# rule is about the *host*: loopback, a name reserved by RFC 2606/6761 for exactly this
# purpose, a compose service name that only resolves inside the stack, or an XML namespace
# that is an identifier and never requested.
# ---------------------------------------------------------------------------------------

URL = re.compile(r"""(?P<scheme>https?)://(?P<host>[^\s/"'`)\\}>,;|]*)""")

LOOPBACK = {"localhost", "127.0.0.1", "[::1]", "::1", "0.0.0.0"}

# RFC 2606 and RFC 6761 keep these unresolvable on purpose. A test that wants a host that
# cannot answer should use one of them, and the ones in this tree do.
RESERVED_SUFFIXES = (
    ".invalid",
    # ICANN reserved `.internal` in 2024 for exactly this: private-use names the public
    # DNS will never resolve. It is the right shape for a placeholder or an example that
    # has to look like an operator's own host without ever being able to be a real one.
    ".internal",
    ".test",
    ".example",
    ".local",
    ".localhost",
    "example.com",
    "example.net",
    "example.org",
)

# Namespaces and specification identifiers. `xmlns="http://www.w3.org/2000/svg"` is a
# string a browser compares, never a URL it fetches.
NAMESPACE_HOSTS = {"www.w3.org", "w3.org", "schemas.xmlsoap.org", "purl.org"}

# Service names from deploy/docker-compose.yml: resolvable only on the compose network, so
# a literal one cannot reach anything outside the operator's own stack.
COMPOSE_HOSTS = {"postgres", "clickhouse", "server", "snmp-agent", "uops-server"}


def host_is_acceptable(host: str) -> bool:
    """Is this host one that cannot reach a third party?"""
    bare = host.split("@")[-1].split(":")[0].lower()
    if not bare:
        # `http://` alone, or `http://{placeholder}` — a prefix check or a template, and
        # either way not a destination.
        return True
    if bare in LOOPBACK or bare in NAMESPACE_HOSTS or bare in COMPOSE_HOSTS:
        return True
    if bare.endswith(RESERVED_SUFFIXES):
        return True
    # A template hole where the host goes: `http://${endpoint}`, `http://{addr}`. The
    # destination is a value, which is the whole point — it came from configuration.
    return bare[0] in "${@<" or "{" in bare


# ---------------------------------------------------------------------------------------
# 2. Dependency manifests.
# ---------------------------------------------------------------------------------------

# Named because each one's entire purpose is to send something somewhere. A crate that
# merely *can* make a request is not in this list — that is most of them, and `ureq` is
# how OIDC discovery reaches an issuer the operator registered.
PHONE_HOME_PACKAGES = (
    "sentry",
    "self_update",
    "self-update",
    "update-informer",
    "update_informer",
    "posthog",
    "mixpanel",
    "segment-analytics",
    "@sentry/",
    "react-ga",
    "@vercel/analytics",
    "@datadog/browser",
    "amplitude",
    "bugsnag",
)


def check_dependencies(root: Path) -> tuple[list[str], str]:
    """A telemetry or self-update package in any manifest."""
    hits: list[str] = []
    manifests = sorted(root.glob("Cargo.toml")) + sorted(root.glob("crates/*/Cargo.toml"))
    manifests += [root / "web" / "package.json"]

    checked = 0
    for m in manifests:
        if not m.is_file():
            continue
        checked += 1
        for n, line in enumerate(m.read_text(encoding="utf-8").splitlines(), 1):
            if EXEMPT in line or line.lstrip().startswith("#"):
                continue
            bare = line.split("#")[0].lower()
            for pkg in PHONE_HOME_PACKAGES:
                # A dependency key, at the start of a TOML line or as a JSON string key.
                if re.search(rf'(^\s*|")({re.escape(pkg)})("|\s*[=.])', bare):
                    hits.append(f"{m.relative_to(root)}:{n}: {line.strip()[:90]}")
    return hits, f"scanned {checked} manifests"


# ---------------------------------------------------------------------------------------
# 3. Non-test Rust.
# ---------------------------------------------------------------------------------------


def strip_test_modules(text: str) -> str:
    """Blank out `#[cfg(test)] mod ... { ... }` bodies, keeping line numbers intact.

    By brace-counting rather than by filename, because most of this repository's URL
    literals live in a `mod tests` inside the file they test — `uops-oidc/src/discovery.rs`
    alone has a dozen. Excluding by path would have excluded `tests/` and kept all of
    those, which is the version of this check that reports nothing but noise.

    Lines are replaced rather than removed so that a reported line number still matches the
    file an engineer opens.
    """
    out = list(text.split("\n"))
    i = 0
    lines = text.split("\n")
    while i < len(lines):
        if re.match(r"\s*#\[cfg\(test\)\]", lines[i]):
            # Find the opening brace of the item this attribute applies to, then match it.
            depth = 0
            started = False
            j = i
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
            for k in range(i, min(j + 1, len(out))):
                out[k] = ""
            i = j + 1
            continue
        i += 1
    return "\n".join(out)


def check_rust(root: Path) -> tuple[list[str], str]:
    """A routable literal destination in code that ships.

    `tests/` and `benches/` directories are skipped wholesale; inline `#[cfg(test)]`
    modules are stripped by brace-counting. Comment lines are dropped for the reason the
    crypto guard drops them: prose about the rule is not a violation of it, and a guard
    that also forbids writing down the reasoning teaches people to delete the reasoning.
    """
    hits: list[str] = []
    checked = 0
    for f in sorted((root / "crates").rglob("*.rs")):
        parts = set(f.relative_to(root).parts)
        if "tests" in parts or "benches" in parts or "examples" in parts:
            continue
        checked += 1
        text = strip_test_modules(f.read_text(encoding="utf-8", errors="replace"))
        for n, line in enumerate(text.split("\n"), 1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "*", "/*")) or EXEMPT in line:
                continue
            for m in URL.finditer(line):
                if not host_is_acceptable(m.group("host")):
                    hits.append(f"{f.relative_to(root)}:{n}: {m.group(0)[:90]}")
    return hits, f"scanned {checked} non-test Rust files"


# ---------------------------------------------------------------------------------------
# 4. Shipped configuration.
# ---------------------------------------------------------------------------------------


def check_configs(root: Path) -> tuple[list[str], str]:
    """An off-box destination in something an operator deploys as-is.

    A default that points somewhere real is a phone-home with extra steps: the operator
    installs the product, never edits the file, and the product starts talking to whoever
    owns that name.
    """
    hits: list[str] = []
    checked = 0
    for pattern in ("deploy/**/*", "profiles/**/*"):
        for f in sorted(root.glob(pattern)):
            if not f.is_file() or f.suffix in {".png", ".svg", ".woff2", ".ico"}:
                continue
            checked += 1
            for n, line in enumerate(
                f.read_text(encoding="utf-8", errors="replace").split("\n"), 1
            ):
                stripped = line.lstrip()
                if stripped.startswith("#") or EXEMPT in line:
                    continue
                for m in URL.finditer(line):
                    if not host_is_acceptable(m.group("host")):
                        hits.append(f"{f.relative_to(root)}:{n}: {m.group(0)[:90]}")
    return hits, f"scanned {checked} shipped config files"


# ---------------------------------------------------------------------------------------


def count_exemptions(root: Path) -> list[str]:
    """Every line in the tree claiming an exemption."""
    found: list[str] = []
    for pattern in ("crates/**/*.rs", "deploy/**/*", "profiles/**/*", "Cargo.toml"):
        for f in sorted(root.glob(pattern)):
            if not f.is_file():
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for n, line in enumerate(text.split("\n"), 1):
                if EXEMPT in line:
                    found.append(f"{f.relative_to(root)}:{n}: {line.strip()[:110]}")
    return found


CHECKS = (
    ("dependency manifests", check_dependencies),
    ("non-test Rust", check_rust),
    ("shipped configuration", check_configs),
)


def run(root: Path) -> int:
    failed = False
    for name, check in CHECKS:
        hits, note = check(root)
        if hits:
            failed = True
            print(f"FAIL  {name} — {note}")
            for h in hits:
                print(f"        {h}")
        else:
            print(f"ok    {name} — {note}")

    exemptions = count_exemptions(root)
    if len(exemptions) != EXPECTED_EXEMPTIONS:
        failed = True
        print(
            f"FAIL  exemptions — expected {EXPECTED_EXEMPTIONS}, found {len(exemptions)}. "
            "Each one is a deliberate outbound request; update EXPECTED_EXEMPTIONS in this "
            "script and say why in the review."
        )
        for e in exemptions:
            print(f"        {e}")
    else:
        print(f"ok    exemptions — {len(exemptions)}, as expected")

    if failed:
        print("\nPLAN line 86: no phone-home, ever. See docs/packaging.md §6.")
        return 1
    print("\nok: nothing reaches a destination the operator did not configure")
    return 0


def self_test(root: Path) -> int:
    """Each check can actually fail.

    A guard nobody has watched fail is a guard nobody knows the direction of, and three of
    these four report nothing on a clean tree — which is indistinguishable from a broken
    regex. So each one is handed a violation in a temporary file and has to find it.
    """
    import shutil
    import tempfile

    cases = [
        ("non-test Rust", "crates/uops-core/src/_probe.rs", 'let u = "https://telemetry.vendor.io/v1";\n'),
        ("shipped configuration", "deploy/_probe.yml", "endpoint: https://collector.vendor.io\n"),
        ("dependency manifests", "crates/uops-core/Cargo.toml", None),
    ]

    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        shutil.copytree(
            root,
            work,
            ignore=shutil.ignore_patterns("target", "node_modules", ".git", ".sqlx"),
        )
        for name, rel, content in cases:
            check = dict(CHECKS)[name]
            target = work / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            original = target.read_text(encoding="utf-8") if target.is_file() else None
            if content is None:
                target.write_text(
                    (original or "") + '\nsentry = "0.34"\n', encoding="utf-8"
                )
            else:
                target.write_text(content, encoding="utf-8")

            hits, _ = check(work)
            if hits:
                print(f"ok    {name} catches a violation — {hits[0]}")
            else:
                ok = False
                print(f"FAIL  {name} did not catch the violation planted in {rel}")

            if original is None:
                target.unlink()
            else:
                target.write_text(original, encoding="utf-8")

    # The stripper is the one piece whose failure is silent in both directions, so both
    # are checked. Under-stripping floods the report with this tree's own test fixtures and
    # somebody widens the rules to quiet it. Over-stripping blanks production code and the
    # check passes while reading nothing -- which looks exactly like success.
    rust = [
        f
        for f in sorted((root / "crates").rglob("*.rs"))
        if not ({"tests", "benches", "examples"} & set(f.relative_to(root).parts))
    ]

    real_stripper = globals()["strip_test_modules"]
    globals()["strip_test_modules"] = lambda t: t
    unstripped, _ = check_rust(root)
    globals()["strip_test_modules"] = real_stripper
    if unstripped:
        print(
            "ok    the test-module stripper is load-bearing -- it suppresses "
            f"{len(unstripped)} test-only literals"
        )
    else:
        ok = False
        print("FAIL  stripping test modules changes nothing, so it is not being applied")

    emptied = []
    for f in rust:
        src = f.read_text(encoding="utf-8", errors="replace")
        out = strip_test_modules(src)
        if len(src.splitlines()) != len(out.splitlines()):
            ok = False
            print(
                f"FAIL  the stripper changed the line count of {f.relative_to(root)}; "
                "a reported line would not match the file"
            )
        if [x for x in src.splitlines() if x.strip()] and not [
            y for y in out.splitlines() if y.strip()
        ]:
            emptied.append(f.relative_to(root))
    if emptied:
        ok = False
        print(
            f"FAIL  the stripper blanked {len(emptied)} files entirely, so nothing in them "
            "is scanned at all:"
        )
        for f in emptied[:5]:
            print(f"        {f}")
    else:
        print(f"ok    the stripper leaves code in every one of {len(rust)} files")

    if not ok:
        print("\na check that cannot fail is not a check")
        return 1
    print("\nok: every check can fail, and the stripper does neither too much nor too little")
    return 0


if __name__ == "__main__":
    # The console this runs on is cp1252 on Windows and utf-8 in CI. Without this the
    # em dashes below raise UnicodeEncodeError and the check fails for the wrong reason.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass

    here = Path(__file__).resolve().parent.parent
    if "--self-test" in sys.argv:
        sys.exit(self_test(here))
    sys.exit(run(here))
