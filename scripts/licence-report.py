#!/usr/bin/env python3
"""Every third-party crate this product ships, and what it is licensed under.

    python3 scripts/licence-report.py > licences.md

M12 §2.5: *an SBOM, a dependency licence report and a list of what the product talks to
are facts about a build. Anything regenerated per release stays true; anything typed into
a document is true on the day it is typed.*

So this is generated, and it is generated from `cargo metadata` — the same resolver cargo
builds with — rather than from a list somebody maintains.

# Why not cargo-about or cargo-license

Both are good and both are another tool to install, pin and trust in a job whose whole
purpose is supply-chain evidence. This reads the metadata cargo already produces and
formats it, which is thirty lines and no new dependency. `cargo deny check licenses`
remains the thing that *enforces* the policy; this is the thing that *reports* it, and
they are different jobs: a report that could fail the build would be a report somebody is
tempted to trim.

# What is excluded, and why it is said rather than assumed

**Workspace members.** The ~28 `uops-*` crates are this product, under AGPL-3.0-only.
Listing them in a third-party report would pad it with rows a buyer's counsel has to read
past to find the ones that matter.

**Nothing else.** Dev-dependencies and build-dependencies are *included*, because the
question a procurement team is asking is what code was involved in producing the artifact,
not only what is linked into it. A build script's licence is a licence that touched the
build.
"""

import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone


def cargo_metadata() -> dict:
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(out.stdout)


def commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        return "unknown"


def main() -> int:
    meta = cargo_metadata()
    ours = {m for m in meta["workspace_members"]}

    third_party = []
    for pkg in meta["packages"]:
        if pkg["id"] in ours:
            continue
        third_party.append(
            {
                "name": pkg["name"],
                "version": pkg["version"],
                # `license_file` rather than `license` means a crate whose terms are not
                # an SPDX expression. It is rare and it is exactly the row somebody needs
                # to look at by hand, so it says so rather than rendering as blank.
                "license": pkg.get("license")
                or ("see " + pkg["license_file"] if pkg.get("license_file") else "UNSTATED"),
                "repository": pkg.get("repository") or "",
            }
        )

    third_party.sort(key=lambda p: (p["name"].lower(), p["version"]))

    by_licence: Counter[str] = Counter(p["license"] for p in third_party)
    crates_per_licence: defaultdict[str, list[str]] = defaultdict(list)
    for p in third_party:
        crates_per_licence[p["license"]].append(p["name"])

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out = sys.stdout

    print("# Third-party licences", file=out)
    print(file=out)
    print(
        f"Generated {generated} from commit `{commit()}` by "
        "`scripts/licence-report.py`, which reads `cargo metadata`.",
        file=out,
    )
    print(file=out)
    print(
        "This product is **AGPL-3.0-only**. The crates below are its third-party "
        "dependencies, including build- and dev-dependencies: the question a "
        "procurement review asks is what code was involved in producing the artifact, "
        "not only what is linked into it.",
        file=out,
    )
    print(file=out)
    print(
        f"**{len(third_party)} third-party crates** across "
        f"{len(by_licence)} distinct licence expressions.",
        file=out,
    )
    print(file=out)

    print("## Summary", file=out)
    print(file=out)
    print("| Licence | Crates |", file=out)
    print("|---|---:|", file=out)
    for licence, count in sorted(by_licence.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"| `{licence}` | {count} |", file=out)
    print(file=out)

    unstated = crates_per_licence.get("UNSTATED", [])
    if unstated:
        print(
            "> **Crates with no stated licence:** "
            + ", ".join(f"`{c}`" for c in sorted(unstated))
            + ". Each needs reading by hand. `cargo deny check licenses` fails the build "
            "on these, so this list being non-empty means the policy has been relaxed "
            "deliberately and somebody should know why.",
            file=out,
        )
        print(file=out)

    print("## Every crate", file=out)
    print(file=out)
    print("| Crate | Version | Licence | Source |", file=out)
    print("|---|---|---|---|", file=out)
    for p in third_party:
        repo = f"[link]({p['repository']})" if p["repository"] else ""
        print(
            f"| `{p['name']}` | {p['version']} | `{p['license']}` | {repo} |",
            file=out,
        )

    print(file=out)
    print(
        "---",
        file=out,
    )
    print(file=out)
    print(
        "The policy these are checked against is `deny.toml`, enforced by "
        "`cargo deny check licenses` on every push. This file reports; that job "
        "enforces. A report that could fail the build would be a report somebody is "
        "tempted to trim.",
        file=out,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
