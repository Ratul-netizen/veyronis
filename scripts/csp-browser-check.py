#!/usr/bin/env python3
"""Load the built web app in a real browser under the real policy, and prove both
directions: that nothing in the application violates it, and that it actually blocks.

`docs/packaging.md` §6.2 decides the policy. Three other things check it and none of them
can answer the question that matters:

* the unit tests in `crates/uops-server/src/headers.rs` assert what the policy *says*
* `boot.rs::every_response_carries_the_security_headers` asserts responses carry it
* the `stack` job asserts the running image sends it

None of those is a browser. A policy that is correct, delivered, and breaks the console is
worse than no policy at all -- and the failure is invisible from here, because a blocked
stylesheet or a blocked module is a page that renders wrong rather than a request that
errors. So this serves `web/dist` with the header taken out of `headers.rs`, loads it in
headless Chrome, and reads the browser's own log.

The negative control is not optional. A clean run prints zero violations, which is exactly
what a harness that cannot see violations prints. So it first loads a page carrying an
external script, a same-origin script that fetches a third party, a tracking pixel and an
inline script, and requires the browser to refuse each one. The first draft of this file
put the fetch inside an inline module, which `script-src` blocked first -- so the control
found no `connect-src` violation and would have passed while proving nothing about the one
directive that carries `PLAN` line 86.

Not wired into CI: it needs a browser, and whether a runner's Chrome behaves identically is
not something this repository has established. Run it after changing the policy, and after
adding a web dependency that touches fonts, images, workers or wasm.

    python scripts/csp-browser-check.py
    CHROME=/usr/bin/google-chrome python scripts/csp-browser-check.py
"""

from __future__ import annotations

import http.server
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DIST = REPO / "web" / "dist"

CANDIDATES = (
    os.environ.get("CHROME", ""),
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)


def find_browser() -> str | None:
    for c in CANDIDATES:
        if c and Path(c).exists():
            return c
    return None


def policy_from_source() -> str:
    """Read the constant out of `headers.rs`, so the two cannot drift.

    Restating the policy here would make this a test of a copy, which is the failure it
    exists to catch one layer up.
    """
    src = (REPO / "crates" / "uops-server" / "src" / "headers.rs").read_text(encoding="utf-8")
    m = re.search(r'pub const CONTENT_SECURITY_POLICY: &str = "(.*?)";', src, re.S)
    if not m:
        sys.exit("could not find CONTENT_SECURITY_POLICY in headers.rs")
    # A Rust string continuation eats the newline and the following indentation.
    return re.sub(r"\\\s*\n\s*", "", m.group(1)).strip()


POLICY = policy_from_source()

# Each of these must be refused. Between them they cover every directive that carries a
# promise: `script-src` for the supply chain, `connect-src` for the phone-home, `img-src`
# because a tracking pixel needs no script at all.
PROBE_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>control</title></head>
<body><div id="root">control</div>
<script src="https://cdn.jsdelivr.net/npm/left-pad@1.3.0/index.js"></script>
<script>document.getElementById('root').textContent = 'INLINE_EXECUTED';</script>
<script src="/control.js"></script>
</body></html>"""

# Same-origin, so `script-src 'self'` lets it run -- which it must, or `connect-src` never
# gets anything to refuse.
PROBE_JS = """fetch("https://analytics.vendor.io/collect", {method: "POST"}).catch(() => {});
new Image().src = "https://tracker.vendor.io/pixel.gif";
"""

MUST_BLOCK = {
    "an external script (script-src)": "cdn.jsdelivr.net",
    "an outbound fetch (connect-src)": "analytics.vendor.io",
    "a tracking pixel (img-src)": "tracker.vendor.io",
    "an inline script (script-src)": "inline",
}


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(DIST), **kw)

    def end_headers(self):
        self.send_header("Content-Security-Policy", POLICY)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def do_GET(self):
        if self.path.startswith("/control"):
            js = self.path.startswith("/control.js")
            body = (PROBE_JS if js else PROBE_HTML).encode()
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/javascript; charset=utf-8" if js else "text/html; charset=utf-8",
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def send_head(self):
        # The SPA fallback `web::serve` does, so a deep link behaves as it would in the
        # product rather than 404ing into a different code path.
        path = self.translate_path(self.path)
        if not Path(path).exists() and "." not in Path(path).name:
            self.path = "/index.html"
        return super().send_head()

    def log_message(self, *a):
        pass


def load(browser: str, path: str) -> tuple[str, str]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as profile:
            p = subprocess.run(
                [
                    browser,
                    "--headless=new",
                    "--disable-gpu",
                    "--no-sandbox",
                    f"--user-data-dir={profile}",
                    "--enable-logging=stderr",
                    "--v=1",
                    "--virtual-time-budget=8000",
                    "--dump-dom",
                    f"http://127.0.0.1:{port}{path}",
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
    finally:
        server.shutdown()
    return p.stdout, p.stderr


def refusals(log: str) -> list[str]:
    return [
        line.strip()
        for line in log.splitlines()
        if "Refused to" in line or "Content Security Policy" in line
    ]


def main() -> int:
    browser = find_browser()
    if browser is None:
        print("no Chrome or Edge found; set CHROME=<path>. Skipping.")
        return 0
    if not (DIST / "index.html").is_file():
        print("no web/dist/index.html -- run `npm run build` in web/ first")
        return 1

    print(f"browser: {browser}")
    print(f"policy:  {POLICY}\n")

    ok = True

    print("=== the control: a page the policy must refuse ===")
    dom, log = load(browser, "/control")
    blocked = " ".join(refusals(log)).lower()
    for label, needle in MUST_BLOCK.items():
        if needle in blocked:
            print(f"ok    the browser refused {label}")
        else:
            ok = False
            print(f"FAIL  {label} was NOT refused -- this harness proves nothing")
    root = re.search(r'<div id="root">(.*?)</div>', dom, re.S)
    if root and root.group(1).strip() == "INLINE_EXECUTED":
        ok = False
        print("FAIL  the inline script's effect reached the DOM")
    else:
        print("ok    the inline script had no effect")

    print("\n=== the application itself ===")
    dom, log = load(browser, "/")
    hits = refusals(log)
    root = re.search(r'<div id="root">(.*?)</div>\s*</body>', dom, re.S)
    rendered = root.group(1).strip() if root else ""
    if hits:
        ok = False
        print(f"FAIL  {len(hits)} violation(s) -- the policy breaks the application:")
        for h in dict.fromkeys(hits):
            print(f"        {h[:200]}")
    else:
        print("ok    no violation")

    # An empty #root means the bundle did not execute, which a violation-free log would
    # otherwise report as success. There is no API behind this server, so what it renders
    # is the "cannot reach the server" state -- which is proof enough that React mounted
    # and the stylesheet applied.
    if len(rendered) < 40:
        ok = False
        print(f"FAIL  the app rendered nothing into #root ({rendered!r})")
    else:
        print(f"ok    the app rendered: {rendered[:120]}")

    print("\n" + ("ok: the policy blocks what it must and breaks nothing" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
