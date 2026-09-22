# Reporting a vulnerability

**Do not open a public issue.**

Report privately through GitHub's [Security Advisories][advisories] on this repository —
*Security* → *Report a vulnerability*. That opens a channel only the maintainers can see,
and it is the fastest route.

[advisories]: https://github.com/Ratul-netizen/veyronis/security/advisories/new

---

## What to expect

This is a small project. The commitments below are the ones that can actually be kept
rather than the ones that look best:

| | |
|---|---|
| **Acknowledgement** | within 3 working days |
| **First assessment** | within 10 working days — whether it is reproduced, and how severe |
| **Fix** | as fast as severity warrants; you will be told the plan, not left waiting |
| **Disclosure** | coordinated, and by default public once a fix is available |

If a deadline is going to be missed you will be told before it passes rather than after.

## What helps

* A version or commit, and how it was deployed.
* What an attacker gets. *"An operator with the viewer role on tenant A can read tenant
  B's logs"* is worth more than a scanner's severity score.
* Steps to reproduce, or a proof of concept. A stack trace or a request/response pair is
  usually enough.
* Whether you have told anybody else.

## Credit

You will be credited in the advisory and the release notes under whatever name you
choose, unless you ask not to be. There is no bug bounty — this project does not have the
money for one, and saying so is better than an unanswered form.

## Out of scope

Reports about these will be closed with a pointer back here, not because they are
uninteresting but because they are already known and written down:

* **Missing TLS between the server and PostgreSQL or ClickHouse.** Deliberate: both are
  expected on a private network, and it is stated in
  [`docs/security-overview.md`](docs/security-overview.md#encryption).
* **The server speaking plain HTTP.** TLS terminates at a reverse proxy, for certificate
  management every deployment already has processes for. Same document.
* **`RUSTSEC-2023-0071` in the `rsa` crate.** Documented, with the argument, in
  `deny.toml`, and there is a CI job that fails the build if the argument stops holding.
* **The development defaults** in `deploy/docker-compose.yml` and
  `docs/dev-environment.md` — `uops`/`uops`, trust auth on loopback. They are development
  defaults, they are obvious on purpose, and the compose file says so in place.
* **Self-XSS**, missing security headers on endpoints that return no HTML, and anything
  requiring an attacker to already hold an admin session on the tenant they are attacking.

## In scope, and especially interesting

* **Anything that crosses a tenant boundary.** That is the product's central claim; see
  the isolation section of the security overview for the three mechanisms it rests on.
  A hole in any of them is the most serious class of bug this product can have.
* **Anything that reads a device credential** without the key-encryption key, or that
  moves a sealed credential between tenants and opens it.
* **Authentication**: session fixation or prediction, the account-enumeration timing path,
  and anything in the OpenID Connect verification — a forged token accepted, an audience
  or issuer check bypassed, an algorithm confusion.
* **Privilege escalation** between roles, or from a tenant admin to an organization admin.
* **Anything reachable without a session**: the sign-in endpoints, the OIDC callback, and
  the collector ingest ports.
