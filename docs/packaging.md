# Packaging, distribution, and the two binaries that do not ship

**Status:** a decision document. **Nothing here is built**, and writing it found two defects
in what *is* — see §2, which is the part to read first if you read nothing else.

Thirteen milestones are complete and there is no way to install this product. There is one
container image, built from `deploy/Dockerfile`, which nothing publishes; a compose file that
brings up a development stack; and a CI release that attaches an SBOM and a licence report to
a GitHub release — evidence about software nobody can download. No packages, no installer, no
per-host agent, no upgrade path.

`PLAN.md` already decided the shape and this document does not relitigate it:

| PLAN | what it settles |
|---|---|
| *"OpenTelemetry first; own agent later"* (§line 17) | the per-host agent is **not ours to write** |
| *"Agent — OpenTelemetry Collector, custom distribution"* (§line 331) | it is a distribution of theirs, with our configuration |
| *"No phone-home, ever. No auto-update check, no crash reporting, no license callback"* (§line 86) | what the product may not do on a customer's network |
| *"Offline path for GeoIP data, OTel Collector distribution, container images"* (§line 86) | every artefact must be transferable by hand |

What is left to decide is the artefacts, the credential that makes an agent safe to hand
out, and what a release *is*.

---

## 1. What exists today, precisely

**`deploy/Dockerfile`** builds every binary in the workspace (`cargo build --release
--workspace --bins`) into one image, runs as a non-root user, and reasons carefully about
air-gapped builds — `SQLX_OFFLINE=true`, because *"a build that needs to reach a live
PostgreSQL to compile is a build that cannot run in an air-gapped CI, which is exactly where
this product's customers build."* That decision is right and this document keeps it.

**`deploy/docker-compose.yml`** declares eight services: PostgreSQL, ClickHouse, an SNMP test
agent, migrations, the server, the poller, the syslog collector and the OTLP collector.

**CI** has a `stack` job that builds the image, brings the compose stack up, waits for health,
checks migrations ran, and verifies that every compose entrypoint exists in the image.

**A release** attaches `licences.md` and CycloneDX SBOMs. That is M12 §2.5's evidence
requirement, and it is met.

**Nothing publishes the image.** Nothing produces a binary anybody can download. There is no
version to ask for: the workspace is `0.0.1` and has been since M0.

## 2. Two binaries do not ship, and one of them is a queue with no consumer

The workspace produces eight binaries. The final image stage copies **six**. Missing:

* **`uops-collector-flow`** — NetFlow, IPFIX and sFlow. The whole of M7.
* **`uops-runner`** — takes the run lease and executes runbooks. The whole of M10.

Neither is named by a compose service either, which is why nothing noticed.

**The runner is the worse of the two.** The API accepts a runbook run, validates it, records
approvals and queues it as `ready`. `uops-runner` is what claims from that queue. Without it
in the image, a deployment built from the only artefact this repository has would accept runs
and never execute one — a queue with no consumer, which reports no error anywhere. An operator
would approve a change at 3 a.m. and watch nothing happen.

**The Dockerfile predicted this, in a comment, directly above the line that causes it:**

> `--workspace --bins`: every binary in this workspace ships in this image, and keeps shipping
> when one is added. Naming them individually is a list that goes stale silently — the image
> builds, and the thing you added is simply not in it.

It then names them individually in the `cp` out of the cache mount, and in the `COPY
--from=server`. The `build` is future-proof; the two copies are the list the comment warns
about, and the list went stale.

**And the guard that exists cannot see it.** CI checks that every compose entrypoint exists in
the image — added, its own comment records, because `uops-collector-syslog` was missing for two
commits. That check is one-directional. A binary in neither the image nor the compose file is
invisible to it: nothing names it, so nothing asks why. The guard verifies that what is
*claimed* is *present*, and the gap is in what is never claimed at all.

That is this repository's recurring shape again — see `STATUS.md` on *built, tested, never
called* — in its packaging form: **built, shipped by the build, absent from the artefact.**

**Decision: fix both in the artefact, and make the guard bidirectional.** Every binary
`--bins` produces is either in the image or listed in the Dockerfile as deliberately excluded
with a reason, and CI fails on a binary that is in neither. The existing entrypoint check
stays; this is the other direction, and it is the one that would have caught this.

> This is a defect, not a decision, so it did not wait for the rest of this document.
> **Fixed the same day**: the build stage copies `target/release/uops-*` by glob and deletes
> the `.d` files, the final stage copies the whole directory, and CI gained *"Every binary the
> workspace builds is in the image"* — which reads the binary list out of the crate manifests,
> so a crate added next year is checked without anybody remembering to. It carries an
> `EXCLUDED` list that is empty today, because everything ships.
>
> **Unverified locally, and that matters.** There is no Docker on the machine this was written
> on — `docs/dev-environment.md` explains why — so the image was not built. The change is a
> shell glob and a directory copy, reasoned about rather than run, and CI's `stack` job is what
> confirms it. Said here because "I fixed the Dockerfile" and "I built the image" are different
> claims and the second one is not true yet.

## 3. The blocker for handing out an agent

`deploy/otlp/listeners.yaml` is explicit:

> An OTLP request carries resource attributes that describe the EMITTER — `host.id`,
> `service.name` — and nothing that says which customer it belongs to. Anything that did would
> be a field the sender controls.
>
> The alternative is stronger here than it was for syslog and is still not taken: OTLP
> exporters send arbitrary headers, so a per-tenant token would be idiomatic and would let one
> endpoint serve every tenant. It is deferred because it is a new credential type — something
> to mint, show once, rotate, revoke and audit — and `uops-secrets` already owns those
> decisions.

And: *"An unknown emitter inside a listener's tenant is not rejected."*

So the trust boundary today is **the network segment**. Whatever can reach port 4318 can write
into that tenant, as any resource it names. That is defensible for a concentrator inside a
datacentre, chosen deliberately, and it is *not* something to hand to fifty machines across an
estate — still less to a laptop fleet.

**Per-tenant ingest tokens are therefore the first thing built, and everything else in the
agent story waits on them.** §4.2.

## 4. The decisions

### 4.1 Three tiers, and only one of them is an agent

The word "agent" has been doing too much work. What a customer installs is three different
things with three different threat models:

| tier | what it is | how many | holds |
|---|---|---|---|
| **server** | API, alerting, the two databases | one per installation | everything |
| **collector** | poller, syslog, flow, OTLP, runner | a handful, one per site or segment | **database credentials, and the KEK where it needs one** |
| **emitter** | OpenTelemetry Collector on a monitored host | hundreds | an ingest token for one tenant |

The middle tier is the one this product ships as binaries and the one `docs/collectors.md`
enrols. **It is not a per-host agent and must never be installed as one**: a collector writes
directly to ClickHouse, so putting one on every monitored machine puts database credentials on
every monitored machine. `docs/collectors.md` says this about the enrolment token — *"A
collector already holds those — it has to, because that is where it writes — and they are
strictly more powerful than any enrolment token"* — and the packaging has to make the
distinction physical rather than documentary.

**Decision: the collector tier and the emitter tier are separate downloads with separate
names in the interface.** Not one "agent" page with a platform dropdown. Somebody reaching for
"install this on my server" must land on the emitter, and reaching for "bring up a site" must
land on the collector.

### 4.2 Per-tenant ingest tokens, following the enrolment token exactly

A new credential type, and the fourth: session tokens (0006), collector enrolment tokens
(0025), user invitations (0030), and now this. **It copies the invitation and enrolment shape
rather than inventing a fifth posture**: high-entropy random, SHA-256 hashed at rest, shown
once, revocable, with a label somebody will recognise in six months.

| | decision | why |
|---|---|---|
| **scope** | one tenant | it is what the listener could not infer from the payload |
| **presented as** | `Authorization: Bearer` on the OTLP request | what every OTel exporter already supports, so no fork of theirs |
| **at rest** | SHA-256 of a random token | high entropy, so nothing to make expensive — the reasoning 0025 gives |
| **shown** | once | the same posture as every other token here |
| **expiry** | optional, `NULL` for none | an emitter token lives in configuration management for years; a laptop's should not |
| **revocation** | immediate, per token | the reason tokens are per-*label* rather than one per tenant |

**A token does not let a sender claim to be any resource.** It authorises *writing into a
tenant*, and the resource is still resolved by identity resolution as it is today, with an
unknown emitter creating a provisional resource and a review item. A token that also asserted
identity would be a field the sender controls, which is the thing the listener file refuses.

**The existing unauthenticated listener stays supported, and does not become the default.**
An installation whose OTLP port is on a trusted segment should not have to mint tokens to keep
working, and a migration that broke every existing collector to close a hole those operators
had already closed with a firewall would be a worse trade. A listener declares whether it
requires a token; new ones default to requiring one.

### 4.3 The artefacts, in the order they are worth building

1. **A published container image**, tagged by version, multi-architecture (amd64 and arm64 —
   `PLAN`'s buyers include appliance-class hardware). This is the primary artefact and the one
   the compose file and any Kubernetes manifest consume.
2. **A tarball of static binaries** plus the migrations, profiles and the built web assets,
   for the on-premise installation that does not run containers. `musl` static linking already
   makes this nearly free: the Dockerfile produces exactly these binaries today and throws the
   intermediate away.
3. **A `.deb` and an `.rpm`** wrapping the tarball with systemd units. Last, because a package
   is a support commitment — an upgrade path, a config-file merge policy, a postinst that must
   be idempotent — and the tarball serves the same buyer without one.
4. **A custom OpenTelemetry Collector distribution** built with `ocb`, carrying the receivers
   this product reads and an OTLP exporter pre-pointed at an ingest endpoint. Per-platform, and
   the thing the console hands out.

**Decision: an installer is not on this list.** The word in the request that started this was
"installer application", and for the server tier the honest answer is that a container image
and a tarball *are* the installation — a graphical installer for a thing that runs as four
processes against two databases would be a wrapper around `docker compose up` that has to be
maintained per platform. Where an installer earns its keep is the emitter tier, and there it is
the OTel Collector's own MSI and packages with our configuration, which is item 4.

### 4.4 No phone-home, and what that costs

`PLAN` §line 86 forbids auto-update checks, crash reporting and licence callbacks. That is not
a gap to work around; it is a property to preserve, and it forecloses the conveniences every
agent-management product is built on. So:

* **There is no auto-update.** Upgrades are the operator pulling a new image or package. The
  product's job is to make that safe, which means migrations that are forward-only and
  idempotent — which they already are — and a version the operator can see.
* **There is no fleet management.** The collector inventory (M12 §2.3) already reports version,
  binding and throughput for every enrolled collector, and *that is the fleet view* — read from
  what collectors send, not from a control channel the server opens. An emitter is not in it
  and should not be: hundreds of OTel Collectors reporting into an inventory would be an
  inventory of the wrong thing.
* **There is no crash telemetry.** A crash goes to the operator's own logs. This is the
  correct trade for the buyer profile and it means a bug report is a conversation.
* **Version skew is therefore real and must be survivable.** A collector one version behind the
  server must keep working, because an operator upgrading a site at a time is the supported
  path rather than an edge case.

### 4.5 A version, and what a release is

`0.0.1` since M0, which was honest while nothing shipped and stops being honest the moment
something does.

**Decision: a release is a tag, and CI builds the artefacts from it.** The tag sets the
workspace version; the release attaches the image digest, the tarball, the SBOM and the licence
report — the last two already work. A release with evidence and no artefacts is the shape today
and it is backwards.

**Versioning is `MAJOR.MINOR.PATCH` with the compatibility statement that matters to an
operator**: a collector of version *N* works against a server of *N* or *N+1*, and the
migration set is forward-only. Not semver as a promise about a Rust API — nothing here is a
published crate — but as a promise about which processes can be upgraded in which order.

### 4.6 The download surface

One screen: **Install**. It answers the two questions somebody actually has — *bring up a
site*, which issues an enrolment token and shows the compose fragment or the systemd unit for
a collector; and *report from a host*, which issues an ingest token for the tenant in the
header and shows a one-line command with the token in it.

**Both show the token once and say to convey it out of band**, because the product still has no
organization-level mail transport — the decision `docs/user-administration.md` §4.1 made for
invitations, applied again rather than re-argued.

## 5. What this does not do

**Kubernetes manifests or a Helm chart.** A real ask, and it wants opinions about storage
classes and ingress that belong to a deployment this product has not yet had. The image is
what a chart would consume, so nothing here forecloses it.

**A hosted offering.** `PLAN` puts a repeatable private deployment first, and this is that.

**Windows collectors.** The server and collector tiers are Linux; the *emitter* is wherever
OTel runs, which includes Windows, which is the tier that needs it.

**Signing and attestation.** Sigstore, provenance, signed packages. It belongs with a published
artefact and is the obvious next document after this one — an unsigned image from a product
whose buyers are defence ministries is a question that will be asked.

**Telemetry about the product's own deployment.** Which is to say: nothing. See §4.4.

## 6. Nothing reaches out, and a grep is only half of proving it

`PLAN` line 86 is unusually absolute: *"No phone-home, ever. No auto-update check, no crash
reporting, no license callback."*

> **Amended while building this.** The paragraph here first said *"thirteen milestones later,
> nothing enforced it"*, and that was wrong — worse, it was wrong in the direction that
> flatters the work. `web/scripts/no-remote-assets.mjs` has scanned the built bundle for
> remote references since the 3D explorer, with an allow-list that gives a reason for every
> hostname appearing in the output. It surfaced the way these things usually do: the first
> draft of this section's own script re-implemented the same scan with a worse allow-list, and
> the two disagreed. What follows is what was *actually* missing, which is less than the first
> draft of this section claimed.

What that guard covers is the web bundle as built. Two things it cannot see, and neither of
them had any guard at all:

* **What a browser does at run time.** A static scan reads the hostnames in the output. It
  cannot see a destination assembled at run time — from a config value, a concatenation, a
  redirect — and it has nothing to say about a dependency added after the last build anybody
  scanned. Only the browser can refuse that, and only if it is told to.
* **Everything that is not the web app.** `uops-poller` resolving a hostname, a shipped YAML
  pointing off-box, a crate whose whole purpose is to report crashes somewhere. The bundle
  guard is scoped to `web/dist` and rightly so.

The criterion below asked for this *"the way the crypto and secret-hygiene greps are:
mechanically, in CI"*. That describes the second gap. The first needs a header, and it is the
more valuable of the two: our own source is where a phone-home would be *deliberate*, and
deliberate is the easy case.

### 6.1 What the artefacts actually do today

Measured before deciding anything, because a policy written against a guess is a policy that
breaks the UI:

| artefact | outbound destinations found |
|---|---|
| `crates/**` non-test source | none. Every destination is a configured one: `CLICKHOUSE_URL`, a webhook the operator created, an OIDC issuer the operator registered |
| shipped `deploy/**`, `profiles/**` | compose service names and `localhost` only |
| the built web bundle | **no third-party fetch**, and already guarded: `no-remote-assets.mjs` fails the build on one. The hostnames present are inert strings — an XML namespace, a React error-docs link, a three.js citation, and this product's own `hooks.internal` webhook placeholder |
| fonts | self-hosted `/fonts/*.woff2` — four subsetted IBM Plex faces, no Google Fonts |
| the world map | `web/src/world.ts`, a vendored SVG path generated by `scripts/worldmap.py`. No tile server, which is the usual way a monitoring UI leaks every site's coordinates to a third party |

So the promise holds. **That is exactly the right moment to enforce it**: a policy added now
cannot break a working feature, because there is no feature that depends on reaching out.

### 6.2 A Content-Security-Policy, because the grep cannot see the bundle

The web UI is served by `uops-server` from the same socket as the API — `web.rs` explains why —
so there is one place to put a response header and no proxy to configure. The policy:

```
default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:;
font-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';
base-uri 'self'; form-action 'self'; worker-src 'none'
```

`connect-src 'self'` is the load-bearing one: it is what makes a phone-home from any
dependency *fail in the browser* rather than be absent by luck. `frame-ancestors 'none'` and
`form-action 'self'` matter for a console that performs privileged actions from a session
cookie; `object-src 'none'` and `base-uri 'self'` close the two injection primitives that
survive a strict `script-src`.

**`'unsafe-inline'` is on `style-src`, and that is a real concession** rather than an oversight.
Nineteen components set a style attribute from data — a meter's width, a status colour, a
tree's indent — and those are values, not stylesheets. Two alternatives were considered and
rejected:

* **`style-src-attr 'unsafe-inline'`**, which permits attributes while still forbidding inline
  `<style>` blocks, is what this wants. Firefox does not implement it, and an unsupported
  directive falls back to `style-src` — so the tighter policy would break every meter and
  status colour in Firefox. Rejected on that alone.
* **Moving all nineteen into CSS custom properties** does not help: setting a custom property
  is still a style attribute. It relocates the concession without removing it.

What `'unsafe-inline'` on styles costs is bounded and worth stating: with an injection point,
an attacker could style the page — including selector-based exfiltration of attribute values.
It does not permit script. `script-src 'self'` has no `'unsafe-inline'` and no
`'unsafe-eval'`, and the built bundle contains no `eval` or `new Function` to need it, which
was verified against `web/dist` rather than assumed.

There is no `nonce`. A nonce requires the server to rewrite `index.html` per request, which
turns a static file into a template and defeats the `ServeDir` design; it buys nothing while
`script-src` is already `'self'` with no inline script in the bundle.

**Three plain headers ship with it**, since the same layer is the only place they would go:
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`.
`no-referrer` rather than `same-origin`: a `Referer` on an outbound navigation from a console
whose URLs contain resource and incident identifiers is itself a small leak, and this product
has no need to send one anywhere. `X-Frame-Options` duplicates `frame-ancestors` for the
benefit of anything that predates CSP 2 — cheap, and the kind of thing procurement scans for.

No `Strict-Transport-Security`. TLS is terminated at the operator's proxy — the workspace
manifest says so — so this process cannot know whether it is reachable over HTTPS, and a
process that asserts HSTS while being served over plain HTTP on a closed management network
makes that installation unreachable. It belongs in their proxy configuration, and
`docs/security-overview.md` says so.

**Verified in a browser, both directions.** `scripts/csp-browser-check.py` serves the built
bundle with the policy read out of `headers.rs` — not restated, so the two cannot drift —
loads it in headless Chrome and reads the browser's own log. The application raises **no
violation** and renders; a control page carrying an external script, a same-origin script
that fetches a third party, a tracking pixel and an inline script has all four refused.

The control is the half that took two attempts. The first version put the `fetch` inside an
inline `<script type="module">`, which `script-src` blocked before it ran — so the harness
saw no `connect-src` violation and reported it as one thing not caught, when in fact nothing
had been tested. A clean run and a broken harness print the same zero. Moving the fetch into
a same-origin script is what made `connect-src` — the directive that carries `PLAN` line 86 —
actually observable.

**The ordering is load-bearing, and was tested rather than reasoned about.** A layer applies
to the fallback registered when it is added, and `web::serve` *replaces* the fallback — so
attaching the headers first leaves the page as the one response without a policy, which is
the only response where a policy does anything. Swapping the two lines in `application` makes
`the_web_app_page_carries_the_policy_as_well` fail while
`every_response_carries_the_security_headers` still passes: the API keeps its policy and only
the page loses it, so the API-level test alone would have shipped this. That is why there are
two.

`scripts/csp-browser-check.py` is **not wired into CI**: it needs a browser, and whether a
runner's Chrome behaves identically is not something this repository has established. It is a local check, to be run
after changing the policy or adding a web dependency that touches fonts, images, workers or
wasm.

### 6.3 The grep, for the half a header cannot reach

A CSP constrains a browser. It says nothing about `uops-poller` resolving a hostname, and
nothing about what a shipped YAML points at. `scripts/no-phone-home.py` covers that half, and
runs in CI beside the crypto and secret-hygiene greps:

1. **No routable literal destination in non-test Rust.** Literal URLs are allowed only when
   they are loopback, an RFC 2606/6761 reserved name (`example.com`, `.invalid`, `.test`,
   `.localhost`), a compose service name, or an XML namespace. A literal
   `https://api.example-vendor.com/telemetry` fails. Inline `#[cfg(test)]` modules are
   excluded by brace-counting, not by filename, because the majority of this repository's URL
   literals live in `mod tests` inside the file they test.
2. **No telemetry or self-update crate**, by name, in any `Cargo.toml` or `package.json`:
   `sentry`, `self_update`, `update-informer`, `posthog`, `mixpanel`, `analytics`. This is the
   check that catches the well-meaning dependency rather than the deliberate act.
3. **No absolute external destination in a shipped config** under `deploy/` or `profiles/`.
   A default pointing somewhere real is a phone-home with extra steps: the operator installs
   the product, never edits the file, and it starts talking to whoever owns that name.

**The built bundle is not in that list**, and that is the amendment above: `no-remote-assets.mjs`
already covers it from the `web` job, after `npm run build`, which is the only point at which
there is an artefact to read.

It is a script rather than four `grep` lines in YAML because of what it has to know: which
literals are unroutable by design, and where a `#[cfg(test)]` module ends. The second needs
brace-counting. Most of this repository's URL literals live in a `mod tests` inside the file
they test — twenty-five of them — so excluding by path would have produced a check that
reports only its own fixtures, which is a check somebody turns off.

**`--self-test` runs first in CI, and that ordering is the point.** All three checks report
nothing on a clean tree, which is indistinguishable from a broken regular expression. The
self-test plants a violation for each one and requires it to be found, and it checks the
stripper in both directions — under-stripping floods the report until somebody widens the
rules to quiet it, and over-stripping makes the whole check pass while reading nothing at
all. Verified: 25 test-only literals suppressed, 267 files still carrying code.

Exemptions are a `phone-home-exempt:` marker on the offending line with a reason, and the
script **asserts the expected count**, exactly as the `credential-print:` exemption does — so
a second one is a change somebody makes deliberately and defends in review. Today the count is
zero, which is the number worth protecting.

## 7. Acceptance criteria

- [x] Every binary `cargo build --workspace --bins` produces is either in the image or named
      in the Dockerfile as deliberately excluded, with a reason, and CI fails if one is in
      neither — the check `uops-collector-flow` and `uops-runner` would have failed. The
      discovery reads `crates/*/Cargo.toml` and `src/bin/*.rs`, verified locally to find
      exactly the eight binaries including `uops-pg-migrate` from its `src/bin/`
- [x] `uops-collector-flow` and `uops-runner` are in the image, and each has a compose
      service, so the stack CI brings up can collect a flow and execute a run —
      `deploy/flow/listeners.yaml` with one listener per tenant on 2055/udp, and the runner
      with the KEK volume the server and poller already use plus a named volume for
      `known_hosts`, which it refuses to start without. **The image build itself is still
      confirmed by CI rather than locally**: there is no Docker on this machine.
      > **Two guards came with them, because a service being declared is not a service that
      > runs.** CI waited only for `server` to be healthy, so any collector could have exited a
      > second after `compose up` — a bad tenant slug, a bound socket, a missing variable — and
      > the build would have gone green. Now *"Every long-running service is still running"*
      > derives the set from `restart: unless-stopped`, which is how a service in that file
      > declares it is meant to stay up, and prints the tail of its log when one is not. And
      > `the_shipped_listener_file_parses` reads `deploy/flow/listeners.yaml` through
      > `include_str!` and the type that will parse it, so a malformed shipped config fails
      > `cargo test` rather than a container exit nobody was watching. Verified by breaking the
      > file two ways and watching it fail.

- [~] A tagged release publishes a multi-architecture image, and the tag's version is what
      `/api/v1/health` reports.
      > **The half that is verified**: the version is 0.1.0 rather than 0.0.1, `/api/v1/health`
      > reports it, two unit tests hold the field in the JSON, and the `stack` job reads the
      > version out of `Cargo.toml` and asserts the running server agrees — so the check cannot
      > drift from the number it checks. The `release-artefacts` job refuses to publish when the
      > tag and the workspace disagree, which is verified by simulating both branches locally.
      >
      > **The half that is not**: nothing has been published, because that needs a tag, and the
      > image build itself has never run on this machine — there is no Docker here. The job is
      > written and its YAML and shell are checked; whether `ghcr.io` accepts the push is
      > knowable only by pushing. Saying it is built would be the claim this document exists to
      > stop somebody making.
- [~] A tarball installs the server on a host with no container runtime, and the smoke test that
      CI runs against compose passes against it. **Built, not proven**: the job assembles a musl
      tarball with every binary, the migrations, the profiles and the web assets, and asserts it
      carries every binary the workspace builds — the same check the image now has, because the
      tarball would otherwise be that bug in a different wrapper. Nothing has installed from it
- [x] An ingest token authorises writing into exactly one tenant, is shown once, is revocable
      with immediate effect, and a request carrying no token or another tenant's is refused —
      all five cases over a real socket in
      `uops-collector-otlp/tests/live::a_listener_that_requires_a_token_refuses_everything_else`:
      no header, an unknown token, another tenant's token, the right token, and the right token
      after revocation
- [x] A listener can be declared as requiring a token or not; an existing unauthenticated
      listener keeps working after the migration that adds this — `require_token` defaults to
      `false` for that reason, and a listener without it prints a warning naming the tenant and
      the address, the `UOPS_INSECURE_COOKIES` posture. `deploy/otlp/listeners.yaml` sets it
- [x] An ingest token does not let a sender assert which resource it is — it authorises writing
      into a tenant and nothing else; identity resolution still decides the resource from what
      the payload says about itself, and an unknown emitter still becomes a provisional resource
      and a review item
- [x] The Install screen issues both token kinds, shows each once, and says to convey it out of
      band — `/ingest` mints, lists and revokes, shows the token once with the OTel exporter
      block to paste on the host, and 14 web tests cover the rules. Enrolment tokens keep their
      own screen under Collectors, which `docs/collectors.md` documents
      > **One thing the build added that §4.2 did not think of.** A retired tenant's tokens have
      > to stop working, and the cascade does not do it: since migration 0031 a tenant is
      > *retired* rather than deleted, so `ON DELETE CASCADE` almost never fires. The
      > authentication query carries `t.retired_at IS NULL` instead. Leaving it out is the same
      > shape as leaving it out of `all_tenant_ids` and worse in consequence — there a removed
      > customer's devices went on being *polled*, which shows up as traffic; here the writes
      > *succeed*, so the installation goes on storing a customer's telemetry and billing the
      > disk while believing it stopped serving them. Nothing about it looks like an error.
      >
      > Also decided while writing the table, and recorded there: **no `last_used_at`.** It is
      > the first column anybody asks for, and it is a write on the hottest path this product
      > has to record a fact that is stale when read. The collector registry already reports
      > throughput, which answers the operator's actual question.
- [ ] A custom OTel Collector distribution reports host metrics into a tenant using only an
      ingest token and the endpoint, with no database credentials anywhere on the host
- [ ] A collector one minor version behind the server still works, asserted by the stack test
      against the previous published image
- [x] Nothing in any artefact makes an outbound request the operator did not configure —
      asserted the way the crypto and secret-hygiene greps are: mechanically, in CI.
      `scripts/no-phone-home.py` runs in `secrets-hygiene` and covers dependency manifests,
      non-test Rust and shipped configuration; `no-remote-assets.mjs` already covered the
      built bundle, which §6 is amended to say. `--self-test` runs first and plants a
      violation for each check, because three checks that report nothing look exactly like
      three checks that are broken
      > **Half of this is a header, and that half is the one worth having.** A grep sees the
      > hostnames somebody typed. It cannot see a destination a dependency assembles at run
      > time, which is the shape an accidental phone-home actually has. The web UI now
      > carries `default-src 'self'; connect-src 'self'` and the rest of §6.2's policy, so
      > the request *fails in the browser* rather than being absent by luck.
      >
      > **Building it found the defect shape again**, for the sixth time: the header layer
      > went into `main.rs`, where `boot.rs` — which builds its own router — could never
      > have seen it. Passing unit tests, a constant no response carried. The assembly is now
      > `uops_server::application`, used by the binary and by the test, and
      > `every_response_carries_the_security_headers` asserts the policy on a real 401 over a
      > real socket. Verified by removing the layer and watching that test fail. The `stack`
      > job asserts the same of the running image, since a test cannot see what a container
      > serves.
      >
      > **And a browser has now loaded the console under it** — `scripts/csp-browser-check.py`,
      > headless Chrome, no violation, the app renders. With a control page proving the same
      > browser refuses an external script, an outbound fetch, a tracking pixel and an inline
      > script, because otherwise "no violations" is also what a harness that cannot see them
      > reports
