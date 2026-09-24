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

## 6. Acceptance criteria

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

- [ ] A tagged release publishes a multi-architecture image, and the tag's version is what
      `/api/v1/health` reports
- [ ] A tarball installs the server on a host with no container runtime, and the smoke test
      that CI runs against compose passes against it
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
- [ ] Nothing in any artefact makes an outbound request the operator did not configure —
      asserted the way the crypto and secret-hygiene greps are: mechanically, in CI
