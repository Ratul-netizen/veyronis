# The unreached list, triaged

**Status:** a findings document, 2026-09-25. `scripts/unreached.py` had accumulated roughly
fifty untriaged candidates across several milestones. This is the triage, and the first thing
it found was that the detector was wrong.

`unreached.py` lists public functions that tests reference and production code does not. It
exists because that shape — correct, tested, reached by nothing that runs — has produced nine
real defects here, and a unit test can never notice it: the test supplies the input it then
asserts on.

---

## 0. The detector was wrong in both directions

Triaging the list meant checking the list, and it did not survive that.

**It hid real instances.** Production use was a search over the *whole* text of every file
except the definition's own; `#[cfg(test)]` was stripped from the defining file and nowhere
else. So a function whose only callers were unit tests **in a different file** counted as
reached. `LocalVault::rotate_kek` is the proof — defined in `vault.rs`, called from
`lib.rs`'s test module and from `store-pg/tests/sealed.rs`, and by no route, binary or job.
It never appeared in the output, and it is the most consequential finding below.

**It flagged things that were fine.** `prod += len(findall(NAME()) - 1` subtracted "the
definition itself", which assumes a declaration matches `NAME(`. A generic one does not:
`pub async fn take_one<T: Transport + ?Sized>(` has a `<` where the regex wants `(`. So for
every generic function the subtraction removed a real *caller* instead, and `take_one` — the
runbook queue consumer, called by `run()` twelve lines below it — was reported as reached by
nothing. Read literally that was an alarm about the whole of M10.

**And it could not see a registered handler at all.** An axum route is a value:
`post(metrics)`, `get(callback)`. Never called with parentheses anywhere in this repository.

The rewrite blanks `#[cfg(test)]` in every file by brace-counting, removes the declaration by
position, counts a bare-name mention as reached, and ignores comments, `mod NAME`, `NAME::`
paths and same-named fields. `--self-test` holds all three former wrong answers, plus that
`access_entries` and `audit_entries` — the pair this script was written for — stay reached.

**The corrected list is 60, and the entries it gained are the ones worth reading.** That is
the lesson worth carrying: a detector nobody audits is a detector that quietly tells you what
you want to hear. Two blind spots remain, both deliberate and both recorded in the script: a
caller reached through a trait object is invisible to any grep, and names under six characters
are skipped as too generic.

---

## 1. Confirmed: credential and KEK rotation have no operator path

**Severity: the highest here.** Five functions, one subsystem, and every caller is a test.

| function | what it is for |
|---|---|
| `LocalVault::rotate_kek` | "Re-wrap every DEK under the active KEK" |
| `KekRing::add_retired` | "Add a retired key so existing rows keep opening during rotation" |
| `promote_kek` | "Introduce a new active KEK, keeping the previous one for unwrapping" |
| `rewrap` | "Re-wrap a data key under the active KEK, leaving the ciphertext untouched" |
| `LocalVault::get_latest` | "Fetch by name, taking the highest live version. **This is how collectors resolve a credential, so a rotation takes effect without reconfiguring anything.**" |

The implementation is right and the design is the one SPEC §M0 argues for — *"KEK rotation is
cheap by construction: re-wrap DEKs, never touch ciphertext."* `rotate_kek` even reasons
about partial failure: *"a rotation that fails halfway leaves every row still openable,
because the retired KEK stays in the ring."*

**Nothing can put a key in that ring.** `uops-server` builds it with `KekRing::from_file` or
`from_env`, both of which end in `Self::new(id, one_key)`, and the configuration surface is
one key and one id — `UOPS_KEK_FILE` *or* `UOPS_KEK_HEX`, plus `UOPS_KEK_ID`. `add_retired`
is the only way to add a second, and no production code calls it.

**So the operator-visible behaviour is:** change `UOPS_KEK_ID` and the key to rotate, as any
runbook would tell you to, and every credential sealed under the old key stops opening with
`UnknownKek`. Polling stops for every device that has a credential. The ciphertext is intact
and the old key still exists, so it is recoverable by putting the old value back — this
destroys availability, not data. And the re-wrap that would actually complete the rotation
cannot be triggered, because no route, CLI subcommand or job calls `rotate_kek`.

`get_latest` compounds it: credential *version* rotation was supposed to take effect without
reconfiguring anything, and the function that would make that true is called only by tests.

**What is not wrong:** `docs/security-overview.md` makes no rotation claim, so nothing has
been oversold to a reader. SPEC's M0 checkbox for it is unticked. The gap is real; the
documentation did not lie about it.

**Verdict:** build it. Key rotation is table stakes for procurement and this is the
"enterprise grade" work the milestone is named after. It needs a configuration surface that
accepts retired keys, an operator trigger, and a test that rotates and then opens a row
sealed under the previous key. That deserves its own decision document first.

---

## 2. Confirmed: four unguarded twins of guarded admin operations

`PgStore` exposes both a guarded and an unguarded version of four privileged mutations. The
unguarded one is public, called only by tests, and takes **no organization parameter**:

| unguarded | guarded counterpart | what the guard adds |
|---|---|---|
| `grant_role(user, tenant, role)` | `grant_role_guarded(scope, user, role, by)` | advisory admin lock; the user must belong to the tenant's own organization |
| `revoke_role(user, tenant)` | `revoke_role_guarded(scope, user)` | the same, plus the last-admin check |
| `disable_user(user)` | `disable_user_in_org(org, user)` | organization scoping |
| `set_break_glass(user, …)` | — | nothing; the only protection is the per-organization unique index from migration 0024 |

Nothing calls the unguarded ones outside tests, so **this is a hazard rather than a live
defect**. It is the shape worth naming anyway: one new route wired to `grant_role` grants a
role across organizations with no lock and no membership check, and it would look exactly like
the guarded call at the call site. M12's cross-tenant isolation criterion is the one that
*"reopens with every new surface"*, and this is a surface sitting in the public API waiting for
one.

`create_user` and `user_credentials` are in the list for the same reason and are **not** in
this category: both take `OrgId`, so they are org-scoped. They are test fixtures superseded by
the product paths — the invitation flow for the first, `user_credentials_by_email` for the
second, which is what `POST /auth/login` actually calls.

**Verdict:** the capability is not missing, so the fix is to make the unguarded path
un-reachable-by-accident rather than to build anything: name the hazard at the declaration and
at every call site, and add a mechanical CI check that no crate's `src/` outside
`uops-store-pg` references them. `docs/user-administration.md`'s last criterion already says
this list is the wrong question; this is the right one.

---

## 3. Confirmed: measurements that no production code takes

Each of these exists to measure something a criterion is written in terms of, and each is
called only by tests — so the criterion is measured in a test fixture and nowhere else.

* `Pipeline::resolution_stats` — *"the resolution cache's counters, **which is where the >99%
  hit-rate criterion is measured**"*, with `CacheStats::hit_rate` beside it. The criterion is
  about a running system's cache; nothing running reads the counter.
* `percentile` — *"for the measurement SPEC asks for"*.

**Verdict:** these are why `STATUS.md` has to say a measurement was *"reasoned about rather
than measured"*, which it already does for M12's two-poller sample count. Surfacing them is
cheap — they are counters that belong in the health or self-monitoring output, which §4 is
about — and until then any criterion phrased as a measured number is `[~]` at best.

---

## 4. Confirmed: five health counters, and a health endpoint that reports two stores

`/api/v1/health` reports `ok`, the product version, and whether PostgreSQL and ClickHouse are
reachable. Meanwhile five subsystems expose a counter whose doc comment says what it is for:

| function | its own words |
|---|---|
| `open_sessions` | "How many sessions are currently open. **For a health endpoint.**" |
| `subscriber_count` | "How many live subscriptions there are. **For health output** and for tests" |
| `wheel_len` | "How many entries the wheel is actually carrying" |
| `has_pending` | "Whether anything is waiting to be replayed" |
| `enrichment_stats` | pipeline counters |

`has_pending` is the interesting one: a write-ahead log with something waiting to be replayed
is a condition an operator needs to know about, and there is no way to ask.

**Verdict:** one piece of work, not five. `docs/self-monitoring.md` is the document it belongs
to; the platform observer already emits self-events, and these are the numbers it has nothing
to say about.

---

## 5. Confirmed: rules written twice, where only one copy runs

Not dead code — a second definition of a rule, free to drift from the one that executes.

* **`RelationshipKind::propagates_impact`** — *"Used for blast-radius traversal. `ConnectedTo`
  is excluded: L2 adjacency is symmetric and does not imply dependence, so treating it as such
  would make every impact analysis spread across the entire network."* That exclusion is real
  and correct, and it is implemented **in SQL**, in `resource_dependencies`. Add a
  relationship kind and the compiler points at this function, which changes nothing; the view
  that decides blast radius is not mentioned. The fix is a test asserting the two agree.
* **`trace_logs`, `trace_spans`, `children_of`** — exported from `uops-query` and called by
  nothing. `web/src/tracepage.tsx` builds the same queries with a TypeScript `traceLogs()`.
  Two definitions of "the logs belonging to this trace", one tested and unused, one shipped
  and untested. `web/src/security.ts` states the rule being broken: the Query AST is *"never a
  parallel code path"*.
* **`ResourceStatus::alertable`** — **confirmed, and fixed the same day.** See §5.1.
* **`Severity::from_syslog`**, `is_admin`, `is_unique`, `is_anonymous`, `is_locatable`,
  `is_authoring_mistake`, `is_configuration`, `is_worth_telling` — the same shape, each
  needing its own check of whether something implements the rule inline instead.
  `is_worth_telling` is the one to look at first: it exists *"so that a caller reconstructing a
  decision from stored state cannot accidentally notify on `pending`"*, which names a specific
  bug it is not currently preventing.


### 5.1 `alertable`: retiring a device made it alert

The first of these triaged all the way to a fix, because the symptom turned out to be live
rather than theoretical.

`ResourceStatus::alertable` returns false for `Maintenance` and `Decommissioned`, and
`Maintenance`'s own doc comment has always said the status *"suppresses alerting without
losing history"*. **No production code consulted either.** The `Suppressions` map the engine
applies was built from maintenance *windows* only — scheduled work with a start and an end,
which is a different thing from a state a resource sits in.

Meanwhile decommissioning is a soft delete: `DELETE /resources/{id}` is
`set_resource_status(Decommissioned)`, per SPEC §M1, and `pollable` deliberately excludes a
decommissioned resource from polling. Selector resolution does not filter on status —
`of_kind`, `at_site`, `in_group` and `tagged` in `catalog.rs` have no status predicate — so
an absence rule scoped to a kind, a site or a group went on expecting a resource that had
stopped reporting **because the operator retired it**, and fired to say it had gone quiet.
Nothing but deleting the rule or the resource would stop it.

`alerts.rs` already refused an absence rule over `ResourceSelector::All` for precisely this
reason, and its comment names *"a decommissioned switch"* as one of the things that would
otherwise fire. The class was understood; the narrower selectors were missed.

**The fix**: `PgStore::not_alertable` reads the resources whose status is not alertable, and
`read_suppressions` adds them before the windows so a window can only ever widen what is
suppressed. The status list comes from `ResourceStatus::not_alertable()`, derived from
`alertable`, rather than `('maintenance', 'decommissioned')` written into the SQL — which
would have been a second copy of the rule, and this section is about that class of bug.
`ResourceStatus::ALL` exists for that derivation, with a test whose `match` has no wildcard
arm, so a seventh variant cannot be added without classifying it.

**Verified both ways**, because suppressing an alert is the dangerous kind of fix — a mistake
is silence, and nobody notices silence.
`a_retired_device_does_not_alert_and_a_live_one_still_does` retires the device and asserts no
notification, puts it in maintenance and asserts the same, then returns it to `Up` with the
same rule, resource and samples and requires exactly one. Removing the three added lines makes
it fail with `phase: Firing, notify: true` on the retired device, which is the defect as an
operator would have met it.

---

## 6. Not defects

Recorded so that the next reader does not re-derive them.

**Test infrastructure deliberately living in `src/`** — needed by integration tests, which are
separate crates and so cannot see `pub(crate)`: `ephemeral_for_tests`, `with_http`, `to_golden`,
`already_resolved`, `behaving`, `with_table`, `alias_of`, `lookup_count`, `resource_count`,
`described`, `default_provider`, `hit_rate`. A `test-fixtures` feature would express this
properly and would have to be passed by every `cargo test` invocation in CI and by hand; the
trade has not been worth making.

**Already recorded elsewhere** — `nominate_platform_tenant` (`docs/self-monitoring.md`, the
seventh instance of the shape, recorded rather than fixed); `is_locatable` (geolocation is not
built at all, `docs/traceroute.md` §6).

**Conveniences with no current caller** — `interface_metrics` (its own comment says it is "for
a profile being inspected" and that `Work` already separates them), `default_repetitions`,
`starting_at`, `modulus`, `advance`, `intervals`, `requests_per_minute`, `as_storage_string`,
`get_str`, `is_empty_set`, `members_of`, `is_outstanding`, `placeholders`,
`across_all_tenants`, `test_context`. Each is small, correct and unused. They are listed
rather than deleted because several are the obvious building block for work that is planned,
and deleting them would mean writing them again — but `test_context` ("the context for a
one-off test from the UI, which a person triggered") and `put_profile` ("store a tenant's own
profile, shadowing a built-in") both name a **user-facing feature with no route**, and belong
in §1's category rather than this one once somebody checks them.

---

## 7. What this changes about ticking criteria

`docs/user-administration.md`'s last criterion — *"`unreached.py` no longer lists
`create_user`, `grant_role`, …"* — was already amended to say it is the wrong criterion,
because the script asks whether a *name* has a production caller and the honest question is
whether a *capability* does. This triage is the evidence for that amendment, and it sharpens
it: those five names are a mix of org-scoped test fixtures (fine) and unguarded twins (a
hazard), and no single answer about the list is the right one.

The rule to carry forward: **run `unreached.py` before ticking a criterion, and read the
entries rather than counting them.** A name on this list is a question, not a defect. A name
that is *missing* from it may still be a defect, which is what the detector fix was about.
