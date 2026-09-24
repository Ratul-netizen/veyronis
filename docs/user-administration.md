# User administration, and the account lifecycle that has no door

**Status:** a decision document. **Nothing here is built.** The store layer is built, tested
by seventeen test files, and reachable from nothing in production. This records what to do
about that before any of it is written, because the decisions are the part that is easy to
get wrong quietly.

`docs/security-overview.md` tells a buyer:

> **Roles** are per `(user, tenant)`: viewer, operator, admin. One MSP engineer is admin on
> one customer and viewer on another with a single account.

`uops_core::Role::Admin`'s own doc comment says the role exists to *"manage credentials,
users, roles and tenants, and read the audit log."* Both are true of the schema. Neither is
true of the product: there is no route, no screen and no command that creates a user, grants
a role, revokes one, disables a departing employee, or lets anybody change their own
password.

This is the same shape as the audit log — filled since M1, readable only through `psql`
until `docs/self-monitoring.md`'s neighbours got fixed — and it is the ninth instance. It is
the first one that is a whole feature area rather than a function.

---

## 1. What is missing, precisely

Found by `scripts/unreached.py`, which lists public functions referenced by tests and by no
production file. These four are the top of that list.

| Operation | Store function | Test files referencing it | Production caller |
|---|---|---|---|
| Create a user | `PgStore::create_user` | 17 | `bootstrap` only, for the **first** admin |
| Grant a role | `PgStore::grant_role` | 14 | none |
| Disable an account | `PgStore::disable_user` | 4 | none |
| Revoke a role | `PgStore::revoke_role` | 2 | none |
| Designate break-glass | `PgStore::set_break_glass` | 1 | none |
| Re-enable an account | — | — | **the function does not exist** |
| Change your own password | `PgStore::update_password_hash` | — | the transparent rehash-on-login in `routes/auth.rs`, and nothing else |

**SSO is not affected and is the reason this survived.** `routes/sso.rs` → `sso::provision`
has its own insert and does create users and grant roles from group mappings, so an
organization with an identity provider onboards people correctly. The gap is invisible there
and total everywhere else:

* an installation using passwords has **exactly one user — the first-run admin — forever**;
* **no** installation can disable a departing employee's account, or change anyone's role,
  without a hand-written `UPDATE`;
* nobody can change their own password, ever.

The last one is not a convenience. A password that the person believes has leaked cannot be
replaced by the person who knows it leaked.

## 2. Why the test suite is structurally blind to exactly this

Seventeen test files call `create_user`. That is not a mitigating detail, it is the
mechanism: every test that needs a second user makes one by calling the store directly,
which is the correct thing for a test to do and is also why no test ever needed a route to
exist. The suite is strong at *is `create_user` correct* and cannot ask *is there any way to
reach it*, because the test is the thing supplying the input.

`bootstrap` and SSO are both real, working paths that create users. Between them they cover
first run and every SSO deployment, which is every deployment anyone here has stood up. The
uncovered case is a password-authenticating organization that wants a second person in it —
and that is the default for an on-premise evaluation, which `PLAN` names as the first way a
buyer meets this product.

## 3. A precondition that turned up while writing this: there can only ever be one tenant

`grant_role` takes a `(user, tenant)` pair, and the MSP story above is *"admin on one
customer and viewer on another"*. So the survey asked where a second tenant comes from.

**Nowhere.** The only `INSERT INTO tenant` outside tests is `bootstrap.rs:152`, and
`bootstrap`'s whole decision is *"does any user exist"* — it runs once. There is no
`create_tenant` function at all. A running installation has one organization, one tenant,
and no way to add another.

That is a heavier finding than the one this document was opened for, and it is *coupled* to
it: a screen for granting a role per tenant is close to meaningless against a single tenant,
and the isolation guarantee that `TenantScope` enforces in the type system — asserted across
every route entry in `crates/uops-api/tests/isolation.rs`, sold in `security-overview.md`, and
a pillar of M12 — was, when this was written, a guarantee about a boundary that production
could only ever have one side of. `docs/tenant-lifecycle.md` closed that the same day.

**Decision: tenant creation is a sibling document, not a section of this one, and this one
does not wait for it.** That document is now written **and built** —
`docs/tenant-lifecycle.md`, 2026-09-24 — and it found a lockout this one would have walked
into: creating a tenant raises the denominator in
`is_org_admin`, so an admin who creates one without being granted a role on it loses
`OrgAdmin` the moment it commits, and cannot get it back. The three reasons for separating
them:

1. Disabling a departing employee and letting somebody change their own password are useful
   on a single-tenant installation today. They should not be held behind a larger change.
2. Tenant creation has its own decisions that are not about people — slug immutability, what
   happens to a tenant's telemetry when it is removed, whether `retired` is a state or a
   deletion, and whether the platform resource in `self-monitoring.md` §4 is per tenant or
   per organization. Mixing them in would produce a document that decides neither well.
   (Answers, for the record: immutability is refused, telemetry is left to its TTL,
   retirement is a state, and the platform resource stays per organization.)
3. The role surface designed here is per `(user, tenant)` whether there are one or fifty, so
   nothing built from this document has to be revisited when the second tenant arrives.

What this document *does* take from the finding: the roles screen is **per tenant and reads
its tenant from the existing request header**, not a matrix keyed on a tenant list that is
currently of length one. See §4.2.

> Recorded in `STATUS.md` as an open gap against M12 the day it was found, rather than left
> in a doc nobody reads before touching tenancy.

## 4. The decisions

### 4.1 An administrator never sets another person's password

An admin who types somebody's password knows a credential that person is then accountable
for. Every action that account takes afterwards is attributed to them in the audit log the
product sells, while somebody else knew the secret — and the audit log is worth less than
nothing if it confidently names the wrong person. Argon2 being irreversible is not the
point; the window between *set* and *first changed* is the point, and the product has no way
to force the change.

**So nobody sets a password but its owner, and the account does not exist until they do.**

> **Amended 2026-09-24, while building it.** This section said the new account is created
> immediately without a password, and that *"the schema already allows it:
> `app_user.password_hash` is nullable, because an SSO-provisioned user has never had one."*
> Nullable, but not unconstrained — migration 0024 added
> `app_user_can_authenticate_somehow`, and it refused the insert:
>
> > An account with neither a password nor a provider identity cannot authenticate at all.
> > It is not a locked account — `disabled_at` is how one of those is written — it is a row
> > that nothing can ever match, and it would be created by a partial write rather than by
> > intent.
>
> An invited account is the *intentional* version of precisely that state, so the choice was
> to name it in the constraint or to not create the row yet. **Not creating it wins**, and
> the deciding argument is not tidiness: §4.4 offers no way to delete a user, because the
> audit and access logs name their actor. An account created at invitation time would make
> every mistyped address a permanent, undeletable row in the user list. An unredeemed
> invitation is not a person yet, so it can simply expire.
>
> The cost, recorded because it is real: **a role cannot be granted before somebody
> accepts.** That is arguably the better shape — a role is granted to a person who exists —
> but it is a consequence, not a feature. It also means the administration screen reads two
> lists, `users_in_org` and `pending_invitations`, rather than one.

**The token is stored hashed and never re-readable,** following the collector enrolment
tokens that already exist (`/api/v1/collectors/tokens`) rather than inventing a second
convention. It is single-use and expires, and there is no account behind it until it is
redeemed — so an unclaimed invitation is not an account waiting to be guessed at. Migration
0030 adds `user_invitation`, which carries the organization, the address and the display
name until somebody accepts.

**Single use is enforced twice, and that is deliberate.** The redemption locks its row with
`SELECT … FOR UPDATE` on a predicate including `accepted_at IS NULL`, so a second
simultaneous redemption matches nothing; and the account insert is `ON CONFLICT DO NOTHING`
against `app_user_email_ci_idx`, so even a token that somehow passed the first check cannot
produce a second account for one address. Mutation testing showed the second alone made the
first look untested, which is why `tests/users.rs` has a case that isolates the predicate by
moving the account off the invited address.

**Delivery, and the decision that keeps an air-gapped install usable.** `uops-notify` has a
working `Smtp` transport, but it is reached through a *notification channel*, which is
tenant-scoped configuration for alert routing. An invitation is an organization-level act
and must not depend on how one customer happens to route its alerts, so this reuses the
`Smtp` transport directly and not the channel model.

When no organization-level SMTP is configured, **the API returns the invitation link exactly
once in the response body and the screen shows it with an instruction to convey it out of
band.** A product whose buyers include government and defence on-premise — `PLAN`'s
unrestricted-buyer position — cannot make adding a colleague depend on outbound mail. Saying
so in the interface is better than an invitation that silently goes nowhere, which is the
failure mode of every product that assumed it had a mail server.

### 4.2 Roles are granted one tenant at a time, on the tenant already in the request

`user_tenant_role` is keyed `(user_id, tenant_id)` and `grant_role` already takes
`granted_by: Option<ActorId>`, so provenance is modelled and should be recorded rather than
passed `None`. Re-granting updates the role instead of failing, which is what a
"change someone's role" control wants and means the surface needs no separate update verb.

The screen is therefore the tenant's own membership list, read under the `X-Tenant` header
every other route already requires — not a user-by-tenant matrix. §3 is one reason; the
other is that a matrix is the wrong shape at fifty tenants too, because the question an
administrator actually has is *who can see this customer*.

### 4.3 The last administrator cannot be removed, and the rule is one statement

An organization that loses its last enabled admin cannot appoint another one, and recovery
is a hand-written `UPDATE` against a production database. So:

* an admin cannot disable their own account;
* the last remaining enabled admin on a tenant cannot have their role revoked or lowered.

**Enforced under a lock, not as a check before the write and not inside one statement.**

> **Amended 2026-09-24, while building it.** This said the rule would be enforced *"inside
> the statement that performs the change"*. That is not sufficient and the reasoning was
> shallow. A single statement can check "is there another enabled admin" against its own
> snapshot, but two concurrent statements removing *different* administrators each see the
> other and both commit: no row is contended, so nothing conflicts and nothing blocks. The
> check has to exclude the other *change*, not the other row.
>
> So every operation that can change the set of enabled administrators — disable, grant,
> revoke — takes a transaction-scoped advisory lock on the organization first, then checks,
> then writes. These are rare administrative acts; serialising them per organization costs
> nothing anybody will measure, and it removes the whole class of race rather than the
> instance somebody thought of. It is the same instrument `bootstrap` uses, for the same
> reason.
>
> The self-disable refusal stays in the route, because comparing the caller's id to the
> target's is not a question about database state and asking the store would be asking the
> wrong layer.

Note that `is_org_admin` requires admin on **every** tenant in the organization, so
organization-wide settings have a stricter requirement than any single tenant's admin list.
The invariant above is per tenant, which is the one that makes a tenant recoverable; whether
an organization can be left with nobody holding admin *everywhere* is a question for the
tenant document, since it only becomes reachable when a second tenant can exist.

### 4.4 Disabling ends every session immediately, and is reversible; deleting is not offered

`disable_user` already sets `disabled_at` and calls `revoke_sessions_of` in the same
function, and `is_org_admin`'s join checks `disabled_at IS NULL` as part of the join rather
than as a separate predicate, so a live session stops working the moment the account does.
That decision is made and this document only records it.

**What is missing is the way back.** There is no `enable_user`, so a suspension cannot be
lifted — and an administrator who needs to restore access has to create a *second* account
for the same person, which splits their audit history across two identities. That is a worse
outcome than the suspension it works around, so `enable_user` is part of this work.

**Deletion is not offered at all.** `audit_log` and `access_log` rows name their actor, and
the product's answer to *who read this* is the thing M0.8 exists for. Removing a user would
either orphan those rows or cascade them away, and both are worse than a tombstone.
`disabled_at` is the tombstone, and the interface says "disabled", never "deleted".

### 4.5 Break-glass designation belongs on this screen, and gets no invented ceremony

`set_break_glass` has no caller, so the one account permitted to sign in with a password
when an organization requires SSO can only be designated by hand. It belongs here.

It is tempting to add a rule — that an admin may not designate themselves, say. **That rule
would be security theatre and is refused:** an admin who wants a password bypass can
designate any account they control, so the rule stops nothing and would read to a reviewer
as though it stopped something. What actually constrains this is already built: requiring SSO
is an organization-wide setting behind `OrgAdmin`, every *use* of the break-glass path is
already audited as `auth.break_glass`, and designating it will be audited too.

At most one account per organization may hold it, and **that was already enforced** —
migration 0024 created `app_user_one_break_glass_per_org`, a partial unique index on
`(org_id) WHERE break_glass`. A first draft of migration 0030 created it a second time and
failed on the duplicate, which is the cheapest possible way to find out the invariant was
already somebody else's decision. Designating therefore clears the previous holder in the
same transaction, because otherwise it trips that index.

### 4.6 Changing your own password is a different thing and sits on `/me`

It is not administration — it needs no admin role and must work for every user — so it does
not belong on the users screen. It requires the current password, because a session cookie
is not evidence of knowing the secret being replaced.

**It revokes every session but the one making the change.** Somebody changing a password
usually believes the old one leaked, and leaving the other sessions alive would defeat the
act itself. Leaving the *current* session alive is what stops the operation from looking like
a bug.

## 5. The surface this implies

| Method and path | Authorisation | Audit action |
|---|---|---|
| `GET /api/v1/users` | `OrgAdmin` | `user.list` |
| `POST /api/v1/users` | `OrgAdmin` | `user.invite` |
| `DELETE /api/v1/users/invitations/{id}` | `OrgAdmin` | `user.invite.withdraw` |
| `GET /api/v1/users/invitations` | `OrgAdmin` | `user.invitations.list` |
| `POST /api/v1/users/{id}/disable` | `OrgAdmin` | `user.disable` |
| `POST /api/v1/users/{id}/enable` | `OrgAdmin` | `user.enable` |
| `POST /api/v1/users/{id}/break-glass` | `OrgAdmin` | `user.break_glass.designate` |
| `GET /api/v1/tenants/roles` | `Role::Admin` on the header's tenant | `user.roles.list` |
| `PUT /api/v1/users/{id}/role` | `Role::Admin` on the header's tenant | `user.role.grant` |
| `DELETE /api/v1/users/{id}/role` | `Role::Admin` on the header's tenant | `user.role.revoke` |
| `POST /api/v1/invitations/{token}` | none — the token *is* the authorisation | `user.invite.accept` |
| `PUT /api/v1/me/password` | `Authenticated` | `me.password.change` |

Action names follow the `noun.verb` convention already in use (`alerts.rule.create`,
`collector.token.issue`, `auth.sign_in.failure`). Every row goes in
`crates/uops-api/tests/isolation.rs`, because M12's cross-tenant criterion is `[~]`
specifically so that it reopens for each new surface.

`POST /api/v1/invitations/{token}` is the one unauthenticated mutating route this adds. It
gets the same treatment as `auth/login`: the response must not distinguish an expired token
from a wrong one, and the attempt is audited either way.

**There is no resend route.** Inviting the same address again *is* the resend: it supersedes
any live invitation in the same transaction, because the partial unique index requires that
either way. One verb with one meaning beats two that differ only in whether something was
there before.

## 6. What this does not do

**SCIM.** Automated provisioning from an identity provider is a real enterprise request and
it is the *third* way to create a user, after invitations and SSO group mappings. Two are
enough to justify a screen; three needs a protocol implementation and a conformance
argument, and it should be decided when a buyer asks rather than guessed at now.

**Multi-factor authentication.** It belongs to authentication, not administration — a
different document and probably a milestone. Nothing here forecloses it.

**User groups.** Note the name collision: `groups` in this product already means *resource*
groups, and a second meaning on the same word in the same interface is how a reader ends up
confidently wrong. If group-based role assignment is ever wanted, SSO group mappings already
do it for SSO organizations, which is the case that asked for it.

**A password policy.** `uops_secrets::password` owns hashing and already upgrades weak
parameters transparently on sign-in. Composition rules — a digit, a symbol, ninety-day
rotation — measurably push people toward worse passwords and are not added. A length floor
is the whole policy.

**Self-service signup.** There is no tenant this product is a SaaS for yet, and an
installation that lets strangers create accounts is not one an enterprise buyer would run.

## 7. Acceptance criteria

Each one names a *reachable* path, because the defect this document exists to fix is a set of
functions that every criterion about them would have passed.

**The store, the routes and the screens are built.** `web/src/userspage.tsx` is the People and
Access screens, `acceptinvite.tsx` is the one page in the app that works with no session, and
`accountpage.tsx` is where somebody changes their own password — which nothing could do before,
since `update_password_hash` was reached only by the transparent rehash during a sign-in.

- [x] An organization with no SSO and one admin can add a second person, who sets their own
      password from the invitation and signs in — with no `psql` at any point.
      `uops-api/tests/users_routes.rs::an_administrator_adds_a_colleague_who_signs_in`
- [x] The invitation is single-use: presenting an accepted token again is refused, and an
      expired token is refused indistinguishably from a wrong one — asserted by comparing the
      two responses, not by reading the message
- [x] With no SMTP configured, the invitation link is returned once and the screen says it
      must be conveyed out of band — `users.ts::CONVEY_OUT_OF_BAND`, shown beside the link
      with a copy button, and asserted to say both that it appears once and what to do if it
      is lost. `InviteResponse::link_token` remains the only place the token ever appears;
      the invitation *list* is asserted not to carry it
- [x] An admin can grant, change and revoke a role on the tenant in the request, and
      `user_tenant_role.granted_by` names the admin who did it rather than being `NULL`
- [x] Disabling an account ends its live sessions within the same request — asserted by a
      session that answered `200` before the call and `401` after it
- [x] A disabled account can be re-enabled, and signs in again afterwards
- [x] The last enabled admin on a tenant cannot be disabled, demoted or revoked, **and the
      refusal holds under two concurrent attempts** —
      `two_simultaneous_revocations_cannot_both_win`, which races two revokes on separate pool
      connections and asserts exactly one wins.
      > Removing the advisory lock and racing **once** fails about four times in five. A guard
      > that reports a real defect 80% of the time is one that gets dismissed as flaky by
      > whoever is unlucky, so it races eight rounds — missing the defect then runs at roughly
      > two in a million, and the mutation is now caught on every attempt. A race can only be
      > tested by racing; it can be tested often.
- [x] An admin cannot disable their own account
- [~] Designating a break-glass account is audited, at most one is held per organization
      (migration 0024's partial unique index, asserted in `uops-store-pg/tests/users.rs`), and
      the People screen offers it. **That it is the only password login accepted when the
      organization requires SSO is covered by M12 §2.2's own tests, not by this work, and the
      two are still not asserted together** — the one criterion here that no new test covers
- [x] A user changes their own password with the current one, their other sessions are
      revoked, and the session that made the change still works
- [x] Every route above appears in `crates/uops-api/tests/isolation.rs` — twelve cases, and
      `every_route_in_the_router_has_an_isolation_case` is what makes that not a promise
- [ ] `scripts/unreached.py` no longer lists `create_user`, `grant_role`, `revoke_role`,
      `disable_user` or `set_break_glass`

> **The last one is not met, and it is the wrong criterion.** Amended rather than quietly
> dropped, because it was written as the mechanical check that would have caught the original
> defect.
>
> It still lists all five. The reason is not that the capability is unreachable — adding a
> person, granting a role, suspending an account and designating break-glass are all now
> reachable over HTTP, which is what the eleven criteria above assert. It is that production
> reaches the *statements* rather than the named wrappers. `grant_role_guarded` must check the
> last-administrator invariant and write in the same transaction, and `grant_role` takes the
> pool; so the statement was extracted to `grant_role_on`, which both call. Sharing it was
> the right move — two `INSERT`s into `user_tenant_role` with different conflict handling is
> exactly how PLAN's *"never a parallel code path"* gets violated at the smallest scale — and
> the side effect is that `grant_role` itself is now called only by fixtures.
>
> So the script is measuring the wrong thing here: it asks whether a *name* has a production
> caller, and the honest question is whether a *capability* does. The five are primitives with
> one production path each, through a statement they share. They are kept rather than deleted
> because `disable_user` and `disable_user_in_org` are genuinely different — the latter
> refuses to remove the last administrator, which is wrong for a fixture that needs to disable
> one — and a test suite forced through the administrative path would be a test suite that
> cannot set up the states it exists to test.
>
> **What should replace it:** a criterion that the *routes* exist and are exercised, which is
> the twelfth above. The script stays useful for finding the next instance; it is not the
> definition of this one being fixed.
