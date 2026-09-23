# Service level objectives, and the number this product refuses to print

**Status:** decisions, closed before building. Scoped as `docs/PRODUCT-STRATEGY.md`
**Stage 2**, taken early alongside Stage 1b.

**Prepared:** 23 September 2026.

---

## 1. What an SLO is here

A target, a window, and an indicator the product can already compute:

```text
  99.5%  of requests succeeded,  over  30 days
  ─────                          ────  ───────
  target        indicator              window
```

Motadata documents SLO as a module of its own, and it is one of the five capabilities
`docs/PRODUCT-STRATEGY.md` §2 lists as absent here. It is also the cheapest of them,
because the arithmetic is a ratio over `service_5m` — a table that has existed since M8 and
already carries `requests` and `errors` per five-minute bucket with a 365-day TTL.

**No new collection, no new table in `ClickHouse`, no new signal.** One control-plane table
holding the definition, and a ratio.

---

## 2. The decisions

### 2.1 Request-based first; availability SLOs wait, and the reason is already written down

An SLO needs an indicator. This product can compute two:

* **request success rate** — `(requests - errors) / requests` from `service_5m`, exact
  arithmetic over data that is already aggregated;
* **availability** — time up over total time, from the `states` signal.

**Only the first is built.** The second is not deferred for effort; it is deferred because
the product has already decided, in writing, that it cannot yet compute the number
honestly. `web/src/overview.tsx` refuses to draw a health percentage:

> There is no defensible formula for it yet — availability with maintenance windows
> excluded is M9 — and a number nobody can explain is worse than an absent one on the
> screen an operator trusts first.

An availability SLO is that same number with a target attached. Shipping it before the
formula is defensible would put the unexplainable number on a contract instead of a
dashboard, which is worse. Maintenance windows exist (M4), the `states` signal exists, and
time-weighting across them is the missing piece.

### 2.2 The ratio is sound over a sample; the count is not

**This is the decision that shapes the whole screen.**

Traces are sampled upstream of this product — head sampling in the SDK, tail sampling in a
collector — and an unsampled span is simply absent. `web/src/services.ts` already draws the
distinction this needs:

> the count columns are headed "sampled" and carry a footnote, and the latency columns carry
> neither — because a percentile over a sample really is an estimate of the percentile over
> everything, and marking it would teach a reader to distrust the one number they can rely
> on.

A **ratio** behaves like a percentile, not like a count. `errors / requests` over an
unbiased sample estimates the same ratio over everything, so an SLI of 99.4% is a
defensible number. So is a **burn rate**, which is a ratio of ratios.

An **error budget in events is not.** "You have 4 213 errors remaining this month" requires
knowing how many requests there actually were, and this product does not know the sampling
denominator. So:

> **The product prints the SLI, the target, the burn rate and the budget as a
> *proportion*. It does not print a remaining error count.**

That is the number every competitor shows and this one will not, and the reason is
specific rather than squeamish: the denominator is unknown.

### 2.3 The window is a rolling window, and it is stored in days

Rolling, not calendar. A calendar month resets the budget at midnight on the first, which
is when an outage on the 31st stops mattering — the arithmetic says so and nobody believes
it. Rolling windows are what an operator actually reasons about.

Days rather than an interval type: the windows people set are 7, 28 and 30 days, and an
SLO with a window of four hours is a monitor, not an objective. A `CHECK` bounds it to
between 1 and 90 days — 90 because `service_5m` has a 365-day TTL and a window longer than
a quarter is a business report rather than an operational instrument.

### 2.4 An objective is not an alert rule, and it does not become one automatically

An SLO describes a target. An alert rule fires. This ships the first and deliberately not
the second, for the reason M11 §1 gives about detections: **the thresholds that matter are
the organisation's, not the product's.** Multi-window multi-burn-rate alerting is the
right pattern and it needs the operator to choose the windows.

What makes this a seam rather than a gap: the burn rate is a number over a `Query`, and an
alert rule is a threshold over a `Query`. When burn-rate alerting is built it is a rule
whose query is the one this screen already runs — not a second evaluation path.

> **Said plainly: an SLO here is a measurement, not a guarantee, and nothing pages anybody
> when it is missed.** A product that implied otherwise would be selling a promise it does
> not keep.

### 2.5 An SLO is attached to a service, not to a resource

A service is where request success rate is defined, and `service_5m` is keyed by
`service_id`. A resource — a switch — has availability, not a success rate, and that is
§2.1's number.

The service is stored by id and may not exist in the inventory: a service appears in
`service_5m` as soon as a span carries it, and the inventory row arrives separately.
Refusing an SLO for a service the inventory has not yet caught up with would be refusing to
measure something that is demonstrably running.

### 2.6 What this will not claim

* **A remaining error count.** §2.2.
* **That the SLI covers unsampled traffic exactly.** It estimates it, and the screen says
  the word "sampled" where the number comes from.
* **That a met objective means users were happy.** An SLO measures what was instrumented.
* **Anything about a window with no traffic in it.** A service with no sampled requests has
  no success rate — `null`, not 100%. A service nobody called did not succeed.

---

## 3. What is built

* Migration **0029** — one `slo` table, tenant-scoped.
* `uops_store_pg::slo` — CRUD.
* Routes under `/api/v1/slos`, in `isolation.rs` like every other surface.
* A screen under **Observability**, beside Services, computing the SLI in the client from
  the same `Query` AST the Services screen uses.

**Why the arithmetic is in the client**: the SLI is a ratio of two columns the query
already returns, and putting it server-side would mean a second code path computing what
the Services screen computes. SPEC §M0.5 — the UI builds the AST — already puts this
class of work there. When burn-rate *alerting* arrives it moves server-side, because an
evaluator cannot ask a browser.

## 4. What is not

Availability SLOs (§2.1), burn-rate alerting (§2.4), error budget policies, and multi-window
alerting. Each needs a decision of its own, and the first two are the ones with a written
precondition rather than a preference.
