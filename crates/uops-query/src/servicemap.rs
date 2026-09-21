//! The service map — M8 §2.6, and the one physical query the AST cannot express.
//!
//! ```text
//!   span in service A  ──parent of──▶  span in service B
//!   └──────────────────── one edge ────────────────────┘
//! ```
//!
//! # Derived, never configured
//!
//! §2.6: *"a parent span in service A with a child in service B **is** an edge, and there
//! is no second source of truth to reconcile."* Nothing is stored, nothing is declared,
//! and no operator maintains a list. An edge exists while the calls exist and stops
//! existing when they stop — which is the same honesty M6 asked of topology, where the
//! edges are evidence rather than assertion.
//!
//! # Why this is not a `Query`
//!
//! §2.4 says the map is computed from the aggregate. `service_5m` cannot answer it:
//! aggregating per service per operation throws the parent away, and an edge is a
//! *relationship between two rows*. So it is a self-join on `spans`, and the AST has no
//! joins.
//!
//! Rather than grow one, this is a second entry point beside [`crate::compile_tail`] —
//! which exists for the same reason and takes the same shape: a different physical query,
//! built by the same `Builder`, so every literal is still bound and the tenant predicate
//! is still written from the scope rather than by a caller.
//!
//! Adding `JOIN` to the AST would mean the planner, the golden files, the saved searches
//! and the alert rules all inheriting a construct exactly one screen needs.
//!
//! # The tenant appears twice, and that is a security property
//!
//! A span id is eight bytes chosen by whoever instrumented the application. A tenant can
//! therefore *choose* a span id that collides with another tenant's — it costs them
//! nothing and nothing rejects it. If the join's right-hand side were not itself
//! restricted to the tenant, a crafted span id would attach one customer's service to
//! another customer's map.
//!
//! So the parent side is a subquery with its own tenant predicate rather than a second
//! alias filtered in the outer `WHERE`. See the adversarial test in
//! `uops-store-ch/tests/telemetry.rs`.
//!
//! # What it costs, and what has not been measured
//!
//! A hash join over every span in the window. The right-hand side carries two columns, so
//! it is the row count rather than the width that decides, and the window is the screen's
//! — minutes or an hour, not the retention period.
//!
//! **It has not been measured at scale.** §2.2 sets the standard for that kind of claim
//! and this does not meet it yet: the number to record is the rows read for a map over an
//! hour at 100M spans. If it disappoints, the answer is the one every APM product
//! reaches for — a materialised view keyed on `(parent_span_id)` maintained at insert
//! time — and it is not free, because a child can arrive before its parent.

use chrono::{DateTime, Utc};
use uops_core::TenantScope;

use crate::compile::{Compiled, TS_PARAM, fmt_ts};
use crate::error::{Error, Result};
use crate::sql::Builder;

/// The most edges a map will return.
///
/// A service map is read by eye. Beyond a few hundred edges nobody is reading a map, they
/// are looking at a hairball — and the edges past this point are the rare ones, because
/// the statement orders by call volume.
pub const MAX_EDGES: u32 = 500;

/// Compile the service map for one window.
///
/// The result has one row per ordered pair of services that called each other, with how
/// often, how often it failed, and how slow the calls were.
///
/// # Errors
///
/// An empty or backwards window, which is the caller's mistake and not a map with no
/// edges in it.
pub fn compile_service_map(
    scope: &TenantScope,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    limit: u32,
) -> Result<Compiled> {
    if end <= start {
        return Err(Error::Invalid(
            "time range must be non-empty and forward: start < end".into(),
        ));
    }
    let limit = limit.clamp(1, MAX_EDGES);
    let tenant = scope.tenant_id().to_string();

    let mut b = Builder::new();
    b.push(
        "SELECT parent.service_id AS from_service, child.service_id AS to_service, \
         count() AS calls, countIf(child.status_code = 'error') AS errors, \
         toUInt64(quantileTDigest(0.95)(child.duration_ns)) AS p95 FROM spans AS child \
         INNER JOIN (SELECT span_id, service_id FROM spans WHERE tenant_id = ",
    );
    // The parent side carries its own tenant predicate. See the module docs: a span id is
    // caller-chosen, so a join that trusted it would be a cross-tenant read.
    b.bind("UUID", tenant.clone());
    b.push(" AND observed_at >= ");
    b.bind(TS_PARAM, fmt_ts(start));
    b.push(" AND observed_at < ");
    b.bind(TS_PARAM, fmt_ts(end));
    // A service that did not resolve is the nil uuid, and every unidentified service
    // shares it. Drawn, it is one node that looks like a real service and is the union of
    // all the ones we could not name.
    b.push(" AND service_id != toUUID('00000000-0000-0000-0000-000000000000')");
    b.push(") AS parent ON child.parent_span_id = parent.span_id WHERE child.tenant_id = ");
    b.bind("UUID", tenant);
    b.push(" AND child.observed_at >= ");
    b.bind(TS_PARAM, fmt_ts(start));
    b.push(" AND child.observed_at < ");
    b.bind(TS_PARAM, fmt_ts(end));
    // A root span has no parent, and an empty id must not be allowed to match anything.
    b.push(" AND child.parent_span_id != ''");
    b.push(" AND child.service_id != toUUID('00000000-0000-0000-0000-000000000000')");
    // The map is about calls that cross a boundary. A span whose parent is in the same
    // service is the service calling itself, which is a flame graph and not a map.
    b.push(" AND child.service_id != parent.service_id");
    b.push(" GROUP BY from_service, to_service ORDER BY calls DESC LIMIT ");
    // From a `u32` that was clamped above, not from caller text.
    b.push(&limit.to_string());

    Ok(Compiled {
        sql: b.finish(),
        warnings: Vec::new(),
        table: "spans",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
    use uops_core::TenantId;

    fn scope() -> TenantScope {
        TenantScope::system(TenantId::from_uuid(
            "018f0000-0000-7000-8000-000000000001"
                .parse()
                .expect("a uuid"),
        ))
    }

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).single().expect("an instant")
    }

    fn map() -> Compiled {
        compile_service_map(&scope(), at(0), at(3600), 50).expect("a statement")
    }

    #[test]
    fn the_tenant_is_filtered_on_both_sides_of_the_join() {
        // The security property. A span id is eight bytes chosen by whoever instrumented
        // the application, so a tenant can pick one that collides with another tenant's.
        // Without the predicate on the *parent* subquery, that crafted id would attach one
        // customer's service to another customer's map.
        let sql = map().sql;
        let tenant_predicates = sql.text().matches("tenant_id = {").count();
        assert_eq!(
            tenant_predicates,
            2,
            "both sides must be scoped: {}",
            sql.text()
        );
        assert_eq!(
            sql.params().values().filter(|p| p.ty == "UUID").count(),
            2,
            "and both from the scope"
        );
    }

    #[test]
    fn every_literal_is_bound() {
        // The same guarantee `compile` makes, restated for the entry point that does not
        // go through it. The only things written into the text are keywords, column names
        // and a clamped integer.
        let sql = map().sql;
        assert!(!sql.text().contains("018f0000"), "{}", sql.text());
        for p in sql.params().values() {
            assert!(!sql.text().contains(&p.value), "{}", sql.text());
        }
    }

    #[test]
    fn a_root_span_is_not_an_edge_from_nowhere() {
        // `parent_span_id` is empty on a root. Joined without this, an empty id would be
        // a key like any other.
        assert!(map().sql.text().contains("child.parent_span_id != ''"));
    }

    #[test]
    fn a_service_calling_itself_is_not_an_edge() {
        // That is a flame graph, not a map — and drawn, it is a loop on every node.
        assert!(
            map()
                .sql
                .text()
                .contains("child.service_id != parent.service_id")
        );
    }

    #[test]
    fn the_unidentified_service_is_not_a_node() {
        // Every service that did not resolve shares the nil uuid. One node that all of
        // them collapse into looks like a real service and is not.
        assert_eq!(
            map()
                .sql
                .text()
                .matches("!= toUUID('00000000-0000-0000-0000-000000000000')")
                .count(),
            2,
            "on both sides of the edge"
        );
    }

    #[test]
    fn a_backwards_window_is_the_callers_mistake() {
        // Rather than a map with no edges, which is what a service that stopped talking
        // looks like — and the two must not be indistinguishable.
        assert!(matches!(
            compile_service_map(&scope(), at(3600), at(0), 50),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            compile_service_map(&scope(), at(0), at(0), 50),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn the_edge_count_is_clamped_rather_than_trusted() {
        // It reaches the statement text as an integer, so it is the one number that has
        // to be bounded here rather than by the server.
        let huge = compile_service_map(&scope(), at(0), at(3600), u32::MAX).expect("a statement");
        assert!(
            huge.sql.text().ends_with(&format!("LIMIT {MAX_EDGES}")),
            "{}",
            huge.sql.text()
        );
        let none = compile_service_map(&scope(), at(0), at(3600), 0).expect("a statement");
        assert!(none.sql.text().ends_with("LIMIT 1"), "{}", none.sql.text());
    }

    #[test]
    fn the_busiest_edges_come_first() {
        // A map is read by eye, and the ones past the limit should be the rare ones.
        assert!(map().sql.text().contains("ORDER BY calls DESC"));
    }

    #[test]
    fn every_timestamp_carries_a_timezone() {
        // The bug that cost a day in M7: `{p:DateTime64(3)}` is parsed in the *server's*
        // timezone, and the columns are UTC. Four timestamps here, all through TS_PARAM.
        let sql = map().sql;
        assert_eq!(
            sql.params().values().filter(|p| p.ty == TS_PARAM).count(),
            4
        );
        assert!(!sql.text().contains("DateTime64(3)}"), "{}", sql.text());
    }
}
