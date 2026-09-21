//! One trace, across two signals — M8 §2.5.
//!
//! ```text
//!   spans.trace_id  ─┐
//!                    ├─ the same 32 hex characters, written by the same function
//!   logs.trace_id   ─┘
//! ```
//!
//! # There is no join, and that is the point
//!
//! `logs.trace_id` has been a column since M3 and `uops_otlp::logs` has populated it for
//! as long — the other end of it was simply missing until M8 stored spans. So *"the logs
//! emitted during this trace"* is not a new capability and needs no new machinery: it is
//! the ordinary log query with one more predicate, compiled by the same compiler, scoped
//! by the same tenant injection, against a column that is already there.
//!
//! §2.5 is explicit that M8 **must not** build a second, parallel way to relate the two.
//! What this module adds is not a relation; it is two constructors, so that the predicate
//! on either side is written once and cannot drift.
//!
//! # Why two constructors rather than none
//!
//! Three things a caller would otherwise get wrong, and one of them is dangerous.
//!
//! * **An empty id matches everything.** `trace_id` is `''` on every log line that was
//!   never part of a trace — which is every syslog message in the estate. A UI that
//!   passed a missing id through would render the tenant's entire log history under the
//!   heading "logs from this trace", and it would look like a working feature. Refused
//!   here, once, rather than in each caller.
//! * **A trace is not one host's.** A trace crosses services on as many machines, so
//!   these are tenant-wide by construction. Narrowing by resource would silently drop
//!   the half of the trace that ran somewhere else, which is the half you are usually
//!   looking for.
//! * **The two queries must agree on the id.** Both sides go through
//!   `uops_otlp::hex`, so the stored values agree; writing the predicate twice is how
//!   they would stop agreeing later.
//!
//! The window stays the caller's. Whoever opened the trace came from a screen that had
//! one, and inventing a wider one here would turn a click into a retention-window scan.

use crate::ast::{CompareOp, Expr, Field, Query, SignalType, Sort, SortKey, TimeRange, Value};
use crate::error::{Error, Result};

/// The spans of one trace, oldest first.
///
/// Ordered by time because a trace read in any other order is a list of fragments: the
/// root is the earliest span, and the shape of the rest only means something against it.
///
/// # Errors
///
/// An empty or non-hex id. See the module docs for why an empty one is refused rather
/// than passed through.
pub fn trace_spans(trace_id: &str, within: TimeRange) -> Result<Query> {
    Ok(Query::new(SignalType::Trace, within)
        .with_filter(identified_by(Field::TraceId, trace_id)?)
        .with_limit(500)
        .ordered_by(Field::ObservedAt))
}

/// The logs emitted during one trace, oldest first.
///
/// The same predicate against the other table. Nothing here knows that `spans` exists:
/// this is a log query, and it would have compiled identically in M3 — there was just
/// nothing on the other end of the column to ask about.
///
/// # Errors
///
/// As [`trace_spans`].
pub fn trace_logs(trace_id: &str, within: TimeRange) -> Result<Query> {
    Ok(Query::new(SignalType::Log, within)
        .with_filter(identified_by(Field::TraceId, trace_id)?)
        .with_limit(500)
        .ordered_by(Field::ObservedAt))
}

/// One span and its children, for walking a trace a level at a time.
///
/// # Errors
///
/// As [`trace_spans`].
pub fn children_of(span_id: &str, within: TimeRange) -> Result<Query> {
    Ok(Query::new(SignalType::Trace, within)
        .with_filter(identified_by(Field::ParentSpanId, span_id)?)
        .with_limit(500)
        .ordered_by(Field::ObservedAt))
}

/// `field = <id>`, with the id checked before it becomes a predicate.
///
/// Bound as a `Value::Str` deliberately. A 32-character trace id parses as a UUID and the
/// compiler would bind it back to a string anyway — see `compile::bind_for` — but saying
/// so here means this predicate does not depend on that repair to be correct.
fn identified_by(field: Field, id: &str) -> Result<Expr> {
    let id = id.trim();
    if id.is_empty() {
        return Err(Error::Invalid(format!(
            "an empty {} matches every row that was never part of a trace; \
             ask for those directly if that is the question",
            field.label()
        )));
    }
    // OTLP carries these as raw bytes and every tool in the ecosystem prints them as
    // lower-case hex. Anything else did not come from a trace, and letting it through
    // would turn a typo into a query that reads the window and finds nothing.
    if !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Invalid(format!(
            "{} is 16 or 32 hexadecimal characters; {id:?} is not an id",
            field.label()
        )));
    }

    Ok(Expr::Compare {
        field,
        cmp: CompareOp::Eq,
        // Lower-cased, because that is how both decoders write the column and
        // `ClickHouse` compares strings byte for byte. An id pasted from a tool that
        // prints upper-case hex would otherwise match nothing, silently.
        value: Value::Str(id.to_ascii_lowercase()),
    })
}

impl Query {
    /// Oldest first on one column, replacing whatever order was there.
    #[must_use]
    fn ordered_by(mut self, field: Field) -> Self {
        self.order_by = vec![Sort {
            key: SortKey::Field { field },
            desc: false,
        }];
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone as _, Utc};

    fn window() -> TimeRange {
        let start = Utc
            .timestamp_opt(1_700_000_000, 0)
            .single()
            .expect("an instant");
        TimeRange::new(start, start + chrono::Duration::hours(1))
    }

    const TRACE: &str = "4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b";

    #[test]
    fn both_sides_carry_the_same_predicate() {
        // The whole of the correlation. If these two ever stop matching, the join returns
        // nothing and looks like a trace that happened to log nothing — which is a
        // plausible thing for a trace to do, and therefore the failure nobody notices.
        let spans = trace_spans(TRACE, window()).expect("a query");
        let logs = trace_logs(TRACE, window()).expect("a query");

        assert_eq!(spans.signal, SignalType::Trace);
        assert_eq!(logs.signal, SignalType::Log);
        assert_eq!(spans.filter, logs.filter);
    }

    #[test]
    fn an_empty_id_is_refused_rather_than_matching_every_untraced_log() {
        // `trace_id` is `''` on every syslog line ever written. A UI passing a missing id
        // through would render the tenant's whole log history under the heading "logs
        // from this trace", and it would look like it worked.
        for id in ["", "   "] {
            assert!(matches!(trace_logs(id, window()), Err(Error::Invalid(_))));
            assert!(matches!(trace_spans(id, window()), Err(Error::Invalid(_))));
        }
    }

    #[test]
    fn an_id_that_is_not_hexadecimal_is_not_an_id() {
        // A typo, or a name pasted into the wrong box. Refusing beats a query that reads
        // the window and reports that the trace does not exist.
        assert!(matches!(
            trace_spans("checkout", window()),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn an_id_pasted_in_upper_case_still_matches() {
        // Some tools print them that way. `ClickHouse` compares strings byte for byte, so
        // without this the query is valid, fast and empty.
        let upper = trace_spans(&TRACE.to_ascii_uppercase(), window()).expect("a query");
        let lower = trace_spans(TRACE, window()).expect("a query");
        assert_eq!(upper.filter, lower.filter);
    }

    #[test]
    fn a_trace_is_read_oldest_first() {
        // The root span is the earliest one, and the rest only mean something against it.
        let q = trace_spans(TRACE, window()).expect("a query");
        assert_eq!(q.order_by.len(), 1);
        assert!(!q.order_by[0].desc);
    }

    #[test]
    fn a_trace_is_never_narrowed_to_one_resource() {
        // It crosses services on as many machines. Narrowing would drop the half that ran
        // somewhere else, which is usually the half being looked for.
        let q = trace_spans(TRACE, window()).expect("a query");
        assert_eq!(q.resources, crate::ast::ResourceSelector::All);
    }

    #[test]
    fn the_children_of_a_span_are_found_by_its_id() {
        let q = children_of("0000000000000001", window()).expect("a query");
        assert!(matches!(
            q.filter,
            Some(Expr::Compare {
                field: Field::ParentSpanId,
                ..
            })
        ));
    }
}
