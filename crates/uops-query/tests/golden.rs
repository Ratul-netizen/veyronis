//! Golden-file codegen tests — SPEC §M0.5 requirement 5.
//!
//! Each `tests/golden/<name>.json` is a `Query` exactly as the API would receive it.
//! Each `tests/golden/<name>.sql` is the statement, parameters, chosen table and
//! warnings it compiles to. Every codegen change diffs against these.
//!
//! This is how the AST stays trustworthy while `ClickHouse` syntax moves underneath it
//! — the text index reached GA in March 2026 and its syntax changed during the beta, so
//! "the SQL we emit" is a moving target that needs to be *visible* when it moves. A
//! reviewer who cannot see the emitted SQL in a diff cannot review the change.
//!
//! Regenerate after an intentional change, then read the diff:
//!
//! ```text
//! UPDATE_GOLDEN=1 cargo test -p uops-query --test golden
//! ```
//!
//! Fixtures named `tail_*` compile through [`uops_query::compile_tail`].

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use uops_core::{ResourceId, ResourceKind, SiteId, TenantId, TenantScope};
use uops_query::{Query, ResourceCatalog, compile, compile_tail, resolve};

/// Fixed so the golden files are stable. A `UUIDv7` prefix, because every real ID is.
const TENANT: &str = "018f0000-0000-7000-8000-000000000001";
const RESOURCES: [&str; 3] = [
    "018f0000-0000-7000-8000-0000000000aa",
    "018f0000-0000-7000-8000-0000000000bb",
    "018f0000-0000-7000-8000-0000000000cc",
];

/// Resolves to the same three resources however it is asked, so a fixture can exercise
/// any selector without the expected SQL depending on catalog behaviour.
struct FixedCatalog;

impl FixedCatalog {
    fn all() -> Vec<ResourceId> {
        RESOURCES
            .iter()
            .map(|s| ResourceId::from_uuid(s.parse().unwrap()))
            .collect()
    }
}

#[async_trait]
impl ResourceCatalog for FixedCatalog {
    async fn canonical(
        &self,
        _t: TenantId,
        ids: &[ResourceId],
    ) -> uops_query::Result<Vec<ResourceId>> {
        Ok(ids.to_vec())
    }
    async fn of_kind(&self, _t: TenantId, _k: ResourceKind) -> uops_query::Result<Vec<ResourceId>> {
        Ok(Self::all())
    }
    async fn at_site(&self, _t: TenantId, _s: SiteId) -> uops_query::Result<Vec<ResourceId>> {
        Ok(Self::all())
    }
    async fn in_group(
        &self,
        _t: TenantId,
        _g: uops_core::ResourceGroupId,
    ) -> uops_query::Result<Vec<ResourceId>> {
        Ok(Self::all())
    }
    async fn tagged(
        &self,
        _t: TenantId,
        _k: &str,
        _v: &str,
    ) -> uops_query::Result<Vec<ResourceId>> {
        Ok(Self::all())
    }
    async fn descendants(
        &self,
        _t: TenantId,
        root: ResourceId,
        _d: u8,
    ) -> uops_query::Result<Vec<ResourceId>> {
        let mut v = Self::all();
        v.retain(|r| *r != root);
        v.insert(0, root);
        Ok(v)
    }
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// Statement, parameters, chosen table and warnings — everything a reviewer needs to
/// judge a codegen change without running `ClickHouse`.
async fn render(path: &Path) -> String {
    let json = fs::read_to_string(path).unwrap();
    let q: Query = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("{} is not a valid Query: {e}", path.display()));

    let scope = TenantScope::system(TenantId::from_uuid(TENANT.parse().unwrap()));
    let resources = resolve(&q.resources, &scope, &FixedCatalog).await.unwrap();

    let is_tail = path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("tail_");
    let out = if is_tail {
        compile_tail(&q, &scope, &resources)
    } else {
        compile(&q, &scope, &resources)
    }
    .unwrap_or_else(|e| panic!("{} failed to compile: {e}", path.display()));

    let mut s = out.sql.to_golden();
    let _ = write!(s, "\n-- table: {}\n", out.table);
    if out.warnings.is_empty() {
        s.push_str("-- warnings: none\n");
    } else {
        s.push_str("-- warnings:\n");
        for w in &out.warnings {
            let _ = writeln!(s, "--   {}", w.message());
        }
    }
    s
}

#[tokio::test]
async fn every_fixture_matches_its_golden_file() {
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    let mut fixtures: Vec<PathBuf> = fs::read_dir(golden_dir())
        .expect("tests/golden must exist")
        .filter_map(|e| {
            let p = e.ok()?.path();
            (p.extension()? == "json").then_some(p)
        })
        .collect();
    fixtures.sort();

    assert!(
        fixtures.len() >= 8,
        "the golden suite must cover the query shapes W1 measured, not one example"
    );

    let mut failures = Vec::new();
    for f in &fixtures {
        let actual = render(f).await;
        let expected_path = f.with_extension("sql");

        if update {
            fs::write(&expected_path, &actual).unwrap();
            continue;
        }

        let expected = fs::read_to_string(&expected_path).unwrap_or_else(|_| {
            panic!(
                "missing {}; run UPDATE_GOLDEN=1 cargo test -p uops-query --test golden",
                expected_path.display()
            )
        });
        // Written on Windows, read on Linux CI.
        if expected.replace("\r\n", "\n") != actual.replace("\r\n", "\n") {
            failures.push(format!(
                "--- {} ---\nexpected:\n{expected}\nactual:\n{actual}",
                f.file_name().unwrap().to_string_lossy()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "codegen changed for {} fixture(s):\n\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        !update,
        "UPDATE_GOLDEN was set; goldens rewritten, re-run to verify"
    );
}

/// The parameter name the tenant predicate uses. Not always `p0`: a group key that is
/// a map lookup binds its key in the SELECT list, before the WHERE clause is written.
fn tenant_placeholder(sql: &str) -> Option<String> {
    let rest = sql.split_once("WHERE tenant_id = {")?.1;
    let name = rest.split_once(':')?.0;
    Some(name.to_owned())
}

#[test]
fn every_golden_statement_filters_by_tenant() {
    // The same invariant the unit tests assert, re-checked against the *recorded*
    // output. A regression that removed the tenant predicate would have to survive
    // both this and a visible diff in the .sql files.
    for f in fs::read_dir(golden_dir()).unwrap() {
        let p = f.unwrap().path();
        if p.extension().is_none_or(|e| e != "sql") {
            continue;
        }
        let sql = fs::read_to_string(&p).unwrap();
        let bound = tenant_placeholder(&sql)
            .unwrap_or_else(|| panic!("{} has no tenant predicate", p.display()));
        assert!(
            sql.contains(&format!("{bound} UUID = {TENANT}")),
            "{} binds {bound} to something other than the tenant",
            p.display()
        );
    }
}

#[test]
fn no_timestamp_parameter_is_left_without_a_timezone() {
    // A `DateTime64(3)` parameter carries no timezone, so ClickHouse parses its text in
    // the *server's* timezone — while every telemetry column is `DateTime64(3, 'UTC')`.
    // On a server that is not running UTC the two disagree by the offset and a window
    // query silently returns the wrong rows, or none: no error, just an empty graph.
    //
    // This is checked against the recorded SQL rather than by running a query, because
    // the bug is invisible on a UTC server — which the pinned image in
    // deploy/docker-compose.yml is, which is exactly why it went unnoticed until the
    // suite was first run against a ClickHouse on America/New_York.
    for f in fs::read_dir(golden_dir()).unwrap() {
        let p = f.unwrap().path();
        if p.extension().is_none_or(|e| e != "sql") {
            continue;
        }
        let sql = fs::read_to_string(&p).unwrap();
        for (n, line) in sql.lines().enumerate() {
            assert!(
                !line.contains("DateTime64(3)"),
                "{}:{} emits a timezone-less DateTime64(3); bind TS_PARAM instead\n  {line}",
                p.display(),
                n + 1,
            );
        }
    }
}

/// The correlation fixture and `trace_logs` must compile to the same statement.
///
/// Not to the same AST — and that difference is the finding. `Value` is untagged, so the
/// fixture's `"4b4b…"` deserialises to `Value::Uuid` while the helper constructs
/// `Value::Str`, and the two are not equal. They compile identically because
/// `compile::bind_for` binds by the *column*, which is exactly the repair that makes a
/// 32-hex trace id safe to compare against a `String` column however it arrived.
///
/// So this asserts the property that matters. Without it the `.sql` beside the fixture
/// is a review of the wrong statement: the file would keep passing while `trace_logs`
/// drifted away from it, and the drift would surface as a trace that appears to have
/// logged nothing — a plausible thing for a trace to do, and therefore the failure
/// nobody notices.
#[tokio::test]
async fn the_correlation_fixture_compiles_to_what_the_helper_does() {
    const TRACE: &str = "4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b";

    let path = golden_dir().join("logs_during_a_trace.json");
    let fixture: Query = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let built = uops_query::trace_logs(TRACE, fixture.time).expect("a log query");

    assert_ne!(
        built.filter, fixture.filter,
        "if these ever become equal, the untagged-UUID hazard is gone and this test          should say something simpler"
    );

    let scope = TenantScope::system(TenantId::from_uuid(TENANT.parse().unwrap()));
    let resources = resolve(&built.resources, &scope, &FixedCatalog)
        .await
        .unwrap();
    let statement = compile(&built, &scope, &resources).unwrap().sql.to_golden();

    let golden = fs::read_to_string(path.with_extension("sql")).unwrap();
    assert!(
        golden.starts_with(&statement),
        "the helper compiles to
{statement}
but the golden file holds
{golden}"
    );
}
