//! Two pollers, one database, counted by samples — M12 §3.
//!
//! # Why this is the version of the claim that cannot be argued with
//!
//! The lease already has a test: sixteen processes race for it and one wins. That proves
//! the *election*. It does not prove the thing an operator actually cares about, which is
//! that running a second poller does not double the SNMP load on their fleet and does not
//! write every sample twice — and a duplicated sample is worse than a duplicated packet,
//! because every rate computed from `metrics` is then wrong rather than merely doubled.
//!
//! So this counts rows in `ClickHouse`, which is the product.
//!
//! # And the control, which is the part that makes it evidence
//!
//! A test that ran two leased pollers and found N samples would pass equally well if the
//! second poller were broken, mis-seeded, or pointed at nothing. So the same loop runs a
//! second time with the lease gate removed — everything else identical — and the sample
//! count has to go up. **The comparison is the measurement; either half alone is an
//! assertion.**
//!
//! # Why the device is simulated and the databases are not
//!
//! `tests/live.rs` uses the containerised `net-snmp` agent and skips without it. This
//! must not skip: it is an acceptance criterion, and one that only runs on a machine with
//! a particular container started is one that stops being run.
//!
//! What is under test is the *lease*, and the lease is a row in `PostgreSQL` and its
//! effect is rows in `ClickHouse`. Both of those are real here. The device is
//! `uops_snmp::sim`, which is what `TransportSource` exists for — see its own docs: *"the
//! something else that matters is the simulator"*. Simulating it also makes the
//! measurement mean something, because a simulated agent answers in microseconds and
//! cannot be the reason one poller wrote fewer samples than two.
//!
//! ```bash
//! DATABASE_URL=postgres://uops:uops@localhost:5432/uops \
//!   CLICKHOUSE_DB=uops CLICKHOUSE_USER=uops CLICKHOUSE_PASSWORD=uops \
//!   cargo test -p uops-poller --test lease
//! ```
//!
//! # Why it gets a database of its own
//!
//! `reload` reads *every* tenant, deliberately — `uops_store_pg::all_tenant_ids` — so on
//! a shared database this polls whatever every other suite has left lying around, and the
//! sample counts it compares would be somebody else's. The same reason `live.rs` gives.

use std::sync::Arc;
use std::time::Duration;

use uops_core::{CredentialRef, OrgId, ResourceId, SiteId, TenantId};
use uops_poll::poller::{JobKey, Schedule};
use uops_poll::{Executor, Limits};
use uops_snmp::sim::{Agent, Fleet};
use uops_profile::Oid;
use uops_snmp::{Transport, Value};
use uops_store_ch::{ChClient, ChConfig, ChStore};
use uops_store_pg::{Config as PgConfig, PgStore};

use uops_poller::credentials::{CredentialProblem, TransportSource};
use uops_poller::run::{self, Runner};

/// Five minutes of schedule, in one-second slots.
///
/// A built-in profile's interval is sixty seconds and the wheel jitters within it, so this
/// is several polls rather than one — a window of a single interval would make the
/// difference between "once" and "twice" a coin toss.
const SLOTS: usize = 300;

/// The address every simulated device is at. One agent serves them all.
const AGENT: &str = "192.0.2.1:161";

// ---- the simulated fleet -------------------------------------------------------

/// Every device reaches the same simulated agent, and no credential is opened.
///
/// A `TransportSource` rather than a patched `Runner`: this is the seam the poller already
/// has, and using it means the loop under test is the same loop the binary runs. The vault
/// is absent on purpose — what a credential does is `live.rs`'s subject, and a KEK here
/// would be a second thing that could fail for reasons unrelated to the lease.
#[derive(Debug)]
struct Simulated {
    fleet: Arc<Fleet>,
}

impl Simulated {
    fn new() -> Self {
        let mut agent = Agent::empty();
        // `sysUpTime`, which every profile in the product reads and every agent has. One
        // scalar is enough: this counts rows, and a row is a row.
        agent.set(
            "1.3.6.1.2.1.1.3.0".parse::<Oid>().expect("a literal OID"),
            Value::Unsigned(12_345),
        );

        let mut fleet = Fleet::new();
        fleet.insert(AGENT.parse().expect("a literal address"), agent);
        Self {
            fleet: Arc::new(fleet),
        }
    }
}

impl TransportSource for Simulated {
    fn for_device(
        &self,
        _tenant: TenantId,
        _resource: ResourceId,
        _credential: Option<CredentialRef>,
        _timeout: Duration,
    ) -> Result<Arc<dyn Transport>, CredentialProblem> {
        Ok(Arc::clone(&self.fleet) as Arc<dyn Transport>)
    }

    fn retry_failures(&self) -> usize {
        0
    }
}

// ---- a database of this test's own ---------------------------------------------

fn admin_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into())
}

/// A migrated, empty database, and its name so the caller can drop it.
///
/// A near-copy of `live.rs`'s. Shared through a module would need a `tests/common/`, which
/// cargo compiles into every test binary in the crate — and the two differ in what they
/// are *for*, which is the thing that would drift.
struct Scratch {
    store: PgStore,
    name: String,
}

impl Scratch {
    async fn new() -> Self {
        // Not a connection to the scratch database — CREATE DATABASE cannot run inside a
        // transaction and needs some other database to be connected to.
        let admin = PgStore::connect(&PgConfig {
            url: admin_url(),
            ..PgConfig::default()
        })
        .await
        .expect("connect to the admin database");

        // Interpolated, not bound: an identifier cannot be a parameter. A literal prefix
        // plus a UUID with the hyphens removed, so there is nothing reachable here.
        let name = format!("uops_lease_{}", uuid::Uuid::now_v7().simple());
        sqlx::query(&format!(r#"CREATE DATABASE "{name}""#))
            .execute(admin.pool())
            .await
            .expect("create the scratch database");

        let base = admin_url()
            .rsplit_once('/')
            .expect("the database url has a path")
            .0
            .to_owned();
        let store = PgStore::connect(&PgConfig {
            url: format!("{base}/{name}"),
            ..PgConfig::default()
        })
        .await
        .expect("connect to the scratch database");

        sqlx::migrate!("../../migrations")
            .run(store.pool())
            .await
            .expect("migrate the scratch database");

        Self { store, name }
    }

    async fn drop_database(self) {
        let Self { store, name } = self;
        drop(store);
        let admin = PgStore::connect(&PgConfig {
            url: admin_url(),
            ..PgConfig::default()
        })
        .await
        .expect("connect to the admin database");
        let _ = sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{name}" WITH (FORCE)"#))
            .execute(admin.pool())
            .await;
    }
}

/// One tenant with one device, pointed at the simulated agent.
async fn seed(store: &PgStore) -> ResourceId {
    let org = OrgId::new();
    let tenant = TenantId::new();
    let site = SiteId::new();
    let resource = ResourceId::new();
    let slug = tenant.into_uuid().simple().to_string();

    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("lease-org-{slug}"))
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("lease-{slug}"))
        .bind(format!("lease-{slug}"))
        .execute(store.pool())
        .await
        .expect("tenant");
    sqlx::query("INSERT INTO site (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(site.into_uuid())
        .bind(tenant.into_uuid())
        .bind("lease-site")
        .execute(store.pool())
        .await
        .expect("site");
    sqlx::query(
        "INSERT INTO resource (id, tenant_id, site_id, kind, name, status)
         VALUES ($1, $2, $3, 'device', $4, 'up')",
    )
    .bind(resource.into_uuid())
    .bind(tenant.into_uuid())
    .bind(site.into_uuid())
    .bind("sim-rtr-01")
    .execute(store.pool())
    .await
    .expect("resource");

    // The `mgmt_ip` identifier is what makes a resource a *device* — the join in
    // `pollable_devices` is on it, so without this the fleet is empty and the measurement
    // compares two zeroes.
    sqlx::query(
        "INSERT INTO resource_identifier
             (id, tenant_id, resource_id, kind, value, confidence, source)
         VALUES ($1, $2, $3, 'mgmt_ip', $4, 0.80, 'manual')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(tenant.into_uuid())
    .bind(resource.into_uuid())
    .bind(AGENT.split(':').next().expect("an address"))
    .execute(store.pool())
    .await
    .expect("mgmt_ip");

    resource
}

fn metrics() -> ChStore {
    ChStore::new(ChClient::new(ChConfig::from_env()))
}

/// How many samples exist for this resource, across every metric.
async fn samples_for(resource: ResourceId) -> u64 {
    let client = ChClient::new(ChConfig::from_env());
    let result = client
        .run(
            "SELECT count() FROM metrics WHERE resource_id = {resource:UUID} FORMAT TSV",
            &[("resource", resource.into_uuid().to_string())],
        )
        .await
        .expect("query ClickHouse");
    result.body.trim().parse().expect("a count")
}

// ---- the pollers ---------------------------------------------------------------

/// One poller: its own runner, its own wheel, and an identity of its own.
///
/// The identity matters. `uops_store_pg::identity()` is hostname plus pid, so two pollers
/// *in one test process* would claim the lease as the same holder and every renewal would
/// look like the incumbent renewing — which is the failure the lease's own "a restarted
/// process must not inherit its predecessor's claim" note is about. Two processes on one
/// box have different pids; two in one test do not, so the suffix is added by hand.
struct Poller {
    runner: Arc<Runner>,
    schedule: Schedule,
    due: Vec<JobKey>,
    me: String,
}

async fn poller(store: &PgStore, tag: &str) -> Poller {
    let runner = Arc::new(Runner::new(
        store.clone(),
        metrics(),
        Arc::new(Simulated::new()),
        Duration::from_secs(5),
    ));
    let mut schedule = Schedule::new();
    let (added, _) = run::reload(&runner, &mut schedule, 10_000)
        .await
        .expect("reload");
    assert!(
        added >= 1,
        "{tag} has nothing to poll; the join in pollable_devices did not find the device"
    );
    Poller {
        runner,
        schedule,
        due: Vec::new(),
        me: format!("{}-{tag}", uops_store_pg::identity()),
    }
}

/// Drive both pollers for [`SLOTS`] slots, returning how many slots each one worked.
///
/// `leased` is the only difference between the measurement and its control, and it is the
/// same gate `run::serve` has: a process that does not hold the lease sends nothing and
/// does not advance its wheel.
///
/// Written here rather than by calling `serve` because `serve` is a `select!` around two
/// real timers — driving it long enough to collect several samples of a sixty-second job
/// means waiting minutes, and a test nobody runs proves nothing. What this composes is the
/// same two public functions `serve` composes, and saying so is better than implying this
/// drove the binary.
async fn drive(
    store: &PgStore,
    executor: &Executor,
    pollers: &mut [Poller],
    leased: bool,
) -> Vec<usize> {
    let mut worked = vec![0usize; pollers.len()];
    for _ in 0..SLOTS {
        for (n, poller) in pollers.iter_mut().enumerate() {
            if leased {
                // The store, not `runner.store` — `Runner` keeps that private. One pool
                // shared by both is right: two processes share a database, not a
                // connection, and the lease is what tells them apart.
                let claim = store
                    .claim(uops_store_pg::Job::Poll, &poller.me)
                    .await
                    .expect("claim");
                if !claim.is_held() {
                    continue;
                }
            }
            worked[n] += 1;
            run::tick_once(
                &poller.runner,
                executor,
                &mut poller.schedule,
                &mut poller.due,
            )
            .await;
        }
    }
    worked
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_pollers_against_one_database_write_the_samples_of_one() {
    let scratch = Scratch::new().await;
    let store = scratch.store.clone();
    let resource = seed(&store).await;

    store
        .seed_builtin_profiles(&uops_profile::builtin::all().expect("built-ins"))
        .await
        .expect("seed profiles");

    let executor = Executor::new(Limits {
        global: 16,
        per_device: 4,
        device_budget: Duration::from_secs(5),
    });

    // --- with the lease, which is how the product runs ---------------------
    let mut leased = vec![poller(&store, "one").await, poller(&store, "two").await];
    let worked = drive(&store, &executor, &mut leased, true).await;

    // ClickHouse batches; give the insert a moment to be visible.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let with_lease = samples_for(resource).await;

    assert!(
        with_lease > 0,
        "nothing was polled at all in {SLOTS} slots; the comparison below would be \
         between two zeroes"
    );
    // One of them did all the work. Not an assertion about *which* — whoever claims first
    // wins, and that is the design — but about there having been one owner.
    assert!(
        worked[0] == 0 || worked[1] == 0,
        "both pollers held the lease: {worked:?} slots each. Either it is not excluding, \
         or one took over — which it should not, because the incumbent renews every slot"
    );

    // --- without it, which is the control ----------------------------------
    // Same device, same wheel size, same executor, same simulated agent. The only
    // difference is the gate. Fresh wheels, because the two above are mid-interval and a
    // comparison that started them from different phases would measure the phase.
    let mut unleased = vec![poller(&store, "three").await, poller(&store, "four").await];
    drive(&store, &executor, &mut unleased, false).await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    let without_lease = samples_for(resource).await - with_lease;

    println!(
        "M12 §3, measured: {SLOTS} slots × 2 pollers wrote {with_lease} samples with the \
         lease and {without_lease} without it"
    );

    // The claim, as a number. Not an exact factor of two — the wheel jitters and a poll
    // can exhaust its budget, so pinning a ratio would make this a flake detector rather
    // than a measurement. What must hold is that removing the lease writes materially
    // more, which is the only shape in which "the lease is doing something" is evidence.
    assert!(
        without_lease > with_lease,
        "removing the lease wrote {without_lease} samples against {with_lease} with it. \
         The control did not exceed the measurement, so this is not measuring the lease — \
         check that both pollers loaded the fleet and that the simulated agent answered"
    );

    scratch.drop_database().await;
}
