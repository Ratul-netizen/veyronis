//! The collector, end to end: a UDP datagram in, a row in `ClickHouse` out.
//!
//! This is the test the decoders' byte-array suites cannot be. They prove a packet is
//! read correctly; this proves the packet reaches a socket bound to the right tenant, the
//! exporter becomes a resource, and the row lands in the table the migration created.
//!
//! Needs both databases. `docs/dev-environment.md` says how to have them.

use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;

use uops_collector_flow::config::{Config, Listener};
use uops_collector_flow::run;
use uops_store_ch::{ChClient, ChConfig, ChStore, TelemetryStore};
use uops_store_pg::PgStore;

async fn postgres() -> PgStore {
    let config = uops_store_pg::Config {
        url: std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://uops@127.0.0.1:5432/uops".into()),
        ..uops_store_pg::Config::default()
    };
    PgStore::connect(&config).await.expect("PostgreSQL")
}

fn ch_config() -> ChConfig {
    ChConfig {
        user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "uops".into()),
        password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "uops".into()),
        ..ChConfig::from_env()
    }
}

/// A tenant of this test's own, so a run never sees another's rows.
///
/// Inserted directly, the way the sweeper's tests do: there is no repository call that
/// creates an organization and a tenant together, and a test that reached for one would
/// be inventing API surface for its own convenience.
async fn tenant(store: &PgStore, prefix: &str) -> (uops_core::TenantId, String) {
    let org = uops_core::OrgId::new();
    let tenant = uops_core::TenantId::new();
    let slug = format!("{prefix}-{}", tenant.into_uuid().simple());

    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("flow-org-{slug}"))
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("flow-{slug}"))
        .bind(&slug)
        .execute(store.pool())
        .await
        .expect("tenant");

    (tenant, slug)
}

/// The wall clock, as a v5 header spells it.
///
/// v5 carries seconds in a `u32`, which runs out in 2106. `try_from` rather than `as`
/// because the fixture should say what it assumes rather than truncate quietly — and
/// because a test that outlives the protocol deserves to fail loudly.
fn export_seconds() -> u32 {
    u32::try_from(chrono::Utc::now().timestamp()).expect("a timestamp that fits in a v5 header")
}

/// One `NetFlow` v5 datagram with a single record.
fn v5_packet(uptime_ms: u32, export_secs: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&5u16.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes()); // one record
    p.extend_from_slice(&uptime_ms.to_be_bytes());
    p.extend_from_slice(&export_secs.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes()); // unix_nsecs
    p.extend_from_slice(&1u32.to_be_bytes()); // sequence
    p.push(0); // engine type
    p.push(0); // engine id
    p.extend_from_slice(&0u16.to_be_bytes()); // sampling: mode 0

    let mut r = [0u8; 48];
    r[0..4].copy_from_slice(&[10, 0, 0, 7]);
    r[4..8].copy_from_slice(&[8, 8, 8, 8]);
    r[12..14].copy_from_slice(&11u16.to_be_bytes());
    r[14..16].copy_from_slice(&22u16.to_be_bytes());
    r[16..20].copy_from_slice(&42u32.to_be_bytes()); // packets
    r[20..24].copy_from_slice(&6000u32.to_be_bytes()); // octets
    r[24..28].copy_from_slice(&(uptime_ms - 5_000).to_be_bytes());
    r[28..32].copy_from_slice(&(uptime_ms - 1_000).to_be_bytes());
    r[32..34].copy_from_slice(&51_000u16.to_be_bytes());
    r[34..36].copy_from_slice(&443u16.to_be_bytes());
    r[37] = 0x18; // tcp flags
    r[38] = 6; // protocol
    p.extend_from_slice(&r);
    p
}

async fn scalar(sql: &str) -> String {
    ChClient::new(ch_config())
        .run(&format!("{sql} FORMAT TSV"), &[])
        .await
        .expect("the statement should run")
        .body
        .trim()
        .to_owned()
}

/// Bind on an ephemeral port so tests can run beside each other.
fn free_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a free port");
    socket.local_addr().expect("its address")
}

/// A resource in `tenant`, already claiming `address` as its management IP.
///
/// Inserted directly for the same reason the tenant is: the point of the test below is
/// what the collector does with an identifier that already exists, not how it came to.
async fn resource_at(
    store: &PgStore,
    tenant: uops_core::TenantId,
    address: &str,
    name: &str,
) -> uops_core::ResourceId {
    let resource = uops_core::ResourceId::new();

    sqlx::query(
        "INSERT INTO resource (id, tenant_id, kind, name, status) \
         VALUES ($1, $2, 'device', $3, 'up')",
    )
    .bind(resource.into_uuid())
    .bind(tenant.into_uuid())
    .bind(name)
    .execute(store.pool())
    .await
    .expect("resource");

    sqlx::query(
        "INSERT INTO resource_identifier \
             (id, tenant_id, resource_id, kind, value, confidence, source) \
         VALUES ($1, $2, $3, 'mgmt_ip', $4, 1.0, 'manual')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(tenant.into_uuid())
    .bind(resource.into_uuid())
    .bind(address)
    .execute(store.pool())
    .await
    .expect("identifier");

    resource
}

/// The configuration for one listener, so a test says what it is about rather than
/// repeating twenty lines of struct literal.
fn one_listener(slug: String, udp: SocketAddr) -> Config {
    Config {
        listeners: vec![Listener { tenant: slug, udp }],
        postgres: uops_store_pg::Config {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://uops@127.0.0.1:5432/uops".into()),
            ..uops_store_pg::Config::default()
        },
        clickhouse: ch_config(),
        queue: 1024,
        workers: 2,
        // Not enrolled: these tests are about the path from a datagram to a row,
        // and the registry is a separate concern with its own tests in
        // `uops-store-pg/tests/collectors.rs`.
        collector_token: None,
        collector_name: "test".to_owned(),
        receive_buffer: 1 << 20,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_netflow_v5_datagram_becomes_a_row() {
    let store = postgres().await;
    let (tenant_id, slug) = tenant(&store, "flow-v5").await;

    let address = free_port();
    let config = Config {
        listeners: vec![Listener {
            tenant: slug,
            udp: address,
        }],
        postgres: uops_store_pg::Config {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://uops@127.0.0.1:5432/uops".into()),
            ..uops_store_pg::Config::default()
        },
        clickhouse: ch_config(),
        queue: 1024,
        workers: 2,
        collector_token: None,
        collector_name: "test".to_owned(),
        receive_buffer: 1 << 20,
    };

    let telemetry = ChStore::new(ChClient::new(ch_config()));
    telemetry.health().await.expect("ClickHouse");

    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let collector = tokio::spawn(run(config, store.clone(), telemetry, async move {
        let _ = stopped.changed().await;
    }));

    // The socket is bound inside `run`, so give it a moment before sending. A send to a
    // port nothing is listening on is silently discarded, which would make this test
    // fail for a reason that is not the one it is about.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let now = export_seconds();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&v5_packet(10_000_000, now), address)
        .await
        .expect("the datagram should send");

    // Long enough for the batcher's deadline to fire.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let _ = stop.send(true);
    let stats = collector
        .await
        .expect("the collector task")
        .expect("no error");

    assert_eq!(stats.datagrams.load(Relaxed), 1);
    assert_eq!(stats.flows.load(Relaxed), 1);
    assert_eq!(stats.undecodable.load(Relaxed), 0);
    assert_eq!(stats.dropped_queue.load(Relaxed), 0);

    let got = scalar(&format!(
        "SELECT concat(toString(bytes), '/', toString(packets), '/', toString(dst_port), '/', \
         IPv6NumToString(src_address)) FROM flows WHERE tenant_id = '{tenant_id}'"
    ))
    .await;
    assert_eq!(got, "6000/42/443/::ffff:10.0.0.7");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exporter_nobody_registered_gets_a_resource_rather_than_a_dropped_packet() {
    // M7 §2.6 as corrected, and SPEC §M0.2 rule 1. The exporter in this test is a
    // 127.0.0.1 nobody has ever added to inventory, and its flow still arrives —
    // attributed to a resource the pipeline created for it.
    let store = postgres().await;
    let (tenant_id, slug) = tenant(&store, "flow-unknown").await;

    let address = free_port();
    let config = Config {
        listeners: vec![Listener {
            tenant: slug,
            udp: address,
        }],
        postgres: uops_store_pg::Config {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://uops@127.0.0.1:5432/uops".into()),
            ..uops_store_pg::Config::default()
        },
        clickhouse: ch_config(),
        queue: 1024,
        workers: 2,
        collector_token: None,
        collector_name: "test".to_owned(),
        receive_buffer: 1 << 20,
    };

    let telemetry = ChStore::new(ChClient::new(ch_config()));
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let collector = tokio::spawn(run(config, store.clone(), telemetry, async move {
        let _ = stopped.changed().await;
    }));
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let now = export_seconds();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&v5_packet(10_000_000, now), address)
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let _ = stop.send(true);
    collector.await.expect("the task").expect("no error");

    // The row exists and names a real resource — not the nil one, which is what an
    // unresolved exporter would have left.
    let resource = scalar(&format!(
        "SELECT DISTINCT toString(resource_id) FROM flows WHERE tenant_id = '{tenant_id}'"
    ))
    .await;
    assert!(!resource.is_empty(), "no row was written at all");
    assert_ne!(
        resource, "00000000-0000-0000-0000-000000000000",
        "the exporter was not resolved to a resource"
    );

    // And §2.3: the endpoints are 10.0.0.7 and 8.8.8.8, neither of which is in this
    // tenant's inventory, so both stay nil. A collector that resolved them by creating
    // would have invented two assets from one packet of traffic.
    let endpoints = scalar(&format!(
        "SELECT DISTINCT concat(toString(src_resource_id), '/', toString(dst_resource_id)) \
         FROM flows WHERE tenant_id = '{tenant_id}'"
    ))
    .await;
    assert_eq!(
        endpoints, "00000000-0000-0000-0000-000000000000/00000000-0000-0000-0000-000000000000",
        "a flow endpoint was turned into inventory"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_datagram_nothing_can_decode_is_counted_and_does_not_stop_the_listener() {
    let store = postgres().await;
    let (_tenant_id, slug) = tenant(&store, "flow-junk").await;

    let address = free_port();
    let config = Config {
        listeners: vec![Listener {
            tenant: slug,
            udp: address,
        }],
        postgres: uops_store_pg::Config {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://uops@127.0.0.1:5432/uops".into()),
            ..uops_store_pg::Config::default()
        },
        clickhouse: ch_config(),
        queue: 1024,
        workers: 1,
        collector_token: None,
        collector_name: "test".to_owned(),
        receive_buffer: 1 << 20,
    };

    let telemetry = ChStore::new(ChClient::new(ch_config()));
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let collector = tokio::spawn(run(config, store.clone(), telemetry, async move {
        let _ = stopped.changed().await;
    }));
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Junk first, then a good one: the listener has to survive the first to deliver the
    // second, which is the whole point of a malformed packet being one lost packet.
    sender
        .send_to(&[0xde, 0xad, 0xbe, 0xef], address)
        .await
        .unwrap();
    sender
        .send_to(b"not a flow datagram at all", address)
        .await
        .unwrap();

    let now = export_seconds();
    sender
        .send_to(&v5_packet(10_000_000, now), address)
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let _ = stop.send(true);
    let stats = collector.await.expect("the task").expect("no error");

    assert_eq!(stats.datagrams.load(Relaxed), 3);
    assert_eq!(stats.undecodable.load(Relaxed), 2);
    assert_eq!(stats.flows.load(Relaxed), 1, "the good packet was lost too");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_listener_naming_a_tenant_that_does_not_exist_refuses_to_start() {
    // Named at startup, because the consequence is the quietest one there is: flow filed
    // under nothing, on a daemon that looks healthy.
    let store = postgres().await;
    let config = Config {
        listeners: vec![Listener {
            tenant: "no-such-tenant-anywhere".to_owned(),
            udp: free_port(),
        }],
        postgres: uops_store_pg::Config {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://uops@127.0.0.1:5432/uops".into()),
            ..uops_store_pg::Config::default()
        },
        clickhouse: ch_config(),
        queue: 16,
        workers: 1,
        collector_token: None,
        collector_name: "test".to_owned(),
        receive_buffer: 1 << 20,
    };

    let telemetry = ChStore::new(ChClient::new(ch_config()));
    let error = run(config, store, telemetry, std::future::pending())
        .await
        .expect_err("a missing tenant must not start");
    assert!(error.contains("no-such-tenant-anywhere"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_packet_on_one_tenants_listener_cannot_produce_a_row_in_another() {
    // The adversarial case, and the one the whole tenancy argument rests on.
    //
    // The bait: tenant B already owns a resource claiming 127.0.0.1 as its management
    // address — which is exactly the address this test sends from. A collector that
    // resolved the exporter globally, or that let the packet's contents pick a tenant,
    // would file this flow under B. §2.6 says the socket decides and nothing else does,
    // so it must land in A and only in A.
    let store = postgres().await;
    let (tenant_a, slug_a) = tenant(&store, "flow-iso-a").await;
    let (tenant_b, _slug_b) = tenant(&store, "flow-iso-b").await;

    let planted = resource_at(&store, tenant_b, "127.0.0.1", "someone-elses-router").await;

    let address = free_port();
    let telemetry = ChStore::new(ChClient::new(ch_config()));
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let collector = tokio::spawn(run(
        one_listener(slug_a, address),
        store.clone(),
        telemetry,
        async move {
            let _ = stopped.changed().await;
        },
    ));
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&v5_packet(10_000_000, export_seconds()), address)
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let _ = stop.send(true);
    collector.await.expect("the task").expect("no error");

    assert_eq!(
        scalar(&format!(
            "SELECT count() FROM flows WHERE tenant_id = '{tenant_a}'"
        ))
        .await,
        "1",
        "the flow did not reach the tenant whose socket it arrived on"
    );

    assert_eq!(
        scalar(&format!(
            "SELECT count() FROM flows WHERE tenant_id = '{tenant_b}'"
        ))
        .await,
        "0",
        "a packet on tenant A's listener wrote into tenant B"
    );

    // And the resource it was attributed to is A's own, not the one B had already
    // registered for that address. Sharing it would be a cross-tenant read even though
    // the row itself landed correctly.
    let attributed = scalar(&format!(
        "SELECT DISTINCT toString(resource_id) FROM flows WHERE tenant_id = '{tenant_a}'"
    ))
    .await;
    assert_ne!(
        attributed,
        planted.into_uuid().to_string(),
        "the exporter resolved to another tenant's resource"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_listeners_keep_their_own_tenants_flow() {
    // The ordinary MSP case rather than the adversarial one: two customers, two sockets,
    // one process. Each packet belongs to the socket it arrived on.
    let store = postgres().await;
    let (tenant_a, slug_a) = tenant(&store, "flow-two-a").await;
    let (tenant_b, slug_b) = tenant(&store, "flow-two-b").await;

    let (address_a, address_b) = (free_port(), free_port());
    let mut config = one_listener(slug_a, address_a);
    config.listeners.push(Listener {
        tenant: slug_b,
        udp: address_b,
    });

    let telemetry = ChStore::new(ChClient::new(ch_config()));
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let collector = tokio::spawn(run(config, store.clone(), telemetry, async move {
        let _ = stopped.changed().await;
    }));
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = v5_packet(10_000_000, export_seconds());
    sender.send_to(&packet, address_a).await.unwrap();
    sender.send_to(&packet, address_b).await.unwrap();
    sender.send_to(&packet, address_b).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let _ = stop.send(true);
    let stats = collector.await.expect("the task").expect("no error");
    assert_eq!(stats.datagrams.load(Relaxed), 3);

    // Identical packets, from one sender, told apart only by which socket took them.
    assert_eq!(
        scalar(&format!(
            "SELECT count() FROM flows WHERE tenant_id = '{tenant_a}'"
        ))
        .await,
        "1"
    );
    assert_eq!(
        scalar(&format!(
            "SELECT count() FROM flows WHERE tenant_id = '{tenant_b}'"
        ))
        .await,
        "2"
    );
}
