//! The EVE-NG datacenter, walked for real — `docs/lab.md`.
//!
//! Every other test of neighbour discovery replaces at least one end: a simulated agent, a
//! fixture of LLDP rows, a scripted transport. Those are the right way to test decoding and
//! orchestration, and they cannot find the class of defect where a component is correct,
//! tested, and reached by nothing — which is what the four-node lab found in M5 when it
//! turned out that nothing walked LLDP at all.
//!
//! This walks the nine-node estate with the product's own code and asserts the graph that
//! comes out. It needs **PostgreSQL only**: a neighbour walk is SNMP in and
//! `resource_relationship` out, so it runs when `ClickHouse` is unavailable — which is how it
//! came to be written.
//!
//! # Running it
//!
//! ```text
//! SQLX_OFFLINE=true \
//! DATABASE_URL=postgres://uops@127.0.0.1:5432/uops_lab \
//! UOPS_LAB=192.168.1.237,192.168.1.64,192.168.1.49,192.168.1.128,192.168.1.207,10.10.6.10,10.10.6.11,10.10.7.10,10.10.7.11 \
//!   cargo test -p uops-poller --test live_lab -- --nocapture
//! ```
//!
//! Skipped, loudly, when `UOPS_LAB` is unset. The addresses are not hard-coded because the
//! fabric is on DHCP and `docs/lab.md` §6 says why a lease is not a stable name.

use std::collections::{BTreeMap, BTreeSet};

use uops_core::{CredentialMaterial, OrgId, ResourceId, Secret, TenantId, TenantScope};
use uops_discover::neighbour::neighbours;
use uops_snmp::bulk::Tuning;
use uops_snmp::transport::Target;
use uops_snmp::udp::UdpTransport;
use uops_store_pg::sweep_ingest::SweepContext;
use uops_store_pg::{Config, PgStore};

/// What the lab's `snmpd.conf` sets. Read-only, and a lab on a private segment.
const COMMUNITY: &str = "uopslab";

fn lab() -> Option<Vec<String>> {
    let raw = std::env::var("UOPS_LAB").ok()?;
    let list: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    (!list.is_empty()).then_some(list)
}

async fn store() -> PgStore {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops@127.0.0.1:5432/uops_lab".into());
    PgStore::connect(&Config {
        url,
        ..Config::default()
    })
    .await
    .expect("connect")
}

/// A tenant to hold the estate, fresh each run so one run never reads another's graph.
async fn tenant(store: &PgStore) -> TenantId {
    let org = OrgId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("lab-{}", org.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("organization");

    let tenant = TenantId::new();
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind("Lab")
        .bind(format!("lab-{}", tenant.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("tenant");
    tenant
}

/// The estate as the product holds it: one resource per address, carrying the identity that a
/// neighbour is matched against.
///
/// **The `mgmt_ip` alone is not enough, and finding that out is half of what this test is
/// for.** `neighbour_ingest::identifiers_of` matches a reported neighbour on its chassis id,
/// its management address or its `sysName`. `lldpd` here advertises a chassis id and a system
/// name and no management address, so a resource known only by the address the *poller* dials
/// matches nothing: every adjacency becomes a discovery candidate and the graph stays empty.
///
/// So this asks each device what it calls itself and records that too — which is what identity
/// resolution does on a real sweep, and skipping it is why the first run of this test reported
/// thirty-two adjacencies and zero edges.
///
/// Raw SQL, as `live.rs` seeds its device: the store's create path asks for a site and a
/// credential reference a neighbour walk does not need.
async fn onboard(
    store: &PgStore,
    tenant: TenantId,
    address: &str,
    sys_name: Option<&str>,
) -> ResourceId {
    let resource = ResourceId::new();
    sqlx::query(
        "INSERT INTO resource (id, tenant_id, kind, name, status)
         VALUES ($1, $2, 'device', $3, 'unknown')",
    )
    .bind(resource.into_uuid())
    .bind(tenant.into_uuid())
    .bind(sys_name.unwrap_or(address))
    .execute(store.pool())
    .await
    .expect("resource");

    let mut identifiers: Vec<(&str, String)> = vec![("mgmt_ip", address.to_owned())];
    if let Some(name) = sys_name {
        identifiers.push(("hostname", name.to_owned()));
    }

    for (kind, value) in identifiers {
        sqlx::query(&format!(
            "INSERT INTO resource_identifier
                 (id, tenant_id, resource_id, kind, value, confidence, source)
             VALUES ($1, $2, $3, '{kind}', $4, 0.80, 'manual')"
        ))
        .bind(uuid::Uuid::now_v7())
        .bind(tenant.into_uuid())
        .bind(resource.into_uuid())
        .bind(value)
        .execute(store.pool())
        .await
        .unwrap_or_else(|e| panic!("{kind}: {e}"));
    }

    resource
}

/// What the device says its name is — `sysName.0`, the object identity resolution reads.
async fn sys_name(transport: &UdpTransport, target: &Target) -> Option<String> {
    let oid: uops_profile::Oid = "1.3.6.1.2.1.1.5.0".parse().expect("a constant OID");
    let rows = uops_snmp::transport::Transport::get_scalars(transport, target, &[oid])
        .await
        .ok()?;
    rows.into_iter().find_map(|vb| match vb.value {
        uops_snmp::transport::Value::Bytes(b) => {
            Some(String::from_utf8_lossy(&b).trim().to_owned())
        }
        _ => None,
    })
}

/// Every adjacency in the graph, as sorted name pairs.
///
/// Sorted because an adjacency has no direction and both ends walk it: `leaf-01 — lb-01` and
/// `lb-01 — leaf-01` are one link, and a comparison that treated them as two would pass while
/// the graph quietly held both.
async fn links(store: &PgStore, scope: &TenantScope) -> BTreeSet<(String, String)> {
    let graph = store.topology(scope).await.expect("topology");
    let names: BTreeMap<ResourceId, String> =
        graph.nodes.iter().map(|n| (n.id, n.name.clone())).collect();

    graph
        .edges
        .iter()
        .map(|e| {
            let a = names.get(&e.source).cloned().unwrap_or_default();
            let b = names.get(&e.target).cloned().unwrap_or_default();
            if a <= b { (a, b) } else { (b, a) }
        })
        .collect()
}

/// Onboard every address, walk its neighbours with the product's own code, and record what
/// came back.
///
/// Returns the resources by address, how many devices answered a walk at all — the one thing
/// that distinguishes an empty graph from an unreachable estate — and how many adjacencies each
/// reported.
async fn walk_estate(
    store: &PgStore,
    scope: &TenantScope,
    tenant: TenantId,
    transport: &UdpTransport,
    addresses: &[String],
) -> (BTreeMap<String, ResourceId>, usize, BTreeMap<String, usize>) {
    let mut by_address: BTreeMap<String, ResourceId> = BTreeMap::new();
    let mut answered = 0usize;
    let mut walked: BTreeMap<String, usize> = BTreeMap::new();

    for address in addresses {
        let target = Target {
            address: format!("{address}:161").parse().expect("an address and port"),
        };
        let named = sys_name(transport, &target).await;
        let resource = onboard(store, tenant, address, named.as_deref()).await;
        by_address.insert(address.clone(), resource);

        let mut tuning = Tuning::default();

        // The product's own walk, not a fixture of its output.
        let found = neighbours(transport, &target, &mut tuning).await;
        if found.lldp.len() + found.cdp.len() + found.arp.len() > 0 {
            answered += 1;
        }
        walked.insert(address.clone(), found.lldp.len());

        // `merged()` is what the poller passes: one list, deduplicated across protocols.
        let outcome = store
            .record_neighbours(scope, resource, &found.merged(), SweepContext::default())
            .await
            .expect("record what the walk found");
        println!(
            "  {address:16} {:22} lldp={:2} -> edges {:2} candidates {:2}",
            named.as_deref().unwrap_or("(no sysName)"),
            found.lldp.len(),
            outcome.edges,
            outcome.candidates
        );
    }

    (by_address, answered, walked)
}

#[tokio::test]
async fn the_lab_estate_becomes_a_topology_graph() {
    let Some(addresses) = lab() else {
        println!(
            "SKIPPED: UOPS_LAB is unset. Bring the estate up per docs/lab.md and list its \
             addresses, comma separated."
        );
        return;
    };

    let store = store().await;
    let tenant = tenant(&store).await;
    let scope = TenantScope::system(tenant);

    // --- onboard, then read each device's own idea of what it is ------------------------
    let transport = UdpTransport::new(Secret::new(CredentialMaterial::SnmpCommunity(
        COMMUNITY.to_owned(),
    )));

    let (by_address, answered, walked) =
        walk_estate(&store, &scope, tenant, &transport, &addresses).await;

    let after_one = links(&store, &scope).await;

    // --- a second pass, because a poller walks every cycle ------------------------------
    //
    // The first pass onboards as it goes, so a device walked before its neighbour existed
    // recorded a candidate rather than an edge. A real poller has the whole estate already.
    // This is the steady state, and it is also where a shared management segment shows up: on
    // Mgmt every fabric node is an LLDP neighbour of every other, which is a true adjacency
    // and not a cabled link.
    let mut second_pass_edges: i64 = 0;
    for (address, resource) in &by_address {
        let target = Target {
            address: format!("{address}:161").parse().expect("an address and port"),
        };
        let mut tuning = Tuning::default();
        let found = neighbours(&transport, &target, &mut tuning).await;
        let outcome = store
            .record_neighbours(&scope, *resource, &found.merged(), SweepContext::default())
            .await
            .expect("record the second pass");
        second_pass_edges += i64::from(outcome.edges);
    }
    println!("\n  second pass recorded {second_pass_edges} adjacencies");

    let after_two = links(&store, &scope).await;
    assert_eq!(
        after_one, after_two,
        "a second walk changed the graph. Both ends of a link report it and a poller walks \
         every cycle, so the sorted pair has to collapse them — the property the schema's \
         UNIQUE alone does not give"
    );

    assert!(
        answered > 0,
        "no device answered a neighbour walk. Check the community and that lldpd is handing \
         its MIB to snmpd over AgentX — without `-x` there is no LLDP in SNMP at all"
    );

    // --- the graph ---------------------------------------------------------------------
    let graph = store.topology(&scope).await.expect("topology");
    let adjacency = after_two;

    println!("\n  nodes: {}  edges: {}", graph.nodes.len(), graph.edges.len());
    for (a, b) in &adjacency {
        println!("    {a} — {b}");
    }

    assert!(
        !graph.edges.is_empty(),
        "the walk reported neighbours and the graph has no edges, which is the M5 defect \
         over again: `record_neighbours` correct, tested, and reaching nothing"
    );

    // --- what M9 can and cannot do with a purely LLDP-discovered estate -----------------
    //
    // Two traversals, and the difference is the whole of §2.4. `resource_neighbourhood`
    // includes `connected_to` and is undirected: it answers *are these two near each other*,
    // which is what groups alerts into one incident. `resource_dependencies` excludes
    // `connected_to` and is directed: it answers *does this one depend on that one*, which is
    // what picks an origin and suppresses the rest.
    //
    // A cable is symmetric and causality is not, so that split is right. Its consequence on
    // this estate is the thing worth writing down: **LLDP alone gives grouping and cannot give
    // an origin.** Every edge here is `connected_to`, so `is_upstream_of` is false between
    // every pair of cabled devices — correctly — and downstream suppression has nothing to act
    // on until something establishes dependency: interface `member_of` edges from a poll, a
    // `hosts` edge from a hypervisor, or an operator saying so.
    let by_role: BTreeMap<String, ResourceId> = by_address
        .values()
        .filter_map(|id| {
            let name = graph.nodes.iter().find(|n| n.id == *id)?.name.clone();
            // `leaf-01-000600` -> `leaf-01`: the MAC suffix makes it unique, the prefix is the
            // role a reader is looking for.
            Some((name.rsplit_once('-')?.0.to_owned(), *id))
        })
        .collect();

    let role = |r: &str| -> ResourceId { *by_role.get(r).unwrap_or_else(|| panic!("{r}: {by_role:?}")) };

    // Grouping: within RADIUS hops of leaf-01, by the undirected walk.
    let hood = store
        .neighbourhood(&scope, role("leaf-01"))
        .await
        .expect("neighbourhood");
    let names: BTreeMap<ResourceId, String> =
        graph.nodes.iter().map(|n| (n.id, n.name.clone())).collect();

    println!("\n  within RADIUS = {} of leaf-01:", uops_incident::RADIUS);
    for (id, depth) in &hood.within {
        println!("    {depth} hop  {}", names.get(id).cloned().unwrap_or_default());
    }

    for near in ["lb-01", "app-01", "spine-01"] {
        assert!(
            hood.within.contains_key(&role(near)),
            "{near} is one hop from leaf-01 over a cabled link and is not in its              neighbourhood, so their alerts would never group into one incident"
        );
    }
    assert!(
        !hood.within.contains_key(&role("core-rtr-01")),
        "core-rtr-01 is three hops from leaf-01, past RADIUS, and grouping that far turns one          datacenter into one incident"
    );

    // Origin: nothing is upstream of anything, because every edge is `connected_to`.
    assert!(
        hood.upstream.is_empty(),
        "something is upstream of leaf-01 on an estate whose only edges are `connected_to`.          Either a dependency edge arrived from somewhere, which is good and this assertion          should be relaxed, or `resource_dependencies` has started walking adjacency, which          would make a cable imply causation"
    );

    println!("\n  upstream of leaf-01: {} — LLDP gives adjacency, not dependency",
             hood.upstream.len());

    // Both ends of every cabled link walk it, so the adjacency count is what a sorted pair
    // collapses to — the dedup property the schema's UNIQUE alone does not give.
    let reported: usize = walked.values().sum();
    println!(
        "\n  {reported} adjacencies reported by {} devices, {} distinct links in the graph",
        answered,
        adjacency.len()
    );
    assert!(
        adjacency.len() <= reported,
        "more links than reported adjacencies: {} > {reported}",
        adjacency.len()
    );
}
