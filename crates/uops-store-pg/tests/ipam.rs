//! Address space against real `PostgreSQL` — `docs/ipam.md`.
//!
//! What only these can settle is the arithmetic and the joins. Every one of the counts
//! here compiles perfectly when written the wrong way, and each wrong way produces a
//! plausible number:
//!
//! * a join instead of correlated subqueries double-counts an address that is both
//!   assigned and responding — which is most of them, because a device that was discovered
//!   and then classified leaves its candidate row behind;
//! * an inner join instead of a full join silently drops exactly the addresses this
//!   feature exists to surface;
//! * the textbook capacity formula returns 0 for a /31 and -1 for a /32, both of which are
//!   ordinary in a routed estate.
//!
//! The isolation test is the one every milestone since M7 has carried, pointed at the new
//! surface.

use std::str::FromStr;

use uops_core::{OrgId, ResourceId, TenantId, TenantScope};
use uops_discover::Range;
use uops_store_pg::{Config, NewSubnet, PgStore};

async fn store() -> PgStore {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into());
    PgStore::connect(&Config {
        url,
        ..Config::default()
    })
    .await
    .expect("connect")
}

struct Fixture {
    store: PgStore,
    a: TenantId,
    b: TenantId,
}

impl Fixture {
    fn scope_a(&self) -> TenantScope {
        TenantScope::system(self.a)
    }
    fn scope_b(&self) -> TenantScope {
        TenantScope::system(self.b)
    }
}

async fn fixture(slug: &str) -> Fixture {
    let store = store().await;
    let org = OrgId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("ipam-org-{slug}-{}", org.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("organization");

    let mut tenants = Vec::new();
    for which in ["a", "b"] {
        let id = TenantId::new();
        sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
            .bind(id.into_uuid())
            .bind(org.into_uuid())
            .bind(format!("ipam-{slug}-{which}"))
            .bind(format!("ipam-{slug}-{which}-{}", id.into_uuid().simple()))
            .execute(store.pool())
            .await
            .expect("tenant");
        tenants.push(id);
    }

    Fixture {
        store,
        a: tenants[0],
        b: tenants[1],
    }
}

fn subnet(range: &str, name: &str) -> NewSubnet {
    NewSubnet {
        range: Range::from_str(range).expect("range"),
        name: name.to_owned(),
        description: String::new(),
        site_id: None,
        assignment: "static".to_owned(),
    }
}

/// A resource claiming one management address.
async fn resource_at(store: &PgStore, tenant: TenantId, name: &str, address: &str) -> ResourceId {
    let id = ResourceId::new();
    sqlx::query(
        "INSERT INTO resource (id, tenant_id, kind, name, status) VALUES ($1,$2,'device',$3,'up')",
    )
    .bind(id.into_uuid())
    .bind(tenant.into_uuid())
    .bind(name)
    .execute(store.pool())
    .await
    .expect("resource");

    sqlx::query(
        "INSERT INTO resource_identifier (id, tenant_id, resource_id, kind, value, confidence, source)
         VALUES ($1, $2, $3, 'mgmt_ip', $4, 0.8, 'manual')",
    )
    .bind(ResourceId::new().into_uuid())
    .bind(tenant.into_uuid())
    .bind(id.into_uuid())
    .bind(address)
    .execute(store.pool())
    .await
    .expect("identifier");

    id
}

/// An address that answered a sweep and was never classified.
async fn candidate_at(store: &PgStore, tenant: TenantId, address: &str) {
    sqlx::query(
        "INSERT INTO discovery_candidate (tenant_id, source, address) VALUES ($1, 'sweep', $2::inet)",
    )
    .bind(tenant.into_uuid())
    .bind(address)
    .execute(store.pool())
    .await
    .expect("candidate");
}

#[tokio::test]
async fn a_declared_range_comes_back_in_address_order() {
    let f = fixture("order").await;
    let scope = f.scope_a();

    // Declared out of order, and deliberately in an order where alphabetical and numeric
    // disagree: "10.0.10.0/24" sorts before "10.0.9.0/24" as text.
    for (range, name) in [("10.0.10.0/24", "ten"), ("10.0.9.0/24", "nine")] {
        f.store
            .declare_subnet(&scope, &subnet(range, name))
            .await
            .expect("declare");
    }

    let listed = f.store.subnets(&scope).await.expect("list");
    assert_eq!(
        listed.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["nine", "ten"],
        "address space is read in address order, not alphabetically"
    );
}

#[tokio::test]
async fn the_same_range_cannot_be_declared_twice() {
    let f = fixture("dup").await;
    let scope = f.scope_a();

    f.store
        .declare_subnet(&scope, &subnet("10.1.0.0/24", "first"))
        .await
        .expect("declare");

    // One subnet described twice would produce two sets of numbers that diverge.
    let again = f
        .store
        .declare_subnet(&scope, &subnet("10.1.0.0/24", "second"))
        .await;
    assert!(
        again.is_err(),
        "a second declaration of one range must be refused"
    );
}

#[tokio::test]
async fn a_host_address_is_normalised_to_its_network() {
    let f = fixture("norm").await;
    let scope = f.scope_a();

    // `cidr` normalises 10.2.0.5/24 to 10.2.0.0/24, which is why the column is `cidr` and
    // not text: two operators entering the same range two ways must not get two rows.
    f.store
        .declare_subnet(&scope, &subnet("10.2.0.0/24", "network"))
        .await
        .expect("declare");
    let again = f
        .store
        .declare_subnet(&scope, &subnet("10.2.0.5/24", "host form"))
        .await;
    assert!(again.is_err(), "10.2.0.5/24 and 10.2.0.0/24 are one range");
}

#[tokio::test]
async fn capacity_is_right_for_the_ranges_that_break_the_textbook_formula() {
    let f = fixture("cap").await;
    let scope = f.scope_a();

    // `2^(32-masklen) - 2` gives 0 for a /31 and -1 for a /32. Both are ordinary: a /31 is
    // a point-to-point link (RFC 3021) and a /32 is a loopback, and an estate has many of
    // each. A screen reporting negative capacity on every loopback is the failure this
    // guards.
    for (range, expected) in [
        ("10.3.0.0/24", 254),
        ("10.3.1.0/30", 2),
        ("10.3.2.0/31", 2),
        ("10.3.3.1/32", 1),
        ("10.4.0.0/16", 65_534),
    ] {
        f.store
            .declare_subnet(&scope, &subnet(range, range))
            .await
            .expect("declare");
        let found = f
            .store
            .subnet_utilisation(&scope)
            .await
            .expect("utilisation")
            .into_iter()
            .find(|u| u.subnet.name == range)
            .expect("declared range is listed");
        assert_eq!(found.capacity, expected, "capacity of {range}");
    }
}

#[tokio::test]
async fn an_address_that_is_both_assigned_and_responding_is_counted_once_in_each() {
    let f = fixture("both").await;
    let scope = f.scope_a();
    f.store
        .declare_subnet(&scope, &subnet("10.5.0.0/24", "both"))
        .await
        .expect("declare");

    // The ordinary case, and the one a join gets wrong: a device that was discovered and
    // then classified has a resource identifier *and* leaves its candidate row behind.
    resource_at(&f.store, f.a, "sw-1", "10.5.0.1").await;
    candidate_at(&f.store, f.a, "10.5.0.1").await;

    let u = &f
        .store
        .subnet_utilisation(&scope)
        .await
        .expect("utilisation")[0];
    assert_eq!(u.assigned, 1);
    assert_eq!(u.responding, 1);
    assert_eq!(
        u.unaccounted, 0,
        "an address a resource claims is accounted for, however it was found"
    );
}

#[tokio::test]
async fn an_address_that_answered_and_nobody_claims_is_the_finding() {
    let f = fixture("unaccounted").await;
    let scope = f.scope_a();
    f.store
        .declare_subnet(&scope, &subnet("10.6.0.0/24", "mixed"))
        .await
        .expect("declare");

    resource_at(&f.store, f.a, "known", "10.6.0.1").await;
    candidate_at(&f.store, f.a, "10.6.0.1").await;
    // Something is on the network that the inventory does not know about. This is the
    // number an address inventory is actually bought for.
    candidate_at(&f.store, f.a, "10.6.0.99").await;

    let u = &f
        .store
        .subnet_utilisation(&scope)
        .await
        .expect("utilisation")[0];
    assert_eq!(u.assigned, 1);
    assert_eq!(u.responding, 2);
    assert_eq!(u.unaccounted, 1);

    let listed = f
        .store
        .subnet_addresses(&scope, u.subnet.id, 100)
        .await
        .expect("addresses")
        .expect("the range is this tenant's");
    assert_eq!(listed.len(), 2, "both addresses are listed");

    let stranger = listed
        .iter()
        .find(|a| a.address.to_string() == "10.6.0.99")
        .expect("the unclassified address is present");
    assert!(
        stranger.is_unaccounted(),
        "an address nothing claims must not be dropped by the join"
    );
    assert!(stranger.resource_id.is_none());

    let known = listed
        .iter()
        .find(|a| a.address.to_string() == "10.6.0.1")
        .expect("the classified address is present");
    assert!(!known.is_unaccounted());
    assert_eq!(known.resource_name.as_deref(), Some("known"));
}

#[tokio::test]
async fn an_assigned_address_that_never_answered_is_still_listed() {
    let f = fixture("quiet").await;
    let scope = f.scope_a();
    f.store
        .declare_subnet(&scope, &subnet("10.7.0.0/24", "quiet"))
        .await
        .expect("declare");

    // A device that is switched off answers nothing and still owns its address —
    // `docs/ipam.md` §2.6. An inner join in the other direction would lose it.
    resource_at(&f.store, f.a, "powered-off", "10.7.0.5").await;

    let u = &f
        .store
        .subnet_utilisation(&scope)
        .await
        .expect("utilisation")[0];
    assert_eq!(u.assigned, 1);
    assert_eq!(u.responding, 0);

    let listed = f
        .store
        .subnet_addresses(&scope, u.subnet.id, 100)
        .await
        .expect("addresses")
        .expect("the range is this tenant's");
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].responding);
    assert_eq!(listed[0].resource_name.as_deref(), Some("powered-off"));
}

#[tokio::test]
async fn an_address_outside_the_range_is_not_counted_in_it() {
    let f = fixture("bounds").await;
    let scope = f.scope_a();
    f.store
        .declare_subnet(&scope, &subnet("10.8.0.0/24", "narrow"))
        .await
        .expect("declare");

    candidate_at(&f.store, f.a, "10.8.0.7").await;
    // One octet outside. A containment operator written as a prefix match on text would
    // accept this.
    candidate_at(&f.store, f.a, "10.8.1.7").await;

    let u = &f
        .store
        .subnet_utilisation(&scope)
        .await
        .expect("utilisation")[0];
    assert_eq!(u.responding, 1, "only the address inside the range counts");
}

#[tokio::test]
async fn one_tenants_addresses_are_invisible_to_another() {
    // The adversarial test every milestone since M7 has carried, pointed at this surface.
    let f = fixture("iso").await;

    let in_a = f
        .store
        .declare_subnet(&f.scope_a(), &subnet("10.9.0.0/24", "a's range"))
        .await
        .expect("declare");
    resource_at(&f.store, f.a, "a-device", "10.9.0.1").await;
    candidate_at(&f.store, f.a, "10.9.0.2").await;

    // The same range declared in the other tenant. Same addresses, different estate —
    // RFC 1918 space is in use in every building on earth, which is exactly why this is
    // the test that matters.
    f.store
        .declare_subnet(&f.scope_b(), &subnet("10.9.0.0/24", "b's range"))
        .await
        .expect("declare in b");

    let b_view = f
        .store
        .subnet_utilisation(&f.scope_b())
        .await
        .expect("utilisation");
    assert_eq!(b_view.len(), 1);
    assert_eq!(
        (b_view[0].assigned, b_view[0].responding),
        (0, 0),
        "tenant b must not see tenant a's addresses in an identical range"
    );

    // And b cannot read a's subnet by id.
    // `None`, not an empty list: the owner of an empty range and somebody probing another
    // tenant's ids must not get the same answer. The API turns this into a 404.
    let leaked = f
        .store
        .subnet_addresses(&f.scope_b(), in_a.id, 100)
        .await
        .expect("addresses");
    assert!(
        leaked.is_none(),
        "a subnet id from another tenant is absent, not empty"
    );

    // Nor delete it.
    let deleted = f
        .store
        .forget_subnet(&f.scope_b(), in_a.id)
        .await
        .expect("forget");
    assert!(
        !deleted,
        "a subnet id from another tenant cannot be deleted"
    );
    assert_eq!(
        f.store.subnets(&f.scope_a()).await.expect("list").len(),
        1,
        "and a's subnet is still there"
    );
}

#[tokio::test]
async fn forgetting_a_range_that_is_not_there_is_not_an_error() {
    let f = fixture("gone").await;
    // The caller asked for it to be gone and it is.
    let done = f
        .store
        .forget_subnet(&f.scope_a(), ResourceId::new().into_uuid())
        .await
        .expect("forget");
    assert!(!done);
}

#[tokio::test]
async fn ipv6_is_refused_by_the_schema() {
    let f = fixture("v6").await;
    // `docs/ipam.md` §2.2: a /64 has no meaningful utilisation, and reporting one would be
    // the product stating something false. Refused by a CHECK rather than by a handler.
    let refused = sqlx::query(
        "INSERT INTO subnet (tenant_id, range, name) VALUES ($1, '2001:db8::/64'::cidr, 'v6')",
    )
    .bind(f.a.into_uuid())
    .execute(f.store.pool())
    .await;
    assert!(
        refused.is_err(),
        "an IPv6 range must be refused by the schema"
    );
}
