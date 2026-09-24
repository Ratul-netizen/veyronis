//! Address space — `docs/ipam.md`.
//!
//! # Almost all of this is a read over data the product already had
//!
//! Migration 0028 adds one table, holding the one thing that cannot be computed: which
//! ranges an operator cares about. Everything else on the screen is derived here from
//! tables that existed before this module did — `resource_identifier` for addresses that
//! belong to something, `discovery_candidate` for addresses that merely answered.
//!
//! That is why there is no collector, no poller and no new protocol in this feature.
//!
//! # Assigned and responding are two numbers, deliberately
//!
//! `docs/ipam.md` §2.3. An address a resource claims and an address that simply answered
//! are different findings, and the second one is what an address inventory is bought for:
//! something is on the network that the inventory does not know about. Summing them into
//! "used" would throw away the only number nobody already has.
//!
//! A single count would also be wrong: the same address is routinely both, because a
//! device that was discovered and then classified leaves a candidate row behind.

use std::net::Ipv4Addr;
use std::str::FromStr;

use uops_core::{Error as CoreError, Result, SiteId, TenantScope};
use uops_discover::Range;

use crate::error::map;
use crate::store::PgStore;

/// A `cidr` column, parsed.
///
/// `cidr` has no `sqlx` mapping without the `ipnetwork` feature, and
/// [`crate::discovery_jobs`] already decided that adding a dependency to move a value
/// [`uops_discover::Range`] models properly is the wrong trade. Same boundary, same
/// reason: cast in the SQL, parsed on the way back, so nothing above this module holds a
/// string that might not be a range.
fn range_from(text: &str) -> Result<Range> {
    Range::from_str(text)
        .or_else(|_| Range::from_str(&format!("{text}/32")))
        .map_err(|e| CoreError::Storage(format!("subnet holds a range that will not parse: {e}")))
}

/// An `inet` column, parsed.
///
/// IPv4 only, which is not a limitation here: migration 0028 refuses a non-IPv4 range, so
/// an address inside one cannot be v6.
fn address_from(text: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(text).map_err(|e| {
        CoreError::Storage(format!("subnet holds an address that will not parse: {e}"))
    })
}

/// A declared range.
#[derive(Clone, Debug)]
pub struct Subnet {
    pub id: uuid::Uuid,
    pub range: Range,
    pub name: String,
    pub description: String,
    pub site_id: Option<SiteId>,
    /// `static`, `dhcp` or `reserved` — a declaration, not an integration.
    pub assignment: String,
}

/// What a caller supplies to declare one.
#[derive(Clone, Debug)]
pub struct NewSubnet {
    pub range: Range,
    pub name: String,
    pub description: String,
    pub site_id: Option<SiteId>,
    pub assignment: String,
}

/// A range, with what is in it.
///
/// The three counts are not derivable from one another and none is a percentage: §2.6
/// refuses "97% full", because it hides whether the remaining 3% is reserved.
#[derive(Clone, Debug)]
pub struct Utilisation {
    pub subnet: Subnet,
    /// Usable addresses. `subnet_usable_addresses` in 0028 — /31 and /32 included.
    pub capacity: i64,
    /// Addresses a resource claims as its management address.
    pub assigned: i64,
    /// Addresses something answered on. Overlaps `assigned`, and that is not a bug.
    pub responding: i64,
    /// Answered, and no resource claims it. **The finding.**
    pub unaccounted: i64,
}

/// One address inside a range.
#[derive(Clone, Debug)]
pub struct Address {
    pub address: Ipv4Addr,
    /// What this probably is, when nothing claims it — `docs/what-is-this-thing.md`.
    ///
    /// Computed on read rather than stored: the inputs are three columns and a lookup
    /// table, so recomputing costs nothing, and a stored guess going stale would be
    /// indistinguishable from a fresh fact.
    ///
    /// `None` for an address a resource already claims. The question "what is this" is
    /// only interesting when the inventory has no answer.
    pub guess: Option<uops_guess::Guess>,
    /// The resource claiming it, when one does.
    pub resource_id: Option<uops_core::ResourceId>,
    pub resource_name: Option<String>,
    /// Whether a discovery candidate answered here.
    pub responding: bool,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

impl Address {
    /// Answered, and nothing in the inventory claims it.
    ///
    /// The one an operator acts on: either a device nobody inventoried, or a device
    /// somebody plugged in. The product does not guess which.
    #[must_use]
    pub const fn is_unaccounted(&self) -> bool {
        self.responding && self.resource_id.is_none()
    }
}

impl PgStore {
    /// Every declared range, in address order.
    ///
    /// Address order rather than by name, because that is how somebody reads address
    /// space: `10.0.0.0/24` before `10.0.1.0/24`.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn subnets(&self, scope: &TenantScope) -> Result<Vec<Subnet>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, host(range) || '/' || masklen(range) AS "range!", name, description,
                   site_id AS "site_id: SiteId", assignment
              FROM subnet
             WHERE tenant_id = $1
             ORDER BY range
            "#,
            scope.tenant_id() as uops_core::TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("subnet", String::new(), e))?;

        rows.into_iter()
            .map(|r| {
                Ok(Subnet {
                    id: r.id,
                    range: range_from(&r.range)?,
                    name: r.name,
                    description: r.description,
                    site_id: r.site_id,
                    assignment: r.assignment,
                })
            })
            .collect()
    }

    /// Declare a range.
    ///
    /// # Errors
    ///
    /// [`uops_core::Error::Conflict`] when the range is already declared in this tenant —
    /// the `UNIQUE (tenant_id, range)` in 0028. Declaring `10.0.1.0/24` twice is one
    /// subnet described twice, and the second attempt should say so rather than produce a
    /// second set of numbers that will diverge.
    pub async fn declare_subnet(&self, scope: &TenantScope, new: &NewSubnet) -> Result<Subnet> {
        let row = sqlx::query!(
            r#"
            INSERT INTO subnet (tenant_id, range, name, description, site_id, assignment)
            VALUES ($1, $2::text::cidr, $3, $4, $5, $6)
            RETURNING id, host(range) || '/' || masklen(range) AS "range!", name, description,
                      site_id AS "site_id: SiteId", assignment
            "#,
            scope.tenant_id() as uops_core::TenantId,
            new.range.to_string(),
            new.name,
            new.description,
            new.site_id as Option<SiteId>,
            new.assignment,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("subnet", new.range.to_string(), e))?;

        Ok(Subnet {
            id: row.id,
            range: range_from(&row.range)?,
            name: row.name,
            description: row.description,
            site_id: row.site_id,
            assignment: row.assignment,
        })
    }

    /// Forget a declared range.
    ///
    /// Deletes the declaration only. Nothing about the addresses is stored here, so there
    /// is nothing else to remove — which is the practical benefit of §2.1's decision that
    /// utilisation is computed rather than kept.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said. A range that was not there is `Ok(false)`, not an
    /// error: the caller asked for it to be gone and it is.
    pub async fn forget_subnet(&self, scope: &TenantScope, id: uuid::Uuid) -> Result<bool> {
        let done = sqlx::query!(
            "DELETE FROM subnet WHERE tenant_id = $1 AND id = $2",
            scope.tenant_id() as uops_core::TenantId,
            id,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("subnet", id.to_string(), e))?
        .rows_affected();

        Ok(done > 0)
    }

    /// Every declared range with its three counts.
    ///
    /// One query rather than one per subnet: an estate has tens of ranges and a round trip
    /// each would make the screen's load time a function of how organised the operator is.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn subnet_utilisation(&self, scope: &TenantScope) -> Result<Vec<Utilisation>> {
        // `<<=` is "is contained within or equals", which is the right operator for an
        // address against a range: `10.0.0.0 << 10.0.0.0/24` is false, and the network
        // address of a /24 is a legitimate thing to have recorded.
        //
        // The two counts come from correlated subqueries rather than joins, because a join
        // would multiply: an address that is both assigned and responding appears in both
        // tables, and a single joined count would count it twice in one direction and
        // collapse two distinct devices in the other.
        let rows = sqlx::query!(
            r#"
            SELECT
                s.id,
                host(s.range) || '/' || masklen(s.range) AS "range!",
                s.name,
                s.description,
                s.site_id     AS "site_id: SiteId",
                s.assignment,
                subnet_usable_addresses(s.range) AS "capacity!",
                (
                    SELECT count(DISTINCT i.value::inet)
                      FROM resource_identifier i
                     WHERE i.tenant_id = s.tenant_id
                       AND i.kind = 'mgmt_ip'
                       AND i.value ~ '^[0-9.]+$'
                       AND i.value::inet <<= s.range
                ) AS "assigned!",
                (
                    SELECT count(DISTINCT c.address)
                      FROM discovery_candidate c
                     WHERE c.tenant_id = s.tenant_id
                       AND c.address IS NOT NULL
                       AND c.address <<= s.range
                ) AS "responding!",
                (
                    SELECT count(DISTINCT c.address)
                      FROM discovery_candidate c
                     WHERE c.tenant_id = s.tenant_id
                       AND c.address IS NOT NULL
                       AND c.address <<= s.range
                       AND NOT EXISTS (
                           SELECT 1
                             FROM resource_identifier i
                            WHERE i.tenant_id = s.tenant_id
                              AND i.kind = 'mgmt_ip'
                              AND i.value ~ '^[0-9.]+$'
                              AND i.value::inet = c.address
                       )
                ) AS "unaccounted!"
              FROM subnet s
             WHERE s.tenant_id = $1
             ORDER BY s.range
            "#,
            scope.tenant_id() as uops_core::TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("subnet", String::new(), e))?;

        rows.into_iter()
            .map(|r| {
                Ok(Utilisation {
                    subnet: Subnet {
                        id: r.id,
                        range: range_from(&r.range)?,
                        name: r.name,
                        description: r.description,
                        site_id: r.site_id,
                        assignment: r.assignment,
                    },
                    capacity: r.capacity,
                    assigned: r.assigned,
                    responding: r.responding,
                    unaccounted: r.unaccounted,
                })
            })
            .collect()
    }

    /// What is in one range, address by address.
    ///
    /// Only addresses something is known about — this does not enumerate a /16. A range's
    /// empty addresses are its capacity minus what is listed, which the caller already has
    /// from [`subnet_utilisation`](Self::subnet_utilisation).
    ///
    /// `None` when the range is not this tenant's, which is **not** the same as an empty
    /// list. The isolation test caught this: a range that belongs to somebody else and a
    /// range of this tenant's that happens to be empty were both answering `200 []`, so
    /// the owner could not tell an empty range from one they cannot see. The existence
    /// check is here rather than in the handler because the scope is here.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn subnet_addresses(
        &self,
        scope: &TenantScope,
        id: uuid::Uuid,
        limit: i64,
    ) -> Result<Option<Vec<Address>>> {
        let exists = sqlx::query_scalar!(
            "SELECT 1 FROM subnet WHERE tenant_id = $1 AND id = $2",
            scope.tenant_id() as uops_core::TenantId,
            id,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("subnet", id.to_string(), e))?;

        if exists.is_none() {
            return Ok(None);
        }

        // A FULL JOIN over the two sources, because an address may be in either, both, or
        // — for a candidate that was never classified — only the second. An inner join
        // would silently drop exactly the rows this screen exists to surface.
        let rows = sqlx::query!(
            r#"
            WITH bounds AS (
                SELECT range FROM subnet WHERE tenant_id = $1 AND id = $2
            ),
            claimed AS (
                SELECT DISTINCT ON (i.value::inet)
                       i.value::inet AS address,
                       i.resource_id,
                       i.last_seen
                  FROM resource_identifier i, bounds b
                 WHERE i.tenant_id = $1
                   AND i.kind = 'mgmt_ip'
                   AND i.value ~ '^[0-9.]+$'
                   AND i.value::inet <<= b.range
                 ORDER BY i.value::inet, i.last_seen DESC
            ),
            answered AS (
                SELECT DISTINCT ON (c.address)
                       c.address, c.last_seen,
                       -- The evidence a guess is made from. All three were already here;
                       -- nothing new is collected for this.
                       c.mac::text AS mac, c.sys_name, c.sys_descr
                  FROM discovery_candidate c, bounds b
                 WHERE c.tenant_id = $1
                   AND c.address IS NOT NULL
                   AND c.address <<= b.range
                 ORDER BY c.address, c.last_seen DESC
            )
            SELECT
                host(coalesce(claimed.address, answered.address)) AS "address!",
                claimed.resource_id AS "resource_id?: uops_core::ResourceId",
                r.name              AS "resource_name?",
                (answered.address IS NOT NULL) AS "responding!",
                answered.mac        AS "mac?",
                answered.sys_name   AS "sys_name?",
                answered.sys_descr  AS "sys_descr?",
                greatest(claimed.last_seen, answered.last_seen) AS "last_seen?"
              FROM claimed
              FULL JOIN answered ON claimed.address = answered.address
              LEFT JOIN resource r
                     ON r.id = claimed.resource_id AND r.tenant_id = $1
             ORDER BY 1
             LIMIT $3
            "#,
            scope.tenant_id() as uops_core::TenantId,
            id,
            limit,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("subnet", id.to_string(), e))?;

        rows.into_iter()
            .map(|r| {
                // Only for an address nothing claims. A device already in the inventory
                // has an identity; offering an opinion beside it would be noise at best
                // and a contradiction at worst.
                let guess = if r.resource_id.is_none() {
                    Some(uops_guess::guess(&uops_guess::Evidence {
                        mac: r.mac.as_deref(),
                        hostname: r.sys_name.as_deref(),
                        sys_descr: r.sys_descr.as_deref(),
                        ttl: None,
                    }))
                } else {
                    None
                };
                Ok(Address {
                    address: address_from(&r.address)?,
                    resource_id: r.resource_id,
                    resource_name: r.resource_name,
                    responding: r.responding,
                    last_seen: r.last_seen,
                    guess,
                })
            })
            .collect::<Result<Vec<_>>>()
            .map(Some)
    }
}
