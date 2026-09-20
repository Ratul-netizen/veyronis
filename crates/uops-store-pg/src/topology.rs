//! The link graph — UI-SPEC §14.
//!
//! What M5's neighbour walk wrote, read back as something that can be drawn: the
//! `connected_to` edges and the resources at their ends.
//!
//! # Why only linked resources are nodes
//!
//! A device with no links is not topology. An estate of two thousand resources of which
//! forty report neighbours would otherwise draw forty links and 1 960 unconnected dots,
//! and the dots would be the overwhelming majority of the picture while carrying none of
//! its information. The inventory is what the resource list is for.
//!
//! # Why the whole graph in one response
//!
//! A topology that fetches a node at a time stops working at exactly the size where it
//! starts being useful, and the alternative — a cursor — would mean the client laying out
//! a graph it has not finished receiving. The bound is `resource_relationship`, which has
//! one row per cable rather than one per device, and the client's own `NODE_BUDGET`
//! decides what is legible once it arrives.

use uops_core::{ResourceId, ResourceKind, ResourceStatus, Result, TenantId, TenantScope};

use crate::error::map;
use crate::store::PgStore;

/// A resource at the end of at least one link.
#[derive(Clone, Debug)]
pub struct TopologyNode {
    pub id: ResourceId,
    pub name: String,
    pub display_name: Option<String>,
    pub kind: ResourceKind,
    pub status: ResourceStatus,
}

/// One `connected_to` relationship.
#[derive(Clone, Debug)]
pub struct TopologyEdge {
    pub source: ResourceId,
    pub target: ResourceId,
    /// Which protocol last confirmed it: `lldp`, `cdp`, `arp`, or `manual`.
    pub discovered_by: String,
}

/// The whole link graph for a tenant.
#[derive(Clone, Debug)]
pub struct Topology {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

impl PgStore {
    /// Every link in the tenant, and the resources at their ends.
    ///
    /// Decommissioned resources are excluded, and so are their links: SPEC §M1 makes
    /// decommissioning a soft delete so history still resolves, but a retired device is
    /// not part of the network and drawing it would make the picture disagree with the
    /// rack.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn topology(&self, scope: &TenantScope) -> Result<Topology> {
        // tenant-exempt: the tenant is the only bound parameter, from the scope.
        let nodes = sqlx::query_as!(
            TopologyNode,
            r#"
            SELECT r.id            AS "id: ResourceId",
                   r.name,
                   r.display_name,
                   r.kind          AS "kind: ResourceKind",
                   r.status        AS "status: ResourceStatus"
              FROM resource r
             WHERE r.tenant_id = $1
               AND r.status <> 'decommissioned'
               AND EXISTS (
                     SELECT 1
                       FROM resource_relationship e
                      WHERE e.tenant_id = r.tenant_id
                        AND e.kind = 'connected_to'
                        AND (e.source_id = r.id OR e.target_id = r.id)
                   )
             ORDER BY r.id
            "#,
            scope.tenant_id() as TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("topology", "nodes".to_owned(), e))?;

        // Both ends joined back to `resource` so an edge to a decommissioned device is
        // dropped here rather than arriving at a client that has no node to attach it to.
        //
        // tenant-exempt: the tenant is the only bound parameter, from the scope.
        let edges = sqlx::query_as!(
            TopologyEdge,
            r#"
            SELECT e.source_id AS "source: ResourceId",
                   e.target_id AS "target: ResourceId",
                   e.discovered_by
              FROM resource_relationship e
              JOIN resource a ON a.id = e.source_id AND a.tenant_id = e.tenant_id
              JOIN resource b ON b.id = e.target_id AND b.tenant_id = e.tenant_id
             WHERE e.tenant_id = $1
               AND e.kind = 'connected_to'
               AND a.status <> 'decommissioned'
               AND b.status <> 'decommissioned'
             ORDER BY e.source_id, e.target_id
            "#,
            scope.tenant_id() as TenantId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("topology", "edges".to_owned(), e))?;

        Ok(Topology { nodes, edges })
    }
}
