//! The link graph — UI-SPEC §14.
//!
//! One route, one shape: the nodes and the edges of the tenant's `connected_to` graph,
//! whole. See `uops_store_pg::topology` for why it is not paged and why a resource with
//! no links is not a node.
//!
//! # Roles
//!
//! `Viewer`. A topology is a read of the inventory, and there is nothing to write here —
//! the edges come from discovery walking a device, not from anybody drawing a line.

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use uops_core::{ResourceId, Role};

use crate::error::ApiResult;
use crate::extract::Caller;
use crate::state::AppState;

/// A device in the graph.
#[derive(Debug, Serialize)]
pub struct NodeView {
    pub id: ResourceId,
    /// What to draw beside the node: the operator's name for it if they set one.
    pub name: String,
    pub kind: String,
    /// One of the semantic five. The client draws it as the node's fill *and* says the
    /// word, because nothing in this product is carried by hue alone.
    pub status: String,
}

/// A link between two devices.
#[derive(Debug, Serialize)]
pub struct EdgeView {
    pub source: ResourceId,
    pub target: ResourceId,
    /// `lldp`, `cdp`, `arp` or `manual`.
    ///
    /// Sent because it is the difference between evidence an operator should trust and
    /// evidence they should not: an ARP sighting proves an address was in use on a
    /// subnet, which is much weaker than a switch naming its neighbour.
    pub discovered_by: String,
}

#[derive(Debug, Serialize)]
pub struct TopologyView {
    pub nodes: Vec<NodeView>,
    pub edges: Vec<EdgeView>,
}

/// `GET /api/v1/topology`
pub async fn get(State(state): State<AppState>, caller: Caller) -> ApiResult<Json<TopologyView>> {
    caller.require(Role::Viewer)?;

    let graph = state.store.topology(caller.scope()).await?;

    caller.audit().read(
        "topology.get",
        Some(i64::try_from(graph.nodes.len()).unwrap_or(i64::MAX)),
    );

    Ok(Json(TopologyView {
        nodes: graph
            .nodes
            .into_iter()
            .map(|n| NodeView {
                id: n.id,
                name: n.display_name.unwrap_or(n.name),
                kind: n.kind.as_str().to_owned(),
                status: n.status.as_str().to_owned(),
            })
            .collect(),
        edges: graph
            .edges
            .into_iter()
            .map(|e| EdgeView {
                source: e.source,
                target: e.target,
                discovered_by: e.discovered_by,
            })
            .collect(),
    }))
}
