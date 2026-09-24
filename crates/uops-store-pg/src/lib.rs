//! The control plane over `PostgreSQL` — M1.
//!
//! Resources, sites, identifiers and aliases: the rows that describe *what is being
//! monitored*, as opposed to the telemetry about it, which lives in `ClickHouse` and is
//! reached through `uops-query`.
//!
//! # Three rules this crate exists to hold
//!
//! | rule | how |
//! |---|---|
//! | No statement without a tenant | every method takes `&TenantScope`, and [`enforced`] reads this crate's own source to prove every query uses it |
//! | No SQL assembled from strings | `sqlx` macros, checked against the real schema at compile time |
//! | No `OFFSET` | keyset pagination on `UUIDv7` ids — see [`page`] |
//!
//! # Compile-time checking, and what it costs
//!
//! The `sqlx::query!` macros verify every statement against a live schema when this
//! crate is built, which is what makes a renamed column a compile error rather than a
//! runtime one. Builds use the checked-in `.sqlx/` metadata (`SQLX_OFFLINE=true`), so a
//! clone with no database still builds; regenerate it with `cargo sqlx prepare` after
//! changing a query, and CI fails if it is stale.
//!
//! # Example
//!
//! ```no_run
//! use uops_core::{ResourceKind, TenantId, TenantScope};
//! use uops_store_pg::{Config, NewResource, PgStore, ResourceFilter};
//!
//! # async fn example() -> uops_core::Result<()> {
//! let store = PgStore::connect(&Config::from_env()).await?;
//! let scope = TenantScope::system(TenantId::new());
//!
//! let device = store
//!     .create_resource(&scope, &NewResource::new(ResourceKind::Device, "rtr-01"))
//!     .await?;
//!
//! let page = store.resources(&scope, &ResourceFilter::default()).await?;
//! assert!(page.items.iter().any(|r| r.id == device.id));
//! # Ok(())
//! # }
//! ```

pub mod alerts;
pub mod audit;
pub mod auth;
pub mod bootstrap;
pub mod catalog;
pub mod collectors;
pub mod dashboards;
pub mod discovery;
pub mod discovery_jobs;
mod enforced;
pub mod enrich;
pub mod error;
pub mod facts;
pub mod groups;
pub mod identity;
pub mod ipam;
pub mod incidents;
pub mod lease;
pub mod maintenance;
pub mod neighbour_ingest;
pub mod notify;
pub mod page;
pub mod platform;
pub mod pollable;
pub mod profile;
pub mod resource;
pub mod runbooks;
pub mod sealed;
pub mod searches;
pub mod sites;
pub mod slo;
pub mod sso;
pub mod store;
pub mod sweep_ingest;
pub mod tenants;
pub mod topology;
pub mod users;

pub use alerts::{ActiveAlert, AlertRule, AlertStateRow, Evaluated, NewRule};
pub use audit::{AccessEntry, AuditEntry};
pub use auth::{
    ABSOLUTE_TIMEOUT, AuthenticatedSession, IDLE_TIMEOUT, TenantMembership, UserCredentials,
    UserProfile,
};
pub use bootstrap::{FirstRun, FirstRunRequest};
pub use catalog::PgCatalog;
pub use collectors::{
    Agent, CollectorRow, Enrolled, HEARTBEAT, Kind, NAME_VAR, QUIET_AFTER, Refused, Report,
    TOKEN_VAR, TokenRow, check_assignment,
};
pub use dashboards::{Dashboard, NewDashboard, Panel, Viz};
pub use discovery::{DiscoveredChild, DiscoveryReport};
pub use enrich::PgEnricher;
pub use facts::{DeviceFacts, IdentityReport};
pub use groups::{GroupSummary, NewGroup};
pub use ipam::{Address, NewSubnet, Subnet, Utilisation};
pub use slo::{NewSlo, Slo};
pub use incidents::IncidentRow;
pub use lease::{Claim, Job, LeaseRow, PERIOD, RENEW_EVERY, identity};
pub use maintenance::{MaintenanceWindow, NewWindow};
pub use notify::{Attempt, Channel, NewChannel, Outcome, Reservation, SentRecord};
pub use page::{Cursor, DEFAULT_PAGE, MAX_PAGE, Page};
pub use platform::PlatformTarget;
pub use pollable::{PollableDevice, SYSOBJECTID_KEY};
pub use resource::{NewResource, ResourceFilter};
pub use runbooks::{
    ApprovalRow, Claimed, FailedRun, QueuedTarget, RunContext, RunRow, RunState, RunStepRow,
    RunbookRow,
};
pub use sealed::PgSealedStore;
pub use tenants::{TenantChange, TenantRow};
pub use users::{
    AdminUser, Change, INVITATION_VALID_FOR, Invited, Member, PendingInvitation,
};
pub use searches::{NewSearch, SavedSearch};
pub use sites::{Location, SiteOverview, StatusCounts};
pub use sso::{OrgAuditEntry, PasswordPolicy, Provider, Provisioned, SignInOption};
pub use store::{Config, PgStore};
