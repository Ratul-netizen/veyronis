//! The route table.
//!
//! Assembled in one place so the surface reads as a list rather than being discovered by
//! grepping for attributes. SPEC §M1 has the full intended surface; this is what exists.
//!
//! `POST /api/v1/query` takes the AST from SPEC §M0.5 directly — the same type the UI
//! builds, saved alerts are instances of, and the M6 text language will parse onto.
//! There is one path to telemetry, and this is it.

pub mod alerts;
pub mod audit_log;
pub mod auth;
pub mod channels;
pub mod collectors;
pub mod credentials;
pub mod dashboards;
pub mod discovery;
pub mod groups;
pub mod health;
pub mod incidents;
pub mod maintenance;
pub mod query;
pub mod resources;
pub mod searches;
pub mod servicemap;
pub mod sites;
pub mod slos;
pub mod subnets;
pub mod sso;
pub mod runbooks;
pub mod topology;
pub mod users;
pub mod path;

use axum::routing::{any, delete, get, patch, post, put};
use axum::{Router, middleware};

use crate::audit;
use crate::error::ApiError;
use crate::state::AppState;

/// Everything under `/api/v1`.
///
/// Long, and deliberately one function: this module exists so the API surface reads as a
/// list rather than being discovered by grepping for attributes, and splitting it into
/// `inventory_routes()`, `telemetry_routes()` and `alerting_routes()` would trade that
/// for a lint. The day it stops being readable is the day to split it, and forty routes
/// is not that day.
#[allow(clippy::too_many_lines)]
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/me", get(auth::me))
        // Redeeming an invitation is unauthenticated because whoever holds the link has no
        // account yet — the token is the whole authorisation. Same discipline as `login`:
        // one sentence for every refusal, since distinguishing *expired* from *never
        // existed* confirms a token was once real.
        .route("/api/v1/invitations/{token}", post(users::accept))
        // Single sign-on -- M12 §2.2. The first three are unauthenticated because they
        // are reached by somebody who has not signed in; routes/sso.rs has the table of
        // what that exposes and what closes each hole. The rest need the admin role on
        // every tenant in the organization, which `OrgAdmin` explains.
        .route("/api/v1/auth/methods", get(sso::methods))
        .route("/api/v1/auth/oidc/{provider}/start", get(sso::start))
        .route("/api/v1/auth/oidc/callback", get(sso::callback))
        .route(
            "/api/v1/sso/providers",
            get(sso::list_providers).post(sso::create_provider),
        )
        .route(
            "/api/v1/sso/providers/{id}/enabled",
            patch(sso::set_provider_enabled),
        )
        .route(
            "/api/v1/sso/providers/{id}/grants",
            get(sso::list_grants).post(sso::grant).delete(sso::revoke_grant),
        )
        // Turning off password login for everybody but the break-glass account. A PUT
        // rather than a POST because it is a setting with two values, not an event.
        .route("/api/v1/sso/require", put(sso::set_required))
        // The organization-level half of the audit log: who signed in through a
        // provider, who was refused, and every use of the break-glass account.
        .route("/api/v1/sso/audit", get(sso::audit))
        // The collector inventory -- M12 §2.3. Every route needs the admin role on every
        // tenant in the organization, because an assignment decides whose telemetry a box
        // may carry, and in an MSP that is a decision about somebody else.
        //
        // There is no enrolment route: a collector enrols through PostgreSQL, which it
        // already holds credentials for. See routes/collectors.rs.
        .route("/api/v1/collectors", get(collectors::list))
        .route("/api/v1/collectors/{id}", delete(collectors::retire))
        .route(
            "/api/v1/collectors/{id}/tenants",
            post(collectors::assign).delete(collectors::unassign),
        )
        .route(
            "/api/v1/collectors/tokens",
            get(collectors::list_tokens).post(collectors::issue_token),
        )
        .route(
            "/api/v1/collectors/tokens/{id}",
            delete(collectors::revoke_token),
        )
        .route(
            "/api/v1/resources",
            get(resources::list).post(resources::create),
        )
        .route("/api/v1/resources/{id}", get(resources::get))
        .route("/api/v1/resources/{id}", delete(resources::decommission))
        .route(
            "/api/v1/resources/{id}/status",
            patch(resources::set_status),
        )
        .route(
            "/api/v1/credentials",
            get(credentials::list).post(credentials::create),
        )
        .route("/api/v1/credentials/{id}", delete(credentials::revoke))
        .route(
            "/api/v1/resources/{id}/credential",
            put(credentials::assign),
        )
        .route(
            "/api/v1/resources/{id}/identifiers",
            get(credentials::identifiers).put(credentials::set_identifiers),
        )
        .route("/api/v1/resources/{id}/groups", get(groups::of_resource))
        // Tags, not attributes. PUT replaces the whole map, which is how a tag is
        // removed; see the route's own docs.
        .route("/api/v1/resources/{id}/tags", put(groups::set_tags))
        .route("/api/v1/groups", get(groups::list).post(groups::create))
        .route(
            "/api/v1/groups/{id}",
            put(groups::rename).delete(groups::delete),
        )
        .route(
            "/api/v1/groups/{id}/members",
            post(groups::add_members).delete(groups::remove_members),
        )
        .route(
            "/api/v1/resources/{id}/maintenance",
            get(maintenance::for_resource),
        )
        .route(
            "/api/v1/maintenance",
            get(maintenance::list).post(maintenance::schedule),
        )
        .route(
            "/api/v1/maintenance/{id}",
            get(maintenance::get).delete(maintenance::cancel),
        )
        // An alert rule is a saved Query AST plus a condition — which is why "alert
        // from a saved search" needs no conversion: the client posts back the `query`
        // the search route returned. Reading is Viewer; everything else, acknowledgement
        // included, is Operator.
        .route(
            "/api/v1/alerts/rules",
            get(alerts::list_rules).post(alerts::create_rule),
        )
        .route(
            "/api/v1/alerts/rules/{id}",
            get(alerts::get_rule)
                .put(alerts::update_rule)
                .delete(alerts::delete_rule),
        )
        .route(
            "/api/v1/alerts/rules/{id}/enabled",
            patch(alerts::set_enabled),
        )
        .route("/api/v1/alerts", get(alerts::list_alerts))
        .route("/api/v1/alerts/{id}/ack", post(alerts::acknowledge))
        // Incidents -- M9. Read is Viewer; acknowledging and closing are Operator,
        // because both are statements a person makes about the estate. There is no POST
        // that *creates* one: §2.1 says an incident is produced by the alert engine and
        // by nothing else, and one that can be raised by hand is the first half of a
        // ticketing system.
        .route("/api/v1/incidents", get(incidents::list))
        .route(
            "/api/v1/incidents/{id}/timeline",
            get(incidents::timeline_of),
        )
        // Whether topology suppression may stop a notification — M9 §2.4. Reading is
        // Viewer, because "will this product decide not to page me" is a question anybody
        // carrying a pager may ask. Writing is Admin: it is the one setting in M9 that can
        // cause a missed outage.
        //
        // Above `/{id}` so that `suppression` is not read as an incident id.
        .route(
            "/api/v1/incidents/suppression",
            get(incidents::suppression).put(incidents::set_suppression),
        )
        .route("/api/v1/incidents/{id}/ack", post(incidents::acknowledge))
        .route("/api/v1/incidents/{id}/close", post(incidents::close))
        // A saved search is a stored Query AST — the same object the route below takes,
        // and the same one an M4 alert rule will be an instance of. Reading is Viewer;
        // saving is Operator, because a saved search is the team's question rather than
        // a personal bookmark.
        .route("/api/v1/searches", get(searches::list).post(searches::save))
        .route(
            "/api/v1/searches/{id}",
            get(searches::get)
                .put(searches::update)
                .delete(searches::delete),
        )
        // A dashboard is a document: a name and an ordered list of panels, each a Query
        // AST and a picture to draw it as. Adding or moving a panel is a PUT of the whole
        // thing — see the module docs for why there is no panel-level route.
        .route(
            "/api/v1/dashboards",
            get(dashboards::list).post(dashboards::create),
        )
        .route(
            "/api/v1/dashboards/{id}",
            get(dashboards::get)
                .put(dashboards::update)
                .delete(dashboards::delete),
        )
        // The link graph -- what M5's neighbour walk found out about how the estate is
        // wired. Read-only: edges come from a device naming its neighbour, not from
        // anybody drawing a line.
        // Runbooks — M10. The only routes in this API whose effect is a command reaching
        // somebody's equipment, and none of them sends one: `POST /runs` writes a row and
        // `uops-runner` picks it up. There is no PUT on a runbook, because editing writes
        // version n+1 — §2.1.
        .route(
            "/api/v1/runbooks",
            get(runbooks::list).post(runbooks::save),
        )
        .route(
            "/api/v1/runbooks/{id}",
            get(runbooks::get).delete(runbooks::retire),
        )
        // What a run *would* do, without creating one: the resolved targets by name and
        // the literal command that would be sent to each. A POST rather than a GET because
        // it resolves a selector across the estate, which is not a thing to put in a URL a
        // proxy will log.
        .route("/api/v1/runbooks/{id}/plan", post(runbooks::plan))
        .route("/api/v1/runbooks/{id}/runs", post(runbooks::start))
        .route("/api/v1/runs", get(runbooks::runs))
        .route("/api/v1/runs/{id}", get(runbooks::run))
        .route("/api/v1/runs/{id}/approve", post(runbooks::approve))
        .route("/api/v1/runs/{id}/cancel", post(runbooks::cancel))
        .route("/api/v1/topology", get(topology::get))
        // The service map -- M8 §2.6. The same posture as the topology above and for the
        // same reason: the edges are evidence rather than assertion, so there is nothing
        // to write. A GET rather than a POST because a window and a limit fit in a URL,
        // which the query AST does not.
        .route("/api/v1/service-map", get(servicemap::get))
        // Finding devices -- M5. Reading is Viewer; writing a job or dismissing a
        // candidate is Operator, because a discovery job is an instruction to send
        // packets across somebody's network and the ranges describe their estate.
        //
        // There is no `POST /discovery/jobs/{id}/run` yet: a sweep takes minutes, so it
        // cannot be the body of a request, and the runner that will own it arrives with
        // the scheduler.
        .route(
            "/api/v1/discovery/jobs",
            get(discovery::list_jobs).post(discovery::create_job),
        )
        .route(
            "/api/v1/discovery/jobs/{id}",
            get(discovery::get_job).delete(discovery::delete_job),
        )
        .route("/api/v1/discovery/runs", get(discovery::list_runs))
        .route(
            "/api/v1/discovery/candidates",
            get(discovery::list_candidates),
        )
        .route(
            "/api/v1/discovery/candidates/{id}/ignore",
            post(discovery::ignore_candidate),
        )
        // Where a page goes. Reading is Viewer; writing is Operator, the same as an
        // alert rule, because changing a channel changes who gets woken up.
        .route(
            "/api/v1/channels",
            get(channels::list).post(channels::create),
        )
        .route(
            "/api/v1/channels/{id}",
            get(channels::get)
                .put(channels::update)
                .delete(channels::delete),
        )
        // "Why did nobody get paged" — the refusals are in here too, which is the whole
        // reason it exists.
        .route("/api/v1/notifications", get(channels::sent))
        .route("/api/v1/sites", get(sites::list))
        // Address space — `docs/ipam.md`. Under Network in the UI, because a range is
        // inventory: what the estate is made of rather than what it is doing.
        .route(
            "/api/v1/subnets",
            get(subnets::list).post(subnets::declare),
        )
        .route("/api/v1/subnets/{id}", delete(subnets::forget))
        .route("/api/v1/subnets/{id}/addresses", get(subnets::addresses))
        // Service level objectives — `docs/slo.md`. Under Observability in the UI, beside
        // Services, because an objective is a statement about a service.
        .route("/api/v1/slos", get(slos::list).post(slos::set))
        .route("/api/v1/slos/{id}", delete(slos::remove))
        // The path to a target — `docs/traceroute.md`. A POST because it sends packets:
        // every other read here asks the database what it already knows.
        .route("/api/v1/path", post(path::run))
        // The two logs — SPEC §M0.8. Written since M1 by every handler and, until now,
        // readable only through psql: `audit_entries` and `access_entries` were called
        // from tests alone. Admin, because an audit log names people.
        .route("/api/v1/audit/changes", get(audit_log::changes))
        .route("/api/v1/audit/reads", get(audit_log::reads))
        // The people in an organization — `docs/user-administration.md`. `create_user`,
        // `grant_role`, `revoke_role` and `disable_user` have existed since M1 and were
        // called by seventeen test files and nothing in production; these are the callers.
        //
        // Two authorisations, because there are two questions. *Who is a person here* is
        // organization-level and takes `OrgAdmin`. *Who may see this customer* belongs to one
        // tenant and takes admin on the tenant in the header.
        .route("/api/v1/users", get(users::list).post(users::invite))
        .route("/api/v1/users/invitations", get(users::invitations))
        .route("/api/v1/users/invitations/{id}", delete(users::withdraw))
        .route("/api/v1/users/{id}/disable", post(users::disable))
        .route("/api/v1/users/{id}/enable", post(users::enable))
        .route("/api/v1/users/{id}/break-glass", post(users::break_glass))
        .route("/api/v1/tenants/roles", get(users::roles))
        .route(
            "/api/v1/users/{id}/role",
            put(users::grant).delete(users::revoke),
        )
        // Changing one's own password is not administration — every user needs it and no
        // role is required — so it sits on `/me` rather than among the routes above.
        .route("/api/v1/me/password", put(users::change_password))
        .route("/api/v1/sites/{id}/location", put(sites::place))
        .route("/api/v1/query", post(query::run))
        // The tail is its own route rather than a flag on the one above, because it is
        // its own physical query — time-ordered, so the `p_by_time` projection serves it
        // — and because its response carries a watermark that a search has no use for.
        .route("/api/v1/query/tail", post(query::tail))
        // Deliberately above the audit layer as well as outside authentication: an
        // orchestrator polling every five seconds would otherwise write an audit row
        // every five seconds, and an audit log that is mostly health checks is one
        // nobody reads. It establishes no scope, so the layer skips it anyway — this
        // route is simply where that stops being an accident.
        .route("/api/v1/health", get(health::health))
        // Anything else under /api is a 404 in problem+json, like every other error
        // here. It exists because uops-server may serve the web build as a fallback for
        // unmatched paths, and without this a mistyped API path would answer 200 with
        // an HTML page — which a client parses as JSON, fails on, and reports as
        // something other than "that endpoint does not exist".
        //
        // Static segments win over a wildcard in axum's router, so this never shadows a
        // real route.
        .route("/api/{*rest}", any(no_such_endpoint))
        // Wrapped around everything rather than a chosen list of routes: a request that
        // never establishes a scope leaves nothing to record and is skipped, so this
        // cannot be forgotten when a route is added. See crate::audit.
        .layer(middleware::from_fn_with_state(state.clone(), audit::layer))
        .with_state(state)
}

/// Every unmatched path under `/api`.
async fn no_such_endpoint() -> ApiError {
    ApiError::NotFound
}
