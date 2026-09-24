//! `GET /api/v1/health` — the one route with no authentication.
//!
//! Read by a container orchestrator that has no session and cannot get one, so it is
//! outside the audit layer and outside `Caller`. That makes it the one place where a
//! careless addition leaks something to an unauthenticated caller, so what it reports
//! is deliberately short:
//!
//! * whether each store answered
//! * the `ClickHouse` server version
//!
//! The version is there because on-premise support asks for it constantly and because
//! the text index syntax moved between 25.x and 26.x — knowing which server is actually
//! running is the difference between a five-minute diagnosis and an afternoon. It is
//! also the one piece of genuine reconnaissance value here, which is the trade: a
//! version string is not a secret to anyone who can reach the port, and an operator who
//! cannot see it debugs blind.
//!
//! Nothing else. Not the database URL, not the tenant count, not the build path.
//!
//! # Degraded is still 200
//!
//! A store being unreachable makes `ok` false and leaves the status at 200. The
//! alternative — 503 when `ClickHouse` is down — makes an orchestrator restart or
//! remove a process that is working correctly and telling you the truth about its
//! dependency. A restart does not fix someone else's database.

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use uops_store_ch::TelemetryStore;

use crate::state::AppState;

/// What `/api/v1/health` returns.
#[derive(Debug, Serialize)]
pub struct Health {
    /// True only when every store answered.
    pub ok: bool,
    /// This product's version — `docs/packaging.md` §4.5.
    ///
    /// Reported here, on the one endpoint outside authentication, because the people who need
    /// it cannot authenticate: an operator checking what a host is running mid-upgrade, and a
    /// load balancer deciding whether to send it traffic. Since no artefact was published there
    /// was nothing to ask about; the moment a release exists, "which version is this" becomes
    /// the first question of every upgrade and every bug report.
    ///
    /// It is a version disclosure on an unauthenticated endpoint, which a security review will
    /// note. The trade is taken deliberately and the precedent was already here — the response
    /// has reported `ClickHouse`'s version, unauthenticated, since M1, and a dependency's
    /// version is the more targetable of the two. An installation that wants neither behind a
    /// proxy can strip the field; what it cannot do is operate a fleet it cannot ask.
    pub version: &'static str,
    pub control_plane: ComponentHealth,
    pub telemetry: ComponentHealth,
}

/// One dependency's state. No error text: a connection error can carry a host, a port
/// and sometimes a username, and this is read by anyone who can reach the port.
#[derive(Debug, Serialize)]
pub struct ComponentHealth {
    pub reachable: bool,
    /// The server's own version, when it answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// `GET /api/v1/health`
pub async fn health(State(state): State<AppState>) -> Json<Health> {
    let control_plane = ComponentHealth {
        reachable: state.store.health().await.is_ok(),
        version: None,
    };

    let telemetry = match state.telemetry.health().await {
        Ok(h) => ComponentHealth {
            reachable: h.reachable,
            version: Some(h.version),
        },
        Err(_) => ComponentHealth {
            reachable: false,
            version: None,
        },
    };

    Json(Health {
        ok: control_plane.reachable && telemetry.reachable,
        // The workspace version, which is what a release tag sets — so this is the tag, and a
        // build from an untagged working tree says so by carrying the last one.
        version: env!("CARGO_PKG_VERSION"),
        control_plane,
        telemetry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The field is in the JSON, under that name, with that value.
    ///
    /// Near-tautological about the constant and not about the wire: what this catches is a
    /// `#[serde(skip_serializing_if)]` or a rename arriving on the struct and quietly removing
    /// the one thing every upgrade and every bug report starts by asking. The neighbouring
    /// `ComponentHealth::version` already carries a `skip_serializing_if`, so that is not a
    /// hypothetical mistake in this file.
    #[test]
    fn health_reports_the_products_own_version() {
        let body = serde_json::to_string(&Health {
            ok: true,
            version: env!("CARGO_PKG_VERSION"),
            control_plane: ComponentHealth {
                reachable: true,
                version: None,
            },
            telemetry: ComponentHealth {
                reachable: true,
                version: Some("26.8.9.10".to_owned()),
            },
        })
        .expect("serialise");

        assert!(
            body.contains(&format!(r#""version":"{}""#, env!("CARGO_PKG_VERSION"))),
            "the product version is not in the response: {body}"
        );
        assert!(
            !env!("CARGO_PKG_VERSION").is_empty(),
            "a build with no version would report an empty string as though it meant something"
        );
    }

    /// A dependency that did not answer carries no version, and the field disappears rather
    /// than reporting `null` — which a chart or a check would render as a version.
    #[test]
    fn an_unreachable_dependency_reports_no_version_at_all() {
        let body = serde_json::to_string(&Health {
            ok: false,
            version: env!("CARGO_PKG_VERSION"),
            control_plane: ComponentHealth {
                reachable: false,
                version: None,
            },
            telemetry: ComponentHealth {
                reachable: false,
                version: None,
            },
        })
        .expect("serialise");

        assert!(!body.contains("null"), "{body}");
        // The product's own version is still there: this process answered, whatever its
        // dependencies did, and an upgrade needs to know which one is refusing to start.
        assert!(body.contains(env!("CARGO_PKG_VERSION")), "{body}");
    }
}
