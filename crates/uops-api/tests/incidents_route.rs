//! `GET /api/v1/incidents` and its timeline, through HTTP — M9.
//!
//! The store proves the queries and `uops-incident` proves the rules. What only these can
//! settle is the chain: a session proves a role, the incident's membership doubles as its
//! tenant check, and the timeline reads six signals out of `ClickHouse` for whichever
//! resources that membership named.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::{Duration, Utc};
use tower::ServiceExt as _;
use uops_api::{AppState, CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, TENANT_HEADER};
use uops_core::{IncidentId, OrgId, ResourceId, Role, Secret, TenantId};
use uops_secrets::password;
use uops_store_ch::{ChClient, ChConfig, ChStore, LogRow, LogStore};
use uops_store_pg::{Config, NewResource, PgStore};

fn telemetry() -> ChStore {
    ChStore::new(ChClient::new(ChConfig {
        user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "uops".into()),
        password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "uops".into()),
        ..ChConfig::from_env()
    }))
}

async fn control_plane() -> PgStore {
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
    telemetry: ChStore,
    tenant: TenantId,
    session: String,
    csrf: String,
}

async fn fixture(slug: &str, role: Role) -> Fixture {
    let store = control_plane().await;
    let org = OrgId::new();
    let tenant = TenantId::new();
    let unique = tenant.into_uuid().simple().to_string();

    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("inc-org-{unique}"))
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("inc-{slug}"))
        .bind(format!("{slug}-{unique}"))
        .execute(store.pool())
        .await
        .expect("tenant");

    let email = format!("{slug}-{unique}@example.invalid");
    let hash = password::hash(&Secret::new("pw".to_owned())).expect("hash");
    let user = store
        .create_user(org, &email, "Tester", &hash)
        .await
        .expect("user");
    store
        .grant_role(user, tenant, role, None)
        .await
        .expect("grant");

    // Through the login route rather than by minting a session row, so the cookies are
    // the ones a browser would hold and the CSRF pair is the one the middleware expects.
    let (session, csrf) = sign_in(&store, &email).await;
    Fixture {
        store,
        telemetry: telemetry(),
        tenant,
        session,
        csrf,
    }
}

async fn sign_in(store: &PgStore, email: &str) -> (String, String) {
    let response = uops_api::router(AppState::new(store.clone(), telemetry()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": email, "password": "pw" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let mut session = String::new();
    let mut csrf = String::new();
    for value in response.headers().get_all(header::SET_COOKIE) {
        let text = value.to_str().unwrap();
        let (pair, _) = text.split_once("; ").unwrap();
        let (name, v) = pair.split_once('=').unwrap();
        if name == SESSION_COOKIE {
            v.clone_into(&mut session);
        } else if name == CSRF_COOKIE {
            v.clone_into(&mut csrf);
        }
    }
    (session, csrf)
}

impl Fixture {
    fn app(&self) -> Router {
        uops_api::router(AppState::new(self.store.clone(), self.telemetry.clone()))
    }

    fn get(&self, uri: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header(
                header::COOKIE,
                format!(
                    "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                    self.session, self.csrf
                ),
            )
            .header(TENANT_HEADER, self.tenant.to_string())
            .body(Body::empty())
            .unwrap()
    }

    fn post(&self, uri: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(
                header::COOKIE,
                format!(
                    "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                    self.session, self.csrf
                ),
            )
            .header(TENANT_HEADER, self.tenant.to_string())
            .header(CSRF_HEADER, self.csrf.clone())
            .body(Body::empty())
            .unwrap()
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = self.app().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// An incident with one firing alert on one device.
    async fn incident(&self) -> (IncidentId, ResourceId) {
        let scope = uops_core::TenantScope::system(self.tenant);
        let device = self
            .store
            .create_resource(
                &scope,
                &NewResource::new(uops_core::ResourceKind::Device, "rtr-01"),
            )
            .await
            .expect("device")
            .id;

        let rule = uuid::Uuid::now_v7();
        sqlx::query(
            "INSERT INTO alert_rule (id, tenant_id, name, kind, query, condition, severity, created_by)
             VALUES ($1, $2, 'cpu', 'threshold', '{}'::jsonb, '{}'::jsonb, 'critical', NULL)",
        )
        .bind(rule)
        .bind(self.tenant.into_uuid())
        .execute(self.store.pool())
        .await
        .expect("rule");

        let alert = uuid::Uuid::now_v7();
        sqlx::query(
            "INSERT INTO alert_state
                (id, tenant_id, rule_id, resource_id, dedup_key, state, since, last_eval)
             VALUES ($1, $2, $3, $4, $5, 'firing', now(), now())",
        )
        .bind(alert)
        .bind(self.tenant.into_uuid())
        .bind(rule)
        .bind(device.into_uuid())
        .bind(format!("{rule}:{device}"))
        .execute(self.store.pool())
        .await
        .expect("alert");

        let id = self
            .store
            .open_incident(
                &scope,
                alert,
                "critical",
                "cpu — one device",
                Utc::now(),
                None,
            )
            .await
            .expect("incident");
        (id, device)
    }
}

#[tokio::test]
async fn an_incident_lists_with_its_candidate_named() {
    let f = fixture("list", Role::Viewer).await;
    let (id, device) = f.incident().await;

    let (status, body) = f.call(f.get("/api/v1/incidents")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let rows = body.as_array().expect("a list");
    assert_eq!(rows.len(), 1, "{body}");
    assert_eq!(rows[0]["id"], id.to_string());
    assert_eq!(rows[0]["state"], "open");
    assert_eq!(rows[0]["severity"], "critical");
    assert_eq!(rows[0]["alerts"], 1);
    // §2.4: sent even when zero. A suppression nobody can see is indistinguishable from
    // a bug.
    assert_eq!(rows[0]["suppressed"], 0);
    assert_eq!(rows[0]["candidate_resource_id"], device.to_string());
    assert_eq!(
        rows[0]["candidate_name"], "rtr-01",
        "the candidate is named, not just identified: {body}"
    );
    assert_eq!(rows[0]["candidate_absent_because"], "");
}

#[tokio::test]
async fn a_timeline_reads_every_signal_and_says_which_expired() {
    // The Investigation Workspace's query, through HTTP. The assertion that matters is
    // not the log line — it is that an *expired* signal comes back labelled rather than
    // empty, because an empty row reads as "nothing was happening".
    let f = fixture("timeline", Role::Viewer).await;
    let (id, device) = f.incident().await;

    let marker = format!("inc-{}", uuid::Uuid::now_v7().simple());
    let at = Utc::now() - Duration::minutes(1);
    f.telemetry
        .insert_logs(&[LogRow {
            tenant_id: f.tenant,
            resource_id: device,
            site_id: uops_core::SiteId::nil(),
            observed_at: at,
            ingested_at: at,
            source_kind: "syslog".to_owned(),
            source_vendor: String::new(),
            severity: "error".to_owned(),
            facility: 1,
            body: marker.clone(),
            attributes: std::collections::BTreeMap::new(),
            trace_id: String::new(),
            span_id: String::new(),
        }])
        .await
        .expect("log");

    let (status, body) = f
        .call(f.get(&format!("/api/v1/incidents/{id}/timeline")))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let tracks = body["tracks"].as_array().expect("tracks");
    assert_eq!(tracks.len(), 6, "every signal has a track: {body}");
    assert_eq!(body["resources"].as_array().expect("resources").len(), 1);

    let track = |signal: &str| {
        tracks
            .iter()
            .find(|t| t["signal"] == signal)
            .unwrap_or_else(|| panic!("{signal} has a track"))
            .clone()
    };

    let logs = track("log");
    assert_eq!(logs["coverage"], "whole");
    assert_eq!(logs["retention_days"], 365);
    let found = logs["rows"].as_array().expect("rows");
    assert!(
        found.iter().any(|row| row
            .as_array()
            .is_some_and(|cells| cells.iter().any(|v| v == &marker))),
        "the log written into the window comes back: {found:?}"
    );

    // Every signal is covered for a window this recent, and each says how long it keeps
    // rows so the screen can explain an expiry without hard-coding a retention.
    assert_eq!(track("flow")["coverage"], "whole");
    assert_eq!(track("flow")["retention_days"], 7);
    assert_eq!(track("trace")["retention_days"], 7);
    assert_eq!(track("state")["retention_days"], 1095);
}

#[tokio::test]
async fn a_timeline_over_an_old_window_reports_the_expired_signals() {
    // The same request with a window past what flows and spans keep. They come back
    // `expired` with no rows, which is a different fact from a quiet hour — and the
    // screen has no way to tell them apart unless the API says which.
    let f = fixture("expired", Role::Viewer).await;
    let (id, _) = f.incident().await;

    let start =
        (Utc::now() - Duration::days(30)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let end = (Utc::now() - Duration::days(29)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let (status, body) = f
        .call(f.get(&format!(
            "/api/v1/incidents/{id}/timeline?start={start}&end={end}"
        )))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let tracks = body["tracks"].as_array().expect("tracks");
    let coverage = |signal: &str| {
        tracks
            .iter()
            .find(|t| t["signal"] == signal)
            .expect("a track")["coverage"]
            .clone()
    };

    assert_eq!(coverage("flow"), "expired");
    assert_eq!(coverage("trace"), "expired");
    assert_eq!(coverage("log"), "whole", "logs are kept a year");
}

#[tokio::test]
async fn acknowledging_takes_responsibility_without_changing_the_state() {
    // The same rule an alert acknowledgement holds: the incident stays in the list, still
    // open, with a name against it.
    let f = fixture("ack", Role::Operator).await;
    let (id, _) = f.incident().await;

    let (status, body) = f.call(f.post(&format!("/api/v1/incidents/{id}/ack"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "open", "acknowledging is not resolving");
    assert!(body["acked_at"].is_string(), "{body}");
}

#[tokio::test]
async fn closing_is_an_operators_claim_and_is_not_idempotent() {
    // §2.1. Closing says it is understood, so the second attempt is two people each
    // believing they were the one who understood it — and the second deserves to be told.
    let f = fixture("close", Role::Operator).await;
    let (id, _) = f.incident().await;

    let (status, body) = f
        .call(f.post(&format!("/api/v1/incidents/{id}/close")))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "closed");
    assert!(body["closed_at"].is_string());

    let (again, _) = f
        .call(f.post(&format!("/api/v1/incidents/{id}/close")))
        .await;
    assert_eq!(again, StatusCode::NOT_FOUND, "closing twice is refused");
}

#[tokio::test]
async fn a_viewer_may_not_close() {
    // Closing is a statement about the estate. Reading it is not.
    let f = fixture("viewer", Role::Viewer).await;
    let (id, _) = f.incident().await;

    let (status, _) = f
        .call(f.post(&format!("/api/v1/incidents/{id}/close")))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (read, _) = f.call(f.get("/api/v1/incidents")).await;
    assert_eq!(read, StatusCode::OK, "but they may look");
}

#[tokio::test]
async fn a_timeline_for_an_incident_in_another_tenant_is_not_found() {
    // The membership read *is* the tenant check, so this is the test that the two cannot
    // get out of step. A leak here is a leak of another tenant's logs, metrics, flows and
    // traces at once.
    let mine = fixture("mine", Role::Operator).await;
    let theirs = fixture("theirs", Role::Operator).await;
    let (id, _) = theirs.incident().await;

    let (status, _) = mine
        .call(mine.get(&format!("/api/v1/incidents/{id}/timeline")))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (list, body) = mine.call(mine.get("/api/v1/incidents")).await;
    assert_eq!(list, StatusCode::OK);
    assert!(
        body.as_array().expect("a list").is_empty(),
        "and it is not in the list either: {body}"
    );
}

// ---- topology suppression ------------------------------------------------------

impl Fixture {
    fn put(&self, uri: &str, body: &serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(uri)
            .header(
                header::COOKIE,
                format!(
                    "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                    self.session, self.csrf
                ),
            )
            .header(TENANT_HEADER, self.tenant.to_string())
            .header(CSRF_HEADER, self.csrf.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn audit_log(
        &self,
    ) -> Vec<(String, Option<serde_json::Value>, Option<serde_json::Value>)> {
        self.store
            .audit_entries(self.tenant, 50)
            .await
            .unwrap()
            .into_iter()
            .map(|e| (e.action, e.before, e.after))
            .collect()
    }
}

#[tokio::test]
async fn suppression_is_off_until_somebody_turns_it_on_and_that_is_audited() {
    // M9 §2.4's last open acceptance criterion. Until this route existed, switching
    // suppression on was a database update and there was nothing to audit — so "a decision
    // with an audit entry rather than a default somebody inherits" was a sentence in a
    // document with nothing behind it.
    let f = fixture("suppress", Role::Admin).await;

    let (status, off) = f.call(f.get("/api/v1/incidents/suppression")).await;
    assert_eq!(status, StatusCode::OK, "{off}");
    assert_eq!(
        off["suppress_downstream_alerts"], false,
        "the default has to be off: suppression is the one thing in M9 that can cause a \
         missed outage"
    );

    let (status, on) = f
        .call(f.put(
            "/api/v1/incidents/suppression",
            &serde_json::json!({ "suppress_downstream_alerts": true }),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{on}");
    assert_eq!(on["suppress_downstream_alerts"], true);

    // It stuck, and the alert engine reads the same column.
    let (_, again) = f.call(f.get("/api/v1/incidents/suppression")).await;
    assert_eq!(again["suppress_downstream_alerts"], true);
    assert!(
        f.store
            .suppression_enabled(&uops_core::TenantScope::system(f.tenant))
            .await
            .unwrap()
    );

    // The audit row, with both sides. "Why did nobody get paged in March" is answered by
    // knowing what it was as well as what it became.
    let log = f.audit_log().await;
    let entry = log
        .iter()
        .find(|(action, _, _)| action == "incidents.suppression.set")
        .expect("switching it on is audited");
    assert_eq!(
        entry.1.as_ref().unwrap()["suppress_downstream_alerts"],
        false
    );
    assert_eq!(
        entry.2.as_ref().unwrap()["suppress_downstream_alerts"],
        true
    );
    assert_eq!(entry.2.as_ref().unwrap()["changed"], true);
}

#[tokio::test]
async fn turning_suppression_off_is_audited_too_and_a_no_op_says_so() {
    // The obvious reading is that switching it *on* is the risky direction, so that is the
    // one to record. But the record exists to answer "why did nobody get paged in March",
    // and the answer is as often "it was on then and it is off now".
    let f = fixture("unsuppress", Role::Admin).await;

    f.call(f.put(
        "/api/v1/incidents/suppression",
        &serde_json::json!({ "suppress_downstream_alerts": true }),
    ))
    .await;
    f.call(f.put(
        "/api/v1/incidents/suppression",
        &serde_json::json!({ "suppress_downstream_alerts": false }),
    ))
    .await;

    let log = f.audit_log().await;
    let sets: Vec<_> = log
        .iter()
        .filter(|(action, _, _)| action == "incidents.suppression.set")
        .collect();
    assert_eq!(sets.len(), 2, "both directions are recorded");

    // Newest first, so the second write is the first row.
    assert_eq!(
        sets[0].1.as_ref().unwrap()["suppress_downstream_alerts"],
        true
    );
    assert_eq!(
        sets[0].2.as_ref().unwrap()["suppress_downstream_alerts"],
        false
    );

    // Clicking the switch twice produces a row that says nothing happened, rather than a
    // second row that looks like a decision.
    f.call(f.put(
        "/api/v1/incidents/suppression",
        &serde_json::json!({ "suppress_downstream_alerts": false }),
    ))
    .await;
    let log = f.audit_log().await;
    let latest = log
        .iter()
        .find(|(action, _, _)| action == "incidents.suppression.set")
        .expect("recorded");
    assert_eq!(latest.2.as_ref().unwrap()["changed"], false);
}

#[tokio::test]
async fn an_operator_can_read_the_setting_and_cannot_change_it() {
    // Everything else in this module is Operator. This one is Admin, because it decides
    // whether the product will decline to wake somebody up — and "will this product decide
    // not to page me" is still a question anybody carrying a pager may ask.
    let f = fixture("supprole", Role::Operator).await;

    let (status, view) = f.call(f.get("/api/v1/incidents/suppression")).await;
    assert_eq!(status, StatusCode::OK, "{view}");

    let (status, refused) = f
        .call(f.put(
            "/api/v1/incidents/suppression",
            &serde_json::json!({ "suppress_downstream_alerts": true }),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");

    // And nothing changed.
    assert!(
        !f.store
            .suppression_enabled(&uops_core::TenantScope::system(f.tenant))
            .await
            .unwrap()
    );
}

/// M11 §3: a security event appears on the Investigation Workspace timeline beside the
/// metrics and logs for the same resource, on the same axis, **with no new timeline code**.
///
/// # Why this is the criterion that justifies §2.1
///
/// §2.1 decided a security event is an `events` row rather than a table of its own, and
/// the argument was that the timeline already reads that table — `uops_query::timeline`'s
/// `SIGNALS` has had `Event` in it since M9, drawing an empty track. This is the test that
/// the argument was true rather than plausible: an event written for the incident's
/// resource comes back on the `event` track, next to the log, from the same request.
///
/// If a second table had been added instead, this would have needed a second query, a
/// second retention rule and a merge — and the Investigation Workspace would have had to
/// learn that two of its tracks are the same kind of thing.
#[tokio::test]
async fn a_security_event_lands_on_the_timeline_beside_the_log() {
    let f = fixture("sec-timeline", Role::Viewer).await;
    let (id, device) = f.incident().await;

    let at = Utc::now() - Duration::minutes(1);
    let marker = format!("denied-{}", uuid::Uuid::now_v7().simple());

    // A log and an event about the same device, in the same minute. The pair is the point:
    // "on the same axis" is only meaningful if something else is on it.
    f.telemetry
        .insert_logs(&[LogRow {
            tenant_id: f.tenant,
            resource_id: device,
            site_id: uops_core::SiteId::nil(),
            observed_at: at,
            ingested_at: at,
            source_kind: "syslog".to_owned(),
            source_vendor: String::new(),
            severity: "error".to_owned(),
            facility: 1,
            body: "the raw line the event came from".to_owned(),
            attributes: std::collections::BTreeMap::new(),
            trace_id: String::new(),
            span_id: String::new(),
        }])
        .await
        .expect("log");

    uops_store_ch::EventStore::insert_events(
        &f.telemetry,
        &[uops_store_ch::EventRow {
            tenant_id: f.tenant,
            resource_id: device,
            site_id: uops_core::SiteId::nil(),
            observed_at: at,
            ingested_at: at,
            source_kind: "syslog".to_owned(),
            source_vendor: "fortinet".to_owned(),
            severity: "warn".to_owned(),
            event_category: "network".to_owned(),
            event_type: "denied".to_owned(),
            summary: marker.clone(),
            attributes: [
                ("source.ip".to_owned(), "198.51.100.7".to_owned()),
                ("destination.port".to_owned(), "22".to_owned()),
            ]
            .into_iter()
            .collect(),
        }],
    )
    .await
    .expect("event");

    let (status, body) = f
        .call(f.get(&format!("/api/v1/incidents/{id}/timeline")))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let tracks = body["tracks"].as_array().expect("tracks");
    let events = tracks
        .iter()
        .find(|t| t["signal"] == "event")
        .expect("the event track exists");

    assert_eq!(events["coverage"], "whole");
    assert_eq!(
        events["retention_days"], 365,
        "events keep as long as logs — 0006_events_states.sql"
    );

    let rows = events["rows"].as_array().expect("rows");
    assert!(
        rows.iter().any(|row| row
            .as_array()
            .is_some_and(|cells| cells.iter().any(|v| v == &marker))),
        "the security event comes back on its own track: {rows:?}"
    );

    // And the log is still there, from the same request. One axis, two signals.
    let logs = tracks
        .iter()
        .find(|t| t["signal"] == "log")
        .expect("the log track exists");
    assert!(
        !logs["rows"].as_array().expect("rows").is_empty(),
        "the line the event was derived from is on the timeline too"
    );
}
