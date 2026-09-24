//! What the daemon is told, and what it refuses to start without.
//!
//! # How a flow record gets a tenant
//!
//! `docs/M7-flow.md` §2.6, and it is the decision this file exists to record. A flow
//! datagram **carries no tenant and cannot be made to**. It carries an exporter address,
//! an observation domain and some counters, all of them chosen by the sender.
//!
//! So the tenant comes from **where the datagram arrived**: one listener per tenant, on
//! its own address or port. The binding is the one thing the sender cannot influence.
//!
//! The alternative — resolve the exporter's address to a resource and take that
//! resource's tenant — is rejected, and not as a matter of taste. It would let an
//! unauthenticated packet select its own tenant by choosing a source address, so a forged
//! datagram writes into whichever customer the attacker names. For an MSP that is a
//! cross-tenant write triggered by a spoofed UDP packet, which is the class of bug
//! `TenantScope` and the composite foreign keys exist to make impossible.
//!
//! # An unknown exporter is not refused
//!
//! It is resolved like any other sender: matched, or given a provisional resource and a
//! review item. SPEC §M0.2 rule 1 — *never block ingestion* — and the same argument
//! `uops-collector-syslog` records: an allow-list loses the data of every device somebody
//! forgot to register, which are disproportionately the devices involved in an incident.
//!
//! §2.6 said the opposite until it was checked against the collector it claimed to copy.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use serde::Deserialize;

/// Where the listener list is read from.
pub const CONFIG_PATH: &str = "UOPS_FLOW_CONFIG";

/// One tenant's ingress.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Listener {
    /// The tenant's slug, as `tenant.slug` in `PostgreSQL`.
    ///
    /// A slug rather than a uuid because a human writes this file, and a mistyped uuid is
    /// a silent misattribution where a mistyped slug fails at startup.
    pub tenant: String,
    /// `0.0.0.0:2055` — the address to receive on.
    ///
    /// One socket, not one per protocol: every one of the four arrives over UDP and the
    /// first bytes say which it is. Collectors that insist on a port per protocol make an
    /// operator configure their exporters around an implementation detail.
    pub udp: SocketAddr,
}

/// The whole file.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct File {
    #[serde(default)]
    pub listeners: Vec<Listener>,
}

/// What `main` needs.
#[derive(Clone, Debug)]
pub struct Config {
    pub listeners: Vec<Listener>,
    /// The enrolment token, or `None` to stay out of the registry — M12 §2.3.
    ///
    /// Unset means this collector behaves exactly as it did before migration 0025. See
    /// `uops_store_pg::Agent` for why enrolment is opt-in and what that costs.
    pub collector_token: Option<String>,
    /// What this collector calls itself in the inventory. Defaults to the hostname.
    pub collector_name: String,
    pub postgres: uops_store_pg::Config,
    pub clickhouse: uops_store_ch::ChConfig,
    /// How many decoded flows may wait between a receiver and the workers.
    pub queue: usize,
    /// How many tasks resolve identity in parallel, per listener.
    ///
    /// One is enough for the cached path — a mutex and an LRU lookup. It is not enough
    /// for the uncached one: a resolution that reaches `PostgreSQL` awaits, and a single
    /// worker would stall every flow behind it.
    pub workers: usize,
    /// What the socket asks for as its receive buffer.
    pub receive_buffer: usize,
}

/// The default ingest queue, in flows.
///
/// Flow arrives in bursts — one datagram can hold thirty records, and an exporter under
/// load sends them back to back — so this absorbs a burst while the workers are awaiting
/// a resolution. Bounded, because the point of a bound is that the loss is counted rather
/// than an out-of-memory kill that loses everything.
pub const DEFAULT_QUEUE: usize = 100_000;

/// What to ask the kernel for, in bytes.
///
/// Eight megabytes, the same as the syslog collector asks for and for the same reason: the
/// buffer's job is to hold a burst while userspace is busy, and one sized for a single
/// datagram drops the rest of it. A drop here is invisible — it happens in the kernel,
/// before any counter this process owns.
pub const DEFAULT_RECEIVE_BUFFER: usize = 8 * 1024 * 1024;

impl Config {
    /// Read the environment and the listener file.
    ///
    /// # Errors
    ///
    /// Anything missing or unreadable, named. A daemon that starts with no listeners sits
    /// there looking healthy and ingesting nothing, which is the failure this product is
    /// least able to notice.
    pub fn load() -> Result<Self, String> {
        let path = std::env::var(CONFIG_PATH)
            .map_err(|_| format!("{CONFIG_PATH} is not set; it must name the listener file"))?;
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("{CONFIG_PATH}={path} could not be read: {e}"))?;
        let file: File = serde_yaml_ng::from_str(&text)
            .map_err(|e| format!("{path} is not a valid listener file: {e}"))?;

        Self::from_parts(file, std::env::var("DATABASE_URL").ok())
    }

    fn from_parts(file: File, database_url: Option<String>) -> Result<Self, String> {
        validate(&file.listeners)?;

        let postgres = uops_store_pg::Config {
            url: database_url.ok_or_else(|| "DATABASE_URL is not set".to_owned())?,
            ..uops_store_pg::Config::default()
        };

        Ok(Self {
            listeners: file.listeners,
            collector_token: std::env::var(uops_store_pg::TOKEN_VAR)
                .ok()
                .filter(|t| !t.trim().is_empty()),
            collector_name: uops_store_pg::Agent::default_name(),
            postgres,
            clickhouse: uops_store_ch::ChConfig::from_env(),
            queue: DEFAULT_QUEUE,
            workers: 4,
            receive_buffer: DEFAULT_RECEIVE_BUFFER,
        })
    }
}

/// Refuse a listener list that cannot mean what it says.
fn validate(listeners: &[Listener]) -> Result<(), String> {
    if listeners.is_empty() {
        return Err("the listener file defines no listeners".to_owned());
    }

    let mut addresses = BTreeSet::new();
    for listener in listeners {
        if listener.tenant.trim().is_empty() {
            return Err("a listener has no tenant".to_owned());
        }
        // Two tenants on one address is the misconfiguration that matters: whichever
        // bound first would receive the other's flow and file it under its own customer.
        // The bind would fail anyway, but late and with an error naming the socket rather
        // than the mistake.
        if !addresses.insert(listener.udp) {
            return Err(format!(
                "{} is named by more than one listener; a socket belongs to one tenant",
                listener.udp
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(tenant: &str, udp: &str) -> Listener {
        Listener {
            tenant: tenant.to_owned(),
            udp: udp.parse().unwrap(),
        }
    }

    #[test]
    fn a_file_with_no_listeners_is_refused() {
        // Starting is worse than failing: the daemon would look healthy and ingest
        // nothing, and nothing downstream can tell that from a quiet network.
        assert!(validate(&[]).is_err());
    }

    #[test]
    fn two_tenants_cannot_share_a_socket() {
        let both = [
            listener("acme", "0.0.0.0:2055"),
            listener("globex", "0.0.0.0:2055"),
        ];
        let message = validate(&both).unwrap_err();
        assert!(message.contains("more than one listener"), "{message}");
    }

    #[test]
    fn one_tenant_may_have_several_listeners() {
        // A site with its own collector address is an ordinary thing to want.
        let many = [
            listener("acme", "10.0.0.1:2055"),
            listener("acme", "10.0.1.1:2055"),
        ];
        assert!(validate(&many).is_ok());
    }

    #[test]
    fn a_listener_with_no_tenant_is_refused() {
        assert!(validate(&[listener("  ", "0.0.0.0:2055")]).is_err());
    }

    #[test]
    fn the_database_url_is_required() {
        let file = File {
            listeners: vec![listener("acme", "0.0.0.0:2055")],
        };
        assert!(Config::from_parts(file, None).is_err());
    }

    #[test]
    fn a_listener_file_parses() {
        let text = "listeners:\n  - tenant: acme\n    udp: 0.0.0.0:2055\n";
        let file: File = serde_yaml_ng::from_str(text).unwrap();
        assert_eq!(file.listeners, vec![listener("acme", "0.0.0.0:2055")]);
    }

    /// The file this product ships, parsed by the code that will read it.
    ///
    /// Nothing else checked it. `deploy/docker-compose.yml` mounts it and the daemon fails at
    /// start-up naming the file, which is right at run time and far too late in a repository:
    /// until CI grew a step asserting the collectors are still running, a malformed file here
    /// would have exited its container a second after `compose up` and the build would have
    /// gone green. `include_str!` moves the failure to `cargo test`.
    #[test]
    fn the_shipped_listener_file_parses() {
        let text = include_str!("../../../deploy/flow/listeners.yaml");
        let file: File = serde_yaml_ng::from_str(text).expect("deploy/flow/listeners.yaml");

        assert!(
            !file.listeners.is_empty(),
            "a shipped file with no listeners would start a daemon that ingests nothing"
        );
        // The tenant the rest of the compose stack uses. A slug no tenant has fails at
        // start-up, which is the one error this file can hold that parsing cannot catch.
        assert!(
            file.listeners.iter().any(|l| l.tenant == "example"),
            "{:?}",
            file.listeners
        );
    }
}
