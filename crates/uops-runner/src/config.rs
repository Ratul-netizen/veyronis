//! Everything the runner reads from its environment.
//!
//! Three of these are chosen against convenience, and the third is the one worth arguing
//! about.
//!
//! **There is no default KEK**, for the poller's reason: a runner whose whole job is to
//! open credentials and act on devices must not start happily and then fail on every step.
//!
//! **There is no `ClickHouse`.** A run writes to `PostgreSQL` and nowhere else. If that ever
//! changes, it should change as a decision rather than by a variable appearing here.
//!
//! **The state directory has no default.** It holds `known_hosts` — the record of which
//! devices this deployment has decided to trust — and a default of `/tmp` or the working
//! directory would mean a container restart silently discarding every host key it had
//! learned, turning `accept-new` back into trust-on-every-use. An operator names a
//! persistent path or the runner does not start.

use std::path::PathBuf;
use std::time::Duration;

use uops_secrets::record::KeyId;
use uops_store_pg::Config as PgConfig;

/// The runner's configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub postgres: PgConfig,
    pub kek: KekSource,
    pub kek_id: KeyId,
    /// Where `known_hosts` and per-step key files live. Must persist across restarts.
    pub state_dir: PathBuf,
    /// How often the queue is asked when it was empty last time.
    pub poll_every: Duration,
    /// How long a run may sit in `running` before it is treated as abandoned.
    pub abandon_after: Duration,
}

/// Where the KEK is read from.
///
/// The poller's two shapes, for the poller's reasons: a file can have permissions, and a
/// variable is what a container platform's secret store usually presents as.
#[derive(Debug, Clone)]
pub enum KekSource {
    File(PathBuf),
    Env(String),
}

/// Something in the environment is unusable.
#[derive(Debug)]
pub struct ConfigError {
    pub variable: &'static str,
    pub problem: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never prints the value: the variables that reach this are the KEK's location and
        // a connection URL, and neither belongs in a support ticket.
        write!(f, "{} is not usable: {}", self.variable, self.problem)
    }
}

impl std::error::Error for ConfigError {}

fn number(name: &'static str, default: u64) -> Result<u64, ConfigError> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(raw) => raw.trim().parse().map_err(|_| ConfigError {
            variable: name,
            problem: "expected a positive whole number".to_owned(),
        }),
    }
}

impl Config {
    /// Read the environment.
    ///
    /// # Errors
    ///
    /// When no KEK is configured, when no state directory is named, or when a numeric
    /// variable is not a number.
    pub fn from_env() -> Result<Self, ConfigError> {
        let kek = match (
            std::env::var("UOPS_KEK_FILE").ok(),
            std::env::var("UOPS_KEK_HEX").ok(),
        ) {
            (Some(path), _) => KekSource::File(path.into()),
            (None, Some(_)) => KekSource::Env("UOPS_KEK_HEX".to_owned()),
            (None, None) => {
                return Err(ConfigError {
                    variable: "UOPS_KEK_FILE",
                    problem: "the runner cannot open a credential without a key-encryption \
                              key; set UOPS_KEK_FILE to a file of 64 hex characters, or \
                              UOPS_KEK_HEX to the characters themselves"
                        .to_owned(),
                });
            }
        };

        let state_dir = match std::env::var("UOPS_RUNNER_STATE_DIR") {
            Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir.trim()),
            _ => {
                return Err(ConfigError {
                    variable: "UOPS_RUNNER_STATE_DIR",
                    problem: "the runner keeps its known_hosts here, and a default would \
                              mean a restart quietly forgetting which devices this \
                              deployment had decided to trust. Name a directory that \
                              persists."
                        .to_owned(),
                });
            }
        };

        Ok(Self {
            postgres: PgConfig::from_env(),
            kek,
            kek_id: KeyId(std::env::var("UOPS_KEK_ID").unwrap_or_else(|_| "default".to_owned())),
            state_dir,
            poll_every: Duration::from_secs(number("UOPS_RUNNER_POLL_SECS", 5)?),
            abandon_after: Duration::from_secs(number("UOPS_RUNNER_ABANDON_SECS", 3600)?),
        })
    }

    /// What the startup banner says.
    ///
    /// Not `Display`: the config inside holds a URL with a password in it, and a `Display`
    /// impl is exactly the kind of thing that later gets used in an error message.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "postgres={} kek={} state={} poll={}s abandon={}s",
            redact(&self.postgres.url),
            match &self.kek {
                KekSource::File(p) => format!("file {}", p.display()),
                KekSource::Env(v) => format!("env {v}"),
            },
            self.state_dir.display(),
            self.poll_every.as_secs(),
            self.abandon_after.as_secs(),
        )
    }
}

/// A connection URL with any credentials removed.
///
/// A third copy, after `uops-server` and `uops-poller`, and for the same reason: the
/// binaries have no crate in common below them that is the right home for it, and a
/// dependency edge from this one to either would pull in a route table or an SNMP stack to
/// reuse nine lines. The tests below are this copy's.
fn redact(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    // rsplit: a password may itself contain an `@`.
    match rest.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}://{host}"),
        None => url.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_loses_its_credentials() {
        assert_eq!(
            redact("postgres://uops:hunter2@db.internal:5432/uops"),
            "postgres://db.internal:5432/uops"
        );
        assert_eq!(
            redact("postgres://uops:p@ss@db:5432/uops"),
            "postgres://db:5432/uops"
        );
        assert_eq!(redact("not a url"), "not a url");
    }

    #[test]
    fn the_summary_carries_no_password() {
        // The banner is the first thing pasted into a support ticket.
        let config = Config {
            postgres: PgConfig {
                url: "postgres://uops:hunter2@db:5432/uops".to_owned(),
                ..PgConfig::from_env()
            },
            kek: KekSource::Env("UOPS_KEK_HEX".to_owned()),
            kek_id: KeyId("default".to_owned()),
            state_dir: PathBuf::from("/var/lib/uops"),
            poll_every: Duration::from_secs(5),
            abandon_after: Duration::from_secs(3600),
        };
        assert!(
            !config.summary().contains("hunter2"),
            "{}",
            config.summary()
        );
    }

    #[test]
    fn a_number_that_is_not_one_is_refused_rather_than_defaulted() {
        // `UOPS_RUNNER_POLL_SECS=1O` silently becoming 5 is the kind of thing discovered
        // during an incident. The unset path is the one this function owns; the parse
        // itself is std's and is asserted directly, because mutating the environment is
        // unsafe in Rust 2024 and racy across test threads regardless.
        assert_eq!(number("UOPS_UNSET_FOR_THIS_TEST", 5).unwrap(), 5);
        assert!("1O".trim().parse::<u64>().is_err());
    }
}
