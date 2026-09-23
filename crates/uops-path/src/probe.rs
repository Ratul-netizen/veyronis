//! Running the operating system's traceroute — `docs/traceroute.md` §2 and §5.
//!
//! # What this file is careful about
//!
//! 1. **The argument vector.** The target is one element of an argv and nothing between
//!    this process and the command interprets it. It is also validated before anything is
//!    spawned, so a value that is not an address or a hostname never reaches a process at
//!    all — `uops_runner::ssh` takes the same two precautions for the same reason.
//! 2. **The time.** An unbounded trace is a request that never returns and a child nobody
//!    reaps. Both a hop ceiling and a wall-clock deadline, and the deadline kills the
//!    child rather than leaking it.
//! 3. **The raw output.** Returned whatever the parser made of it, so a reader can check.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use uops_core::{Error, Result};

use crate::{Hop, parse};

/// The furthest this will look.
///
/// Thirty is `traceroute`'s own default and is past the diameter of the public internet;
/// a path that has not arrived by then is not going to.
pub const MAX_HOPS: u8 = 30;

/// How long a whole trace may take before it is abandoned.
///
/// Thirty hops that each time out three times at a second apiece is ninety seconds, and a
/// web request should not wait that long. The ceiling is what makes the hop cap a bound on
/// *time* rather than only on distance.
pub const DEADLINE: Duration = Duration::from_secs(45);

/// What a trace found.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Trace {
    pub target: String,
    pub hops: Vec<Hop>,
    /// Whether the last hop is the target — that is, whether the path arrived.
    pub reached: bool,
    /// Exactly what the command printed. Kept because the parser reads prose, and a reader
    /// must be able to see past it — `docs/traceroute.md` §3.
    pub raw: String,
}

/// Whether a target is safe to hand to a process.
///
/// Deliberately strict: an IPv4 address, or a hostname of letters, digits, dots and
/// hyphens. Nothing here is passed through a shell, so this is defence in depth rather
/// than the only guard — but the argument that `uops_runbook::render` makes about
/// allow-lists holds, and a target is exactly as much attacker-influenced as a runbook
/// parameter.
#[must_use]
pub fn is_usable_target(target: &str) -> bool {
    let target = target.trim();
    if target.is_empty() || target.len() > 253 {
        return false;
    }
    if target.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    // A hostname. No leading or trailing dot or hyphen, and nothing but the allowed set.
    !target.starts_with(['.', '-'])
        && !target.ends_with(['.', '-'])
        && target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// The command and its arguments for this platform.
///
/// `-d` / `-n` in both cases: resolving every hop turns a five-second trace into a
/// thirty-second one, and the product wants the address. A name can be looked up after.
fn argv(target: &str, max_hops: u8) -> (&'static str, Vec<String>) {
    if cfg!(windows) {
        (
            "tracert",
            vec![
                "-d".to_owned(),
                "-h".to_owned(),
                max_hops.to_string(),
                // Per-probe wait. Without it Windows waits four seconds on every silent
                // hop, and a path with three of those exceeds any sensible deadline.
                "-w".to_owned(),
                "1000".to_owned(),
                target.to_owned(),
            ],
        )
    } else {
        (
            "traceroute",
            vec![
                "-n".to_owned(),
                "-m".to_owned(),
                max_hops.to_string(),
                "-w".to_owned(),
                "1".to_owned(),
                target.to_owned(),
            ],
        )
    }
}

/// Trace the path to a target.
///
/// # Errors
///
/// [`Error::Invalid`] for a target that is not an address or a hostname, and
/// [`Error::Storage`] when the command could not be run or did not finish in time — the
/// latter carrying which, because "traceroute is not installed" and "the path is slow" are
/// different problems for whoever reads it.
pub async fn trace(target: &str, max_hops: u8) -> Result<Trace> {
    if !is_usable_target(target) {
        return Err(Error::Invalid(format!(
            "{target:?} is not an IPv4 address or a hostname"
        )));
    }
    let hops = max_hops.clamp(1, MAX_HOPS);
    let (program, args) = argv(target.trim(), hops);

    let mut command = tokio::process::Command::new(program);
    command.args(&args).kill_on_drop(true);
    // No console window when the server runs without one. `tokio::process::Command`
    // provides this inherently on Windows, so the `std::os::windows` import the standard
    // library needs is not wanted here — and would be an unused import everywhere else.
    #[cfg(windows)]
    command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW

    let run = command.output();
    let finished = tokio::time::timeout(DEADLINE, run).await.map_err(|_| {
        Error::Storage(format!(
            "the trace to {target} did not finish within {}s",
            DEADLINE.as_secs()
        ))
    })?;

    let output = finished.map_err(|e| {
        Error::Storage(format!(
            "{program} could not be run: {e}. A traceroute needs the system's own command \
             — see docs/traceroute.md §2."
        ))
    })?;

    // Both streams: `tracert` reports an unresolvable target on stdout and some builds of
    // `traceroute` use stderr, and a reader needs whichever it was.
    let mut raw = String::from_utf8_lossy(&output.stdout).into_owned();
    let errors = String::from_utf8_lossy(&output.stderr);
    if !errors.trim().is_empty() {
        raw.push_str(&errors);
    }

    let hops = if cfg!(windows) {
        parse::parse_windows(&raw)
    } else {
        parse::parse_unix(&raw)
    };

    // Arrived, if the last hop that answered is the target itself. Compared as text
    // because the target may be a hostname, in which case the product does not claim to
    // know whether it arrived.
    let reached = hops
        .last()
        .and_then(|h| h.address.as_deref())
        .is_some_and(|a| a == target.trim());

    Ok(Trace {
        target: target.trim().to_owned(),
        hops,
        reached,
        raw,
    })
}
