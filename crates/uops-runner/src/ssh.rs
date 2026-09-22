//! The SSH transport: `ssh(1)`, as a child process — M10 §2.10.
//!
//! This is not the transport anybody wanted. The decision and the search that led to it
//! are in §2.10; the short version is that the one maintained async SSH client in Rust
//! offers a choice of two crypto backends, both of which carry the OpenSSL licence term,
//! and neither is on this workspace's allow-list. Writing an SSH client instead was never
//! a serious proposal.
//!
//! # What this file is careful about
//!
//! 1. **The argument vector.** The rendered command is one element of an argv. Nothing
//!    between this process and `ssh` interprets it. The far end still does — a device CLI
//!    is an interpreter — which is why `uops_runbook::render` refuses a value containing
//!    anything but letters, digits and `. : - _ / @`.
//! 2. **The key on disk.** Written to a file this process creates with no group or world
//!    access, passed as `-i`, and removed when the step ends — including when the step
//!    times out, which is the path that is easy to leave out and is the one that matters.
//! 3. **The host key.** `StrictHostKeyChecking=accept-new` against a `known_hosts` file
//!    the product owns. Trust on first use is weak; `no`, which every hurried integration
//!    picks, is not weak, it is nothing.
//! 4. **The time.** A device that accepts a connection and then says nothing would
//!    otherwise hold a step open forever, and a run holds the lease while it does.
//!
//! # What it will not do
//!
//! Authenticate with a password, or with a passphrase-protected key. `ssh(1)` cannot take
//! either without a helper program whose job is to print a secret, and a runbook that
//! changes an estate should be using a key. Both are refused at execution with a message
//! that says which, rather than at validation: the runbook is not wrong, the credential it
//! names is of a kind this transport will not use, and that is a thing an operator fixes
//! in the credential store.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use uops_core::{CredentialMaterial, CredentialRef};

use crate::transport::{Endpoint, Outcome};
use crate::vault::Vault;

/// How long a single step may take.
///
/// Five minutes: long enough for a device that reboots an interface and comes back, short
/// enough that one unresponsive switch does not hold the `run` lease for an afternoon. Per
/// *step*, not per run — a run over forty devices is legitimately long.
pub const STEP_BUDGET: Duration = Duration::from_secs(300);

/// How long the TCP connection and the SSH handshake get.
///
/// Well under [`STEP_BUDGET`], because a device that is not answering at all should fail
/// fast: the operator is watching a run, and four hundred seconds of nothing reads as a
/// hung product rather than as an unreachable device.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The most output read back from one step, before redaction.
///
/// Sixteen times [`uops_runbook::MAX_OUTPUT`], so that a truncated transcript is truncated
/// by the rule that has a reason written against it rather than by whatever this happened
/// to read. The cap here exists only so a device emitting without end cannot exhaust this
/// process's memory.
pub const MAX_READ: usize = uops_runbook::MAX_OUTPUT * 16;

/// The SSH transport.
///
/// Holds the vault and the directory the `known_hosts` file lives in. One per process.
pub struct Ssh {
    vault: Arc<Vault>,
    /// Where host keys accumulate. A path the product owns, not the invoking user's
    /// `~/.ssh/known_hosts`: a runner's trust decisions should not be mixed into the
    /// personal file of whichever account the container happens to run as.
    known_hosts: PathBuf,
    /// Where key files are written for the duration of a step.
    work_dir: PathBuf,
}

impl std::fmt::Debug for Ssh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Paths only. Everything else is a credential or reaches one.
        f.debug_struct("Ssh")
            .field("known_hosts", &self.known_hosts)
            .finish_non_exhaustive()
    }
}

impl Ssh {
    #[must_use]
    pub fn new(vault: Arc<Vault>, state_dir: &Path) -> Self {
        Self {
            vault,
            known_hosts: state_dir.join("known_hosts"),
            work_dir: state_dir.to_path_buf(),
        }
    }

    /// Run one rendered command against one device.
    ///
    /// Public because [`crate::live::Live`] dispatches to it. `Ssh` does not implement
    /// [`crate::transport::Transport`] itself: a transport that answered "this does not
    /// make HTTP requests" to half the trait would be a type whose shape lies about what
    /// it is for.
    pub async fn command(&self, to: &Endpoint, command: &str, credential: CredentialRef) -> Outcome {
        let context = crate::vault::step_context(to.resource, crate::vault::SSH_STEP);
        let opened = match self.vault.get(to.tenant, credential, &context) {
            Ok(material) => material,
            Err(e) => return Outcome::failed(format!("the credential could not be opened: {e}")),
        };

        // Bound as narrowly as possible: the key text is copied out of the Secret exactly
        // once, straight into the file, and the copy is dropped at the end of the block.
        let (user, key_file) = {
            let material: &CredentialMaterial = opened.expose();
            match material {
                CredentialMaterial::SshKey {
                    username,
                    private_key,
                    passphrase,
                } => {
                    if !passphrase.is_empty() {
                        return Outcome::failed(
                            "this credential's key has a passphrase, and a runbook step \
                             cannot type one. Use a key without a passphrase, held in the \
                             vault — see M10 §2.10.",
                        );
                    }
                    match write_key(&self.work_dir, private_key).await {
                        Ok(path) => (username.clone(), path),
                        Err(e) => {
                            return Outcome::failed(format!(
                                "the key could not be made available to ssh: {e}"
                            ));
                        }
                    }
                }
                CredentialMaterial::SshPassword { .. } => {
                    return Outcome::failed(
                        "this credential is a password, and a runbook step authenticates \
                         with a key. A runbook that changes an estate should be using one \
                         — see M10 §2.10.",
                    );
                }
                other => {
                    return Outcome::failed(format!(
                        "an ssh.command step needs an SSH key credential, and this one is \
                         {other:?}"
                    ));
                }
            }
        };

        let argv = argv(&self.known_hosts, &user, &to.address, &key_file, command);
        let outcome = spawn(&argv, &to.address).await;

        // Removed on every path, including the timeout — which is the one that is easy to
        // leave out and the one that leaves a private key on a disk.
        let removed = tokio::fs::remove_file(&key_file).await;
        match (outcome, removed) {
            (outcome, Ok(())) => outcome,
            (mut outcome, Err(e)) => {
                // Reported rather than swallowed, and it makes the step a failure even
                // when the command succeeded: a key left behind is a thing somebody has
                // to go and delete, and a green run would hide it.
                outcome.error = Some(format!(
                    "the step ran, but its key file at {} could not be removed: {e}",
                    key_file.display()
                ));
                outcome
            }
        }
    }
}

/// Run `ssh` with an already-built argument vector.
///
/// A free function, like [`argv`], and for the same reason: it is the half of this
/// transport that can be exercised against a real `ssh(1)` without a vault, a database or
/// a device — and a refused connection is a contract worth asserting on, because the whole
/// of `Outcome`'s "answered no" versus "never asked" distinction rests on exit 255.
async fn spawn(argv: &[String], address: &str) -> Outcome {
    let child = match tokio::process::Command::new("ssh")
        .args(argv)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Outcome::failed(
                "`ssh` was not found on this host. The runner executes SSH steps \
                 through OpenSSH — see M10 §2.10 — so it has to be installed where the \
                 runner runs.",
            );
        }
        Err(e) => return Outcome::failed(format!("ssh could not be started: {e}")),
    };

    let waited = tokio::time::timeout(STEP_BUDGET, child.wait_with_output()).await;

    let output = match waited {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => return Outcome::failed(format!("ssh could not be waited on: {e}")),
        // The child is killed by `kill_on_drop` when the future is dropped here.
        Err(_) => {
            return Outcome::failed(format!(
                "the step did not finish within {}s and was stopped. What the device \
                 did with it is not known.",
                STEP_BUDGET.as_secs()
            ));
        }
    };

    // stderr after stdout, both kept: a device CLI writes its refusals to one and its
    // answers to the other, inconsistently, and a transcript missing half of that is a
    // transcript an operator cannot use.
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    truncate_on_boundary(&mut text, MAX_READ);

    // 255 is `ssh`'s own failure — refused, unresolvable, a changed host key — as
    // distinct from the remote command exiting 255, which no device CLI does. Reported
    // as a transport error so the run record says the device was never asked.
    match output.status.code() {
        // 255 is `ssh`'s own failure — refused, unresolvable, a changed host key — as
        // distinct from the remote command exiting 255, which no device CLI does.
        // Reported as a transport error so the record says the device was never asked.
        Some(255) => {
            // Redacted on the way into the *failure message*, and this is not
            // belt-and-braces: `record_step` redacts the transcript, and nothing
            // redacts a run's `failure` column. A device that prints a credential in
            // its first line of refusal would otherwise put it there in the clear —
            // and `failure` is the one field a run list shows without being asked.
            let why = format!(
                "ssh could not reach {address}: {}",
                uops_runbook::redact::output(first_line(&text)).trim_end()
            );
            let mut outcome = Outcome::exited(255, text);
            outcome.error = Some(why);
            outcome
        }
        Some(code) => Outcome::exited(code, text),
        // No code: killed by a signal.
        None => {
            let mut outcome = Outcome::failed("ssh was killed before it finished");
            outcome.output = text;
            outcome
        }
    }
}

/// The argument vector, built where it can be asserted on.
///
/// A free function rather than a method because the ordering and the options *are* the
/// security content of this file, and a test should be able to read them without a vault,
/// a database or an SSH server.
#[must_use]
fn argv(known_hosts: &Path, user: &str, address: &str, key: &Path, command: &str) -> Vec<String> {
    vec![
            // Never prompt. Without this a missing key turns into a password prompt
            // against a closed stdin, and the step hangs until the budget expires rather
            // than failing with something an operator can read.
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "StrictHostKeyChecking=accept-new".to_owned(),
            "-o".to_owned(),
            format!("UserKnownHostsFile={}", known_hosts.display()),
            // Use the key we were given and nothing else. Without it, `ssh` will offer
            // every key in the invoking account's agent and `~/.ssh`, which means a run
            // could succeed using a credential the product does not know it used — and
            // the access log would say it opened one it did not need.
            "-o".to_owned(),
            "IdentitiesOnly=yes".to_owned(),
            "-o".to_owned(),
            format!("ConnectTimeout={}", CONNECT_TIMEOUT.as_secs()),
            "-i".to_owned(),
            key.display().to_string(),
            "-l".to_owned(),
            user.to_owned(),
            address.to_owned(),
            // The rendered command, as one argument. `--` first so an address or a
            // command that begins with a dash cannot be read as an option.
            "--".to_owned(),
            command.to_owned(),
        ]
}

/// Write a private key where `ssh` can read it and nothing else can.
///
/// The name is random, so two steps running at once against different devices do not
/// collide and so the path is not guessable by another process on the box.
async fn write_key(dir: &Path, key: &str) -> std::io::Result<PathBuf> {
    tokio::fs::create_dir_all(dir).await?;
    let path = dir.join(format!("key-{}", uuid::Uuid::now_v7()));

    // Created with the mode set at open time rather than chmod'ed afterwards: between
    // those two calls the file exists and is readable, and that window is the whole of
    // what the permission is for. `ssh` refuses a group-readable key anyway, which is a
    // second check we get for free and do not rely on.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        use tokio::io::AsyncWriteExt as _;

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .await?;
        file.write_all(key.as_bytes()).await?;
        file.sync_all().await?;
    }

    // On Windows a new file inherits the directory's ACL. The state directory is the
    // product's own, and OpenSSH for Windows performs its own ACL check on the key and
    // refuses one that is too open — which is the check that matters here. Windows is a
    // development platform for this product, not a deployment one.
    #[cfg(not(unix))]
    tokio::fs::write(&path, key.as_bytes()).await?;

    Ok(path)
}

/// Cut a string to at most `max` bytes without splitting a character.
///
/// Device output is not guaranteed UTF-8 and the lossy conversion above can put a
/// three-byte replacement character across any boundary.
pub(crate) fn truncate_on_boundary(text: &mut String, max: usize) {
    if text.len() <= max {
        return;
    }
    let at = (0..=max)
        .rev()
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(0);
    text.truncate(at);
}

/// The first line, for a one-sentence failure.
fn first_line(text: &str) -> &str {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn built(command: &str) -> Vec<String> {
        argv(
            Path::new("/var/lib/uops/known_hosts"),
            "netops",
            "10.0.0.1",
            Path::new("/var/lib/uops/key-1"),
            command,
        )
    }

    #[test]
    fn the_rendered_command_is_exactly_one_argument() {
        // The property this whole transport exists for. A command with spaces in it must
        // arrive as one element, because the moment it is joined into a string something
        // on this side has interpreted it.
        let argv = built("show ip bgp summary");
        assert_eq!(argv.last().unwrap(), "show ip bgp summary");
        assert_eq!(argv.iter().filter(|a| a.contains("show ip bgp")).count(), 1);
    }

    #[test]
    fn a_command_beginning_with_a_dash_is_not_read_as_an_option() {
        // `--` is what makes this true, and removing it is a one-character change that
        // nothing else here would catch.
        let argv = built("-oProxyCommand=curl evil");
        let dashdash = argv.iter().position(|a| a == "--").expect("no -- in argv");
        assert_eq!(argv[dashdash + 1], "-oProxyCommand=curl evil");
        assert_eq!(dashdash + 2, argv.len(), "-- must be last but one");
    }

    #[test]
    fn host_keys_are_checked_against_a_file_the_product_owns() {
        let argv = built("show version");
        assert!(argv.iter().any(|a| a == "StrictHostKeyChecking=accept-new"));
        assert!(
            argv.iter()
                .any(|a| a == "UserKnownHostsFile=/var/lib/uops/known_hosts"),
            "{argv:?}"
        );
        // `no` would make the option present and meaningless, which is the shape a hurried
        // fix takes when a host key changes and somebody wants the run to go green.
        assert!(
            !argv.iter().any(|a| a.contains("StrictHostKeyChecking=no")),
            "{argv:?}"
        );
    }

    #[test]
    fn nothing_prompts_and_no_other_key_is_offered() {
        let argv = built("show version");
        // BatchMode: without it a missing key becomes a password prompt against a closed
        // stdin and the step hangs until the budget expires.
        assert!(argv.iter().any(|a| a == "BatchMode=yes"));
        // IdentitiesOnly: without it a run could succeed using a key from the invoking
        // account's agent — a credential the product does not know it used.
        assert!(argv.iter().any(|a| a == "IdentitiesOnly=yes"));
        assert!(argv.iter().any(|a| a == "ConnectTimeout=15"));
    }

    #[test]
    fn the_connect_timeout_is_well_inside_the_step_budget() {
        // A device that is not answering at all should fail fast, because an operator is
        // watching the run. Asserted rather than commented: raising CONNECT_TIMEOUT past
        // the budget would make the connect timeout unreachable.
        assert!(CONNECT_TIMEOUT < STEP_BUDGET / 4);
    }

    #[test]
    fn the_read_cap_is_above_what_a_transcript_keeps() {
        // Reading less than the transcript stores would mean the cut was made here, by
        // accident, rather than by the rule in `uops_runbook::redact` that has a reason
        // written against it.
        const { assert!(MAX_READ > uops_runbook::MAX_OUTPUT) };
    }

    #[test]
    fn output_is_cut_on_a_character_boundary() {
        let mut text = "descripción".repeat(100);
        truncate_on_boundary(&mut text, 51);
        assert!(text.is_char_boundary(text.len()));
        assert!(text.len() <= 51);
    }

    #[test]
    fn a_short_string_is_left_alone() {
        let mut text = "up".to_owned();
        truncate_on_boundary(&mut text, 4096);
        assert_eq!(text, "up");
    }

    /// A real `ssh(1)`, against a port with nothing on it.
    ///
    /// **This is the only test in the crate that runs the actual transport**, and it runs
    /// everywhere OpenSSH is installed — no server, no key, no device. What it settles is
    /// the contract the rest of the crate is built on: `ssh` exits 255 when *it* failed,
    /// and this transport turns that into an [`Outcome`] whose `error` is set, so a run
    /// record says the device was never asked rather than that it answered no.
    ///
    /// Skipped, loudly, where `ssh` is absent — the same shape as the SNMP agent fixture.
    #[tokio::test]
    async fn a_refused_connection_is_reported_as_never_having_asked() {
        if std::process::Command::new("ssh")
            .arg("-V")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err()
        {
            eprintln!("skipping: no ssh(1) on this host");
            return;
        }

        // Port 1 on loopback. Nothing listens there, and choosing loopback means the test
        // sends no packet anywhere somebody else's intrusion detection would see.
        let dir = std::env::temp_dir().join(format!("uops-ssh-test-{}", uuid::Uuid::now_v7()));
        tokio::fs::create_dir_all(&dir).await.expect("temp dir");
        let key = dir.join("absent-key");

        let argv = argv(
            &dir.join("known_hosts"),
            "netops",
            "127.0.0.1",
            &key,
            "show version",
        );
        let outcome = super::spawn(&argv, "127.0.0.1:1").await;

        assert!(!outcome.succeeded());
        assert!(
            outcome.error.is_some(),
            "a connection that was refused must not read as the device answering: {outcome:?}"
        );
        assert!(
            outcome.why().contains("could not reach") || outcome.why().contains("ssh"),
            "{}",
            outcome.why()
        );

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[test]
    fn the_first_line_skips_the_blank_ones() {
        assert_eq!(first_line("\n\n  refused\nmore\n"), "refused");
        assert_eq!(first_line(""), "no output");
        assert_eq!(first_line("   \n"), "no output");
    }
}
