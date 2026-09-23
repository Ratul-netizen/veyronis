//! A dry run against a **real SSH server** — M10's one open acceptance criterion.
//!
//! > A dry run resolves the targets, names every resource, renders every command, and
//! > executes only the read-only steps — verified against a real SSH server, not a mock
//!
//! Everything but the last clause was already settled by `runner.rs`, whose `Scripted`
//! transport makes each orchestration property one assertion. What it could not settle is
//! whether the read-only step *actually reaches a device and comes back* — a scripted
//! transport returns whatever it was told to, so a dry run that sent nothing at all and a
//! dry run that ran the first step look identical to it.
//!
//! The criterion stayed open because no SSH server was reachable from the machine this was
//! built on. One is now.
//!
//! # What is real here and what that buys
//!
//! `uops_runner::Live` → `Ssh` → `ssh(1)` as a child process → a real `sshd`. The key is
//! sealed in the vault, opened through `PgSealedStore`, written to a private file for the
//! duration of the step and removed afterwards. Nothing is stubbed between the run queue
//! and the remote shell.
//!
//! So this test is the only thing in the workspace that can fail if:
//!
//! * the argument vector is wrong and `ssh` rejects it;
//! * the key file is written in a form `ssh` will not load, or with permissions it refuses;
//! * `StrictHostKeyChecking=accept-new` does not in fact accept a new host;
//! * the remote command is mangled by a shell somewhere between here and the device;
//! * a dry run sends the destructive step to something that would really do it.
//!
//! # Skipped, loudly, when the fixture is absent
//!
//! The pattern `uops-poller/tests/live.rs` established: a developer who has not built the
//! fixture should not get a red suite for a server they did not ask for, and the skip says
//! so out loud so it cannot be mistaken for a pass.
//!
//! ```bash
//! # In a guest with sshd running and a key authorised for $USER:
//! UOPS_SSH_HOST=192.168.1.219 UOPS_SSH_USER=kali //!   UOPS_SSH_KEY=/tmp/uops_live_key cargo test -p uops-runner --test live_ssh
//! ```

use std::sync::Arc;

use uops_core::{ActorId, CredentialMaterial, CredentialRef, OrgId, ResourceId, Secret, TenantId, TenantScope};
use uops_query::ast::ResourceSelector;
use uops_runbook::{Action, Approvals, Expect, Rollback, Runbook, Step};
use uops_secrets::{CredentialMeta, KekRing, LocalVault};
use uops_store_pg::{Config, PgSealedStore, PgStore, RunState};

/// Where the live SSH server is, or `None` when the fixture is not set up.
struct Target {
    host: String,
    user: String,
    key_path: String,
}

fn target() -> Option<Target> {
    let host = std::env::var("UOPS_SSH_HOST").ok()?;
    let key_path = std::env::var("UOPS_SSH_KEY").ok()?;
    let user = std::env::var("UOPS_SSH_USER").unwrap_or_else(|_| "root".to_owned());
    Some(Target {
        host,
        user,
        key_path,
    })
}

/// The one line a reader must see when this did not run.
macro_rules! skip_without_fixture {
    () => {
        match target() {
            Some(t) => t,
            None => {
                println!(
                    "SKIPPED: no live SSH fixture. Set UOPS_SSH_HOST, UOPS_SSH_USER and \
                     UOPS_SSH_KEY to run this — see the module docs."
                );
                return;
            }
        }
    };
}

async fn store() -> PgStore {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into());
    PgStore::connect(&Config {
        url,
        ..Config::default()
    })
    .await
    .expect("connect")
}

type Vault = LocalVault<uops_secrets::RustCryptoAead, PgSealedStore, uops_secrets::MemoryAccessLog>;

/// A fixed key, for the reason the poller's live test gives: an ephemeral one would be a
/// fresh key per call, which is what a restart must not do and what two processes sharing
/// a database must not do either.
fn fixed_kek() -> KekRing {
    let path = std::env::temp_dir().join("uops-runner-live-kek.hex");
    if !path.exists() {
        std::fs::write(&path, "0".repeat(64)).expect("write the test kek");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("tighten the test kek");
    }
    KekRing::from_file(&path, uops_secrets::record::KeyId("live-kek".to_owned())).expect("kek")
}

fn vault(store: &PgStore) -> Vault {
    LocalVault::new(
        uops_secrets::RustCryptoAead,
        PgSealedStore::new(store.clone()),
        uops_secrets::MemoryAccessLog::new(),
        fixed_kek(),
    )
}

struct Fixture {
    store: PgStore,
    scope: TenantScope,
    starter: ActorId,
    device: ResourceId,
    device_name: String,
    credential: CredentialRef,
}

/// A tenant with one device pointed at the live SSH server, and the key that opens it.
async fn fixture(slug: &str, t: &Target) -> Fixture {
    let store = store().await;

    // The same drain `runner.rs` performs, and for the same reason: `claim_next_run` takes
    // the oldest `ready` run in the deployment, so a database with abandoned rows hands
    // this test somebody else's work.
    sqlx::query("UPDATE runbook_run SET state = 'cancelled' WHERE state = 'ready'")
        .execute(store.pool())
        .await
        .expect("drain the queue");

    let org = OrgId::new();
    let tenant = TenantId::new();
    let tag = tenant.into_uuid().simple().to_string();

    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("live-org-{slug}-{tag}"))
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("live-{slug}"))
        .bind(format!("live-{slug}-{tag}"))
        .execute(store.pool())
        .await
        .expect("tenant");

    let hash =
        uops_secrets::password::hash(&Secret::new("correct horse".to_owned())).expect("hash");
    let starter = store
        .create_user(org, &format!("starter-{tag}@test.invalid"), "starter", &hash)
        .await
        .expect("user");

    // The real private key, sealed the way a deployment would seal it. Read from disk
    // rather than embedded, so the key this test uses is never in the repository.
    let private_key = std::fs::read_to_string(&t.key_path)
        .unwrap_or_else(|e| panic!("UOPS_SSH_KEY at {} could not be read: {e}", t.key_path));

    let credential = vault(&store)
        .put(
            tenant,
            Secret::new(CredentialMaterial::SshKey {
                username: t.user.clone(),
                private_key,
                // The transport refuses a passphrase-protected key by design — `ssh(1)`
                // cannot be handed one without a helper whose job is to print a secret.
                passphrase: String::new(),
            }),
            &CredentialMeta::new("live-ssh"),
        )
        .expect("seal the credential");

    let device = ResourceId::new();
    let device_name = "live-ssh-host".to_owned();
    sqlx::query(
        "INSERT INTO resource (id, tenant_id, kind, name, status)
         VALUES ($1, $2, 'device', $3, 'unknown')",
    )
    .bind(device.into_uuid())
    .bind(tenant.into_uuid())
    .bind(&device_name)
    .execute(store.pool())
    .await
    .expect("resource");

    // The management address the runner resolves at execution time — the real one.
    sqlx::query(
        "INSERT INTO resource_identifier
             (id, tenant_id, resource_id, kind, value, confidence, source)
         VALUES ($1, $2, $3, 'mgmt_ip', $4, 0.80, 'manual')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(tenant.into_uuid())
    .bind(device.into_uuid())
    .bind(&t.host)
    .execute(store.pool())
    .await
    .expect("mgmt_ip");

    Fixture {
        store,
        scope: TenantScope::system(tenant),
        starter,
        device,
        device_name,
        credential,
    }
}

/// The shape M10 §2.1's example uses: one step a dry run runs, one it must not.
///
/// The read-only step is a command whose output could not be produced by anything but a
/// real shell — the marker is generated per run, so a stubbed or replayed transcript
/// cannot contain it.
fn two_step(name: &str, credential: CredentialRef, marker: &str) -> Runbook {
    Runbook {
        name: name.to_owned(),
        description: "prove a dry run reaches a device and stops".to_owned(),
        targets: ResourceSelector::All,
        steps: vec![
            Step {
                name: "read something only a real shell can answer".to_owned(),
                action: Action::SshCommand {
                    command: format!("echo {marker}-$(uname -s)"),
                    credential,
                },
                destructive: false,
                rollback: None,
                // The expectation is checked against what the device actually said, so a
                // step that "ran" and returned nothing fails here rather than passing.
                expect: Some(Expect::Contains {
                    text: marker.to_owned(),
                }),
                continue_on_error: false,
            },
            Step {
                // If a dry run ever sent this, the file would exist afterwards — which is
                // what the test checks, rather than trusting the transcript.
                name: "write a file that must never appear".to_owned(),
                action: Action::SshCommand {
                    command: format!("touch /tmp/{marker}.destructive"),
                    credential,
                },
                destructive: true,
                rollback: Some(Rollback::None {
                    because: "the test removes it".to_owned(),
                }),
                expect: None,
                continue_on_error: false,
            },
        ],
        max_targets: 10,
        concurrency: 1,
        approvals: Approvals::None,
        maintenance_only: false,
    }
}

async fn queue(fixture: &Fixture, runbook: &Runbook, dry_run: bool) -> uuid::Uuid {
    let saved = fixture
        .store
        .save_runbook(&fixture.scope, runbook, Some(fixture.starter))
        .await
        .expect("save");
    fixture
        .store
        .create_run(
            &fixture.scope,
            saved.id,
            saved.version_id,
            RunState::Ready,
            dry_run,
            &[(fixture.device, fixture.device_name.clone())],
            "fingerprint-live",
            "M10's last criterion",
            fixture.starter,
            false,
        )
        .await
        .expect("create run")
}

async fn steps_of(fixture: &Fixture, run: uuid::Uuid) -> Vec<(i32, String, String, Option<String>)> {
    sqlx::query_as::<_, (i32, String, String, Option<String>)>(
        "SELECT step_index, name, state::text, output
           FROM runbook_run_step
          WHERE run_id = $1 AND tenant_id = $2
          ORDER BY step_index",
    )
    .bind(run)
    .bind(fixture.scope.tenant_id().into_uuid())
    .fetch_all(fixture.store.pool())
    .await
    .expect("steps")
}

/// Ask the live host directly whether a path exists. Not through the product.
fn exists_on_device(t: &Target, path: &str) -> bool {
    let out = std::process::Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
            "-i",
            &t.key_path,
            "-l",
            &t.user,
            &t.host,
            "--",
            &format!("test -e {path} && echo PRESENT || echo ABSENT"),
        ])
        .output()
        .expect("ask the device directly");
    String::from_utf8_lossy(&out.stdout).contains("PRESENT")
}

fn live_transport() -> uops_runner::Live {
    let store = futures_store();
    let state_dir = std::env::temp_dir().join("uops-runner-live");
    std::fs::create_dir_all(&state_dir).expect("state dir");
    uops_runner::Live::new(Arc::new(vault(&store)), &state_dir)
}

/// A blocking connect, because `Live::new` is not async and the vault it wraps needs a
/// store. Kept separate so the test bodies read as the thing they are testing.
fn futures_store() -> PgStore {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into());
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            PgStore::connect(&Config {
                url,
                ..Config::default()
            })
            .await
            .expect("connect")
        })
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dry_run_reaches_a_real_device_runs_the_read_only_step_and_sends_nothing_destructive() {
    let t = skip_without_fixture!();
    let marker = format!("uops{}", uuid::Uuid::now_v7().simple());
    let fixture = fixture("dry", &t).await;
    let runbook = two_step("live-dry", fixture.credential, &marker);
    let run = queue(&fixture, &runbook, true).await;

    let transport = live_transport();
    uops_runner::take_one(&fixture.store, &transport, chrono::Utc::now())
        .await
        .expect("take")
        .expect("a run was queued");

    let steps = steps_of(&fixture, run).await;
    assert_eq!(steps.len(), 2, "both steps are recorded: {steps:?}");

    // 1. The read-only step really ran, and the proof is output no mock produced: the
    //    marker came back from a shell that expanded `$(uname -s)`.
    assert_eq!(steps[0].2, "ok", "{steps:?}");
    let output = steps[0].3.as_deref().unwrap_or_default();
    assert!(
        output.contains(&marker),
        "the read-only step's transcript must hold what the device said: {output:?}"
    );
    assert!(
        output.contains("Linux"),
        "the command was expanded by a real remote shell: {output:?}"
    );

    // 2. The destructive step was not sent, and the transcript says why rather than
    //    claiming success.
    assert_eq!(steps[1].2, "skipped", "{steps:?}");
    assert!(
        steps[1].3.as_deref().unwrap_or_default().contains("dry run"),
        "a skipped step says it was a dry run: {steps:?}"
    );

    // 3. And the device agrees — asked directly, not through the product. This is the
    //    assertion a scripted transport cannot make: it is about the far end's disk.
    assert!(
        !exists_on_device(&t, &format!("/tmp/{marker}.destructive")),
        "a dry run must not have created the file the destructive step writes"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_real_run_does_send_the_destructive_step_to_the_device() {
    // The paired positive case, without which the test above proves only that *nothing*
    // was sent. `uops-store-pg/tests/restore.rs` makes the same argument about its own
    // negative assertion.
    let t = skip_without_fixture!();
    let marker = format!("uops{}", uuid::Uuid::now_v7().simple());
    let path = format!("/tmp/{marker}.destructive");
    let fixture = fixture("real", &t).await;
    let runbook = two_step("live-real", fixture.credential, &marker);
    let run = queue(&fixture, &runbook, false).await;

    let transport = live_transport();
    uops_runner::take_one(&fixture.store, &transport, chrono::Utc::now())
        .await
        .expect("take")
        .expect("a run was queued");

    let steps = steps_of(&fixture, run).await;
    assert_eq!(steps[0].2, "ok", "{steps:?}");
    assert_eq!(steps[1].2, "ok", "{steps:?}");
    assert!(
        exists_on_device(&t, &path),
        "a real run sends the destructive step, and the file exists"
    );

    // Tidy up after ourselves on somebody else's machine.
    let _ = std::process::Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-i",
            &t.key_path,
            "-l",
            &t.user,
            &t.host,
            "--",
            &format!("rm -f {path}"),
        ])
        .output();
}
