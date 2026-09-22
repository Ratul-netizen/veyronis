//! What a restored control plane can and cannot do — M12 §2.4.
//!
//! §2.4's last paragraph: *credentials restore or they do not. The KEK never enters the
//! database — SPEC §M0.4 — so a restored control plane without its key material holds
//! sealed credentials nobody can open. That is the correct behaviour and it has to be
//! written down where an operator will read it before the restore rather than during
//! one.*
//!
//! It is also a claim, and a claim in a runbook is worth exactly as much as the last
//! time somebody checked it. So it is here as well: a credential is sealed, the key ring
//! is swapped for a different one — which is what a restore onto a machine that does not
//! have the original KEK *is* — and the credential does not open.
//!
//! # The half that matters as much
//!
//! That everything else still works. A restore whose credentials are locked is a
//! recoverable position: the inventory is there, the users are there, the roles, the
//! rules and the dashboards are there, and an operator who finds the key can carry on.
//! A restore that *lost the rows* is not recoverable at all, and the difference is worth
//! asserting rather than assuming — so this checks that the sealed row is still present
//! and still describable with the wrong key in hand.

use uops_core::{AuthProtocol, CredentialMaterial, OrgId, PrivProtocol, Secret, TenantId};
use uops_secrets::record::KeyId;
use uops_secrets::{AccessContext, CredentialMeta, KekRing, Key, LocalVault};
use uops_store_pg::{Config, PgSealedStore, PgStore};

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

async fn tenant(store: &PgStore, slug: &str) -> TenantId {
    let org = OrgId::new();
    let id = TenantId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind(format!("restore-org-{slug}-{}", id.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(id.into_uuid())
        .bind(org.into_uuid())
        .bind(format!("restore-{slug}"))
        .bind(format!("restore-{slug}-{}", id.into_uuid().simple()))
        .execute(store.pool())
        .await
        .expect("tenant");
    id
}

fn snmpv3() -> Secret<CredentialMaterial> {
    Secret::new(CredentialMaterial::SnmpV3 {
        username: "netops".into(),
        auth: AuthProtocol::Sha256,
        auth_key: "the-auth-key-that-must-not-survive-a-key-loss".into(),
        privacy: PrivProtocol::Aes256,
        priv_key: "priv-key-material".into(),
    })
}

fn ctx() -> AccessContext {
    AccessContext::new(uops_core::scope::Actor::Collector, "restore-drill")
}

type Vault = LocalVault<uops_secrets::RustCryptoAead, PgSealedStore, uops_secrets::MemoryAccessLog>;

fn vault(store: &PgStore, ring: KekRing) -> Vault {
    LocalVault::new(
        uops_secrets::RustCryptoAead,
        PgSealedStore::new(store.clone()),
        uops_secrets::MemoryAccessLog::new(),
        ring,
    )
}

/// A key ring from fixed bytes, under a fixed id.
///
/// Fixed rather than generated so that two rings can be *the same* — which is what a
/// restart, and a restore onto the machine that has the key, both are. And the id is
/// shared between the two rings below while the material differs, because that is the
/// shape the mistake actually takes: a restore onto a host with a freshly generated KEK
/// under the same `UOPS_KEK_ID`. A ring whose id did not match would fail at the lookup
/// and prove something weaker than this needs to.
fn ring(material: u8) -> KekRing {
    KekRing::new(
        KeyId("drill-kek".to_owned()),
        Secret::new(Key::from_bytes([material; uops_secrets::KEY_LEN])),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restore_without_the_kek_cannot_open_a_credential() {
    let store = store().await;
    let tenant = tenant(&store, "no-kek").await;

    // Sealed by the deployment that took the backup.
    let id = vault(&store, ring(0x0a))
        .put(tenant, snmpv3(), &CredentialMeta::new("core-switches-snmpv3"))
        .expect("seal");

    // The restored deployment: same rows, same key id, different key material. Nothing
    // about the database says anything is wrong — the KEK was never in it.
    let restored = vault(&store, ring(0x0b));

    let opened = restored.get(tenant, id, &ctx());
    assert!(
        opened.is_err(),
        "a credential opened with the wrong key material; SPEC §M0.4 says it must not"
    );

    // And the recoverable half: the row is still there and still describable, so the
    // inventory shows the credential exists and names it. An operator who finds the key
    // carries on; an operator who finds an empty table has lost it.
    let summary = restored
        .describe(tenant, id)
        .expect("the row survives a key it cannot open");
    assert_eq!(summary.name, "core-switches-snmpv3");
    assert_eq!(
        restored.list(tenant).expect("listing works without the key").len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restore_with_the_kek_opens_it() {
    // The control. Without this, the test above would pass just as well against a vault
    // that could never open anything — which is the failure mode of every negative test
    // written on its own.
    let store = store().await;
    let tenant = tenant(&store, "with-kek").await;

    let id = vault(&store, ring(0x0a))
        .put(tenant, snmpv3(), &CredentialMeta::new("core-switches-snmpv3"))
        .expect("seal");

    let opened = vault(&store, ring(0x0a))
        .get(tenant, id, &ctx())
        .expect("the same key material opens it");

    let CredentialMaterial::SnmpV3 { auth_key, .. } = opened.expose() else {
        panic!("the material came back as something else")
    };
    assert_eq!(auth_key, "the-auth-key-that-must-not-survive-a-key-loss");
}
