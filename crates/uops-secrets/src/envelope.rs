//! Sealing a secret that is not a device credential — M12.
//!
//! # Why [`LocalVault`](crate::vault::LocalVault) is not this
//!
//! The vault seals a `CredentialMaterial` for a *tenant*, logs every read to the
//! credential access log, and versions rows for rotation. All three are right for an
//! `SNMPv3` passphrase and wrong for an `OpenID` Connect client secret, which belongs to
//! organization rather than a tenant, is read once per sign-in rather than per poll, and
//! is replaced rather than rotated through versions.
//!
//! Forcing one through the other would have meant inventing a tenant for an org-level
//! record — which is precisely the fiction `TenantScope` exists to make impossible.
//!
//! # What is the same, deliberately
//!
//! The envelope. A fresh data key per secret, wrapped under the active KEK, and an AAD
//! that binds the ciphertext to the row it sits in:
//!
//! ```text
//!   secret ──sealed under──▶ DEK ──wrapped under──▶ KEK (never in the database)
//!                             │
//!                    AAD = "identity_provider:<uuid>"
//! ```
//!
//! The AAD is the part worth pausing on. Without it, the sealed bytes of one provider's
//! client secret can be copied into another provider's row and will open there — so an
//! operator who may edit provider B could learn provider A's secret by moving it and
//! asking the product to use it. With it, the move produces a decryption failure.
//!
//! A KEK rotation re-wraps the data key and never touches the ciphertext, exactly as in
//! the vault, which is what makes rotation cheap and a half-finished one harmless.

use uops_core::Secret;

use crate::aead::{AeadProvider, KEY_LEN, Key, NONCE_LEN, Nonce};
use crate::error::{Error, Result};
use crate::kek::KekRing;
use crate::record::KeyId;

/// One sealed secret, as it is stored.
///
/// Every field is either public or encrypted; there is nothing here that a database
/// backup must not contain. The KEK is the one thing that is missing, and it is missing
/// on purpose — SPEC §M0.4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedValue {
    pub kek_id: KeyId,
    pub wrapped_dek: Vec<u8>,
    pub dek_nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    /// Which crypto build produced these bytes. Makes a backend change detectable.
    pub backend_id: String,
}

/// Seals and opens org-level secrets.
#[derive(Debug)]
pub struct Envelope<A: AeadProvider> {
    aead: A,
    keks: KekRing,
}

impl<A: AeadProvider> Envelope<A> {
    #[must_use]
    pub const fn new(aead: A, keks: KekRing) -> Self {
        Self { aead, keks }
    }

    /// Seal a secret against a context.
    ///
    /// `context` becomes the AAD and must identify the row this will be stored in —
    /// `"identity_provider:<uuid>"`. It is not a secret and does not need to be; it is
    /// what makes the ciphertext refuse to open anywhere else.
    ///
    /// Takes the plaintext **by value**, as the vault does: the caller surrenders it at
    /// this boundary and it is zeroized on return, rather than leaving a live copy in
    /// the caller's frame for an unbounded time.
    ///
    /// # Errors
    ///
    /// [`Error`] if randomness is unavailable or the AEAD refuses.
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal(&self, context: &str, secret: Secret<String>) -> Result<SealedValue> {
        let dek = Key::generate()?;
        let nonce = Nonce::generate()?;
        let dek_nonce = Nonce::generate()?;
        let aad = context.as_bytes();

        let ciphertext = self
            .aead
            .seal(dek.expose(), &nonce, aad, secret.expose().as_bytes())?;

        let wrapped_dek =
            self.aead
                .seal(self.keks.active()?, &dek_nonce, aad, dek.expose().as_bytes())?;

        Ok(SealedValue {
            kek_id: self.keks.active_id().clone(),
            wrapped_dek,
            dek_nonce: *dek_nonce.as_bytes(),
            ciphertext,
            nonce: *nonce.as_bytes(),
            backend_id: self.aead.backend_id().to_owned(),
        })
    }

    /// Open a sealed secret.
    ///
    /// # Errors
    ///
    /// [`Error::Open`] when the context does not match the one it was sealed under —
    /// which is what a transplanted row looks like — and when the KEK that wrapped it is
    /// not in the ring, which is what a restore without its key material looks like.
    pub fn open(&self, context: &str, sealed: &SealedValue) -> Result<Secret<String>> {
        let aad = context.as_bytes();
        let kek = self.keks.get(&sealed.kek_id)?;

        let dek_bytes = self.aead.open(
            kek,
            &Nonce::from_bytes(sealed.dek_nonce),
            aad,
            &sealed.wrapped_dek,
        )?;
        let dek_array: [u8; KEY_LEN] = dek_bytes
            .expose()
            .as_slice()
            .try_into()
            .map_err(|_| Error::Open)?;
        let dek = Secret::new(Key::from_bytes(dek_array));

        let plaintext = self.aead.open(
            dek.expose(),
            &Nonce::from_bytes(sealed.nonce),
            aad,
            &sealed.ciphertext,
        )?;

        // A secret that is not UTF-8 was not sealed by this code. Reporting it as a
        // decryption failure rather than a lossy conversion keeps a corrupt row from
        // becoming a client secret with a replacement character in it, which fails at
        // the identity provider with a message nobody can trace back to here.
        String::from_utf8(plaintext.expose().clone())
            .map(Secret::new)
            .map_err(|_| Error::Open)
    }

    /// Introduce a new active KEK, keeping the previous one for unwrapping.
    ///
    /// The mirror of `LocalVault::promote_kek`, and the same reason it is a method
    /// rather than a rebuild: the ring holds key material and is deliberately not
    /// `Clone`, so there is no way to hand the same keys to two envelopes.
    pub fn promote_kek(&mut self, id: KeyId, key: Secret<Key>) {
        self.keks.promote(id, key);
    }

    /// Re-wrap a data key under the active KEK, leaving the ciphertext untouched.
    ///
    /// The same trade the vault makes: rotating a key encrypting one 32-byte value per
    /// row instead of re-encrypting every secret, and a rotation that fails halfway
    /// leaves every row still openable because the retired KEK stays in the ring.
    ///
    /// # Errors
    ///
    /// [`Error`] if the old KEK is absent or the AEAD refuses.
    pub fn rewrap(&self, context: &str, sealed: &SealedValue) -> Result<SealedValue> {
        let aad = context.as_bytes();
        let old = self.keks.get(&sealed.kek_id)?;
        let dek_bytes = self.aead.open(
            old,
            &Nonce::from_bytes(sealed.dek_nonce),
            aad,
            &sealed.wrapped_dek,
        )?;

        let dek_nonce = Nonce::generate()?;
        let wrapped_dek =
            self.aead
                .seal(self.keks.active()?, &dek_nonce, aad, dek_bytes.expose())?;

        Ok(SealedValue {
            kek_id: self.keks.active_id().clone(),
            wrapped_dek,
            dek_nonce: *dek_nonce.as_bytes(),
            ..sealed.clone()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::default_provider;

    fn envelope() -> Envelope<impl AeadProvider> {
        Envelope::new(default_provider(), KekRing::ephemeral_for_tests().unwrap())
    }

    const CONTEXT: &str = "identity_provider:018f0c1e-0000-7000-8000-000000000001";

    #[test]
    fn a_sealed_secret_comes_back() {
        let e = envelope();
        let sealed = e
            .seal(CONTEXT, Secret::new("the client secret".to_owned()))
            .unwrap();
        assert_eq!(e.open(CONTEXT, &sealed).unwrap().expose(), "the client secret");
    }

    #[test]
    fn the_plaintext_is_not_in_the_row() {
        // The property a database backup depends on. Asserted rather than assumed,
        // because "of course it is encrypted" is how a debug field gets added later.
        let e = envelope();
        let sealed = e
            .seal(CONTEXT, Secret::new("hunter2-the-client-secret".to_owned()))
            .unwrap();
        let haystack = format!("{sealed:?}");
        assert!(!haystack.contains("hunter2"), "{haystack}");
        assert!(
            !sealed
                .ciphertext
                .windows(7)
                .any(|w| w == b"hunter2")
        );
    }

    #[test]
    fn a_secret_moved_to_another_row_does_not_open() {
        // An operator who may edit provider B must not be able to learn provider A's
        // client secret by copying the sealed bytes across. The AAD is what stops it.
        let e = envelope();
        let sealed = e
            .seal(CONTEXT, Secret::new("provider A's secret".to_owned()))
            .unwrap();
        let elsewhere = "identity_provider:018f0c1e-0000-7000-8000-000000000002";
        assert!(e.open(elsewhere, &sealed).is_err());
    }

    #[test]
    fn two_seals_of_the_same_secret_differ() {
        // A fresh data key and nonce per seal. Identical ciphertexts would tell anyone
        // with read access to the table which two providers share a secret.
        let e = envelope();
        let a = e.seal(CONTEXT, Secret::new("same".to_owned())).unwrap();
        let b = e.seal(CONTEXT, Secret::new("same".to_owned())).unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.wrapped_dek, b.wrapped_dek);
    }

    #[test]
    fn a_tampered_ciphertext_is_refused_rather_than_returning_rubbish() {
        let e = envelope();
        let mut sealed = e.seal(CONTEXT, Secret::new("secret".to_owned())).unwrap();
        sealed.ciphertext[0] ^= 0x01;
        assert!(e.open(CONTEXT, &sealed).is_err());
    }

    #[test]
    fn rewrapping_changes_the_key_and_not_the_ciphertext() {
        let mut e = envelope();
        let sealed = e.seal(CONTEXT, Secret::new("secret".to_owned())).unwrap();
        let old_id = sealed.kek_id.clone();

        e.promote_kek(KeyId::new("kek-2"), Key::generate().unwrap());

        let rewrapped = e.rewrap(CONTEXT, &sealed).unwrap();
        assert_ne!(rewrapped.kek_id, old_id);
        assert_eq!(
            rewrapped.ciphertext, sealed.ciphertext,
            "a rotation must not re-encrypt the secret itself"
        );
        assert_eq!(e.open(CONTEXT, &rewrapped).unwrap().expose(), "secret");
        // The retired key stays in the ring, so a rotation that stops halfway leaves
        // every un-rewrapped row still openable.
        assert_eq!(e.open(CONTEXT, &sealed).unwrap().expose(), "secret");
    }

    #[test]
    fn a_restore_without_the_key_material_cannot_open_anything() {
        // SPEC §M0.4, and the sentence that has to appear in the restore runbook before
        // somebody performs a restore rather than during one.
        let sealed = envelope()
            .seal(CONTEXT, Secret::new("secret".to_owned()))
            .unwrap();
        let different_keys = envelope();
        assert!(different_keys.open(CONTEXT, &sealed).is_err());
    }
}
