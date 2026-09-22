//! Identity providers, their group mapping, and the accounts they provision — M12 §2.2.
//!
//! # What this layer will and will not decide
//!
//! It stores configuration and it provisions. It does not verify a token, choose a role
//! or decide whether a sign-in is allowed — `uops-oidc` does the first two and `uops-api`
//! the third. The division is the same one `create_user` has with password hashing: a
//! repository that could make an access decision is a repository that could make one
//! nobody reviewed.
//!
//! # Provisioning is one statement
//!
//! A sign-in that finds no account creates one and grants its roles. Doing that in three
//! round trips leaves a window in which two simultaneous first logins both find nothing
//! and both insert — which the unique index turns into a failed login for one of them,
//! at the worst possible moment, on somebody's first day. [`PgStore::provision`] is a
//! transaction with an `ON CONFLICT`, so the second one finds the first one's account.

use uops_core::{ActorId, OrgId, Result, Role, TenantId};
use uops_oidc::mapping::{Grant, Mapping};
use uops_secrets::SealedValue;
use uops_secrets::record::KeyId;

use crate::error::map;
use crate::store::PgStore;

/// An identity provider as it is configured.
///
/// The client secret is not here. It is fetched separately by
/// [`PgStore::provider_secret`], so that listing providers for the sign-in page cannot
/// accidentally carry sealed material into a response.
#[derive(Clone, Debug)]
pub struct Provider {
    pub id: uuid::Uuid,
    pub org_id: OrgId,
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub groups_claim: String,
    pub enabled: bool,
    /// Whether a client secret is stored, without revealing it.
    ///
    /// An operator needs to know which of the two configurations this is — confidential
    /// client or public client with PKCE alone — and that question is answerable without
    /// the secret.
    pub has_secret: bool,
}

/// What the sign-in page needs, and nothing that would help an attacker.
///
/// No issuer, no client id. Both are discoverable elsewhere and neither is secret, but
/// an unauthenticated endpoint that enumerates a company's identity provider is a
/// reconnaissance gift for a phishing campaign aimed at the same company.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignInOption {
    pub id: uuid::Uuid,
    pub name: String,
}

/// How an account came to exist, for the audit entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provisioned {
    /// First sign-in: the account was created now.
    Created,
    /// The account already existed and its roles were reconciled.
    Matched,
}

impl PgStore {
    /// Create an identity provider.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said — including the unique violation for a second provider
    /// with the same issuer in one organization.
    pub async fn create_provider(
        &self,
        org: OrgId,
        name: &str,
        issuer: &str,
        client_id: &str,
        groups_claim: &str,
        secret: Option<&SealedValue>,
    ) -> Result<uuid::Uuid> {
        // tenant-exempt: an identity provider belongs to an organization, which sits
        // above the tenant isolation boundary — the same reason `app_user` does.
        let row = sqlx::query!(
            r#"
            INSERT INTO identity_provider
                (org_id, name, issuer, client_id, groups_claim,
                 kek_id, wrapped_dek, dek_nonce, ciphertext, nonce, backend_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
            "#,
            org as OrgId,
            name,
            issuer,
            client_id,
            groups_claim,
            secret.map(|s| s.kek_id.as_str().to_owned()),
            secret.map(|s| s.wrapped_dek.clone()),
            secret.map(|s| s.dek_nonce.to_vec()),
            secret.map(|s| s.ciphertext.clone()),
            secret.map(|s| s.nonce.to_vec()),
            secret.map(|s| s.backend_id.clone()),
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("identity provider", issuer.to_owned(), e))?;
        Ok(row.id)
    }

    /// Create a provider whose id the caller has already chosen.
    ///
    /// Not a convenience. The client secret is sealed under an AAD naming the row it
    /// will live in, so the id has to exist *before* the secret is sealed — and a
    /// database-generated one would only be known after. Sealing under a different id
    /// produces a row whose secret can never be opened, discovered at somebody's first
    /// sign-in rather than at the write.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    // Eight arguments, and a struct would not improve it: every one is a column of the
    // row being written, and the one caller fills them from a request body it has just
    // validated. A `NewProvider` here would be the same eight fields with a name.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_provider_with_id(
        &self,
        id: uuid::Uuid,
        org: OrgId,
        name: &str,
        issuer: &str,
        client_id: &str,
        groups_claim: &str,
        secret: Option<&SealedValue>,
    ) -> Result<uuid::Uuid> {
        // tenant-exempt: as `create_provider`.
        let row = sqlx::query!(
            r#"
            INSERT INTO identity_provider
                (id, org_id, name, issuer, client_id, groups_claim,
                 kek_id, wrapped_dek, dek_nonce, ciphertext, nonce, backend_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id
            "#,
            id,
            org as OrgId,
            name,
            issuer,
            client_id,
            groups_claim,
            secret.map(|s| s.kek_id.as_str().to_owned()),
            secret.map(|s| s.wrapped_dek.clone()),
            secret.map(|s| s.dek_nonce.to_vec()),
            secret.map(|s| s.ciphertext.clone()),
            secret.map(|s| s.nonce.to_vec()),
            secret.map(|s| s.backend_id.clone()),
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("identity provider", issuer.to_owned(), e))?;
        Ok(row.id)
    }

    /// One provider, by id, within an organization.
    ///
    /// Scoped by `org` and not only by `id`: the id arrives from a URL, and a lookup on
    /// the id alone would let a member of one organization start a sign-in against
    /// another's provider. Nothing terrible follows from that on its own — the token
    /// still has to verify — but it is the kind of gap that becomes terrible when
    /// something downstream starts trusting the row.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn provider(&self, org: OrgId, id: uuid::Uuid) -> Result<Option<Provider>> {
        // tenant-exempt: as `create_provider`.
        let row = sqlx::query!(
            r#"
            SELECT id, org_id AS "org_id: OrgId", name, issuer, client_id, groups_claim,
                   enabled, (kek_id IS NOT NULL) AS "has_secret!"
              FROM identity_provider
             WHERE id = $1 AND org_id = $2
            "#,
            id,
            org as OrgId,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("identity provider", id.to_string(), e))?;

        Ok(row.map(|r| Provider {
            id: r.id,
            org_id: r.org_id,
            name: r.name,
            issuer: r.issuer,
            client_id: r.client_id,
            groups_claim: r.groups_claim,
            enabled: r.enabled,
            has_secret: r.has_secret,
        }))
    }

    /// Every provider an organization has configured, enabled or not.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn providers(&self, org: OrgId) -> Result<Vec<Provider>> {
        // tenant-exempt: as `create_provider`.
        let rows = sqlx::query!(
            r#"
            SELECT id, org_id AS "org_id: OrgId", name, issuer, client_id, groups_claim,
                   enabled, (kek_id IS NOT NULL) AS "has_secret!"
              FROM identity_provider
             WHERE org_id = $1
             ORDER BY name, id
            "#,
            org as OrgId,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("identity provider", org.to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| Provider {
                id: r.id,
                org_id: r.org_id,
                name: r.name,
                issuer: r.issuer,
                client_id: r.client_id,
                groups_claim: r.groups_claim,
                enabled: r.enabled,
                has_secret: r.has_secret,
            })
            .collect())
    }

    /// The buttons to put on the sign-in page.
    ///
    /// Across the whole deployment rather than per organization, because a person at a
    /// sign-in page has not identified themselves yet. That is a deliberate exposure and
    /// a small one — it lists the names an operator chose for their own buttons — and it
    /// is why [`SignInOption`] carries no issuer and no client id.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn sign_in_options(&self) -> Result<Vec<SignInOption>> {
        // tenant-exempt: this is asked before anybody has authenticated, so there is no
        // tenant and no user to scope it by.
        let rows = sqlx::query!(
            r#"
            SELECT id, name FROM identity_provider
             WHERE enabled ORDER BY name, id
            "#
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("identity provider", String::new(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| SignInOption {
                id: r.id,
                name: r.name,
            })
            .collect())
    }

    /// A provider by id alone, for the sign-in flow.
    ///
    /// The one place an id is *not* scoped by organization, because the browser at the
    /// sign-in page has not said who it is yet — the provider is what will tell us. It
    /// returns only enabled providers, which is what makes disabling one an immediate
    /// stop rather than a change that takes effect at the next restart.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn enabled_provider(&self, id: uuid::Uuid) -> Result<Option<Provider>> {
        // tenant-exempt: as `sign_in_options`.
        let row = sqlx::query!(
            r#"
            SELECT id, org_id AS "org_id: OrgId", name, issuer, client_id, groups_claim,
                   enabled, (kek_id IS NOT NULL) AS "has_secret!"
              FROM identity_provider
             WHERE id = $1 AND enabled
            "#,
            id,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("identity provider", id.to_string(), e))?;

        Ok(row.map(|r| Provider {
            id: r.id,
            org_id: r.org_id,
            name: r.name,
            issuer: r.issuer,
            client_id: r.client_id,
            groups_claim: r.groups_claim,
            enabled: r.enabled,
            has_secret: r.has_secret,
        }))
    }

    /// The sealed client secret, for the token exchange.
    ///
    /// Returns the envelope, never the plaintext: opening it is `uops_secrets::Envelope`
    /// and needs the KEK, which this process has and this module does not.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn provider_secret(&self, id: uuid::Uuid) -> Result<Option<SealedValue>> {
        // tenant-exempt: as `create_provider`.
        let row = sqlx::query!(
            r#"
            SELECT kek_id, wrapped_dek, dek_nonce, ciphertext, nonce, backend_id
              FROM identity_provider WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("identity provider", id.to_string(), e))?;

        // The `identity_provider_secret_is_whole` CHECK makes "some present, some
        // absent" unrepresentable, so this is the two legitimate cases and not a
        // partial-row defence. A `let else` on all six keeps it that way even if the
        // constraint is ever weakened.
        let Some(r) = row else { return Ok(None) };
        let (
            Some(kek_id),
            Some(wrapped_dek),
            Some(dek_nonce),
            Some(ciphertext),
            Some(nonce),
            Some(backend_id),
        ) = (
            r.kek_id,
            r.wrapped_dek,
            r.dek_nonce,
            r.ciphertext,
            r.nonce,
            r.backend_id,
        )
        else {
            return Ok(None);
        };

        Ok(Some(SealedValue {
            kek_id: KeyId::new(kek_id),
            wrapped_dek,
            dek_nonce: nonce_array(&dek_nonce)?,
            ciphertext,
            nonce: nonce_array(&nonce)?,
            backend_id,
        }))
    }

    /// Enable or disable a provider.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn set_provider_enabled(
        &self,
        org: OrgId,
        id: uuid::Uuid,
        enabled: bool,
    ) -> Result<bool> {
        // tenant-exempt: as `create_provider`.
        let affected = sqlx::query!(
            r#"UPDATE identity_provider SET enabled = $3 WHERE id = $1 AND org_id = $2"#,
            id,
            org as OrgId,
            enabled,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("identity provider", id.to_string(), e))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// Add or change one line of the group mapping.
    ///
    /// Re-granting the same group on the same tenant changes the role rather than
    /// failing, which is what an operator correcting a mistake expects.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said — including the composite foreign key that refuses a
    /// tenant belonging to another organization.
    pub async fn grant_group(
        &self,
        org: OrgId,
        provider: uuid::Uuid,
        group: &str,
        tenant: TenantId,
        role: Role,
        by: Option<ActorId>,
    ) -> Result<()> {
        // tenant-exempt: the tenant is a *value* here rather than a scope — this writes
        // a rule about a tenant, and which tenants may appear is enforced by the
        // composite foreign key to `tenant (id, org_id)` rather than by a predicate.
        sqlx::query!(
            r#"
            INSERT INTO identity_provider_grant
                (provider_id, org_id, group_name, tenant_id, role, created_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (provider_id, group_name, tenant_id)
            DO UPDATE SET role = EXCLUDED.role,
                          created_at = now(),
                          created_by = EXCLUDED.created_by
            "#,
            provider,
            org as OrgId,
            group,
            tenant as TenantId,
            role as Role,
            by as Option<ActorId>,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("group mapping", group.to_owned(), e))?;
        Ok(())
    }

    /// Remove one line of the group mapping.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn revoke_group(
        &self,
        org: OrgId,
        provider: uuid::Uuid,
        group: &str,
        tenant: TenantId,
    ) -> Result<bool> {
        // tenant-exempt: as `grant_group`.
        let affected = sqlx::query!(
            r#"
            DELETE FROM identity_provider_grant
             WHERE provider_id = $1 AND org_id = $2 AND group_name = $3 AND tenant_id = $4
            "#,
            provider,
            org as OrgId,
            group,
            tenant as TenantId,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("group mapping", group.to_owned(), e))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// A provider's whole group mapping.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn mapping(&self, provider: uuid::Uuid) -> Result<Mapping> {
        // tenant-exempt: this reads the rule set that *decides* tenant access, so it
        // cannot itself be scoped to one tenant. It is keyed on a provider, which is
        // org-scoped by its own foreign key.
        let rows = sqlx::query!(
            r#"
            SELECT group_name, tenant_id AS "tenant_id: TenantId", role AS "role: Role"
              FROM identity_provider_grant
             WHERE provider_id = $1
             ORDER BY group_name, tenant_id
            "#,
            provider,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("group mapping", provider.to_string(), e))?;

        Ok(Mapping::new(
            rows.into_iter()
                .map(|r| Grant {
                    group: r.group_name,
                    tenant_id: r.tenant_id,
                    role: r.role,
                })
                .collect(),
        ))
    }

    /// A provider's group mapping as rows, for the screen that edits it.
    ///
    /// The same data [`PgStore::mapping`] returns, in the shape a list needs rather than
    /// the shape a decision needs. Two methods rather than one conversion, because the
    /// decision side should not be able to grow a field the display side wanted.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn grants(&self, provider: uuid::Uuid) -> Result<Vec<Grant>> {
        // tenant-exempt: as `mapping`.
        let rows = sqlx::query!(
            r#"
            SELECT group_name, tenant_id AS "tenant_id: TenantId", role AS "role: Role"
              FROM identity_provider_grant
             WHERE provider_id = $1
             ORDER BY group_name, tenant_id
            "#,
            provider,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("group mapping", provider.to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| Grant {
                group: r.group_name,
                tenant_id: r.tenant_id,
                role: r.role,
            })
            .collect())
    }

    /// Find or create the account for a provider's subject, and set its roles.
    ///
    /// One transaction, for the reason in the module docs: two simultaneous first logins
    /// must not race into a unique violation that one of them experiences as a failed
    /// sign-in.
    ///
    /// **Roles are replaced, not merged.** The provider is authoritative for an account
    /// it owns, so a user removed from a group at the provider loses the role here at
    /// their next sign-in. Merging would mean the only way to take access away is to
    /// find it in this product too, which is precisely the second access list an
    /// identity team asked for SSO to avoid.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn provision(
        &self,
        provider: &Provider,
        subject: &str,
        email: &str,
        display_name: &str,
        roles: &[(TenantId, Role)],
    ) -> Result<(ActorId, Provisioned)> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| map("user", subject.to_owned(), e))?;

        // tenant-exempt: a user is an organization-level record.
        //
        // `ON CONFLICT ... DO UPDATE` rather than `DO NOTHING`, because `DO NOTHING`
        // returns no row and the caller would have to select again — which is the race
        // this transaction exists to remove, moved one statement later.
        let existing = sqlx::query!(
            r#"SELECT id AS "id: ActorId" FROM app_user WHERE idp_id = $1 AND idp_subject = $2"#,
            provider.id,
            subject,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map("user", subject.to_owned(), e))?;

        // `match` rather than `if let ... else`: the two arms are a find and an insert,
        // both several statements long, and the `else` form reads as an afterthought
        // attached to the shorter one.
        #[allow(clippy::single_match_else)]
        let (user_id, outcome) = match existing {
            Some(r) => {
                // tenant-exempt: a user is an organization-level record.
                sqlx::query!(
                    r#"
                    UPDATE app_user
                       SET email = $2, display_name = $3, idp_last_login_at = now()
                     WHERE id = $1
                    "#,
                    r.id as ActorId,
                    email,
                    display_name,
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| map("user", subject.to_owned(), e))?;
                (r.id, Provisioned::Matched)
            }
            None => {
                let id = ActorId::new();
                // tenant-exempt: a user is an organization-level record. Which tenants
                // this account may reach is written below, into `user_tenant_role`.
                let inserted = sqlx::query!(
                    r#"
                    INSERT INTO app_user
                        (id, org_id, email, display_name, idp_id, idp_subject,
                         idp_last_login_at)
                    VALUES ($1, $2, $3, $4, $5, $6, now())
                    ON CONFLICT (idp_id, idp_subject) WHERE idp_id IS NOT NULL
                    DO UPDATE SET idp_last_login_at = now()
                    RETURNING id AS "id: ActorId", (xmax = 0) AS "created!"
                    "#,
                    id as ActorId,
                    provider.org_id as OrgId,
                    email,
                    display_name,
                    provider.id,
                    subject,
                )
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| map("user", subject.to_owned(), e))?;

                // `xmax = 0` distinguishes the insert from the conflict update. It is a
                // system column rather than a documented API, and it is the only way to
                // learn which happened in one statement — the alternative is the second
                // round trip whose race this whole transaction removes.
                (
                    inserted.id,
                    if inserted.created {
                        Provisioned::Created
                    } else {
                        Provisioned::Matched
                    },
                )
            }
        };

        // Replace the role set. See the doc comment for why this is not a merge.
        //
        // tenant-exempt: this deliberately spans *every* tenant, because the provider is
        // authoritative for all of them at once. A per-tenant delete could only remove
        // roles on tenants the token still grants, which is the opposite of what
        // reconciliation means.
        sqlx::query!(
            r#"DELETE FROM user_tenant_role WHERE user_id = $1"#,
            user_id as ActorId,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| map("role", user_id.to_string(), e))?;

        for (tenant, role) in roles {
            sqlx::query!(
                r#"
                INSERT INTO user_tenant_role (user_id, tenant_id, role)
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id, tenant_id) DO UPDATE SET role = EXCLUDED.role
                "#,
                user_id as ActorId,
                *tenant as TenantId,
                *role as Role,
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| map("role", user_id.to_string(), e))?;
        }

        tx.commit()
            .await
            .map_err(|e| map("user", subject.to_owned(), e))?;

        Ok((user_id, outcome))
    }

    /// Whether an organization requires SSO, and which of its accounts may still use a
    /// password.
    ///
    /// Both in one statement, because the login handler needs both to decide and asking
    /// twice would let the answer change between them.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn password_policy(&self, user: ActorId) -> Result<PasswordPolicy> {
        // tenant-exempt: authentication precedes knowing a tenant.
        let row = sqlx::query!(
            r#"
            SELECT o.require_sso, u.break_glass
              FROM app_user u JOIN organization o ON o.id = u.org_id
             WHERE u.id = $1
            "#,
            user as ActorId,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("user", user.to_string(), e))?;

        Ok(match row {
            Some(r) => PasswordPolicy {
                require_sso: r.require_sso,
                break_glass: r.break_glass,
            },
            // An account that vanished between the credential check and this one. The
            // safe answer is the restrictive one.
            None => PasswordPolicy {
                require_sso: true,
                break_glass: false,
            },
        })
    }

    /// Require or stop requiring SSO for an organization.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn set_require_sso(&self, org: OrgId, required: bool) -> Result<()> {
        // tenant-exempt: an organization sits above the tenant isolation boundary.
        sqlx::query!(
            r#"UPDATE organization SET require_sso = $2 WHERE id = $1"#,
            org as OrgId,
            required,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("organization", org.to_string(), e))?;
        Ok(())
    }

    /// Whether an organization requires SSO.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn requires_sso(&self, org: OrgId) -> Result<bool> {
        // tenant-exempt: as `set_require_sso`.
        let row = sqlx::query_scalar!(
            r#"SELECT require_sso FROM organization WHERE id = $1"#,
            org as OrgId,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| map("organization", org.to_string(), e))?;
        Ok(row.unwrap_or(false))
    }

    /// Whether a user is an administrator of their whole organization.
    ///
    /// **Admin on every tenant the organization has, and on at least one.** A weaker
    /// rule — admin on *any* tenant — would be a privilege escalation with a very
    /// specific shape: an MSP gives a customer's own staff the admin role on that
    /// customer's tenant, and one of them then configures the MSP's identity provider
    /// and maps a group they belong to onto every other customer.
    ///
    /// In a single-company deployment, which is one organization and usually one tenant,
    /// this is exactly "is an admin" and costs nothing. In an MSP it means only somebody
    /// who can already reach everything may change how anybody signs in, which is the
    /// correct bar for a setting that decides who gets an account.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn is_org_admin(&self, user: ActorId, org: OrgId) -> Result<bool> {
        // tenant-exempt: the question is about *all* of an organization's tenants at
        // once, so there is no single scope it could be asked within.
        let row = sqlx::query!(
            r#"
            SELECT count(*)                                      AS "total!",
                   count(r.role) FILTER (WHERE r.role = 'admin') AS "held!"
              FROM tenant t
              -- The account being live is part of the *join*, not a separate predicate.
              -- As a `LEFT JOIN app_user` it would filter nothing — a left join keeps the
              -- row either way — and a disabled account would still count as an admin.
              -- Checked here as well as at login for the same reason `role_for` does it:
              -- a live session must stop working the moment the account does.
              LEFT JOIN user_tenant_role r
                     ON r.tenant_id = t.id
                    AND r.user_id = $1
                    AND EXISTS (
                        SELECT 1 FROM app_user u
                         WHERE u.id = r.user_id AND u.disabled_at IS NULL
                    )
             WHERE t.org_id = $2
            "#,
            user as ActorId,
            org as OrgId,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| map("role", user.to_string(), e))?;

        Ok(row.total > 0 && row.held == row.total)
    }

    /// Record an act that happened above the tenant boundary.
    ///
    /// Signing in, configuring an identity provider, using the break-glass account.
    /// Migration 0024 made `audit_log.tenant_id` nullable for exactly these: writing
    /// them against an arbitrary tenant would be a lie, and specifically the kind an
    /// auditor has to be told about afterwards — which is worse than a gap.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn record_org_audit(
        &self,
        org: OrgId,
        actor: &str,
        action: &str,
        target: &str,
        detail: Option<serde_json::Value>,
        ip: Option<std::net::IpAddr>,
    ) -> Result<()> {
        // tenant-exempt: this is the org-level half of the audit log. `tenant_id` is
        // left NULL on purpose and `org_id` is what makes the row findable.
        sqlx::query!(
            r#"
            INSERT INTO audit_log (tenant_id, org_id, actor, action, target, after, ip)
            VALUES (NULL, $1, $2, $3, $4, $5, $6::text::inet)
            "#,
            org as OrgId,
            actor,
            action,
            target,
            detail,
            ip.map(|ip| ip.to_string()),
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("audit_log", target.to_owned(), e))?;
        Ok(())
    }

    /// Recent organization-level audit entries.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn org_audit_entries(&self, org: OrgId, limit: i64) -> Result<Vec<OrgAuditEntry>> {
        // tenant-exempt: as `record_org_audit`.
        let rows = sqlx::query!(
            r#"
            SELECT actor, action, target, after, host(ip) AS ip, at
              FROM audit_log
             WHERE org_id = $1 AND tenant_id IS NULL
             ORDER BY at DESC
             LIMIT $2
            "#,
            org as OrgId,
            limit.clamp(1, 1_000),
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("audit_log", org.to_string(), e))?;

        Ok(rows
            .into_iter()
            .map(|r| OrgAuditEntry {
                actor: r.actor,
                action: r.action,
                target: r.target,
                detail: r.after,
                ip: r.ip,
                at: r.at,
            })
            .collect())
    }

    /// Mark an account as the organization's break-glass account.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said — including the unique index that refuses a second one
    /// and the check that refuses one without a password.
    pub async fn set_break_glass(&self, user: ActorId, is_break_glass: bool) -> Result<()> {
        // tenant-exempt: a user is an organization-level record.
        sqlx::query!(
            r#"UPDATE app_user SET break_glass = $2 WHERE id = $1"#,
            user as ActorId,
            is_break_glass,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("user", user.to_string(), e))?;
        Ok(())
    }
}

/// One organization-level audit entry, as an administrator reads it.
#[derive(Clone, Debug)]
pub struct OrgAuditEntry {
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: Option<serde_json::Value>,
    pub ip: Option<String>,
    pub at: chrono::DateTime<chrono::Utc>,
}

/// What a password login is allowed to do for one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// The organization requires single sign-on.
    pub require_sso: bool,
    /// This account is the named exception.
    pub break_glass: bool,
}

impl PasswordPolicy {
    /// Whether a password login may proceed.
    #[must_use]
    pub const fn allows_password(self) -> bool {
        !self.require_sso || self.break_glass
    }

    /// Whether this login is the exceptional one that must be audited.
    #[must_use]
    pub const fn is_break_glass_use(self) -> bool {
        self.require_sso && self.break_glass
    }
}

/// A nonce out of `bytea`, which is any length.
///
/// A row whose nonce is the wrong size was not written by this code. The same defence
/// `PgSealedStore` makes, and for the same reason: a silently truncated nonce produces a
/// decryption failure somewhere far away from the corruption.
fn nonce_array(bytes: &[u8]) -> Result<[u8; uops_secrets::NONCE_LEN]> {
    bytes.try_into().map_err(|_| {
        uops_core::Error::Storage(format!(
            "a sealed client secret has a {}-byte nonce; {} is the only valid length",
            bytes.len(),
            uops_secrets::NONCE_LEN
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requiring_sso_leaves_exactly_one_way_in() {
        let ordinary = PasswordPolicy {
            require_sso: true,
            break_glass: false,
        };
        assert!(!ordinary.allows_password());

        let glass = PasswordPolicy {
            require_sso: true,
            break_glass: true,
        };
        assert!(glass.allows_password());
        assert!(glass.is_break_glass_use());
    }

    #[test]
    fn a_break_glass_account_is_unremarkable_until_sso_is_required() {
        // Marking an account break-glass is preparation, not an event. Auditing its
        // every login before SSO is required would fill the log with entries that mean
        // nothing, which is how the one that means something gets missed.
        let policy = PasswordPolicy {
            require_sso: false,
            break_glass: true,
        };
        assert!(policy.allows_password());
        assert!(!policy.is_break_glass_use());
    }

    #[test]
    fn a_vanished_account_gets_the_restrictive_answer() {
        // Not a test of a branch so much as of a direction: the fallback in
        // `password_policy` denies rather than permits.
        let fallback = PasswordPolicy {
            require_sso: true,
            break_glass: false,
        };
        assert!(!fallback.allows_password());
    }
}
