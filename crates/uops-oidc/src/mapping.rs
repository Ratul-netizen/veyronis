//! Turning the provider's groups into this product's roles — M12 §2.2.
//!
//! # Configuration, never inference
//!
//! The product does not guess that a group called `network-admins` means [`Role::Admin`].
//! An operator writes the mapping down, because the alternative is that renaming a group
//! in the identity provider silently grants or removes access here — and nobody renaming
//! a group in Entra ID is thinking about this product.
//!
//! # A user who maps to nothing gets nothing
//!
//! Not a viewer, not a default tenant. Authentication succeeded and authorisation did
//! not, and those are different answers: the first says the person is who they say, the
//! second says nobody has decided what they may do. A default role here would mean that
//! every employee of a 2 000-person company can read a customer's network the day SSO is
//! switched on, which is exactly the outcome the identity team is trying to prevent by
//! asking for SSO in the first place.

use std::collections::BTreeMap;

use uops_core::{Role, TenantId};

/// One line of the mapping: a group at the provider, a tenant here, a role there.
///
/// Per tenant rather than global, because that is how this product's roles work — SPEC
/// §M1, *one MSP operator can be admin on one tenant and viewer on another* — and a
/// mapping that could not express it would force every MSP customer into one blast
/// radius.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The claim value, as the provider sends it.
    ///
    /// A name from Okta or Keycloak, an object id from Entra ID. Both are opaque here,
    /// which is why this is a string and not something cleverer.
    pub group: String,
    pub tenant_id: TenantId,
    pub role: Role,
}

/// Every grant configured for one identity provider.
#[derive(Clone, Debug, Default)]
pub struct Mapping {
    grants: Vec<Grant>,
}

/// What a user's groups entitle them to, once the mapping has been applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entitlement {
    /// One role per tenant. Empty means no access at all.
    pub roles: BTreeMap<TenantId, Role>,
    /// Groups the token carried that no grant mentions.
    ///
    /// Kept for the log, not for the decision. It is the difference between *the user is
    /// in no groups* and *the user is in six groups nobody has mapped*, and an operator
    /// debugging a refused login needs to know which — the first is a provider problem
    /// and the second is theirs.
    pub unmapped: Vec<String>,
}

impl Entitlement {
    /// Whether this user may sign in at all.
    #[must_use]
    pub fn grants_access(&self) -> bool {
        !self.roles.is_empty()
    }

    /// Why a sign-in was refused, for the audit entry and the server log.
    ///
    /// Never shown to the user: which groups a product maps is a description of the
    /// customer's internal structure, and an unauthenticated stranger learning it from a
    /// failed login has learned something.
    #[must_use]
    pub fn refusal(&self) -> String {
        if self.unmapped.is_empty() {
            "the token carried no group claim, so no role could be granted".to_owned()
        } else {
            format!(
                "none of the {} group(s) in the token is mapped to a role: {}",
                self.unmapped.len(),
                self.unmapped.join(", ")
            )
        }
    }
}

impl Mapping {
    #[must_use]
    pub fn new(grants: Vec<Grant>) -> Self {
        Self { grants }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Apply the mapping to the groups a token carried.
    ///
    /// **The highest role wins** when several groups grant roles on the same tenant.
    /// The alternative — the lowest, or the first — would make access depend on the
    /// order of a JSON array the provider chose, and would mean that adding somebody to
    /// an additional group could take permissions away. Neither is a rule an operator
    /// could hold in their head.
    #[must_use]
    pub fn apply(&self, groups: &[String]) -> Entitlement {
        let mut roles: BTreeMap<TenantId, Role> = BTreeMap::new();
        let mut unmapped = Vec::new();

        for group in groups {
            let mut matched = false;
            for grant in &self.grants {
                // Case-insensitive: group names in Active Directory are, and an
                // operator who types `Network-Admins` where the provider sends
                // `network-admins` has made a typo that should not cost them a day.
                // Entra ID object ids are hex, where the same comparison is harmless.
                if grant.group.eq_ignore_ascii_case(group) {
                    matched = true;
                    roles
                        .entry(grant.tenant_id)
                        .and_modify(|held| *held = (*held).max(grant.role))
                        .or_insert(grant.role);
                }
            }
            if !matched {
                unmapped.push(group.clone());
            }
        }

        Entitlement { roles, unmapped }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId::new()
    }

    #[test]
    fn a_mapped_group_grants_its_role() {
        let t = tenant();
        let mapping = Mapping::new(vec![Grant {
            group: "network-admins".to_owned(),
            tenant_id: t,
            role: Role::Admin,
        }]);
        let out = mapping.apply(&["network-admins".to_owned()]);
        assert_eq!(out.roles.get(&t), Some(&Role::Admin));
        assert!(out.grants_access());
    }

    #[test]
    fn an_unmapped_group_grants_nothing() {
        let mapping = Mapping::new(vec![Grant {
            group: "network-admins".to_owned(),
            tenant_id: tenant(),
            role: Role::Admin,
        }]);
        let out = mapping.apply(&["everyone".to_owned()]);
        assert!(!out.grants_access());
        assert_eq!(out.unmapped, ["everyone"]);
    }

    #[test]
    fn no_groups_at_all_is_no_access_rather_than_a_default_role() {
        // The decision this file exists to enforce. A default viewer role would mean
        // every employee of the company can read a customer's network the day SSO is
        // switched on.
        let mapping = Mapping::new(vec![Grant {
            group: "network-admins".to_owned(),
            tenant_id: tenant(),
            role: Role::Viewer,
        }]);
        let out = mapping.apply(&[]);
        assert!(!out.grants_access());
        assert!(out.roles.is_empty());
    }

    #[test]
    fn the_highest_role_wins_on_one_tenant() {
        let t = tenant();
        let mapping = Mapping::new(vec![
            Grant {
                group: "staff".to_owned(),
                tenant_id: t,
                role: Role::Viewer,
            },
            Grant {
                group: "noc".to_owned(),
                tenant_id: t,
                role: Role::Operator,
            },
            Grant {
                group: "admins".to_owned(),
                tenant_id: t,
                role: Role::Admin,
            },
        ]);

        // Every order of the same three groups gives the same answer. If it did not,
        // access would depend on a JSON array's order, which is the provider's to
        // change without telling anyone.
        for groups in [
            vec!["staff", "noc", "admins"],
            vec!["admins", "noc", "staff"],
            vec!["noc", "admins", "staff"],
        ] {
            let owned: Vec<String> = groups.iter().map(|s| (*s).to_owned()).collect();
            assert_eq!(mapping.apply(&owned).roles.get(&t), Some(&Role::Admin));
        }
    }

    #[test]
    fn adding_a_group_never_removes_access() {
        let t = tenant();
        let mapping = Mapping::new(vec![
            Grant {
                group: "admins".to_owned(),
                tenant_id: t,
                role: Role::Admin,
            },
            Grant {
                group: "contractors".to_owned(),
                tenant_id: t,
                role: Role::Viewer,
            },
        ]);
        let before = mapping.apply(&["admins".to_owned()]);
        let after = mapping.apply(&["admins".to_owned(), "contractors".to_owned()]);
        assert_eq!(before.roles.get(&t), Some(&Role::Admin));
        assert_eq!(after.roles.get(&t), Some(&Role::Admin));
    }

    #[test]
    fn one_user_can_hold_different_roles_on_different_tenants() {
        // SPEC §M1's MSP case, which is the reason grants name a tenant at all.
        let acme = tenant();
        let globex = tenant();
        let mapping = Mapping::new(vec![
            Grant {
                group: "noc".to_owned(),
                tenant_id: acme,
                role: Role::Admin,
            },
            Grant {
                group: "noc".to_owned(),
                tenant_id: globex,
                role: Role::Viewer,
            },
        ]);
        let out = mapping.apply(&["noc".to_owned()]);
        assert_eq!(out.roles.get(&acme), Some(&Role::Admin));
        assert_eq!(out.roles.get(&globex), Some(&Role::Viewer));
    }

    #[test]
    fn group_comparison_ignores_case() {
        let t = tenant();
        let mapping = Mapping::new(vec![Grant {
            group: "Network-Admins".to_owned(),
            tenant_id: t,
            role: Role::Operator,
        }]);
        assert_eq!(
            mapping.apply(&["network-admins".to_owned()]).roles.get(&t),
            Some(&Role::Operator)
        );
    }

    #[test]
    fn an_empty_mapping_grants_nothing_to_anyone() {
        // A provider configured but not yet mapped must refuse, not admit. This is the
        // state an operator is in between creating the provider and finishing the job.
        let mapping = Mapping::default();
        assert!(!mapping.apply(&["admins".to_owned()]).grants_access());
    }

    #[test]
    fn the_refusal_distinguishes_no_groups_from_unmapped_groups() {
        // One is the provider's problem and the other is the operator's, and a message
        // that conflated them would send somebody to the wrong console.
        let mapping = Mapping::new(vec![Grant {
            group: "admins".to_owned(),
            tenant_id: tenant(),
            role: Role::Admin,
        }]);
        assert!(mapping.apply(&[]).refusal().contains("no group claim"));
        assert!(
            mapping
                .apply(&["everyone".to_owned()])
                .refusal()
                .contains("everyone")
        );
    }
}
