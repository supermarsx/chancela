//! Tenants — the isolation boundary **above** [`crate::Entity`] (spec 05 DAT-01, SCP-30 phase 4).
//!
//! A [`Tenant`] (a.k.a. organization) is the hard isolation boundary of the platform hierarchy
//! `Platform → Tenant → Company/Entity → Book → Act`. Every [`crate::Entity`] belongs to exactly
//! one tenant; books and acts inherit their tenant transitively through the existing
//! `entity_id → book_id` ownership chain, so the tenant is materialised on exactly one aggregate.
//!
//! ## Additive, non-breaking rollout
//!
//! `tenant_id` rides **inside** `entities.json` as a `#[serde(default = "default_tenant_id")]`
//! field (see [`crate::Entity`]): old-shape entity JSON that predates tenancy deserialises to the
//! singleton [`DEFAULT_TENANT_ID`], so all pre-existing data migrates cleanly to one default
//! tenant and single-tenant behaviour stays byte-identical until a genuinely multi-tenant actor
//! is introduced. There is **no** new column on `entities` (the store is additive-migration-only);
//! tenancy state is persisted only as a new `tenants` table.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Opaque identifier for a [`Tenant`]. Transparent UUID on the wire, so it is store/wire-compatible
/// with `chancela_authz`'s tenant scope id without either crate depending on the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TenantId(pub Uuid);

impl TenantId {
    /// Mint a fresh random identifier.
    #[must_use]
    pub fn new() -> Self {
        TenantId(Uuid::new_v4())
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The **singleton default tenant** that absorbs all pre-existing entities on migration.
///
/// A fixed, well-known id (like the seeded role ids): the high bytes spell an ASCII mnemonic
/// (`"tenant"`) so it is recognisable in a dump. Every entity whose `entities.json` lacks a
/// `tenant_id` resolves here via [`default_tenant_id`], and the API seeds a [`Tenant`] with this id
/// on boot so a single-tenant deployment has exactly one tenant containing everything.
pub const DEFAULT_TENANT_ID: TenantId =
    TenantId(Uuid::from_u128(0x74656e616e740000_0000000000000001));

/// The serde default for [`crate::Entity::tenant_id`]: the [`DEFAULT_TENANT_ID`] singleton. Old
/// entity JSON (no `tenant_id` key) deserialises to this, migrating cleanly to the default tenant.
#[must_use]
pub fn default_tenant_id() -> TenantId {
    DEFAULT_TENANT_ID
}

/// A tenant / organization: the isolation boundary that owns [`crate::Entity`]s (DAT-01).
///
/// Deliberately minimal — an id and a display name. Isolation is enforced centrally through the
/// authz scope tree (a `Scope::Tenant` level fed the entity→tenant relation), not by fields here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    /// Stable identifier.
    pub id: TenantId,
    /// Human-readable organization name.
    pub name: String,
}

impl Tenant {
    /// Construct a tenant with a fresh id.
    pub fn new(name: impl Into<String>) -> Self {
        Tenant {
            id: TenantId::new(),
            name: name.into(),
        }
    }

    /// The singleton default tenant ([`DEFAULT_TENANT_ID`]) that holds all pre-tenancy entities.
    #[must_use]
    pub fn default_tenant() -> Self {
        Tenant {
            id: DEFAULT_TENANT_ID,
            name: "Default".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tenant_id_is_stable() {
        assert_eq!(default_tenant_id(), DEFAULT_TENANT_ID);
        // The mnemonic id is fixed across builds (seeded-id discipline).
        assert_eq!(
            DEFAULT_TENANT_ID.0,
            Uuid::from_u128(0x74656e616e740000_0000000000000001)
        );
    }

    #[test]
    fn tenant_round_trips_through_json() {
        let t = Tenant::default_tenant();
        let json = serde_json::to_string(&t).unwrap();
        let back: Tenant = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
        assert_eq!(back.id, DEFAULT_TENANT_ID);
    }
}
