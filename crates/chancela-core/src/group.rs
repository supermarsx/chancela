//! Tenant-local company groups and their shared, versioned template libraries (ENT-C7, DAT-03,
//! WFL-32).
//!
//! A group is a convenience aggregate inside one [`crate::Tenant`], never a second authorization
//! boundary. Entities keep owning their books, acts, and audit chains; membership is only the
//! additive [`crate::Entity::group_id`] label. The API enforces the load-bearing invariant that a
//! group and every member entity have the same `tenant_id`.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Entity, TenantId};

/// Opaque identifier for a [`CompanyGroup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GroupId(pub Uuid);

impl GroupId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for GroupId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Opaque identifier for one named shared template library inside a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TemplateLibraryId(pub Uuid);

impl TemplateLibraryId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TemplateLibraryId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TemplateLibraryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A named group of companies within exactly one tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanyGroup {
    pub id: GroupId,
    pub tenant_id: TenantId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub archived_at: Option<OffsetDateTime>,
}

impl CompanyGroup {
    #[must_use]
    pub fn new(tenant_id: TenantId, name: impl Into<String>, now: OffsetDateTime) -> Self {
        Self {
            id: GroupId::new(),
            tenant_id,
            name: name.into(),
            description: None,
            created_at: now,
            updated_at: now,
            archived_at: None,
        }
    }

    /// The membership invariant: groups may contain only entities from their own tenant.
    #[must_use]
    pub fn can_contain(&self, entity: &Entity) -> bool {
        self.tenant_id == entity.tenant_id
    }

    #[must_use]
    pub fn is_archived(&self) -> bool {
        self.archived_at.is_some()
    }
}

/// One named shared template library owned by a company group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupTemplateLibrary {
    pub id: TemplateLibraryId,
    pub group_id: GroupId,
    pub tenant_id: TenantId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub archived_at: Option<OffsetDateTime>,
}

impl GroupTemplateLibrary {
    #[must_use]
    pub fn new(group: &CompanyGroup, name: impl Into<String>, now: OffsetDateTime) -> Self {
        Self {
            id: TemplateLibraryId::new(),
            group_id: group.id,
            tenant_id: group.tenant_id,
            name: name.into(),
            description: None,
            created_at: now,
            updated_at: now,
            archived_at: None,
        }
    }

    #[must_use]
    pub fn is_archived(&self) -> bool {
        self.archived_at.is_some()
    }
}

/// An immutable snapshot of the template identifiers shared through one library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupTemplateLibraryRevision {
    pub group_id: GroupId,
    pub library_id: TemplateLibraryId,
    pub tenant_id: TenantId,
    /// Starts at one and increases by exactly one within a library.
    pub revision: u64,
    /// Deterministically ordered, duplicate-free ids of built-in or user-authored templates.
    pub template_ids: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub created_by: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntityKind, Nipc};

    #[test]
    fn group_membership_requires_the_same_tenant() {
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let group = CompanyGroup::new(tenant_a, "Grupo A", OffsetDateTime::UNIX_EPOCH);
        let entity_a = Entity::new(
            "A, Lda.",
            Nipc::parse("503004642").unwrap(),
            "Lisboa",
            EntityKind::SociedadePorQuotas,
        )
        .in_tenant(tenant_a);
        let entity_b = Entity::new(
            "B, Lda.",
            Nipc::parse("501964843").unwrap(),
            "Porto",
            EntityKind::SociedadePorQuotas,
        )
        .in_tenant(tenant_b);

        assert!(group.can_contain(&entity_a));
        assert!(!group.can_contain(&entity_b));
    }
}
