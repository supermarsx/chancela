//! `chancela-apikey` — the API-key model and the **key → RBAC-principal** seam (t65-E1).
//!
//! An API key **is** an RBAC principal, exactly like a session. This crate freezes:
//!
//! - [`ApiKey`] — a persisted key that stores **only** a sha256 hash of its high-entropy secret
//!   ([`ApiKey::key_hash`]), is shown once at [`ApiKey::issue`], and carries a `principal_grant`
//!   ([`ApiKeyGrant`]) reusing the frozen `chancela-authz` [`Scope`](chancela_authz::Scope) +
//!   [`Permission`](chancela_authz::Permission).
//! - **Generation + verification** — [`ApiKey::generate`] mints an unguessable `chk_…` plaintext and
//!   keeps only its hash; [`ApiKey::verify`] is a **constant-time** digest compare. The plaintext is
//!   never stored, returned again, or logged.
//! - **The attenuation invariant (the security crux)** — [`can_create_key`] / [`ApiKey::issue`]: a key
//!   may only grant authority **within its creator's own effective permissions** (at scope), and never
//!   a meta-permission. An over-powerful key is *impossible to construct*, not merely rejected.
//! - **The principal seam** — [`resolve`] turns a key + its creator's current authority into a
//!   [`RequestPrincipal`] carrying the *same* [`ScopedPermissionSet`](chancela_authz::ScopedPermissionSet)
//!   a session yields, so the API's single `require_permission` gate serves web, integration API and
//!   MCP uniformly. Expired/revoked keys, and downgraded/gone creators, resolve to **empty** authority
//!   (fail-closed).
//! - **Rate limiting** — [`RateLimit`] policy + a pure [`RateLimit::check`] token-bucket transition.
//!
//! **Purity / fail-closed.** No clock, no network, no store: the caller supplies `now`, the
//! [`RoleCatalog`](chancela_authz::RoleCatalog), the creator's authority, and the book→entity relation
//! ([`BookScope`](chancela_authz::BookScope)). Every uncertain case (unknown/expired/revoked key,
//! missing role, gone creator, malformed hash) resolves to *deny*.

mod grant;
mod hex;
mod key;
mod ratelimit;

use std::collections::BTreeSet;

use chancela_authz::{
    BookScope, Permission, Role, RoleAssignment, RoleCatalog, RoleId, Scope, ScopedPermissionSet,
    UserId, effective_permissions, has_permission,
};
use time::OffsetDateTime;
use uuid::Uuid;

pub use grant::ApiKeyGrant;
pub use key::{ApiKey, ApiKeyId, IssueError, KeySpec, NewApiKey, extract_prefix};
pub use ratelimit::{RateLimit, RateLimitOutcome, RateLimitState};

/// How a request authenticated. Distinguishes a session user from an API key so the two are never
/// conflated and the ledger attributes the right actor (plan §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalKind {
    /// A session token resolved to a user.
    Session { user: UserId },
    /// An API key, with its id and the creator whose authority bounds it.
    ApiKey { key: ApiKeyId, creator: UserId },
}

/// The unified subject the API's `require_permission` gate consumes — produced identically by a
/// session and an API key (plan §3.2). `effective_permissions` is the same
/// [`ScopedPermissionSet`](chancela_authz::ScopedPermissionSet) shape in both cases, so there is one
/// fail-closed gate for web, integration API and MCP with no api-key-only bypass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPrincipal {
    /// The ledger/audit actor: a username for a session, or `apikey:<name>#<prefix>` for a key.
    pub actor_label: String,
    /// The subject's resolved authority.
    pub effective_permissions: ScopedPermissionSet,
    /// Which credential authenticated, for attribution.
    pub kind: PrincipalKind,
}

impl RequestPrincipal {
    /// Build the principal for a **session** user. Provided so the API mints session and key
    /// principals through one type (the key path is [`resolve`]).
    #[must_use]
    pub fn for_session(
        user: UserId,
        actor_label: String,
        effective_permissions: ScopedPermissionSet,
    ) -> Self {
        RequestPrincipal {
            actor_label,
            effective_permissions,
            kind: PrincipalKind::Session { user },
        }
    }
}

/// **The attenuation invariant.** May `creator_effective` create a key carrying `grant`?
///
/// True iff the grant (resolved through `roles`) is **non-empty**, holds **no meta-permission**, and
/// **every** `(permission, scope)` it confers is within the creator's own authority
/// ([`has_permission`], honouring scope narrowing). This is the whole point of the model: a key can
/// never be more powerful than the user who minted it, and it can never wield the RBAC machinery.
///
/// This is the predicate; [`ApiKey::issue`] enforces it at mint time (returning a typed
/// [`IssueError`]). Holding a would-be `apikey.manage` permission does **not** exempt this check — as
/// with roles/delegations, authority to *manage* keys never lets you *exceed* your own ceiling.
#[must_use]
pub fn can_create_key(
    creator_effective: &ScopedPermissionSet,
    grant: &ApiKeyGrant,
    roles: &RoleCatalog,
    books: &impl BookScope,
) -> bool {
    let pairs = grant.grant_pairs(roles);
    !pairs.is_empty()
        && pairs.iter().all(|&(p, _)| !p.is_meta())
        && pairs
            .iter()
            .all(|&(p, s)| has_permission(creator_effective, p, s, books))
}

/// **The key → principal seam.** Resolve `key` into a [`RequestPrincipal`], given its creator's
/// *current* authority `creator_effective` (the API computes it via
/// [`effective_permissions`](chancela_authz::effective_permissions) from the creator's live
/// roles+delegations — pass an **empty** set if the creator is gone/inactive).
///
/// The resolved authority is the key's declared grant, **minus any meta-permission**, **intersected**
/// with `creator_effective` (honouring scope narrowing). So a key **auto-attenuates**: if the creator
/// is later downgraded, the key silently loses whatever the creator lost, with no re-issue. An
/// **expired or revoked** key (or an empty `creator_effective`) resolves to **no** permissions —
/// fail-closed. The `actor_label`/`kind` are always populated so the caller can attribute (and deny)
/// the request.
#[must_use]
pub fn resolve(
    key: &ApiKey,
    creator_effective: &ScopedPermissionSet,
    roles: &RoleCatalog,
    now: OffsetDateTime,
    books: &impl BookScope,
) -> RequestPrincipal {
    let kind = PrincipalKind::ApiKey {
        key: key.id,
        creator: key.created_by,
    };
    let actor_label = key.actor_label();

    if !key.is_active(now) {
        return RequestPrincipal {
            actor_label,
            effective_permissions: ScopedPermissionSet::new(),
            kind,
        };
    }

    // Key grant, stripped of meta-permissions (a key never wields RBAC machinery, even if hand-edited
    // into the store), intersected with the creator's current authority (auto-attenuation).
    let allowed: BTreeSet<(Permission, Scope)> = key
        .principal_grant
        .grant_pairs(roles)
        .into_iter()
        .filter(|&(p, _)| !p.is_meta())
        .filter(|&(p, s)| has_permission(creator_effective, p, s, books))
        .collect();

    RequestPrincipal {
        actor_label,
        effective_permissions: scoped_set_from_pairs(&allowed),
        kind,
    }
}

/// Build a [`ScopedPermissionSet`] holding exactly the given `(permission, scope)` pairs in its
/// role-grant bucket.
///
/// `chancela-authz` (frozen) exposes no direct constructor for a populated set — the only way in is
/// [`effective_permissions`]. So we synthesise, in a throwaway catalog, one role per distinct scope
/// carrying that scope's permissions, and resolve a matching assignment. The result is a *real*
/// `ScopedPermissionSet` byte-identical to what a session with those grants would produce, which is
/// exactly why the API's `require_permission` treats keys and sessions uniformly. The synthetic role
/// ids live only inside the throwaway catalog and never leak into the result.
fn scoped_set_from_pairs(pairs: &BTreeSet<(Permission, Scope)>) -> ScopedPermissionSet {
    use std::collections::BTreeMap;

    let mut by_scope: BTreeMap<Scope, BTreeSet<Permission>> = BTreeMap::new();
    for &(p, s) in pairs {
        by_scope.entry(s).or_default().insert(p);
    }

    let mut catalog = RoleCatalog::new();
    let mut assignments = Vec::with_capacity(by_scope.len());
    for (i, (scope, permission_set)) in by_scope.into_iter().enumerate() {
        let synth_id = RoleId(Uuid::from_u128(i as u128));
        catalog.insert(Role {
            id: synth_id,
            name: String::new(),
            permission_set,
            protected: false,
        });
        assignments.push(RoleAssignment::new(synth_id, scope));
    }

    // `now`/delegations are irrelevant here (no delegations); UNIX_EPOCH is a stable placeholder.
    effective_permissions(
        UserId(Uuid::nil()),
        &assignments,
        &catalog,
        &[],
        OffsetDateTime::UNIX_EPOCH,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_authz::{
        EntityId, GESTOR_ROLE_ID, LEITOR_ROLE_ID, NoBooks, OWNER_ROLE_ID, SIGNATARIO_ROLE_ID,
    };
    use std::collections::HashMap;
    use time::Duration;

    fn uid(n: u128) -> UserId {
        UserId(Uuid::from_u128(n))
    }
    fn ent(n: u128) -> EntityId {
        EntityId(Uuid::from_u128(0xE00 + n))
    }
    fn t0() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }
    fn books() -> impl BookScope {
        let mut m = HashMap::new();
        m.insert(chancela_authz::BookId(Uuid::from_u128(0xB01)), ent(1));
        move |b: chancela_authz::BookId| m.get(&b).copied()
    }
    /// A minimal key spec (creator uid(1), no expiry / rate-limit).
    fn ks(name: &str, grant: ApiKeyGrant) -> KeySpec {
        KeySpec {
            name: name.into(),
            principal_grant: grant,
            created_by: uid(1),
            created_at: t0(),
            expires_at: None,
            rate_limit: None,
        }
    }

    /// The effective authority of a user holding `role_id` at `scope`.
    fn eff_of(role_id: RoleId, scope: Scope) -> ScopedPermissionSet {
        let cat = RoleCatalog::seeded_defaults();
        effective_permissions(
            uid(1),
            &[RoleAssignment::new(role_id, scope)],
            &cat,
            &[],
            t0(),
        )
    }

    // ---- attenuation: can_create_key -------------------------------------------------------

    #[test]
    fn owner_can_create_a_gestor_scoped_key() {
        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();
        let grant = ApiKeyGrant::role(GESTOR_ROLE_ID, Scope::Global);
        assert!(can_create_key(&owner, &grant, &cat, &books()));
    }

    #[test]
    fn cannot_create_a_key_more_powerful_than_creator() {
        // A Leitor (read-only) cannot mint a key that can write.
        let leitor = eff_of(LEITOR_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();
        // Via a fat role...
        let via_role = ApiKeyGrant::role(GESTOR_ROLE_ID, Scope::Global);
        assert!(!can_create_key(&leitor, &via_role, &cat, &books()));
        // ...and via an explicit perm the creator lacks.
        let via_perms = ApiKeyGrant::perms([Permission::ActDraft], Scope::Global);
        assert!(!can_create_key(&leitor, &via_perms, &cat, &books()));
        // But a key ⊆ the creator's own authority is fine.
        let ok = ApiKeyGrant::perms([Permission::EntityRead], Scope::Global);
        assert!(can_create_key(&leitor, &ok, &cat, &books()));
    }

    #[test]
    fn attenuation_holds_at_scope() {
        // Creator is Gestor of entity 1 ONLY.
        let scoped = eff_of(GESTOR_ROLE_ID, Scope::Entity(ent(1)));
        let cat = RoleCatalog::seeded_defaults();
        // A key scoped to entity 1 with a perm the creator holds there: allowed.
        let within = ApiKeyGrant::perms([Permission::BookOpen], Scope::Entity(ent(1)));
        assert!(can_create_key(&scoped, &within, &cat, &books()));
        // The SAME perm but scoped GLOBALLY: refused (a scoped creator cannot mint global authority).
        let global = ApiKeyGrant::perms([Permission::BookOpen], Scope::Global);
        assert!(!can_create_key(&scoped, &global, &cat, &books()));
        // The same perm scoped to a DIFFERENT entity: refused.
        let other = ApiKeyGrant::perms([Permission::BookOpen], Scope::Entity(ent(2)));
        assert!(!can_create_key(&scoped, &other, &cat, &books()));
    }

    #[test]
    fn a_key_may_never_hold_a_meta_permission() {
        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();
        // Even the Owner (who holds every meta-permission) cannot mint a key that holds one...
        for meta in Permission::META {
            let grant = ApiKeyGrant::perms([meta], Scope::Global);
            assert!(!can_create_key(&owner, &grant, &cat, &books()));
        }
        // ...and cannot mint an Owner-role key, because Owner's set contains the meta permissions.
        let owner_key = ApiKeyGrant::role(OWNER_ROLE_ID, Scope::Global);
        assert!(!can_create_key(&owner, &owner_key, &cat, &books()));
    }

    #[test]
    fn empty_grant_cannot_create_a_key() {
        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();
        assert!(!can_create_key(
            &owner,
            &ApiKeyGrant::perms([], Scope::Global),
            &cat,
            &books()
        ));
        // A role absent from the catalog resolves to nothing ⇒ powerless ⇒ refused.
        let empty_cat = RoleCatalog::new();
        assert!(!can_create_key(
            &owner,
            &ApiKeyGrant::role(GESTOR_ROLE_ID, Scope::Global),
            &empty_cat,
            &books()
        ));
    }

    // ---- issue enforces attenuation --------------------------------------------------------

    #[test]
    fn issue_refuses_over_powerful_and_meta_grants() {
        let leitor = eff_of(LEITOR_ROLE_ID, Scope::Global);
        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();

        // Exceeds creator.
        let err = ApiKey::issue(
            &leitor,
            &cat,
            &books(),
            ks(
                "k",
                ApiKeyGrant::perms([Permission::DataWipe], Scope::Global),
            ),
        )
        .unwrap_err();
        assert_eq!(err, IssueError::GrantExceedsCreator);

        // Meta perm.
        let err = ApiKey::issue(
            &owner,
            &cat,
            &books(),
            ks(
                "k",
                ApiKeyGrant::perms([Permission::RoleManage], Scope::Global),
            ),
        )
        .unwrap_err();
        assert_eq!(err, IssueError::GrantContainsMeta);

        // Empty grant.
        let err = ApiKey::issue(
            &owner,
            &cat,
            &books(),
            ks("k", ApiKeyGrant::perms([], Scope::Global)),
        )
        .unwrap_err();
        assert_eq!(err, IssueError::EmptyGrant);
    }

    #[test]
    fn issue_succeeds_within_creator_authority() {
        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();
        let issued = ApiKey::issue(
            &owner,
            &cat,
            &books(),
            ks(
                "Integração ERP Encosto Estratégico",
                ApiKeyGrant::role(SIGNATARIO_ROLE_ID, Scope::Global),
            ),
        )
        .unwrap();
        assert!(issued.api_key.verify(&issued.plaintext));
    }

    // ---- resolve → RequestPrincipal --------------------------------------------------------

    #[test]
    fn resolve_yields_the_creator_bounded_scoped_permission_set() {
        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();
        let issued = ApiKey::issue(
            &owner,
            &cat,
            &books(),
            ks("erp", ApiKeyGrant::role(SIGNATARIO_ROLE_ID, Scope::Global)),
        )
        .unwrap();

        let principal = resolve(&issued.api_key, &owner, &cat, t0(), &books());
        // Holds exactly the Signatário permissions the key was granted...
        let signatario = cat.get(SIGNATARIO_ROLE_ID).unwrap();
        for &p in &signatario.permission_set {
            assert!(has_permission(
                &principal.effective_permissions,
                p,
                Scope::Global,
                &books()
            ));
        }
        // ...and nothing else (e.g. not data.wipe).
        assert!(!has_permission(
            &principal.effective_permissions,
            Permission::DataWipe,
            Scope::Global,
            &books()
        ));
        // Attribution is the key, never a secret.
        assert!(principal.actor_label.starts_with("apikey:erp#chk_"));
        assert_eq!(
            principal.kind,
            PrincipalKind::ApiKey {
                key: issued.api_key.id,
                creator: uid(1),
            }
        );
    }

    #[test]
    fn resolve_preserves_key_scope_narrower_than_creator() {
        // Owner (global) mints a key scoped to entity 1. The resolved authority is entity-scoped,
        // NOT widened to global.
        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();
        let issued = ApiKey::issue(
            &owner,
            &cat,
            &books(),
            ks(
                "scoped",
                ApiKeyGrant::perms([Permission::BookOpen], Scope::Entity(ent(1))),
            ),
        )
        .unwrap();
        let principal = resolve(&issued.api_key, &owner, &cat, t0(), &books());
        assert!(has_permission(
            &principal.effective_permissions,
            Permission::BookOpen,
            Scope::Entity(ent(1)),
            &books()
        ));
        // Not global.
        assert!(!has_permission(
            &principal.effective_permissions,
            Permission::BookOpen,
            Scope::Global,
            &books()
        ));
    }

    #[test]
    fn expired_or_revoked_key_resolves_to_no_permissions() {
        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();
        let issued = ApiKey::issue(
            &owner,
            &cat,
            &books(),
            KeySpec {
                expires_at: Some(t0() + Duration::hours(1)),
                ..ks("k", ApiKeyGrant::role(GESTOR_ROLE_ID, Scope::Global))
            },
        )
        .unwrap();

        // Expired.
        let expired = resolve(
            &issued.api_key,
            &owner,
            &cat,
            t0() + Duration::hours(2),
            &books(),
        );
        assert!(expired.effective_permissions.is_empty());
        assert!(!has_permission(
            &expired.effective_permissions,
            Permission::EntityRead,
            Scope::Global,
            &books()
        ));

        // Revoked.
        let mut revoked_key = issued.api_key.clone();
        revoked_key.revoked = true;
        let revoked = resolve(&revoked_key, &owner, &cat, t0(), &books());
        assert!(revoked.effective_permissions.is_empty());
    }

    #[test]
    fn resolve_auto_attenuates_when_creator_is_downgraded() {
        // Key granted Gestor@Global by an Owner. Later the creator is downgraded to Leitor.
        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();
        let issued = ApiKey::issue(
            &owner,
            &cat,
            &books(),
            ks("k", ApiKeyGrant::role(GESTOR_ROLE_ID, Scope::Global)),
        )
        .unwrap();

        // Creator now holds only Leitor.
        let downgraded = eff_of(LEITOR_ROLE_ID, Scope::Global);
        let principal = resolve(&issued.api_key, &downgraded, &cat, t0(), &books());
        // Write perms the creator no longer has are gone...
        assert!(!has_permission(
            &principal.effective_permissions,
            Permission::BookOpen,
            Scope::Global,
            &books()
        ));
        // ...but reads still within the creator's (Leitor) authority remain.
        assert!(has_permission(
            &principal.effective_permissions,
            Permission::EntityRead,
            Scope::Global,
            &books()
        ));
    }

    #[test]
    fn resolve_with_gone_creator_is_fail_closed() {
        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();
        let issued = ApiKey::issue(
            &owner,
            &cat,
            &books(),
            ks("k", ApiKeyGrant::role(GESTOR_ROLE_ID, Scope::Global)),
        )
        .unwrap();
        // The API passes an empty set when the creator is deactivated/deleted.
        let principal = resolve(
            &issued.api_key,
            &ScopedPermissionSet::new(),
            &cat,
            t0(),
            &books(),
        );
        assert!(principal.effective_permissions.is_empty());
    }

    #[test]
    fn resolve_strips_meta_even_if_a_key_was_hand_edited_to_hold_one() {
        // Defence in depth: a key persisted (e.g. by tampering) with a meta perm still resolves
        // without it. Owner authority covers role.manage, so only the meta-strip removes it.
        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let cat = RoleCatalog::seeded_defaults();
        let NewApiKey { mut api_key, .. } = ApiKey::generate(ks(
            "tampered",
            ApiKeyGrant::perms(
                [Permission::RoleManage, Permission::EntityRead],
                Scope::Global,
            ),
        ));
        api_key.revoked = false;
        let principal = resolve(&api_key, &owner, &cat, t0(), &books());
        assert!(!has_permission(
            &principal.effective_permissions,
            Permission::RoleManage,
            Scope::Global,
            &books()
        ));
        // The non-meta perm survives.
        assert!(has_permission(
            &principal.effective_permissions,
            Permission::EntityRead,
            Scope::Global,
            &books()
        ));
    }

    // ---- ESCALATION BATTERY (every attempt to mint/resolve excess authority is DENIED) -----

    #[test]
    fn escalation_battery_all_denied() {
        let cat = RoleCatalog::seeded_defaults();
        // Attacker: a Gestor (broad, not Owner) trying to mint a key beyond themselves.
        let attacker = eff_of(GESTOR_ROLE_ID, Scope::Global);
        let r = books();

        // 1. Mint a key holding a permission the attacker lacks (data.wipe / ledger.recover / user.manage).
        for p in [
            Permission::DataWipe,
            Permission::LedgerRecover,
            Permission::UserManage,
            Permission::DataStartOver,
        ] {
            assert!(!can_create_key(
                &attacker,
                &ApiKeyGrant::perms([p], Scope::Global),
                &cat,
                &r
            ));
        }

        // 2. Mint an Owner-role key (privilege grab via a fat role).
        assert!(!can_create_key(
            &attacker,
            &ApiKeyGrant::role(OWNER_ROLE_ID, Scope::Global),
            &cat,
            &r
        ));

        // 3. Mint a key holding any meta-permission (even if the attacker somehow held it).
        for meta in Permission::META {
            assert!(!can_create_key(
                &attacker,
                &ApiKeyGrant::perms([meta], Scope::Global),
                &cat,
                &r
            ));
        }

        // 4. Scope-escape: a creator scoped to entity 1 mints a GLOBAL key of a perm they hold only
        //    within entity 1.
        let scoped = eff_of(GESTOR_ROLE_ID, Scope::Entity(ent(1)));
        assert!(!can_create_key(
            &scoped,
            &ApiKeyGrant::perms([Permission::BookOpen], Scope::Global),
            &cat,
            &r
        ));
        // ...or a cross-entity key.
        assert!(!can_create_key(
            &scoped,
            &ApiKeyGrant::perms([Permission::BookOpen], Scope::Entity(ent(2))),
            &cat,
            &r
        ));

        // 5. Even if such a key existed, resolve() bounds it to the creator: a Gestor-authority
        //    creator resolving a (hand-crafted) key that claims data.wipe yields no data.wipe.
        let NewApiKey { api_key, .. } = ApiKey::generate(KeySpec {
            created_by: uid(7),
            ..ks(
                "crafted",
                ApiKeyGrant::perms([Permission::DataWipe], Scope::Global),
            )
        });
        let principal = resolve(&api_key, &attacker, &cat, t0(), &r);
        assert!(!has_permission(
            &principal.effective_permissions,
            Permission::DataWipe,
            Scope::Global,
            &r
        ));

        // 6. A key issued with a global grant never satisfies a check the creator can't (scope stays
        //    bounded): scoped creator ⇒ resolved key is scoped, never global.
        let issued = ApiKey::issue(
            &scoped,
            &cat,
            &r,
            KeySpec {
                created_by: uid(8),
                ..ks(
                    "k",
                    ApiKeyGrant::perms([Permission::BookOpen], Scope::Entity(ent(1))),
                )
            },
        )
        .unwrap();
        let p = resolve(&issued.api_key, &scoped, &cat, t0(), &r);
        assert!(!has_permission(
            &p.effective_permissions,
            Permission::BookOpen,
            Scope::Global,
            &r
        ));
        assert!(has_permission(
            &p.effective_permissions,
            Permission::BookOpen,
            Scope::Entity(ent(1)),
            &r
        ));
    }

    #[test]
    fn session_principal_and_key_principal_share_the_permission_shape() {
        // A session user with Signatário@Global and a key granted Signatário@Global resolve to
        // permission-sets that answer has_permission identically — the uniform-gate guarantee.
        let cat = RoleCatalog::seeded_defaults();
        let session_eff = eff_of(SIGNATARIO_ROLE_ID, Scope::Global);
        let session = RequestPrincipal::for_session(uid(5), "amelia.marques".into(), session_eff);

        let owner = eff_of(OWNER_ROLE_ID, Scope::Global);
        let issued = ApiKey::issue(
            &owner,
            &cat,
            &NoBooks,
            ks("k", ApiKeyGrant::role(SIGNATARIO_ROLE_ID, Scope::Global)),
        )
        .unwrap();
        let key_principal = resolve(&issued.api_key, &owner, &cat, t0(), &NoBooks);

        for p in Permission::ALL {
            assert_eq!(
                has_permission(&session.effective_permissions, p, Scope::Global, &NoBooks),
                has_permission(
                    &key_principal.effective_permissions,
                    p,
                    Scope::Global,
                    &NoBooks
                ),
                "divergence at {p}"
            );
        }
    }
}
