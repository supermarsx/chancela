//! The [`ApiKey`] model, key generation (shown once), and constant-time verification (t65 §3.1/E1-2).
//!
//! **Secret handling (the security core).** A key's plaintext is a high-entropy string
//! `chk_<prefix>_<secret>` (a 48-bit random prefix + a **256-bit** random secret, both hex). It is
//! returned **exactly once** at generation ([`ApiKey::issue`] → [`NewApiKey::plaintext`]) and is
//! **never stored**: only `sha256(plaintext)` is persisted ([`ApiKey::key_hash`]).
//!
//! **Why sha256, not argon2 (plan decision 8-D).** Argon2 exists to make *low-entropy* passwords
//! expensive to brute-force. An API key is 256 bits of CSPRNG output — brute force is already
//! infeasible, so a slow KDF buys nothing and would put an argon2 hash on the **hot, public,
//! unauthenticated** request path (a self-inflicted DoS). A single sha256 is the standard,
//! constant-work choice for verifying a high-entropy bearer token. Verification is a **constant-time**
//! comparison of the 32-byte digests so a timing side-channel cannot leak the stored hash.

use chancela_authz::UserId;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::grant::ApiKeyGrant;
use crate::hex;
use crate::ratelimit::RateLimit;

/// The human-facing tag that opens every Chancela key and its displayable prefix.
const KEY_TAG: &str = "chk";
/// Random bytes in the displayable prefix (48-bit id) and the secret (256-bit).
const PREFIX_BYTES: usize = 6;
const SECRET_BYTES: usize = 32;

/// Opaque identifier of an API key (uuid v4). Transparent UUID on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ApiKeyId(pub Uuid);

impl std::fmt::Display for ApiKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A persisted API key. **Contains no secret** — only the sha256 hash of the plaintext and the
/// displayable prefix. This is the durable shape (`apikeys.json`); the newer audit fields the API may
/// add (`last_used_at`, `revoked_at`, `revoked_by`) are additive `#[serde(default)]` and are omitted
/// from the frozen core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKey {
    /// Stable id.
    pub id: ApiKeyId,
    /// Operator label, e.g. `"Integração ERP Encosto Estratégico"`. Never the secret.
    pub name: String,
    /// The displayable, non-secret identifier — the leading `chk_<prefix>` of the plaintext. Shown in
    /// key lists and used to look a key up before verification. Safe to log.
    pub prefix: String,
    /// `sha256(plaintext)` as lowercase hex — the **only** stored form of the secret.
    pub key_hash: String,
    /// The authority this key confers (a role@scope or an explicit scoped permission set).
    pub principal_grant: ApiKeyGrant,
    /// The user who created the key. Its authority is the ceiling this key can never exceed
    /// (attenuation) and the audit trail of who minted it.
    pub created_by: UserId,
    /// When the key was created.
    pub created_at: OffsetDateTime,
    /// Optional expiry; `None` means "until revoked". Boundary-inclusive (see [`ApiKey::is_expired`]).
    #[serde(default)]
    pub expires_at: Option<OffsetDateTime>,
    /// Whether the key has been revoked. A revoked key resolves to **no** permissions.
    #[serde(default)]
    pub revoked: bool,
    /// Per-key rate-limit override; `None` = use the instance policy default.
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
}

/// A freshly generated key: the **shown-once** plaintext plus the persistable [`ApiKey`] (hash only).
/// The plaintext lives only here; drop it after displaying it to the operator.
#[derive(Debug, Clone)]
pub struct NewApiKey {
    /// The full secret `chk_<prefix>_<secret>`. Display **once**, never store, never log.
    pub plaintext: String,
    /// The record to persist — carries the hash, never the plaintext.
    pub api_key: ApiKey,
}

/// The operator-supplied fields of a key to be minted (everything except the generated id, prefix and
/// hash). Bundled so [`ApiKey::generate`]/[`ApiKey::issue`] take one descriptor instead of a long
/// positional argument list.
#[derive(Debug, Clone)]
pub struct KeySpec {
    /// Operator label. Never the secret.
    pub name: String,
    /// The authority the key confers.
    pub principal_grant: ApiKeyGrant,
    /// The creator whose authority bounds the key.
    pub created_by: UserId,
    /// Creation timestamp (caller-supplied — this crate holds no clock).
    pub created_at: OffsetDateTime,
    /// Optional expiry; `None` = until revoked.
    pub expires_at: Option<OffsetDateTime>,
    /// Per-key rate-limit override; `None` = instance policy default.
    pub rate_limit: Option<RateLimit>,
}

impl ApiKey {
    /// Generate a new key from `spec`. Produces a high-entropy plaintext via [`OsRng`], stores only
    /// its sha256 hash. This is the mechanical mint; it does **not** enforce attenuation — use
    /// [`ApiKey::issue`] (which does) on any path where a creator is granting authority. Exposed for
    /// callers that have already validated the grant.
    #[must_use]
    pub fn generate(spec: KeySpec) -> NewApiKey {
        let mut prefix_bytes = [0u8; PREFIX_BYTES];
        let mut secret_bytes = [0u8; SECRET_BYTES];
        OsRng.fill_bytes(&mut prefix_bytes);
        OsRng.fill_bytes(&mut secret_bytes);

        let prefix = format!("{KEY_TAG}_{}", hex::encode(&prefix_bytes));
        let plaintext = format!("{prefix}_{}", hex::encode(&secret_bytes));
        let key_hash = hex::encode(&sha256(plaintext.as_bytes()));

        let api_key = ApiKey {
            id: ApiKeyId(Uuid::new_v4()),
            name: spec.name,
            prefix,
            key_hash,
            principal_grant: spec.principal_grant,
            created_by: spec.created_by,
            created_at: spec.created_at,
            expires_at: spec.expires_at,
            revoked: false,
            rate_limit: spec.rate_limit,
        };
        NewApiKey { plaintext, api_key }
    }

    /// **Issue** a key under the attenuation invariant — the only sanctioned mint path. Fails
    /// (without generating anything) unless the grant satisfies [`crate::can_create_key`]: it must be
    /// non-empty, hold no meta-permission, and be **entirely within `creator_effective`**. This makes
    /// an over-powerful key *impossible to construct*, not merely rejected after the fact.
    ///
    /// `creator_effective` is the creator's *current* authority (the API computes it via
    /// `chancela_authz::effective_permissions`); `roles` resolves a role grant; `books` supplies the
    /// book→entity relation for scoped coverage.
    pub fn issue(
        creator_effective: &chancela_authz::ScopedPermissionSet,
        roles: &chancela_authz::RoleCatalog,
        books: &impl chancela_authz::BookScope,
        spec: KeySpec,
    ) -> Result<NewApiKey, IssueError> {
        let pairs = spec.principal_grant.grant_pairs(roles);
        if pairs.is_empty() {
            return Err(IssueError::EmptyGrant);
        }
        if pairs.iter().any(|&(p, _)| p.is_meta()) {
            return Err(IssueError::GrantContainsMeta);
        }
        if !pairs
            .iter()
            .all(|&(p, s)| chancela_authz::has_permission(creator_effective, p, s, books))
        {
            return Err(IssueError::GrantExceedsCreator);
        }
        Ok(Self::generate(spec))
    }

    /// Has this key expired at `now`? A key with no expiry never expires. Boundary-inclusive (at
    /// exactly `expires_at` the key is spent) — matching `chancela_authz::Delegation`.
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }

    /// Is this key currently usable? True iff **not revoked and not expired**. An inactive key
    /// resolves to no permissions (see [`crate::resolve`]).
    #[must_use]
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        !self.revoked && !self.is_expired(now)
    }

    /// The ledger actor label for this key: `apikey:<name>#<prefix>`. Contains no secret (the prefix
    /// is public), so it is safe to record in the audit chain and logs.
    #[must_use]
    pub fn actor_label(&self) -> String {
        format!("apikey:{}#{}", self.name, self.prefix)
    }

    /// Verify a presented plaintext against this key's stored hash, in **constant time**. Returns
    /// `false` for a wrong secret and for a malformed stored hash (fail-closed). Does **not** check
    /// expiry/revocation — that is [`ApiKey::is_active`]/[`crate::resolve`].
    #[must_use]
    pub fn verify(&self, presented: &str) -> bool {
        let Some(stored) = hex::decode_32(&self.key_hash) else {
            return false;
        };
        let digest = sha256(presented.as_bytes());
        ct_eq(&digest, &stored)
    }
}

/// Extract the displayable `chk_<prefix>` from a presented plaintext, for looking the key up before
/// verifying it (avoids verifying against every stored key). Returns `None` if the shape is wrong.
/// The prefix is non-secret, so this leaks nothing.
#[must_use]
pub fn extract_prefix(presented: &str) -> Option<&str> {
    let (prefix, secret) = presented.rsplit_once('_')?;
    let tag = format!("{KEY_TAG}_");
    if prefix.starts_with(&tag) && secret.len() == SECRET_BYTES * 2 {
        Some(prefix)
    } else {
        None
    }
}

/// Why a key could not be issued. Distinct reasons so the API can return an honest, specific error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError {
    /// The grant resolves to no permissions (empty permission set, or a role absent from the catalog).
    EmptyGrant,
    /// The grant includes a meta-permission (`role.*`/`delegation.*`). Keys never wield the RBAC
    /// machinery — an automated, long-lived credential must not be able to mint or move authority.
    GrantContainsMeta,
    /// Some permission in the grant is not within the creator's own effective authority (at scope).
    GrantExceedsCreator,
}

impl std::fmt::Display for IssueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            IssueError::EmptyGrant => "the grant confers no permissions",
            IssueError::GrantContainsMeta => "an API key may not hold a meta-permission",
            IssueError::GrantExceedsCreator => {
                "the grant exceeds the creator's own effective permissions"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for IssueError {}

/// sha256 of `data`, as a 32-byte digest.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Constant-time equality over two 32-byte digests: always inspects all 32 bytes (no data-dependent
/// early exit), so it leaks no timing information about how many leading bytes matched.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_authz::Scope;

    fn uid(n: u128) -> UserId {
        UserId(Uuid::from_u128(n))
    }
    fn t0() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }
    fn a_grant() -> ApiKeyGrant {
        ApiKeyGrant::perms([chancela_authz::Permission::EntityRead], Scope::Global)
    }
    fn spec(name: &str) -> KeySpec {
        KeySpec {
            name: name.into(),
            principal_grant: a_grant(),
            created_by: uid(1),
            created_at: t0(),
            expires_at: None,
            rate_limit: None,
        }
    }

    #[test]
    fn generate_never_stores_the_plaintext_and_hash_matches() {
        let NewApiKey { plaintext, api_key } = ApiKey::generate(spec("k"));
        // The plaintext is high-entropy and prefixed.
        assert!(plaintext.starts_with("chk_"));
        // The stored record contains neither the plaintext nor the secret half.
        let secret_half = plaintext.rsplit_once('_').unwrap().1;
        let serialized = serde_json::to_string(&api_key).unwrap();
        assert!(!serialized.contains(&plaintext));
        assert!(!serialized.contains(secret_half));
        // The stored hash equals sha256(plaintext).
        assert_eq!(api_key.key_hash, hex::encode(&sha256(plaintext.as_bytes())));
        assert_eq!(api_key.key_hash.len(), 64);
    }

    #[test]
    fn each_key_is_unique_and_unguessable() {
        let a = ApiKey::generate(spec("k"));
        let b = ApiKey::generate(spec("k"));
        assert_ne!(a.plaintext, b.plaintext);
        assert_ne!(a.api_key.prefix, b.api_key.prefix);
        assert_ne!(a.api_key.key_hash, b.api_key.key_hash);
        // 256-bit secret ⇒ 64 hex chars in the secret half.
        assert_eq!(a.plaintext.rsplit_once('_').unwrap().1.len(), 64);
    }

    #[test]
    fn verify_true_for_the_right_secret_false_otherwise() {
        let NewApiKey { plaintext, api_key } = ApiKey::generate(spec("k"));
        assert!(api_key.verify(&plaintext));
        assert!(!api_key.verify(&format!("{plaintext}x")));
        assert!(!api_key.verify("chk_deadbeef_0000"));
        assert!(!api_key.verify(""));
    }

    #[test]
    fn verify_fails_closed_on_malformed_stored_hash() {
        let NewApiKey {
            plaintext,
            mut api_key,
        } = ApiKey::generate(spec("k"));
        api_key.key_hash = "not-hex".into();
        assert!(!api_key.verify(&plaintext));
    }

    #[test]
    fn ct_eq_is_symmetric_and_correct() {
        let a = [7u8; 32];
        let mut b = [7u8; 32];
        assert!(ct_eq(&a, &b));
        b[31] = 8;
        assert!(!ct_eq(&a, &b));
        b[31] = 7;
        b[0] = 9; // difference in the first byte still detected (no early exit)
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn extract_prefix_recovers_the_lookup_key() {
        let NewApiKey { plaintext, api_key } = ApiKey::generate(spec("k"));
        assert_eq!(extract_prefix(&plaintext), Some(api_key.prefix.as_str()));
        assert_eq!(extract_prefix("garbage"), None);
        assert_eq!(extract_prefix("chk_abc_short"), None);
    }

    #[test]
    fn expiry_and_revocation_gate_activity() {
        let NewApiKey { mut api_key, .. } = ApiKey::generate(KeySpec {
            expires_at: Some(t0() + time::Duration::hours(1)),
            ..spec("k")
        });
        assert!(api_key.is_active(t0()));
        // Boundary is inclusive: at exactly expiry the key is spent.
        assert!(!api_key.is_active(t0() + time::Duration::hours(1)));
        assert!(api_key.is_expired(t0() + time::Duration::hours(2)));
        // Revocation overrides an un-expired key.
        api_key.expires_at = None;
        api_key.revoked = true;
        assert!(!api_key.is_active(t0()));
    }

    #[test]
    fn actor_label_carries_no_secret() {
        let NewApiKey { plaintext, api_key } =
            ApiKey::generate(spec("Integração ERP Encosto Estratégico"));
        let label = api_key.actor_label();
        assert!(label.starts_with("apikey:Integração ERP Encosto Estratégico#chk_"));
        let secret_half = plaintext.rsplit_once('_').unwrap().1;
        assert!(!label.contains(secret_half));
    }
}
