//! Opt-in zero-knowledge repository contracts (ARC-30..33 / SCP-D3).
//!
//! This crate deliberately contains no content encryption or server-side unwrapping operation.
//! Encryption, CEK generation, key derivation, unwrapping, and readability-package assembly happen
//! inside a trusted client. The server persists only [`OpaqueBlobManifest`] values, opaque bytes,
//! encrypted metadata envelopes, and recipient-wrapped CEKs. `deny_unknown_fields` on every wire
//! object makes accidental `plaintext`, raw `cek`, private-key, or recovery-share fields fail
//! closed instead of being silently retained.
//!
//! The client contract is AES-256-GCM with a fresh 96-bit nonce per CEK and object version. The
//! canonical associated data from [`AssociatedData::canonical_bytes`] binds ciphertext to the
//! repository, logical object, and immutable version. Key slots support BYOK, WebAuthn PRF backed
//! unsealing, and split-key continuity without putting an unwrapped key or recovery share here.

use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// Current, deliberately explicit manifest schema.
pub const MANIFEST_SCHEMA_VERSION: u16 = 1;
/// AES-GCM's recommended nonce width. A nonce must never repeat for the same key.
pub const AES_GCM_NONCE_LEN: usize = 12;
const SHA256_HEX_LEN: usize = 64;
const MAX_ENVELOPE_BYTES: usize = 1_048_576;
const MAX_WRAPPED_KEY_BYTES: usize = 16_384;
const MAX_KEY_SLOTS: usize = 64;
const MAX_LABEL_BYTES: usize = 256;

macro_rules! uuid_id {
    ($name:ident) => {
        #[doc = concat!("Opaque ", stringify!($name), " UUID.")]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

uuid_id!(RepositoryId);
uuid_id!(ObjectId);
uuid_id!(KeySlotId);
uuid_id!(ReadabilityTransferId);

/// Whether a repository uses ordinary server-managed storage or the opt-in ZK boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryEncryptionMode {
    Standard,
    ZeroKnowledge,
}

/// Scope at which an operator opted into ZK. Repository mode is the recommended default; tenant
/// mode is available where every repository in an isolated tenant must inherit the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ZeroKnowledgeScope {
    Tenant { tenant_id: Uuid },
    Repository { repository_id: RepositoryId },
}

/// Public, non-secret repository policy. It records the trust boundary and custody capabilities;
/// it never carries a key, PIN, WebAuthn PRF output, or recovery share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPolicy {
    pub repository_id: RepositoryId,
    pub tenant_id: Uuid,
    pub name: String,
    pub encryption_mode: RepositoryEncryptionMode,
    pub zk_scope: Option<ZeroKnowledgeScope>,
    pub custody: KeyCustodyPolicy,
    /// This is intentionally required to remain true (ARC-33 / LEG-13).
    pub gdpr_obligations_remain: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl RepositoryPolicy {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_label("repository name", &self.name)?;
        if !self.gdpr_obligations_remain {
            return Err(ContractError::GdprOverclaim);
        }
        match (self.encryption_mode, self.zk_scope) {
            (RepositoryEncryptionMode::Standard, None) => {}
            (
                RepositoryEncryptionMode::ZeroKnowledge,
                Some(ZeroKnowledgeScope::Repository { repository_id }),
            ) if repository_id == self.repository_id => {}
            (
                RepositoryEncryptionMode::ZeroKnowledge,
                Some(ZeroKnowledgeScope::Tenant { tenant_id }),
            ) if tenant_id == self.tenant_id => {}
            _ => return Err(ContractError::ScopePolicyMismatch),
        }
        self.custody.validate(self.encryption_mode)
    }
}

/// Supported key-custody and continuity mechanisms. Multiple methods may be enabled so a tenant
/// can, for example, use hardware-backed daily unsealing and a threshold recovery plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCustodyPolicy {
    pub bring_your_own_key: bool,
    pub webauthn_prf_unsealing: bool,
    pub split_key_recovery: Option<SplitKeyRecoveryPolicy>,
}

impl KeyCustodyPolicy {
    fn validate(&self, mode: RepositoryEncryptionMode) -> Result<(), ContractError> {
        if let Some(split) = &self.split_key_recovery {
            split.validate()?;
        }
        if mode == RepositoryEncryptionMode::ZeroKnowledge
            && !self.bring_your_own_key
            && !self.webauthn_prf_unsealing
            && self.split_key_recovery.is_none()
        {
            return Err(ContractError::NoCustodyMethod);
        }
        Ok(())
    }
}

/// Threshold metadata only. Actual shares are created and held by trusted clients/custodians and
/// are structurally absent from every server wire type in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitKeyRecoveryPolicy {
    pub threshold: u8,
    pub share_count: u8,
    /// Human-readable custodian labels, not secrets or share values.
    pub custodian_labels: Vec<String>,
}

impl SplitKeyRecoveryPolicy {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.threshold < 2
            || self.share_count < self.threshold
            || usize::from(self.share_count) != self.custodian_labels.len()
        {
            return Err(ContractError::InvalidRecoveryThreshold);
        }
        let mut labels = HashSet::new();
        for label in &self.custodian_labels {
            validate_label("custodian label", label)?;
            if !labels.insert(label.trim().to_lowercase()) {
                return Err(ContractError::DuplicateCustodian);
            }
        }
        Ok(())
    }
}

/// AEAD suite understood by the client/server manifest boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentEncryptionAlgorithm {
    Aes256Gcm,
}

/// Stable associated data. Its canonical bytes are authenticated by AES-GCM but remain public.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociatedData {
    pub repository_id: RepositoryId,
    pub object_id: ObjectId,
    pub version: u64,
}

impl AssociatedData {
    /// Cross-language canonical form. UUIDs are lower-case hyphenated ASCII and fields are joined
    /// with NUL delimiters to avoid concatenation ambiguity:
    /// `chancela-zk-v1\0<repository>\0<object>\0<decimal-version>`.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        format!(
            "chancela-zk-v1\0{}\0{}\0{}",
            self.repository_id, self.object_id, self.version
        )
        .into_bytes()
    }
}

/// An opaque, encrypted metadata envelope. The optional metadata that supports search/preview in a
/// standard repository is intentionally unavailable to a ZK server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedMetadataEnvelope {
    pub algorithm: ContentEncryptionAlgorithm,
    pub nonce_base64: String,
    pub ciphertext_base64: String,
    pub ciphertext_sha256: String,
}

impl EncryptedMetadataEnvelope {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_nonce(&self.nonce_base64)?;
        let ciphertext = decode_bounded(
            "encrypted metadata",
            &self.ciphertext_base64,
            MAX_ENVELOPE_BYTES,
        )?;
        if ciphertext.is_empty() {
            return Err(ContractError::EmptyCiphertext);
        }
        validate_digest(&self.ciphertext_sha256, &ciphertext)
    }
}

/// How a trusted client wrapped one object's random 256-bit CEK. These values identify algorithms;
/// no variant accepts the derived KEK, WebAuthn PRF output, hardware PIN, or raw recovery key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyWrappingAlgorithm {
    Aes256KwByok,
    HkdfSha256Aes256KwWebauthnPrf,
    Aes256KwSplitRecovery,
    RsaOaepSha256Recipient,
}

/// Non-secret recipient classification used for policy and UI display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRecipientKind {
    BringYourOwnKey,
    WebauthnCredential,
    SplitRecoveryPlan,
    ExternalRecipient,
}

/// A client-produced wrapped CEK. `key_reference` is a public fingerprint/credential reference,
/// never key material. `wrapped_cek_base64` must contain ciphertext only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedContentEncryptionKey {
    pub slot_id: KeySlotId,
    pub recipient_kind: KeyRecipientKind,
    pub recipient_id: String,
    pub algorithm: KeyWrappingAlgorithm,
    pub key_reference: String,
    pub wrapped_cek_base64: String,
    pub created_at: OffsetDateTime,
}

impl WrappedContentEncryptionKey {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_label("recipient id", &self.recipient_id)?;
        validate_label("key reference", &self.key_reference)?;
        let wrapped = decode_bounded(
            "wrapped CEK",
            &self.wrapped_cek_base64,
            MAX_WRAPPED_KEY_BYTES,
        )?;
        if wrapped.len() < 24 {
            return Err(ContractError::WrappedKeyTooShort);
        }
        let pair_is_valid = matches!(
            (self.recipient_kind, self.algorithm),
            (
                KeyRecipientKind::BringYourOwnKey,
                KeyWrappingAlgorithm::Aes256KwByok
            ) | (
                KeyRecipientKind::WebauthnCredential,
                KeyWrappingAlgorithm::HkdfSha256Aes256KwWebauthnPrf
            ) | (
                KeyRecipientKind::SplitRecoveryPlan,
                KeyWrappingAlgorithm::Aes256KwSplitRecovery
            ) | (
                KeyRecipientKind::ExternalRecipient,
                KeyWrappingAlgorithm::RsaOaepSha256Recipient
            )
        );
        if !pair_is_valid {
            return Err(ContractError::RecipientAlgorithmMismatch);
        }
        Ok(())
    }
}

/// Server-stored manifest for one immutable ciphertext version. Blob bytes travel separately and
/// are verified against `ciphertext_sha256` before commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueBlobManifest {
    pub schema_version: u16,
    pub associated_data: AssociatedData,
    pub algorithm: ContentEncryptionAlgorithm,
    pub nonce_base64: String,
    pub ciphertext_sha256: String,
    pub ciphertext_len: u64,
    pub encrypted_metadata: Option<EncryptedMetadataEnvelope>,
    pub wrapped_keys: Vec<WrappedContentEncryptionKey>,
    pub created_at: OffsetDateTime,
}

impl OpaqueBlobManifest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedSchema(self.schema_version));
        }
        if self.associated_data.version == 0 {
            return Err(ContractError::ZeroObjectVersion);
        }
        validate_nonce(&self.nonce_base64)?;
        validate_digest_syntax(&self.ciphertext_sha256)?;
        if self.ciphertext_len == 0 {
            return Err(ContractError::EmptyCiphertext);
        }
        if let Some(metadata) = &self.encrypted_metadata {
            metadata.validate()?;
        }
        if self.wrapped_keys.is_empty() || self.wrapped_keys.len() > MAX_KEY_SLOTS {
            return Err(ContractError::InvalidKeySlotCount);
        }
        let mut slots = HashSet::new();
        let mut recipients = HashSet::new();
        for key in &self.wrapped_keys {
            key.validate()?;
            if !slots.insert(key.slot_id) {
                return Err(ContractError::DuplicateKeySlot);
            }
            if !recipients.insert((key.recipient_kind, key.recipient_id.trim().to_lowercase())) {
                return Err(ContractError::DuplicateRecipient);
            }
        }
        Ok(())
    }

    /// Verify the separately uploaded opaque bytes before an atomic commit.
    pub fn verify_ciphertext(&self, ciphertext: &[u8]) -> Result<(), ContractError> {
        self.validate()?;
        if u64::try_from(ciphertext.len()).ok() != Some(self.ciphertext_len) {
            return Err(ContractError::CiphertextLengthMismatch);
        }
        validate_digest(&self.ciphertext_sha256, ciphertext)
    }
}

/// Reject nonce reuse within one CEK/key reference. Call this against every existing manifest in
/// the repository transaction before accepting a new object version.
pub fn ensure_nonce_is_unique<'a>(
    candidate: &OpaqueBlobManifest,
    existing: impl IntoIterator<Item = &'a OpaqueBlobManifest>,
) -> Result<(), ContractError> {
    candidate.validate()?;
    let candidate_refs: HashSet<&str> = candidate
        .wrapped_keys
        .iter()
        .map(|slot| slot.key_reference.as_str())
        .collect();
    for manifest in existing {
        if manifest.nonce_base64 == candidate.nonce_base64
            && manifest
                .wrapped_keys
                .iter()
                .any(|slot| candidate_refs.contains(slot.key_reference.as_str()))
        {
            return Err(ContractError::NonceReuse);
        }
    }
    Ok(())
}

/// Readability transfer produced inside a trusted client (ARC-32). A client may either decrypt the
/// legal archive before handoff, or attach a portable *encrypted* key package plus documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadabilityDeliveryMode {
    ClientDecryptedArchive,
    EncryptedArchiveWithPortableKeyPackage,
}

/// Portable encrypted decryption material. The recipient passphrase/private key is exchanged out of
/// band; this package never contains it in plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableEncryptedKeyPackage {
    pub format: String,
    pub algorithm: String,
    pub encrypted_material_base64: String,
    pub material_sha256: String,
    pub recipient_instructions: String,
}

impl PortableEncryptedKeyPackage {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_label("key package format", &self.format)?;
        validate_label("key package algorithm", &self.algorithm)?;
        validate_label("recipient instructions", &self.recipient_instructions)?;
        let bytes = decode_bounded(
            "portable key package",
            &self.encrypted_material_base64,
            MAX_ENVELOPE_BYTES,
        )?;
        if bytes.is_empty() {
            return Err(ContractError::EmptyCiphertext);
        }
        validate_digest(&self.material_sha256, &bytes)
    }
}

/// Portable handoff manifest. `gdpr_obligations_remain` is a required true invariant and
/// `legal_archive_certified` is a required false no-overclaim invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadabilityTransferManifest {
    pub transfer_id: ReadabilityTransferId,
    pub repository_id: RepositoryId,
    pub mode: ReadabilityDeliveryMode,
    pub archive_sha256: String,
    pub archive_format: String,
    pub documentation_profile: String,
    pub portable_key_package: Option<PortableEncryptedKeyPackage>,
    pub gdpr_obligations_remain: bool,
    pub legal_archive_certified: bool,
    pub created_at: OffsetDateTime,
}

impl ReadabilityTransferManifest {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_digest_syntax(&self.archive_sha256)?;
        validate_label("archive format", &self.archive_format)?;
        validate_label("documentation profile", &self.documentation_profile)?;
        if !self.gdpr_obligations_remain {
            return Err(ContractError::GdprOverclaim);
        }
        if self.legal_archive_certified {
            return Err(ContractError::LegalArchiveOverclaim);
        }
        match (self.mode, &self.portable_key_package) {
            (ReadabilityDeliveryMode::ClientDecryptedArchive, None) => Ok(()),
            (ReadabilityDeliveryMode::EncryptedArchiveWithPortableKeyPackage, Some(package)) => {
                package.validate()
            }
            _ => Err(ContractError::ReadabilityModeMismatch),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContractError {
    #[error("unsupported ZK manifest schema version {0}")]
    UnsupportedSchema(u16),
    #[error("repository scope and encryption policy do not match")]
    ScopePolicyMismatch,
    #[error("a zero-knowledge repository needs at least one custody method")]
    NoCustodyMethod,
    #[error("GDPR obligations must remain explicitly acknowledged")]
    GdprOverclaim,
    #[error("this transfer cannot claim legal-archive certification")]
    LegalArchiveOverclaim,
    #[error("invalid split-key threshold/share count")]
    InvalidRecoveryThreshold,
    #[error("duplicate split-key custodian label")]
    DuplicateCustodian,
    #[error("{0} is empty or exceeds the bounded wire length")]
    InvalidLabel(&'static str),
    #[error("{0} is not valid bounded base64")]
    InvalidBase64(&'static str),
    #[error("AES-256-GCM nonce must decode to exactly 12 bytes")]
    InvalidNonce,
    #[error("SHA-256 digest must be 64 lower-case hexadecimal characters")]
    InvalidDigest,
    #[error("declared SHA-256 digest does not match opaque bytes")]
    DigestMismatch,
    #[error("ciphertext cannot be empty")]
    EmptyCiphertext,
    #[error("object version zero is reserved")]
    ZeroObjectVersion,
    #[error("wrapped key is too short for the declared wrapping algorithm")]
    WrappedKeyTooShort,
    #[error("recipient kind and key-wrapping algorithm do not match")]
    RecipientAlgorithmMismatch,
    #[error("a manifest must have between one and 64 key slots")]
    InvalidKeySlotCount,
    #[error("duplicate key slot id")]
    DuplicateKeySlot,
    #[error("duplicate key recipient")]
    DuplicateRecipient,
    #[error("ciphertext byte length does not match manifest")]
    CiphertextLengthMismatch,
    #[error("nonce reuse detected for the same key reference")]
    NonceReuse,
    #[error("readability delivery mode and key package do not match")]
    ReadabilityModeMismatch,
}

fn validate_label(name: &'static str, value: &str) -> Result<(), ContractError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_LABEL_BYTES || trimmed.contains('\0') {
        Err(ContractError::InvalidLabel(name))
    } else {
        Ok(())
    }
}

fn decode_bounded(
    name: &'static str,
    value: &str,
    max_decoded_len: usize,
) -> Result<Vec<u8>, ContractError> {
    if value.len() > max_decoded_len.saturating_mul(2) {
        return Err(ContractError::InvalidBase64(name));
    }
    let decoded = BASE64
        .decode(value)
        .map_err(|_| ContractError::InvalidBase64(name))?;
    if decoded.len() > max_decoded_len {
        return Err(ContractError::InvalidBase64(name));
    }
    Ok(decoded)
}

fn validate_nonce(value: &str) -> Result<(), ContractError> {
    let nonce = decode_bounded("nonce", value, AES_GCM_NONCE_LEN)?;
    if nonce.len() == AES_GCM_NONCE_LEN {
        Ok(())
    } else {
        Err(ContractError::InvalidNonce)
    }
}

fn validate_digest_syntax(value: &str) -> Result<(), ContractError> {
    if value.len() == SHA256_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ContractError::InvalidDigest)
    }
}

fn validate_digest(expected: &str, bytes: &[u8]) -> Result<(), ContractError> {
    validate_digest_syntax(expected)?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual == expected {
        Ok(())
    } else {
        Err(ContractError::DigestMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn wrapped_key(reference: &str) -> WrappedContentEncryptionKey {
        WrappedContentEncryptionKey {
            slot_id: KeySlotId::new(),
            recipient_kind: KeyRecipientKind::BringYourOwnKey,
            recipient_id: "primary-owner".to_owned(),
            algorithm: KeyWrappingAlgorithm::Aes256KwByok,
            key_reference: reference.to_owned(),
            wrapped_cek_base64: BASE64.encode([7_u8; 40]),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn manifest(ciphertext: &[u8], nonce: [u8; AES_GCM_NONCE_LEN]) -> OpaqueBlobManifest {
        OpaqueBlobManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            associated_data: AssociatedData {
                repository_id: RepositoryId(Uuid::from_u128(1)),
                object_id: ObjectId(Uuid::from_u128(2)),
                version: 1,
            },
            algorithm: ContentEncryptionAlgorithm::Aes256Gcm,
            nonce_base64: BASE64.encode(nonce),
            ciphertext_sha256: digest(ciphertext),
            ciphertext_len: ciphertext.len() as u64,
            encrypted_metadata: None,
            wrapped_keys: vec![wrapped_key("sha256:owner-key")],
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn opaque_manifest_verifies_bytes_and_canonical_aad() {
        let ciphertext = b"opaque bytes, never plaintext";
        let manifest = manifest(ciphertext, [1; AES_GCM_NONCE_LEN]);
        manifest.verify_ciphertext(ciphertext).unwrap();
        assert_eq!(
            manifest.associated_data.canonical_bytes(),
            b"chancela-zk-v1\x0000000000-0000-0000-0000-000000000001\x0000000000-0000-0000-0000-000000000002\x001"
        );
        assert_eq!(
            manifest.verify_ciphertext(b"tampered"),
            Err(ContractError::CiphertextLengthMismatch)
        );
    }

    #[test]
    fn wire_contract_rejects_plaintext_and_raw_secret_fields() {
        let value = serde_json::to_value(manifest(b"ciphertext", [2; AES_GCM_NONCE_LEN])).unwrap();
        for field in ["plaintext", "cek", "private_key", "recovery_share"] {
            let mut injected = value.clone();
            injected
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), json!("must-not-be-stored"));
            assert!(
                serde_json::from_value::<OpaqueBlobManifest>(injected).is_err(),
                "{field} must fail closed"
            );
        }

        let mut slot = serde_json::to_value(wrapped_key("sha256:k")).unwrap();
        slot.as_object_mut()
            .unwrap()
            .insert("unwrapped_cek".to_owned(), json!(vec![0; 32]));
        assert!(serde_json::from_value::<WrappedContentEncryptionKey>(slot).is_err());
    }

    #[test]
    fn nonce_reuse_is_rejected_for_same_key_reference() {
        let first = manifest(b"one", [3; AES_GCM_NONCE_LEN]);
        let mut second = manifest(b"two", [3; AES_GCM_NONCE_LEN]);
        second.associated_data.version = 2;
        assert_eq!(
            ensure_nonce_is_unique(&second, [&first]),
            Err(ContractError::NonceReuse)
        );
        second.wrapped_keys[0].key_reference = "sha256:different-key".to_owned();
        ensure_nonce_is_unique(&second, [&first]).unwrap();
    }

    #[test]
    fn zk_policy_requires_custody_and_permanent_gdpr_caveat() {
        let repository_id = RepositoryId::new();
        let tenant_id = Uuid::new_v4();
        let mut policy = RepositoryPolicy {
            repository_id,
            tenant_id,
            name: "Legal archive".to_owned(),
            encryption_mode: RepositoryEncryptionMode::ZeroKnowledge,
            zk_scope: Some(ZeroKnowledgeScope::Repository { repository_id }),
            custody: KeyCustodyPolicy {
                bring_your_own_key: true,
                webauthn_prf_unsealing: true,
                split_key_recovery: Some(SplitKeyRecoveryPolicy {
                    threshold: 2,
                    share_count: 3,
                    custodian_labels: vec![
                        "Records manager".to_owned(),
                        "Legal counsel".to_owned(),
                        "Board custodian".to_owned(),
                    ],
                }),
            },
            gdpr_obligations_remain: true,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        policy.validate().unwrap();
        policy.gdpr_obligations_remain = false;
        assert_eq!(policy.validate(), Err(ContractError::GdprOverclaim));
    }

    #[test]
    fn readability_transfer_requires_matching_encrypted_material_and_no_claims() {
        let encrypted_material = [9_u8; 64];
        let mut transfer = ReadabilityTransferManifest {
            transfer_id: ReadabilityTransferId::new(),
            repository_id: RepositoryId::new(),
            mode: ReadabilityDeliveryMode::EncryptedArchiveWithPortableKeyPackage,
            archive_sha256: digest(b"archive"),
            archive_format: "Chancela legal archive ZIP v1".to_owned(),
            documentation_profile: "chancela-zk-readability-v1".to_owned(),
            portable_key_package: Some(PortableEncryptedKeyPackage {
                format: "JWE compact".to_owned(),
                algorithm: "PBES2-HS512+A256KW / A256GCM".to_owned(),
                encrypted_material_base64: BASE64.encode(encrypted_material),
                material_sha256: digest(&encrypted_material),
                recipient_instructions: "Use the separately delivered recipient secret.".to_owned(),
            }),
            gdpr_obligations_remain: true,
            legal_archive_certified: false,
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        transfer.validate().unwrap();
        transfer.portable_key_package = None;
        assert_eq!(
            transfer.validate(),
            Err(ContractError::ReadabilityModeMismatch)
        );
        transfer.mode = ReadabilityDeliveryMode::ClientDecryptedArchive;
        transfer.legal_archive_certified = true;
        assert_eq!(
            transfer.validate(),
            Err(ContractError::LegalArchiveOverclaim)
        );
    }

    #[test]
    fn no_wire_type_serializes_secretish_field_names() {
        let samples: Vec<Value> = vec![
            serde_json::to_value(manifest(b"ciphertext", [4; AES_GCM_NONCE_LEN])).unwrap(),
            serde_json::to_value(wrapped_key("sha256:key")).unwrap(),
        ];
        for value in samples {
            let serialized = serde_json::to_string(&value).unwrap();
            for forbidden in ["plaintext", "private_key", "unwrapped", "recovery_share"] {
                assert!(
                    !serialized.contains(forbidden),
                    "leaked field name: {forbidden}"
                );
            }
        }
    }
}
