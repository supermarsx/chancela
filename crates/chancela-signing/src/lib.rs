//! `chancela-signing` — signature orchestration middleware (spec 04).
//!
//! This crate is the orchestration layer of the signature subsystem. It keeps the load-bearing
//! *vocabulary* the product must speak — the four signing families, signature formats, baseline
//! profiles, evidentiary labelling, envelopes, and trusted-list status — and wires the concrete
//! integrations behind it into working pipelines:
//!
//! - [`SignerProvider`] abstracts a signing device/service. [`SmartcardProvider`] wraps a
//!   `chancela-smartcard` [`CryptoToken`](chancela_smartcard::CryptoToken) (Cartão de Cidadão),
//!   [`CmdProvider`] wraps a `chancela-cmd` [`ScmdClient`](chancela_cmd::ScmdClient) (Chave Móvel
//!   Digital), and [`MockProvider`] drives offline tests.
//! - The [`pipeline`] builds detached CAdES-B (via `chancela-cades`) or PAdES-B (via
//!   `chancela-pades`) from a provider's [`RawSignature`], with an optional qualified timestamp
//!   (via `chancela-tsa`).
//! - The [`policy`] gate consults the Portuguese Trusted List (via `chancela-tsl`) before a
//!   qualified signature is trusted (SIG-11/23), rejecting withdrawn/unknown issuers.
//! - The [`envelope`] engine drives serial and parallel multi-signatory collection (SIG-31).
//! - [`validate_signature`] produces a signature-validation report (SIG-24).
//!
//! The evidentiary labelling here is load-bearing, not cosmetic: Portuguese/eIDAS law attaches
//! presumptions to a *qualified electronic signature*, and the product must never misrepresent a
//! weaker artifact as one (SIG-01/02/03). In particular the Chave Móvel Digital OTP is a
//! confirmation step *inside* the qualified flow — labelled [`EvidentiaryLevel::OtpConfirmation`]
//! — and is never produced as a signature artifact (SIG-02).

#![forbid(unsafe_code)]
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

pub mod cc;
pub mod cmd_session;
pub mod envelope;
pub mod mock;
pub mod pipeline;
pub mod policy;
pub mod provider;
pub mod remote;
pub mod validate;

pub use cc::{CcSignedPdf, sign_pdf_cc};
pub use cmd_session::{
    CMD_PROVIDER_ID, CmdInitiate, CmdRemoteSource, CmdSignSession, cmd_confirm, cmd_initiate,
};
pub use envelope::{
    DocumentInput, SigningJob, is_complete, pending_slots, record_manual_signature, sign_slot,
};
pub use mock::MockProvider;
pub use pipeline::{TimestampProvider, sign_detached_cades, sign_pdf_pades};
pub use policy::{StaticTrustPolicy, TrustPolicy, TslTrustPolicy};
pub use provider::{CmdProvider, SignerProvider, SmartcardProvider};
pub use remote::{RemoteInitiate, RemoteSignSession, RemoteSigningSource};
pub use validate::{SignatureValidationReport, validate_signature};

// Re-export the pieces of the underlying stack callers most often name through this crate.
pub use chancela_cades::{RawSignature, SignatureAlgorithm};
pub use chancela_pades::{PreparedSignature, SignOptions, embed_signature, prepare_signature};
pub use chancela_tsa::{Timestamp, TsaClient};

/// The four signing families the product MUST natively support (SIG-01).
///
/// Each maps to a distinct production path and a distinct evidentiary position; see
/// [`EvidentiaryLevel`] and [`SigningFamily::default_evidentiary_level`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SigningFamily {
    /// Cartão de Cidadão qualified signature — smartcard reader + CC signature PIN.
    /// Qualified ⇒ handwritten-equivalent (eIDAS art. 25; DL 12/2021).
    CartaoDeCidadao,
    /// Chave Móvel Digital — legally regulated *remote* qualified signing; requires an
    /// active CMD, an active signature function, and the CMD signature PIN.
    ChaveMovelDigital,
    /// Other qualified certificates imported from Portuguese/EU QTSPs (incl. representative
    /// and professional certificates); qualified status is verified against the TSL.
    QualifiedCertificate,
    /// Manual (handwritten): scan + archival workflow. Legally admissible (CSC art. 63.º;
    /// DL 268/94) but carries **no** automation presumptions — see [`MANUAL_WARNING`].
    Manual,
}

impl SigningFamily {
    /// The evidentiary level a *successful* signature in this family would carry (SIG-01).
    pub fn default_evidentiary_level(self) -> EvidentiaryLevel {
        match self {
            SigningFamily::CartaoDeCidadao
            | SigningFamily::ChaveMovelDigital
            | SigningFamily::QualifiedCertificate => EvidentiaryLevel::Qualified,
            SigningFamily::Manual => EvidentiaryLevel::HandwrittenScanned,
        }
    }

    /// Whether this family produces a qualified electronic signature (SIG-01). The three
    /// certificate-backed families do; `Manual` does not.
    pub fn is_qualified(self) -> bool {
        self.default_evidentiary_level().is_qualified_signature()
    }
}

/// Advanced/Qualified Electronic Signature container formats the subsystem MUST support
/// (SIG-20): PAdES for PDFs, XAdES/CAdES/ASiC for structured or detached workflows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SignatureFormat {
    /// PAdES — PDF Advanced Electronic Signatures (the default for sealed acts, DOC-01).
    PAdES,
    /// XAdES — XML Advanced Electronic Signatures.
    XAdES,
    /// CAdES — CMS Advanced Electronic Signatures.
    CAdES,
    /// ASiC — Associated Signature Containers (detached/packaged).
    ASiC,
}

/// ETSI baseline profiles the subsystem MUST support (SIG-21).
///
/// `B_LTA` (long-term with archival timestamps) is the default for sealed acts destined for
/// the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[non_exhaustive]
// Variant names mirror the ETSI baseline-profile identifiers (B-B, B-T, B-LT, B-LTA)
// verbatim; keeping the standard spelling is worth more here than camel-case conformance.
#[allow(non_camel_case_types)]
pub enum BaselineProfile {
    /// B-B — basic: signature + signing certificate.
    B_B,
    /// B-T — adds a trusted timestamp.
    B_T,
    /// B-LT — adds long-term validation material (certs, CRL/OCSP).
    B_LT,
    /// B-LTA — adds archival timestamps for long-term preservation (default for archive).
    /// SIG-21: B-LTA is the archival default.
    #[default]
    B_LTA,
}

impl BaselineProfile {
    /// Whether reaching this profile requires a trusted timestamp (B-T and above).
    pub fn requires_timestamp(self) -> bool {
        matches!(
            self,
            BaselineProfile::B_T | BaselineProfile::B_LT | BaselineProfile::B_LTA
        )
    }
}

/// The legal weight actually carried by a produced artifact (SIG-01 evidentiary column).
///
/// This exists so the UI and archive can never silently upgrade a weaker artifact into a
/// "qualified signature". Note especially [`EvidentiaryLevel::OtpConfirmation`]: an OTP on
/// its own is **not** a signature (SIG-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EvidentiaryLevel {
    /// Qualified electronic signature — handwritten-equivalent, with presumptions of
    /// identity/representation, intent, and integrity (eIDAS art. 25; DL 12/2021).
    Qualified,
    /// Advanced electronic signature — stronger than simple, but not the qualified
    /// presumption.
    Advanced,
    /// A handwritten signature captured by scanning; admissible but weaker force for company
    /// resolutions, with no automation presumptions (SIG-01 Manual row; SIG-03).
    HandwrittenScanned,
    /// A confirmation OTP event. **Not a signature** on its own (SIG-02); may only appear
    /// *inside* a qualified trust-service flow (e.g. CMD) and MUST be labelled as such.
    OtpConfirmation,
}

impl EvidentiaryLevel {
    /// Whether an artifact at this level may be presented to users as a *qualified
    /// electronic signature*. Only [`EvidentiaryLevel::Qualified`] may (SIG-02).
    pub fn is_qualified_signature(self) -> bool {
        matches!(self, EvidentiaryLevel::Qualified)
    }
}

/// The prominent warning that manual-signature mode MUST display (SIG-03).
pub const MANUAL_WARNING: &str = "This act may still be legally valid, but the digital copy \
is not being finalized with a qualified electronic signature. Preserve the original signed \
paper or original digitized signature chain.";

/// Ordering of signatures within an envelope (SIG-31): both MUST be supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SigningOrder {
    /// All signatories may sign in any order, concurrently.
    #[default]
    Parallel,
    /// Signatories must sign in the defined sequence.
    Serial,
}

/// The capacity in which a person signs — part of the evidence (ROL-04, SIG-04 via SCAP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SignerCapacity {
    /// Chair of the meeting.
    Chair,
    /// Secretary of the meeting.
    Secretary,
    /// Ordinary member/participant.
    Member,
    /// Manager (gerente).
    Manager,
    /// Administrator (administrador).
    Administrator,
    /// Attorney/representative acting under a power (records the legal basis).
    Attorney,
    /// Condominium owner (condómino).
    CondoOwner,
    /// Any other capacity, described free-form.
    Other(String),
}

/// Current status of a trust service resolved from the Portuguese Trusted List (SIG-10/11).
///
/// The real value comes from ingesting the signed TSL published by GNS (via `chancela-tsl`),
/// never a curated spreadsheet — see [`policy`] and the [`From`] mapping from
/// [`chancela_tsl::QualifiedStatus`] below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TrustedListStatus {
    /// Service is currently granted/qualified for the intended operation.
    Granted,
    /// Service exists on the list but is withdrawn/suspended — not usable.
    Withdrawn,
    /// Status not yet resolved against the TSL.
    Unknown,
}

impl From<chancela_tsl::QualifiedStatus> for TrustedListStatus {
    /// Map the `chancela-tsl` query result 1:1 onto the vocabulary status (t4-e5 mapping note).
    fn from(status: chancela_tsl::QualifiedStatus) -> Self {
        use chancela_tsl::QualifiedStatus as Q;
        match status {
            Q::Granted => TrustedListStatus::Granted,
            Q::Withdrawn => TrustedListStatus::Withdrawn,
            Q::Unknown => TrustedListStatus::Unknown,
            // `QualifiedStatus` is #[non_exhaustive]; treat any future variant conservatively.
            _ => TrustedListStatus::Unknown,
        }
    }
}

/// A request to produce a signature over a document with a chosen family/format/profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureRequest {
    /// Which signing family to use.
    pub family: SigningFamily,
    /// Container format to produce (SIG-20).
    pub format: SignatureFormat,
    /// Baseline profile to reach (SIG-21).
    pub profile: BaselineProfile,
    /// The capacity in which the signer acts (SIG-04).
    pub capacity: SignerCapacity,
    /// sha256 digest of the document to be signed (content itself lives outside this crate).
    pub document_digest: [u8; 32],
}

/// A produced signature artifact and its evidentiary labelling.
///
/// Beyond the evidentiary metadata, the artifact carries the produced [`Self::signature`] bytes
/// (a detached CAdES `SignedData` for [`SignatureFormat::CAdES`], the full signed PDF for
/// [`SignatureFormat::PAdES`], or the scanned image for [`SigningFamily::Manual`]) plus the
/// trusted-list status resolved at signing time and any attached qualified timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureArtifact {
    /// Stable id of the artifact.
    pub id: uuid::Uuid,
    /// The envelope slot this artifact fills (index into [`SignatureEnvelope::requests`]).
    pub slot: usize,
    /// The family that produced it.
    pub family: SigningFamily,
    /// The container format.
    pub format: SignatureFormat,
    /// The baseline profile actually reached (may be lower than requested; LT/LTA are phase-2).
    pub profile: BaselineProfile,
    /// The evidentiary weight this artifact carries (SIG-01).
    pub evidentiary_level: EvidentiaryLevel,
    /// When the signature was produced.
    #[serde(with = "time::serde::rfc3339::option")]
    pub signed_at: Option<time::OffsetDateTime>,
    /// The produced bytes: detached CMS DER (CAdES), signed-PDF bytes (PAdES), or scan (Manual).
    pub signature: Vec<u8>,
    /// The trusted-list status of the signer's issuer resolved at signing time (SIG-11/23), if a
    /// trust policy was consulted.
    pub trusted_list_status: Option<TrustedListStatus>,
    /// A qualified RFC 3161 timestamp token (DER `ContentInfo`) attached to this artifact
    /// (SIG-22), if the profile requested a timestamp and one was produced.
    pub timestamp_token_der: Option<Vec<u8>>,
}

impl SignatureArtifact {
    /// Whether this artifact may be presented as a qualified electronic signature (SIG-02).
    pub fn is_qualified(&self) -> bool {
        self.evidentiary_level.is_qualified_signature()
    }
}

/// A signature envelope: an ordered set of expected signatures over one act (SIG-31; DAT-01).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SignatureEnvelope {
    /// Serial or parallel signing order.
    pub order: SigningOrder,
    /// The requested signatures, in slot order.
    pub requests: Vec<SignatureRequest>,
    /// The artifacts collected so far (each tagged with the [`SignatureArtifact::slot`] it fills;
    /// for parallel envelopes their order in this vector reflects completion order, not slot).
    pub artifacts: Vec<SignatureArtifact>,
}

impl SignatureEnvelope {
    /// A new, empty envelope with the given order and requested slots.
    pub fn new(order: SigningOrder, requests: Vec<SignatureRequest>) -> Self {
        Self {
            order,
            requests,
            artifacts: Vec::new(),
        }
    }

    /// The artifact filling `slot`, if any.
    pub fn artifact_for(&self, slot: usize) -> Option<&SignatureArtifact> {
        self.artifacts.iter().find(|a| a.slot == slot)
    }
}

/// Errors from the signing subsystem.
///
/// Kept `Clone + PartialEq + Eq` (the vocabulary contract): failures from the underlying
/// crates — whose error types are not `Clone`/`Eq` — are captured as their `Display` string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SigningError {
    /// The operation (or requested profile/format) is not yet implemented (phase-2 seam).
    #[error("signing operation not implemented: {0}")]
    NotImplemented(&'static str),
    /// The chosen trust service is not currently granted on the trusted list (SIG-11/23).
    #[error("trust service is not currently granted on the trusted list: {status:?}")]
    UntrustedService {
        /// The resolved trusted-list status that caused the rejection.
        status: TrustedListStatus,
    },
    /// No issuer certificate was available to resolve the signer's trusted-list status, and a
    /// trust policy was configured (a qualified signature must not skip the trust check).
    #[error("no issuer certificate available for the trusted-list policy check")]
    MissingIssuerCertificate,
    /// A signing device/service (smartcard, CMD, mock) failed to produce a signature.
    #[error("signer provider failure: {0}")]
    Provider(String),
    /// CAdES/CMS assembly or validation failed (`chancela-cades`).
    #[error("CAdES/CMS error: {0}")]
    Cades(String),
    /// PAdES PDF signing/validation failed (`chancela-pades`).
    #[error("PAdES error: {0}")]
    Pades(String),
    /// Qualified-timestamp acquisition failed (`chancela-tsa`).
    #[error("timestamp error: {0}")]
    Timestamp(String),
    /// A trusted-list lookup failed (`chancela-tsl`).
    #[error("trusted-list error: {0}")]
    TrustedList(String),
    /// The container format requested is recognised by the vocabulary but not yet produced by
    /// this crate (only PAdES and detached CAdES are implemented; XAdES/ASiC are phase-2).
    #[error("signature format not supported yet: {0:?}")]
    UnsupportedFormat(SignatureFormat),
    /// The document input did not match the requested format (e.g. PAdES needs PDF bytes, a
    /// detached CAdES needs a content digest).
    #[error("document input does not match the requested format {format:?}")]
    FormatInputMismatch {
        /// The requested container format.
        format: SignatureFormat,
    },
    /// The provider's family did not match the family the envelope slot requested.
    #[error("provider family {provided:?} does not match the requested family {requested:?}")]
    FamilyMismatch {
        /// The family the slot requested.
        requested: SigningFamily,
        /// The family the supplied provider serves.
        provided: SigningFamily,
    },
    /// The referenced envelope slot is out of range.
    #[error("envelope slot {slot} is out of range (envelope has {len} requests)")]
    SlotOutOfRange {
        /// The requested slot index.
        slot: usize,
        /// The number of slots in the envelope.
        len: usize,
    },
    /// The referenced envelope slot has already been signed.
    #[error("envelope slot {0} has already been signed")]
    SlotAlreadySigned(usize),
    /// A serial envelope was signed out of order (slot `got` while `expected` is still open).
    #[error("serial envelope must be signed in order: expected slot {expected}, got {got}")]
    SlotOrder {
        /// The next slot the serial order allows.
        expected: usize,
        /// The slot the caller attempted to sign.
        got: usize,
    },
    /// A manual (scan) slot was routed through the cryptographic signing path, or a qualified
    /// slot was routed through the manual path.
    #[error("family {family:?} cannot be signed via this path")]
    WrongSigningPath {
        /// The family that was mis-routed.
        family: SigningFamily,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_serde_round_trip() {
        for family in [
            SigningFamily::CartaoDeCidadao,
            SigningFamily::ChaveMovelDigital,
            SigningFamily::QualifiedCertificate,
            SigningFamily::Manual,
        ] {
            let json = serde_json::to_string(&family).unwrap();
            let back: SigningFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(family, back);
        }
    }

    #[test]
    fn only_qualified_is_a_qualified_signature() {
        // SIG-02: OTP alone is not a signature; manual scans are not qualified.
        assert!(EvidentiaryLevel::Qualified.is_qualified_signature());
        assert!(!EvidentiaryLevel::Advanced.is_qualified_signature());
        assert!(!EvidentiaryLevel::HandwrittenScanned.is_qualified_signature());
        assert!(!EvidentiaryLevel::OtpConfirmation.is_qualified_signature());
    }

    #[test]
    fn manual_family_is_not_qualified() {
        assert!(
            !SigningFamily::Manual
                .default_evidentiary_level()
                .is_qualified_signature()
        );
        assert!(
            SigningFamily::CartaoDeCidadao
                .default_evidentiary_level()
                .is_qualified_signature()
        );
    }

    #[test]
    fn archival_default_profile_is_b_lta() {
        assert_eq!(BaselineProfile::default(), BaselineProfile::B_LTA);
    }

    #[test]
    fn trusted_list_status_maps_from_tsl_query() {
        // The `chancela-tsl` query result maps 1:1 onto the vocabulary status (t4-e5 note).
        use chancela_tsl::QualifiedStatus as Q;
        assert_eq!(
            TrustedListStatus::from(Q::Granted),
            TrustedListStatus::Granted
        );
        assert_eq!(
            TrustedListStatus::from(Q::Withdrawn),
            TrustedListStatus::Withdrawn
        );
        assert_eq!(
            TrustedListStatus::from(Q::Unknown),
            TrustedListStatus::Unknown
        );
    }
}
