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

use std::fmt;

use serde::{Deserialize, Serialize};

pub mod asic;
pub mod asic_sign;
pub mod asic_validate;
pub mod batch;
pub mod cc;
pub mod cmd_session;
pub mod dss_collect;
pub mod envelope;
pub mod mock;
pub mod pipeline;
pub mod policy;
pub mod provider;
pub mod remote;
pub mod revocation;
pub mod soft_cert;
pub mod validate;

pub use asic::{
    ASICE_ARCHIVE_MANIFEST_PATH, ASICE_ARCHIVE_TIMESTAMP_PATH, ASICE_CADES_SIGNATURE_PATH,
    ASICE_MANIFEST_PATH, ASICE_MIMETYPE, ASICS_CADES_SIGNATURE_PATH, ASICS_MIMETYPE,
    ASICS_XADES_SIGNATURE_PATH, AsicArchiveReference, AsicBoundedProfile, AsicContainer,
    AsicContainerKind, AsicEContainer, AsicEDataObject, AsicPayload, AsicProfileReport,
    AsicSContainer, AsicSignatureProfile, RFC3161_TIMESTAMP_MIME_TYPE, assemble_asic_e_container,
    build_asic_archive_manifest, build_asic_e_manifest, create_asic_e_container,
    create_asic_s_container, create_asic_s_xades_container, extract_asic_container,
    extract_asic_e_container, extract_asic_s_container, inspect_asic_profile,
    sha256_content_digest,
};
pub use asic_sign::{
    AsicEMultiSignRequest, sign_asic_e_multi, sign_asic_e_xades_lt, sign_asic_s_xades,
};
pub use asic_validate::{
    AsicArchiveTimestampValidation, AsicEmbeddedEvidenceBlocker, AsicEmbeddedEvidenceIndicator,
    AsicSignatureValidation, AsicValidationReport, validate_asic_container,
};
pub use batch::{
    AuthMode, BatchCadesDocument, BatchDocumentOutcome, BatchPdfDocument, BatchReport,
    RemoteBatchAuthMode, RemoteBatchConfirmDocument, RemoteBatchConfirmReport,
    RemoteBatchInitiateOutcome, RemoteBatchInitiateReport, RemoteBatchPdfDocument,
    RemoteBatchPendingDocument, RemoteBatchPreparedDocument,
    confirm_remote_pdf_batch_repeated_sessions, initiate_remote_pdf_batch_repeated_sessions,
    initiate_remote_prepared_batch_repeated_sessions, sign_detached_cades_batch, sign_pdf_batch,
};
pub use cc::{CcProviderProbe, CcSignedPdf, probe_cc_provider, sign_pdf_cc};
pub use cmd_session::{
    CMD_PROVIDER_ID, CmdInitiate, CmdRemoteSource, CmdSignSession, cmd_confirm, cmd_initiate,
};
pub use dss_collect::collect_dss_evidence;
pub use envelope::{
    DocumentInput, SigningJob, is_complete, pending_slots, record_manual_signature, sign_slot,
};
pub use mock::MockProvider;
pub use pipeline::{
    PadesLtaExecution, PadesLtvRenewal, TimestampProvider, add_pdf_document_timestamp,
    attach_pdf_dss, attach_pdf_lt, attach_pdf_revocation_evidence, execute_pdf_lta, renew_pdf_ltv,
    sign_asic_e, sign_asic_s, sign_detached_cades, sign_pdf_pades, timestamp_pdf,
    timestamp_pdf_with_url,
};
pub use policy::{StaticTrustPolicy, TrustAnchorSource, TrustPolicy, TslTrustPolicy};
pub use provider::{CmdProvider, SignerProvider, SmartcardProvider};
pub use remote::{RemoteInitiate, RemoteSignSession, RemoteSigningSource};
pub use revocation::{
    BoundedHttpRevocationTransport, DiscoveredRevocationUris, OcspRevocationSource,
    REVOCATION_CACHE_FALLBACK_TTL, RevocationCache, RevocationCacheKey, RevocationError,
    RevocationEvidence, RevocationEvidenceProvider, RevocationFetchLimits, RevocationHttpResponse,
    RevocationHttpTransport, RevocationSource, unsigned_ocsp_request_der,
};
pub use soft_cert::{
    Pkcs12IdentitySelector, Pkcs12SigningSource, SoftCertificateError, SoftCertificateIdentity,
};
pub use validate::{
    SignatureValidationReport, SignerTrustDecision, SignerTrustReport, TimestampQtstMatchReport,
    TimestampTrustDecision, TimestampTrustPolicy, TimestampTrustReport, validate_signature,
    validate_signer_trust, validate_timestamp_trust,
};

// Re-export the pieces of the underlying stack callers most often name through this crate.
pub use chancela_cades::{RawSignature, SignatureAlgorithm};
pub use chancela_pades::validate::PdfSignatureCoverage;
pub use chancela_pades::{
    DssEvidence, DssReport, ImageSeal, PreparedSignature, SealAppearance, SealContent,
    SealImageFormat, SealPlacement, SealTextLine, SignOptions, TextSeal, embed_signature,
    prepare_signature, prepare_signature_with_appearance, sign_pdf_with_appearance,
};
pub use chancela_tsa::{Timestamp, TsaClient};
pub use chancela_xades::{ValidationMaterial, XadesLevel, XadesValidationReport, validate_xades};

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

/// Advanced/Qualified Electronic Signature container formats the subsystem vocabulary recognises
/// (SIG-20). PAdES and detached CAdES are implemented directly; local ASiC helpers cover
/// ASiC-S/CAdES, ASiC-S/XAdES, and ASiC-E technical containers (CAdES + XAdES, multiple signatures,
/// per-signature manifests, and an `ASiCArchiveManifest` archive timestamp) via
/// [`crate::asic_sign`] / [`crate::asic_validate`]. XAdES here is the detached XMLDSig/XAdES-B/T
/// carried inside those ASiC containers; a bare (non-ASiC) XAdES document through
/// [`validate_signature`](crate::validate_signature) is still a phase-2 seam and returns
/// [`SigningError::UnsupportedProfile`]. None of this vocabulary decides complete ASiC/XAdES
/// conformance, trust status, or legal qualification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SignatureFormat {
    /// PAdES — PDF Advanced Electronic Signatures (the default for sealed acts, DOC-01).
    PAdES,
    /// XAdES — XML Advanced Electronic Signatures.
    XAdES,
    /// CAdES — CMS Advanced Electronic Signatures.
    CAdES,
    /// ASiC — Associated Signature Containers (bounded ASiC-S/CAdES and ASiC-E/CAdES support).
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
    /// The produced bytes: detached CMS DER (CAdES), signed-PDF bytes (PAdES), ASiC ZIP bytes, or
    /// scan (Manual).
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

/// Structured evidence for a recognised signature profile this crate deliberately does not
/// implement yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UnsupportedSignatureProfile {
    /// The top-level format family the caller requested or the container declared.
    pub format: SignatureFormat,
    /// The unsupported profile name, e.g. `XAdES` or `ASiC-XAdES`.
    pub profile: String,
    /// Why the profile was rejected by this bounded implementation.
    pub reason: String,
    /// Concrete evidence that led to the decision, such as member paths found in a container.
    pub evidence: Vec<String>,
    /// Profiles this crate can currently produce or validate instead.
    pub supported_profiles: Vec<String>,
}

impl UnsupportedSignatureProfile {
    /// Build an unsupported-profile diagnostic with no evidence yet.
    pub fn new(
        format: SignatureFormat,
        profile: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            format,
            profile: profile.into(),
            reason: reason.into(),
            evidence: Vec::new(),
            supported_profiles: Vec::new(),
        }
    }

    /// Attach concrete evidence used to classify the unsupported profile.
    pub fn with_evidence(mut self, evidence: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.evidence = evidence.into_iter().map(Into::into).collect();
        self
    }

    /// Attach the currently supported alternatives.
    pub fn with_supported_profiles(
        mut self,
        supported_profiles: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.supported_profiles = supported_profiles.into_iter().map(Into::into).collect();
        self
    }
}

impl fmt::Display for UnsupportedSignatureProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}/{} is not supported: {}",
            self.format, self.profile, self.reason
        )?;
        if !self.evidence.is_empty() {
            write!(f, "; evidence: {}", self.evidence.join(", "))?;
        }
        if !self.supported_profiles.is_empty() {
            write!(
                f,
                "; supported profiles: {}",
                self.supported_profiles.join(", ")
            )?;
        }
        Ok(())
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
    ///
    /// Since t61-e2 this means what it says: the list **did** authenticate against a configured
    /// trust anchor, and the signer's own service is not `Granted`. The two failures that are
    /// about the *operator's* anchor configuration rather than the signer are reported as
    /// [`Self::TrustAnchorNotConfigured`] and [`Self::TrustedListNotAnchored`].
    #[error("trust service is not currently granted on the trusted list: {status:?}")]
    UntrustedService {
        /// The resolved trusted-list status that caused the rejection.
        status: TrustedListStatus,
    },
    /// No Trusted List trust anchor is configured at all, so no list can ever be authenticated and
    /// no signer can be trusted (SIG-11; t61-e2 case A).
    ///
    /// This is **not** a statement about the signer's trust service — the operator has provisioned
    /// nothing. Kept distinct from [`Self::TrustedListNotAnchored`] so a diagnostic can never tell
    /// an operator who *did* configure an anchor that they configured none, nor the reverse.
    #[error("no trusted-list trust anchor is configured; anchors were resolved from {checked}")]
    TrustAnchorNotConfigured {
        /// Where the anchors were resolved from, so the operator knows which surface to configure.
        checked: policy::TrustAnchorSource,
    },
    /// Trust anchors are configured, but the Trusted List's own XML-DSig signature does not
    /// authenticate against any of them (SIG-11; t61-e2 case B) — a wrong anchor, or a scheme-key
    /// rotation whose new signing certificate has not been provisioned yet.
    ///
    /// The signer's trusted-list status is therefore *unestablished*, not withdrawn: an
    /// unauthenticated list is not evidence about anybody. Reporting this as
    /// [`Self::UntrustedService`] blames the signer's service for the operator's stale anchor.
    #[error(
        "the trusted list did not authenticate against any of the {anchor_count} trust anchor(s) \
         resolved from {configured_in}"
    )]
    TrustedListNotAnchored {
        /// Where the anchors that failed to authenticate the list came from.
        configured_in: policy::TrustAnchorSource,
        /// How many anchors were configured. Never zero — that is
        /// [`Self::TrustAnchorNotConfigured`].
        anchor_count: usize,
    },
    /// No issuer certificate was available to resolve the signer's trusted-list status, and a
    /// trust policy was configured (a qualified signature must not skip the trust check).
    #[error("no issuer certificate available for the trusted-list policy check")]
    MissingIssuerCertificate,
    /// A signing device/service (smartcard, CMD, mock) failed to produce a signature.
    #[error("signer provider failure: {0}")]
    Provider(String),
    /// PKCS#12/software-certificate loading or signing failed.
    #[error("software certificate error: {0}")]
    SoftCertificate(SoftCertificateError),
    /// CAdES/CMS assembly or validation failed (`chancela-cades`).
    #[error("CAdES/CMS error: {0}")]
    Cades(String),
    /// PAdES PDF signing/validation failed (`chancela-pades`).
    #[error("PAdES error: {0}")]
    Pades(String),
    /// ASiC container creation/parsing/validation failed.
    #[error("ASiC container error: {0}")]
    Asic(String),
    /// XAdES/XMLDSig assembly or validation failed (`chancela-xades`).
    #[error("XAdES error: {0}")]
    Xades(String),
    /// A recognised profile is deliberately unsupported; includes evidence and supported
    /// alternatives so callers can surface an actionable diagnostic without overclaiming support.
    #[error("unsupported signature profile: {0}")]
    UnsupportedProfile(UnsupportedSignatureProfile),
    /// Qualified-timestamp acquisition failed (`chancela-tsa`).
    #[error("timestamp error: {0}")]
    Timestamp(String),
    /// A trusted-list lookup failed (`chancela-tsl`).
    #[error("trusted-list error: {0}")]
    TrustedList(String),
    /// The container format requested is recognised by the vocabulary but not yet produced by this
    /// crate. More specific profile gaps use [`SigningError::UnsupportedProfile`].
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

// ─── THE STABLE SIGNING-ERROR CODE VOCABULARY ──────────────────────────────────────────────────
//
// One code per cause, so a failing signature can be told apart from another failing signature.
// Every constant is `snake_case` ASCII; the web layer owns the sentence and reads this list out of
// this file (`apiErrorFallback.test.ts`) to prove none is left untranslated.
//
// **Append-only.** A code that has shipped is in operator logs and in the client's copy catalog;
// renaming one silently demotes the client to a bare status tier.
//
// Five entries are deliberately NOT `signing_`-prefixed: they already shipped as call-site codes
// with copy behind them (`trust_anchor_not_configured`, `trusted_list_not_anchored`,
// `signer_service_not_active`, `pkcs12_password_incorrect`, `pkcs12_material_invalid`). Making the
// code intrinsic must not change what the wire says, or every operator runbook quoting them breaks.

/// The requested operation, profile or format is recognised but not produced by this build.
pub const SIGNING_NOT_IMPLEMENTED: &str = "signing_not_implemented";
/// The signer's trust service is not currently `Granted` on an **authenticated** Trusted List.
pub const SIGNING_SIGNER_SERVICE_NOT_ACTIVE: &str = "signer_service_not_active";
/// No Trusted List trust anchor is configured anywhere, so no list can ever be authenticated.
pub const SIGNING_TRUST_ANCHOR_NOT_CONFIGURED: &str = "trust_anchor_not_configured";
/// Anchors are configured, but the Trusted List did not authenticate against any of them.
pub const SIGNING_TRUSTED_LIST_NOT_ANCHORED: &str = "trusted_list_not_anchored";
/// No issuer certificate was available to resolve the signer's trusted-list status.
pub const SIGNING_ISSUER_CERTIFICATE_MISSING: &str = "signing_issuer_certificate_missing";
/// A signing device or service refused, or could not complete, the signature.
pub const SIGNING_PROVIDER_REFUSED: &str = "signing_provider_refused";
/// The PKCS#12 password failed the MAC/decryption gate.
pub const SIGNING_PKCS12_PASSWORD_INCORRECT: &str = "pkcs12_password_incorrect";
/// The PKCS#12 material carries no usable signing key or chain.
pub const SIGNING_PKCS12_MATERIAL_INVALID: &str = "pkcs12_material_invalid";
/// CAdES/CMS assembly or validation failed inside this application.
pub const SIGNING_CADES_FAILED: &str = "signing_cades_failed";
/// PAdES PDF signing or validation failed inside this application.
pub const SIGNING_PADES_FAILED: &str = "signing_pades_failed";
/// ASiC container creation, parsing or validation failed inside this application.
pub const SIGNING_ASIC_FAILED: &str = "signing_asic_failed";
/// XAdES/XMLDSig assembly or validation failed inside this application.
pub const SIGNING_XADES_FAILED: &str = "signing_xades_failed";
/// A recognised signature profile this build deliberately does not support.
pub const SIGNING_UNSUPPORTED_PROFILE: &str = "signing_unsupported_profile";
/// The qualified timestamp authority did not return a usable timestamp.
pub const SIGNING_TIMESTAMP_FAILED: &str = "signing_timestamp_failed";
/// The Trusted List itself could not be fetched, read or parsed — no trust verdict was reached.
pub const SIGNING_TRUSTED_LIST_UNAVAILABLE: &str = "signing_trusted_list_unavailable";
/// The requested container format is in the vocabulary but is not produced by this build.
pub const SIGNING_UNSUPPORTED_FORMAT: &str = "signing_unsupported_format";
/// The document input did not match the requested container format.
pub const SIGNING_FORMAT_INPUT_MISMATCH: &str = "signing_format_input_mismatch";
/// The provider's signing family did not match the family the envelope slot requested.
pub const SIGNING_FAMILY_MISMATCH: &str = "signing_family_mismatch";
/// The referenced envelope slot index does not exist.
pub const SIGNING_SLOT_OUT_OF_RANGE: &str = "signing_slot_out_of_range";
/// The referenced envelope slot has already been signed.
pub const SIGNING_SLOT_ALREADY_SIGNED: &str = "signing_slot_already_signed";
/// A serial envelope was signed out of order.
pub const SIGNING_SLOT_OUT_OF_ORDER: &str = "signing_slot_out_of_order";
/// A slot was routed through the wrong signing path (manual through crypto, or the reverse).
pub const SIGNING_WRONG_PATH: &str = "signing_wrong_path";

/// Every stable signing-error code, in one closed list.
///
/// The closed list is what makes the client gate possible: `apiErrorFallback.test.ts` scans this
/// file for the constants, reads this array, and fails if any entry has no pt-PT and English copy.
/// A constant declared but left out of this array is caught by the same test.
pub const ALL_SIGNING_ERROR_CODES: &[&str] = &[
    SIGNING_NOT_IMPLEMENTED,
    SIGNING_SIGNER_SERVICE_NOT_ACTIVE,
    SIGNING_TRUST_ANCHOR_NOT_CONFIGURED,
    SIGNING_TRUSTED_LIST_NOT_ANCHORED,
    SIGNING_ISSUER_CERTIFICATE_MISSING,
    SIGNING_PROVIDER_REFUSED,
    SIGNING_PKCS12_PASSWORD_INCORRECT,
    SIGNING_PKCS12_MATERIAL_INVALID,
    SIGNING_CADES_FAILED,
    SIGNING_PADES_FAILED,
    SIGNING_ASIC_FAILED,
    SIGNING_XADES_FAILED,
    SIGNING_UNSUPPORTED_PROFILE,
    SIGNING_TIMESTAMP_FAILED,
    SIGNING_TRUSTED_LIST_UNAVAILABLE,
    SIGNING_UNSUPPORTED_FORMAT,
    SIGNING_FORMAT_INPUT_MISMATCH,
    SIGNING_FAMILY_MISMATCH,
    SIGNING_SLOT_OUT_OF_RANGE,
    SIGNING_SLOT_ALREADY_SIGNED,
    SIGNING_SLOT_OUT_OF_ORDER,
    SIGNING_WRONG_PATH,
];

impl SigningError {
    /// The stable, machine-readable code for this failure.
    ///
    /// **Intrinsic, produced here and nowhere else.** Before this existed, the API's four
    /// `SigningError` → `ApiError` mappers each named the causes they cared about and swept the rest
    /// into one `other => ApiError::Upstream(…)` arm, which renders as an opaque
    /// `{"error": "erro de gateway", "code": "http.upstream"}` with the detail diverted to the server
    /// log. "The Trusted List could not be fetched", "the timestamp authority refused" and "this
    /// profile is not implemented" were therefore indistinguishable to the operator — and all three
    /// were reported as a *gateway* failure, which two of them are not.
    ///
    /// Producing the code at the error rather than at the mapper is the whole point: four mappers
    /// classifying the same enum drift apart, and the arm that drifts is the `_ =>` fallback, which
    /// fails by getting vaguer rather than by failing to compile. Path-specific *prose* still belongs
    /// to each mapper (a Cartão de Cidadão sentence is not a Chave Móvel Digital one); the cause does
    /// not.
    ///
    /// Every value is in [`ALL_SIGNING_ERROR_CODES`].
    pub fn code(&self) -> &'static str {
        match self {
            SigningError::NotImplemented(_) => SIGNING_NOT_IMPLEMENTED,
            SigningError::UntrustedService { .. } => SIGNING_SIGNER_SERVICE_NOT_ACTIVE,
            SigningError::TrustAnchorNotConfigured { .. } => SIGNING_TRUST_ANCHOR_NOT_CONFIGURED,
            SigningError::TrustedListNotAnchored { .. } => SIGNING_TRUSTED_LIST_NOT_ANCHORED,
            SigningError::MissingIssuerCertificate => SIGNING_ISSUER_CERTIFICATE_MISSING,
            SigningError::Provider(_) => SIGNING_PROVIDER_REFUSED,
            // The password case is split out because it is the one an operator can fix by typing
            // again; everything else about a PKCS#12 file needs a different file.
            SigningError::SoftCertificate(SoftCertificateError::WrongPassword) => {
                SIGNING_PKCS12_PASSWORD_INCORRECT
            }
            SigningError::SoftCertificate(_) => SIGNING_PKCS12_MATERIAL_INVALID,
            SigningError::Cades(_) => SIGNING_CADES_FAILED,
            SigningError::Pades(_) => SIGNING_PADES_FAILED,
            SigningError::Asic(_) => SIGNING_ASIC_FAILED,
            SigningError::Xades(_) => SIGNING_XADES_FAILED,
            SigningError::UnsupportedProfile(_) => SIGNING_UNSUPPORTED_PROFILE,
            SigningError::Timestamp(_) => SIGNING_TIMESTAMP_FAILED,
            SigningError::TrustedList(_) => SIGNING_TRUSTED_LIST_UNAVAILABLE,
            SigningError::UnsupportedFormat(_) => SIGNING_UNSUPPORTED_FORMAT,
            SigningError::FormatInputMismatch { .. } => SIGNING_FORMAT_INPUT_MISMATCH,
            SigningError::FamilyMismatch { .. } => SIGNING_FAMILY_MISMATCH,
            SigningError::SlotOutOfRange { .. } => SIGNING_SLOT_OUT_OF_RANGE,
            SigningError::SlotAlreadySigned(_) => SIGNING_SLOT_ALREADY_SIGNED,
            SigningError::SlotOrder { .. } => SIGNING_SLOT_OUT_OF_ORDER,
            SigningError::WrongSigningPath { .. } => SIGNING_WRONG_PATH,
        }
    }

    pub(crate) fn unsupported_xades(operation: &'static str) -> Self {
        SigningError::UnsupportedProfile(
            UnsupportedSignatureProfile::new(
                SignatureFormat::XAdES,
                "XAdES",
                format!("{operation} is not implemented for XMLDSig/XAdES artifacts"),
            )
            .with_supported_profiles([
                "PAdES/CAdES-backed PDF signatures",
                "detached CAdES-B",
                "bounded ASiC-S/CAdES",
                "bounded ASiC-E/CAdES",
            ]),
        )
    }
}

#[cfg(test)]
mod signing_error_code_tests {
    use super::*;
    use std::collections::BTreeSet;

    /// One instance of **every** variant. Constructed by hand rather than derived, so the list is a
    /// reviewed inventory: adding a variant to the enum makes `SigningError::code()` fail to compile
    /// (the match is exhaustive in-crate despite `#[non_exhaustive]`), and adding it here is what
    /// forces someone to decide whether its code is new or shared.
    fn every_variant() -> Vec<SigningError> {
        vec![
            SigningError::NotImplemented("phase-2 seam"),
            SigningError::UntrustedService {
                status: TrustedListStatus::Withdrawn,
            },
            SigningError::TrustAnchorNotConfigured {
                checked: policy::TrustAnchorSource::ApplicationSettings,
            },
            SigningError::TrustedListNotAnchored {
                configured_in: policy::TrustAnchorSource::Environment,
                anchor_count: 2,
            },
            SigningError::MissingIssuerCertificate,
            SigningError::Provider("the card was removed".to_owned()),
            SigningError::SoftCertificate(SoftCertificateError::WrongPassword),
            SigningError::SoftCertificate(SoftCertificateError::MissingPrivateKey),
            SigningError::SoftCertificate(SoftCertificateError::EmptyCertificateChain),
            SigningError::SoftCertificate(SoftCertificateError::MalformedInput("bad".to_owned())),
            SigningError::Cades("CMS assembly failed".to_owned()),
            SigningError::Pades("PDF byte range is malformed".to_owned()),
            SigningError::Asic("container has no mimetype member".to_owned()),
            SigningError::Xades("XMLDSig reference did not digest".to_owned()),
            SigningError::UnsupportedProfile(UnsupportedSignatureProfile::new(
                SignatureFormat::XAdES,
                "XAdES",
                "not implemented",
            )),
            SigningError::Timestamp("the TSA returned status 5".to_owned()),
            SigningError::TrustedList("the trusted list could not be fetched".to_owned()),
            SigningError::UnsupportedFormat(SignatureFormat::XAdES),
            SigningError::FormatInputMismatch {
                format: SignatureFormat::PAdES,
            },
            SigningError::FamilyMismatch {
                requested: SigningFamily::CartaoDeCidadao,
                provided: SigningFamily::ChaveMovelDigital,
            },
            SigningError::SlotOutOfRange { slot: 4, len: 2 },
            SigningError::SlotAlreadySigned(1),
            SigningError::SlotOrder {
                expected: 0,
                got: 1,
            },
            SigningError::WrongSigningPath {
                family: SigningFamily::Manual,
            },
        ]
    }

    #[test]
    fn every_variant_yields_a_code_from_the_closed_list() {
        for error in every_variant() {
            let code = error.code();
            assert!(
                ALL_SIGNING_ERROR_CODES.contains(&code),
                "{error:?} yielded code {code:?}, which is not in ALL_SIGNING_ERROR_CODES"
            );
        }
    }

    #[test]
    fn the_closed_list_has_no_entry_nothing_produces() {
        // The mirror of the test above. A constant left in the array after its variant was removed
        // is a code the client would keep copy for and the server could never send.
        let produced: BTreeSet<&str> = every_variant().iter().map(|e| e.code()).collect();
        let orphans: Vec<&&str> = ALL_SIGNING_ERROR_CODES
            .iter()
            .filter(|code| !produced.contains(**code))
            .collect();
        assert!(orphans.is_empty(), "codes nothing produces: {orphans:?}");
    }

    #[test]
    fn codes_are_unique_and_client_safe_identifiers() {
        let unique: BTreeSet<&&str> = ALL_SIGNING_ERROR_CODES.iter().collect();
        assert_eq!(
            unique.len(),
            ALL_SIGNING_ERROR_CODES.len(),
            "two signing error codes collide, so a client cannot tell their sentences apart"
        );
        for code in ALL_SIGNING_ERROR_CODES {
            assert!(
                !code.is_empty()
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{code:?} is not a snake_case ASCII identifier"
            );
        }
    }

    /// The four causes the API's `Upstream` catch-all used to merge. They are what an operator has
    /// to be able to tell apart: a list that could not be fetched, a timestamp authority that
    /// refused, a profile this build does not produce, and a provider that said no.
    #[test]
    fn the_previously_merged_causes_are_four_distinct_codes() {
        let codes = [
            SigningError::TrustedList("fetch failed".to_owned()).code(),
            SigningError::Timestamp("TSA refused".to_owned()).code(),
            SigningError::NotImplemented("XAdES-LTA").code(),
            SigningError::Provider("card removed".to_owned()).code(),
        ];
        let unique: BTreeSet<&&str> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "merged again: {codes:?}");
    }

    /// A wrong PKCS#12 password is retryable by typing; anything else about the file is not. The two
    /// must not share a code, or the client cannot tell an operator which one they are looking at.
    #[test]
    fn a_wrong_pkcs12_password_is_distinct_from_unusable_material() {
        assert_ne!(
            SigningError::SoftCertificate(SoftCertificateError::WrongPassword).code(),
            SigningError::SoftCertificate(SoftCertificateError::MissingPrivateKey).code()
        );
    }

    /// The three trust states t61-e2 split apart keep three codes, and keep the ones already on the
    /// wire. Renaming any of them would silently demote a client that has copy for the old name.
    #[test]
    fn the_three_trust_states_keep_their_shipped_codes() {
        assert_eq!(
            SigningError::TrustAnchorNotConfigured {
                checked: policy::TrustAnchorSource::Environment,
            }
            .code(),
            "trust_anchor_not_configured"
        );
        assert_eq!(
            SigningError::TrustedListNotAnchored {
                configured_in: policy::TrustAnchorSource::Environment,
                anchor_count: 1,
            }
            .code(),
            "trusted_list_not_anchored"
        );
        assert_eq!(
            SigningError::UntrustedService {
                status: TrustedListStatus::Withdrawn,
            }
            .code(),
            "signer_service_not_active"
        );
        // And an unauthenticated list is never reported as the signer's service being inactive.
        assert_ne!(
            SigningError::TrustedList("fetch failed".to_owned()).code(),
            SigningError::UntrustedService {
                status: TrustedListStatus::Withdrawn,
            }
            .code()
        );
    }
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
