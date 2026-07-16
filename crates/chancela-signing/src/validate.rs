//! Signature validation and reporting (SIG-24).
//!
//! Delegates the cryptographic and structural check to `chancela-cades` (detached CAdES),
//! `chancela-pades` (PAdES over the embedded ByteRange), or the bounded ASiC/CAdES parsers, and
//! folds in the evidentiary labelling and trusted-list status recorded on the artifact. The EU DSS
//! validation-sidecar cross-check (SIG-23) is a documented phase-2 seam; this native path produces
//! the report required at sealing time.

use time::OffsetDateTime;

use crate::{
    EvidentiaryLevel, RevocationCache, RevocationError, RevocationEvidenceProvider,
    RevocationHttpTransport, SignatureArtifact, SignatureFormat, SigningError, TrustedListStatus,
    asic::AsicContainer,
};

/// Policy input for technical timestamp-trust validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TimestampTrustPolicy {
    /// Accepted `TSTInfo.policy` OIDs in dotted notation. Empty means no configured/known policy
    /// OID is enforced by this layer.
    pub accepted_policy_oids: Vec<String>,
}

impl TimestampTrustPolicy {
    /// Build a policy that enforces one of the supplied `TSTInfo.policy` OIDs.
    pub fn require_one_of(
        accepted_policy_oids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            accepted_policy_oids: accepted_policy_oids.into_iter().map(Into::into).collect(),
        }
    }
}

/// Technical timestamp-trust outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimestampTrustDecision {
    /// Token, policy, TSL/QTST match and offline certificate path all passed.
    Accepted,
    /// One or more technical checks failed. See
    /// [`TimestampTrustReport::failure_reasons`].
    Rejected,
}

/// QTST match evidence copied into the timestamp-trust report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TimestampQtstMatchReport {
    pub provider_name: String,
    pub service_name: String,
    pub granted_and_effective: bool,
    pub trust_anchor_count: usize,
}

/// Technical trust report for an RFC 3161 signature timestamp.
///
/// This is deliberately a technical policy report. It records local cryptographic, path, policy
/// OID and TSL/QTST evidence; it does not make a legal qualification or probative-value claim.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TimestampTrustReport {
    pub decision: TimestampTrustDecision,
    pub timestamp_policy_oid: String,
    pub policy_oid_accepted: Option<bool>,
    pub tsa_certificate_embedded: bool,
    pub embedded_certificate_count: usize,
    pub trusted_list_status: TrustedListStatus,
    pub trusted_list_authenticated: bool,
    pub qtst_matches: Vec<TimestampQtstMatchReport>,
    pub trust_anchor_count: usize,
    pub certificate_path_valid: bool,
    pub certificate_path_anchor_index: Option<usize>,
    pub certificate_path_len: Option<usize>,
    pub failure_reasons: Vec<String>,
    pub scope_note: &'static str,
}

/// A signature-validation report (SIG-24).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignatureValidationReport {
    /// Whether the signature verified cryptographically over its content (always `true` on `Ok`).
    pub cryptographically_valid: bool,
    /// The signer's certificate, DER-encoded, as embedded in the signature.
    pub signer_cert_der: Vec<u8>,
    /// The `signing-time` attribute, if present.
    pub signing_time: Option<OffsetDateTime>,
    /// The trusted-list status recorded when the artifact was produced (SIG-11/23), if any.
    pub trusted_list_status: Option<TrustedListStatus>,
    /// Whether a qualified signature timestamp is present (PAdES-B-T, or a CAdES token attached as
    /// evidence) (SIG-22).
    pub has_signature_timestamp: bool,
    /// The evidentiary weight this artifact carries (SIG-01).
    pub evidentiary_level: EvidentiaryLevel,
    /// For PAdES, whether the ByteRange covers the whole file except the `/Contents` value (the
    /// well-formed shape). `None` for detached CAdES.
    pub covers_whole_file: Option<bool>,
    /// Embedded PAdES DSS/VRI evidence, if any. Empty for detached CAdES.
    pub dss: chancela_pades::DssReport,
    /// Technical local evidence marker: true only when a PAdES signature has B-T timestamp evidence
    /// and embedded DSS OCSP/CRL material. This is not a legal B-LT sufficiency claim.
    pub has_local_dss_revocation_evidence: bool,
    /// Live end-entity signer trust decision, when one was computed via
    /// [`validate_signer_trust`] and folded in. `None` when this report was produced without a
    /// live TSL/revocation check (the default; [`validate_signature`] does not perform network
    /// I/O and always leaves this `None`).
    pub signer_trust: Option<SignerTrustReport>,
}

/// Validate a produced [`SignatureArtifact`] and build its report (SIG-24).
///
/// For [`SignatureFormat::PAdES`] the artifact's [`SignatureArtifact::signature`] bytes are the
/// signed PDF and validation is self-contained (`content_digest` is ignored). For
/// [`SignatureFormat::CAdES`] the bytes are the detached CMS and the caller MUST supply the
/// `content_digest` the signature covers. For [`SignatureFormat::ASiC`] the bytes are a bounded
/// ASiC-S or ASiC-E/CAdES ZIP container and validation is self-contained. If `content_digest` is
/// supplied, it is cross-checked against the packaged ASiC-S payload digest, or against the single
/// ASiC-E payload digest when the ASiC-E container has exactly one payload. XAdES remains
/// unsupported (phase-2).
pub fn validate_signature(
    artifact: &SignatureArtifact,
    content_digest: Option<&[u8; 32]>,
) -> Result<SignatureValidationReport, SigningError> {
    match artifact.format {
        SignatureFormat::PAdES => {
            let report = chancela_pades::validate_pdf_signature(&artifact.signature)
                .map_err(|e| SigningError::Pades(e.to_string()))?;
            Ok(SignatureValidationReport {
                cryptographically_valid: true,
                signer_cert_der: report.cades.signer_cert_der,
                signing_time: report.cades.signing_time,
                trusted_list_status: artifact.trusted_list_status,
                has_signature_timestamp: report.has_signature_timestamp,
                evidentiary_level: artifact.evidentiary_level,
                covers_whole_file: Some(report.covers_whole_file_except_contents),
                has_local_dss_revocation_evidence: report.has_signature_timestamp
                    && report.dss.has_revocation_evidence(),
                dss: report.dss,
                signer_trust: None,
            })
        }
        SignatureFormat::CAdES => {
            let content_digest = content_digest.ok_or(SigningError::FormatInputMismatch {
                format: SignatureFormat::CAdES,
            })?;
            let validation = chancela_cades::validate_cades_b(&artifact.signature, content_digest)
                .map_err(|e| SigningError::Cades(e.to_string()))?;
            Ok(SignatureValidationReport {
                cryptographically_valid: true,
                signer_cert_der: validation.signer_cert_der,
                signing_time: validation.signing_time,
                trusted_list_status: artifact.trusted_list_status,
                has_signature_timestamp: artifact.timestamp_token_der.is_some(),
                evidentiary_level: artifact.evidentiary_level,
                covers_whole_file: None,
                dss: chancela_pades::DssReport::default(),
                has_local_dss_revocation_evidence: false,
                signer_trust: None,
            })
        }
        SignatureFormat::ASiC => match crate::asic::extract_asic_container(&artifact.signature)? {
            AsicContainer::S(container) => {
                let packaged_digest = crate::asic::sha256_content_digest(&container.content);
                if let Some(expected) = content_digest
                    && expected != &packaged_digest
                {
                    return Err(SigningError::Asic(
                        "ASiC payload digest does not match the supplied content digest"
                            .to_string(),
                    ));
                }
                validate_cades_member(artifact, container.cades_signature_der, &packaged_digest)
            }
            AsicContainer::E(container) => {
                if let Some(expected) = content_digest {
                    match container.data_objects.as_slice() {
                        [single] if expected == &single.sha256_digest => {}
                        [single] => {
                            return Err(SigningError::Asic(format!(
                                "ASiC-E payload digest for {} does not match the supplied content digest",
                                single.name
                            )));
                        }
                        _ => {
                            return Err(SigningError::Asic(
                                "ASiC-E contains multiple payloads; a single supplied content digest is ambiguous"
                                    .to_string(),
                            ));
                        }
                    }
                }

                let manifest_digest = crate::asic::sha256_content_digest(&container.manifest);
                validate_cades_member(artifact, container.cades_signature_der, &manifest_digest)
            }
        },
        SignatureFormat::XAdES => Err(SigningError::unsupported_xades("validation")),
    }
}

fn validate_cades_member(
    artifact: &SignatureArtifact,
    cades_signature_der: Vec<u8>,
    content_digest: &[u8; 32],
) -> Result<SignatureValidationReport, SigningError> {
    let cades_artifact = SignatureArtifact {
        id: artifact.id,
        slot: artifact.slot,
        family: artifact.family,
        format: SignatureFormat::CAdES,
        profile: artifact.profile,
        evidentiary_level: artifact.evidentiary_level,
        signed_at: artifact.signed_at,
        signature: cades_signature_der,
        trusted_list_status: artifact.trusted_list_status,
        timestamp_token_der: artifact.timestamp_token_der.clone(),
    };
    validate_signature(&cades_artifact, Some(content_digest))
}

/// Validate technical timestamp trust from already-verified RFC 3161 output and QTST details.
///
/// The caller is expected to feed `timestamp` from `chancela-tsa::verify_response` or an
/// equivalent path that has already checked the token structure, imprint/nonce binding, signed
/// attributes and TSA CMS signature value. This function then combines the embedded TSA
/// certificate material, QTST match anchors from `chancela-tsl`, optional policy-OID enforcement
/// and the offline TSA certificate-path validator into one fail-closed report.
pub fn validate_timestamp_trust(
    timestamp: &chancela_tsa::Timestamp,
    qtst: &chancela_tsl::QtstMatchDetails,
    policy: &TimestampTrustPolicy,
) -> TimestampTrustReport {
    let mut failure_reasons = Vec::new();

    let policy_oid_accepted = if policy.accepted_policy_oids.is_empty() {
        None
    } else {
        let accepted = policy
            .accepted_policy_oids
            .iter()
            .any(|oid| oid == &timestamp.policy);
        if !accepted {
            failure_reasons.push(format!(
                "timestamp policy OID {} is not configured as accepted",
                timestamp.policy
            ));
        }
        Some(accepted)
    };

    let trusted_list_status = if qtst.authenticated {
        TrustedListStatus::from(qtst.status)
    } else {
        if qtst.status == chancela_tsl::QualifiedStatus::Granted {
            failure_reasons
                .push("TSL grant is unauthenticated and was downgraded to Unknown".to_owned());
        }
        TrustedListStatus::Unknown
    };

    if trusted_list_status != TrustedListStatus::Granted {
        failure_reasons.push(format!(
            "QTST trusted-list status is {trusted_list_status:?}, not Granted"
        ));
    }

    let mut certificate_path_valid = false;
    let mut certificate_path_anchor_index = None;
    let mut certificate_path_len = None;

    match timestamp.tsa_certificate_der.as_deref() {
        Some(tsa_cert) if trusted_list_status == TrustedListStatus::Granted => {
            if qtst.trust_anchor_ders.is_empty() {
                failure_reasons
                    .push("QTST match returned no authenticated trust anchors".to_owned());
            } else {
                match chancela_tsa::validate_tsa_certificate_path(
                    tsa_cert,
                    &timestamp.embedded_certificate_ders,
                    &qtst.trust_anchor_ders,
                    timestamp.gen_time,
                ) {
                    Ok(path) => {
                        certificate_path_valid = true;
                        certificate_path_anchor_index = Some(path.trust_anchor_index);
                        certificate_path_len = Some(path.path_der.len());
                    }
                    Err(err) => {
                        failure_reasons.push(format!("TSA certificate path failed: {err}"));
                    }
                }
            }
        }
        Some(_) => {}
        None => failure_reasons
            .push("timestamp token did not expose an embedded TSA signing certificate".to_owned()),
    }

    let qtst_matches = qtst
        .matches
        .iter()
        .map(|m| TimestampQtstMatchReport {
            provider_name: m.provider_name.clone(),
            service_name: m.service_name.clone(),
            granted_and_effective: m.granted_and_effective,
            trust_anchor_count: m.trust_anchor_ders.len(),
        })
        .collect();

    TimestampTrustReport {
        decision: if failure_reasons.is_empty() {
            TimestampTrustDecision::Accepted
        } else {
            TimestampTrustDecision::Rejected
        },
        timestamp_policy_oid: timestamp.policy.clone(),
        policy_oid_accepted,
        tsa_certificate_embedded: timestamp.tsa_certificate_der.is_some(),
        embedded_certificate_count: timestamp.embedded_certificate_ders.len(),
        trusted_list_status,
        trusted_list_authenticated: qtst.authenticated,
        qtst_matches,
        trust_anchor_count: qtst.trust_anchor_ders.len(),
        certificate_path_valid,
        certificate_path_anchor_index,
        certificate_path_len,
        failure_reasons,
        scope_note: "technical timestamp trust report only; no legal qualification claim",
    }
}

/// Technical end-entity signer-trust outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignerTrustDecision {
    /// The signer certificate chained to an authenticated Trusted List anchor and every issuing
    /// link had fresh, non-revoked revocation evidence.
    Accepted,
    /// One or more technical checks failed. See [`SignerTrustReport::failure_reasons`].
    Rejected,
}

/// Technical live-trust report for an end-entity signing certificate (wp26 §2.2).
///
/// This is deliberately a **technical** report: it records the certificate-path build against a
/// live, authenticated [`chancela_tsl::TslTrustStore`] QC anchor and the per-link OCSP/CRL
/// revocation outcome. It makes no legal-qualification claim and asserts nothing about the
/// probative weight of the signature — only that, at `validation_time`, the signer chained to a
/// currently-authenticated Trusted List anchor with fresh non-revoked revocation for every link.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SignerTrustReport {
    /// The overall technical decision.
    pub decision: SignerTrustDecision,
    /// Whether a certificate path from the signer to a configured QC anchor was built.
    pub certificate_path_valid: bool,
    /// Number of certificates in the built path (leaf + intermediates + anchor), when built.
    pub certificate_path_len: Option<usize>,
    /// Whether the built path terminated at a Trusted List QC anchor. Always mirrors
    /// `certificate_path_valid`: the path builder only succeeds by reaching a configured anchor.
    pub trust_anchor_matched: bool,
    /// Whether the Trusted List the anchors came from was cryptographically authenticated
    /// (carried from [`chancela_tsl::TslTrustStore::authenticated`]). An unauthenticated store
    /// grounds no trust (fail-closed).
    pub trusted_list_authenticated: bool,
    /// Whether the Trusted List the anchors came from was served from a stale fallback cache
    /// (carried from [`chancela_tsl::TslTrustStore::stale`]). Reported, never silently upgraded.
    pub trusted_list_stale: bool,
    /// Number of issuing links whose revocation was successfully checked (returned evidence).
    pub revocation_checked_links: usize,
    /// Whether any link's revocation evidence was served stale from the offline fallback. A stale
    /// link never grounds an `Accepted` decision (fail-closed, wp26 §5 risk 4).
    pub revocation_stale: bool,
    /// Human-readable technical reasons the decision was `Rejected` (empty when `Accepted`).
    pub failure_reasons: Vec<String>,
    /// Scope note kept technical: this report carries no legal-qualification claim.
    pub scope_note: &'static str,
}

/// Scope note shared by every [`SignerTrustReport`] — deliberately technical, no legal claim.
const SIGNER_TRUST_SCOPE_NOTE: &str = "technical end-entity signer trust report only; live TSL path + revocation, no legal \
     qualification claim";

/// Compute a live end-entity signer-trust decision (wp26 §2.2).
///
/// Builds a certificate path from `signer_cert_der` (bridged by `intermediate_certs`) to a
/// **granted-and-effective QC anchor** of the authenticated `trust_store`, then checks OCSP/CRL
/// revocation for every issuing link in that built path. Crucially, the issuer used for each
/// revocation check is **resolved from the built path itself** (`certs_der[i]` is checked against
/// `certs_der[i + 1]`), never taken from the caller — so a caller cannot substitute a benign
/// issuer to dodge the real CA's revocation service.
///
/// Fail-closed rules (wp26 §5 risk 4):
/// - An **unauthenticated** trust store trusts nothing: the decision is `Rejected` without any
///   path build or network access.
/// - A path that does not reach a configured anchor (including an **empty** `qc_anchors` set, which
///   [`chancela_tsl::build_path`] rejects) is `Rejected`.
/// - A link returning a **definitive** negative (revoked / unknown / invalid / untrusted responder)
///   or a transport failure **with no cached fallback** is `Rejected`.
/// - **Stale** revocation evidence (served from the offline fallback after a live fetch failed) is
///   surfaced via `revocation_stale = true` and — because it has not been re-confirmed against the
///   CA at `validation_time` — is treated as insufficient to ground an `Accepted` decision. It
///   therefore also records a failure reason and yields `Rejected`, never a silent upgrade.
///
/// `decision` is `Accepted` only when the store was authenticated, the path was built to an anchor,
/// and every issuing link returned fresh, non-revoked revocation evidence with zero failures.
pub fn validate_signer_trust<T: RevocationHttpTransport>(
    signer_cert_der: &[u8],
    intermediate_certs: &[Vec<u8>],
    trust_store: &chancela_tsl::TslTrustStore,
    revocation: &RevocationEvidenceProvider<T>,
    cache: &RevocationCache,
    validation_time: OffsetDateTime,
) -> SignerTrustReport {
    let trusted_list_authenticated = trust_store.authenticated;
    let trusted_list_stale = trust_store.stale;

    let reject = |failure_reasons: Vec<String>,
                  certificate_path_valid: bool,
                  certificate_path_len: Option<usize>,
                  revocation_checked_links: usize,
                  revocation_stale: bool| SignerTrustReport {
        decision: SignerTrustDecision::Rejected,
        certificate_path_valid,
        certificate_path_len,
        trust_anchor_matched: certificate_path_valid,
        trusted_list_authenticated,
        trusted_list_stale,
        revocation_checked_links,
        revocation_stale,
        failure_reasons,
        scope_note: SIGNER_TRUST_SCOPE_NOTE,
    };

    // Fail-closed: anchors from an unauthenticated list MUST NOT ground a trust decision.
    if !trusted_list_authenticated {
        return reject(
            vec!["trust store is not authenticated".to_owned()],
            false,
            None,
            0,
            false,
        );
    }

    // Build the signer path to a live QC anchor. `build_path` fails closed on an empty anchor set
    // and only succeeds by reaching a configured anchor, so a successful build means the anchor was
    // matched.
    let path = match chancela_tsl::build_path(
        signer_cert_der,
        intermediate_certs,
        &trust_store.qc_anchors,
        &chancela_tsl::PathBuildOptions::at(validation_time),
    ) {
        Ok(path) => path,
        Err(err) => {
            return reject(
                vec![format!("signer certificate path failed: {err}")],
                false,
                None,
                0,
                false,
            );
        }
    };

    let certificate_path_len = Some(path.len());

    // Check revocation for each issuing link, with the issuer resolved from the built path
    // (`certs_der[i]` issued by `certs_der[i + 1]`) — never caller-supplied.
    let mut failure_reasons = Vec::new();
    let mut revocation_checked_links = 0usize;
    let mut revocation_stale = false;
    for window in path.certs_der.windows(2) {
        let subject = &window[0];
        let issuer = &window[1];
        match revocation.collect_for_signer_cached(cache, subject, issuer, validation_time) {
            Ok(evidence) => {
                revocation_checked_links += 1;
                if evidence.stale {
                    // Stale evidence was NOT re-confirmed against the CA at validation time; report
                    // it and refuse to ground trust on it (fail-closed, never a silent upgrade).
                    revocation_stale = true;
                    failure_reasons.push(format!(
                        "revocation evidence for a signer→issuer link is stale (offline \
                         fallback) and cannot ground trust: {}",
                        describe_link(subject, issuer)
                    ));
                }
            }
            Err(err) => {
                failure_reasons.push(format!(
                    "revocation check failed for a signer→issuer link ({}): {err}",
                    revocation_failure_kind(&err)
                ));
            }
        }
    }

    let decision = if failure_reasons.is_empty() {
        SignerTrustDecision::Accepted
    } else {
        SignerTrustDecision::Rejected
    };

    SignerTrustReport {
        decision,
        certificate_path_valid: true,
        certificate_path_len,
        trust_anchor_matched: true,
        trusted_list_authenticated,
        trusted_list_stale,
        revocation_checked_links,
        revocation_stale,
        failure_reasons,
        scope_note: SIGNER_TRUST_SCOPE_NOTE,
    }
}

/// Short, stable classification of a revocation failure for the report (no URLs/PII).
fn revocation_failure_kind(err: &RevocationError) -> &'static str {
    if err.is_transport_failure() {
        "unavailable with no cached fallback"
    } else {
        match err {
            RevocationError::OcspSignerRevoked { .. } | RevocationError::SignerRevoked { .. } => {
                "revoked"
            }
            RevocationError::OcspSignerUnknown { .. } => "unknown status",
            _ => "definitive check failure",
        }
    }
}

/// A short, non-identifying description of a path link for diagnostics — the SHA-256 prefixes of
/// the subject and issuer DER, so the message stays stable and carries no certificate contents.
fn describe_link(subject_der: &[u8], issuer_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let subject = Sha256::digest(subject_der);
    let issuer = Sha256::digest(issuer_der);
    format!(
        "subject {:02x}{:02x}… issued by {:02x}{:02x}…",
        subject[0], subject[1], issuer[0], issuer[1]
    )
}

#[cfg(test)]
mod signer_trust_tests {
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration as StdDuration, UNIX_EPOCH};

    use der::asn1::{Any, BitString, Ia5String, OctetString};
    use der::oid::ObjectIdentifier;
    use der::{Decode, Encode};
    use rsa::pkcs8::EncodePublicKey;
    use rsa::rand_core::OsRng;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
    use sha2::{Digest, Sha256};
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use time::OffsetDateTime;
    use x509_cert::certificate::{Certificate, TbsCertificate, Version};
    use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::crl::CrlDistributionPoints;
    use x509_cert::ext::pkix::crl::dp::DistributionPoint;
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    use chancela_tsl::TslTrustStore;

    use super::{SignerTrustDecision, validate_signer_trust};
    use crate::{
        RevocationCache, RevocationError, RevocationEvidenceProvider, RevocationFetchLimits,
        RevocationHttpResponse, RevocationHttpTransport,
    };

    const T: u64 = 1_750_000_000;
    const DAY: u64 = 86_400;
    const CRL_URL: &str = "http://crl.example/signer.crl";

    const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
    const OID_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
    const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    // --- Mock transport --------------------------------------------------------------------------

    /// A CRL transport that returns a fixed CRL, or a forced transport failure when `fail` is set —
    /// modelling a responder going offline. It exposes no OCSP endpoint (the test signer advertises
    /// only a CRL distribution point).
    #[derive(Clone)]
    struct MockCrlTransport {
        crl_der: Vec<u8>,
        fail: Arc<AtomicBool>,
    }

    impl RevocationHttpTransport for MockCrlTransport {
        fn get_crl(
            &self,
            _url: &str,
            _limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(RevocationError::Http("forced offline".to_string()));
            }
            Ok(RevocationHttpResponse {
                status: 200,
                body: self.crl_der.clone(),
            })
        }

        fn post_ocsp(
            &self,
            _url: &str,
            _request_der: &[u8],
            _limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            panic!("signer-trust tests advertise only a CRL distribution point")
        }
    }

    /// A transport that must never be reached (used where the decision is taken before any network
    /// access — unauthenticated store, empty anchors).
    #[derive(Clone)]
    struct PanicTransport;

    impl RevocationHttpTransport for PanicTransport {
        fn get_crl(
            &self,
            _url: &str,
            _limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            panic!("revocation transport must not be reached")
        }

        fn post_ocsp(
            &self,
            _url: &str,
            _request_der: &[u8],
            _limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            panic!("revocation transport must not be reached")
        }
    }

    // --- Cert / CRL minting (real RSA-SHA256 signatures) -----------------------------------------

    fn sha256_rsa_alg() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: SHA256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        }
    }

    fn rsa_key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa key")
    }

    fn spki_of(key: &RsaPrivateKey) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned::from_der(
            RsaPublicKey::from(key)
                .to_public_key_der()
                .expect("public key der")
                .as_bytes(),
        )
        .expect("spki")
    }

    fn rsa_sign(key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
        let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
        digest_info.extend_from_slice(&Sha256::digest(message));
        key.sign(Pkcs1v15Sign::new_unprefixed(), &digest_info)
            .expect("rsa sign")
    }

    fn time_at(unix: u64) -> Time {
        Time::try_from(UNIX_EPOCH + StdDuration::from_secs(unix)).expect("time")
    }

    fn time_at_dt(dt: OffsetDateTime) -> Time {
        let secs = dt.unix_timestamp();
        assert!(secs >= 0, "test times are post-epoch");
        time_at(secs as u64)
    }

    fn extension(oid: ObjectIdentifier, critical: bool, value: Vec<u8>) -> Extension {
        Extension {
            extn_id: oid,
            critical,
            extn_value: OctetString::new(value).expect("extension value"),
        }
    }

    fn ca_extensions() -> Vec<Extension> {
        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        let ku = KeyUsage(KeyUsages::KeyCertSign.into());
        vec![
            extension(OID_BASIC_CONSTRAINTS, true, bc.to_der().expect("bc der")),
            extension(OID_KEY_USAGE, true, ku.to_der().expect("ku der")),
        ]
    }

    fn cdp_extension(url: &str) -> Extension {
        let cdp = CrlDistributionPoints(vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![
                GeneralName::UniformResourceIdentifier(Ia5String::new(url).expect("ia5 uri")),
            ])),
            reasons: None,
            crl_issuer: None,
        }]);
        extension(
            OID_CRL_DISTRIBUTION_POINTS,
            false,
            cdp.to_der().expect("cdp der"),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn make_cert(
        subject_cn: &str,
        serial: u8,
        subject_key: &RsaPrivateKey,
        issuer_name: &Name,
        issuer_key: &RsaPrivateKey,
        extensions: Vec<Extension>,
        not_before: u64,
        not_after: u64,
    ) -> Vec<u8> {
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[serial]).expect("serial"),
            signature: sha256_rsa_alg(),
            issuer: issuer_name.clone(),
            validity: Validity {
                not_before: time_at(not_before),
                not_after: time_at(not_after),
            },
            subject: Name::from_str(&format!("CN={subject_cn}")).expect("subject name"),
            subject_public_key_info: spki_of(subject_key),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: (!extensions.is_empty()).then_some(extensions),
        };
        let tbs_der = tbs.to_der().expect("tbs der");
        let signature = rsa_sign(issuer_key, &tbs_der);
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sha256_rsa_alg(),
            signature: BitString::from_bytes(&signature).expect("signature bits"),
        }
        .to_der()
        .expect("cert der")
    }

    /// A CA anchor: its key, its distinguished name, and its self-signed DER.
    struct Anchor {
        key: RsaPrivateKey,
        name: Name,
        der: Vec<u8>,
    }

    fn anchor_ca() -> Anchor {
        let key = rsa_key();
        let name = Name::from_str("CN=Chancela QC Anchor").expect("anchor name");
        let der = make_cert(
            "Chancela QC Anchor",
            1,
            &key,
            &name,
            &key,
            ca_extensions(),
            T - DAY,
            T + DAY,
        );
        Anchor { key, name, der }
    }

    /// An end-entity signer (serial 7) issued by `anchor`, advertising a single HTTP CRL
    /// distribution point.
    fn signer_under(anchor: &Anchor) -> Vec<u8> {
        let key = rsa_key();
        make_cert(
            "Chancela Signer",
            7,
            &key,
            &anchor.name,
            &anchor.key,
            vec![cdp_extension(CRL_URL)],
            T - DAY,
            T + DAY,
        )
    }

    /// Build a DER CRL issued (and signed) by `anchor`, optionally revoking the signer serial.
    fn build_signed_crl(
        anchor: &Anchor,
        this_update: OffsetDateTime,
        next_update: OffsetDateTime,
        revoke_signer: bool,
    ) -> Vec<u8> {
        let revoked_certificates = revoke_signer.then(|| {
            vec![RevokedCert {
                serial_number: SerialNumber::new(&[7]).expect("revoked serial"),
                revocation_date: time_at_dt(this_update),
                crl_entry_extensions: None,
            }]
        });
        let tbs = TbsCertList {
            version: Version::V2,
            signature: sha256_rsa_alg(),
            issuer: anchor.name.clone(),
            this_update: time_at_dt(this_update),
            next_update: Some(time_at_dt(next_update)),
            revoked_certificates,
            crl_extensions: None,
        };
        let tbs_der = tbs.to_der().expect("crl tbs der");
        let signature = rsa_sign(&anchor.key, &tbs_der);
        CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: sha256_rsa_alg(),
            signature: BitString::from_bytes(&signature).expect("crl signature bits"),
        }
        .to_der()
        .expect("crl der")
    }

    fn base_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(T as i64).expect("validation time")
    }

    /// An authenticated, non-stale store whose single QC anchor is `anchor`.
    fn authenticated_store(anchor: &Anchor) -> TslTrustStore {
        let mut store = TslTrustStore::default();
        store.qc_anchors = vec![anchor.der.clone()];
        store.authenticated = true;
        store.stale = false;
        store
    }

    fn crl_provider(crl_der: Vec<u8>, fail: bool) -> RevocationEvidenceProvider<MockCrlTransport> {
        RevocationEvidenceProvider::new(
            MockCrlTransport {
                crl_der,
                fail: Arc::new(AtomicBool::new(fail)),
            },
            RevocationFetchLimits::default(),
        )
    }

    // --- Tests -----------------------------------------------------------------------------------

    #[test]
    fn unauthenticated_trust_store_is_rejected_without_trusting() {
        let anchor = anchor_ca();
        let signer = signer_under(&anchor);
        // Anchors present, but the list was never authenticated.
        let mut store = authenticated_store(&anchor);
        store.authenticated = false;

        let provider =
            RevocationEvidenceProvider::new(PanicTransport, RevocationFetchLimits::default());
        let cache = RevocationCache::new();

        let report = validate_signer_trust(&signer, &[], &store, &provider, &cache, base_time());

        assert_eq!(report.decision, SignerTrustDecision::Rejected);
        assert!(!report.certificate_path_valid);
        assert!(!report.trust_anchor_matched);
        assert!(!report.trusted_list_authenticated);
        assert_eq!(report.revocation_checked_links, 0);
        assert!(
            report
                .failure_reasons
                .iter()
                .any(|r| r.contains("not authenticated"))
        );
    }

    #[test]
    fn empty_qc_anchors_is_rejected_fail_closed() {
        let anchor = anchor_ca();
        let signer = signer_under(&anchor);
        let mut store = authenticated_store(&anchor);
        store.qc_anchors.clear();

        let provider =
            RevocationEvidenceProvider::new(PanicTransport, RevocationFetchLimits::default());
        let cache = RevocationCache::new();

        let report = validate_signer_trust(&signer, &[], &store, &provider, &cache, base_time());

        assert_eq!(report.decision, SignerTrustDecision::Rejected);
        assert!(!report.certificate_path_valid);
        assert!(!report.trust_anchor_matched);
        assert!(!report.failure_reasons.is_empty());
        assert_eq!(report.revocation_checked_links, 0);
    }

    #[test]
    fn signer_chaining_to_anchor_with_good_crl_is_accepted() {
        let anchor = anchor_ca();
        let signer = signer_under(&anchor);
        let store = authenticated_store(&anchor);
        let now = base_time();
        let crl = build_signed_crl(
            &anchor,
            now - time::Duration::hours(1),
            now + time::Duration::hours(24),
            false,
        );
        let provider = crl_provider(crl, false);
        let cache = RevocationCache::new();

        let report = validate_signer_trust(&signer, &[], &store, &provider, &cache, now);

        assert_eq!(report.decision, SignerTrustDecision::Accepted, "{report:?}");
        assert!(report.certificate_path_valid);
        assert!(report.trust_anchor_matched);
        assert_eq!(report.certificate_path_len, Some(2));
        assert_eq!(report.revocation_checked_links, 1);
        assert!(!report.revocation_stale);
        assert!(report.failure_reasons.is_empty());
    }

    #[test]
    fn definitively_revoked_link_is_rejected() {
        let anchor = anchor_ca();
        let signer = signer_under(&anchor);
        let store = authenticated_store(&anchor);
        let now = base_time();
        let crl = build_signed_crl(
            &anchor,
            now - time::Duration::hours(1),
            now + time::Duration::hours(24),
            true, // revokes the signer serial
        );
        let provider = crl_provider(crl, false);
        let cache = RevocationCache::new();

        let report = validate_signer_trust(&signer, &[], &store, &provider, &cache, now);

        assert_eq!(report.decision, SignerTrustDecision::Rejected);
        // The path itself was valid; the rejection is due to revocation.
        assert!(report.certificate_path_valid);
        assert!(report.trust_anchor_matched);
        assert!(!report.revocation_stale);
        assert_eq!(
            report.revocation_checked_links, 0,
            "revoked link is not a completed check"
        );
        assert!(report.failure_reasons.iter().any(|r| r.contains("revoked")));
    }

    #[test]
    fn offline_fallback_stale_evidence_is_reported_and_never_silently_upgraded() {
        let anchor = anchor_ca();
        let signer = signer_under(&anchor);
        let store = authenticated_store(&anchor);
        let now = base_time();
        // CRL nextUpdate is only one hour out, so the cache entry expires before `later`.
        let crl = build_signed_crl(
            &anchor,
            now - time::Duration::hours(1),
            now + time::Duration::hours(1),
            false,
        );
        let fail = Arc::new(AtomicBool::new(false));
        let provider = RevocationEvidenceProvider::new(
            MockCrlTransport {
                crl_der: crl,
                fail: fail.clone(),
            },
            RevocationFetchLimits::default(),
        );
        let cache = RevocationCache::new();

        // Populate the last-good cache entry with a fresh fetch (issuer resolved as the anchor).
        provider
            .collect_for_signer_cached(&cache, &signer, &anchor.der, now)
            .expect("fresh fetch seeds the cache");
        assert_eq!(cache.len(), 1);

        // Responder goes offline; the cached entry is now expired -> graceful stale fallback.
        fail.store(true, Ordering::SeqCst);
        let later = now + time::Duration::hours(2);
        let report = validate_signer_trust(&signer, &[], &store, &provider, &cache, later);

        assert!(report.revocation_stale, "stale fallback must be reported");
        assert_eq!(
            report.revocation_checked_links, 1,
            "the stale link still returned evidence"
        );
        // Documented rule: stale evidence is not fresh confirmation, so it cannot ground trust.
        assert_eq!(
            report.decision,
            SignerTrustDecision::Rejected,
            "stale evidence must never silently upgrade to Accepted"
        );
        assert!(report.certificate_path_valid);
        assert!(report.failure_reasons.iter().any(|r| r.contains("stale")));
    }
}
