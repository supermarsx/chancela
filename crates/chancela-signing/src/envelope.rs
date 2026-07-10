//! The envelope engine: drive serial and parallel multi-signatory collection over a
//! [`SignatureEnvelope`] (SIG-31), producing evidentiary-labelled [`SignatureArtifact`]s.
//!
//! Each artifact records the [`SignatureArtifact::slot`] it fills, so a parallel envelope can be
//! completed in any order while a serial one is enforced to fill slots in sequence. Signing one
//! slot runs the full pipeline for that request: the trusted-list policy gate (SIG-11/23), the
//! CAdES/PAdES signature (SIG-01/20/21), and an optional qualified timestamp (SIG-22).

use time::OffsetDateTime;
use uuid::Uuid;

use chancela_pades::SignOptions;

use crate::asic::AsicPayload;
use crate::pipeline::{self, TimestampProvider};
use crate::policy::TrustPolicy;
use crate::provider::SignerProvider;
use crate::{
    BaselineProfile, EvidentiaryLevel, SignatureArtifact, SignatureEnvelope, SignatureFormat,
    SigningError, SigningFamily, SigningOrder, TrustedListStatus,
};

/// The document being signed for one slot: a precomputed content digest (detached CAdES), the PDF
/// bytes to sign in place (PAdES), one named payload to package in ASiC-S, or multiple payloads to
/// package in ASiC-E/CAdES.
#[derive(Debug, Clone, Copy)]
pub enum DocumentInput<'a> {
    /// A SHA-256 content digest — for a detached [`SignatureFormat::CAdES`] signature.
    Digest(&'a [u8; 32]),
    /// The PDF bytes — for an in-place [`SignatureFormat::PAdES`] signature.
    Pdf(&'a [u8]),
    /// One payload file to package in a bounded ASiC-S/CAdES container.
    AsicContent {
        /// The payload member name inside the ASiC ZIP container.
        name: &'a str,
        /// The payload bytes to hash, sign with detached CAdES-B, and package.
        bytes: &'a [u8],
    },
    /// One or more payload files to package in a bounded ASiC-E/CAdES container.
    AsicPayloads(&'a [AsicPayload<'a>]),
}

/// Everything needed to sign one envelope slot, beyond the envelope and the slot index.
pub struct SigningJob<'a> {
    /// The signing device/service for this slot; its family must match the request's.
    pub provider: &'a dyn SignerProvider,
    /// An optional trusted-list policy gate (SIG-11/23). When present, a qualified family whose
    /// issuer is not `Granted` is rejected; when absent, the trust check is skipped.
    pub policy: Option<&'a mut dyn TrustPolicy>,
    /// An optional qualified-timestamp source (SIG-22). Applied when the requested profile is B-T
    /// or above.
    pub tsa: Option<&'a dyn TimestampProvider>,
    /// The document to sign.
    pub input: DocumentInput<'a>,
    /// The signing time recorded in the CAdES signed attributes (must be stable across the flow).
    pub signing_time: OffsetDateTime,
    /// PAdES `/Sig` dictionary options (ignored for detached CAdES).
    pub pdf_options: SignOptions,
}

/// The slots that may be signed next given the envelope's order and what is already filled.
///
/// For [`SigningOrder::Parallel`], every unfilled slot; for [`SigningOrder::Serial`], the single
/// next unfilled slot (empty when complete).
pub fn pending_slots(envelope: &SignatureEnvelope) -> Vec<usize> {
    let unfilled = || (0..envelope.requests.len()).filter(|s| envelope.artifact_for(*s).is_none());
    match envelope.order {
        SigningOrder::Parallel => unfilled().collect(),
        SigningOrder::Serial => unfilled().next().into_iter().collect(),
    }
}

/// Whether every slot in the envelope has been signed.
pub fn is_complete(envelope: &SignatureEnvelope) -> bool {
    (0..envelope.requests.len()).all(|s| envelope.artifact_for(s).is_some())
}

/// The next unfilled slot in serial order, if any.
fn next_serial_slot(envelope: &SignatureEnvelope) -> Option<usize> {
    (0..envelope.requests.len()).find(|s| envelope.artifact_for(*s).is_none())
}

/// Validate that `slot` may be filled now: in range, not already signed, and (serial) in order.
fn ensure_slot_allowed(envelope: &SignatureEnvelope, slot: usize) -> Result<(), SigningError> {
    if slot >= envelope.requests.len() {
        return Err(SigningError::SlotOutOfRange {
            slot,
            len: envelope.requests.len(),
        });
    }
    if envelope.artifact_for(slot).is_some() {
        return Err(SigningError::SlotAlreadySigned(slot));
    }
    if envelope.order == SigningOrder::Serial {
        // `next_serial_slot` is Some here because `slot` itself is unfilled.
        let expected = next_serial_slot(envelope).expect("an unfilled slot exists");
        if slot != expected {
            return Err(SigningError::SlotOrder {
                expected,
                got: slot,
            });
        }
    }
    Ok(())
}

/// Sign envelope `slot` with `job`, appending the produced [`SignatureArtifact`] to the envelope.
///
/// Enforces slot order (SIG-31), matches the provider's family to the request, applies the
/// trusted-list policy gate for qualified families (SIG-11/23), produces the CAdES/PAdES signature
/// (SIG-01/20/21), optionally attaches a qualified timestamp (SIG-22), and labels the artifact's
/// evidentiary level (SIG-01/02). `Manual` slots must use [`record_manual_signature`] instead.
pub fn sign_slot(
    envelope: &mut SignatureEnvelope,
    slot: usize,
    job: SigningJob<'_>,
) -> Result<(), SigningError> {
    ensure_slot_allowed(envelope, slot)?;
    let request = envelope.requests[slot].clone();

    if request.family == SigningFamily::Manual {
        return Err(SigningError::WrongSigningPath {
            family: SigningFamily::Manual,
        });
    }

    let SigningJob {
        provider,
        policy,
        tsa,
        input,
        signing_time,
        pdf_options,
    } = job;

    if provider.family() != request.family {
        return Err(SigningError::FamilyMismatch {
            requested: request.family,
            provided: provider.family(),
        });
    }

    // Trusted-list policy gate (SIG-11/23): a qualified signature must not be trusted unless its
    // issuer is currently granted. Skipped entirely when no policy is supplied.
    let trusted_list_status = if let Some(policy) = policy {
        let issuer = provider
            .issuer_certificate_der()?
            .ok_or(SigningError::MissingIssuerCertificate)?;
        let status = policy.issuer_status(&issuer, signing_time)?;
        if status != TrustedListStatus::Granted {
            return Err(SigningError::UntrustedService { status });
        }
        Some(status)
    } else {
        None
    };

    // Produce the signature and reach the highest supported profile for the request.
    let want_timestamp = request.profile.requires_timestamp();
    let (bytes, profile, timestamp_token_der) = match (request.format, input) {
        (SignatureFormat::PAdES, DocumentInput::Pdf(pdf)) => {
            let signed = pipeline::sign_pdf_pades(provider, pdf, signing_time, &pdf_options)?;
            match (want_timestamp, tsa) {
                (true, Some(tsa)) => {
                    let (stamped, token) = pipeline::timestamp_pdf(&signed, tsa)?;
                    (stamped, BaselineProfile::B_T, Some(token))
                }
                _ => (signed, BaselineProfile::B_B, None),
            }
        }
        (SignatureFormat::CAdES, DocumentInput::Digest(content_digest)) => {
            let cms = pipeline::sign_detached_cades(provider, content_digest, signing_time)?;
            // In-CMS B-T embedding for detached CAdES is a phase-2 seam (it needs the `cms`/`der`
            // surgery `chancela-pades` does for PDFs). When a TSA is supplied we still capture the
            // token as external archival evidence, keeping the profile honestly at B-B.
            let token = match (want_timestamp, tsa) {
                (true, Some(tsa)) => Some(tsa.timestamp_data(&cms)?.token_der),
                _ => None,
            };
            (cms, BaselineProfile::B_B, token)
        }
        (SignatureFormat::ASiC, DocumentInput::AsicContent { name, bytes }) => {
            let (container, cades) = pipeline::sign_asic_s(provider, name, bytes, signing_time)?;
            // ASiC-S/CAdES generation is bounded to B-B. As with detached CAdES, a requested
            // timestamp is captured only as external evidence; it is not embedded in the ASiC ZIP
            // and does not upgrade the reported baseline profile.
            let token = match (want_timestamp, tsa) {
                (true, Some(tsa)) => Some(tsa.timestamp_data(&cades)?.token_der),
                _ => None,
            };
            (container, BaselineProfile::B_B, token)
        }
        (SignatureFormat::ASiC, DocumentInput::AsicPayloads(payloads)) => {
            let (container, cades) = pipeline::sign_asic_e(provider, payloads, signing_time)?;
            // ASiC-E/CAdES generation is bounded to B-B: the CAdES signature covers the
            // ASiCManifest, whose digest entries bind the payload files. A requested timestamp is
            // external evidence and does not upgrade the reported profile.
            let token = match (want_timestamp, tsa) {
                (true, Some(tsa)) => Some(tsa.timestamp_data(&cades)?.token_der),
                _ => None,
            };
            (container, BaselineProfile::B_B, token)
        }
        (SignatureFormat::PAdES, _) => {
            return Err(SigningError::FormatInputMismatch {
                format: SignatureFormat::PAdES,
            });
        }
        (SignatureFormat::CAdES, _) => {
            return Err(SigningError::FormatInputMismatch {
                format: SignatureFormat::CAdES,
            });
        }
        (SignatureFormat::ASiC, _) => {
            return Err(SigningError::FormatInputMismatch {
                format: SignatureFormat::ASiC,
            });
        }
        (other, _) => return Err(SigningError::UnsupportedFormat(other)),
    };

    let artifact = SignatureArtifact {
        id: Uuid::new_v4(),
        slot,
        family: request.family,
        format: request.format,
        profile,
        evidentiary_level: provider.evidentiary_level(),
        signed_at: Some(signing_time),
        signature: bytes,
        trusted_list_status,
        timestamp_token_der,
    };
    envelope.artifacts.push(artifact);
    Ok(())
}

/// Record a manual (handwritten, scanned) signature for a `Manual` slot (SIG-01/03).
///
/// No cryptography is performed: the artifact is labelled [`EvidentiaryLevel::HandwrittenScanned`]
/// and carries the scan bytes. The caller is responsible for surfacing [`crate::MANUAL_WARNING`].
pub fn record_manual_signature(
    envelope: &mut SignatureEnvelope,
    slot: usize,
    scan: Vec<u8>,
    signed_at: OffsetDateTime,
) -> Result<(), SigningError> {
    ensure_slot_allowed(envelope, slot)?;
    let request = &envelope.requests[slot];
    if request.family != SigningFamily::Manual {
        return Err(SigningError::WrongSigningPath {
            family: request.family,
        });
    }
    let format = request.format;
    let artifact = SignatureArtifact {
        id: Uuid::new_v4(),
        slot,
        family: SigningFamily::Manual,
        format,
        // A manual scan reaches no ETSI baseline profile; B-B is the least-overclaiming placeholder.
        profile: BaselineProfile::B_B,
        evidentiary_level: EvidentiaryLevel::HandwrittenScanned,
        signed_at: Some(signed_at),
        signature: scan,
        trusted_list_status: None,
        timestamp_token_der: None,
    };
    envelope.artifacts.push(artifact);
    Ok(())
}
