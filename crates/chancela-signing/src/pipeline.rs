//! The signing pipeline: turn a [`SignerProvider`]'s [`RawSignature`](chancela_cades::RawSignature)
//! into a detached CAdES-B `SignedData` (via `chancela-cades`) or a PAdES-B signed PDF (via
//! `chancela-pades`), with an optional qualified RFC 3161 timestamp (via `chancela-tsa`).
//!
//! `chancela-pades` and `chancela-cades` own the wire formats; this module owns the *composition*:
//! it fetches the signer certificate, builds the signed-attributes digest, asks the provider to
//! sign it, and wraps the result. That is the "closure contract" `chancela-pades` was designed
//! around (t4-e7): `sign_cms(byterange_digest) = signed_attributes_digest → provider-sign →
//! assemble_cades_b`.

use time::OffsetDateTime;

use chancela_cades::{assemble_cades_b, signed_attributes_digest};
use chancela_pades::archive_timestamp::add_doc_timestamp_revision_with;
use chancela_pades::renewal::{LtvRenewalExecution, execute_ltv_renewal};
use chancela_pades::{
    DocTimeStampReport, DssEvidence, DssReport, SignOptions, add_dss_revision,
    add_dss_revision_with_validation_time, add_signature_timestamp, inspect_doc_timestamps,
    inspect_dss, sign_pdf,
};
use chancela_tsa::{HttpTsaTransport, Timestamp, TimestampRequest, TsaClient, TsaTransport};

use crate::SigningError;
use crate::asic::{
    ASICE_CADES_SIGNATURE_PATH, AsicPayload, build_asic_e_manifest, create_asic_e_container,
    create_asic_s_container, sha256_content_digest,
};
use crate::provider::SignerProvider;
use crate::revocation::{
    RevocationError, RevocationEvidence, RevocationEvidenceProvider, RevocationHttpTransport,
};

/// A source of qualified timestamps (SIG-22), abstracted so the envelope engine can hold it as
/// `&dyn TimestampProvider` and so tests can inject a `chancela-tsa` mock.
pub trait TimestampProvider {
    /// Timestamp a precomputed SHA-256 digest.
    fn timestamp_digest(&self, digest: &[u8; 32]) -> Result<Timestamp, SigningError>;

    /// Timestamp arbitrary data (hashed with SHA-256 by the TSA layer).
    fn timestamp_data(&self, data: &[u8]) -> Result<Timestamp, SigningError>;
}

impl<T: TsaTransport> TimestampProvider for TsaClient<T> {
    fn timestamp_digest(&self, digest: &[u8; 32]) -> Result<Timestamp, SigningError> {
        self.timestamp(*digest)
            .map_err(|e| SigningError::Timestamp(e.to_string()))
    }

    fn timestamp_data(&self, data: &[u8]) -> Result<Timestamp, SigningError> {
        self.stamp(&TimestampRequest::over_data(data).with_generated_nonce())
            .map_err(|e| SigningError::Timestamp(e.to_string()))
    }
}

/// Produce a detached CAdES-B `SignedData` (DER `ContentInfo`) over `content_digest` using
/// `provider` (SIG-01). `content_digest` is the SHA-256 of the detached content.
pub fn sign_detached_cades(
    provider: &dyn SignerProvider,
    content_digest: &[u8; 32],
    signing_time: OffsetDateTime,
) -> Result<Vec<u8>, SigningError> {
    let cert_der = provider.signing_certificate_der()?;
    let signed_attrs_digest =
        signed_attributes_digest(content_digest, &cert_der, signing_time).map_err(cades_err)?;
    let raw = provider.sign_signed_attributes(&signed_attrs_digest)?;
    assemble_cades_b(&raw, content_digest, signing_time).map_err(cades_err)
}

/// Produce a bounded ASiC-S/CAdES container over one payload.
///
/// Returns the ASiC ZIP bytes plus the detached CAdES-B CMS bytes stored at
/// `META-INF/signatures.p7s`, so callers that attach external timestamp evidence can timestamp the
/// exact CMS signature object without claiming an in-container B-T profile.
pub fn sign_asic_s(
    provider: &dyn SignerProvider,
    content_name: &str,
    content: &[u8],
    signing_time: OffsetDateTime,
) -> Result<(Vec<u8>, Vec<u8>), SigningError> {
    let content_digest = sha256_content_digest(content);
    let cades = sign_detached_cades(provider, &content_digest, signing_time)?;
    let container = create_asic_s_container(content_name, content, &cades)?;
    Ok((container, cades))
}

/// Produce a bounded ASiC-E/CAdES container over one or more payloads.
///
/// The CAdES signature covers the generated `META-INF/ASiCManifest.xml`; that manifest records
/// one SHA-256 digest per payload. This is a technical ASiC-E/CAdES container only and does not
/// claim long-term or legal sufficiency.
pub fn sign_asic_e(
    provider: &dyn SignerProvider,
    payloads: &[AsicPayload<'_>],
    signing_time: OffsetDateTime,
) -> Result<(Vec<u8>, Vec<u8>), SigningError> {
    let manifest = build_asic_e_manifest(payloads, ASICE_CADES_SIGNATURE_PATH)?;
    let manifest_digest = sha256_content_digest(&manifest);
    let cades = sign_detached_cades(provider, &manifest_digest, signing_time)?;
    let container = create_asic_e_container(payloads, &cades)?;
    Ok((container, cades))
}

/// Sign an existing PDF, producing a PAdES-B-B signed PDF (SIG-21) using `provider`.
///
/// `chancela-pades` computes the `/ByteRange` digest and hands it to our closure, which builds the
/// detached CMS via `chancela-cades` — pades owns the PDF mechanics, we own the CMS assembly.
pub fn sign_pdf_pades(
    provider: &dyn SignerProvider,
    pdf: &[u8],
    signing_time: OffsetDateTime,
    options: &SignOptions,
) -> Result<Vec<u8>, SigningError> {
    let cert_der = provider.signing_certificate_der()?;
    sign_pdf(pdf, options, |byterange_digest: &[u8; 32]| {
        let signed_attrs_digest =
            signed_attributes_digest(byterange_digest, &cert_der, signing_time)
                .map_err(cades_err)?;
        let raw = provider.sign_signed_attributes(&signed_attrs_digest)?;
        assemble_cades_b(&raw, byterange_digest, signing_time).map_err(cades_err)
    })
    .map_err(pades_err)
}

/// Upgrade a PAdES-B-B signed PDF to PAdES-B-T by embedding a qualified signature timestamp
/// (SIG-22). Returns the new PDF and the timestamp token DER (for the artifact's evidence record).
pub fn timestamp_pdf(
    signed_pdf: &[u8],
    tsa: &dyn TimestampProvider,
) -> Result<(Vec<u8>, Vec<u8>), SigningError> {
    use std::cell::RefCell;
    // `add_signature_timestamp` hands us the SHA-256 of the CMS signature value and takes the
    // produced token; we capture the token DER on the side for the artifact's evidence record.
    let captured: RefCell<Option<Vec<u8>>> = RefCell::new(None);
    let out = add_signature_timestamp(signed_pdf, |sig_digest: &[u8; 32]| {
        let ts = tsa.timestamp_digest(sig_digest)?;
        *captured.borrow_mut() = Some(ts.token_der.clone());
        Ok::<Timestamp, SigningError>(ts)
    })
    .map_err(pades_err)?;
    let token = captured
        .into_inner()
        .ok_or_else(|| SigningError::Timestamp("timestamp callback did not run".to_string()))?;
    Ok((out, token))
}

/// Upgrade a PAdES-B-B signed PDF to PAdES-B-T using an HTTP RFC 3161 TSA endpoint URL.
pub fn timestamp_pdf_with_url(
    signed_pdf: &[u8],
    tsa_url: &str,
) -> Result<(Vec<u8>, Vec<u8>), SigningError> {
    let transport =
        HttpTsaTransport::new(tsa_url).map_err(|e| SigningError::Timestamp(e.to_string()))?;
    let client = TsaClient::new(transport);
    use std::cell::RefCell;
    // B-T only needs the signature timestamp token. Certificate/revocation material belongs to
    // B-LT/B-LTA, which this adapter deliberately does not claim to collect.
    let captured: RefCell<Option<Vec<u8>>> = RefCell::new(None);
    let out = add_signature_timestamp(signed_pdf, |sig_digest: &[u8; 32]| {
        let request = TimestampRequest::new(*sig_digest)
            .with_generated_nonce()
            .without_certificate();
        let ts = client
            .stamp(&request)
            .map_err(|e| SigningError::Timestamp(e.to_string()))?;
        *captured.borrow_mut() = Some(ts.token_der.clone());
        Ok::<Timestamp, SigningError>(ts)
    })
    .map_err(pades_err)?;
    let token = captured
        .into_inner()
        .ok_or_else(|| SigningError::Timestamp("timestamp callback did not run".to_string()))?;
    Ok((out, token))
}

/// Append caller-supplied DSS/VRI evidence to a signed PAdES PDF.
///
/// This is a thin orchestration wrapper only: `chancela-pades` owns the PDF update and DSS report,
/// and this function does not fetch revocation data or claim legal B-LT sufficiency.
pub fn attach_pdf_dss(
    signed_pdf: &[u8],
    evidence: &DssEvidence,
) -> Result<(Vec<u8>, DssReport), SigningError> {
    let out = add_dss_revision(signed_pdf, evidence).map_err(pades_err)?;
    let report = inspect_dss(&out).map_err(pades_err)?;
    Ok((out, report))
}

/// Append caller-supplied DSS/VRI evidence with caller-supplied validation-time metadata.
///
/// This only formats the already-validated API timestamp for the PAdES `/TU` writer. It does not
/// fetch OCSP/CRL/TSA/trust data and does not claim legal B-LT sufficiency.
pub fn attach_pdf_dss_with_validation_time(
    signed_pdf: &[u8],
    evidence: &DssEvidence,
    validation_time: OffsetDateTime,
) -> Result<(Vec<u8>, DssReport), SigningError> {
    let validation_time = validation_time
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| SigningError::Pades(format!("invalid DSS validation time: {e}")))?;
    let out = add_dss_revision_with_validation_time(signed_pdf, evidence, &validation_time)
        .map_err(pades_err)?;
    let report = inspect_dss(&out).map_err(pades_err)?;
    Ok((out, report))
}

/// Append validated CRL revocation evidence to a signed PAdES PDF.
///
/// The supplied evidence must already have been validated by
/// [`RevocationEvidenceProvider`](crate::RevocationEvidenceProvider). This records local DSS/VRI
/// material plus `/TU` validation-time metadata only; it does not mark the artifact as B-LT or
/// make a legal long-term-validation sufficiency claim.
pub fn attach_pdf_revocation_evidence(
    signed_pdf: &[u8],
    evidence: &RevocationEvidence,
) -> Result<(Vec<u8>, DssReport), SigningError> {
    let validation_time = evidence
        .validation_time
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| SigningError::Pades(format!("invalid revocation validation time: {e}")))?;
    let out = add_dss_revision_with_validation_time(signed_pdf, &evidence.dss, &validation_time)
        .map_err(pades_err)?;
    let report = inspect_dss(&out).map_err(pades_err)?;
    Ok((out, report))
}

/// Fetch validated revocation evidence for the signer chain and embed it as a PAdES `/DSS` + `/VRI`
/// revision with `/TU` validation-time metadata — the long-term-validation material of PAdES-B-LT.
///
/// Unlike [`attach_pdf_revocation_evidence`] (which embeds already-collected evidence), this drives
/// the real fetch: [`RevocationEvidenceProvider::collect_for_signer`] pulls OCSP/CRL over the
/// (mockable) transport and validates issuer/responder trust, freshness, status, and signatures
/// before anything is embedded. The returned [`RevocationEvidence`] records exactly which validated
/// material was written. This embeds genuine LT evidence; it does not on its own make a legal
/// long-term-validation sufficiency claim (TSA/trust-list qualification stays a trust-layer job).
pub fn attach_pdf_lt<T: RevocationHttpTransport>(
    signed_pdf: &[u8],
    signer_cert_der: &[u8],
    issuer_cert_der: &[u8],
    revocation: &RevocationEvidenceProvider<T>,
    validation_time: OffsetDateTime,
) -> Result<(Vec<u8>, DssReport, RevocationEvidence), SigningError> {
    let evidence = revocation
        .collect_for_signer(signer_cert_der, issuer_cert_der, validation_time)
        .map_err(revocation_err)?;
    let (out, report) = attach_pdf_revocation_evidence(signed_pdf, &evidence)?;
    Ok((out, report, evidence))
}

/// Produce a PAdES document timestamp (`/DocTimeStamp` archive timestamp) over the current PDF
/// revision's `/ByteRange` and append it as an incremental revision (the "A" of PAdES-B-LTA).
///
/// `tsa` timestamps the SHA-256 digest of the new revision, and the produced RFC 3161 token is
/// embedded so [`chancela_pades::inspect_doc_timestamps`] / `validate_pdf_signature` can verify the
/// token's imprint binds this revision. Returns the new PDF and the archive-timestamp token DER for
/// the artifact's evidence record.
pub fn add_pdf_document_timestamp(
    pdf: &[u8],
    tsa: &dyn TimestampProvider,
) -> Result<(Vec<u8>, Vec<u8>), SigningError> {
    use std::cell::RefCell;
    let captured: RefCell<Option<Vec<u8>>> = RefCell::new(None);
    let out = add_doc_timestamp_revision_with(pdf, |byterange_digest: &[u8; 32]| {
        let ts = tsa.timestamp_digest(byterange_digest)?;
        *captured.borrow_mut() = Some(ts.token_der.clone());
        Ok::<Vec<u8>, SigningError>(ts.token_der)
    })
    .map_err(pades_err)?;
    let token = captured.into_inner().ok_or_else(|| {
        SigningError::Timestamp("document timestamp callback did not run".to_string())
    })?;
    Ok((out, token))
}

/// A produced PAdES-B-LTA upgrade: the long-term-validation `/DSS` revision plus the archive
/// `/DocTimeStamp` over it, with a faithful account of the evidence embedded.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PadesLtaExecution {
    /// The upgraded PDF: original signature + `/DSS`+`/VRI` revision + `/DocTimeStamp` revision.
    pub pdf: Vec<u8>,
    /// The validated revocation evidence embedded in the `/DSS` revision.
    pub revocation: RevocationEvidence,
    /// `/DSS` state reported after the revocation revision was appended.
    pub dss: DssReport,
    /// `/DocTimeStamp` state after the archive timestamp was appended, including per-token imprint
    /// validation against the revision each covers.
    pub doc_timestamps: DocTimeStampReport,
    /// The archive-timestamp RFC 3161 token DER (for the artifact's evidence record).
    pub archive_timestamp_token_der: Vec<u8>,
}

/// Execute a full PAdES-B-LTA upgrade over an already-signed PDF: fetch and embed validated
/// revocation evidence (`/DSS`+`/VRI`, LT) then append a document timestamp over it (LTA).
///
/// This composes [`attach_pdf_lt`] and [`add_pdf_document_timestamp`]. Every field of the returned
/// [`PadesLtaExecution`] reports evidence that was actually embedded; no legal sufficiency is
/// asserted beyond that.
pub fn execute_pdf_lta<T: RevocationHttpTransport>(
    signed_pdf: &[u8],
    signer_cert_der: &[u8],
    issuer_cert_der: &[u8],
    revocation: &RevocationEvidenceProvider<T>,
    validation_time: OffsetDateTime,
    tsa: &dyn TimestampProvider,
) -> Result<PadesLtaExecution, SigningError> {
    let (with_dss, dss, revocation) = attach_pdf_lt(
        signed_pdf,
        signer_cert_der,
        issuer_cert_der,
        revocation,
        validation_time,
    )?;
    let (pdf, archive_timestamp_token_der) = add_pdf_document_timestamp(&with_dss, tsa)?;
    let doc_timestamps = inspect_doc_timestamps(&pdf).map_err(pades_err)?;
    Ok(PadesLtaExecution {
        pdf,
        revocation,
        dss,
        doc_timestamps,
        archive_timestamp_token_der,
    })
}

/// A produced PAdES long-term-evidence renewal: a fresh `/DSS` revocation revision plus a fresh
/// `/DocTimeStamp` over it, appended on top of existing evidence.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PadesLtvRenewal {
    /// The renewed PDF with the appended `/DSS` + `/DocTimeStamp` revisions.
    pub pdf: Vec<u8>,
    /// The freshly fetched and validated revocation evidence embedded by this renewal round.
    pub revocation: RevocationEvidence,
    /// A faithful account of the evidence the renewal round embedded.
    pub execution: LtvRenewalExecution,
    /// The renewal archive-timestamp RFC 3161 token DER (for the artifact's evidence record).
    pub archive_timestamp_token_der: Vec<u8>,
}

/// Execute one long-term-evidence renewal round over a PDF that already carries LT/LTA evidence:
/// fetch fresh revocation material, append a new `/DSS`+`/VRI` revision, and append a new
/// `/DocTimeStamp` over it (drives [`chancela_pades::renewal::execute_ltv_renewal`]).
///
/// Renewal preserves the earlier evidence (each revision is an incremental append) and re-anchors
/// the document with a fresh archive timestamp. It reports what was embedded and makes no legal
/// long-term-validation sufficiency claim.
pub fn renew_pdf_ltv<T: RevocationHttpTransport>(
    signed_pdf: &[u8],
    signer_cert_der: &[u8],
    issuer_cert_der: &[u8],
    revocation: &RevocationEvidenceProvider<T>,
    validation_time: OffsetDateTime,
    tsa: &dyn TimestampProvider,
) -> Result<PadesLtvRenewal, SigningError> {
    let evidence = revocation
        .collect_for_signer(signer_cert_der, issuer_cert_der, validation_time)
        .map_err(revocation_err)?;
    let validation_time_str = evidence
        .validation_time
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| SigningError::Pades(format!("invalid renewal validation time: {e}")))?;

    use std::cell::RefCell;
    let captured: RefCell<Option<Vec<u8>>> = RefCell::new(None);
    let (pdf, execution) = execute_ltv_renewal(
        signed_pdf,
        &evidence.dss,
        &validation_time_str,
        |byterange_digest: &[u8; 32]| {
            let ts = tsa.timestamp_digest(byterange_digest)?;
            *captured.borrow_mut() = Some(ts.token_der.clone());
            Ok::<Vec<u8>, SigningError>(ts.token_der)
        },
    )
    .map_err(pades_err)?;
    let archive_timestamp_token_der = captured.into_inner().ok_or_else(|| {
        SigningError::Timestamp("renewal document timestamp callback did not run".to_string())
    })?;

    Ok(PadesLtvRenewal {
        pdf,
        revocation: evidence,
        execution,
        archive_timestamp_token_der,
    })
}

fn revocation_err(e: RevocationError) -> SigningError {
    SigningError::Pades(format!("revocation evidence collection failed: {e}"))
}

fn cades_err(e: chancela_cades::CadesError) -> SigningError {
    SigningError::Cades(e.to_string())
}

fn pades_err(e: chancela_pades::PadesError) -> SigningError {
    match e {
        chancela_pades::PadesError::Timestamp(source) => {
            SigningError::Timestamp(source.to_string())
        }
        chancela_pades::PadesError::Signer(source) => SigningError::Cades(source.to_string()),
        other => SigningError::Pades(other.to_string()),
    }
}
