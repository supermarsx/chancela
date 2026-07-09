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
use chancela_pades::{
    DssEvidence, DssReport, SignOptions, add_dss_revision, add_signature_timestamp, inspect_dss,
    sign_pdf,
};
use chancela_tsa::{HttpTsaTransport, Timestamp, TimestampRequest, TsaClient, TsaTransport};

use crate::SigningError;
use crate::provider::SignerProvider;

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
