//! Batch document signing under a single authentication (t67-e6, plan §2 Phase 3).
//!
//! A notary often has to seal a whole stack of acts in one sitting. Asking the signer to
//! re-authenticate for every single document is both hostile and, for the Cartão de Cidadão, the
//! default hardware behaviour (the qualified-signature key is `CKA_ALWAYS_AUTHENTICATE`, so the
//! Autenticação.gov middleware prompts at the reader *per operation* — see
//! `chancela_smartcard::pkcs11`). This module batches a set of documents behind **one** signer
//! authentication where the family allows it, and — critically — reports *honestly* when it cannot:
//!
//! - **Cartão de Cidadão.** The batch reuses **one** [`SignerProvider`] (one middleware context /
//!   one open card session) across every document. When an **in-app PIN** is supplied it is held in
//!   a single [`Zeroizing`] buffer and replayed programmatically to each context-specific login via
//!   the [`SignerProvider::sign_signed_attributes_with_pin`] seam (t67-e1): the signer types the PIN
//!   **once**, so [`AuthMode::SingleAuth`] is honest even though the card performs one login per
//!   document. With **no** in-app PIN the protected-authentication path runs, the middleware owns the
//!   reader dialog, and `CKA_ALWAYS_AUTHENTICATE` forces a prompt per document — reported as
//!   [`AuthMode::PerDocumentAuth`]. The batch **never** claims a single PIN when the signer will in
//!   fact be prompted per document (plan decision 3, §6 honesty).
//! - **Software certificate (PKCS#12).** The passphrase unlocked the key once, at
//!   [`Pkcs12SigningSource`](crate::Pkcs12SigningSource) construction; every document then signs with
//!   no further authentication → [`AuthMode::SingleAuth`].
//! - **Chave Móvel Digital (via [`CmdProvider`](crate::CmdProvider)).** The synchronous provider
//!   dispatches a fresh OTP per signature (each `sign_signed_attributes` runs a request/confirm
//!   round trip), so a batch over it is honestly [`AuthMode::PerDocumentAuth`].
//!
//! **Remote two-phase seam.** The resumable [`RemoteSigningSource`](crate::RemoteSigningSource)
//! (CMD/CSC across two stateless HTTP requests) is **strictly one-digest-per-session**:
//! [`initiate`](crate::RemoteSigningSource::initiate) takes exactly one prepared ByteRange digest and
//! [`confirm`](crate::RemoteSigningSource::confirm) returns exactly one CMS. A *true* single-auth
//! fan-out (one activation authorising N digests) would require extending that trait, which lives
//! outside this slice's locks; this module therefore batches over the synchronous
//! [`SignerProvider`] path only and leaves the remote-seam multi-digest extension to a future slice.
//!
//! **Per-document isolation.** One document's failure never aborts the batch: each document reports
//! its own [`BatchDocumentOutcome::result`] and the [`BatchReport`] aggregates the successes,
//! failures, and authentication accounting. Each document may carry its own visible-seal
//! [`SealAppearance`] (t67-e3) and its own [`SignOptions`], so placement and field metadata are
//! per-document, not batch-wide.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use chancela_cades::{assemble_cades_b, signed_attributes_digest};
use chancela_pades::{
    SealAppearance, SignOptions, embed_signature, prepare_signature_with_appearance,
    validate_pdf_signature,
};

use crate::policy::TrustPolicy;
use crate::provider::SignerProvider;
use crate::{SigningError, SigningFamily, TrustedListStatus};

/// How many times the signer had to authenticate to cover the whole batch (plan decision 3).
///
/// This is the **human-facing** truth, distinct from [`BatchReport::auth_events`] (the number of
/// underlying signing invocations). It must never overstate: a Cartão de Cidadão batch is only
/// [`Self::SingleAuth`] when an in-app PIN was supplied and replayed, never on the
/// protected-authentication path where `CKA_ALWAYS_AUTHENTICATE` forces a per-document reader
/// prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuthMode {
    /// A single signer authentication covered every document in the batch (e.g. one in-app CC PIN
    /// replayed to each card login, or one PKCS#12 passphrase unlock).
    SingleAuth,
    /// Each document required its own signer authentication (e.g. CC protected-authentication with
    /// `CKA_ALWAYS_AUTHENTICATE`, or a CMD OTP per document).
    PerDocumentAuth,
}

/// One PDF to sign in a batch: its bytes, per-document [`SignOptions`], and optional visible seal.
///
/// `appearance` is per-document so each act may place its seal independently (t67-e3); `None` keeps
/// the invisible, locked signature widget (the backward-compatible default).
pub struct BatchPdfDocument<'a> {
    /// A caller-chosen stable id used to correlate the [`BatchDocumentOutcome`] back to this input.
    pub id: String,
    /// The unsigned PDF/A bytes to sign (PAdES-B-B).
    pub pdf: &'a [u8],
    /// PAdES signing options for this document (field name, reason, location, …).
    pub options: SignOptions,
    /// Optional visible-seal appearance for this document; `None` = invisible signature widget.
    pub appearance: Option<SealAppearance>,
}

/// One detached-CAdES payload to sign in a batch: a caller id and the SHA-256 of the content.
pub struct BatchCadesDocument {
    /// A caller-chosen stable id used to correlate the [`BatchDocumentOutcome`] back to this input.
    pub id: String,
    /// SHA-256 digest of the detached content this signature covers.
    pub content_digest: [u8; 32],
}

/// The outcome for one document in a batch: either the produced bytes or that document's own error.
///
/// `result` is `Ok(signed PDF bytes)` for [`sign_pdf_batch`] and `Ok(detached CAdES-B DER)` for
/// [`sign_detached_cades_batch`]. A failure here is isolated to this document — the rest of the
/// batch still runs (plan §2).
#[derive(Debug, Clone)]
pub struct BatchDocumentOutcome {
    /// The [`BatchPdfDocument::id`] / [`BatchCadesDocument::id`] this outcome corresponds to.
    pub id: String,
    /// The produced signature bytes, or this document's isolated error.
    pub result: Result<Vec<u8>, SigningError>,
}

impl BatchDocumentOutcome {
    /// Whether this document was signed successfully.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.result.is_ok()
    }
}

/// The aggregate report of a batch: the authentication accounting plus every per-document outcome.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BatchReport {
    /// How many signer authentications the batch required overall (plan decision 3).
    pub auth_mode: AuthMode,
    /// The number of documents that reached the provider's signing operation — i.e. the number of
    /// underlying signing invocations. Under [`AuthMode::SingleAuth`] these were all covered by one
    /// signer authentication; under [`AuthMode::PerDocumentAuth`] each was its own authentication.
    pub auth_events: usize,
    /// The signer's leaf certificate (DER) resolved once for the whole batch, if signing started.
    pub signing_cert_der: Option<Vec<u8>>,
    /// The trusted-list status of the signer's issuer resolved once at batch start (SIG-11/23), if a
    /// policy was consulted. Only [`TrustedListStatus::Granted`] lets the batch proceed.
    pub trusted_list_status: Option<TrustedListStatus>,
    /// The per-document outcomes, in input order.
    pub results: Vec<BatchDocumentOutcome>,
}

impl BatchReport {
    /// The number of documents signed successfully.
    #[must_use]
    pub fn ok_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_ok()).count()
    }

    /// The number of documents that failed.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.results.len() - self.ok_count()
    }

    /// Whether every document in the batch was signed successfully.
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.results.iter().all(BatchDocumentOutcome::is_ok)
    }
}

/// Sign a set of PDFs with one [`SignerProvider`] under a single authentication where the family
/// allows it, placing each document's own optional visible seal (plan §2 Phase 3).
///
/// The trusted-list gate (SIG-11/23) runs **once** over the shared signer issuer before any document
/// is signed: a non-`Granted` issuer (or a missing issuer when a policy is configured) fails the
/// whole batch **closed**, so no document — and no card PIN prompt — is reached. Passing `policy:
/// None` skips the gate (the qualified path MUST supply one).
///
/// `pin` is the optional transient **in-app** Cartão de Cidadão PIN. When `Some`, it is held here in
/// one [`Zeroizing`] buffer and replayed (borrowed, never copied) to every document's
/// context-specific card login via the t67-e1 seam, so the signer authenticates once
/// ([`AuthMode::SingleAuth`]); it is dropped and zeroized when this call returns, on every path
/// including unwinding (plan §6). Other families ignore it (their auth is their own).
///
/// One document's failure does not abort the rest — see [`BatchReport`]. `signing_time` is fixed
/// across the batch so every signature carries the same authoritative time.
pub fn sign_pdf_batch(
    provider: &dyn SignerProvider,
    documents: &[BatchPdfDocument<'_>],
    signing_time: OffsetDateTime,
    policy: Option<&mut dyn TrustPolicy>,
    pin: Option<Zeroizing<String>>,
) -> BatchReport {
    let auth_mode = resolve_auth_mode(provider.family(), pin.is_some());

    let (signing_cert_der, trusted_list_status) =
        match gate_and_resolve(provider, policy, signing_time) {
            Ok(resolved) => resolved,
            Err(error) => {
                return all_failed(documents.iter().map(|d| d.id.clone()), &error, auth_mode);
            }
        };

    let mut results = Vec::with_capacity(documents.len());
    let mut auth_events = 0usize;
    for doc in documents {
        let (reached_sign, result) =
            sign_one_pdf(provider, &signing_cert_der, doc, signing_time, pin.as_ref());
        auth_events += usize::from(reached_sign);
        results.push(BatchDocumentOutcome {
            id: doc.id.clone(),
            result,
        });
    }

    BatchReport {
        auth_mode,
        auth_events,
        signing_cert_der: Some(signing_cert_der),
        trusted_list_status,
        results,
    }
    // `pin` (the only copy of the in-app PIN this batch held) drops here and is zeroized.
}

/// Sign a set of detached-CAdES payloads with one provider under a single authentication.
///
/// The trivial CAdES sibling of [`sign_pdf_batch`]: same one-shot trusted-list gate, same in-app-PIN
/// custody and honest [`AuthMode`] accounting, same per-document isolation — but each document is a
/// precomputed content digest and each success is the detached CAdES-B `SignedData` (DER
/// `ContentInfo`).
pub fn sign_detached_cades_batch(
    provider: &dyn SignerProvider,
    documents: &[BatchCadesDocument],
    signing_time: OffsetDateTime,
    policy: Option<&mut dyn TrustPolicy>,
    pin: Option<Zeroizing<String>>,
) -> BatchReport {
    let auth_mode = resolve_auth_mode(provider.family(), pin.is_some());

    let (signing_cert_der, trusted_list_status) =
        match gate_and_resolve(provider, policy, signing_time) {
            Ok(resolved) => resolved,
            Err(error) => {
                return all_failed(documents.iter().map(|d| d.id.clone()), &error, auth_mode);
            }
        };

    let mut results = Vec::with_capacity(documents.len());
    let mut auth_events = 0usize;
    for doc in documents {
        let result = sign_one_cades(
            provider,
            &signing_cert_der,
            &doc.content_digest,
            signing_time,
            pin.as_ref(),
        );
        // Every CAdES document reaches the provider's signing operation (there is no pre-sign
        // preparation that can fail first), so each is one signing invocation.
        auth_events += 1;
        results.push(BatchDocumentOutcome {
            id: doc.id.clone(),
            result,
        });
    }

    BatchReport {
        auth_mode,
        auth_events,
        signing_cert_der: Some(signing_cert_der),
        trusted_list_status,
        results,
    }
}

/// Resolve the honest [`AuthMode`] for this signer family and in-app-PIN presence (plan decision 3).
fn resolve_auth_mode(family: SigningFamily, in_app_pin_supplied: bool) -> AuthMode {
    match family {
        // Cartão de Cidadão: the qualified-signature key is CKA_ALWAYS_AUTHENTICATE. An in-app PIN
        // is replayed programmatically to each per-operation login (one human authentication);
        // without it the middleware prompts at the reader per document — surfaced honestly.
        SigningFamily::CartaoDeCidadao => {
            if in_app_pin_supplied {
                AuthMode::SingleAuth
            } else {
                AuthMode::PerDocumentAuth
            }
        }
        // A locally-unlocked software key (PKCS#12 passphrase entered once at load) signs every
        // document with no further authentication.
        SigningFamily::QualifiedCertificate => AuthMode::SingleAuth,
        // CMD via the synchronous provider dispatches a fresh OTP per signature.
        SigningFamily::ChaveMovelDigital => AuthMode::PerDocumentAuth,
        // Manual (scan) acts are not cryptographically batched here; report conservatively.
        SigningFamily::Manual => AuthMode::PerDocumentAuth,
    }
}

/// Run the shared, once-per-batch trusted-list gate and resolve the signer certificate.
///
/// Mirrors the fail-closed semantics of [`sign_pdf_cc`](crate::sign_pdf_cc): with a policy, the
/// signer issuer MUST be present and `Granted` or the whole batch is refused before any signing.
fn gate_and_resolve(
    provider: &dyn SignerProvider,
    policy: Option<&mut dyn TrustPolicy>,
    signing_time: OffsetDateTime,
) -> Result<(Vec<u8>, Option<TrustedListStatus>), SigningError> {
    let trusted_list_status = match policy {
        Some(policy) => {
            let issuer = provider
                .issuer_certificate_der()?
                .ok_or(SigningError::MissingIssuerCertificate)?;
            let status = policy.issuer_status(&issuer, signing_time)?;
            if status != TrustedListStatus::Granted {
                return Err(SigningError::UntrustedService { status });
            }
            Some(status)
        }
        None => None,
    };
    let signing_cert_der = provider.signing_certificate_der()?;
    Ok((signing_cert_der, trusted_list_status))
}

/// Build a report where the whole batch failed before any document was signed (gate/cert failure).
///
/// Every document reports the same isolated error so callers still get a per-document outcome list;
/// the trusted-list status is surfaced when the failure was an untrusted issuer.
fn all_failed(
    ids: impl Iterator<Item = String>,
    error: &SigningError,
    auth_mode: AuthMode,
) -> BatchReport {
    let trusted_list_status = match error {
        SigningError::UntrustedService { status } => Some(*status),
        _ => None,
    };
    let results = ids
        .map(|id| BatchDocumentOutcome {
            id,
            result: Err(error.clone()),
        })
        .collect();
    BatchReport {
        auth_mode,
        auth_events: 0,
        signing_cert_der: None,
        trusted_list_status,
        results,
    }
}

/// Sign one PDF document, returning whether the provider's signing operation was reached (so the
/// caller can count authentications) and the per-document result.
///
/// The trusted-list gate already ran once for the batch, so no policy is consulted here.
fn sign_one_pdf(
    provider: &dyn SignerProvider,
    signing_cert_der: &[u8],
    doc: &BatchPdfDocument<'_>,
    signing_time: OffsetDateTime,
    pin: Option<&Zeroizing<String>>,
) -> (bool, Result<Vec<u8>, SigningError>) {
    // Pre-sign preparation (may fail before the card is ever contacted).
    let prepared =
        match prepare_signature_with_appearance(doc.pdf, &doc.options, doc.appearance.as_ref()) {
            Ok(prepared) => prepared,
            Err(e) => return (false, Err(pades_err(e))),
        };
    let signed_attrs_digest =
        match signed_attributes_digest(prepared.byterange_digest(), signing_cert_der, signing_time)
        {
            Ok(digest) => digest,
            Err(e) => return (false, Err(cades_err(e))),
        };

    // From here the signer's device/service is contacted — one signing invocation (one
    // context-specific authentication).
    let result = sign_prepared_pdf(provider, &prepared, &signed_attrs_digest, signing_time, pin);
    (true, result)
}

/// Complete a prepared PDF signature: card/service sign → assemble CAdES-B → embed → validate.
fn sign_prepared_pdf(
    provider: &dyn SignerProvider,
    prepared: &chancela_pades::PreparedSignature,
    signed_attrs_digest: &[u8; 32],
    signing_time: OffsetDateTime,
    pin: Option<&Zeroizing<String>>,
) -> Result<Vec<u8>, SigningError> {
    let raw = provider.sign_signed_attributes_with_pin(signed_attrs_digest, pin)?;
    let cms =
        assemble_cades_b(&raw, prepared.byterange_digest(), signing_time).map_err(cades_err)?;
    let signed_pdf = embed_signature(prepared, &cms).map_err(pades_err)?;
    // Post-sign sanity gate (SIG-24): never emit a malformed signature, even in a batch.
    validate_pdf_signature(&signed_pdf).map_err(pades_err)?;
    Ok(signed_pdf)
}

/// Sign one detached-CAdES payload (the card/service is always contacted, so this is one invocation).
fn sign_one_cades(
    provider: &dyn SignerProvider,
    signing_cert_der: &[u8],
    content_digest: &[u8; 32],
    signing_time: OffsetDateTime,
    pin: Option<&Zeroizing<String>>,
) -> Result<Vec<u8>, SigningError> {
    let signed_attrs_digest =
        signed_attributes_digest(content_digest, signing_cert_der, signing_time)
            .map_err(cades_err)?;
    let raw = provider.sign_signed_attributes_with_pin(&signed_attrs_digest, pin)?;
    assemble_cades_b(&raw, content_digest, signing_time).map_err(cades_err)
}

fn cades_err(e: chancela_cades::CadesError) -> SigningError {
    SigningError::Cades(e.to_string())
}

fn pades_err(e: chancela_pades::PadesError) -> SigningError {
    SigningError::Pades(e.to_string())
}
