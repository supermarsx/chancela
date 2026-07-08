//! The synchronous **Cartão de Cidadão → PAdES** signing seam (t58 Slice 1).
//!
//! Unlike Chave Móvel Digital — whose SMS-OTP round-trip forces the two-phase
//! [`cmd_initiate`](crate::cmd_initiate) / [`cmd_confirm`](crate::cmd_confirm) split spanning two
//! stateless HTTP requests (see [`crate::cmd_session`]) — a Cartão de Cidadão signature is **local
//! and synchronous**: the card, reader, Autenticação.gov middleware, and PIN entry all live on the
//! same host, and the PIN is entered *at the reader*, by the middleware, inside the single PKCS#11
//! `sign_digest` call. The PIN never enters this process (protected-authentication / NULL-PIN
//! path). So CC needs no session, no persisted pending state, and no secret in flight: **one call**
//! takes the unsigned PDF/A + a [`SmartcardProvider`](crate::SmartcardProvider) + an optional
//! trusted-list policy and returns the signed PDF.
//!
//! [`sign_pdf_cc`] is the seam the api (`spawn_blocking`) and desktop code sign against. It mirrors
//! the CMD gate ([`cmd_initiate`](crate::cmd_initiate)) and the envelope gate
//! ([`sign_slot`](crate::sign_slot)): the CC issuer certificate — supplied out-of-band via
//! [`SmartcardProvider::with_issuer_certificate`](crate::SmartcardProvider::with_issuer_certificate),
//! since the card exposes only the leaf — is checked against the Portuguese Trusted List
//! (SIG-11/23) and a non-`Granted` issuer is rejected **fail-closed, before any signature is
//! produced**. It then runs the existing synchronous PAdES pipeline
//! ([`sign_pdf_pades`](crate::pipeline::sign_pdf_pades): `prepare` → provider `sign_digest` →
//! assemble CAdES-B → `embed`) and a post-sign validation sanity gate (SIG-24) over the result, so
//! a malformed signature never leaves this call. Card-generation branching (CC v1 RSA-2048 /
//! CC v2 P-256) is handled below the provider, in `chancela-smartcard`.

use time::OffsetDateTime;

use chancela_cades::{assemble_cades_b, signed_attributes_digest};
use chancela_pades::{SignOptions, embed_signature, prepare_signature, validate_pdf_signature};

use crate::policy::TrustPolicy;
use crate::provider::SignerProvider;
use crate::{SigningError, TrustedListStatus};

/// The result of a synchronous Cartão de Cidadão PAdES signature ([`sign_pdf_cc`]).
///
/// Non-secret throughout — there is no PIN or OTP anywhere in the CC flow (the PIN is entered at
/// the reader and never enters this process). The api persists these fields as the signed-document
/// variant + evidence record (t58 reuses t57's F4 store shape).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CcSignedPdf {
    /// The signed PDF/A bytes (PAdES-B-B), already checked by the post-sign validation sanity gate.
    pub signed_pdf: Vec<u8>,
    /// The signer's qualified-**signature** leaf certificate (DER), as selected on the card by
    /// label (never the authentication certificate — SIG-02). Recorded as signer evidence.
    pub signing_cert_der: Vec<u8>,
    /// The trusted-list status of the CC issuer resolved at signing time (SIG-11/23), if a policy
    /// was consulted. Only [`TrustedListStatus::Granted`] passes the gate, so whenever a policy was
    /// supplied this is `Some(TrustedListStatus::Granted)`; `None` when no policy was supplied.
    pub trusted_list_status: Option<TrustedListStatus>,
}

/// Sign `pdf` with a Cartão de Cidadão in a single synchronous call (t58 F-CC — the frozen CC seam).
///
/// `provider` is a [`SmartcardProvider`](crate::SmartcardProvider) over any
/// [`CryptoToken`](chancela_smartcard::CryptoToken): the real
/// [`Pkcs11Token`](chancela_smartcard::Pkcs11Token) in the co-located desktop deployment, or a
/// [`MockToken`](chancela_smartcard::MockToken) / in-test key-backed token in CI. The steps:
///
/// 1. **Trusted-list gate (SIG-11/23), fail-closed.** When `policy` is `Some`, the provider's
///    issuer certificate is resolved — it MUST be present (a card exposes only the leaf, so the
///    issuing CA is supplied out-of-band via
///    [`SmartcardProvider::with_issuer_certificate`](crate::SmartcardProvider::with_issuer_certificate);
///    absence ⇒ [`SigningError::MissingIssuerCertificate`]) — and checked against the TSL. A
///    non-`Granted` issuer is rejected with [`SigningError::UntrustedService`] **before** the card
///    is asked to sign, so an untrusted signer never even prompts for the PIN. Passing `policy:
///    None` skips the gate (the caller resolved trust out-of-band); the qualified path MUST supply
///    a policy.
/// 2. **PAdES sign (synchronous).** The prepare/embed seam (t57-S2 F5) computes the `/ByteRange`
///    digest; the card signs the CAdES signed-attributes digest via `sign_digest` — the middleware
///    shows the PIN dialog at the reader; the PIN never enters this process — a detached CAdES-B CMS
///    is assembled (RSA for CC v1, P-256 for CC v2, branched inside `chancela-smartcard`) and
///    embedded. The card is asked to sign directly here (not through the `sign_pdf` callback) so a
///    card/PIN/activation failure surfaces as a distinct [`SigningError::Provider`] — the api needs
///    that granularity for honest error messages ("insira o cartão", "assinatura não ativada")
///    rather than a generic PDF error.
/// 3. **Validation sanity gate (SIG-24).** The produced PDF is validated so this call can never
///    emit a structurally or cryptographically invalid signature.
///
/// **Blocking:** the real token's `sign_digest` blocks on PKCS#11/PC/SC FFI and on human PIN entry
/// at the reader, so the api MUST invoke this on `spawn_blocking`.
pub fn sign_pdf_cc(
    provider: &dyn SignerProvider,
    pdf: &[u8],
    signing_time: OffsetDateTime,
    options: &SignOptions,
    policy: Option<&mut dyn TrustPolicy>,
) -> Result<CcSignedPdf, SigningError> {
    // 1. Trusted-list gate on the CC issuer (SIG-11/23), fail-closed — identical semantics to
    //    `cmd_initiate` and `sign_slot`: a qualified signature must not be trusted, nor even
    //    started at the reader, unless its issuer is currently granted.
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

    // The selected qualified-signature leaf (by CKA_LABEL, never the auth cert — SIG-02). Needed to
    // build the signed attributes, and recorded in the outcome as signer evidence.
    let signing_cert_der = provider.signing_certificate_der()?;

    // 2. Prepare → card sign_digest → assemble CAdES-B → embed (the t57-S2 F5 seam, reused). No
    //    two-phase suspend is needed: CC is a single blocking call (plan §2).
    let prepared = prepare_signature(pdf, options).map_err(pades_err)?;
    let signed_attrs_digest =
        signed_attributes_digest(prepared.byterange_digest(), &signing_cert_der, signing_time)
            .map_err(cades_err)?;
    // The card signs here; a card/PIN/activation failure surfaces as `SigningError::Provider`.
    let raw = provider.sign_signed_attributes(&signed_attrs_digest)?;
    let cms =
        assemble_cades_b(&raw, prepared.byterange_digest(), signing_time).map_err(cades_err)?;
    let signed_pdf = embed_signature(&prepared, &cms).map_err(pades_err)?;

    // 3. Post-sign validation sanity gate (SIG-24) — never emit a malformed signature.
    validate_pdf_signature(&signed_pdf).map_err(pades_err)?;

    Ok(CcSignedPdf {
        signed_pdf,
        signing_cert_der,
        trusted_list_status,
    })
}

fn cades_err(e: chancela_cades::CadesError) -> SigningError {
    SigningError::Cades(e.to_string())
}

fn pades_err(e: chancela_pades::PadesError) -> SigningError {
    SigningError::Pades(e.to_string())
}
