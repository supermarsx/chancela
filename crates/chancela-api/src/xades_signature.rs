//! XAdES (XMLDSig) sign + validate endpoints for Ferramentas (t67-e10).
//!
//! Two local, technical endpoints layered on the `chancela-xades` two-phase seam (which itself sits
//! on the same `RawSignature` seam as CAdES/PAdES):
//!
//! - `POST /v1/signature/xades/sign` — produce a detached or enveloping **XAdES-B** (or **XAdES-T**
//!   when a live TSA is configured) over caller-supplied content, using a co-located software
//!   certificate (PKCS#12) as the signer. Co-location-gated (`state.local_signing`) exactly like the
//!   local PKCS#12 PDF-signing lane, because it needs a private key on this host. The produced XML is
//!   returned to the caller and never persisted.
//! - `POST /v1/signature/xades/validate` — run [`chancela_signing::validate_xades`] over a
//!   caller-supplied XAdES/XMLDSig document and report the structural + cryptographic result. This is
//!   read-only, local, and technical: it verifies the signature over its bound references, not signer
//!   trust or qualified status.
//!
//! Both endpoints are deliberately honest about scope: producing/validating a XAdES **signature** is
//! a technical operation and makes no trusted-list, qualified-signature, or legal-effect claim.
//!
//! The CMD/CSC and Cartão de Cidadão signers reach XAdES through the *same* seam
//! ([`chancela_xades::prepare_xades`] → `SignerProvider::sign_signed_attributes` →
//! `PreparedXades::assemble`); this slice wires the straightforward, fully-testable software-
//! certificate path and leaves the two-phase remote/hardware wiring to follow the existing
//! CMD/CSC/CC PDF lanes.

use axum::Json;
use axum::extract::State;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_authz::{Permission, Scope};
use chancela_signing::{Pkcs12IdentitySelector, Pkcs12SigningSource, SignatureAlgorithm};
use chancela_signing::{
    RevocationEvidenceProvider, SignerProvider, SigningError, ValidationMaterial,
};
use chancela_xades::{
    DetachedRef, EnvelopingObject, ObjectContent, PreparedXades, SignaturePackaging, XadesContext,
    XadesLevel, XadesSignRequest, XadesValidationReport, prepare_xades, validate_xades,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use x509_cert::certificate::Certificate;
use x509_cert::der::Decode;
use zeroize::Zeroizing;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;

/// Envelope size cap for the XAdES sign/validate endpoints (PKCS#12 + content, or an XML document).
pub(crate) const XADES_REQUEST_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Body limit applied at the router (base64 inflates by ~4/3, plus JSON overhead).
pub(crate) const XADES_REQUEST_ENVELOPE_BYTES: usize = XADES_REQUEST_MAX_BYTES * 2;

const SIGN_REPORT_KIND: &str = "xades_signature";
const VALIDATE_REPORT_KIND: &str = "xades_signature_validation";
const TECHNICAL_SCOPE: &str = "local_technical_xades_evidence";
const SIGN_LEGAL_NOTICE: &str = "Local technical XAdES signature production only. No trusted-list \
lookup, qualified-signature determination, or legal-validity conclusion is performed or claimed.";
const VALIDATE_LEGAL_NOTICE: &str = "Local technical XAdES/XMLDSig validation only: the signature is \
verified over its bound references. No signer-trust, qualified-status, or legal-validity conclusion \
is performed or claimed.";

/// How the signed data objects relate to the signature.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PackagingRequest {
    /// The content is referenced by URI and hashed as-is (the ASiC-E form).
    #[default]
    Detached,
    /// The content is embedded in the signature as a `<ds:Object>`.
    Enveloping,
}

/// The requested XAdES conformance level.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum LevelRequest {
    /// Baseline (`SignedProperties`).
    #[default]
    B,
    /// B + a signature timestamp (requires a configured live TSA).
    T,
    /// T + validation material (`CertificateValues` + `RevocationValues`). Requires a configured
    /// live TSA and reachable OCSP/CRL endpoints on the signer chain.
    Lt,
}

/// The signer material. Only the co-located software-certificate lane is wired in this slice.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SignerRequest {
    /// A PKCS#12 software certificate uploaded for this request only (transient).
    SoftPkcs12 {
        /// Base64 DER PKCS#12 (PFX). Transient — zeroized after loading.
        pkcs12_base64: String,
        /// The PKCS#12 passphrase. Transient — zeroized after loading.
        passphrase: String,
        /// Optional friendly-name selector when the PFX holds several identities.
        #[serde(default)]
        friendly_name: Option<String>,
    },
}

/// Body of `POST /v1/signature/xades/sign`.
#[derive(Debug, Deserialize)]
pub(crate) struct XadesSignRequestBody {
    /// Base64 content to sign.
    content_base64: String,
    /// The `URI`/name the detached reference carries (and the enveloping object id). Defaults to
    /// `content`.
    #[serde(default)]
    content_name: Option<String>,
    /// Packaging (detached | enveloping). Defaults to detached.
    #[serde(default)]
    packaging: PackagingRequest,
    /// Level (B | T). Defaults to B.
    #[serde(default)]
    level: LevelRequest,
    /// The signer material.
    signer: SignerRequest,
}

/// Response of `POST /v1/signature/xades/sign`.
#[derive(Debug, Serialize)]
pub struct XadesSignResponse {
    pub report_kind: &'static str,
    pub scope: &'static str,
    pub legal_notice: &'static str,
    /// The produced XAdES document, base64-encoded.
    pub xades_base64: String,
    /// SHA-256 of the produced XAdES document (hex).
    pub xades_sha256: String,
    /// The achieved conformance level (`XAdES-B` / `XAdES-T`).
    pub level: &'static str,
    /// The packaging used (`detached` / `enveloping`).
    pub packaging: &'static str,
    /// SHA-256 of the signed content (hex).
    pub content_sha256: String,
    /// The signer's leaf-certificate subject DN, best-effort.
    pub signer_cert_subject: Option<String>,
    /// SHA-256 of the signer's leaf certificate DER (hex).
    pub signer_cert_sha256: String,
    /// The XMLDSig signature algorithm inferred from the signer key (`rsa-sha256`/`ecdsa-sha256`).
    pub signature_algorithm: &'static str,
}

/// Body of `POST /v1/signature/xades/validate`.
#[derive(Debug, Deserialize)]
pub(crate) struct XadesValidateRequestBody {
    /// The XAdES/XMLDSig document, base64-encoded.
    #[serde(alias = "xml_base64", alias = "content_base64", alias = "base64")]
    xades_base64: String,
}

/// Response of `POST /v1/signature/xades/validate`.
#[derive(Debug, Serialize)]
pub struct XadesValidateResponse {
    pub report_kind: &'static str,
    pub scope: &'static str,
    pub legal_notice: &'static str,
    /// SHA-256 of the validated document (hex).
    pub sha256: String,
    pub report: XadesValidationReportDto,
}

/// Serializable projection of [`XadesValidationReport`].
#[derive(Debug, Serialize)]
pub struct XadesValidationReportDto {
    pub level: &'static str,
    pub signature_valid: bool,
    pub references_valid: bool,
    pub reference_count: usize,
    pub references_checked: usize,
    pub signed_properties_present: bool,
    pub signing_certificate_v2_present: bool,
    pub signing_time: Option<String>,
    pub signer_cert_subject: Option<String>,
    pub signer_cert_sha256: Option<String>,
    pub signature_timestamp_present: bool,
    /// The convenience "valid at XAdES-B" roll-up ([`XadesValidationReport::is_valid_b`]).
    pub is_valid_b: bool,
}

/// `POST /v1/signature/xades/sign` — produce a XAdES-B/T over caller content with a co-located
/// software certificate. Co-location-gated; the produced XML is returned and never persisted.
pub async fn sign_xades(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<XadesSignRequestBody>,
) -> Result<Json<XadesSignResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SigningPerform, Scope::Global).await?;

    if !state.local_signing {
        return Err(ApiError::Conflict(
            "a assinatura XAdES local com certificado de software só está disponível na aplicação \
             de secretária (co-localizada com a chave privada)"
                .to_owned(),
        ));
    }

    let content = B64
        .decode(req.content_base64.trim())
        .map_err(|e| ApiError::Unprocessable(format!("invalid base64 content: {e}")))?;
    if content.is_empty() {
        return Err(ApiError::Unprocessable("content is empty".to_owned()));
    }
    if content.len() > XADES_REQUEST_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "content is {} bytes; XAdES signing accepts at most {} bytes",
            content.len(),
            XADES_REQUEST_MAX_BYTES
        )));
    }
    let content_sha256 = sha256_hex(&content);
    let content_name = req
        .content_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("content")
        .to_owned();

    let level = match req.level {
        LevelRequest::B => XadesLevel::B,
        LevelRequest::T => XadesLevel::T,
        LevelRequest::Lt => XadesLevel::LT,
    };
    let packaging = req.packaging;
    let packaging_label = match packaging {
        PackagingRequest::Detached => "detached",
        PackagingRequest::Enveloping => "enveloping",
    };

    // XAdES-T and XAdES-LT both carry a signature timestamp: resolve the configured live TSA
    // up-front (a clean 422 if none is configured), before entering the blocking signing task.
    let tsa_provider = match level {
        XadesLevel::T | XadesLevel::LT => Some(
            crate::signature::configured_tsa_provider(&state)
                .await?
                .ok_or_else(|| {
                    ApiError::Unprocessable(
                        "XAdES-T/LT requer um prestador TSA configurado para o carimbo temporal da \
                         assinatura"
                            .to_owned(),
                    )
                })?,
        ),
        XadesLevel::B => None,
        XadesLevel::LTA => {
            return Err(ApiError::Unprocessable(
                "XAdES-LTA ainda não é suportado por este endpoint".to_owned(),
            ));
        }
    };

    let SignerRequest::SoftPkcs12 {
        pkcs12_base64,
        passphrase,
        friendly_name,
    } = req.signer;

    let pkcs12_der =
        Zeroizing::new(B64.decode(pkcs12_base64.trim()).map_err(|e| {
            ApiError::Unprocessable(format!("invalid base64 PKCS#12 content: {e}"))
        })?);
    if pkcs12_der.is_empty() {
        return Err(ApiError::Unprocessable(
            "PKCS#12 upload is empty".to_owned(),
        ));
    }
    if pkcs12_der.len() > XADES_REQUEST_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "PKCS#12 upload is {} bytes; XAdES signing accepts at most {} bytes",
            pkcs12_der.len(),
            XADES_REQUEST_MAX_BYTES
        )));
    }
    let passphrase = Zeroizing::new(passphrase);
    let selector = friendly_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|name| Pkcs12IdentitySelector::by_friendly_name(name.to_owned()))
        .unwrap_or_else(Pkcs12IdentitySelector::any);

    let signing_time = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());

    // PKCS#12 loading + the (RSA/ECDSA) private-key sign are CPU-bound: run off the async runtime.
    // For XAdES-T the TSA call is a bounded blocking reqwest, also fine inside spawn_blocking.
    let tsa_client = tsa_provider
        .as_ref()
        .map(crate::signature::build_bounded_tsa_client)
        .transpose()?;

    let (xades_xml, cert_der, sig_alg) = tokio::task::spawn_blocking(move || {
        let source = Pkcs12SigningSource::from_der_with_selector(
            pkcs12_der.as_slice(),
            &passphrase,
            &selector,
        )?;
        let cert_der = source.signing_certificate_der()?;
        let sig_alg = xmldsig_algorithm_for_cert(&cert_der)?;
        let signature_packaging = match packaging {
            PackagingRequest::Detached => SignaturePackaging::Detached(vec![DetachedRef {
                uri: content_name.clone(),
                bytes: content.clone(),
            }]),
            PackagingRequest::Enveloping => {
                SignaturePackaging::Enveloping(vec![EnvelopingObject {
                    id: content_name.clone(),
                    content: ObjectContent::Text(String::from_utf8_lossy(&content).into_owned()),
                }])
            }
        };
        let prepared: PreparedXades = prepare_xades(XadesSignRequest {
            signature_id: "xades-sig".to_owned(),
            signing_cert_der: cert_der.clone(),
            sig_alg,
            level,
            context: XadesContext { signing_time },
            packaging: signature_packaging,
        })
        .map_err(|e| SigningError::Xades(e.to_string()))?;

        // The co-located PKCS#12 lane signs a 32-byte SHA-256 digest (RSA-2048 / ECDSA-P256, the
        // real Cartão de Cidadão / CMD material). Wider-curve XAdES profiles (P-384/P-521 with
        // SHA-384/512) are a crate-level capability that needs a variable-length signer seam.
        let signed_info_digest: [u8; 32] = prepared
            .signed_info_digest()
            .as_slice()
            .try_into()
            .map_err(|_| {
                SigningError::Xades(
                    "the local PKCS#12 signer only supports SHA-256 XAdES profiles (RSA/ECDSA-P256)"
                        .to_owned(),
                )
            })?;
        let raw = source.sign_signed_attributes(&signed_info_digest)?;
        let assembled = prepared
            .assemble(&raw)
            .map_err(|e| SigningError::Xades(e.to_string()))?;

        let xml = match level {
            XadesLevel::B => assembled
                .into_bytes()
                .map_err(|e| SigningError::Xades(e.to_string()))?,
            XadesLevel::T => {
                let tsa = tsa_client.as_ref().expect("XAdES-T resolved a TSA client");
                let digest = assembled
                    .signature_timestamp_digest()
                    .map_err(|e| SigningError::Xades(e.to_string()))?;
                let token =
                    chancela_signing::pipeline::TimestampProvider::timestamp_digest(tsa, &digest)?;
                assembled
                    .with_signature_timestamp(&token.token_der)
                    .map_err(|e| SigningError::Xades(e.to_string()))?
            }
            XadesLevel::LT => {
                let tsa = tsa_client.as_ref().expect("XAdES-LT resolved a TSA client");
                // The issuer needed to validate revocation is the first chain certificate the PFX
                // carries above the signer leaf.
                let issuer_der = source.identity().chain_der.first().ok_or_else(|| {
                    SigningError::Xades(
                        "XAdES-LT needs the issuer certificate in the PKCS#12 chain to fetch \
                         revocation material"
                            .to_owned(),
                    )
                })?;
                // Collect validated chain + OCSP/CRL exactly as the PAdES-LT lane does (reused
                // revocation client; never a second one).
                let evidence = RevocationEvidenceProvider::http()
                    .collect_for_signer(&cert_der, issuer_der, signing_time)
                    .map_err(|e| {
                        SigningError::Xades(format!("revocation collection failed: {e}"))
                    })?;
                let material = ValidationMaterial {
                    certificates: evidence.dss.certificates,
                    ocsp_responses: evidence.dss.ocsp_responses,
                    crls: evidence.dss.crls,
                };
                let digest = assembled
                    .signature_timestamp_digest()
                    .map_err(|e| SigningError::Xades(e.to_string()))?;
                let token =
                    chancela_signing::pipeline::TimestampProvider::timestamp_digest(tsa, &digest)?;
                assembled
                    .with_lt(&token.token_der, &material)
                    .map_err(|e| SigningError::Xades(e.to_string()))?
            }
            XadesLevel::LTA => {
                return Err(SigningError::Xades("XAdES-LTA not supported".to_owned()));
            }
        };
        Ok::<_, SigningError>((xml, cert_der, sig_alg))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("XAdES signing task failed: {e}")))?
    .map_err(map_signing_error)?;

    Ok(Json(XadesSignResponse {
        report_kind: SIGN_REPORT_KIND,
        scope: TECHNICAL_SCOPE,
        legal_notice: SIGN_LEGAL_NOTICE,
        xades_sha256: sha256_hex(&xades_xml),
        xades_base64: B64.encode(&xades_xml),
        level: match level {
            XadesLevel::B => "XAdES-B",
            XadesLevel::T => "XAdES-T",
            XadesLevel::LT => "XAdES-LT",
            XadesLevel::LTA => "XAdES-LTA",
        },
        packaging: packaging_label,
        content_sha256,
        signer_cert_subject: subject_dn(&cert_der),
        signer_cert_sha256: sha256_hex(&cert_der),
        signature_algorithm: xmldsig_algorithm_label(sig_alg),
    }))
}

/// `POST /v1/signature/xades/validate` — local technical XAdES/XMLDSig validation.
pub async fn validate_xades_document(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<XadesValidateRequestBody>,
) -> Result<Json<XadesValidateResponse>, ApiError> {
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;

    let xml = B64
        .decode(req.xades_base64.trim())
        .map_err(|e| ApiError::Unprocessable(format!("invalid base64 XAdES content: {e}")))?;
    if xml.is_empty() {
        return Err(ApiError::Unprocessable(
            "XAdES document is empty".to_owned(),
        ));
    }
    if xml.len() > XADES_REQUEST_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "XAdES document is {} bytes; validation accepts at most {} bytes",
            xml.len(),
            XADES_REQUEST_MAX_BYTES
        )));
    }
    let sha256 = sha256_hex(&xml);
    let report = validate_xades(&xml)
        .map_err(|e| ApiError::Unprocessable(format!("não foi possível validar o XAdES: {e}")))?;

    Ok(Json(XadesValidateResponse {
        report_kind: VALIDATE_REPORT_KIND,
        scope: TECHNICAL_SCOPE,
        legal_notice: VALIDATE_LEGAL_NOTICE,
        sha256,
        report: report_dto(report),
    }))
}

fn report_dto(report: XadesValidationReport) -> XadesValidationReportDto {
    let is_valid_b = report.is_valid_b();
    XadesValidationReportDto {
        level: match report.level {
            XadesLevel::B => "XAdES-B",
            XadesLevel::T => "XAdES-T",
            XadesLevel::LT => "XAdES-LT",
            XadesLevel::LTA => "XAdES-LTA",
        },
        signature_valid: report.signature_valid,
        references_valid: report.references_valid,
        reference_count: report.reference_count,
        references_checked: report.references_checked,
        signed_properties_present: report.signed_properties_present,
        signing_certificate_v2_present: report.signing_certificate_v2_present,
        signing_time: report.signing_time.and_then(|t| t.format(&Rfc3339).ok()),
        signer_cert_subject: report.signer_cert_der.as_deref().and_then(subject_dn),
        signer_cert_sha256: report.signer_cert_der.as_deref().map(sha256_hex),
        signature_timestamp_present: report.signature_timestamp_present,
        is_valid_b,
    }
}

/// The XMLDSig signature algorithm the signer uses, inferred from its certificate public key
/// (RSA → RSA-SHA256, EC P-256 → ECDSA-P256-SHA256), mirroring `chancela-signing::asic_sign`.
fn xmldsig_algorithm_for_cert(cert_der: &[u8]) -> Result<SignatureAlgorithm, SigningError> {
    const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    let cert = Certificate::from_der(cert_der)
        .map_err(|_| SigningError::Xades("signer certificate is not valid DER".to_owned()))?;
    let oid = cert
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid
        .to_string();
    match oid.as_str() {
        RSA_ENCRYPTION => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
        EC_PUBLIC_KEY => Ok(SignatureAlgorithm::EcdsaP256Sha256),
        other => Err(SigningError::Xades(format!(
            "unsupported XAdES signer public-key algorithm {other}"
        ))),
    }
}

fn xmldsig_algorithm_label(alg: SignatureAlgorithm) -> &'static str {
    match alg {
        SignatureAlgorithm::RsaPkcs1Sha256 => "rsa-sha256",
        SignatureAlgorithm::EcdsaP256Sha256 => "ecdsa-sha256",
        SignatureAlgorithm::EcdsaP384Sha384 => "ecdsa-sha384",
        SignatureAlgorithm::EcdsaP521Sha512 => "ecdsa-sha512",
        _ => "unknown",
    }
}

/// Map a signing failure to an HTTP error, keeping the wrong-passphrase case a clean 422 and never
/// echoing any secret.
fn map_signing_error(err: SigningError) -> ApiError {
    match &err {
        SigningError::SoftCertificate(e) => ApiError::Unprocessable(format!(
            "não foi possível carregar o certificado PKCS#12: {e}"
        )),
        SigningError::Xades(msg) => {
            ApiError::Unprocessable(format!("não foi possível produzir o XAdES: {msg}"))
        }
        SigningError::Timestamp(msg) => {
            ApiError::Unprocessable(format!("falha ao obter carimbo temporal: {msg}"))
        }
        _ => ApiError::Internal(format!("XAdES signing failed: {err}")),
    }
}

fn subject_dn(der: &[u8]) -> Option<String> {
    Certificate::from_der(der)
        .ok()
        .map(|cert| cert.tbs_certificate.subject.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
