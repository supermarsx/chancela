//! ASiC **signing** endpoints for Ferramentas (t67-e10).
//!
//! Produces ASiC containers over the `chancela-signing` seam:
//!
//! - `POST /v1/signature/asic/sign` with `container = "asic_s_xades"` — a bounded ASiC-S container
//!   carrying one payload and a detached **XAdES-B/T** signature ([`sign_asic_s_xades`]).
//! - `POST /v1/signature/asic/sign` with `container = "asic_e_multi"` — a multi-signature ASiC-E
//!   container over a shared payload set, with any mix of CAdES and XAdES signers and an optional
//!   RFC 3161 archive manifest ([`sign_asic_e_multi`]).
//!
//! Each signer is a co-located software certificate (PKCS#12), so the endpoint is co-location-gated
//! (`state.local_signing`) like the other local software-certificate signing lanes. The produced
//! container is returned to the caller and never persisted. This is a technical operation: it makes
//! no trusted-list, qualified-signature, or legal-validity claim.
//!
//! ASiC *validation* is intentionally out of scope here — it is served by the separate ASiC
//! signature-inspection endpoint.

use axum::Json;
use axum::extract::State;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_authz::{Permission, Scope};
use chancela_signing::pipeline::TimestampProvider;
use chancela_signing::{
    AsicEMultiSignRequest, AsicPayload, Pkcs12IdentitySelector, Pkcs12SigningSource,
    SignerProvider, SigningError, XadesLevel, sign_asic_e_multi, sign_asic_s_xades,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;

/// Per-member cap for an ASiC payload / PKCS#12 upload.
pub(crate) const ASIC_SIGN_MAX_MEMBER_BYTES: usize = 8 * 1024 * 1024;
/// Body limit applied at the router (multiple base64 members inflate the envelope).
pub(crate) const ASIC_SIGN_ENVELOPE_BYTES: usize = 48 * 1024 * 1024;

const REPORT_KIND: &str = "asic_signature";
const SCOPE: &str = "local_technical_asic_evidence";
const LEGAL_NOTICE: &str = "Local technical ASiC container production only. No trusted-list lookup, \
qualified-signature determination, or legal-validity conclusion is performed or claimed.";

/// Which container form to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ContainerRequest {
    /// ASiC-S with a detached XAdES signature over exactly one payload.
    AsicSXades,
    /// Multi-signature ASiC-E over a shared payload set (CAdES and/or XAdES signers).
    AsicEMulti,
}

/// The XAdES level for the XAdES signers.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum LevelRequest {
    #[default]
    B,
    T,
}

/// The role a signer plays in an ASiC-E multi-signature container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SignerRole {
    Cades,
    #[default]
    Xades,
}

/// A payload member.
#[derive(Debug, Deserialize)]
struct PayloadRequest {
    name: String,
    content_base64: String,
    #[serde(default)]
    mime_type: Option<String>,
}

/// A co-located software-certificate signer.
#[derive(Debug, Deserialize)]
struct AsicSignerRequest {
    /// The role in an ASiC-E container (ignored for ASiC-S, which is always XAdES). Defaults to
    /// XAdES.
    #[serde(default)]
    role: SignerRole,
    pkcs12_base64: String,
    passphrase: String,
    #[serde(default)]
    friendly_name: Option<String>,
}

/// Body of `POST /v1/signature/asic/sign`.
#[derive(Debug, Deserialize)]
pub(crate) struct AsicSignRequestBody {
    container: ContainerRequest,
    payloads: Vec<PayloadRequest>,
    signers: Vec<AsicSignerRequest>,
    #[serde(default)]
    xades_level: LevelRequest,
    /// Add an ASiC-E archive manifest protected by an RFC 3161 archive timestamp (ASiC-E only;
    /// requires a configured live TSA).
    #[serde(default)]
    archive_timestamp: bool,
}

/// Response of `POST /v1/signature/asic/sign`.
#[derive(Debug, Serialize)]
pub struct AsicSignResponse {
    pub report_kind: &'static str,
    pub scope: &'static str,
    pub legal_notice: &'static str,
    /// The produced ASiC container, base64-encoded.
    pub asic_base64: String,
    /// SHA-256 of the produced container (hex).
    pub asic_sha256: String,
    /// The container kind (`ASiC-S` / `ASiC-E`).
    pub container: &'static str,
    /// The XAdES level applied to XAdES signers (`XAdES-B` / `XAdES-T`).
    pub xades_level: &'static str,
    pub payload_count: usize,
    pub cades_signature_count: usize,
    pub xades_signature_count: usize,
    /// Whether an archive manifest + archive timestamp was embedded.
    pub archive_timestamp: bool,
}

/// `POST /v1/signature/asic/sign` — produce an ASiC-S-XAdES or multi-signature ASiC-E container.
pub async fn sign_asic(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<AsicSignRequestBody>,
) -> Result<Json<AsicSignResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SigningPerform, Scope::Global).await?;

    if !state.local_signing {
        return Err(ApiError::Conflict(
            "a assinatura ASiC local com certificado de software só está disponível na aplicação \
             de secretária (co-localizada com a chave privada)"
                .to_owned(),
        ));
    }

    if req.payloads.is_empty() {
        return Err(ApiError::Unprocessable(
            "an ASiC container requires at least one payload".to_owned(),
        ));
    }
    if req.signers.is_empty() {
        return Err(ApiError::Unprocessable(
            "an ASiC container requires at least one signer".to_owned(),
        ));
    }

    let level = match req.xades_level {
        LevelRequest::B => XadesLevel::B,
        LevelRequest::T => XadesLevel::T,
    };
    let container = req.container;

    if container == ContainerRequest::AsicSXades {
        if req.payloads.len() != 1 {
            return Err(ApiError::Unprocessable(
                "ASiC-S carries exactly one payload".to_owned(),
            ));
        }
        if req.signers.len() != 1 {
            return Err(ApiError::Unprocessable(
                "ASiC-S carries exactly one signature".to_owned(),
            ));
        }
        if req.archive_timestamp {
            return Err(ApiError::Unprocessable(
                "the archive timestamp applies to ASiC-E containers only".to_owned(),
            ));
        }
    }

    // Decode + bound-check payloads.
    let mut owned_payloads: Vec<OwnedPayload> = Vec::with_capacity(req.payloads.len());
    for p in req.payloads {
        let name = p.name.trim().to_owned();
        if name.is_empty() {
            return Err(ApiError::Unprocessable(
                "each payload requires a name".to_owned(),
            ));
        }
        let bytes = decode_member(&p.content_base64, "payload")?;
        owned_payloads.push(OwnedPayload {
            name,
            bytes,
            mime_type: p
                .mime_type
                .map(|m| m.trim().to_owned())
                .filter(|m| !m.is_empty()),
        });
    }

    // Decode + bound-check signer material.
    let mut owned_signers: Vec<OwnedSigner> = Vec::with_capacity(req.signers.len());
    for s in req.signers {
        let der = Zeroizing::new(decode_member(&s.pkcs12_base64, "PKCS#12")?);
        if der.is_empty() {
            return Err(ApiError::Unprocessable(
                "PKCS#12 upload is empty".to_owned(),
            ));
        }
        owned_signers.push(OwnedSigner {
            role: s.role,
            der,
            passphrase: Zeroizing::new(s.passphrase),
            friendly_name: s
                .friendly_name
                .map(|n| n.trim().to_owned())
                .filter(|n| !n.is_empty()),
        });
    }

    let cades_count = owned_signers
        .iter()
        .filter(|s| s.role == SignerRole::Cades)
        .count();
    let xades_count = owned_signers.len() - cades_count;
    let payload_count = owned_payloads.len();

    // Resolve a live TSA if XAdES-T or the archive timestamp is requested (a clean 422 if none is
    // configured), before the blocking signing task.
    let need_tsa = matches!(level, XadesLevel::T) || req.archive_timestamp;
    let tsa_client = if need_tsa {
        let provider = crate::signature::configured_tsa_provider(&state)
            .await?
            .ok_or_else(|| {
                ApiError::Unprocessable(
                    "o carimbo temporal ASiC (XAdES-T / manifesto de arquivo) requer um prestador \
                     TSA configurado"
                        .to_owned(),
                )
            })?;
        Some(crate::signature::build_bounded_tsa_client(&provider)?)
    } else {
        None
    };

    let signing_time = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    let archive_timestamp = req.archive_timestamp;

    let asic_bytes = tokio::task::spawn_blocking(move || {
        // Load every signer's private key up-front so a bad PFX is a clean error before any bytes
        // are produced.
        let sources: Vec<(SignerRole, Pkcs12SigningSource)> = owned_signers
            .iter()
            .map(|s| {
                let selector = s
                    .friendly_name
                    .as_deref()
                    .map(|name| Pkcs12IdentitySelector::by_friendly_name(name.to_owned()))
                    .unwrap_or_else(Pkcs12IdentitySelector::any);
                let source = Pkcs12SigningSource::from_der_with_selector(
                    s.der.as_slice(),
                    &s.passphrase,
                    &selector,
                )?;
                Ok::<_, SigningError>((s.role, source))
            })
            .collect::<Result<_, _>>()?;

        let tsa_dyn: Option<&dyn TimestampProvider> =
            tsa_client.as_ref().map(|c| c as &dyn TimestampProvider);

        match container {
            ContainerRequest::AsicSXades => {
                let payload = &owned_payloads[0];
                let source = &sources[0].1;
                sign_asic_s_xades(
                    source,
                    &payload.name,
                    &payload.bytes,
                    signing_time,
                    level,
                    if matches!(level, XadesLevel::T) {
                        tsa_dyn
                    } else {
                        None
                    },
                )
            }
            ContainerRequest::AsicEMulti => {
                let payloads: Vec<AsicPayload<'_>> = owned_payloads
                    .iter()
                    .map(|p| AsicPayload {
                        name: p.name.as_str(),
                        bytes: p.bytes.as_slice(),
                        mime_type: p.mime_type.as_deref(),
                    })
                    .collect();
                let cades_signers: Vec<&dyn SignerProvider> = sources
                    .iter()
                    .filter(|(role, _)| *role == SignerRole::Cades)
                    .map(|(_, s)| s as &dyn SignerProvider)
                    .collect();
                let xades_signers: Vec<&dyn SignerProvider> = sources
                    .iter()
                    .filter(|(role, _)| *role == SignerRole::Xades)
                    .map(|(_, s)| s as &dyn SignerProvider)
                    .collect();
                sign_asic_e_multi(AsicEMultiSignRequest {
                    payloads: &payloads,
                    cades_signers: &cades_signers,
                    xades_signers: &xades_signers,
                    signing_time,
                    xades_level: level,
                    xades_tsa: if matches!(level, XadesLevel::T) {
                        tsa_dyn
                    } else {
                        None
                    },
                    archive_tsa: if archive_timestamp { tsa_dyn } else { None },
                })
            }
        }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("ASiC signing task failed: {e}")))?
    .map_err(map_signing_error)?;

    Ok(Json(AsicSignResponse {
        report_kind: REPORT_KIND,
        scope: SCOPE,
        legal_notice: LEGAL_NOTICE,
        asic_sha256: sha256_hex(&asic_bytes),
        asic_base64: B64.encode(&asic_bytes),
        container: match container {
            ContainerRequest::AsicSXades => "ASiC-S",
            ContainerRequest::AsicEMulti => "ASiC-E",
        },
        xades_level: match level {
            XadesLevel::B => "XAdES-B",
            XadesLevel::T => "XAdES-T",
            XadesLevel::LT => "XAdES-LT",
            XadesLevel::LTA => "XAdES-LTA",
        },
        payload_count,
        cades_signature_count: cades_count,
        xades_signature_count: xades_count,
        archive_timestamp,
    }))
}

struct OwnedPayload {
    name: String,
    bytes: Vec<u8>,
    mime_type: Option<String>,
}

struct OwnedSigner {
    role: SignerRole,
    der: Zeroizing<Vec<u8>>,
    passphrase: Zeroizing<String>,
    friendly_name: Option<String>,
}

fn decode_member(base64: &str, label: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = B64
        .decode(base64.trim())
        .map_err(|e| ApiError::Unprocessable(format!("invalid base64 {label} content: {e}")))?;
    if bytes.len() > ASIC_SIGN_MAX_MEMBER_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "{label} is {} bytes; ASiC signing accepts at most {} bytes per member",
            bytes.len(),
            ASIC_SIGN_MAX_MEMBER_BYTES
        )));
    }
    Ok(bytes)
}

fn map_signing_error(err: SigningError) -> ApiError {
    match &err {
        SigningError::SoftCertificate(e) => ApiError::Unprocessable(format!(
            "não foi possível carregar o certificado PKCS#12: {e}"
        )),
        SigningError::Xades(msg) => {
            ApiError::Unprocessable(format!("falha ao produzir a assinatura XAdES: {msg}"))
        }
        SigningError::Asic(msg) => {
            ApiError::Unprocessable(format!("falha ao produzir o contentor ASiC: {msg}"))
        }
        SigningError::Timestamp(msg) => {
            ApiError::Unprocessable(format!("falha ao obter carimbo temporal: {msg}"))
        }
        _ => ApiError::Internal(format!("ASiC signing failed: {err}")),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
