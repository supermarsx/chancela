//! SCAP (professional-attribute) endpoints for Ferramentas (t67-e10).
//!
//! Three endpoints over the `chancela-scap` client:
//!
//! - `POST /v1/scap/providers` — list the attribute providers SCAP knows about.
//! - `POST /v1/scap/attributes` — fetch the professional attributes SCAP reports for a citizen.
//! - `POST /v1/scap/sign` — attach a professional-attribute selection at signing time: build the
//!   signature evidence, produce a CAdES attribute-qualified signature over caller content with a
//!   co-located software certificate, and report the **honesty status** of the capacity claim.
//!
//! ## Honesty-marker evolution (t67 §1.2 — binding)
//!
//! The verification status is decided *by the transport*, never by this layer. The default transport
//! is [`MockScapTransport`], which is structurally incapable of yielding a verified status — so every
//! mock-backed signature reports `declared_capacity_by_provider` /
//! `declared_capacity_evidence_only`, never `verified_by_scap`. A `verified_by_scap` status is only
//! reachable through the real [`HttpScapTransport`] on a live `Granted` decision. The real transport
//! is selected only when the deployment is configured for AMA production **with** credentials; a
//! production request without credentials **fails closed** (mirrors the `chancela-cmd`
//! PROD-without-AMA-cert rejection).
//!
//! The transport selection can be forced to `prod` per request (`"environment": "prod"`) so the
//! fail-closed invariant is exercised deterministically at the API boundary; without deployment
//! credentials that path is rejected before any signature is produced.

use axum::Json;
use axum::extract::State;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_authz::{Permission, Scope};
use chancela_scap::{
    AmaScapConfig, AttributeProvider, CadesAttributeBinder, CitizenRef, EvidenceReport,
    HttpScapTransport, MockScapTransport, ProfessionalAttribute, ScapClient, ScapCredentials,
    ScapError, ScapSignatureEvidence,
};
use chancela_signing::{Pkcs12IdentitySelector, Pkcs12SigningSource, SignerProvider};
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

/// Envelope cap for the SCAP sign endpoint (PKCS#12 + content).
pub(crate) const SCAP_SIGN_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Body limit applied at the router.
pub(crate) const SCAP_SIGN_ENVELOPE_BYTES: usize = SCAP_SIGN_MAX_BYTES * 2;

const PROVIDERS_REPORT_KIND: &str = "scap_attribute_providers";
const ATTRIBUTES_REPORT_KIND: &str = "scap_citizen_attributes";
const SIGN_REPORT_KIND: &str = "scap_professional_attribute_signature";
const DECLARED_LEGAL_NOTICE: &str = "The professional capacity is a declared claim reported by the \
attribute provider; it was not verified against SCAP. This response makes no qualified-signature or \
legal-validity claim.";
const VERIFIED_LEGAL_NOTICE: &str = "The professional capacity was verified against SCAP on a live \
Granted decision. This response still makes no qualified-signature or legal-validity claim.";

/// The environment/transport selection for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EnvironmentRequest {
    /// Offline mock transport (default). Always declared-only.
    #[default]
    Preprod,
    /// Real AMA production HTTP transport. Requires deployment credentials or fails closed.
    Prod,
}

/// A SCAP client bound to a concrete transport, dispatched at the enum boundary so the handlers stay
/// transport-agnostic.
enum ScapClientKind {
    Mock(ScapClient<MockScapTransport>),
    Http(ScapClient<HttpScapTransport>),
}

impl ScapClientKind {
    fn transport_kind(&self) -> &'static str {
        match self {
            ScapClientKind::Mock(_) => "mock",
            ScapClientKind::Http(_) => "http",
        }
    }

    fn environment_label(&self) -> &'static str {
        match self {
            ScapClientKind::Mock(_) => "preprod",
            ScapClientKind::Http(_) => "prod",
        }
    }

    fn list_providers(&self) -> Result<Vec<AttributeProvider>, ScapError> {
        match self {
            ScapClientKind::Mock(c) => c.list_providers(),
            ScapClientKind::Http(c) => c.list_providers(),
        }
    }

    fn fetch_attributes(
        &self,
        citizen: &CitizenRef,
    ) -> Result<Vec<ProfessionalAttribute>, ScapError> {
        match self {
            ScapClientKind::Mock(c) => c.fetch_attributes(citizen),
            ScapClientKind::Http(c) => c.fetch_attributes(citizen),
        }
    }

    fn build_signature_evidence(
        &self,
        attribute: ProfessionalAttribute,
        citizen: &CitizenRef,
    ) -> Result<ScapSignatureEvidence, ScapError> {
        match self {
            ScapClientKind::Mock(c) => c.build_signature_evidence(attribute, citizen),
            ScapClientKind::Http(c) => c.build_signature_evidence(attribute, citizen),
        }
    }

    fn verify_evidence(
        &self,
        evidence: &ScapSignatureEvidence,
    ) -> Result<EvidenceReport, ScapError> {
        match self {
            ScapClientKind::Mock(c) => c.verify_evidence(evidence),
            ScapClientKind::Http(c) => c.verify_evidence(evidence),
        }
    }

    fn qualified_signing_digest(
        &self,
        binder: &CadesAttributeBinder,
        content_digest: &[u8; 32],
        evidence: &ScapSignatureEvidence,
        signing_cert_der: &[u8],
        signing_time: OffsetDateTime,
    ) -> Result<[u8; 32], ScapError> {
        match self {
            ScapClientKind::Mock(c) => c.qualified_signing_digest(
                binder,
                content_digest,
                evidence,
                signing_cert_der,
                signing_time,
            ),
            ScapClientKind::Http(c) => c.qualified_signing_digest(
                binder,
                content_digest,
                evidence,
                signing_cert_der,
                signing_time,
            ),
        }
    }

    fn assemble_qualified_signature(
        &self,
        binder: &CadesAttributeBinder,
        raw: &chancela_signing::RawSignature,
        content_digest: &[u8; 32],
        evidence: &ScapSignatureEvidence,
        signing_time: OffsetDateTime,
    ) -> Result<Vec<u8>, ScapError> {
        match self {
            ScapClientKind::Mock(c) => {
                c.assemble_qualified_signature(binder, raw, content_digest, evidence, signing_time)
            }
            ScapClientKind::Http(c) => {
                c.assemble_qualified_signature(binder, raw, content_digest, evidence, signing_time)
            }
        }
    }
}

/// Build the SCAP client for the requested environment.
///
/// Preprod → the offline [`MockScapTransport`] (no credentials, always declared-only). Prod → the
/// real [`HttpScapTransport`], which **fails closed** without the deployment-supplied AMA
/// credentials (`CHANCELA_SCAP_APPLICATION_ID` + `CHANCELA_SCAP_SECRET`).
fn build_scap_client(environment: EnvironmentRequest) -> Result<ScapClientKind, ApiError> {
    match environment {
        EnvironmentRequest::Preprod => {
            let client = ScapClient::new(AmaScapConfig::preprod(), MockScapTransport::default())
                .map_err(map_scap_error)?;
            Ok(ScapClientKind::Mock(client))
        }
        EnvironmentRequest::Prod => {
            let credentials = match (
                env_nonempty("CHANCELA_SCAP_APPLICATION_ID"),
                env_nonempty("CHANCELA_SCAP_SECRET"),
            ) {
                (Some(app), Some(secret)) => Some(ScapCredentials::new(app, secret)),
                _ => None,
            };
            // A prod config without credentials fails closed at `ScapClient::new`/
            // `HttpScapTransport::new` (both call `validate*`). Build the config explicitly so the
            // rejection happens here rather than depending on process-env presence.
            let config = match credentials {
                Some(creds) => AmaScapConfig::prod(creds),
                None => AmaScapConfig {
                    environment: chancela_scap::ScapEnvironment::Prod,
                    base_url: chancela_scap::config::PROD_BASE_URL.to_owned(),
                    credentials: None,
                    provider_filter: None,
                },
            };
            let transport = HttpScapTransport::new(config.clone()).map_err(map_scap_error)?;
            let client = ScapClient::new(config, transport).map_err(map_scap_error)?;
            Ok(ScapClientKind::Http(client))
        }
    }
}

/// Body of `POST /v1/scap/providers`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ScapProvidersRequest {
    #[serde(default)]
    environment: EnvironmentRequest,
}

/// Response of `POST /v1/scap/providers`.
#[derive(Debug, Serialize)]
pub struct ScapProvidersResponse {
    pub report_kind: &'static str,
    pub environment: &'static str,
    pub transport: &'static str,
    pub providers: Vec<AttributeProviderDto>,
}

#[derive(Debug, Serialize)]
pub struct AttributeProviderDto {
    pub id: String,
    pub name: String,
    pub attribute_names: Vec<String>,
}

/// Body of `POST /v1/scap/attributes`.
#[derive(Debug, Deserialize)]
pub(crate) struct ScapAttributesRequest {
    citizen_id: String,
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    environment: EnvironmentRequest,
}

/// Response of `POST /v1/scap/attributes`.
#[derive(Debug, Serialize)]
pub struct ScapAttributesResponse {
    pub report_kind: &'static str,
    pub environment: &'static str,
    pub transport: &'static str,
    pub citizen_id: String,
    pub attributes: Vec<ProfessionalAttributeDto>,
}

#[derive(Debug, Serialize)]
pub struct ProfessionalAttributeDto {
    pub provider_id: String,
    pub provider_name: String,
    pub name: String,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub sub_attributes: Vec<SubAttributeDto>,
}

#[derive(Debug, Serialize)]
pub struct SubAttributeDto {
    pub name: String,
    pub value: String,
}

/// The signer material for the SCAP sign endpoint. Only the co-located software-certificate lane is
/// wired in this slice.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SignerRequest {
    SoftPkcs12 {
        pkcs12_base64: String,
        passphrase: String,
        #[serde(default)]
        friendly_name: Option<String>,
    },
}

/// Body of `POST /v1/scap/sign`.
#[derive(Debug, Deserialize)]
pub(crate) struct ScapSignRequest {
    citizen_id: String,
    #[serde(default)]
    full_name: Option<String>,
    /// The id of the provider whose attribute is being attached.
    provider_id: String,
    /// The professional attribute name being attached (must be one SCAP reports for the citizen).
    attribute_name: String,
    /// Base64 content the attribute-qualified signature binds over.
    content_base64: String,
    signer: SignerRequest,
    #[serde(default)]
    environment: EnvironmentRequest,
}

/// Response of `POST /v1/scap/sign`.
#[derive(Debug, Serialize)]
pub struct ScapSignResponse {
    pub report_kind: &'static str,
    pub environment: &'static str,
    pub transport: &'static str,
    pub legal_notice: &'static str,
    /// The honesty status of the professional-capacity claim.
    pub verification: ScapVerificationDto,
    /// SHA-256 of the bound content (hex).
    pub content_sha256: String,
    /// The CAdES attribute-qualified signature, base64-encoded.
    pub signature_base64: String,
    /// SHA-256 of the produced signature (hex).
    pub signature_sha256: String,
    /// The signer's leaf-certificate subject DN, best-effort.
    pub signer_cert_subject: Option<String>,
    /// SHA-256 of the signer's leaf certificate DER (hex).
    pub signer_cert_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct ScapVerificationDto {
    /// Whether a real SCAP verification backs this capacity. Always `false` for the mock transport.
    pub verified: bool,
    /// The `verification_status` marker (`verified_by_scap` / `declared_capacity_by_provider` / ...).
    pub verification_status: &'static str,
    /// The `status_scope` marker (`scap_verified_capacity` / `declared_capacity_evidence_only`).
    pub status_scope: &'static str,
    pub attribute_name: String,
    pub provider_id: String,
}

/// `POST /v1/scap/providers` — list attribute providers.
pub async fn list_providers(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<ScapProvidersRequest>,
) -> Result<Json<ScapProvidersResponse>, ApiError> {
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;

    let providers = tokio::task::spawn_blocking(move || {
        let client = build_scap_client(req.environment)?;
        let providers = client.list_providers().map_err(map_scap_error)?;
        Ok::<_, ApiError>((
            client.environment_label(),
            client.transport_kind(),
            providers,
        ))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("SCAP provider-list task failed: {e}")))??;

    let (environment, transport, providers) = providers;
    Ok(Json(ScapProvidersResponse {
        report_kind: PROVIDERS_REPORT_KIND,
        environment,
        transport,
        providers: providers.into_iter().map(provider_dto).collect(),
    }))
}

/// `POST /v1/scap/attributes` — fetch the professional attributes SCAP reports for a citizen.
pub async fn fetch_attributes(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<ScapAttributesRequest>,
) -> Result<Json<ScapAttributesResponse>, ApiError> {
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;

    let citizen_id = req.citizen_id.trim().to_owned();
    if citizen_id.is_empty() {
        return Err(ApiError::Unprocessable("citizen_id is required".to_owned()));
    }
    let citizen = citizen_ref(&citizen_id, req.full_name.as_deref());

    let result = tokio::task::spawn_blocking(move || {
        let client = build_scap_client(req.environment)?;
        let attributes = client.fetch_attributes(&citizen).map_err(map_scap_error)?;
        Ok::<_, ApiError>((
            client.environment_label(),
            client.transport_kind(),
            attributes,
        ))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("SCAP attribute-fetch task failed: {e}")))??;

    let (environment, transport, attributes) = result;
    Ok(Json(ScapAttributesResponse {
        report_kind: ATTRIBUTES_REPORT_KIND,
        environment,
        transport,
        citizen_id,
        attributes: attributes.into_iter().map(attribute_dto).collect(),
    }))
}

/// `POST /v1/scap/sign` — attach a professional-attribute selection and produce a CAdES
/// attribute-qualified signature over caller content, reporting the honest capacity status.
pub async fn sign_with_attribute(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<ScapSignRequest>,
) -> Result<Json<ScapSignResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SigningPerform, Scope::Global).await?;

    if !state.local_signing {
        return Err(ApiError::Conflict(
            "a assinatura SCAP com certificado de software só está disponível na aplicação de \
             secretária (co-localizada com a chave privada)"
                .to_owned(),
        ));
    }

    let citizen_id = req.citizen_id.trim().to_owned();
    if citizen_id.is_empty() {
        return Err(ApiError::Unprocessable("citizen_id is required".to_owned()));
    }
    let provider_id = req.provider_id.trim().to_owned();
    let attribute_name = req.attribute_name.trim().to_owned();
    if provider_id.is_empty() || attribute_name.is_empty() {
        return Err(ApiError::Unprocessable(
            "provider_id and attribute_name are required".to_owned(),
        ));
    }

    let content = B64
        .decode(req.content_base64.trim())
        .map_err(|e| ApiError::Unprocessable(format!("invalid base64 content: {e}")))?;
    if content.is_empty() {
        return Err(ApiError::Unprocessable("content is empty".to_owned()));
    }
    if content.len() > SCAP_SIGN_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "content is {} bytes; SCAP signing accepts at most {} bytes",
            content.len(),
            SCAP_SIGN_MAX_BYTES
        )));
    }
    let content_sha256 = sha256_hex(&content);
    let citizen = citizen_ref(&citizen_id, req.full_name.as_deref());

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
    if pkcs12_der.len() > SCAP_SIGN_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "PKCS#12 upload is {} bytes; SCAP signing accepts at most {} bytes",
            pkcs12_der.len(),
            SCAP_SIGN_MAX_BYTES
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
    let environment = req.environment;

    let outcome = tokio::task::spawn_blocking(move || {
        let client = build_scap_client(environment)?;

        // Select the attribute SCAP reports for this citizen (a claim can only be attached if SCAP
        // reports it — an unreported attribute is a 422, never a silent success).
        let attributes = client.fetch_attributes(&citizen).map_err(map_scap_error)?;
        let attribute = attributes
            .into_iter()
            .find(|a| a.provider_id == provider_id && a.name == attribute_name)
            .ok_or_else(|| {
                ApiError::Unprocessable(format!(
                    "SCAP does not report attribute '{attribute_name}' from provider \
                     '{provider_id}' for this citizen"
                ))
            })?;

        // The transport decides the honesty status; the mock can only ever produce declared-only.
        let evidence = client
            .build_signature_evidence(attribute, &citizen)
            .map_err(map_scap_error)?;
        let report = client.verify_evidence(&evidence).map_err(map_scap_error)?;

        let source = Pkcs12SigningSource::from_der_with_selector(
            pkcs12_der.as_slice(),
            &passphrase,
            &selector,
        )
        .map_err(|e| {
            ApiError::Unprocessable(format!(
                "não foi possível carregar o certificado PKCS#12: {e}"
            ))
        })?;
        let cert_der = source
            .signing_certificate_der()
            .map_err(|e| ApiError::Internal(format!("signer certificate unavailable: {e}")))?;

        let content_digest: [u8; 32] = Sha256::digest(&content).into();
        let binder = CadesAttributeBinder;
        let binding_digest = client
            .qualified_signing_digest(&binder, &content_digest, &evidence, &cert_der, signing_time)
            .map_err(map_scap_error)?;
        let raw = source
            .sign_signed_attributes(&binding_digest)
            .map_err(|e| ApiError::Internal(format!("signer failure: {e}")))?;
        let signature = client
            .assemble_qualified_signature(&binder, &raw, &content_digest, &evidence, signing_time)
            .map_err(map_scap_error)?;

        Ok::<_, ApiError>(SignOutcome {
            environment: client.environment_label(),
            transport: client.transport_kind(),
            report,
            signature,
            cert_der,
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("SCAP signing task failed: {e}")))??;

    let SignOutcome {
        environment,
        transport,
        report,
        signature,
        cert_der,
    } = outcome;

    let legal_notice = if report.verified {
        VERIFIED_LEGAL_NOTICE
    } else {
        DECLARED_LEGAL_NOTICE
    };

    Ok(Json(ScapSignResponse {
        report_kind: SIGN_REPORT_KIND,
        environment,
        transport,
        legal_notice,
        verification: ScapVerificationDto {
            verified: report.verified,
            verification_status: report.verification_status_marker,
            status_scope: report.status_scope_marker,
            attribute_name: report.attribute_name,
            provider_id: report.provider_id,
        },
        content_sha256,
        signature_sha256: sha256_hex(&signature),
        signature_base64: B64.encode(&signature),
        signer_cert_subject: subject_dn(&cert_der),
        signer_cert_sha256: sha256_hex(&cert_der),
    }))
}

struct SignOutcome {
    environment: &'static str,
    transport: &'static str,
    report: EvidenceReport,
    signature: Vec<u8>,
    cert_der: Vec<u8>,
}

fn citizen_ref(citizen_id: &str, full_name: Option<&str>) -> CitizenRef {
    let citizen = CitizenRef::new(citizen_id.to_owned());
    match full_name.map(str::trim).filter(|s| !s.is_empty()) {
        Some(name) => citizen.with_full_name(name.to_owned()),
        None => citizen,
    }
}

fn provider_dto(p: AttributeProvider) -> AttributeProviderDto {
    AttributeProviderDto {
        id: p.id,
        name: p.name,
        attribute_names: p.attribute_names,
    }
}

fn attribute_dto(a: ProfessionalAttribute) -> ProfessionalAttributeDto {
    ProfessionalAttributeDto {
        provider_id: a.provider_id,
        provider_name: a.provider_name,
        name: a.name,
        valid_from: a.valid_from.and_then(|t| t.format(&Rfc3339).ok()),
        valid_until: a.valid_until.and_then(|t| t.format(&Rfc3339).ok()),
        sub_attributes: a
            .sub_attributes
            .into_iter()
            .map(|s| SubAttributeDto {
                name: s.name,
                value: s.value,
            })
            .collect(),
    }
}

/// Map a SCAP error to an HTTP status. A config failure (notably PROD-without-credentials) is a
/// fail-closed `409 Conflict`; a verification denial / unreported attribute is a `422`; transport
/// failures are `502 Bad Gateway`. No SCAP error ever carries credential material (see
/// `chancela-scap` `error.rs`), so echoing the message is safe.
fn map_scap_error(err: ScapError) -> ApiError {
    match &err {
        ScapError::Config(msg) => ApiError::Conflict(format!("configuração SCAP inválida: {msg}")),
        ScapError::Verification(msg) => {
            ApiError::Unprocessable(format!("verificação SCAP falhou: {msg}"))
        }
        ScapError::Signature(msg) => {
            ApiError::Unprocessable(format!("assinatura com atributo SCAP falhou: {msg}"))
        }
        ScapError::Transport(msg) => ApiError::Upstream(format!("transporte SCAP falhou: {msg}")),
        _ => ApiError::Internal(format!("SCAP error: {err}")),
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
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
