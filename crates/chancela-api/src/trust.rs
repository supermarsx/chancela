//! Trusted List catalog endpoints: offline TSL status, provider/service search, and detail views.
//!
//! It parses an on-disk cached Portuguese TSL XML when one is present in the data directory,
//! otherwise it falls back to the bundled `chancela-tsl` fixture. Operators may also trigger an
//! explicit URL/file import into that cache. Imported XML is promoted only after signature/trust
//! anchor validation succeeds; invalid imports are recorded as failed attempts and the previous
//! cache is preserved.

#[cfg(debug_assertions)]
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
#[cfg(debug_assertions)]
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use chancela_authz::{Permission, Scope};
use chancela_tsa::mock::{
    FIXTURE_DIGEST, FIXTURE_NONCE, FIXTURE_REQUEST_DER, FIXTURE_RESPONSE_DER,
};
use chancela_tsa::{QualifiedTimestampPolicy, TimestampRequest, verify_response};
use chancela_tsl::{
    DigitalIdentity, LocalizedText, ServiceHistoryEntry, ServiceStatus, TrustService,
    TrustServiceProvider, TrustedList, parse_tsl, validate_tsl_signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;
use crate::hex;
use crate::settings::{RuntimeTsaProvider, RuntimeTsaSelection, RuntimeTslSelection};

const BUNDLED_PT_TSL: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../chancela-tsl/fixtures/pt-tsl-sample.xml"
));

const DEFAULT_SEARCH_LIMIT: usize = 50;
const MAX_SEARCH_LIMIT: usize = 500;

const CACHE_CANDIDATES: &[&str] = &[
    "tsl.xml",
    "TSLPT.xml",
    "trusted-list.xml",
    "trusted-list.pt.xml",
];
const TRUST_CACHE_FILE: &str = "tsl.xml";
const TRUST_REFRESH_STATUS_FILE: &str = "tsl-refresh-status.json";
const DEFAULT_TSL_FETCH_TIMEOUT_SECONDS: u16 = 30;
const DEFAULT_TSL_FETCH_MAX_BYTES: u64 = 25 * 1024 * 1024;

#[cfg(debug_assertions)]
static LOCAL_TRUST_URL_TEST_ALLOWANCES: OnceLock<Mutex<BTreeMap<String, usize>>> = OnceLock::new();

#[cfg(debug_assertions)]
#[derive(Debug)]
pub struct LocalTrustUrlTestAllowance {
    origin: String,
}

#[cfg(debug_assertions)]
impl Drop for LocalTrustUrlTestAllowance {
    fn drop(&mut self) {
        let allowances = local_trust_url_allowances();
        let mut allowances = allowances.lock().expect("local trust URL test allowances");
        match allowances.get_mut(&self.origin) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                allowances.remove(&self.origin);
            }
            None => {}
        }
    }
}

#[cfg(debug_assertions)]
pub fn allow_local_trust_url_for_tests(
    raw_url: &str,
) -> Result<LocalTrustUrlTestAllowance, String> {
    let url =
        reqwest::Url::parse(raw_url).map_err(|e| format!("invalid local trust test URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "local trust test URL scheme '{}' is not allowed; use http or https",
            url.scheme()
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| "local trust test URL is missing host".to_owned())?;
    let is_loopback = host.parse::<IpAddr>().is_ok_and(is_loopback_ip) || is_localhost_name(host);
    if !is_loopback {
        return Err(format!(
            "local trust test URL host '{}' is not loopback",
            strip_url_host_for_error(host)
        ));
    }
    let origin = url_origin_key(&url)?;
    let allowances = local_trust_url_allowances();
    let mut allowances = allowances.lock().expect("local trust URL test allowances");
    *allowances.entry(origin.clone()).or_insert(0) += 1;
    Ok(LocalTrustUrlTestAllowance { origin })
}

// --- Views -------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum TslSourceKind {
    Cache,
    Fixture,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslSourceView {
    pub kind: TslSourceKind,
    pub path: Option<String>,
    pub note: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TslSignatureStatus {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TslValidationView {
    pub checked_at: String,
    pub signature: TslSignatureStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslSummaryView {
    pub source: TslSourceView,
    pub last_refresh: Option<TslRefreshStatusView>,
    pub scheme_operator_name: String,
    pub scheme_name: String,
    pub scheme_territory: String,
    pub sequence_number: Option<u32>,
    pub issue_date_time: Option<String>,
    pub next_update: Option<String>,
    pub stale: bool,
    pub validation: TslValidationView,
    pub providers: usize,
    pub services: usize,
    pub ca_qc_services: usize,
    pub qualified_esignature_services: usize,
    pub trusted_esignature_services: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TslRefreshSourceKind {
    Url,
    File,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TslRefreshOutcome {
    Success,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TslRefreshStatusView {
    pub attempted_at: String,
    pub source_kind: TslRefreshSourceKind,
    pub source_url: Option<String>,
    pub source_path: Option<String>,
    pub target_path: Option<String>,
    pub outcome: TslRefreshOutcome,
    pub validation: TslValidationView,
    pub providers: Option<usize>,
    pub services: Option<usize>,
    pub ca_qc_services: Option<usize>,
    pub qualified_esignature_services: Option<usize>,
    pub trusted_esignature_services: Option<usize>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TslRefreshRequest {
    pub url: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslCatalogView {
    pub summary: TslSummaryView,
    pub providers: Vec<TslProviderView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslProviderView {
    pub id: String,
    pub name: String,
    pub trade_names: Vec<String>,
    pub information_uris: Vec<String>,
    pub analysis: TslProviderAnalysisView,
    pub services: Vec<TslServiceSummaryView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslServiceStatusView {
    pub kind: String,
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslIdentitySummaryView {
    pub certificates: usize,
    pub subject_names: Vec<String>,
    pub subject_key_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslServiceSummaryView {
    pub id: String,
    pub provider_id: String,
    pub provider_name: String,
    pub name: String,
    pub service_type: String,
    pub status: TslServiceStatusView,
    pub status_starting_time: Option<String>,
    pub status_starting_time_raw: Option<String>,
    pub ca_qc: bool,
    pub qualified_for_esignatures: bool,
    pub trusted_for_esignatures: bool,
    pub additional_service_info: Vec<String>,
    pub service_supply_points: Vec<String>,
    pub history_count: usize,
    pub identities: TslIdentitySummaryView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier_match: Option<Vec<IdentifierMatchField>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslProviderAnalysisView {
    pub services: usize,
    pub granted_services: usize,
    pub withdrawn_services: usize,
    pub other_status_services: usize,
    pub services_with_history: usize,
    pub services_with_supply_points: usize,
    pub ca_qc_services: usize,
    pub qualified_esignature_services: usize,
    pub trusted_esignature_services: usize,
    pub duplicate_service_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslProviderDetailView {
    pub provider: TslProviderView,
    pub summary: TslSummaryView,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslDigitalIdentityView {
    pub kind: String,
    pub value: String,
    pub sha256: Option<String>,
    pub byte_length: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslServiceDetailView {
    #[serde(flatten)]
    pub service: TslServiceSummaryView,
    pub digital_identities: Vec<TslDigitalIdentityView>,
    pub history: Vec<TslServiceHistoryView>,
    pub summary: TslSummaryView,
}

#[derive(Debug, Clone, Serialize)]
pub struct TslServiceHistoryView {
    pub name: String,
    pub service_type: String,
    pub status: TslServiceStatusView,
    pub status_starting_time: Option<String>,
    pub status_starting_time_raw: Option<String>,
    pub additional_service_info: Vec<String>,
    pub service_supply_points: Vec<String>,
    pub identities: TslIdentitySummaryView,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum TsaStatusKind {
    Ready,
    Unconfigured,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum TsaProbeKind {
    Fixture,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum TsaProbeStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct TsaProfileView {
    pub protocol: String,
    pub hash_algorithm: String,
    pub request_content_type: String,
    pub response_content_type: String,
    pub nonce_policy: String,
    pub cert_req_default: bool,
    pub accepted_policy: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TsaAcceptedHashView {
    pub algorithm: String,
    pub input: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TsaTimestampMetadataView {
    pub gen_time: String,
    pub policy: String,
    pub serial_number: String,
    pub token_sha256: String,
    pub token_bytes: usize,
    pub tsa_certificate_embedded: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TsaProbeView {
    pub kind: TsaProbeKind,
    pub status: TsaProbeStatus,
    pub checked_at: String,
    pub request_der_sha256: String,
    pub response_der_sha256: String,
    pub request_matches_fixture: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TsaTslDiagnosticsView {
    pub source: TslSourceView,
    pub signature: TslSignatureStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TsaSummaryView {
    pub configured_url: Option<String>,
    pub status: TsaStatusKind,
    pub status_message: String,
    pub profile: TsaProfileView,
    pub accepted_hash: TsaAcceptedHashView,
    pub timestamp: Option<TsaTimestampMetadataView>,
    pub last_probe: TsaProbeView,
    pub tsl: TsaTslDiagnosticsView,
    pub records: usize,
    pub granted_records: usize,
    pub trusted_records: usize,
    pub policy_analysis: TsaPolicyAnalysisView,
}

#[derive(Debug, Clone, Serialize)]
pub struct TsaPolicyAnalysisView {
    pub accepted_policy: String,
    pub fixture_policy: Option<String>,
    pub fixture_policy_accepted: bool,
    pub qualified_timestamp_records: usize,
    pub trusted_qualified_timestamp_records: usize,
    pub advisory: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TsaRecordView {
    pub id: String,
    pub provider_id: String,
    pub provider_name: String,
    pub name: String,
    pub service_type: String,
    pub status: TslServiceStatusView,
    pub status_starting_time: Option<String>,
    pub status_starting_time_raw: Option<String>,
    pub qualified_timestamp_service: bool,
    pub granted: bool,
    pub effective: bool,
    pub trusted: bool,
    pub additional_service_info: Vec<String>,
    pub service_supply_points: Vec<String>,
    pub history_count: usize,
    pub identities: TslIdentitySummaryView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier_match: Option<Vec<IdentifierMatchField>>,
    pub analysis: TsaRecordAnalysisView,
}

#[derive(Debug, Clone, Serialize)]
pub struct TsaRecordAnalysisView {
    pub classification: String,
    pub trust_basis: String,
    pub blocking_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TsaCatalogView {
    pub summary: TsaSummaryView,
    pub records: Vec<TsaRecordView>,
}

#[derive(Deserialize)]
pub struct TslCatalogQuery {
    pub search: Option<String>,
    pub identifier: Option<String>,
    pub service_type: Option<String>,
    pub status: Option<String>,
    pub history: Option<String>,
    pub supply_point: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Deserialize)]
pub struct TsaCatalogQuery {
    pub search: Option<String>,
    pub identifier: Option<String>,
    pub service_type: Option<String>,
    pub status: Option<String>,
    pub history: Option<String>,
    pub supply_point: Option<String>,
    pub limit: Option<usize>,
}

struct LoadedTsl {
    xml: Vec<u8>,
    list: TrustedList,
    source: TslSourceView,
    last_refresh: Option<TslRefreshStatusView>,
}

#[derive(Default)]
struct ServiceFilters {
    search: Option<String>,
    identifier: Option<IdentifierFilter>,
    service_type: Option<String>,
    status: Option<String>,
    history: Option<String>,
    supply_point: Option<String>,
}

#[derive(Clone)]
struct IdentifierFilter {
    kind: IdentifierFilterKind,
    value: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IdentifierFilterKind {
    CertificateSha256,
    SubjectKeyId,
    Text,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierMatchField {
    CertificateSha256,
    SubjectKeyId,
    SubjectName,
    Provider,
    Service,
    SupplyPoint,
    Catalog,
}

enum HexLikeInput {
    Hex(String),
    Malformed,
    Text,
}

impl ServiceFilters {
    fn from_tsl_query(query: &TslCatalogQuery) -> Self {
        Self {
            search: folded_query(&query.search),
            identifier: identifier_filter(query.identifier.as_deref()),
            service_type: folded_query(&query.service_type),
            status: folded_query(&query.status),
            history: folded_query(&query.history),
            supply_point: folded_query(&query.supply_point),
        }
    }

    fn from_tsa_query(query: &TsaCatalogQuery) -> Self {
        Self {
            search: folded_query(&query.search),
            identifier: identifier_filter(query.identifier.as_deref()),
            service_type: folded_query(&query.service_type),
            status: folded_query(&query.status),
            history: folded_query(&query.history),
            supply_point: folded_query(&query.supply_point),
        }
    }

    fn is_active(&self) -> bool {
        self.search.is_some()
            || self.identifier.is_some()
            || self.service_type.is_some()
            || self.status.is_some()
            || self.history.is_some()
            || self.supply_point.is_some()
    }
}

// --- Handlers ----------------------------------------------------------------------------------

/// `GET /v1/trust/status` — parsed TSL scheme and validation summary.
pub async fn trust_status(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<TslSummaryView>, ApiError> {
    require_reference_read(&state, &actor).await?;
    let tsl_selection = state.settings.read().await.signing.runtime_tsl_selection();
    let loaded = load_tsl(&state)?;
    let now = OffsetDateTime::now_utc();
    Ok(Json(summary_view(&loaded, now, Some(&tsl_selection))))
}

/// `POST /v1/trust/refresh` — operator-triggered TSL import from a URL or local XML file.
///
/// With an empty body, the handler uses the configured signing TSL URL, falling back to the
/// Portuguese default. The imported XML is parsed and its XML-DSig/trust-anchor status is recorded.
/// Only authenticated lists are cached as `tsl.xml`; invalid signatures fail closed and preserve the
/// previous cache.
pub async fn refresh_trust_tsl(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(request): Json<TslRefreshRequest>,
) -> Result<Json<TslRefreshStatusView>, ApiError> {
    require_reference_refresh(&state, &actor).await?;
    let data_dir = state.data_dir().ok_or_else(|| {
        ApiError::Unprocessable(
            "TSL import requires CHANCELA_DATA_DIR so the cache and last-attempt status can be persisted"
                .to_owned(),
        )
    })?;
    let tsl_selection = state.settings.read().await.signing.runtime_tsl_selection();
    let attempt = tokio::task::spawn_blocking(move || {
        import_tsl_to_cache(data_dir, tsl_selection, request, OffsetDateTime::now_utc())
    })
    .await
    .map_err(|e| ApiError::Internal(format!("TSL import worker failed: {e}")))??;
    Ok(Json(attempt))
}

/// `GET /v1/trust/catalog?search=&service_type=&status=&history=&supply_point=&limit=` —
/// without filters, the full provider catalog; with filters, matching service rows.
pub async fn trust_catalog(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(query): Query<TslCatalogQuery>,
) -> Result<Response, ApiError> {
    require_reference_read(&state, &actor).await?;
    let tsl_selection = state.settings.read().await.signing.runtime_tsl_selection();
    let loaded = load_tsl(&state)?;
    let now = OffsetDateTime::now_utc();
    let signature_valid = validate_tsl_signature(&loaded.xml).is_ok();
    let filters = ServiceFilters::from_tsl_query(&query);
    if filters.is_active() {
        let limit = query
            .limit
            .unwrap_or(DEFAULT_SEARCH_LIMIT)
            .min(MAX_SEARCH_LIMIT);
        Ok(Json(filter_services(
            &loaded.list,
            &filters,
            limit,
            now,
            signature_valid,
        ))
        .into_response())
    } else {
        Ok(Json(catalog_view(&loaded, now, Some(&tsl_selection))).into_response())
    }
}

/// `GET /v1/trust/tsa?search=&service_type=&status=&history=&supply_point=&limit=` — read-only
/// TSA configuration, offline fixture probe, and Trusted List TSA/QTST records. No live timestamp
/// request is issued.
pub async fn trust_tsa(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(query): Query<TsaCatalogQuery>,
) -> Result<Response, ApiError> {
    require_reference_read(&state, &actor).await?;
    let signing = state.settings.read().await.signing.clone();
    let tsa_selection = signing.runtime_tsa_selection();
    let loaded = load_tsl(&state)?;
    let now = OffsetDateTime::now_utc();
    let signature_valid = validate_tsl_signature(&loaded.xml).is_ok();
    let catalog = tsa_catalog_view(&loaded, now, &tsa_selection);
    let filters = ServiceFilters::from_tsa_query(&query);
    if filters.is_active() {
        let limit = query
            .limit
            .unwrap_or(DEFAULT_SEARCH_LIMIT)
            .min(MAX_SEARCH_LIMIT);
        Ok(Json(filter_tsa_records(
            &loaded.list,
            &filters,
            limit,
            now,
            signature_valid,
        ))
        .into_response())
    } else {
        Ok(Json(catalog).into_response())
    }
}

/// `GET /v1/trust/providers/{id}` — provider detail by stable derived id.
pub async fn trust_provider(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
) -> Result<Json<TslProviderDetailView>, ApiError> {
    require_reference_read(&state, &actor).await?;
    let tsl_selection = state.settings.read().await.signing.runtime_tsl_selection();
    let loaded = load_tsl(&state)?;
    let now = OffsetDateTime::now_utc();
    let signature_valid = validate_tsl_signature(&loaded.xml).is_ok();
    let provider = loaded
        .list
        .providers
        .iter()
        .enumerate()
        .find(|(index, p)| provider_id_at(*index, p) == id)
        .map(|(index, p)| provider_view(index, p, now, signature_valid))
        .ok_or(ApiError::NotFound)?;
    Ok(Json(TslProviderDetailView {
        provider,
        summary: summary_view(&loaded, now, Some(&tsl_selection)),
    }))
}

/// `GET /v1/trust/services/{id}` — trust service detail by stable derived id.
pub async fn trust_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
) -> Result<Json<TslServiceDetailView>, ApiError> {
    require_reference_read(&state, &actor).await?;
    let tsl_selection = state.settings.read().await.signing.runtime_tsl_selection();
    let loaded = load_tsl(&state)?;
    let now = OffsetDateTime::now_utc();
    let signature_valid = validate_tsl_signature(&loaded.xml).is_ok();
    for (provider_index, provider) in loaded.list.providers.iter().enumerate() {
        let provider_id = provider_id_at(provider_index, provider);
        for (service_index, service) in provider.services.iter().enumerate() {
            let summary = service_summary(
                &provider_id,
                &provider.name,
                service_index,
                service,
                now,
                signature_valid,
            );
            if summary.id == id {
                return Ok(Json(TslServiceDetailView {
                    digital_identities: digital_identity_views(service),
                    history: service_history_views(service),
                    service: summary,
                    summary: summary_view(&loaded, now, Some(&tsl_selection)),
                }));
            }
        }
    }
    Err(ApiError::NotFound)
}

async fn require_reference_read(state: &AppState, actor: &CurrentActor) -> Result<(), ApiError> {
    // There is no trust-specific verb in the current RBAC catalog. Reuse the read-only reference
    // permission until a future authz migration can add `trust.read` without widening roles here.
    require_permission(state, actor, Permission::CaeRead, Scope::Global).await
}

async fn require_reference_refresh(state: &AppState, actor: &CurrentActor) -> Result<(), ApiError> {
    // There is no trust-specific mutation verb yet. Reuse the reference refresh permission used by
    // CAE operator refreshes until an authz migration can add `trust.refresh`.
    require_permission(state, actor, Permission::CaeRefresh, Scope::Global).await
}

// --- Catalog assembly --------------------------------------------------------------------------

fn import_tsl_to_cache(
    data_dir: PathBuf,
    selection: RuntimeTslSelection,
    request: TslRefreshRequest,
    now: OffsetDateTime,
) -> Result<TslRefreshStatusView, ApiError> {
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| ApiError::Internal(format!("failed to create TSL cache directory: {e}")))?;
    let target_path = data_dir.join(TRUST_CACHE_FILE);
    let status_path = data_dir.join(TRUST_REFRESH_STATUS_FILE);
    let source_path = request
        .path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let source_url = request
        .url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let selected_source = if source_path.is_none() && source_url.is_none() {
        if let Some(error) = selection.selection_error {
            return Err(ApiError::Unprocessable(format!(
                "TSL import could not select a configured source: {error}"
            )));
        }
        selection.selected
    } else {
        None
    };
    let source_kind = if source_path.is_some()
        || selected_source
            .as_ref()
            .and_then(|source| source.location.path())
            .is_some()
    {
        TslRefreshSourceKind::File
    } else {
        TslRefreshSourceKind::Url
    };
    let (display_url, display_path, timeout_seconds, max_bytes) = match selected_source.as_ref() {
        Some(source) if source_path.is_none() && source_url.is_none() => (
            source.location.url().map(str::to_owned),
            source.location.path().map(str::to_owned),
            source.timeout_seconds,
            source.max_bytes,
        ),
        _ => (
            source_url,
            source_path.as_ref().map(|path| path.display().to_string()),
            DEFAULT_TSL_FETCH_TIMEOUT_SECONDS,
            DEFAULT_TSL_FETCH_MAX_BYTES,
        ),
    };
    if display_url.is_none() && display_path.is_none() {
        return Err(ApiError::Unprocessable(
            "TSL import requires an explicit url/path or an enabled signing.tsl_sources entry"
                .to_owned(),
        ));
    }
    let status_source_url = if source_kind == TslRefreshSourceKind::Url {
        display_url.clone()
    } else {
        None
    };

    let fetched = if let Some(path) = display_path.as_deref() {
        read_bounded_tsl_file(path, max_bytes)
    } else {
        fetch_bounded_tsl_url(
            display_url.as_deref().expect("URL source has display_url"),
            timeout_seconds,
            max_bytes,
        )
    };

    let mut status = match &fetched {
        Ok(xml) => status_for_imported_xml(
            xml,
            now,
            source_kind,
            status_source_url.clone(),
            display_path,
            Some(target_path.display().to_string()),
        ),
        Err(error) => failed_refresh_status(
            now,
            source_kind,
            status_source_url,
            display_path,
            Some(target_path.display().to_string()),
            error.clone(),
        ),
    };

    if status.outcome == TslRefreshOutcome::Success {
        let tmp_path = target_path.with_extension("xml.tmp");
        let xml =
            fetched.map_err(|e| ApiError::Internal(format!("missing imported TSL bytes: {e}")))?;
        std::fs::write(&tmp_path, xml)
            .map_err(|e| ApiError::Internal(format!("failed to write TSL cache: {e}")))?;
        std::fs::rename(&tmp_path, &target_path)
            .map_err(|e| ApiError::Internal(format!("failed to replace TSL cache: {e}")))?;
        status.target_path = Some(target_path.display().to_string());
    }

    persist_refresh_status(&status_path, &status)?;
    Ok(status)
}

fn read_bounded_tsl_file(path: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "Trusted List file exceeds configured max_bytes ({len} > {max_bytes})",
            len = bytes.len()
        ));
    }
    Ok(bytes)
}

#[derive(Debug, Clone)]
pub(crate) struct VettedHttpUrl {
    url: reqwest::Url,
    host: String,
    resolved_addrs: Vec<SocketAddr>,
    host_is_ip: bool,
}

impl VettedHttpUrl {
    pub(crate) fn as_str(&self) -> &str {
        self.url.as_str()
    }

    pub(crate) fn client(
        &self,
        timeout: Duration,
    ) -> Result<reqwest::blocking::Client, reqwest::Error> {
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none());
        if !self.host_is_ip {
            builder = builder.resolve_to_addrs(&self.host, &self.resolved_addrs);
        }
        builder.build()
    }
}

pub(crate) fn validate_outbound_http_url(raw_url: &str) -> Result<VettedHttpUrl, String> {
    let url = reqwest::Url::parse(raw_url)
        .map_err(|e| format!("unsafe outbound URL: invalid URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "unsafe outbound URL: scheme '{}' is not allowed; use http or https",
            url.scheme()
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| "unsafe outbound URL: missing host".to_owned())?
        .to_owned();
    let test_origin_allowed = local_trust_url_origin_allowed_for_tests(&url);
    if is_localhost_name(&host) && !test_origin_allowed {
        return Err(format!(
            "unsafe outbound URL: host '{}' is local-only",
            strip_url_host_for_error(&host)
        ));
    }
    let port = url.port_or_known_default().ok_or_else(|| {
        format!(
            "unsafe outbound URL: scheme '{}' has no default port",
            url.scheme()
        )
    })?;

    let host_is_ip = host.parse::<IpAddr>().is_ok();
    let resolved_addrs = if let Ok(ip) = host.parse::<IpAddr>() {
        if is_disallowed_ip_for_outbound_policy(ip, test_origin_allowed) {
            return Err(format!(
                "unsafe outbound URL: host '{}' is a disallowed address",
                strip_url_host_for_error(&host)
            ));
        }
        vec![SocketAddr::new(ip, port)]
    } else {
        let addrs: Vec<SocketAddr> = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| format!("unsafe outbound URL: failed to resolve host '{host}': {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!(
                "unsafe outbound URL: host '{host}' resolved to no addresses"
            ));
        }
        if let Some(addr) = addrs
            .iter()
            .find(|addr| is_disallowed_ip_for_outbound_policy(addr.ip(), test_origin_allowed))
        {
            return Err(format!(
                "unsafe outbound URL: host '{host}' resolves to disallowed address {}",
                addr.ip()
            ));
        }
        addrs
    };

    Ok(VettedHttpUrl {
        url,
        host,
        resolved_addrs,
        host_is_ip,
    })
}

pub(crate) fn validate_outbound_http_url_metadata(raw_url: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(raw_url)
        .map_err(|e| format!("unsafe outbound URL: invalid URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "unsafe outbound URL: scheme '{}' is not allowed; use http or https",
            url.scheme()
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| "unsafe outbound URL: missing host".to_owned())?;
    if is_localhost_name(host) {
        return Err(format!(
            "unsafe outbound URL: host '{}' is local-only",
            strip_url_host_for_error(host)
        ));
    }
    if url.port_or_known_default().is_none() {
        return Err(format!(
            "unsafe outbound URL: scheme '{}' has no default port",
            url.scheme()
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_disallowed_ip(ip) {
            return Err(format!(
                "unsafe outbound URL: host '{}' is a disallowed address",
                strip_url_host_for_error(host)
            ));
        }
    }
    Ok(())
}

fn is_localhost_name(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    normalized == "localhost" || normalized.ends_with(".localhost")
}

fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => is_disallowed_ipv4(addr),
        IpAddr::V6(addr) => is_disallowed_ipv6(addr),
    }
}

fn is_disallowed_ip_for_outbound_policy(ip: IpAddr, test_origin_allowed: bool) -> bool {
    is_disallowed_ip(ip) && !(test_origin_allowed && is_loopback_ip(ip))
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => addr.is_loopback(),
        IpAddr::V6(addr) => addr.is_loopback(),
    }
}

fn local_trust_url_origin_allowed_for_tests(url: &reqwest::Url) -> bool {
    #[cfg(debug_assertions)]
    {
        url_origin_key(url)
            .ok()
            .and_then(|origin| {
                local_trust_url_allowances()
                    .lock()
                    .expect("local trust URL test allowances")
                    .get(&origin)
                    .copied()
            })
            .is_some_and(|count| count > 0)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = url;
        false
    }
}

#[cfg(debug_assertions)]
fn local_trust_url_allowances() -> &'static Mutex<BTreeMap<String, usize>> {
    LOCAL_TRUST_URL_TEST_ALLOWANCES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn url_origin_key(url: &reqwest::Url) -> Result<String, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "URL is missing host".to_owned())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("scheme '{}' has no default port", url.scheme()))?;
    let host = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{}]", host.to_ascii_lowercase())
    } else {
        host.to_ascii_lowercase()
    };
    Ok(format!("{}://{host}:{port}", url.scheme()))
}

fn is_disallowed_ipv4(addr: Ipv4Addr) -> bool {
    addr.is_unspecified()
        || ipv4_in_cidr(addr, Ipv4Addr::new(0, 0, 0, 0), 8)
        || addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_broadcast()
        || addr.is_multicast()
        || ipv4_in_cidr(addr, Ipv4Addr::new(100, 64, 0, 0), 10)
        || ipv4_in_cidr(addr, Ipv4Addr::new(192, 0, 0, 0), 24)
        || ipv4_in_cidr(addr, Ipv4Addr::new(192, 0, 2, 0), 24)
        || ipv4_in_cidr(addr, Ipv4Addr::new(192, 88, 99, 0), 24)
        || ipv4_in_cidr(addr, Ipv4Addr::new(198, 18, 0, 0), 15)
        || ipv4_in_cidr(addr, Ipv4Addr::new(198, 51, 100, 0), 24)
        || ipv4_in_cidr(addr, Ipv4Addr::new(203, 0, 113, 0), 24)
        || ipv4_in_cidr(addr, Ipv4Addr::new(240, 0, 0, 0), 4)
}

fn is_disallowed_ipv6(addr: Ipv6Addr) -> bool {
    if let Some(mapped) = addr.to_ipv4_mapped() {
        return is_disallowed_ipv4(mapped);
    }
    addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_multicast()
        || ipv6_in_cidr(addr, Ipv6Addr::from(0xfc00_u128 << 112), 7)
        || ipv6_in_cidr(addr, Ipv6Addr::from(0xfe80_u128 << 112), 10)
        || ipv6_in_cidr(addr, Ipv6Addr::from(0x2001_0db8_u128 << 96), 32)
        || ipv6_in_cidr(addr, Ipv6Addr::from(0x2001_u128 << 112), 23)
}

fn ipv4_in_cidr(addr: Ipv4Addr, base: Ipv4Addr, prefix: u32) -> bool {
    let addr = u32::from(addr);
    let base = u32::from(base);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (addr & mask) == (base & mask)
}

fn ipv6_in_cidr(addr: Ipv6Addr, base: Ipv6Addr, prefix: u32) -> bool {
    let addr = u128::from(addr);
    let base = u128::from(base);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (addr & mask) == (base & mask)
}

fn strip_url_host_for_error(host: &str) -> String {
    host.trim_matches(['[', ']']).to_owned()
}

fn fetch_bounded_tsl_url(
    url: &str,
    timeout_seconds: u16,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    let vetted = validate_outbound_http_url(url)?;
    let client = vetted
        .client(Duration::from_secs(u64::from(timeout_seconds)))
        .map_err(|e| e.to_string())?;
    let bytes = client
        .get(vetted.as_str())
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|e| e.to_string())?
        .bytes()
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "Trusted List response exceeds configured max_bytes ({len} > {max_bytes})",
            len = bytes.len()
        ));
    }
    Ok(bytes.to_vec())
}

fn status_for_imported_xml(
    xml: &[u8],
    now: OffsetDateTime,
    source_kind: TslRefreshSourceKind,
    source_url: Option<String>,
    source_path: Option<String>,
    target_path: Option<String>,
) -> TslRefreshStatusView {
    match parse_tsl(xml) {
        Ok(list) => {
            let validation_error = validate_tsl_signature(xml)
                .err()
                .map(|e| format!("Trusted List signature/trust-anchor validation failed: {e}"));
            let signature_valid = validation_error.is_none();
            let services = list.services().count();
            let ca_qc_services = list.services().filter(|s| s.is_ca_qc()).count();
            let qualified_esignature_services = list
                .services()
                .filter(|s| qualifies_for_esignature(s, now))
                .count();
            TslRefreshStatusView {
                attempted_at: format_time(now),
                source_kind,
                source_url,
                source_path,
                target_path,
                outcome: if signature_valid {
                    TslRefreshOutcome::Success
                } else {
                    TslRefreshOutcome::Failed
                },
                validation: TslValidationView {
                    checked_at: format_time(now),
                    signature: if signature_valid {
                        TslSignatureStatus::Valid
                    } else {
                        TslSignatureStatus::Invalid
                    },
                    error: validation_error.clone(),
                },
                providers: Some(list.providers.len()),
                services: Some(services),
                ca_qc_services: Some(ca_qc_services),
                qualified_esignature_services: Some(qualified_esignature_services),
                trusted_esignature_services: Some(if signature_valid {
                    qualified_esignature_services
                } else {
                    0
                }),
                error: validation_error.clone(),
            }
        }
        Err(error) => failed_refresh_status(
            now,
            source_kind,
            source_url,
            source_path,
            target_path,
            format!("failed to parse Trusted List: {error}"),
        ),
    }
}

fn failed_refresh_status(
    now: OffsetDateTime,
    source_kind: TslRefreshSourceKind,
    source_url: Option<String>,
    source_path: Option<String>,
    target_path: Option<String>,
    error: String,
) -> TslRefreshStatusView {
    TslRefreshStatusView {
        attempted_at: format_time(now),
        source_kind,
        source_url,
        source_path,
        target_path,
        outcome: TslRefreshOutcome::Failed,
        validation: TslValidationView {
            checked_at: format_time(now),
            signature: TslSignatureStatus::Invalid,
            error: Some(error.clone()),
        },
        providers: None,
        services: None,
        ca_qc_services: None,
        qualified_esignature_services: None,
        trusted_esignature_services: None,
        error: Some(error),
    }
}

fn persist_refresh_status(
    path: &std::path::Path,
    status: &TslRefreshStatusView,
) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec_pretty(status)
        .map_err(|e| ApiError::Internal(format!("failed to serialize TSL refresh status: {e}")))?;
    std::fs::write(path, bytes)
        .map_err(|e| ApiError::Internal(format!("failed to persist TSL refresh status: {e}")))
}

fn load_refresh_status(data_dir: Option<PathBuf>) -> Option<TslRefreshStatusView> {
    let path = data_dir?.join(TRUST_REFRESH_STATUS_FILE);
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn load_tsl(state: &AppState) -> Result<LoadedTsl, ApiError> {
    let (xml, source) = match find_cached_tsl(state.data_dir()) {
        Some(path) => {
            let xml = std::fs::read(&path)
                .map_err(|e| ApiError::Internal(format!("failed to read TSL cache: {e}")))?;
            (
                xml,
                TslSourceView {
                    kind: TslSourceKind::Cache,
                    path: Some(path.display().to_string()),
                    note: "parsed from cached Trusted List XML in the data directory".to_owned(),
                },
            )
        }
        None => (
            BUNDLED_PT_TSL.to_vec(),
            TslSourceView {
                kind: TslSourceKind::Fixture,
                path: None,
                note: "parsed from bundled chancela-tsl fixture; no live TSL fetch attempted"
                    .to_owned(),
            },
        ),
    };
    let list = parse_tsl(&xml)
        .map_err(|e| ApiError::Internal(format!("failed to parse Trusted List: {e}")))?;
    let last_refresh = load_refresh_status(state.data_dir());
    Ok(LoadedTsl {
        xml,
        list,
        source,
        last_refresh,
    })
}

fn find_cached_tsl(data_dir: Option<PathBuf>) -> Option<PathBuf> {
    let dir = data_dir?;
    CACHE_CANDIDATES
        .iter()
        .map(|name| dir.join(name))
        .find(|path| path.is_file())
}

fn catalog_view(
    loaded: &LoadedTsl,
    now: OffsetDateTime,
    runtime_selection: Option<&RuntimeTslSelection>,
) -> TslCatalogView {
    let signature_valid = validate_tsl_signature(&loaded.xml).is_ok();
    TslCatalogView {
        summary: summary_view(loaded, now, runtime_selection),
        providers: loaded
            .list
            .providers
            .iter()
            .enumerate()
            .map(|(index, p)| provider_view(index, p, now, signature_valid))
            .collect(),
    }
}

fn summary_view(
    loaded: &LoadedTsl,
    now: OffsetDateTime,
    runtime_selection: Option<&RuntimeTslSelection>,
) -> TslSummaryView {
    let validation_error = validate_tsl_signature(&loaded.xml)
        .err()
        .map(|e| e.to_string());
    let signature_valid = validation_error.is_none();
    let services = loaded.list.services().count();
    let ca_qc_services = loaded.list.services().filter(|s| s.is_ca_qc()).count();
    let qualified_esignature_services = loaded
        .list
        .services()
        .filter(|s| qualifies_for_esignature(s, now))
        .count();
    let mut source = loaded.source.clone();
    if let Some(selection) = runtime_selection {
        source.note = tsl_runtime_note(&source.note, selection);
    }
    TslSummaryView {
        source,
        last_refresh: loaded.last_refresh.clone(),
        scheme_operator_name: loaded.list.scheme_operator_name.clone(),
        scheme_name: loaded.list.scheme_name.clone(),
        scheme_territory: loaded.list.scheme_territory.clone(),
        sequence_number: loaded.list.sequence_number,
        issue_date_time: format_optional_time(loaded.list.issue_date_time),
        next_update: format_optional_time(loaded.list.next_update),
        stale: loaded.list.next_update.is_some_and(|next| now >= next),
        validation: TslValidationView {
            checked_at: format_time(now),
            signature: if signature_valid {
                TslSignatureStatus::Valid
            } else {
                TslSignatureStatus::Invalid
            },
            error: validation_error,
        },
        providers: loaded.list.providers.len(),
        services,
        ca_qc_services,
        qualified_esignature_services,
        trusted_esignature_services: if signature_valid {
            qualified_esignature_services
        } else {
            0
        },
    }
}

fn tsl_runtime_note(base: &str, selection: &RuntimeTslSelection) -> String {
    let detail = if let Some(error) = &selection.selection_error {
        format!(
            "runtime TSL selection error: {error}; configured_sources={}, enabled={}, disabled={}",
            selection.configured_count, selection.enabled_count, selection.disabled_count
        )
    } else if let Some(source) = &selection.selected {
        format!(
            "runtime TSL source '{}' selected from {} configured source(s), {} enabled, {} disabled; location={}; compatibility_fallback={}",
            source.id,
            selection.configured_count,
            selection.enabled_count,
            selection.disabled_count,
            source.location.kind(),
            source.legacy
        )
    } else {
        format!(
            "no runtime TSL source selected; configured_sources={}, enabled={}, disabled={}",
            selection.configured_count, selection.enabled_count, selection.disabled_count
        )
    };
    format!("{base}; {detail}")
}

fn provider_view(
    provider_index: usize,
    provider: &TrustServiceProvider,
    now: OffsetDateTime,
    signature_valid: bool,
) -> TslProviderView {
    let id = provider_id_at(provider_index, provider);
    TslProviderView {
        id: id.clone(),
        name: provider.name.clone(),
        trade_names: provider.trade_names.clone(),
        information_uris: provider.information_uris.clone(),
        analysis: provider_analysis(provider, now, signature_valid),
        services: provider
            .services
            .iter()
            .enumerate()
            .map(|(index, s)| service_summary(&id, &provider.name, index, s, now, signature_valid))
            .collect(),
    }
}

fn service_summary(
    provider_id: &str,
    provider_name: &str,
    service_index: usize,
    service: &TrustService,
    now: OffsetDateTime,
    signature_valid: bool,
) -> TslServiceSummaryView {
    let qualified = qualifies_for_esignature(service, now);
    TslServiceSummaryView {
        id: service_id(provider_id, service_index, service),
        provider_id: provider_id.to_owned(),
        provider_name: provider_name.to_owned(),
        name: service.name.clone(),
        service_type: service.service_type.clone(),
        status: service_status_view(&service.status),
        status_starting_time: format_optional_time(service.status_starting_time),
        status_starting_time_raw: service.status_starting_time_raw.clone(),
        ca_qc: service.is_ca_qc(),
        qualified_for_esignatures: qualified,
        trusted_for_esignatures: signature_valid && qualified,
        additional_service_info: service.additional_service_info.clone(),
        service_supply_points: service.service_supply_points.clone(),
        history_count: service.history.len(),
        identities: identity_summary(service),
        identifier_match: None,
    }
}

#[cfg(test)]
fn search_services(
    list: &TrustedList,
    search: &str,
    limit: usize,
    now: OffsetDateTime,
    signature_valid: bool,
) -> Vec<TslServiceSummaryView> {
    let filters = ServiceFilters {
        search: Some(fold(search)),
        ..ServiceFilters::default()
    };
    filter_services(list, &filters, limit, now, signature_valid)
}

fn filter_services(
    list: &TrustedList,
    filters: &ServiceFilters,
    limit: usize,
    now: OffsetDateTime,
    signature_valid: bool,
) -> Vec<TslServiceSummaryView> {
    let list_text = fold(&format!(
        "{} {} {} {} {}",
        list.scheme_operator_name,
        localized_text_values(&list.scheme_operator_names),
        list.scheme_name,
        localized_text_values(&list.scheme_names),
        list.scheme_territory
    ));
    let mut out = Vec::new();
    for (provider_index, provider) in list.providers.iter().enumerate() {
        let provider_id = provider_id_at(provider_index, provider);
        let provider_text = fold(&format!(
            "{} {} {} {} {}",
            provider.name,
            localized_text_values(&provider.names),
            provider.trade_names.join(" "),
            localized_text_values(&provider.localized_trade_names),
            provider.information_uris.join(" ")
        ));
        for (service_index, service) in provider.services.iter().enumerate() {
            let service_text = fold(&service_search_text(service));
            if let Some(identifier_match) =
                service_matches_filters(service, &list_text, &provider_text, &service_text, filters)
            {
                let mut summary = service_summary(
                    &provider_id,
                    &provider.name,
                    service_index,
                    service,
                    now,
                    signature_valid,
                );
                summary.identifier_match = identifier_match;
                out.push(summary);
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
}

fn tsa_catalog_view(
    loaded: &LoadedTsl,
    now: OffsetDateTime,
    selection: &RuntimeTsaSelection,
) -> TsaCatalogView {
    let signature_error = validate_tsl_signature(&loaded.xml)
        .err()
        .map(|e| e.to_string());
    let signature_valid = signature_error.is_none();
    let records = tsa_records(&loaded.list, now, signature_valid);
    let granted_records = records.iter().filter(|r| r.granted).count();
    let trusted_records = records.iter().filter(|r| r.trusted).count();
    let (last_probe, timestamp) = tsa_fixture_probe(now);
    let policy_analysis = tsa_policy_analysis(&records, timestamp.as_ref(), signature_valid);
    let configured_url = selection.selected.as_ref().and_then(public_runtime_tsa_url);
    let runtime_error = tsa_runtime_error(selection);
    let status = if runtime_error.is_some() {
        TsaStatusKind::Error
    } else if selection.selected.is_none() {
        TsaStatusKind::Unconfigured
    } else if last_probe.status == TsaProbeStatus::Passed {
        TsaStatusKind::Ready
    } else {
        TsaStatusKind::Error
    };
    let status_message = match status {
        TsaStatusKind::Ready => match selection.selected.as_ref() {
            Some(provider) => format!(
                "TSA provider '{}' selected from {} configured provider(s), {} enabled, {} disabled; offline RFC 3161 fixture probe passed. No live TSA request was sent.",
                provider.id,
                selection.configured_count,
                selection.enabled_count,
                selection.disabled_count
            ),
            None => {
                "TSA URL configured; offline RFC 3161 fixture probe passed. No live TSA request was sent."
                    .to_owned()
            }
        },
        TsaStatusKind::Unconfigured => {
            "No enabled TSA provider or legacy TSA URL is configured; timestamping is unavailable until an operator sets one."
                .to_owned()
        }
        TsaStatusKind::Error => runtime_error.unwrap_or_else(|| {
            "Offline RFC 3161 fixture probe failed; timestamp parsing or verification needs attention."
                .to_owned()
        }),
    };
    TsaCatalogView {
        summary: TsaSummaryView {
            configured_url,
            status,
            status_message,
            profile: TsaProfileView {
                protocol: "RFC 3161 Time-Stamp Protocol".to_owned(),
                hash_algorithm: "SHA-256".to_owned(),
                request_content_type: "application/timestamp-query".to_owned(),
                response_content_type: "application/timestamp-reply".to_owned(),
                nonce_policy: "request nonce must be echoed when present".to_owned(),
                cert_req_default: true,
                accepted_policy: selection
                    .selected
                    .as_ref()
                    .and_then(|provider| provider.policy.clone())
                    .unwrap_or_else(|| "Any".to_owned()),
            },
            accepted_hash: TsaAcceptedHashView {
                algorithm: "SHA-256".to_owned(),
                input: "abc".to_owned(),
                digest: hex::hex(&FIXTURE_DIGEST),
            },
            timestamp,
            last_probe,
            tsl: TsaTslDiagnosticsView {
                source: loaded.source.clone(),
                signature: if signature_valid {
                    TslSignatureStatus::Valid
                } else {
                    TslSignatureStatus::Invalid
                },
                error: signature_error,
            },
            records: records.len(),
            granted_records,
            trusted_records,
            policy_analysis,
        },
        records,
    }
}

fn tsa_fixture_probe(now: OffsetDateTime) -> (TsaProbeView, Option<TsaTimestampMetadataView>) {
    let request = TimestampRequest::new(FIXTURE_DIGEST)
        .without_certificate()
        .with_nonce(FIXTURE_NONCE);
    let request_der_sha256 = cert_fingerprint(FIXTURE_REQUEST_DER);
    let response_der_sha256 = cert_fingerprint(FIXTURE_RESPONSE_DER);
    let mut request_matches_fixture = false;
    let mut error = None;
    let mut status = TsaProbeStatus::Passed;

    match request.to_der() {
        Ok(der) => {
            request_matches_fixture = der == FIXTURE_REQUEST_DER;
            if !request_matches_fixture {
                status = TsaProbeStatus::Failed;
                error =
                    Some("encoded TimeStampReq does not match bundled OpenSSL fixture".to_owned());
            }
        }
        Err(e) => {
            status = TsaProbeStatus::Failed;
            error = Some(e.to_string());
        }
    }

    let timestamp = if status == TsaProbeStatus::Passed {
        match verify_response(
            FIXTURE_RESPONSE_DER,
            &request,
            &QualifiedTimestampPolicy::Any,
        ) {
            Ok(ts) => Some(TsaTimestampMetadataView {
                gen_time: format_time(ts.gen_time),
                policy: ts.policy,
                serial_number: hex_bytes(&ts.serial_number),
                token_sha256: cert_fingerprint(&ts.token_der),
                token_bytes: ts.token_der.len(),
                tsa_certificate_embedded: ts.tsa_certificate_der.is_some(),
            }),
            Err(e) => {
                status = TsaProbeStatus::Failed;
                error = Some(e.to_string());
                None
            }
        }
    } else {
        None
    };

    (
        TsaProbeView {
            kind: TsaProbeKind::Fixture,
            status,
            checked_at: format_time(now),
            request_der_sha256,
            response_der_sha256,
            request_matches_fixture,
            error,
        },
        timestamp,
    )
}

fn tsa_records(
    list: &TrustedList,
    now: OffsetDateTime,
    signature_valid: bool,
) -> Vec<TsaRecordView> {
    let mut out = Vec::new();
    for (provider_index, provider) in list.providers.iter().enumerate() {
        let provider_id = provider_id_at(provider_index, provider);
        for (service_index, service) in provider
            .services
            .iter()
            .enumerate()
            .filter(|(_, s)| is_tsa_service(s))
        {
            out.push(tsa_record(
                &provider_id,
                &provider.name,
                service_index,
                service,
                now,
                signature_valid,
            ));
        }
    }
    out
}

fn tsa_record(
    provider_id: &str,
    provider_name: &str,
    service_index: usize,
    service: &TrustService,
    now: OffsetDateTime,
    signature_valid: bool,
) -> TsaRecordView {
    let granted = service.is_granted();
    let effective = service.is_effective_at(now);
    let qualified_timestamp_service = is_qualified_timestamp_service(service);
    TsaRecordView {
        id: service_id(provider_id, service_index, service),
        provider_id: provider_id.to_owned(),
        provider_name: provider_name.to_owned(),
        name: service.name.clone(),
        service_type: service.service_type.clone(),
        status: service_status_view(&service.status),
        status_starting_time: format_optional_time(service.status_starting_time),
        status_starting_time_raw: service.status_starting_time_raw.clone(),
        qualified_timestamp_service,
        granted,
        effective,
        trusted: signature_valid && granted && effective && qualified_timestamp_service,
        additional_service_info: service.additional_service_info.clone(),
        service_supply_points: service.service_supply_points.clone(),
        history_count: service.history.len(),
        identities: identity_summary(service),
        identifier_match: None,
        analysis: tsa_record_analysis(service, signature_valid, granted, effective),
    }
}

#[cfg(test)]
fn search_tsa_records(
    list: &TrustedList,
    search: &str,
    limit: usize,
    now: OffsetDateTime,
    signature_valid: bool,
) -> Vec<TsaRecordView> {
    let filters = ServiceFilters {
        search: Some(fold(search)),
        ..ServiceFilters::default()
    };
    filter_tsa_records(list, &filters, limit, now, signature_valid)
}

fn filter_tsa_records(
    list: &TrustedList,
    filters: &ServiceFilters,
    limit: usize,
    now: OffsetDateTime,
    signature_valid: bool,
) -> Vec<TsaRecordView> {
    let mut out = Vec::new();
    for (provider_index, provider) in list.providers.iter().enumerate() {
        let provider_id = provider_id_at(provider_index, provider);
        let provider_text = fold(&format!(
            "{} {} {} {} {}",
            provider.name,
            localized_text_values(&provider.names),
            provider.trade_names.join(" "),
            localized_text_values(&provider.localized_trade_names),
            provider.information_uris.join(" ")
        ));
        for (service_index, service) in provider
            .services
            .iter()
            .enumerate()
            .filter(|(_, s)| is_tsa_service(s))
        {
            let service_text = fold(&service_search_text(service));
            if let Some(identifier_match) =
                service_matches_filters(service, "", &provider_text, &service_text, filters)
            {
                let mut record = tsa_record(
                    &provider_id,
                    &provider.name,
                    service_index,
                    service,
                    now,
                    signature_valid,
                );
                record.identifier_match = identifier_match;
                out.push(record);
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
}

fn service_matches_filters(
    service: &TrustService,
    list_text: &str,
    provider_text: &str,
    service_text: &str,
    filters: &ServiceFilters,
) -> Option<Option<Vec<IdentifierMatchField>>> {
    if let Some(search) = &filters.search {
        let matches_search = matches_folded(list_text, search)
            || matches_folded(provider_text, search)
            || matches_folded(service_text, search);
        if !matches_search {
            return None;
        }
    }
    let identifier_match = if let Some(identifier) = &filters.identifier {
        let fields = identity_match_fields(service, list_text, provider_text, identifier);
        if fields.is_empty() {
            return None;
        }
        Some(fields)
    } else {
        None
    };
    if let Some(service_type) = &filters.service_type {
        let current_type = fold(&service.service_type);
        let history_types = service
            .history
            .iter()
            .map(|entry| entry.service_type.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        if !matches_folded(&current_type, service_type)
            && !matches_folded(&fold(&history_types), service_type)
        {
            return None;
        }
    }
    if let Some(status) = &filters.status {
        if !status_matches_filter(&service.status, status) {
            return None;
        }
    }
    if let Some(history) = &filters.history {
        if !history_matches_filter(service, history) {
            return None;
        }
    }
    if let Some(supply_point) = &filters.supply_point {
        if !supply_point_matches_filter(service, supply_point) {
            return None;
        }
    }
    Some(identifier_match)
}

fn identity_match_fields(
    service: &TrustService,
    list_text: &str,
    provider_text: &str,
    filter: &IdentifierFilter,
) -> Vec<IdentifierMatchField> {
    match filter.kind {
        IdentifierFilterKind::Unknown => Vec::new(),
        IdentifierFilterKind::CertificateSha256 => {
            if service.digital_identities.iter().any(|id| {
                matches!(id, DigitalIdentity::Certificate(der) if cert_fingerprint(der) == filter.value)
            }) {
                vec![IdentifierMatchField::CertificateSha256]
            } else {
                Vec::new()
            }
        }
        IdentifierFilterKind::SubjectKeyId => {
            if service.digital_identities.iter().any(|id| {
                matches!(id, DigitalIdentity::SubjectKeyId(ski) if hex_bytes(ski) == filter.value)
            }) {
                vec![IdentifierMatchField::SubjectKeyId]
            } else {
                Vec::new()
            }
        }
        IdentifierFilterKind::Text => {
            let mut fields = Vec::new();
            if subject_name_matches_filter(service, &filter.value) {
                push_identifier_match(&mut fields, IdentifierMatchField::SubjectName);
            }
            if matches_folded(provider_text, &filter.value) {
                push_identifier_match(&mut fields, IdentifierMatchField::Provider);
            }
            if service_text_matches_identifier(service, &filter.value) {
                push_identifier_match(&mut fields, IdentifierMatchField::Service);
            }
            if supply_point_text_matches_identifier(service, &filter.value) {
                push_identifier_match(&mut fields, IdentifierMatchField::SupplyPoint);
            }
            if matches_folded(list_text, &filter.value) {
                push_identifier_match(&mut fields, IdentifierMatchField::Catalog);
            }
            fields
        }
    }
}

fn push_identifier_match(fields: &mut Vec<IdentifierMatchField>, field: IdentifierMatchField) {
    if !fields.contains(&field) {
        fields.push(field);
    }
}

fn subject_name_matches_filter(service: &TrustService, filter: &str) -> bool {
    service.digital_identities.iter().any(|id| {
        matches!(id, DigitalIdentity::SubjectName(name) if matches_folded(&fold(name), filter))
    }) || service.history.iter().any(|history| {
        history.digital_identities.iter().any(|id| {
            matches!(id, DigitalIdentity::SubjectName(name) if matches_folded(&fold(name), filter))
        })
    })
}

fn service_text_matches_identifier(service: &TrustService, filter: &str) -> bool {
    let current = fold(&format!(
        "{} {} {}",
        service.name.as_str(),
        localized_text_values(&service.names),
        service.service_type.as_str()
    ));
    if matches_folded(&current, filter) {
        return true;
    }
    service.history.iter().any(|history| {
        matches_folded(
            &fold(&format!(
                "{} {} {}",
                history.name.as_str(),
                localized_text_values(&history.names),
                history.service_type.as_str()
            )),
            filter,
        )
    })
}

fn supply_point_text_matches_identifier(service: &TrustService, filter: &str) -> bool {
    let current = fold(&service.service_supply_points.join(" "));
    if matches_folded(&current, filter) {
        return true;
    }
    service
        .history
        .iter()
        .any(|history| matches_folded(&fold(&history.service_supply_points.join(" ")), filter))
}

fn status_matches_filter(status: &ServiceStatus, filter: &str) -> bool {
    let label = fold(&service_status_view(status).kind);
    let text = fold(&status_text(status));
    matches_folded(&label, filter)
        || matches_folded(&text, filter)
        || (filter == "revoked" && matches!(status, ServiceStatus::Revoked(_)))
}

fn history_matches_filter(service: &TrustService, filter: &str) -> bool {
    match filter {
        "any" | "true" | "yes" | "with" => !service.history.is_empty(),
        "none" | "false" | "no" | "without" => service.history.is_empty(),
        _ => service.history.iter().any(|history| {
            matches_folded(&fold(&history_search_text(history)), filter)
                || status_matches_filter(&history.status, filter)
        }),
    }
}

fn supply_point_matches_filter(service: &TrustService, filter: &str) -> bool {
    let current = !service.service_supply_points.is_empty();
    let historical = service
        .history
        .iter()
        .any(|history| !history.service_supply_points.is_empty());
    match filter {
        "any" | "true" | "yes" | "with" => current || historical,
        "none" | "false" | "no" | "without" => !current && !historical,
        _ => {
            let history_supply_points = service
                .history
                .iter()
                .flat_map(|history| history.service_supply_points.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ");
            let text = fold(&format!(
                "{} {}",
                service.service_supply_points.join(" "),
                history_supply_points
            ));
            matches_folded(&text, filter)
        }
    }
}

fn is_tsa_service(service: &TrustService) -> bool {
    let text = fold(&format!(
        "{} {} {}",
        service.service_type,
        service.name,
        service.additional_service_info.join(" ")
    ));
    text.contains("/tsa") || text.contains("timestamp")
}

fn is_qualified_timestamp_service(service: &TrustService) -> bool {
    fold(&service.service_type).contains("/tsa/qtst")
}

fn qualifies_for_esignature(service: &TrustService, now: OffsetDateTime) -> bool {
    service.is_ca_qc()
        && service.is_granted()
        && service.is_effective_at(now)
        && service.qualifies_for_esig()
}

fn provider_analysis(
    provider: &TrustServiceProvider,
    now: OffsetDateTime,
    signature_valid: bool,
) -> TslProviderAnalysisView {
    let services = provider.services.len();
    let granted_services = provider.services.iter().filter(|s| s.is_granted()).count();
    let withdrawn_services = provider
        .services
        .iter()
        .filter(|s| s.status == ServiceStatus::Withdrawn)
        .count();
    let other_status_services = services - granted_services - withdrawn_services;
    let services_with_history = provider
        .services
        .iter()
        .filter(|s| !s.history.is_empty())
        .count();
    let services_with_supply_points = provider
        .services
        .iter()
        .filter(|s| !s.service_supply_points.is_empty())
        .count();
    let ca_qc_services = provider.services.iter().filter(|s| s.is_ca_qc()).count();
    let qualified_esignature_services = provider
        .services
        .iter()
        .filter(|s| qualifies_for_esignature(s, now))
        .count();
    TslProviderAnalysisView {
        services,
        granted_services,
        withdrawn_services,
        other_status_services,
        services_with_history,
        services_with_supply_points,
        ca_qc_services,
        qualified_esignature_services,
        trusted_esignature_services: if signature_valid {
            qualified_esignature_services
        } else {
            0
        },
        duplicate_service_names: duplicate_service_names(provider),
    }
}

fn duplicate_service_names(provider: &TrustServiceProvider) -> Vec<String> {
    let mut seen: Vec<(String, String, usize)> = Vec::new();
    for service in &provider.services {
        for name in &service.names {
            let display = name.value.trim();
            if display.is_empty() {
                continue;
            }
            let folded = fold(display);
            match seen.iter_mut().find(|(key, _, _)| key == &folded) {
                Some((_, _, count)) => *count += 1,
                None => seen.push((folded, display.to_owned(), 1)),
            }
        }
    }
    seen.into_iter()
        .filter_map(|(_, display, count)| (count > 1).then_some(display))
        .collect()
}

fn tsa_policy_analysis(
    records: &[TsaRecordView],
    timestamp: Option<&TsaTimestampMetadataView>,
    signature_valid: bool,
) -> TsaPolicyAnalysisView {
    let qualified_timestamp_records = records
        .iter()
        .filter(|record| record.qualified_timestamp_service)
        .count();
    let trusted_qualified_timestamp_records = records
        .iter()
        .filter(|record| record.qualified_timestamp_service && record.trusted)
        .count();
    TsaPolicyAnalysisView {
        accepted_policy: "Any".to_owned(),
        fixture_policy: timestamp.map(|ts| ts.policy.clone()),
        fixture_policy_accepted: timestamp.is_some(),
        qualified_timestamp_records,
        trusted_qualified_timestamp_records,
        advisory: !signature_valid || trusted_qualified_timestamp_records == 0,
    }
}

fn tsa_record_analysis(
    service: &TrustService,
    signature_valid: bool,
    granted: bool,
    effective: bool,
) -> TsaRecordAnalysisView {
    let qualified_timestamp_service = is_qualified_timestamp_service(service);
    let mut blocking_reasons = Vec::new();
    if !qualified_timestamp_service {
        blocking_reasons.push("service type is not TSA/QTST".to_owned());
    }
    if !granted {
        blocking_reasons.push("service status is not granted".to_owned());
    }
    if !effective {
        blocking_reasons.push("service status starting time is in the future".to_owned());
    }
    if !signature_valid {
        blocking_reasons.push("TSL signature is not valid; record is advisory".to_owned());
    }
    TsaRecordAnalysisView {
        classification: if qualified_timestamp_service {
            "QualifiedTimestampService".to_owned()
        } else {
            "TimestampService".to_owned()
        },
        trust_basis: if signature_valid {
            "ValidTslSignature".to_owned()
        } else {
            "AdvisoryOnlyInvalidTslSignature".to_owned()
        },
        blocking_reasons,
    }
}

fn identity_summary(service: &TrustService) -> TslIdentitySummaryView {
    identity_summary_for(&service.digital_identities)
}

fn history_identity_summary(history: &ServiceHistoryEntry) -> TslIdentitySummaryView {
    identity_summary_for(&history.digital_identities)
}

fn identity_summary_for(identities: &[DigitalIdentity]) -> TslIdentitySummaryView {
    let mut certificates = 0usize;
    let mut subject_names = Vec::new();
    let mut subject_key_ids = Vec::new();
    for id in identities {
        match id {
            DigitalIdentity::Certificate(_) => certificates += 1,
            DigitalIdentity::SubjectName(name) => subject_names.push(name.clone()),
            DigitalIdentity::SubjectKeyId(ski) => subject_key_ids.push(hex_bytes(ski)),
            _ => {}
        }
    }
    TslIdentitySummaryView {
        certificates,
        subject_names,
        subject_key_ids,
    }
}

fn service_search_text(service: &TrustService) -> String {
    let mut parts = vec![
        service.name.clone(),
        localized_text_values(&service.names),
        service.service_type.clone(),
        status_text(&service.status),
        service.status_starting_time_raw.clone().unwrap_or_default(),
        service.additional_service_info.join(" "),
        service.service_supply_points.join(" "),
    ];
    parts.extend(identity_search_parts(&service.digital_identities));
    for history in &service.history {
        parts.push(history_search_text(history));
    }
    parts.join(" ")
}

fn history_search_text(history: &ServiceHistoryEntry) -> String {
    let mut parts = vec![
        history.name.clone(),
        localized_text_values(&history.names),
        history.service_type.clone(),
        status_text(&history.status),
        history.status_starting_time_raw.clone().unwrap_or_default(),
        history.additional_service_info.join(" "),
        history.service_supply_points.join(" "),
    ];
    parts.extend(identity_search_parts(&history.digital_identities));
    parts.join(" ")
}

fn identity_search_parts(identities: &[DigitalIdentity]) -> Vec<String> {
    identities
        .iter()
        .map(|id| match id {
            DigitalIdentity::Certificate(der) => cert_fingerprint(der),
            DigitalIdentity::SubjectName(name) => name.clone(),
            DigitalIdentity::SubjectKeyId(ski) => hex_bytes(ski),
            _ => String::new(),
        })
        .collect()
}

fn localized_text_values(values: &[LocalizedText]) -> String {
    values
        .iter()
        .map(|value| value.value.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

fn digital_identity_views(service: &TrustService) -> Vec<TslDigitalIdentityView> {
    service
        .digital_identities
        .iter()
        .map(|id| match id {
            DigitalIdentity::Certificate(der) => TslDigitalIdentityView {
                kind: "Certificate".to_owned(),
                value: cert_fingerprint(der),
                sha256: Some(cert_fingerprint(der)),
                byte_length: Some(der.len()),
            },
            DigitalIdentity::SubjectName(name) => TslDigitalIdentityView {
                kind: "SubjectName".to_owned(),
                value: name.clone(),
                sha256: None,
                byte_length: None,
            },
            DigitalIdentity::SubjectKeyId(ski) => TslDigitalIdentityView {
                kind: "SubjectKeyId".to_owned(),
                value: hex_bytes(ski),
                sha256: None,
                byte_length: Some(ski.len()),
            },
            _ => TslDigitalIdentityView {
                kind: "Other".to_owned(),
                value: String::new(),
                sha256: None,
                byte_length: None,
            },
        })
        .collect()
}

fn service_history_views(service: &TrustService) -> Vec<TslServiceHistoryView> {
    service
        .history
        .iter()
        .map(|history| TslServiceHistoryView {
            name: history.name.clone(),
            service_type: history.service_type.clone(),
            status: service_status_view(&history.status),
            status_starting_time: format_optional_time(history.status_starting_time),
            status_starting_time_raw: history.status_starting_time_raw.clone(),
            additional_service_info: history.additional_service_info.clone(),
            service_supply_points: history.service_supply_points.clone(),
            identities: history_identity_summary(history),
        })
        .collect()
}

fn service_status_view(status: &ServiceStatus) -> TslServiceStatusView {
    match status {
        ServiceStatus::Granted => TslServiceStatusView {
            kind: "Granted".to_owned(),
            uri: None,
        },
        ServiceStatus::Withdrawn => TslServiceStatusView {
            kind: "Withdrawn".to_owned(),
            uri: None,
        },
        ServiceStatus::Revoked(uri) => TslServiceStatusView {
            // Keep the public enum stable for the web contract; the precise revoked URI is
            // retained in `uri` and search text.
            kind: "Other".to_owned(),
            uri: Some(uri.clone()),
        },
        ServiceStatus::Other(uri) => TslServiceStatusView {
            kind: "Other".to_owned(),
            uri: Some(uri.clone()),
        },
        _ => TslServiceStatusView {
            kind: "Other".to_owned(),
            uri: None,
        },
    }
}

fn status_text(status: &ServiceStatus) -> String {
    match status {
        ServiceStatus::Granted => "Granted".to_owned(),
        ServiceStatus::Withdrawn => "Withdrawn".to_owned(),
        ServiceStatus::Revoked(uri) => uri.clone(),
        ServiceStatus::Other(uri) => uri.clone(),
        _ => "Other".to_owned(),
    }
}

fn provider_id_at(provider_index: usize, provider: &TrustServiceProvider) -> String {
    let mut h = Sha256::new();
    h.update(provider_index.to_be_bytes());
    h.update([0]);
    h.update(provider.name.as_bytes());
    h.update([0]);
    for name in &provider.trade_names {
        h.update(name.as_bytes());
        h.update([0]);
    }
    for uri in &provider.information_uris {
        h.update(uri.as_bytes());
        h.update([0]);
    }
    format!("tsp-{}", short_hash(h))
}

fn service_id(provider_id: &str, service_index: usize, service: &TrustService) -> String {
    let mut h = Sha256::new();
    h.update(provider_id.as_bytes());
    h.update([0]);
    h.update(service_index.to_be_bytes());
    h.update([0]);
    h.update(service.name.as_bytes());
    h.update([0]);
    h.update(service.service_type.as_bytes());
    h.update([0]);
    h.update(status_text(&service.status).as_bytes());
    h.update([0]);
    if let Some(start) = service.status_starting_time {
        h.update(format_time(start).as_bytes());
    }
    h.update([0]);
    if let Some(raw) = &service.status_starting_time_raw {
        h.update(raw.as_bytes());
    }
    h.update([0]);
    for id in &service.digital_identities {
        match id {
            DigitalIdentity::Certificate(der) => h.update(der),
            DigitalIdentity::SubjectName(name) => h.update(name.as_bytes()),
            DigitalIdentity::SubjectKeyId(ski) => h.update(ski),
            _ => h.update(b"unknown-digital-identity"),
        }
        h.update([0]);
    }
    format!("svc-{}", short_hash(h))
}

fn short_hash(hasher: Sha256) -> String {
    let digest: [u8; 32] = hasher.finalize().into();
    hex::hex(&digest)[..20].to_owned()
}

fn cert_fingerprint(der: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(der).into();
    hex::hex(&digest)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("high nibble < 16"));
        s.push(char::from_digit((b & 0x0f) as u32, 16).expect("low nibble < 16"));
    }
    s
}

fn folded_query(value: &Option<String>) -> Option<String> {
    let trimmed = value.as_deref()?.trim();
    (!trimmed.is_empty()).then(|| fold(trimmed))
}

fn identifier_filter(value: Option<&str>) -> Option<IdentifierFilter> {
    let trimmed = value?.trim();
    if trimmed.is_empty() {
        return None;
    }
    match compact_fingerprint_hex(trimmed) {
        HexLikeInput::Hex(compact_hex) => {
            return Some(match compact_hex.len() {
                64 => IdentifierFilter {
                    kind: IdentifierFilterKind::CertificateSha256,
                    value: compact_hex,
                },
                40 => IdentifierFilter {
                    kind: IdentifierFilterKind::SubjectKeyId,
                    value: compact_hex,
                },
                _ => IdentifierFilter {
                    kind: IdentifierFilterKind::Unknown,
                    value: compact_hex,
                },
            });
        }
        HexLikeInput::Malformed => {
            return Some(IdentifierFilter {
                kind: IdentifierFilterKind::Unknown,
                value: String::new(),
            });
        }
        HexLikeInput::Text => {}
    }

    let text = fold(trimmed);
    Some(
        if text.chars().filter(|c| c.is_alphanumeric()).count() >= 3 {
            IdentifierFilter {
                kind: IdentifierFilterKind::Text,
                value: text,
            }
        } else {
            IdentifierFilter {
                kind: IdentifierFilterKind::Unknown,
                value: text,
            }
        },
    )
}

fn compact_fingerprint_hex(input: &str) -> HexLikeInput {
    let mut out = String::new();
    let mut saw_separator = false;
    for c in input.chars() {
        if c.is_ascii_hexdigit() {
            out.push(c.to_ascii_lowercase());
        } else if c == ':' || c == '-' || c.is_ascii_whitespace() {
            saw_separator = true;
            continue;
        } else {
            return if saw_separator {
                HexLikeInput::Malformed
            } else {
                HexLikeInput::Text
            };
        }
    }
    if out.is_empty() {
        HexLikeInput::Text
    } else {
        HexLikeInput::Hex(out)
    }
}

fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().flat_map(|c| c.to_lowercase()) {
        match c {
            '\u{00e0}' | '\u{00e1}' | '\u{00e2}' | '\u{00e3}' | '\u{00e4}' | '\u{00e5}' => {
                out.push('a')
            }
            '\u{00e7}' => out.push('c'),
            '\u{00e8}' | '\u{00e9}' | '\u{00ea}' | '\u{00eb}' => out.push('e'),
            '\u{00ec}' | '\u{00ed}' | '\u{00ee}' | '\u{00ef}' => out.push('i'),
            '\u{00f1}' => out.push('n'),
            '\u{00f2}' | '\u{00f3}' | '\u{00f4}' | '\u{00f5}' | '\u{00f6}' => out.push('o'),
            '\u{00f9}' | '\u{00fa}' | '\u{00fb}' | '\u{00fc}' => out.push('u'),
            '\u{00fd}' | '\u{00ff}' => out.push('y'),
            '\u{00e6}' => out.push_str("ae"),
            '\u{0153}' => out.push_str("oe"),
            '\u{00df}' => out.push_str("ss"),
            other => out.push(other),
        }
    }
    out
}

fn matches_folded(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
        || needle
            .split_whitespace()
            .filter(|term| !term.is_empty())
            .all(|term| haystack.contains(term))
}

fn format_optional_time(t: Option<OffsetDateTime>) -> Option<String> {
    t.map(format_time)
}

fn format_time(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

#[cfg(test)]
fn public_configured_url(configured: Option<String>) -> Option<String> {
    let trimmed = configured?.trim().to_owned();
    if trimmed.is_empty() {
        return None;
    }
    Some(strip_url_secrets(&trimmed))
}

fn public_runtime_tsa_url(provider: &RuntimeTsaProvider) -> Option<String> {
    provider.location.url().map(strip_url_secrets)
}

fn tsa_runtime_error(selection: &RuntimeTsaSelection) -> Option<String> {
    if let Some(error) = &selection.selection_error {
        return Some(format!("TSA provider selection error: {error}"));
    }
    let provider = selection.selected.as_ref()?;
    if provider.location.url().is_none() {
        return Some(format!(
            "TSA provider '{}' is path-backed; live RFC 3161 timestamping requires an HTTP URL. Local TSA replay/signing is not implemented in this slice.",
            provider.id
        ));
    }
    if provider.digest.trim() != "sha256" {
        return Some(format!(
            "TSA provider '{}' requests digest {:?}; live timestamping currently supports sha256 only.",
            provider.id, provider.digest
        ));
    }
    None
}

fn strip_url_secrets(url: &str) -> String {
    let cutoff = [url.find('?'), url.find('#')]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(url.len());
    let base = &url[..cutoff];
    let Some((scheme, rest)) = base.split_once("://") else {
        return base.to_owned();
    };
    let slash = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..slash];
    let path = &rest[slash..];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    format!("{scheme}://{host}{path}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{SigningSettings, TsaProviderSettings, TslSourceSettings};
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-07-06 12:00:00 UTC);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "chancela-trust-test-{}-{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos()
            ));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> LoadedTsl {
        let xml = BUNDLED_PT_TSL.to_vec();
        LoadedTsl {
            list: parse_tsl(&xml).expect("fixture parses"),
            xml,
            source: TslSourceView {
                kind: TslSourceKind::Fixture,
                path: None,
                note: "fixture".to_owned(),
            },
            last_refresh: None,
        }
    }

    fn tsa_selection_for_url(url: &str) -> RuntimeTsaSelection {
        let mut signing = SigningSettings::default();
        signing.tsa_providers[0].url = Some(url.to_owned());
        signing.runtime_tsa_selection()
    }

    fn unconfigured_tsa_selection() -> RuntimeTsaSelection {
        let mut signing = SigningSettings::default();
        signing.tsa_providers.clear();
        signing.tsa_url = None;
        signing.runtime_tsa_selection()
    }

    #[test]
    fn outbound_url_policy_rejects_reserved_ipv4_zero_eight() {
        for url in ["http://0.1.2.3/tsl.xml", "http://0.255.255.255/tsa"] {
            let runtime = validate_outbound_http_url(url)
                .expect_err("runtime URL validation rejects 0.0.0.0/8");
            assert!(runtime.contains("unsafe outbound URL"), "{runtime}");
            assert!(runtime.contains("disallowed address"), "{runtime}");

            let metadata = validate_outbound_http_url_metadata(url)
                .expect_err("settings URL validation rejects 0.0.0.0/8");
            assert!(metadata.contains("unsafe outbound URL"), "{metadata}");
            assert!(metadata.contains("disallowed address"), "{metadata}");
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn local_trust_url_test_allowance_is_scoped_to_registered_origin() {
        let registered = "http://127.0.0.1:31000/tsa";
        validate_outbound_http_url(registered)
            .expect_err("loopback is rejected before the test origin is registered");

        let allowance =
            allow_local_trust_url_for_tests(registered).expect("register exact mock origin");
        validate_outbound_http_url("http://127.0.0.1:31000/other")
            .expect("same registered origin is allowed");

        let other_port = validate_outbound_http_url("http://127.0.0.1:31001/tsa")
            .expect_err("different loopback authority remains rejected");
        assert!(other_port.contains("disallowed address"), "{other_port}");

        let localhost_alias = validate_outbound_http_url("http://localhost:31000/tsa")
            .expect_err("localhost alias is not covered by the registered IP origin");
        assert!(localhost_alias.contains("local-only"), "{localhost_alias}");

        let reserved = validate_outbound_http_url("http://0.1.2.3/tsa")
            .expect_err("registered loopback origin does not allow reserved ranges");
        assert!(reserved.contains("disallowed address"), "{reserved}");

        drop(allowance);
        validate_outbound_http_url(registered)
            .expect_err("loopback is rejected after the scoped allowance is dropped");
    }

    #[test]
    fn summary_reports_fixture_validation_without_trusting_it() {
        let loaded = fixture();
        let summary = summary_view(&loaded, NOW, None);
        assert_eq!(summary.scheme_territory, "PT");
        assert!(summary.last_refresh.is_none());
        assert_eq!(summary.providers, 4);
        assert_eq!(summary.qualified_esignature_services, 1);
        assert_eq!(summary.trusted_esignature_services, 0);
        assert_eq!(summary.validation.signature, TslSignatureStatus::Invalid);
        assert!(summary.validation.error.is_some());
    }

    #[test]
    fn import_from_file_with_invalid_signature_persists_failure_without_replacing_cache() {
        let tmp = TempDir::new();
        let source = tmp.0.join("source-tsl.xml");
        std::fs::write(&source, BUNDLED_PT_TSL).expect("fixture source");
        let cache = tmp.0.join(TRUST_CACHE_FILE);
        std::fs::write(&cache, b"previous-cache").expect("existing cache");

        let status = import_tsl_to_cache(
            tmp.0.clone(),
            SigningSettings::default().runtime_tsl_selection(),
            TslRefreshRequest {
                url: None,
                path: Some(source.display().to_string()),
            },
            NOW,
        )
        .expect("import status");

        assert_eq!(status.outcome, TslRefreshOutcome::Failed);
        assert_eq!(status.source_kind, TslRefreshSourceKind::File);
        assert_eq!(status.source_url, None);
        assert_eq!(status.providers, Some(4));
        assert_eq!(status.services, Some(5));
        assert_eq!(status.validation.signature, TslSignatureStatus::Invalid);
        assert!(
            status
                .error
                .as_deref()
                .is_some_and(|e| e.contains("signature/trust-anchor")),
            "{status:?}"
        );
        assert_eq!(
            std::fs::read(&cache).expect("cache still readable"),
            b"previous-cache"
        );

        let persisted = load_refresh_status(Some(tmp.0.clone())).expect("persisted status");
        assert_eq!(persisted.outcome, TslRefreshOutcome::Failed);
        assert_eq!(
            std::fs::read(&cache).expect("cache still readable after status write"),
            b"previous-cache"
        );
    }

    #[test]
    fn failed_import_persists_error_without_replacing_cache() {
        let tmp = TempDir::new();
        let source = tmp.0.join("bad-tsl.xml");
        std::fs::write(&source, b"<not-tsl>").expect("bad source");

        let status = import_tsl_to_cache(
            tmp.0.clone(),
            SigningSettings::default().runtime_tsl_selection(),
            TslRefreshRequest {
                url: None,
                path: Some(source.display().to_string()),
            },
            NOW,
        )
        .expect("failed attempt still persists status");

        assert_eq!(status.outcome, TslRefreshOutcome::Failed);
        assert!(status.error.as_deref().is_some_and(|e| e.contains("parse")));
        assert!(!tmp.0.join(TRUST_CACHE_FILE).exists());
        let persisted = load_refresh_status(Some(tmp.0.clone())).expect("persisted failure");
        assert_eq!(persisted.outcome, TslRefreshOutcome::Failed);
        assert_eq!(persisted.providers, None);
    }

    #[test]
    fn import_from_unsafe_url_persists_failure_without_fetching_or_cache() {
        let tmp = TempDir::new();
        let status = import_tsl_to_cache(
            tmp.0.clone(),
            SigningSettings::default().runtime_tsl_selection(),
            TslRefreshRequest {
                url: Some("http://127.0.0.1:9/tsl.xml".to_owned()),
                path: None,
            },
            NOW,
        )
        .expect("unsafe URL attempt still records status");

        assert_eq!(status.outcome, TslRefreshOutcome::Failed);
        assert_eq!(status.source_kind, TslRefreshSourceKind::Url);
        assert!(
            status
                .error
                .as_deref()
                .is_some_and(|e| e.contains("unsafe outbound URL"))
        );
        assert!(!tmp.0.join(TRUST_CACHE_FILE).exists());
        let persisted = load_refresh_status(Some(tmp.0.clone())).expect("persisted failure");
        assert_eq!(persisted.outcome, TslRefreshOutcome::Failed);
        assert!(
            persisted
                .error
                .as_deref()
                .is_some_and(|e| e.contains("unsafe outbound URL"))
        );
    }

    #[test]
    fn search_returns_provider_qualified_service_rows() {
        let loaded = fixture();
        let hits = search_services(&loaded.list, "multicert", 10, NOW, false);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].provider_name.contains("MULTICERT"));
        assert!(hits[0].qualified_for_esignatures);
        assert!(!hits[0].trusted_for_esignatures);
        assert!(hits[0].identifier_match.is_none());
        let serialized_hit = serde_json::to_value(&hits[0]).expect("summary serializes");
        assert!(serialized_hit.get("identifier_match").is_none());

        let history_hits = search_services(&loaded.list, "legacy", 10, NOW, false);
        assert_eq!(history_hits.len(), 1);
        assert_eq!(
            history_hits[0].name,
            "MULTICERT CA para Assinatura Qualificada"
        );

        let accent_hits = search_services(&loaded.list, "seguranca", 10, NOW, false);
        assert!(
            accent_hits.len() >= loaded.list.services().count(),
            "scheme-operator search should fold Portuguese accents"
        );
    }

    #[test]
    fn tsl_refresh_uses_first_enabled_configured_source_and_ignores_disabled_sources() {
        let tmp = TempDir::new();
        let disabled_source = tmp.0.join("disabled-tsl.xml");
        let enabled_source = tmp.0.join("enabled-tsl.xml");
        std::fs::write(&disabled_source, b"<not-tsl>").expect("disabled source");
        std::fs::write(&enabled_source, BUNDLED_PT_TSL).expect("enabled source");

        let signing = SigningSettings {
            tsl_url: Some("http://legacy.example.test/tsl.xml".to_owned()),
            tsl_sources: vec![
                TslSourceSettings {
                    id: "disabled-local".to_owned(),
                    name: "Disabled local TSL".to_owned(),
                    enabled: false,
                    path: Some(disabled_source.display().to_string()),
                    ..TslSourceSettings::default()
                },
                TslSourceSettings {
                    id: "enabled-local".to_owned(),
                    name: "Enabled local TSL".to_owned(),
                    enabled: true,
                    path: Some(enabled_source.display().to_string()),
                    ..TslSourceSettings::default()
                },
            ],
            ..SigningSettings::default()
        };

        let status = import_tsl_to_cache(
            tmp.0.clone(),
            signing.runtime_tsl_selection(),
            TslRefreshRequest {
                url: None,
                path: None,
            },
            NOW,
        )
        .expect("configured source import");

        assert_eq!(status.outcome, TslRefreshOutcome::Failed);
        assert_eq!(status.source_kind, TslRefreshSourceKind::File);
        let enabled_source_display = enabled_source.display().to_string();
        assert_eq!(
            status.source_path.as_deref(),
            Some(enabled_source_display.as_str())
        );
        assert_eq!(status.providers, Some(4));
        assert!(
            status
                .error
                .as_deref()
                .is_some_and(|e| e.contains("signature/trust-anchor"))
        );
    }

    #[test]
    fn structured_service_filters_cover_status_history_supply_and_empty_results() {
        let loaded = fixture();
        let granted_ca_qc = filter_services(
            &loaded.list,
            &ServiceFilters {
                service_type: Some(fold("CA/QC")),
                status: Some(fold("GRANTED")),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert_eq!(granted_ca_qc.len(), 2);
        assert!(
            granted_ca_qc
                .iter()
                .any(|service| service.name.contains("MULTICERT"))
        );
        assert!(
            granted_ca_qc
                .iter()
                .any(|service| service.name.contains("Selo Qualificado"))
        );

        let history_hits = filter_services(
            &loaded.list,
            &ServiceFilters {
                history: Some(fold("WITHDRAWN")),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert_eq!(history_hits.len(), 1);
        assert!(history_hits[0].history_count > 0);

        let supply_point_hits = filter_services(
            &loaded.list,
            &ServiceFilters {
                supply_point: Some(fold("TSA.CARTORIO.EXAMPLE.TEST")),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert_eq!(supply_point_hits.len(), 2);
        assert!(
            supply_point_hits
                .iter()
                .all(|service| !service.service_supply_points.is_empty())
        );

        let no_match = filter_services(
            &loaded.list,
            &ServiceFilters {
                search: Some(fold("sem resultado deterministico")),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert!(no_match.is_empty());
    }

    #[test]
    fn structured_identifier_filters_match_complete_material_only() {
        let loaded = fixture();
        let multicert = loaded
            .list
            .providers
            .iter()
            .find(|provider| provider.name.contains("MULTICERT"))
            .expect("provider");
        let service = &multicert.services[0];
        let fingerprint = service
            .digital_identities
            .iter()
            .find_map(|id| match id {
                DigitalIdentity::Certificate(der) => Some(cert_fingerprint(der)),
                _ => None,
            })
            .expect("certificate identity");
        let ski = service
            .digital_identities
            .iter()
            .find_map(|id| match id {
                DigitalIdentity::SubjectKeyId(ski) => Some(hex_bytes(ski)),
                _ => None,
            })
            .expect("ski identity");

        let fingerprint_hits = filter_services(
            &loaded.list,
            &ServiceFilters {
                identifier: identifier_filter(Some(&fingerprint.to_uppercase())),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert_eq!(fingerprint_hits.len(), 1);
        assert_eq!(
            fingerprint_hits[0].name,
            "MULTICERT CA para Assinatura Qualificada"
        );
        assert_eq!(
            fingerprint_hits[0].identifier_match,
            Some(vec![IdentifierMatchField::CertificateSha256])
        );
        let fingerprint_json =
            serde_json::to_value(&fingerprint_hits[0]).expect("fingerprint hit serializes");
        assert_eq!(
            fingerprint_json
                .get("identifier_match")
                .and_then(|value| value.as_array())
                .and_then(|fields| fields.first())
                .and_then(|field| field.as_str()),
            Some("certificate_sha256")
        );

        let ski_hits = filter_services(
            &loaded.list,
            &ServiceFilters {
                identifier: identifier_filter(Some(&ski)),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert_eq!(ski_hits.len(), 1);
        assert_eq!(
            ski_hits[0].identifier_match,
            Some(vec![IdentifierMatchField::SubjectKeyId])
        );

        let subject_hits = filter_services(
            &loaded.list,
            &ServiceFilters {
                identifier: identifier_filter(Some("CN=MULTICERT CA para Assinatura Qualificada")),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert_eq!(subject_hits.len(), 1);
        assert!(
            subject_hits[0]
                .identifier_match
                .as_ref()
                .is_some_and(|fields| fields.contains(&IdentifierMatchField::SubjectName))
        );

        let provider_hint_hits = filter_services(
            &loaded.list,
            &ServiceFilters {
                identifier: identifier_filter(Some("MULTICERT")),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert!(!provider_hint_hits.is_empty());
        assert!(provider_hint_hits.iter().any(|hit| {
            hit.identifier_match
                .as_ref()
                .is_some_and(|fields| fields.contains(&IdentifierMatchField::Provider))
        }));

        let partial = filter_services(
            &loaded.list,
            &ServiceFilters {
                identifier: identifier_filter(Some("84:b7:8a:44")),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert!(partial.is_empty());

        let malformed = filter_services(
            &loaded.list,
            &ServiceFilters {
                identifier: identifier_filter(Some("ab:cd:not-hex")),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert!(malformed.is_empty());
    }

    #[test]
    fn provider_analysis_and_detail_views_expose_duplicate_names_and_raw_dates() {
        let loaded = fixture();
        let catalog = catalog_view(&loaded, NOW, None);
        let multicert = catalog
            .providers
            .iter()
            .find(|provider| provider.name.contains("MULTICERT"))
            .expect("MULTICERT provider");
        assert_eq!(multicert.analysis.services, 1);
        assert_eq!(multicert.analysis.services_with_history, 1);
        assert_eq!(multicert.analysis.qualified_esignature_services, 1);
        assert_eq!(multicert.analysis.trusted_esignature_services, 0);
        assert_eq!(
            multicert.analysis.duplicate_service_names,
            vec!["MULTICERT CA para Assinatura Qualificada".to_owned()]
        );

        let digitalsign = catalog
            .providers
            .iter()
            .flat_map(|provider| provider.services.iter())
            .find(|service| service.provider_name.contains("DigitalSign"))
            .expect("DigitalSign service");
        assert_eq!(digitalsign.status_starting_time, None);
        assert_eq!(
            digitalsign.status_starting_time_raw.as_deref(),
            Some("not-a-date")
        );

        let multicert_service = &loaded
            .list
            .providers
            .iter()
            .find(|provider| provider.name.contains("MULTICERT"))
            .expect("provider")
            .services[0];
        let history = service_history_views(multicert_service);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status.kind, "Withdrawn");
        assert_eq!(
            history[0].status_starting_time.as_deref(),
            Some("2016-07-01T00:00:00Z")
        );
        assert_eq!(history[0].identities.subject_key_ids.len(), 1);
    }

    #[test]
    fn stable_service_ids_resolve_to_detail_material() {
        let loaded = fixture();
        let signature_valid = false;
        let (provider_index, provider) = loaded
            .list
            .providers
            .iter()
            .enumerate()
            .find(|(_, p)| p.name.contains("MULTICERT"))
            .expect("provider");
        let pid = provider_id_at(provider_index, provider);
        let summary = service_summary(
            &pid,
            &provider.name,
            0,
            &provider.services[0],
            NOW,
            signature_valid,
        );
        assert!(summary.id.starts_with("svc-"));
        let identities = digital_identity_views(&provider.services[0]);
        assert!(identities.iter().any(|id| id.kind == "Certificate"));
        assert!(identities.iter().any(|id| id.kind == "SubjectKeyId"));
    }

    #[test]
    fn tsa_catalog_reports_configured_url_and_fixture_timestamp_metadata() {
        let loaded = fixture();
        let selection = tsa_selection_for_url("http://ts.cartaodecidadao.pt/tsa/server");
        let catalog = tsa_catalog_view(&loaded, NOW, &selection);
        assert_eq!(catalog.summary.status, TsaStatusKind::Ready);
        assert_eq!(
            catalog.summary.accepted_hash.digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(catalog.summary.last_probe.status, TsaProbeStatus::Passed);
        assert!(catalog.summary.last_probe.request_matches_fixture);
        let ts = catalog.summary.timestamp.expect("fixture timestamp");
        assert_eq!(ts.policy, "1.2.3.4.1");
        assert_eq!(ts.serial_number, "04");
        assert_eq!(ts.gen_time, "2023-06-07T11:26:26Z");
        assert!(!ts.tsa_certificate_embedded);
    }

    #[test]
    fn tsa_catalog_filters_tsl_timestamp_authority_records() {
        let loaded = fixture();
        let selection = tsa_selection_for_url("http://tsa.example.test");
        let catalog = tsa_catalog_view(&loaded, NOW, &selection);
        assert_eq!(catalog.records.len(), 2);
        assert_eq!(catalog.summary.records, 2);
        assert_eq!(catalog.summary.granted_records, 1);
        assert_eq!(
            catalog.summary.policy_analysis.fixture_policy.as_deref(),
            Some("1.2.3.4.1")
        );
        assert!(catalog.summary.policy_analysis.fixture_policy_accepted);
        assert_eq!(
            catalog.summary.policy_analysis.qualified_timestamp_records,
            1
        );
        assert!(catalog.summary.policy_analysis.advisory);
        let record = catalog
            .records
            .iter()
            .find(|record| record.qualified_timestamp_service)
            .expect("QTST record");
        assert_eq!(record.provider_name, "Cartorio Notarial Timestamping");
        assert_eq!(
            record.service_type,
            "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
        );
        assert_eq!(
            record.service_supply_points,
            vec!["http://tsa.cartorio.example.test/tsa/server".to_owned()]
        );
        assert_eq!(record.analysis.classification, "QualifiedTimestampService");
        assert!(
            record
                .analysis
                .blocking_reasons
                .iter()
                .any(|reason| reason.contains("TSL signature"))
        );
        assert!(record.qualified_timestamp_service);
        assert!(record.granted);
        assert!(!record.trusted, "fixture TSL signature is invalid");
        let hits = search_tsa_records(&loaded.list, "qtst", 10, NOW, false);
        assert_eq!(hits.len(), 1);
        let structured_hits = filter_tsa_records(
            &loaded.list,
            &ServiceFilters {
                service_type: Some(fold("/TSA/QTST")),
                status: Some(fold("granted")),
                supply_point: Some(fold("tsa.cartorio.example.test")),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert_eq!(structured_hits.len(), 1);
        let supply_point_hits =
            search_tsa_records(&loaded.list, "tsa.cartorio.example.test", 10, NOW, false);
        assert_eq!(supply_point_hits.len(), 2);
        let tsa_ski = loaded
            .list
            .providers
            .iter()
            .find(|provider| provider.name == "Cartorio Notarial Timestamping")
            .expect("TSA provider")
            .services[0]
            .digital_identities
            .iter()
            .find_map(|id| match id {
                DigitalIdentity::SubjectKeyId(ski) => Some(hex_bytes(ski)),
                _ => None,
            })
            .expect("TSA SKI");
        let identifier_hits = filter_tsa_records(
            &loaded.list,
            &ServiceFilters {
                identifier: identifier_filter(Some(&tsa_ski)),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert_eq!(identifier_hits.len(), 1);
        assert!(identifier_hits[0].qualified_timestamp_service);
        assert_eq!(
            identifier_hits[0].identifier_match,
            Some(vec![IdentifierMatchField::SubjectKeyId])
        );
        let supply_point_identifier_hits = filter_tsa_records(
            &loaded.list,
            &ServiceFilters {
                identifier: identifier_filter(Some("tsa.cartorio.example.test")),
                ..ServiceFilters::default()
            },
            10,
            NOW,
            false,
        );
        assert_eq!(supply_point_identifier_hits.len(), 2);
        assert!(supply_point_identifier_hits.iter().all(|record| {
            record
                .identifier_match
                .as_ref()
                .is_some_and(|fields| fields.contains(&IdentifierMatchField::SupplyPoint))
        }));
        let accent_hits = search_tsa_records(&loaded.list, "ancora sao tome", 10, NOW, false);
        assert_eq!(accent_hits.len(), 2);
        assert!(
            accent_hits
                .iter()
                .all(|record| record.identifier_match.is_none())
        );
        let revoked_hits = search_tsa_records(&loaded.list, "supervisionrevoked", 10, NOW, false);
        assert_eq!(revoked_hits.len(), 1);
        assert_eq!(revoked_hits[0].status.kind, "Other");
        assert!(
            revoked_hits[0]
                .status
                .uri
                .as_deref()
                .is_some_and(|uri| uri.ends_with("/supervisionRevoked"))
        );
    }

    #[test]
    fn tsa_catalog_reports_unconfigured_and_redacts_url_credentials() {
        let loaded = fixture();
        let selection = unconfigured_tsa_selection();
        let unconfigured = tsa_catalog_view(&loaded, NOW, &selection);
        assert_eq!(unconfigured.summary.status, TsaStatusKind::Unconfigured);
        assert_eq!(unconfigured.summary.configured_url, None);

        assert_eq!(
            public_configured_url(Some(
                " https://user:secret@tsa.example.pt/tsr?token=hidden#frag ".to_owned()
            ))
            .as_deref(),
            Some("https://tsa.example.pt/tsr")
        );
    }

    #[test]
    fn tsa_catalog_selects_enabled_default_provider_before_disabled_and_legacy_entries() {
        let loaded = fixture();
        let signing = SigningSettings {
            tsa_url: Some("http://legacy.example.test/tsa".to_owned()),
            tsa_providers: vec![
                TsaProviderSettings {
                    id: "disabled-default".to_owned(),
                    name: "Disabled default".to_owned(),
                    enabled: false,
                    r#default: true,
                    url: Some("http://disabled.example.test/tsa".to_owned()),
                    ..TsaProviderSettings::default()
                },
                TsaProviderSettings {
                    id: "selected-default".to_owned(),
                    name: "Selected default".to_owned(),
                    enabled: true,
                    r#default: true,
                    url: Some(
                        "https://user:secret@selected.example.test/tsa?token=hidden".to_owned(),
                    ),
                    ..TsaProviderSettings::default()
                },
            ],
            ..SigningSettings::default()
        };

        let selection = signing.runtime_tsa_selection();
        let catalog = tsa_catalog_view(&loaded, NOW, &selection);

        assert_eq!(catalog.summary.status, TsaStatusKind::Ready);
        assert_eq!(
            catalog.summary.configured_url.as_deref(),
            Some("https://selected.example.test/tsa")
        );
        assert!(catalog.summary.status_message.contains("selected-default"));
        assert!(catalog.summary.status_message.contains("2 configured"));
    }

    #[test]
    fn tsa_catalog_reports_path_backed_default_provider_as_local_replay_blocker() {
        let loaded = fixture();
        let signing = SigningSettings {
            tsa_url: Some("http://legacy.example.test/tsa".to_owned()),
            tsa_providers: vec![TsaProviderSettings {
                id: "offline-default".to_owned(),
                name: "Offline default".to_owned(),
                enabled: true,
                r#default: true,
                path: Some("fixtures/tsa-response.der".to_owned()),
                ..TsaProviderSettings::default()
            }],
            ..SigningSettings::default()
        };

        let selection = signing.runtime_tsa_selection();
        let catalog = tsa_catalog_view(&loaded, NOW, &selection);

        assert_eq!(catalog.summary.status, TsaStatusKind::Error);
        assert_eq!(catalog.summary.configured_url, None);
        assert!(catalog.summary.status_message.contains("path-backed"));
        assert!(catalog.summary.status_message.contains("Local TSA replay"));
    }

    #[test]
    fn tsa_catalog_reports_enabled_provider_without_default_as_selection_error() {
        let loaded = fixture();
        let signing = SigningSettings {
            tsa_url: Some("http://legacy.example.test/tsa".to_owned()),
            tsa_providers: vec![TsaProviderSettings {
                id: "enabled-not-default".to_owned(),
                name: "Enabled but not default".to_owned(),
                enabled: true,
                r#default: false,
                url: Some("http://enabled.example.test/tsa".to_owned()),
                ..TsaProviderSettings::default()
            }],
            ..SigningSettings::default()
        };

        let selection = signing.runtime_tsa_selection();
        let catalog = tsa_catalog_view(&loaded, NOW, &selection);

        assert_eq!(catalog.summary.status, TsaStatusKind::Error);
        assert!(
            catalog
                .summary
                .status_message
                .contains("exactly one default")
        );
    }
}
