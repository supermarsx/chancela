//! Application settings (contract §2.8): a typed, versioned configuration document plus its
//! `GET`/`PUT` endpoints and optional file persistence.
//!
//! The settings document is the single place where operator-facing configuration lives —
//! organization identity, document defaults, signing preferences, and appearance. It is
//! **whole-document** on the wire: `PUT` replaces the entire [`Settings`] (simpler than a
//! PATCH merge, and the Configurações UI always holds the full form). Every field carries a
//! serde default so a partial or empty stored document still deserializes cleanly, which is
//! what makes a hand-edited or older `settings.json` safe to load.
//!
//! ## Persistence
//!
//! When [`AppState`](crate::AppState) is built with a data directory (see
//! [`AppState::with_data_dir`](crate::AppState::with_data_dir) /
//! [`AppState::from_env`](crate::AppState::from_env)), `settings.json` in that directory is
//! read at startup and rewritten atomically (temp file + rename) on every successful `PUT`.
//! Without a data directory the settings live purely in memory and reset on restart, exactly
//! like the rest of the scaffold state.
//!
//! Each successful `PUT` also appends a `settings.updated` event to the audit ledger (DAT-10),
//! so a configuration change is as auditable as any domain mutation.

use std::path::{Path, PathBuf};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Query, State};
use chancela_cae::{CaeSourceFormat, PreferredOfficialSource};
use chancela_core::NumberingScheme;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use chancela_authz::{Permission, Scope};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::require_permission;
use crate::error::ApiError;

/// The current schema version of the settings document. Bumped only on a breaking shape
/// change; a stored document with an older/newer value still loads (unknown fields ignored,
/// missing fields defaulted) but this lets a future migration recognise what it is reading.
pub const SETTINGS_SCHEMA_VERSION: u32 = 1;

// --- The settings document ----------------------------------------------------------------

/// The full, versioned settings document (contract §2.8).
///
/// `#[serde(default)]` on the container means any missing section falls back to its default,
/// so both an empty `{}` and a partial document deserialize into a complete, valid value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Schema version discriminator (always [`SETTINGS_SCHEMA_VERSION`] when written here).
    pub schema_version: u32,
    /// Who the books belong to, and the default audit actor.
    pub organization: OrganizationSettings,
    /// Document-production defaults (locale, numbering).
    pub documents: DocumentSettings,
    /// Catalog-management sources (currently the CAE auto-update dataset URL).
    pub catalog: CatalogSettings,
    /// Signing preferences and trust-service endpoints.
    pub signing: SigningSettings,
    /// Purely cosmetic front-end preferences (theme, leather texture).
    pub appearance: AppearanceSettings,
    /// First-use onboarding state (plan t29 §4.1): the authoritative "is the app set up?" signal.
    pub onboarding: OnboardingSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            schema_version: SETTINGS_SCHEMA_VERSION,
            organization: OrganizationSettings::default(),
            documents: DocumentSettings::default(),
            catalog: CatalogSettings::default(),
            signing: SigningSettings::default(),
            appearance: AppearanceSettings::default(),
            onboarding: OnboardingSettings::default(),
        }
    }
}

/// First-use onboarding flag (plan t29 §4.1). Additive, serde-defaulted, no `schema_version`
/// bump. The web first-run guard treats `completed == false` **and** an empty `GET /v1/users` as
/// "fresh install"; the wizard sets `completed = true` (and stamps `completed_at`) on finish.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OnboardingSettings {
    /// Whether first-use onboarding has been completed.
    pub completed: bool,
    /// When onboarding was completed (RFC 3339), or `null`.
    pub completed_at: Option<String>,
}

/// Organization identity and the default actor recorded on ledger events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OrganizationSettings {
    /// Display name of the organization, or `null` if not set.
    pub name: Option<String>,
    /// Default actor attributed to audit events when a request does not name one.
    pub default_actor: String,
}

impl Default for OrganizationSettings {
    fn default() -> Self {
        OrganizationSettings {
            name: None,
            default_actor: "api".to_owned(),
        }
    }
}

/// Document-production defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DocumentSettings {
    /// UI / document locale.
    pub locale: Locale,
    /// Default numbering scheme proposed when opening a new book.
    pub numbering_scheme_default: NumberingScheme,
}

impl Default for DocumentSettings {
    fn default() -> Self {
        DocumentSettings {
            locale: Locale::default(),
            numbering_scheme_default: NumberingScheme::Sequential,
        }
    }
}

/// Catalog-management configuration (§catalog-v2).
///
/// `POST /v1/cae/refresh` builds an **ordered source chain** from these fields and tries each in
/// turn, the first that fetches, parses, and supersedes the active catalog winning (plan t23 §2.7):
///
/// 1. the built-in official Diário da República diploma pair, prepended when
///    [`cae_official_source`](Self::cae_official_source) is `true`;
/// 2. every entry in [`cae_sources`](Self::cae_sources), in order (each a URL + declared/auto
///    format + optional sha256 pin);
/// 3. the legacy single [`cae_update_url`](Self::cae_update_url) as a trailing `Auto` mirror entry;
/// 4. the `CHANCELA_CAE_URL` environment variable as a final trailing `Auto` mirror entry.
///
/// `cae_update_url` is kept for backward compatibility (t19-e1b): a config that only sets it keeps
/// working unchanged, as the last-but-one chain entry. When **nothing** is configured the refresh
/// runs the built-in official chain ([`chancela_cae::official_chain_for`], ordered by
/// [`preferred_official_source`](Self::preferred_official_source)) rather than erroring — so the
/// catalog is always obtainable from the official gov source (§catalog-v3).
///
/// **The built-in official source ordering (§catalog-v3, user directive t37: "default is ine").**
/// Wherever the built-in official source enters the chain — the [`cae_official_source`] prepend and the
/// no-config default — it is expanded per [`preferred_official_source`](Self::preferred_official_source):
/// INE first (the default) then the Diário da República pair, or the DR pair alone. INE publishes no
/// downloadable bulk CAE artifact (investigation t37), so the INE entry fails honestly and the DR pair
/// (always present) fulfils the refresh: the outcome `failures` show "INE indisponível → Diário da
/// República", never a silent substitution, and the reliable default never regresses.
///
/// **Defaults:** `cae_update_url: null`, `cae_sources: []`, `cae_official_source: false` (no official
/// machine-readable CAE *feed* exists and the DR obtain is heavy, so mirror/official opt-ins are
/// explicit); `preferred_official_source: Ine` (the user's stated default preference).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CatalogSettings {
    /// URL of the CAE dataset for `POST /v1/cae/refresh`; `null` (default) leaves it unset. Kept as
    /// the trailing fallback chain entry for backward compatibility.
    pub cae_update_url: Option<String>,
    /// Ordered fallback chain of CAE update sources, each auto-detected or format-pinned. Empty by
    /// default; tried in order after the optional official pair and before `cae_update_url`.
    pub cae_sources: Vec<CaeSourceEntry>,
    /// When `true`, prepend the built-in official source(s) to the chain — expanded per
    /// [`preferred_official_source`](Self::preferred_official_source) (a complete both-revision catalog
    /// obtained + parsed in-app). Default `false`.
    pub cae_official_source: bool,
    /// Which built-in official government source leads when the chain obtains from the official source
    /// (the `cae_official_source` prepend and the no-config default). `Ine` (default) → INE first then
    /// the Diário da República pair; `DiarioRepublica` → the DR pair directly. The DR pair is always
    /// present as the reliable fallback (§catalog-v3, user directive t37).
    pub preferred_official_source: PreferredOfficialSource,
}

/// One entry in the ordered CAE source chain ([`CatalogSettings::cae_sources`]).
///
/// A mirror URL plus its declared [`format`](Self::format) (`Auto` sniffs the bytes) and an optional
/// `digest` — a lowercase-hex sha256 pin of the fetched artifact, refused on mismatch. Maps to a
/// [`chancela_cae::MirrorArtifactSource`] at refresh time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaeSourceEntry {
    /// The mirror URL (validated http(s) on `PUT`).
    pub url: String,
    /// The declared artifact format; `Auto` (default) sniffs `%PDF` / `{` / `[`.
    #[serde(default)]
    pub format: CaeSourceFormat,
    /// Optional lowercase-hex sha256 pin of the fetched artifact (`null` = unpinned).
    #[serde(default)]
    pub digest: Option<String>,
}

/// Default RFC 3161 timestamping authority: AMA's Cartão de Cidadão qualified timestamp service
/// (Entidade de Validação Cronológica do CC), the Portuguese state's free public endpoint.
///
/// Sourced from the official autenticacao.gov / Cartão de Cidadão trust services — an
/// admin-configurable default, not a hard dependency. Notes:
/// - **Plain `http://` is correct here and MUST NOT be "upgraded" to https.** RFC 3161 tokens
///   are cryptographically signed, so integrity does not rely on TLS; there is no https listener
///   and switching the scheme would break it. [`is_http_url`] already accepts `http://`.
/// - **Rate-limited: ~20 requests / 20-minute window; exceeding it blocks the caller for 24h.**
///   This matters only for live use, which stays network-gated (the app never contacts the TSA
///   at rest — see [`SigningSettings`]). A test endpoint exists at
///   `http://ts.teste.cartaodecidadao.pt/`; we deliberately do not default to it.
pub const DEFAULT_PT_TSA_URL: &str = "http://ts.cartaodecidadao.pt/tsa/server";

/// Default Portuguese Trusted List (TSL) location, published by the Gabinete Nacional de
/// Segurança (GNS). Mirror of `chancela_tsl::DEFAULT_PT_TSL_URL` (kept in sync by hand rather
/// than depending on the whole TSL crate for one string). Verified live 2026-07-07; GNS renames
/// the published asset from time to time, so this is an admin-configurable default with the
/// `CHANCELA_TSL_URL` env override / the settings field as escape hatches.
pub const DEFAULT_PT_TSL_URL: &str = "https://www.gns.gov.pt/media/TSLPT.xml";

/// Signing preferences and trust-service endpoints.
///
/// `tsa_url`/`tsl_url` default to the official Portuguese trust services
/// ([`DEFAULT_PT_TSA_URL`] / [`DEFAULT_PT_TSL_URL`]) so a fresh install is pre-wired to real,
/// free state endpoints. **Pre-filling a URL does not change runtime behaviour**: the app never
/// contacts the TSA/TSL at rest; live use stays network-gated (feature-gated, operator-initiated)
/// exactly as before. An admin may override or clear either URL in Configurações → Assinaturas.
///
/// Null-vs-default policy (backward-compatible, no schema bump — the container `#[serde(default)]`
/// drives it): a stored document that **omits** `tsa_url`/`tsl_url` inherits the official default;
/// one that stores an explicit `null` keeps `null` (`None`) — the operator's recorded choice wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningSettings {
    /// Preferred qualified-signature family offered first in the UI.
    pub preferred_family: SignatureFamily,
    /// RFC 3161 timestamping authority URL. Defaults to [`DEFAULT_PT_TSA_URL`]; `null` clears it.
    pub tsa_url: Option<String>,
    /// Trusted-list (TSL) URL used for qualified-status checks. Defaults to
    /// [`DEFAULT_PT_TSL_URL`]; `null` clears it.
    pub tsl_url: Option<String>,
    /// When true, an act cannot reach the finalized-**qualified** status until a valid qualified
    /// signature is present (t57 ruling 6 / deliverable D). This gates the STATUS, **not** the seal:
    /// sealing still succeeds and the unsigned PDF/A still exists; the async OTP signing flow is a
    /// distinct post-seal step. With it `false`, the non-qualified finalized path stays fully usable.
    pub require_qualified_for_seal: bool,
    /// Chave Móvel Digital signing configuration (t57 Slice 1). Non-secret selectors only — the AMA
    /// ApplicationId secret material and the field-encryption certificate PEM come from the
    /// environment (`CHANCELA_CMD_*`), never this echoed settings document.
    pub cmd: SigningCmdSettings,
}

impl Default for SigningSettings {
    fn default() -> Self {
        SigningSettings {
            preferred_family: SignatureFamily::default(),
            tsa_url: Some(DEFAULT_PT_TSA_URL.to_owned()),
            tsl_url: Some(DEFAULT_PT_TSL_URL.to_owned()),
            require_qualified_for_seal: false,
            cmd: SigningCmdSettings::default(),
        }
    }
}

/// Chave Móvel Digital signing configuration surfaced in the settings document (t57 F1).
///
/// **Secrets never live here.** The AMA field-encryption certificate PEM and the ApplicationId are
/// read from the environment (`CHANCELA_CMD_ENV` / `CHANCELA_CMD_APPLICATION_ID` /
/// `CHANCELA_CMD_AMA_CERT_PEM`) by `chancela_cmd::CmdConfig::from_env`. This sub-object carries only
/// the non-secret selectors an operator sees: which environment, the (non-secret) ApplicationId
/// echo, and a read-only "is the AMA cert configured?" indicator.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningCmdSettings {
    /// Which AMA SCMD environment to talk to. Defaults to `Preprod` (t57 ruling 5): ship pointing at
    /// pre-production until real prod credentials + AMA onboarding are in place.
    pub env: CmdEnvSetting,
    /// The AMA-assigned ApplicationId, or `null` if not set. Non-secret opaque identifier; required
    /// (from env in production) before a signature can be started.
    pub application_id: Option<String>,
    /// Read-only surface: whether the AMA field-encryption certificate is configured (the PEM itself
    /// comes from `CHANCELA_CMD_AMA_CERT_PEM`, never this document). PROD requires it.
    pub ama_cert_configured: bool,
}

/// The AMA SCMD environment selector (mirrors `chancela_cmd::CmdEnv`, serialized lowercase).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CmdEnvSetting {
    /// AMA pre-production — the default (cleartext fields allowed).
    #[default]
    Preprod,
    /// AMA production (field encryption required).
    Prod,
}

/// Cosmetic front-end preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppearanceSettings {
    /// Light/dark/system theme selection.
    pub theme: ThemeMode,
    /// Whether the procedural leather-texture background is rendered.
    pub leather_texture: bool,
    /// Texture strength, `0..=100` (validated on `PUT`).
    pub texture_intensity: u8,
    /// Whether the subtle leather grain is applied to buttons. Additive and defaults to `true`,
    /// so an older stored document that omits it keeps the textured buttons.
    pub button_texture: bool,
}

impl Default for AppearanceSettings {
    fn default() -> Self {
        AppearanceSettings {
            theme: ThemeMode::default(),
            leather_texture: true,
            texture_intensity: 60,
            button_texture: true,
        }
    }
}

// --- Enums (serde encodings pinned by the contract) ---------------------------------------

/// Document/UI locale. Serialized as the BCP-47 tag the front-end expects (language subtag
/// lowercase, region subtag UPPERCASE). The set is additive: the pre-existing `pt-PT`/`en-US`
/// tags keep their exact encodings, so older stored documents remain valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Locale {
    /// Portuguese (Portugal) — the default.
    #[default]
    #[serde(rename = "pt-PT")]
    PtPt,
    /// Portuguese (Brazil).
    #[serde(rename = "pt-BR")]
    PtBr,
    /// Danish (Denmark).
    #[serde(rename = "da-DK")]
    DaDk,
    /// German (Germany).
    #[serde(rename = "de-DE")]
    DeDe,
    /// French (France).
    #[serde(rename = "fr-FR")]
    FrFr,
    /// Finnish (Finland).
    #[serde(rename = "fi-FI")]
    FiFi,
    /// Swedish (Finland) — Finland-Swedish, distinct from `sv-SE`.
    #[serde(rename = "sv-FI")]
    SvFi,
    /// Italian (Italy).
    #[serde(rename = "it-IT")]
    ItIt,
    /// Dutch (Netherlands).
    #[serde(rename = "nl-NL")]
    NlNl,
    /// Polish (Poland).
    #[serde(rename = "pl-PL")]
    PlPl,
    /// English (United Kingdom).
    #[serde(rename = "en-GB")]
    EnGb,
    /// English (United States).
    #[serde(rename = "en-US")]
    EnUs,
    /// Swedish (Sweden).
    #[serde(rename = "sv-SE")]
    SvSe,
    /// Spanish (Spain).
    #[serde(rename = "es-ES")]
    EsEs,
}

/// Preferred qualified-signature family. Variant names match the domain vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SignatureFamily {
    /// Cartão de Cidadão (smart card).
    CartaoCidadao,
    /// Chave Móvel Digital (remote qualified signing) — the default (t57 Slice 1). CMD is the
    /// family the product wires end-to-end (two-phase OTP flow); it needs no local card reader, so
    /// it is the sensible default offered first in the UI.
    #[default]
    ChaveMovelDigital,
    /// Any other qualified certificate.
    OtherQualified,
    /// Manual (wet-ink / out-of-band) signature.
    Manual,
}

/// Theme selection. Lowercase to match the CSS/theme tokens the web app uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    /// Follow the operating-system preference — the default.
    #[default]
    System,
    /// Force the light theme.
    Light,
    /// Force the dark theme.
    Dark,
}

// --- Validation ---------------------------------------------------------------------------

impl Settings {
    /// Validate the ranges and URL shapes serde cannot express on its own. Enum and locale
    /// values are already validated by deserialization; this covers `texture_intensity`'s
    /// numeric range and the trust-service URLs. Returns `422` on any violation.
    fn validate(&self) -> Result<(), ApiError> {
        if self.appearance.texture_intensity > 100 {
            return Err(ApiError::Unprocessable(format!(
                "appearance.texture_intensity must be between 0 and 100, got {}",
                self.appearance.texture_intensity
            )));
        }
        for (field, url) in [
            ("signing.tsa_url", &self.signing.tsa_url),
            ("signing.tsl_url", &self.signing.tsl_url),
            ("catalog.cae_update_url", &self.catalog.cae_update_url),
        ] {
            if let Some(raw) = url {
                let trimmed = raw.trim();
                // A present-but-empty string is treated as "unset"; anything non-empty must
                // look like an http(s) URL (plain string check, no URL-parsing dependency).
                if !trimmed.is_empty() && !is_http_url(trimmed) {
                    return Err(ApiError::Unprocessable(format!(
                        "{field} must be an http(s) URL, got {raw:?}"
                    )));
                }
            }
        }
        // Each ordered CAE source entry: a required http(s) URL and, when present, a 64-char
        // sha256-hex digest pin. A bad entry is a client-actionable `422`.
        for (i, entry) in self.catalog.cae_sources.iter().enumerate() {
            let trimmed = entry.url.trim();
            if trimmed.is_empty() || !is_http_url(trimmed) {
                return Err(ApiError::Unprocessable(format!(
                    "catalog.cae_sources[{i}].url must be an http(s) URL, got {:?}",
                    entry.url
                )));
            }
            if let Some(digest) = &entry.digest {
                let digest = digest.trim();
                if !digest.is_empty()
                    && (digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()))
                {
                    return Err(ApiError::Unprocessable(format!(
                        "catalog.cae_sources[{i}].digest must be a 64-character sha256 hex, got {:?}",
                        entry.digest
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Minimal http(s) URL shape check: an `http://` or `https://` scheme with a non-empty
/// authority following it. Deliberately not a full RFC 3986 parse — just enough to reject
/// obviously wrong values (empty, `ftp://…`, a bare hostname) without adding a dependency.
fn is_http_url(s: &str) -> bool {
    match s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
    {
        Some(rest) => !rest.is_empty(),
        None => false,
    }
}

// --- Persistence --------------------------------------------------------------------------

/// The file name holding the settings document inside the data directory.
pub const SETTINGS_FILE: &str = "settings.json";

/// Read `settings.json` from `path`, returning `None` if it is absent or unreadable, and
/// falling back to defaults (with a warning) if it is present but malformed. A corrupt file
/// must never stop the server from starting.
pub(crate) fn load_settings(path: &Path) -> Option<Settings> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(settings) => Some(settings),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid settings document ({e}); using defaults",
                path.display()
            );
            None
        }
    }
}

/// Atomically write `settings` to `path`: serialize to a uniquely-named temp file in the same
/// directory, then rename it over the destination (an atomic replace on both Windows and
/// Unix). The parent directory is created if missing.
fn write_settings_atomic(path: &Path, settings: &Settings) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_vec_pretty(settings).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path);
    std::fs::write(&tmp, &json)?;
    // rename over the destination is atomic and, on Windows, replaces an existing file.
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Best-effort cleanup so a failed rename does not leave a stray temp file behind.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// A sibling temp path for the atomic write, made unique so two concurrent `PUT`s never race
/// on the same temp file before their renames.
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| SETTINGS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

// --- Handlers -----------------------------------------------------------------------------

/// Query for `PUT /v1/settings`: an optional actor override for the audit event.
#[derive(Deserialize)]
pub struct SettingsActorQuery {
    /// Actor to attribute the `settings.updated` event to; falls back to the document's
    /// `organization.default_actor` when absent or blank.
    pub actor: Option<String>,
}

/// `GET /v1/settings` — the current settings document (defaults if never set).
pub async fn get_settings(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Settings>, ApiError> {
    // RBAC (t64-E3): reading settings is `settings.read` at Global.
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;
    Ok(Json(state.settings.read().await.clone()))
}

/// `PUT /v1/settings` — replace the whole settings document.
///
/// The body is the entire [`Settings`] document. It is parsed leniently (missing fields
/// default), then validated (`texture_intensity` range, trust-service URL shapes). On success
/// the document is persisted (atomically, if the state is file-backed), a `settings.updated`
/// ledger event is appended, the in-memory copy is replaced, and the stored document is
/// echoed back. Any validation failure returns `422` with the standard `{"error": …}` body.
pub async fn put_settings(
    State(state): State<AppState>,
    Query(query): Query<SettingsActorQuery>,
    current_actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<Json<Settings>, ApiError> {
    // RBAC (t64-E3): replacing settings is `settings.manage` at Global.
    require_permission(
        &state,
        &current_actor,
        Permission::SettingsManage,
        Scope::Global,
    )
    .await?;
    // Parse by hand (rather than via the `Json` extractor) so every rejection — malformed
    // JSON, a bad enum, a bad locale — renders through `ApiError` as the standard body.
    let mut settings: Settings = serde_json::from_slice(&body)
        .map_err(|e| ApiError::Unprocessable(format!("invalid settings document: {e}")))?;
    // Always stamp the current schema version regardless of what the client sent.
    settings.schema_version = SETTINGS_SCHEMA_VERSION;
    settings.validate()?;

    // Persist before we acknowledge success, so we never report a write we did not make.
    if let Some(path) = &state.persist_path {
        write_settings_atomic(path, &settings)
            .map_err(|e| ApiError::Internal(format!("failed to persist settings: {e}")))?;
    }

    // Actor precedence (contract §2.8): a valid session wins; else the `?actor=` override; else
    // the document's own default actor.
    let request_actor = query
        .actor
        .filter(|a| !a.trim().is_empty())
        .unwrap_or_else(|| settings.organization.default_actor.clone());
    let actor = current_actor.resolve(&request_actor);

    let payload = serde_json::to_vec(&settings)?;
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            "settings",
            "settings.updated",
            Some("settings updated"),
            &payload,
        );
        // Persist the audit event; the settings document itself is durable via `settings.json`.
        state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
        state.attest_latest(&attestor, &ledger).await;
    }

    *state.settings.write().await = settings.clone();
    Ok(Json(settings))
}
