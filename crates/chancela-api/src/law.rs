//! Law archive endpoints (spec/09 AI-20..22, spec/02 statutory anchors): a curated, locally
//! managed shelf of the diplomas that ground the product, each optionally paired with an
//! immutable official PDF the operator can download into an on-disk archive.
//!
//! The manifest ([`LAW_MANIFEST`]) is embedded, curated data — the statutory table of
//! [spec/02](../../../spec/02-legal-compliance.md): the CSC articles, the eIDAS execution
//! diploma, the two CAE diplomas, GDPR, and the rest. Each entry carries a stable **official
//! page** (a DRE ELI resolver URL or an EUR-Lex ELI URL) and, *only where an immutable official
//! PDF URL is known-good*, a `pdf_url`. Today that is the two Diário da República CAE diplomas
//! whose URLs are pinned (and sha256-vendored) in `crates/chancela-cae/data/source/PROVENANCE.md`;
//! every other entry has `pdf_url = null` and the UI falls back to its official page.
//!
//! ## The archive (mini law store)
//!
//! `POST /v1/law/{id}/fetch` downloads the entry's `pdf_url` — on a dedicated OS thread (the
//! `reqwest::blocking` client owns an internal runtime that must be built and dropped clear of the
//! async runtime, exactly like [`crate::cae`] / the registry consult) — enforces a size cap and a
//! `%PDF` magic-byte sanity check, then stores the bytes atomically at `<data_dir>/laws/<id>.pdf`
//! alongside a `manifest-state.json` recording the digest, size, and retrieval time (the same
//! atomic temp-file+rename pattern as `settings.json`). `GET /v1/law/{id}/pdf` serves the stored
//! bytes; `DELETE /v1/law/{id}/pdf` removes them. `GET /v1/law` merges the manifest with the store
//! state so the UI can show, per diploma, whether it is archived.
//!
//! Without a data directory the archive cannot persist: `fetch` returns a friendly `422` and every
//! manifest entry simply reports `stored: false`.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path as FsPath, PathBuf};
use std::time::Duration;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use chancela_authz::{Permission, Scope};
use chancela_law::{
    DiplomaKind, LawArticle, LawCatalog, LawCounts, LawDiploma, LawOrigin, LawProvenance,
    LawSource, Verification,
};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::require_permission;
use crate::error::ApiError;

// --- Manifest -----------------------------------------------------------------------------

/// One curated diploma on the law shelf. Static, embedded data (no persistence): the store state
/// is merged in at request time to form a [`LawEntryView`].
#[derive(Debug)]
pub struct LawEntry {
    /// Stable slug, also the on-disk file stem (`<id>.pdf`) and the `{id}` path parameter.
    pub id: &'static str,
    /// Human-readable diploma title (PT).
    pub title: &'static str,
    /// Formal legal reference (PT), e.g. `Decreto-Lei n.º 262/86, de 2 de setembro`.
    pub reference: &'static str,
    /// The specific articles that ground the product, when the entry is cited by article.
    pub articles: &'static [&'static str],
    /// One-sentence rationale (PT): why this diploma matters to Chancela.
    pub why: &'static str,
    /// Stable official page — a DRE ELI resolver URL (`data.dre.pt/eli/…`) or an EUR-Lex ELI URL.
    pub official_url: &'static str,
    /// An immutable official PDF URL, or `None` when no trustworthy pinned URL is known (then the
    /// archive cannot fetch this entry and the UI falls back to [`official_url`](Self::official_url)).
    pub pdf_url: Option<&'static str>,
    /// A note on the last relevant amendment/status, or `None`.
    pub last_amended: Option<&'static str>,
    /// The date this entry was last reviewed against the source (ISO `YYYY-MM-DD`).
    pub reviewed_on: &'static str,
}

/// The curated law shelf: the statutory anchors of [spec/02](../../../spec/02-legal-compliance.md).
///
/// `pdf_url` is populated **only** for the two Diário da República CAE diplomas whose immutable
/// URLs are pinned in `crates/chancela-cae/data/source/PROVENANCE.md` (verbatim). Every other entry
/// keeps `pdf_url = null` — no other official PDF URL can be pinned with confidence, so the archive
/// honestly cannot fetch it and the UI opens the official page instead.
pub const LAW_MANIFEST: &[LawEntry] = &[
    LawEntry {
        id: "csc",
        title: "Código das Sociedades Comerciais",
        reference: "Decreto-Lei n.º 262/86, de 2 de setembro",
        articles: &[
            "Artigo 63.º",
            "Artigo 376.º",
            "Artigo 377.º",
            "Artigo 388.º",
        ],
        why: "Fixa o conteúdo mínimo obrigatório das atas, as regras de convocação e realização \
              das assembleias gerais e a exigência de ata por cada reunião das sociedades comerciais.",
        official_url: "https://data.dre.pt/eli/dec-lei/262/1986/p/cons/20260101",
        pdf_url: None,
        last_amended: None,
        reviewed_on: "2026-07-07",
    },
    LawEntry {
        id: "dl-268-94",
        title: "Normas regulamentares do regime da propriedade horizontal (condomínios)",
        reference: "Decreto-Lei n.º 268/94, de 25 de outubro",
        articles: &[],
        why: "Torna obrigatória a ata das assembleias de condóminos, exige o resumo das matérias \
              essenciais e do resultado de cada votação e admite assinatura eletrónica qualificada \
              ou manuscrita.",
        official_url: "https://data.dre.pt/eli/dec-lei/268/1994/p/cons/20260101",
        pdf_url: None,
        last_amended: Some("Lei n.º 8/2022, de 10 de janeiro"),
        reviewed_on: "2026-07-07",
    },
    LawEntry {
        id: "dl-12-2021",
        title: "Execução na ordem jurídica nacional do Regulamento eIDAS",
        reference: "Decreto-Lei n.º 12/2021, de 9 de fevereiro",
        articles: &[],
        why: "Assegura a execução do eIDAS em Portugal: a assinatura eletrónica qualificada equivale \
              à assinatura manuscrita e as validações cronológicas qualificadas presumem-se quanto \
              à data e integridade.",
        official_url: "https://data.dre.pt/eli/dec-lei/12/2021/p/cons/20260101",
        pdf_url: None,
        last_amended: None,
        reviewed_on: "2026-07-07",
    },
    LawEntry {
        id: "eidas-910-2014",
        title: "Regulamento eIDAS — identificação eletrónica e serviços de confiança",
        reference: "Regulamento (UE) n.º 910/2014, de 23 de julho",
        articles: &["Artigo 25.º"],
        why: "Define o efeito jurídico das assinaturas eletrónicas qualificadas em toda a União \
              Europeia, equiparando-as à assinatura manuscrita.",
        official_url: "https://eur-lex.europa.eu/eli/reg/2014/910/oj",
        pdf_url: None,
        last_amended: None,
        reviewed_on: "2026-07-07",
    },
    LawEntry {
        id: "dl-76-a-2006",
        title: "Simplificação e eliminação de atos registais e notariais (societários)",
        reference: "Decreto-Lei n.º 76-A/2006, de 29 de março",
        articles: &[],
        why: "Elimina a exigência de escritura pública e de reconhecimento notarial para numerosos \
              atos societários e registais, admitindo deliberações e atos sociais em suporte \
              simplificado.",
        official_url: "https://data.dre.pt/eli/dec-lei/76-a/2006/p/cons/20260101",
        pdf_url: None,
        last_amended: None,
        reviewed_on: "2026-07-07",
    },
    LawEntry {
        id: "dl-381-2007",
        title: "Classificação Portuguesa das Atividades Económicas (CAE-Rev.3)",
        reference: "Decreto-Lei n.º 381/2007, de 14 de novembro",
        articles: &[],
        why: "Aprovou a CAE-Rev.3, o quadro de classificação das atividades económicas em vigor de \
              2008 a 2024 e base histórica da consulta de códigos CAE do produto.",
        official_url: "https://data.dre.pt/eli/dec-lei/381/2007/p/cons/20260101",
        // Pinned Diário da República PDF (PROVENANCE.md, verbatim; sha256-vendored).
        pdf_url: Some("https://files.dre.pt/1s/2007/11/21900/0844008464.pdf"),
        last_amended: None,
        reviewed_on: "2026-07-07",
    },
    LawEntry {
        id: "dl-9-2025",
        title: "Classificação Portuguesa das Atividades Económicas (CAE-Rev.4)",
        reference: "Decreto-Lei n.º 9/2025, de 12 de fevereiro",
        articles: &[],
        why: "Aprova a CAE-Rev.4, harmonizada com a NACE-Rev.2.1 e em vigor desde 1 de janeiro de \
              2025 — a classificação CAE atual usada pelo produto.",
        official_url: "https://diariodarepublica.pt/dr/detalhe/decreto-lei/9-2025-907097147",
        // Pinned Diário da República PDF (PROVENANCE.md, verbatim; sha256-vendored).
        pdf_url: Some("https://files.diariodarepublica.pt/1s/2025/02/03000/0000800049.pdf"),
        last_amended: None,
        reviewed_on: "2026-07-07",
    },
    LawEntry {
        id: "gdpr-2016-679",
        title: "Regulamento Geral sobre a Proteção de Dados (RGPD)",
        reference: "Regulamento (UE) 2016/679, de 27 de abril",
        articles: &["Artigo 5.º", "Artigo 25.º", "Artigo 32.º", "Artigo 35.º"],
        why: "Estabelece a minimização e limitação da finalidade dos dados, a proteção de dados \
              desde a conceção e por defeito, a segurança do tratamento e a AIPD para tratamentos \
              de risco elevado.",
        official_url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        pdf_url: None,
        last_amended: None,
        reviewed_on: "2026-07-07",
    },
    LawEntry {
        id: "lei-24-2012",
        title: "Lei-Quadro das Fundações",
        reference: "Lei n.º 24/2012, de 9 de julho",
        articles: &[],
        why: "Enquadra as fundações como pessoas coletivas de direito privado, relevante para as \
              entidades fundacionais suportadas pelo produto.",
        official_url: "https://data.dre.pt/eli/lei/24/2012/p/cons/20260101",
        pdf_url: None,
        last_amended: None,
        reviewed_on: "2026-07-07",
    },
];

/// Find a manifest entry by its slug.
fn manifest_entry(id: &str) -> Option<&'static LawEntry> {
    LAW_MANIFEST.iter().find(|e| e.id == id)
}

// --- Store state --------------------------------------------------------------------------

/// The subdirectory of the data directory holding the archived PDFs and the state file.
pub const LAWS_DIR: &str = "laws";
/// The file (inside [`LAWS_DIR`]) recording per-entry store metadata.
pub const LAW_STATE_FILE: &str = "manifest-state.json";
/// Maximum size of a downloaded law PDF (~40 MB). A larger body is rejected as a `502`.
pub const LAW_PDF_MAX_BYTES: u64 = 40 * 1024 * 1024;

/// What the archive knows about one stored PDF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredLawInfo {
    /// Lowercase-hex sha256 of the stored bytes.
    pub digest: String,
    /// Size of the stored PDF in bytes.
    pub bytes: u64,
    /// RFC 3339 timestamp of when the PDF was retrieved.
    pub retrieved_at: String,
}

/// The persisted archive state: a map of manifest id → [`StoredLawInfo`]. Serialized transparently
/// as a JSON object (the `manifest-state.json` document), loaded at startup and rewritten
/// atomically on every `fetch`/`delete`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LawStore {
    entries: BTreeMap<String, StoredLawInfo>,
}

/// Load the archive state from `<dir>/manifest-state.json`. A missing file yields an empty store;
/// a present-but-malformed file also falls back to empty (with a warning) so a bad file never
/// blocks startup — mirrors [`crate::settings::load_settings`].
pub(crate) fn load_law_store(laws_dir: &FsPath) -> LawStore {
    let path = laws_dir.join(LAW_STATE_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            eprintln!(
                "warning: {} is not a valid law-archive state document ({e}); using an empty archive",
                path.display()
            );
            LawStore::default()
        }),
        Err(_) => LawStore::default(),
    }
}

// --- Views --------------------------------------------------------------------------------

/// A manifest entry merged with its store state — the element of `GET /v1/law` and the body of a
/// successful `fetch`/`delete`.
#[derive(Debug, Serialize)]
pub struct LawEntryView {
    pub id: &'static str,
    pub title: &'static str,
    #[serde(rename = "ref")]
    pub reference: &'static str,
    pub articles: &'static [&'static str],
    pub why: &'static str,
    pub official_url: &'static str,
    pub pdf_url: Option<&'static str>,
    pub last_amended: Option<&'static str>,
    pub reviewed_on: &'static str,
    /// Whether an archived PDF exists for this entry.
    pub stored: bool,
    /// The archived PDF's digest, or `null` when not stored.
    pub stored_digest: Option<String>,
    /// The archived PDF's size in bytes, or `null` when not stored.
    pub stored_bytes: Option<u64>,
    /// When the PDF was retrieved (RFC 3339), or `null` when not stored.
    pub retrieved_at: Option<String>,
}

impl LawEntryView {
    fn new(e: &'static LawEntry, stored: Option<&StoredLawInfo>) -> Self {
        LawEntryView {
            id: e.id,
            title: e.title,
            reference: e.reference,
            articles: e.articles,
            why: e.why,
            official_url: e.official_url,
            pdf_url: e.pdf_url,
            last_amended: e.last_amended,
            reviewed_on: e.reviewed_on,
            stored: stored.is_some(),
            stored_digest: stored.map(|s| s.digest.clone()),
            stored_bytes: stored.map(|s| s.bytes),
            retrieved_at: stored.map(|s| s.retrieved_at.clone()),
        }
    }
}

// --- Handlers -----------------------------------------------------------------------------

/// `GET /v1/law` — the curated manifest merged with the archive state (per entry: `stored`,
/// `stored_digest`, `stored_bytes`, `retrieved_at`). Works with or without persistence; in memory
/// every entry reports `stored: false`.
pub async fn list_law(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<LawEntryView>>, ApiError> {
    // RBAC (t64-E3): the law archive is `law.read` at Global.
    require_permission(&state, &actor, Permission::LawRead, Scope::Global).await?;
    let store = state.law_store.read().await;
    let views = LAW_MANIFEST
        .iter()
        .map(|e| LawEntryView::new(e, store.entries.get(e.id)))
        .collect();
    Ok(Json(views))
}

/// `POST /v1/law/{id}/fetch` — download the entry's pinned PDF into the archive.
///
/// Unknown `id` → `404`. An entry without a pinned `pdf_url` → `409` (nothing trustworthy to
/// fetch). Without a data directory → a friendly `422` (the archive needs persistence). The
/// download runs on a dedicated OS thread (blocking `reqwest`), enforces [`LAW_PDF_MAX_BYTES`] and
/// a `%PDF` magic-byte check (a non-PDF body → `502`), stores the bytes atomically, records the
/// digest/size/time in `manifest-state.json`, and appends a `law.fetched` ledger event.
pub async fn fetch_law(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<LawEntryView>, ApiError> {
    // RBAC (t64-E3): fetching a diploma PDF into the archive is `law.manage` at Global.
    require_permission(&state, &actor, Permission::LawManage, Scope::Global).await?;
    let entry = manifest_entry(&id).ok_or(ApiError::NotFound)?;
    // The 409 gate is a manifest property: this diploma has no pinned official PDF to archive.
    if entry.pdf_url.is_none() {
        return Err(ApiError::Conflict(
            "este diploma não tem um PDF oficial fixável para descarregar — abra a página oficial"
                .to_owned(),
        ));
    }
    let laws_dir = match &state.laws_dir {
        Some(dir) => dir.as_ref().clone(),
        None => {
            return Err(ApiError::Unprocessable(
                "arquivo de leis requer persistência — defina CHANCELA_DATA_DIR".to_owned(),
            ));
        }
    };

    // Resolve where to download from: a test/DI base-URL override redirects the download to a
    // fixture (per-entry `<base>/<id>.pdf`); otherwise the manifest's pinned `pdf_url`.
    let url = match &state.law_pdf_base_override {
        Some(base) => format!("{}/{}.pdf", base.trim_end_matches('/'), entry.id),
        None => entry
            .pdf_url
            .expect("pdf_url present (checked above)")
            .to_owned(),
    };

    // Run the blocking fetch on a dedicated OS thread (no tokio context) so `reqwest::blocking`'s
    // internal runtime is built and dropped clear of the async runtime — mirrors `cae::refresh_cae`.
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("law-fetch".to_owned())
        .spawn(move || {
            let _ = tx.send(fetch_pdf_blocking(&url, LAW_PDF_MAX_BYTES));
        })
        .map_err(|e| ApiError::Internal(format!("failed to spawn law fetch thread: {e}")))?;
    let bytes = rx
        .await
        .map_err(|_| ApiError::Internal("law fetch thread ended unexpectedly".to_owned()))??;

    let digest = sha256_hex(&bytes);
    let info = StoredLawInfo {
        digest: digest.clone(),
        bytes: bytes.len() as u64,
        retrieved_at: now_rfc3339(),
    };

    // Persist the PDF, then the state file (both atomic), before acknowledging success.
    write_atomic(&laws_dir.join(format!("{}.pdf", entry.id)), &bytes)
        .map_err(|e| ApiError::Internal(format!("failed to store law pdf: {e}")))?;
    {
        let mut store = state.law_store.write().await;
        store.entries.insert(entry.id.to_owned(), info.clone());
        write_law_state_atomic(&laws_dir.join(LAW_STATE_FILE), &store)
            .map_err(|e| ApiError::Internal(format!("failed to persist law state: {e}")))?;
    }

    let actor = actor.resolve("api");
    let payload = serde_json::to_vec(&json!({ "id": entry.id, "digest": digest }))?;
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            "law",
            "law.fetched",
            Some("law pdf fetched"),
            &payload,
        );
        // Persist the audit event; the PDF + its metadata are durable via the `laws/` archive.
        state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
        state.attest_latest(&attestor, &ledger).await;
    }

    Ok(Json(LawEntryView::new(entry, Some(&info))))
}

/// `GET /v1/law/{id}/pdf` — serve the archived PDF bytes (`application/pdf`, inline). Unknown `id`
/// or an entry that is not archived → `404`.
pub async fn get_law_pdf(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    // RBAC (t64-E3): reading an archived diploma PDF is `law.read` at Global.
    require_permission(&state, &actor, Permission::LawRead, Scope::Global).await?;
    let entry = manifest_entry(&id).ok_or(ApiError::NotFound)?;
    let laws_dir = state.laws_dir.as_ref().ok_or(ApiError::NotFound)?;
    // Only serve what the state records as stored (guards against a stray file).
    if !state.law_store.read().await.entries.contains_key(entry.id) {
        return Err(ApiError::NotFound);
    }
    let bytes = std::fs::read(laws_dir.join(format!("{}.pdf", entry.id)))
        .map_err(|_| ApiError::NotFound)?;
    Response::builder()
        .header(CONTENT_TYPE, "application/pdf")
        .header(
            CONTENT_DISPOSITION,
            format!("inline; filename=\"{}.pdf\"", entry.id),
        )
        .body(Body::from(bytes))
        .map_err(|e| ApiError::Internal(format!("failed to build pdf response: {e}")))
}

/// `DELETE /v1/law/{id}/pdf` — remove the archived PDF. Unknown `id` or a not-archived entry →
/// `404`; on success `200` with the (now unstored) entry view and a `law.removed` ledger event.
pub async fn delete_law_pdf(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<LawEntryView>, ApiError> {
    // RBAC (t64-E3): removing an archived diploma PDF is `law.manage` at Global.
    require_permission(&state, &actor, Permission::LawManage, Scope::Global).await?;
    let entry = manifest_entry(&id).ok_or(ApiError::NotFound)?;
    let laws_dir = state
        .laws_dir
        .as_ref()
        .ok_or(ApiError::NotFound)?
        .as_ref()
        .clone();

    let removed = {
        let mut store = state.law_store.write().await;
        let existed = store.entries.remove(entry.id).is_some();
        if existed {
            write_law_state_atomic(&laws_dir.join(LAW_STATE_FILE), &store)
                .map_err(|e| ApiError::Internal(format!("failed to persist law state: {e}")))?;
        }
        existed
    };
    if !removed {
        return Err(ApiError::NotFound);
    }
    // Best-effort file removal — the authoritative record is the state file, already updated.
    let _ = std::fs::remove_file(laws_dir.join(format!("{}.pdf", entry.id)));

    let actor = actor.resolve("api");
    let payload = serde_json::to_vec(&json!({ "id": entry.id }))?;
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            "law",
            "law.removed",
            Some("law pdf removed"),
            &payload,
        );
        // Persist the audit event; the archive removal is durable via the `laws/` state file.
        state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
        state.attest_latest(&attestor, &ledger).await;
    }

    Ok(Json(LawEntryView::new(entry, None)))
}

// --- Download + persistence helpers -------------------------------------------------------

/// Fetch a PDF over HTTP with a blocking client, capping the read at `cap` bytes and requiring a
/// `%PDF` magic prefix. Build/drop the client on the calling thread (never a runtime-bearing one).
fn fetch_pdf_blocking(url: &str, cap: u64) -> Result<Vec<u8>, ApiError> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("chancela-api/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| ApiError::Internal(format!("failed to build http client: {e}")))?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| ApiError::Upstream(format!("law pdf fetch failed: {e}")))?
        .error_for_status()
        .map_err(|e| ApiError::Upstream(format!("law pdf fetch failed: {e}")))?;

    // Read at most cap+1 bytes so an oversized (or unbounded) body cannot exhaust memory.
    let mut buf = Vec::new();
    resp.take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| ApiError::Upstream(format!("law pdf read failed: {e}")))?;
    if buf.len() as u64 > cap {
        return Err(ApiError::Upstream(format!(
            "law pdf exceeds the maximum size of {cap} bytes"
        )));
    }
    if !buf.starts_with(b"%PDF") {
        return Err(ApiError::Upstream(
            "a resposta não é um PDF (não começa por %PDF)".to_owned(),
        ));
    }
    Ok(buf)
}

/// Lowercase-hex sha256, matching the ledger/registry digest convention.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(bytes));
    crate::hex::hex(&digest)
}

/// Current UTC time as an RFC 3339 string.
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Serialize the archive state and write it atomically.
fn write_law_state_atomic(path: &FsPath, store: &LawStore) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(store).map_err(std::io::Error::other)?;
    write_atomic(path, &json)
}

/// Atomically write `bytes` to `path`: a uniquely-named sibling temp file + rename (an atomic
/// replace on both Windows and Unix). The parent directory is created if missing. Mirrors
/// [`crate::settings`]'s atomic write.
fn write_atomic(path: &FsPath, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = tmp_path(path);
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// A unique sibling temp path so two concurrent writes never race on the same temp file.
fn tmp_path(path: &FsPath) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| LAW_STATE_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

// =============================================================================================
// The law corpus reader (t55-E2)
// =============================================================================================
//
// Read-only, full-text access to the embedded [`chancela_law`] corpus: list the diplomas, read a
// diploma's / a single article's full verbatim text, and full-text search across everything. This
// is distinct from the PDF archive above — that shelf pins official PDFs; this surfaces the
// article-by-article statute text committed in `chancela-law`, with the **authenticity status**
// ([`Verification`]) on every result so the reader can badge Verified vs Pending honestly and never
// presents an unverified/empty body as law (a `Pending` article always renders the loud
// `UNVERIFIED_MARKER`, via [`LawArticle::display_body`], never a raw un-sourced body).
//
// The corpus is immutable and compiled in ([`LawCatalog::embedded`], parsed once), so — unlike the
// refreshable CAE catalog — it needs no `AppState` slot; handlers read the static catalog directly.
// Routes are namespaced under `/v1/law/corpus` to sit cleanly beside the `/v1/law` PDF archive with
// no path/param collision, and are gated `law.read@Global` like the rest of the law shelf.

/// Default and maximum number of hits returned by `GET /v1/law/corpus/search`.
const DEFAULT_LAW_SEARCH_LIMIT: usize = 50;
const MAX_LAW_SEARCH_LIMIT: usize = 500;
/// Characters of context included on each side of a search match in a snippet.
const SNIPPET_CONTEXT: usize = 90;
/// Maximum article references accepted by the bounded citation resolver.
const MAX_LAW_CITATION_REFS: usize = 32;

// --- Corpus views -----------------------------------------------------------------------------

/// One article's provenance/citation — a self-contained mirror of the corpus' [`LawSource`], with
/// `complete` surfacing whether it cites a full authentic origin (the `Verified` precondition).
#[derive(Debug, Serialize)]
pub struct LawSourceView {
    pub diploma: String,
    pub article: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dr_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dr_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrieved_at: Option<String>,
    /// Whether this source cites a complete authentic origin.
    pub complete: bool,
}

impl LawSourceView {
    fn from_source(s: &LawSource) -> Self {
        LawSourceView {
            diploma: s.diploma.clone(),
            article: s.article.clone(),
            dr_reference: s.dr_reference.clone(),
            dr_date: s.dr_date.clone(),
            url: s.url.clone(),
            source_digest: s.source_digest.clone(),
            retrieved_at: s.retrieved_at.clone(),
            complete: s.is_complete(),
        }
    }
}

/// One article with its full (display) text + authenticity + citation metadata. `body` is the
/// verbatim text once `Verified`, or the loud unverified marker while `Pending` — via
/// [`LawArticle::display_body`], so an un-sourced body is never returned as if it were law.
#[derive(Debug, Serialize)]
pub struct LawArticleView {
    pub diploma_id: String,
    pub number: String,
    pub label: String,
    pub heading: String,
    pub body: String,
    pub verification: Verification,
    pub verified: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cross_refs: Vec<String>,
    pub source: LawSourceView,
}

/// One requested corpus citation key.
#[derive(Debug, Deserialize)]
pub struct LawCitationRef {
    pub diploma_id: String,
    pub article: String,
}

/// Request body for `POST /v1/law/citations/resolve`.
#[derive(Debug, Deserialize)]
pub struct LawCitationRequest {
    pub references: Vec<LawCitationRef>,
}

/// A compliance/draft-friendly legal basis view derived from a corpus article. It deliberately
/// carries the corpus verification state as-is: `Pending` remains pending and incomplete.
#[derive(Debug, Serialize)]
pub struct LawCitationView {
    pub source_id: String,
    pub source_label: String,
    pub article: String,
    pub article_label: String,
    pub citation: String,
    pub verification: Verification,
    pub source_url: Option<String>,
    pub source_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dr_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrieved_at: Option<String>,
}

impl LawCitationView {
    fn from_article(diploma: &LawDiploma, article: &LawArticle) -> Self {
        LawCitationView {
            source_id: diploma.id.clone(),
            source_label: diploma.title.clone(),
            article: article.number.clone(),
            article_label: article.label.clone(),
            citation: format!("{}, {}", diploma.reference, article.label),
            verification: article.verification,
            source_url: article.source.url.clone(),
            source_complete: article.source.is_complete(),
            dr_reference: article.source.dr_reference.clone(),
            source_digest: article.source.source_digest.clone(),
            retrieved_at: article.source.retrieved_at.clone(),
        }
    }
}

/// The bounded citation report returned to draft/compliance UIs. It is reference metadata only,
/// not persistence and not a legal-validity assertion.
#[derive(Debug, Serialize)]
pub struct LawCitationReport {
    pub legal_notice: &'static str,
    pub count: usize,
    pub citations: Vec<LawCitationView>,
}

impl LawArticleView {
    fn from_article(a: &LawArticle) -> Self {
        LawArticleView {
            diploma_id: a.diploma_id.clone(),
            number: a.number.clone(),
            label: a.label.clone(),
            heading: a.heading.clone(),
            body: a.display_body().to_owned(),
            verification: a.verification,
            verified: a.is_verified(),
            cross_refs: a.cross_refs.clone(),
            source: LawSourceView::from_source(&a.source),
        }
    }
}

/// A diploma summary (no article bodies): the element of `GET /v1/law/corpus` and the header of a
/// diploma detail. Carries per-diploma authenticity counts so the reader can badge coverage.
#[derive(Debug, Serialize)]
pub struct LawDiplomaSummaryView {
    pub id: String,
    pub kind: DiplomaKind,
    pub number: String,
    pub title: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub official_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eli: Option<String>,
    pub article_count: usize,
    pub verified_count: usize,
    pub pending_count: usize,
}

impl LawDiplomaSummaryView {
    fn from_diploma(d: &LawDiploma) -> Self {
        let verified = d.articles.iter().filter(|a| a.is_verified()).count();
        LawDiplomaSummaryView {
            id: d.id.clone(),
            kind: d.kind,
            number: d.number.clone(),
            title: d.title.clone(),
            reference: d.reference.clone(),
            official_url: d.official_url.clone(),
            eli: d.eli.clone(),
            article_count: d.articles.len(),
            verified_count: verified,
            pending_count: d.articles.len() - verified,
        }
    }
}

/// The embedded corpus' provenance/integrity metadata plus a per-diploma summary list: the body of
/// `GET /v1/law/corpus`.
#[derive(Debug, Serialize)]
pub struct LawCorpusView {
    pub schema_version: u32,
    pub generated_at: String,
    pub source_note: String,
    pub digest: String,
    pub origin: LawOrigin,
    pub counts: LawCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<LawProvenance>,
    pub diplomas: Vec<LawDiplomaSummaryView>,
}

/// A diploma with its full article set: the body of `GET /v1/law/corpus/{diploma}`.
#[derive(Debug, Serialize)]
pub struct LawDiplomaDetailView {
    #[serde(flatten)]
    pub summary: LawDiplomaSummaryView,
    pub articles: Vec<LawArticleView>,
}

/// One search hit: the matched article, its owning diploma, a context snippet, and authenticity.
#[derive(Debug, Serialize)]
pub struct LawSearchHitView {
    pub diploma_id: String,
    pub diploma_title: String,
    pub number: String,
    pub label: String,
    pub heading: String,
    /// A context window around the first match (accent/case-insensitive), with `…` elision.
    pub snippet: String,
    pub verification: Verification,
    pub verified: bool,
}

/// The body of `GET /v1/law/corpus/search`: the (echoed) query, hit count, and ranked hits.
#[derive(Debug, Serialize)]
pub struct LawSearchView {
    pub query: String,
    pub count: usize,
    pub results: Vec<LawSearchHitView>,
}

/// Query for `GET /v1/law/corpus/search`: the search text `q` and an optional result cap.
#[derive(Debug, Deserialize)]
pub struct LawSearchQuery {
    pub q: Option<String>,
    pub limit: Option<usize>,
}

// --- Corpus handlers --------------------------------------------------------------------------

/// `GET /v1/law/corpus` — the embedded law corpus: its provenance/integrity metadata plus a
/// per-diploma summary (article/verified/pending counts). Read-only reference (`law.read@Global`).
pub async fn list_law_corpus(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<LawCorpusView>, ApiError> {
    // RBAC (t64-E3): the law corpus is reference material — `law.read` at Global, like `/v1/law`.
    require_permission(&state, &actor, Permission::LawRead, Scope::Global).await?;
    let catalog = LawCatalog::embedded();
    let m = catalog.metadata();
    let diplomas = catalog
        .diplomas()
        .iter()
        .map(LawDiplomaSummaryView::from_diploma)
        .collect();
    Ok(Json(LawCorpusView {
        schema_version: m.schema_version,
        generated_at: m.generated_at.clone(),
        source_note: m.source_note.clone(),
        digest: m.digest.clone(),
        origin: m.origin,
        counts: m.counts,
        provenance: m.provenance.clone(),
        diplomas,
    }))
}

/// `GET /v1/law/corpus/{diploma}` — one diploma with its full article set (verbatim text for
/// `Verified` articles; the unverified marker for `Pending`). Unknown diploma → `404`.
pub async fn get_law_diploma(
    State(state): State<AppState>,
    Path(diploma): Path<String>,
    actor: CurrentActor,
) -> Result<Json<LawDiplomaDetailView>, ApiError> {
    require_permission(&state, &actor, Permission::LawRead, Scope::Global).await?;
    let catalog = LawCatalog::embedded();
    let d = catalog.diploma(&diploma).ok_or(ApiError::NotFound)?;
    let articles = d
        .articles
        .iter()
        .map(LawArticleView::from_article)
        .collect();
    Ok(Json(LawDiplomaDetailView {
        summary: LawDiplomaSummaryView::from_diploma(d),
        articles,
    }))
}

/// `GET /v1/law/corpus/{diploma}/{article}` — a single article's full text + citation metadata,
/// keyed by diploma slug + canonical article number (`"63"`, `"270-A"`). Unknown diploma or article
/// → `404`.
pub async fn get_law_article(
    State(state): State<AppState>,
    Path((diploma, article)): Path<(String, String)>,
    actor: CurrentActor,
) -> Result<Json<LawArticleView>, ApiError> {
    require_permission(&state, &actor, Permission::LawRead, Scope::Global).await?;
    let catalog = LawCatalog::embedded();
    let a = catalog
        .article(&diploma, &article)
        .ok_or(ApiError::NotFound)?;
    Ok(Json(LawArticleView::from_article(a)))
}

/// `POST /v1/law/citations/resolve` — normalize selected corpus article refs into the
/// compliance-panel legal-basis shape. This is intentionally bounded and read-only: it helps a
/// draft UI copy/pin references without pretending to persist them or upgrade authenticity.
pub async fn resolve_law_citations(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<LawCitationRequest>,
) -> Result<Json<LawCitationReport>, ApiError> {
    require_permission(&state, &actor, Permission::LawRead, Scope::Global).await?;
    if req.references.len() > MAX_LAW_CITATION_REFS {
        return Err(ApiError::Unprocessable(format!(
            "demasiadas referências: máximo de {MAX_LAW_CITATION_REFS}"
        )));
    }

    let catalog = LawCatalog::embedded();
    let mut citations = Vec::with_capacity(req.references.len());
    for r in req.references {
        let diploma = catalog
            .diploma(r.diploma_id.trim())
            .ok_or(ApiError::NotFound)?;
        let article = catalog
            .article(&diploma.id, r.article.trim())
            .ok_or(ApiError::NotFound)?;
        citations.push(LawCitationView::from_article(diploma, article));
    }

    Ok(Json(LawCitationReport {
        legal_notice: "Referências informativas para apoio à redação/conformidade; não substituem a publicação oficial nem revisão jurídica.",
        count: citations.len(),
        citations,
    }))
}

/// `GET /v1/law/corpus/search?q=&limit=` — accent/case-insensitive full-text search across every
/// article (label + heading + body + diploma title/reference), in corpus order, each hit carrying a
/// context snippet and its authenticity status. Blank/absent `q` → an empty result set. Matching is
/// delegated to [`LawCatalog::search`] (the authoritative fold); the snippet re-locates the match
/// with the same fold so its window is consistent.
pub async fn search_law_corpus(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(query): Query<LawSearchQuery>,
) -> Result<Json<LawSearchView>, ApiError> {
    require_permission(&state, &actor, Permission::LawRead, Scope::Global).await?;
    let catalog = LawCatalog::embedded();
    let q = query.q.as_deref().map(str::trim).unwrap_or_default();
    let limit = query
        .limit
        .unwrap_or(DEFAULT_LAW_SEARCH_LIMIT)
        .min(MAX_LAW_SEARCH_LIMIT);
    let needle = fold_law(q);

    let mut results = Vec::new();
    if !needle.is_empty() {
        for a in catalog.search(q).into_iter().take(limit) {
            let diploma_title = catalog
                .diploma(&a.diploma_id)
                .map(|d| d.title.clone())
                .unwrap_or_default();
            results.push(LawSearchHitView {
                diploma_id: a.diploma_id.clone(),
                diploma_title,
                number: a.number.clone(),
                label: a.label.clone(),
                heading: a.heading.clone(),
                snippet: build_snippet(a, &needle),
                verification: a.verification,
                verified: a.is_verified(),
            });
        }
    }
    Ok(Json(LawSearchView {
        query: q.to_owned(),
        count: results.len(),
        results,
    }))
}

// --- Search folding + snippet extraction ------------------------------------------------------

/// Accent+case fold mirroring `chancela_law`'s internal `fold` (and `diplomas.ts::foldForSearch`):
/// strip diacritics + lowercase, **1:1 per character**, so a folded char index maps back to the
/// original text for snippet windowing. Kept in sync with the corpus' fold so the snippet locates
/// exactly what [`LawCatalog::search`] matched.
fn fold_char(c: char) -> char {
    match c {
        'á' | 'à' | 'â' | 'ã' | 'ä' | 'Á' | 'À' | 'Â' | 'Ã' | 'Ä' => 'a',
        'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'e',
        'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'i',
        'ó' | 'ò' | 'ô' | 'õ' | 'ö' | 'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'o',
        'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'u',
        'ç' | 'Ç' => 'c',
        other => other.to_ascii_lowercase(),
    }
}

/// Fold a query into a char vector for subslice matching against folded article text.
fn fold_law(s: &str) -> Vec<char> {
    s.trim().chars().map(fold_char).collect()
}

/// The first index at which `needle` occurs as a contiguous subslice of `hay`, or `None`.
fn find_subslice(hay: &[char], needle: &[char]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| hay[i..i + needle.len()] == *needle)
}

/// A `…`-elided context window of `orig` around the `[match_start, match_start+match_len)` span.
fn window(orig: &[char], match_start: usize, match_len: usize) -> String {
    let start = match_start.saturating_sub(SNIPPET_CONTEXT);
    let end = (match_start + match_len + SNIPPET_CONTEXT).min(orig.len());
    let mut s = String::new();
    if start > 0 {
        s.push('…');
    }
    s.extend(orig[start..end].iter());
    if end < orig.len() {
        s.push('…');
    }
    s.trim().to_owned()
}

/// Build a context snippet for a search hit: locate the folded `needle` in the article's **display**
/// text (body → heading → label, in priority order) and window around the first match. When the
/// match lay only in the diploma context (title/reference), fall back to the heading (else the head
/// of the display body). Uses [`LawArticle::display_body`], so a `Pending` article's snippet is
/// drawn from its marker/heading — never from an un-sourced body.
fn build_snippet(article: &LawArticle, needle: &[char]) -> String {
    let body = article.display_body();
    for cand in [body, article.heading.as_str(), article.label.as_str()] {
        if cand.is_empty() {
            continue;
        }
        let orig: Vec<char> = cand.chars().collect();
        let folded: Vec<char> = orig.iter().map(|&c| fold_char(c)).collect();
        if let Some(i) = find_subslice(&folded, needle) {
            return window(&orig, i, needle.len());
        }
    }
    // Matched only on diploma context: show the heading (else the head of the display body).
    let fallback = if article.heading.is_empty() {
        body
    } else {
        article.heading.as_str()
    };
    window(&fallback.chars().collect::<Vec<_>>(), 0, 0)
}
