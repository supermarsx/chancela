//! Official-source obtainer engine (plan t23 §2.2): fetch an OFFICIAL CAE artifact, parse it into a
//! [`CaeDataset`], and run it through the existing structural-integrity gate plus a full-count
//! fidelity gate before it may supersede the active catalog. The reliable-obtain guarantee lives in
//! the pipeline, not the parser — a bad parse is rejected, never promoted.
//!
//! **Skeleton status (t23-m1):** this module pins the public surface (the [`OfficialCaeSource`]
//! trait, [`DrPdfSource`], [`ObtainedDataset`], [`obtain_and_supersede`]) and the load-bearing
//! constants (immutable Diário da República URLs + pinned artifact digests); the bodies are
//! `todo!()` stubs that t23-e1 fills in.
//!
//! **PDF engine:** pure-Rust `lopdf` (already a workspace dep). No native library is bundled, so the
//! default build stays native-dep-free — unlike a `pdfium-render` path, which is the documented
//! escalation if `lopdf`'s content-stream text extraction proves infeasible.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::cache::supersedes;
use crate::catalog::CaeOrigin;
use crate::dataset::{CAE_SCHEMA_VERSION, CaeProvenance};
use crate::{CaeCatalog, CaeDataset, CaeError, CaeRefreshOutcome, CaeRevision, load_catalog};

mod chain;
mod fidelity;
mod format;
mod pdf;
mod simple;
mod smi;
mod verify;

pub use chain::{
    CaeSourceChain, ChainEntry, ChainFailure, ChainOutcome, MirrorArtifactSource, obtain_from_chain,
};
pub use fidelity::{EXPECTED_REV3_COUNTS, EXPECTED_REV4_COUNTS, verify_fidelity};
pub use format::{CaeSourceFormat, detect_format, parse_artifact};
pub use smi::{
    CaeVersions, SMI_BASE_URL, SMI_CAE_REV3_VERSION, SMI_CAE_REV4_VERSION, SMI_VERSION_EXPORT_PATH,
    SmiSource, SmiVersion, SmiVersionCatalog, parse_smi_version_catalog,
};
pub use verify::{CaeVerifier, SICONF_BASE_URL, SiconfVerifier, VerifierFinding};

/// The built-in **official** source chain used when no update URL is configured (user directive t33):
/// refresh should still obtain CAE Rev.3 + Rev.4 from the official gov source rather than erroring.
///
/// The chain is the digest-pinned **Diário da República diploma pair** ([`ChainEntry::official`]) —
/// the only source that reliably yields a complete both-revision [`CaeDataset`] passing the exact
/// fidelity gate (1962 / 1847 nodes). It is the official Portuguese government publication of the two
/// CAE revisions, so "no URL configured ⇒ obtain from the gov source" is honoured in full.
///
/// **INE SMI is intentionally NOT a bulk entry here.** Live investigation (see [`smi`]) established
/// that SMI serves only the version *catalog* non-interactively — its CAE node tree (`/Categoria`)
/// returns HTTP 500 for every anonymous access pattern — so an [`SmiSource`] cannot supply the codes
/// a fidelity-passing dataset needs; it would be a guaranteed chain failure. SMI is exposed instead as
/// an update-availability signal ([`SmiSource::fetch_catalog`] → [`SmiVersionCatalog::cae_versions`]).
/// The api leg may resolve additional operator-configured mirrors *before* this default chain; this
/// helper is the fallback when nothing is configured.
pub fn default_official_chain() -> CaeSourceChain {
    CaeSourceChain::new(vec![ChainEntry::official()])
}

/// Human note recording which official diplomas an obtained dataset was parsed from (mirrors the
/// embedded dataset's note; the in-app obtainer reads the same two DR diplomas).
const OBTAIN_SOURCE_NOTE: &str = "Obtido a partir de DL 381/2007 (CAE-Rev.3) e DL 9/2025 \
     (CAE-Rev.4), Diário da República 1.ª série, via o obtentor oficial em-aplicação (lopdf).";

/// The obtainer/parser version stamped into provenance: crate version + the DR-PDF parser revision.
const PARSER_VERSION: &str = concat!("chancela-cae/", env!("CARGO_PKG_VERSION"), "+drpdf.1");

/// The immutable Diário da República diploma PDF for **CAE-Rev.4** (Decreto-Lei n.º 9/2025). A
/// `files.diariodarepublica.pt` diploma URL is a published file that never moves or mutates.
pub const DR_REV4_PDF_URL: &str =
    "https://files.diariodarepublica.pt/1s/2025/02/03000/0000800049.pdf";
/// Pinned sha256 (lowercase hex) of the Rev.4 diploma PDF — detects even a silent republish.
pub const DR_REV4_PDF_SHA256: &str =
    "84286f31e98b06347007d78b3bcf3258ad4c81dd84adce728af15c27be29c641";

/// The immutable Diário da República diploma PDF for **CAE-Rev.3** (Decreto-Lei n.º 381/2007).
pub const DR_REV3_PDF_URL: &str = "https://files.dre.pt/1s/2007/11/21900/0844008464.pdf";
/// Pinned sha256 (lowercase hex) of the Rev.3 diploma PDF.
pub const DR_REV3_PDF_SHA256: &str =
    "ab037e43d4376870fd9a3559a2176c07032d0ada6eccb104ccef1efcdf11662a";

/// User-agent presented on the diploma fetch (identifies the app to the DR host).
const DEFAULT_USER_AGENT: &str = concat!("chancela-cae/", env!("CARGO_PKG_VERSION"));

/// An OFFICIAL artifact source: fetch + parse to a complete [`CaeDataset`] with provenance.
///
/// The only bulk source that implements this trait is [`DrPdfSource`] — the Diário da República
/// diploma PDFs, the single artifact that is authoritative, complete (including the Portugal-specific
/// 5th-digit subclasses), and at an immutable digest-pinnable URL. Two further official-ecosystem
/// surfaces are built as **sibling capabilities** (not `OfficialCaeSource` bulk sources, because
/// neither can supply a fidelity-passing both-revision dataset non-interactively):
///
/// - **INE SMI** (`smi.ine.pt`) — the legal maintainer's classification registry. Built as
///   [`SmiSource`](super::SmiSource): its CAE node tree (`/Categoria`) returns HTTP 500 for every
///   anonymous access pattern, so the only reliably-served artifact is the *version catalog*
///   (`/Versao/Exportacao`, chunked — no duplicate-`Content-Length` hazard). `SmiSource` parses that
///   into an *update-availability signal* ("which CAE version does INE currently publish?"), not a
///   bulk catalog (see `src/obtain/smi.rs`).
/// - **SICONF** (`www2.gov.pt/.../PesquisaIntegradaCAE.aspx`) — the gov.pt RegistoOnline CAE picker.
///   A genuine, current (Rev.4) official surface, but a postback-only ASP.NET WebForms `TreeView`
///   with **no export and no per-code GET**, so it is at most a per-code *live verifier*
///   ([`SiconfVerifier`](super::SiconfVerifier), live transport deferred), never a bulk obtainer.
pub trait OfficialCaeSource: Send + Sync {
    /// The kind of official source, for provenance recording and the UI.
    fn kind(&self) -> OfficialSourceKind;

    /// Fetch the artifact(s), parse them, and build a complete dataset carrying provenance.
    fn obtain(&self) -> Result<ObtainedDataset, CaeError>;
}

/// Which official source produced a dataset. Serializes as the bare variant name
/// (`"DiarioRepublica"` / `"Mirror"`); recorded in the provenance envelope (§2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OfficialSourceKind {
    DiarioRepublica,
    Mirror,
}

impl OfficialSourceKind {
    /// A short human label for outcome notes / the UI.
    pub fn label(self) -> &'static str {
        match self {
            OfficialSourceKind::DiarioRepublica => "Diário da República",
            OfficialSourceKind::Mirror => "espelho",
        }
    }
}

/// A dataset obtained from an official source, ready for the integrity + fidelity gates.
#[derive(Clone, Debug)]
pub struct ObtainedDataset {
    /// The parsed dataset (carries the provenance record added by t23-e1).
    pub dataset: CaeDataset,
}

/// Where a single revision's PDF comes from: a remote URL (fetched) or a local path (offline / DI).
enum RevisionInput {
    Url(String),
    File(PathBuf),
}

impl RevisionInput {
    /// A human/audit label for provenance (the URL, or the file path).
    fn label(&self) -> String {
        match self {
            RevisionInput::Url(u) => u.clone(),
            RevisionInput::File(p) => p.display().to_string(),
        }
    }
}

/// Diário da República diploma-PDF source: fetches the immutable per-revision PDF(s) (or reads local
/// files for tests/DI), parses both revisions, and optionally digest-pins the fetched artifact.
pub struct DrPdfSource {
    rev4: RevisionInput,
    rev3: RevisionInput,
    expected_rev4_digest: Option<String>,
    expected_rev3_digest: Option<String>,
    user_agent: String,
}

impl DrPdfSource {
    /// The built-in official source: the immutable DR diploma URLs with their pinned digests.
    pub fn official() -> Self {
        Self {
            rev4: RevisionInput::Url(DR_REV4_PDF_URL.to_owned()),
            rev3: RevisionInput::Url(DR_REV3_PDF_URL.to_owned()),
            expected_rev4_digest: Some(DR_REV4_PDF_SHA256.to_owned()),
            expected_rev3_digest: Some(DR_REV3_PDF_SHA256.to_owned()),
            user_agent: DEFAULT_USER_AGENT.to_owned(),
        }
    }

    /// Override the fetch URLs (each `None` falls back to the built-in immutable DR URL). Overridden
    /// URLs are unpinned (a caller-supplied mirror is not the pinned official artifact).
    pub fn with_urls(rev4: Option<String>, rev3: Option<String>) -> Self {
        Self {
            rev4: RevisionInput::Url(rev4.unwrap_or_else(|| DR_REV4_PDF_URL.to_owned())),
            rev3: RevisionInput::Url(rev3.unwrap_or_else(|| DR_REV3_PDF_URL.to_owned())),
            expected_rev4_digest: None,
            expected_rev3_digest: None,
            user_agent: DEFAULT_USER_AGENT.to_owned(),
        }
    }

    /// Parse vendored/fixture PDFs from disk instead of fetching (offline tests + dependency
    /// injection). No network access; artifact digests are not pinned.
    pub fn from_files(rev4: &Path, rev3: &Path) -> Self {
        Self {
            rev4: RevisionInput::File(rev4.to_path_buf()),
            rev3: RevisionInput::File(rev3.to_path_buf()),
            expected_rev4_digest: None,
            expected_rev3_digest: None,
            user_agent: DEFAULT_USER_AGENT.to_owned(),
        }
    }

    /// Resolve one revision's input to its bytes, digest-pinning against `expected` when set. Reads a
    /// local file or fetches the URL (blocking `reqwest`). A digest mismatch is a rejecting
    /// [`CaeError::Integrity`] — even a silently-republished artifact is refused.
    fn load(
        &self,
        input: &RevisionInput,
        expected: &Option<String>,
        revision: CaeRevision,
    ) -> Result<Vec<u8>, CaeError> {
        let bytes = match input {
            RevisionInput::File(path) => std::fs::read(path)
                .map_err(|e| CaeError::Http(format!("read {}: {e}", path.display())))?,
            RevisionInput::Url(url) => fetch_bytes(url, &self.user_agent)?,
        };
        if let Some(expected) = expected {
            let digest = sha256_hex(&bytes);
            if !digest.eq_ignore_ascii_case(expected.trim()) {
                return Err(CaeError::Integrity(format!(
                    "{revision:?} artifact digest mismatch: expected {expected}, got {digest}"
                )));
            }
        }
        Ok(bytes)
    }
}

impl OfficialCaeSource for DrPdfSource {
    fn kind(&self) -> OfficialSourceKind {
        OfficialSourceKind::DiarioRepublica
    }

    fn obtain(&self) -> Result<ObtainedDataset, CaeError> {
        // Resolve + digest-pin each revision's artifact, then parse it via the lopdf port.
        let rev4_bytes = self.load(&self.rev4, &self.expected_rev4_digest, CaeRevision::Rev4)?;
        let rev3_bytes = self.load(&self.rev3, &self.expected_rev3_digest, CaeRevision::Rev3)?;
        let rev4 = pdf::parse_revision_pdf(&rev4_bytes, CaeRevision::Rev4)?;
        let rev3 = pdf::parse_revision_pdf(&rev3_bytes, CaeRevision::Rev3)?;

        // Provenance records the CURRENT revision's (Rev.4) artifact — the headline official source;
        // both diplomas are named in `source_note`.
        let now = now_rfc3339();
        let provenance = CaeProvenance {
            source_kind: self.kind(),
            source_url: self.rev4.label(),
            artifact_digest: sha256_hex(&rev4_bytes),
            retrieved_at: now.clone(),
            parser_version: PARSER_VERSION.to_owned(),
        };
        let dataset = CaeDataset {
            schema_version: CAE_SCHEMA_VERSION,
            generated_at: now,
            source_note: OBTAIN_SOURCE_NOTE.to_owned(),
            rev3,
            rev4,
            provenance: Some(provenance),
        };
        Ok(ObtainedDataset { dataset })
    }
}

/// Fetch an artifact's bytes over HTTP with a short-lived blocking client (built + dropped inside
/// the call, so it never outlives a surrounding async runtime — run off any tokio runtime, as the
/// API's refresh handler does). Mirrors [`crate::HttpCaeSource`]'s transport.
fn fetch_bytes(url: &str, user_agent: &str) -> Result<Vec<u8>, CaeError> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(user_agent)
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| CaeError::Config(e.to_string()))?;
    let bytes = client
        .get(url)
        .send()
        .map_err(|e| CaeError::Http(e.to_string()))?
        .error_for_status()
        .map_err(|e| CaeError::Http(e.to_string()))?
        .bytes()
        .map_err(|e| CaeError::Http(e.to_string()))?;
    Ok(bytes.to_vec())
}

/// Lowercase-hex sha256 of a byte slice.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut hex = String::with_capacity(64);
    for b in hasher.finalize() {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Current instant as an RFC 3339 string (empty on the practically-impossible format failure).
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// The full obtain pipeline: obtain → structural integrity ([`CaeCatalog::from_dataset`]) → full
/// fidelity ([`verify_fidelity`]) → supersede (atomic cache write + in-memory swap). Mirrors
/// [`crate::refresh`] but for an [`OfficialCaeSource`] and with the added fidelity gate. No-op-safe:
/// a same/older dataset returns `updated: false`; any failure leaves the active catalog untouched.
pub fn obtain_and_supersede(
    source: &dyn OfficialCaeSource,
    data_dir: Option<&Path>,
) -> Result<(CaeCatalog, CaeRefreshOutcome), CaeError> {
    // Obtain → structural integrity → full fidelity. Any failure returns Err before the cache or the
    // active catalog is touched, so a bad obtain can never corrupt the known-good catalog.
    let dataset = source.obtain()?.dataset;
    let fetched = CaeCatalog::from_dataset_with_origin(dataset.clone(), CaeOrigin::Cache)?;
    verify_fidelity(&fetched.metadata().counts)?;

    let current = load_catalog(data_dir);
    if !supersedes(fetched.metadata(), current.metadata()) {
        let outcome = CaeRefreshOutcome {
            updated: false,
            metadata: current.metadata().clone(),
            note: "obtained dataset does not supersede the active catalog".to_owned(),
        };
        return Ok((current, outcome));
    }

    let note = match data_dir {
        Some(dir) => {
            crate::write_cache_atomic(dir, &dataset)
                .map_err(|e| CaeError::Config(format!("failed to write cache: {e}")))?;
            format!(
                "catalog obtained from {} (generated {})",
                source.kind().label(),
                fetched.metadata().generated_at
            )
        }
        None => "obtained in memory (no data dir configured; not persisted)".to_owned(),
    };
    let outcome = CaeRefreshOutcome {
        updated: true,
        metadata: fetched.metadata().clone(),
        note,
    };
    Ok((fetched, outcome))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vendored(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("data/source")
            .join(name)
    }

    /// Build a `DrPdfSource` reading the vendored PDFs with caller-set expected digests (exercises
    /// the digest-pin path offline; `from_files` alone leaves the pins unset).
    fn pinned(rev4: Option<&str>, rev3: Option<&str>) -> DrPdfSource {
        DrPdfSource {
            rev4: RevisionInput::File(vendored("rev4.pdf")),
            rev3: RevisionInput::File(vendored("rev3.pdf")),
            expected_rev4_digest: rev4.map(str::to_owned),
            expected_rev3_digest: rev3.map(str::to_owned),
            user_agent: "chancela-cae-test".to_owned(),
        }
    }

    /// The vendored PDFs' sha256 equal the pinned official DR digests — i.e. the committed files ARE
    /// the official artifacts — so pinning them accepts and the obtain succeeds with provenance.
    #[test]
    fn correct_digest_pins_accept_vendored_artifacts() {
        let ds = pinned(Some(DR_REV4_PDF_SHA256), Some(DR_REV3_PDF_SHA256))
            .obtain()
            .expect("vendored PDFs match the pinned official digests")
            .dataset;
        let p = ds.provenance.expect("provenance recorded");
        assert_eq!(p.source_kind, OfficialSourceKind::DiarioRepublica);
        assert_eq!(p.artifact_digest, DR_REV4_PDF_SHA256);
    }

    /// A wrong expected digest is refused (a silently-republished/tampered artifact is rejected).
    #[test]
    fn wrong_digest_is_rejected() {
        let err = pinned(Some(&"00".repeat(32)), None)
            .obtain()
            .expect_err("digest mismatch must be rejected");
        assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
    }
}
