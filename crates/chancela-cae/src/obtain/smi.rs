//! INE SMI **version-catalog** source (plan t23 §1, user directive t33) — the official INE
//! classification registry at <https://smi.ine.pt>.
//!
//! # Feasibility verdict (live-probed 2026-07-07, over `reqwest`/`curl`)
//!
//! The user asked to obtain the CAE list ("rev3 and 4") from `https://smi.ine.pt/Categoria`. Live
//! investigation of that host establishes a hard boundary:
//!
//! - **The CAE node tree (`/Categoria`, `/Categoria/Parent`, `/Categoria/Exportacao`) is NOT
//!   obtainable non-interactively.** Every anonymous access pattern returns **HTTP 500** — a bare GET,
//!   a GET carrying the `ASP.NET_SessionId` cookie the host itself sets, a GET after visiting a
//!   version-detail page (`/Versao/Detalhes/{id}` → 200), a GET with `?versao=`/`?tipo=` query
//!   parameters, a `POST`, and the treeview AJAX loader `/Categoria/Parent`. The controller only
//!   renders through the site's stateful interactive flow (a version must be committed into the
//!   server-side session by an action that the direct URLs do not trigger). This is a genuine `500`
//!   status, not a client-side parse problem. So the only surface that carries actual codes +
//!   designations cannot be crawled reliably or politely — matching the SICONF finding.
//! - **Duplicate `Content-Length` hazard is confined to those 500 error pages.** The 500 responses
//!   carry two identical `Content-Length` headers (which strict HTTP parsers may reject). The
//!   **usable** export endpoints below use `Transfer-Encoding: chunked` with **no** `Content-Length`,
//!   so `reqwest`/`hyper` fetches them without issue — no tolerant-parsing workaround is needed.
//!
//! **What SMI *does* serve reliably** (clean, cold, cookieless GET; chunked; no session): the
//! **version / classification catalog** —
//! - `GET /Versao/Exportacao?tipo=2` → the list of every classification *version* as CSV (also
//!   `tipo=0` XLSX, `tipo=1` XML), including the two current CAE revisions:
//!   `V05497 = "Classificação portuguesa das atividades económicas, revisão 4" (CAE Rev.4)` and
//!   `V00554 = … revisão 3 (CAE Rev.3)`.
//! - `GET /Classificacao/Exportacao?tipo={0,1,2}` → the list of classification *families* (CAE,
//!   NACE, CN, …).
//!
//! Neither export contains the ~2000 CAE **nodes** (codes/designations) — they are metadata catalogs.
//!
//! # This module's role — an official **update-availability signal**, not a bulk catalog
//!
//! [`SmiSource`] fetches and parses the version catalog (the artifact SMI reliably serves) into
//! [`SmiVersionCatalog`], and extracts the current official CAE Rev.3 / Rev.4 version records via
//! [`SmiVersionCatalog::cae_versions`]. That answers "which CAE version does INE currently publish, and
//! when was it extracted?" — a real, useful *update signal* to compare against the embedded dataset.
//!
//! It deliberately does **not** implement [`OfficialCaeSource`](super::OfficialCaeSource): that trait
//! must yield a complete both-revision [`CaeDataset`] that clears the exact-count fidelity gate
//! (1962 / 1847 nodes), which no non-interactive SMI artifact can supply. Wiring SMI in as a bulk
//! source would therefore be a guaranteed fidelity failure. The reliable bulk official source stays
//! the digest-pinned Diário da República diploma pair ([`DrPdfSource`](super::DrPdfSource)); see
//! [`default_official_chain`](super::default_official_chain). This mirrors how the SICONF
//! [`CaeVerifier`](super::CaeVerifier) is a separate seam, honest about its boundary, rather than a
//! forced-fit bulk source.
//!
//! Parser coverage is offline via the checked-in `fixtures/smi_version_catalog.csv` (a trimmed real
//! capture, UTF-16LE + BOM); the **live** fetch is a `network-tests` + `#[ignore]` probe.

use crate::error::CaeError;
use crate::model::CaeRevision;

use super::fetch_bytes;

/// The SMI host base URL. The version catalog is served cold and cookieless from here.
pub const SMI_BASE_URL: &str = "https://smi.ine.pt";

/// The version-catalog export path (CSV form, `tipo=2`) appended to [`SMI_BASE_URL`]. Reliably a
/// clean, chunked, session-free GET (unlike the `/Categoria` code-tree endpoints, which 500).
pub const SMI_VERSION_EXPORT_PATH: &str = "/Versao/Exportacao?tipo=2";

/// The INE SMI version code of the current **CAE-Rev.4** classification version (`Decreto-Lei
/// n.º 9/2025`). Confirmed live in the version catalog; corrects the brief's earlier `V02624`.
pub const SMI_CAE_REV4_VERSION: &str = "V05497";

/// The INE SMI version code of the **CAE-Rev.3** classification version (`Decreto-Lei n.º 381/2007`).
pub const SMI_CAE_REV3_VERSION: &str = "V00554";

/// The `Sigla` value SMI stamps on the Rev.4 CAE version row.
const SMI_CAE_REV4_SIGLA: &str = "CAE Rev.4";
/// The `Sigla` value SMI stamps on the Rev.3 CAE version row.
const SMI_CAE_REV3_SIGLA: &str = "CAE Rev.3";

/// One classification-version record from the SMI version catalog: its SMI code (`V#####`), its full
/// Portuguese designation, and its short `Sigla`. For the CAE rows, [`revision`](Self::revision)
/// resolves the CAE revision from the sigla.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmiVersion {
    /// The SMI version code, e.g. `"V05497"`.
    pub code: String,
    /// The full designation, e.g. `"Classificação portuguesa das atividades económicas, revisão 4"`.
    pub designation: String,
    /// The short sigla, e.g. `"CAE Rev.4"` (may be empty for versions SMI leaves unsiglaed).
    pub sigla: String,
}

impl SmiVersion {
    /// The CAE revision this version denotes, if it is one of the two current CAE revisions
    /// (matched on the exact SMI sigla `"CAE Rev.3"` / `"CAE Rev.4"`). `None` for any other
    /// classification version (NACE, CN, older CAE revisions, …).
    pub fn revision(&self) -> Option<CaeRevision> {
        match self.sigla.as_str() {
            SMI_CAE_REV4_SIGLA => Some(CaeRevision::Rev4),
            SMI_CAE_REV3_SIGLA => Some(CaeRevision::Rev3),
            _ => None,
        }
    }
}

/// The parsed SMI version catalog — every classification version SMI lists, in file order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmiVersionCatalog {
    /// Every version row, in the order the export lists them.
    pub versions: Vec<SmiVersion>,
}

impl SmiVersionCatalog {
    /// The version row for a given CAE revision, if the catalog carries it.
    pub fn cae_version(&self, revision: CaeRevision) -> Option<&SmiVersion> {
        self.versions
            .iter()
            .find(|v| v.revision() == Some(revision))
    }

    /// The current official CAE Rev.3 and Rev.4 version rows, when both are present. This is the
    /// update signal: their codes/designations are the versions INE currently publishes.
    pub fn cae_versions(&self) -> Option<CaeVersions<'_>> {
        Some(CaeVersions {
            rev3: self.cae_version(CaeRevision::Rev3)?,
            rev4: self.cae_version(CaeRevision::Rev4)?,
        })
    }
}

/// The pair of current official CAE version rows extracted from an [`SmiVersionCatalog`].
#[derive(Clone, Copy, Debug)]
pub struct CaeVersions<'a> {
    /// The CAE-Rev.3 version row (`V00554`).
    pub rev3: &'a SmiVersion,
    /// The CAE-Rev.4 version row (`V05497`).
    pub rev4: &'a SmiVersion,
}

/// The INE SMI version-catalog source (plan t23 §1). Fetches and parses the classification-version
/// list SMI reliably serves; an **update-availability signal**, not a bulk catalog obtainer (the CAE
/// node tree is not non-interactively obtainable — see the module docs).
pub struct SmiSource {
    base_url: String,
    user_agent: String,
}

impl Default for SmiSource {
    fn default() -> Self {
        Self::official()
    }
}

impl SmiSource {
    /// A source pointed at the official INE SMI host.
    pub fn official() -> Self {
        Self {
            base_url: SMI_BASE_URL.to_owned(),
            user_agent: concat!("chancela-cae/", env!("CARGO_PKG_VERSION")).to_owned(),
        }
    }

    /// Override the base URL (a mirror or a local test server). Trailing slashes are trimmed.
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            user_agent: concat!("chancela-cae/", env!("CARGO_PKG_VERSION")).to_owned(),
        }
    }

    /// The full version-catalog export URL this source fetches.
    pub fn version_export_url(&self) -> String {
        format!("{}{}", self.base_url, SMI_VERSION_EXPORT_PATH)
    }

    /// Fetch the live SMI version catalog (a cold, cookieless, chunked GET) and parse it. A
    /// network/read failure is a [`CaeError::Http`]; an unparseable export is a [`CaeError::Parse`].
    ///
    /// Runs a short-lived blocking `reqwest` client built and dropped inside the call, so it is safe
    /// to run off a tokio runtime (like the existing mirror/DR fetches). Network-gated in tests.
    pub fn fetch_catalog(&self) -> Result<SmiVersionCatalog, CaeError> {
        let bytes = fetch_bytes(&self.version_export_url(), &self.user_agent)?;
        parse_smi_version_catalog(&bytes)
    }
}

/// Parse an SMI version-catalog CSV export into an [`SmiVersionCatalog`].
///
/// Handles the real INE artifact shape: **UTF-16LE with a BOM** (falling back to UTF-8/UTF-16BE), an
/// INE metadata + filter preamble, then a `Código,Designação,Sigla` column header, then one CSV data
/// row per version (the designation is double-quoted when it contains a comma). Rows are read up to
/// the three known columns; a row missing a code is skipped. An input with no recognisable header +
/// data is a [`CaeError::Parse`].
pub fn parse_smi_version_catalog(bytes: &[u8]) -> Result<SmiVersionCatalog, CaeError> {
    let text = decode_text(bytes);

    let mut versions = Vec::new();
    let mut seen_header = false;
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if !seen_header {
            // Skip the INE preamble/filter block until the column header row.
            if is_column_header(line) {
                seen_header = true;
            }
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_csv_line(line);
        let code = fields.first().map(|s| s.trim()).unwrap_or_default();
        // A version code is `V#####`; anything else on a data line is a stray/footer row.
        if !is_version_code(code) {
            continue;
        }
        versions.push(SmiVersion {
            code: code.to_owned(),
            designation: fields
                .get(1)
                .map(|s| s.trim().to_owned())
                .unwrap_or_default(),
            sigla: fields
                .get(2)
                .map(|s| s.trim().to_owned())
                .unwrap_or_default(),
        });
    }

    if !seen_header {
        return Err(CaeError::Parse(
            "SMI version catalog: no 'Código,Designação,Sigla' header row found (not an SMI version \
             export?)"
                .to_owned(),
        ));
    }
    if versions.is_empty() {
        return Err(CaeError::Parse(
            "SMI version catalog: header found but no version (V#####) rows".to_owned(),
        ));
    }
    Ok(SmiVersionCatalog { versions })
}

/// Decode raw export bytes to a `String`, honouring a UTF-16 BOM (LE or BE) and otherwise assuming
/// UTF-8. INE serves the CSV as UTF-16LE + BOM; UTF-8 is accepted for mirrors/robustness. Lossy so a
/// stray un-mappable unit never aborts a parse (the fidelity of the *values* is checked by callers).
fn decode_text(bytes: &[u8]) -> String {
    match bytes {
        [0xff, 0xfe, rest @ ..] => decode_utf16(rest, u16::from_le_bytes),
        [0xfe, 0xff, rest @ ..] => decode_utf16(rest, u16::from_be_bytes),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Decode UTF-16 code units (post-BOM) with the given endianness reader. A trailing odd byte (never
/// present in a well-formed export) is dropped.
fn decode_utf16(rest: &[u8], read: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = rest.chunks_exact(2).map(|c| read([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// Whether a line is the SMI data column header (`Código,Designação,Sigla`), tolerant of casing and
/// surrounding whitespace.
fn is_column_header(line: &str) -> bool {
    let normalized = line.trim().to_lowercase();
    normalized.starts_with("código,designação")
}

/// Whether a token is an SMI version code: `V` followed by digits (e.g. `V05497`).
fn is_version_code(token: &str) -> bool {
    let mut chars = token.chars();
    matches!(chars.next(), Some('V' | 'v')) && token.len() > 1 && chars.all(|c| c.is_ascii_digit())
}

/// Split one CSV line into fields, honouring double-quoted fields (which may contain commas) and
/// doubled-quote escapes (`""`). Minimal RFC-4180 single-line parse — enough for the SMI export's
/// three columns, no `csv` crate needed.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut field));
            }
            other => field.push(other),
        }
    }
    fields.push(field);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checked-in fixture is a trimmed real capture (UTF-16LE + BOM, CRLF, the INE preamble and
    /// column header, the five CAE-revision rows plus a CNP and a NACE row).
    const FIXTURE: &[u8] = include_bytes!("../../fixtures/smi_version_catalog.csv");

    #[test]
    fn fixture_is_utf16le_with_bom() {
        assert_eq!(
            &FIXTURE[..2],
            &[0xff, 0xfe],
            "fixture must be the real UTF-16LE+BOM shape"
        );
    }

    #[test]
    fn parses_the_utf16_fixture_and_extracts_the_cae_versions() {
        let catalog = parse_smi_version_catalog(FIXTURE).expect("fixture parses");
        // The preamble/filter block is skipped; every V-row is kept in file order.
        assert!(
            catalog.versions.len() >= 5,
            "kept the version rows: {:?}",
            catalog.versions
        );
        assert_eq!(catalog.versions[0].code, "V00001");

        let cae = catalog
            .cae_versions()
            .expect("both current CAE versions present");
        assert_eq!(cae.rev4.code, SMI_CAE_REV4_VERSION);
        assert_eq!(cae.rev4.sigla, "CAE Rev.4");
        assert_eq!(cae.rev4.revision(), Some(CaeRevision::Rev4));
        assert_eq!(
            cae.rev4.designation,
            "Classificação portuguesa das atividades económicas, revisão 4"
        );
        assert_eq!(cae.rev3.code, SMI_CAE_REV3_VERSION);
        assert_eq!(cae.rev3.revision(), Some(CaeRevision::Rev3));
    }

    #[test]
    fn only_the_two_current_cae_revisions_resolve_a_revision() {
        let catalog = parse_smi_version_catalog(FIXTURE).unwrap();
        // Older CAE revisions (Rev.1/Rev.2.1) and non-CAE families carry no CaeRevision.
        let older = catalog
            .versions
            .iter()
            .find(|v| v.code == "V00001")
            .unwrap();
        assert_eq!(older.sigla, "CAE Rev.2.1");
        assert_eq!(older.revision(), None);
        let nace = catalog.versions.iter().find(|v| v.sigla == "NACE Rev.2");
        assert!(nace.is_some() && nace.unwrap().revision().is_none());
    }

    #[test]
    fn parses_a_utf8_mirror_of_the_same_shape() {
        // A mirror may host the catalog as UTF-8; the decoder handles both.
        let utf8 = "Fonte: www.ine.pt\r\n\r\nCódigo,Designação,Sigla\r\n\
             V05497,\"Classificação portuguesa das atividades económicas, revisão 4\",CAE Rev.4\r\n\
             V00554,\"Classificação portuguesa das atividades económicas, revisão 3\",CAE Rev.3\r\n";
        let catalog = parse_smi_version_catalog(utf8.as_bytes()).expect("utf-8 parses");
        let cae = catalog.cae_versions().expect("both CAE versions");
        assert_eq!(cae.rev4.code, "V05497");
        assert_eq!(cae.rev3.code, "V00554");
    }

    #[test]
    fn quoted_designation_with_a_comma_is_one_field() {
        let fields = split_csv_line(r#"V05497,"Classificação portuguesa, revisão 4",CAE Rev.4"#);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[1], "Classificação portuguesa, revisão 4");
        assert_eq!(fields[2], "CAE Rev.4");
    }

    #[test]
    fn a_non_smi_document_is_a_parse_error() {
        // No column header at all.
        let err =
            parse_smi_version_catalog(b"just,some,csv\r\n1,2,3\r\n").expect_err("no SMI header");
        assert!(matches!(err, CaeError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn header_without_version_rows_is_a_parse_error() {
        let err = parse_smi_version_catalog("Código,Designação,Sigla\r\n\r\n".as_bytes())
            .expect_err("no data rows");
        assert!(matches!(err, CaeError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn version_export_url_composes_from_the_base() {
        assert_eq!(
            SmiSource::official().version_export_url(),
            "https://smi.ine.pt/Versao/Exportacao?tipo=2"
        );
        assert_eq!(
            SmiSource::with_base_url("http://localhost:9/").version_export_url(),
            "http://localhost:9/Versao/Exportacao?tipo=2"
        );
    }
}
