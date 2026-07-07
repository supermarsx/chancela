//! Per-code **verifier** seam (plan t23 §2.6) — a spot-check enricher, **never a catalog builder**.
//!
//! A [`CaeVerifier`] confirms a single code's official designation against a live public source. It
//! deliberately cannot build the catalog: the reliable bulk path is the digest-pinned Diário da
//! República diploma pair, and the fidelity gate rejects any partial obtain, so a verifier is scoped
//! to one code per call.
//!
//! **SICONF status — seam + fixture parser only; live transport deferred (coordinator ruling).**
//! The user's candidate source, SICONF `PesquisaIntegradaCAE.aspx`, is a genuine, current (CAE-Rev.4)
//! official surface, but a postback-only ASP.NET WebForms `TreeView`: each node is reached by a
//! stateful `__doPostBack` carrying a growing `__VIEWSTATE`, with **no per-code GET and no export**.
//! The transport is therefore inferred, offline-untestable end-to-end, and a politeness risk against a
//! production consultation UI. This module ships the **response parser** — validated against a
//! checked-in fixture of a plausible TreeView node fragment (`fixtures/siconf_node.html`) — and
//! leaves the live client as a documented `todo`. A network-gated `#[ignore]` skeleton in
//! `tests/network.rs` marks the missing live capture. The multi-format bulk engine does not depend on
//! any of this.

use crate::error::CaeError;
use crate::model::CaeRevision;

/// The outcome of verifying one code against a live source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifierFinding {
    /// The source confirmed the code, with the official designation it returned.
    Found {
        code: String,
        designation: String,
        revision: CaeRevision,
    },
    /// The source responded but did not carry the requested code.
    NotFound,
}

/// Confirm a single code's official designation against a live public source. NEVER builds the
/// catalog — enrichment / spot-check only (plan t23 §2.6).
pub trait CaeVerifier: Send + Sync {
    /// Look up one code (in `revision`) against the source. A transport/read failure is a
    /// [`CaeError::Http`]; an unparseable response is a [`CaeError::Parse`].
    fn verify_code(&self, code: &str, revision: CaeRevision) -> Result<VerifierFinding, CaeError>;
}

/// A per-code verifier against SICONF `PesquisaIntegradaCAE.aspx`. Its **response parser** is
/// implemented and tested (against `fixtures/siconf_node.html`); the **live transport is deferred**
/// (postback-only WebForms viewstate — see the module docs), so [`verify_code`] returns a clear
/// [`CaeError::Config`] until a live client is built. It performs at most **one** lookup per call —
/// never a full-tree crawl.
pub struct SiconfVerifier {
    #[allow(dead_code)] // used by the deferred live transport (documented todo).
    base_url: String,
    #[allow(dead_code)]
    user_agent: String,
}

/// The default SICONF integrated-search endpoint (the user's candidate source).
pub const SICONF_BASE_URL: &str =
    "https://www2.gov.pt/RegistoOnline/Services/PesquisaIntegradaCAE.aspx";

impl SiconfVerifier {
    /// A verifier pointed at the default official SICONF endpoint.
    pub fn official() -> Self {
        Self {
            base_url: SICONF_BASE_URL.to_owned(),
            user_agent: concat!("chancela-cae/", env!("CARGO_PKG_VERSION")).to_owned(),
        }
    }

    /// Parse a SICONF TreeView response fragment for `code`, returning what the node carries. Shared
    /// by the fixture test and the (deferred) live transport, so it is exercised only by tests until
    /// the viewstate client lands — hence `dead_code`-allowed rather than removed.
    ///
    /// A SICONF node renders as an anchor whose visible text is `"<code> - <designation>"` (an ASCII
    /// hyphen or an en/em dash). This scans the anchor texts for the one that starts with `code` and
    /// returns its designation; if no node matches, [`VerifierFinding::NotFound`].
    #[allow(dead_code)] // used by the fixture test + the deferred live transport (documented todo).
    pub(crate) fn parse_node_fragment(
        html: &str,
        code: &str,
        revision: CaeRevision,
    ) -> Result<VerifierFinding, CaeError> {
        for text in anchor_texts(html) {
            let text = decode_entities(&text);
            let trimmed = text.trim();
            let Some(rest) = trimmed.strip_prefix(code) else {
                continue;
            };
            // The code must be followed by a separator, not be a prefix of a longer code (e.g. "68"
            // must not match "681 - …").
            let sep = rest.trim_start();
            let Some(designation) = sep
                .strip_prefix('-')
                .or_else(|| sep.strip_prefix('\u{2013}')) // en dash
                .or_else(|| sep.strip_prefix('\u{2014}'))
            // em dash
            else {
                continue;
            };
            let designation = designation.trim().to_owned();
            if designation.is_empty() {
                return Err(CaeError::Parse(format!(
                    "SICONF node for {code} carried an empty designation"
                )));
            }
            return Ok(VerifierFinding::Found {
                code: code.to_owned(),
                designation,
                revision,
            });
        }
        Ok(VerifierFinding::NotFound)
    }
}

impl CaeVerifier for SiconfVerifier {
    fn verify_code(
        &self,
        _code: &str,
        _revision: CaeRevision,
    ) -> Result<VerifierFinding, CaeError> {
        // Deferred: SICONF is a postback-only WebForms TreeView with no per-code GET. Building the
        // viewstate-postback client is a documented todo (see the module docs + tests/network.rs);
        // the response parser is ready in `parse_node_fragment`.
        Err(CaeError::Config(
            "o verificador SICONF ao vivo ainda não está implementado (transporte WebForms/viewstate \
             adiado); o parser de respostas está disponível para captura de rede"
                .to_owned(),
        ))
    }
}

/// Extract the visible text of every `<a …>text</a>` in an HTML fragment (a tiny, dependency-free
/// scan — enough for the flat anchor texts a SICONF TreeView node renders; not a general HTML parser).
#[allow(dead_code)] // reached via parse_node_fragment (tests + deferred live transport).
fn anchor_texts(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(open) = rest.find("<a") {
        rest = &rest[open..];
        let Some(gt) = rest.find('>') else { break };
        let after_open = &rest[gt + 1..];
        let Some(close) = after_open.find("</a>") else {
            break;
        };
        out.push(after_open[..close].trim().to_owned());
        rest = &after_open[close + "</a>".len()..];
    }
    out
}

/// Decode the handful of HTML entities SICONF emits in designations (`&amp;`, `&nbsp;`, quotes).
#[allow(dead_code)] // reached via parse_node_fragment (tests + deferred live transport).
fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&nbsp;", " ")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&aacute;", "á")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_transport_is_deferred_with_a_clear_error() {
        let err = SiconfVerifier::official()
            .verify_code("68", CaeRevision::Rev4)
            .expect_err("live transport is deferred");
        assert!(matches!(err, CaeError::Config(_)), "got {err:?}");
    }

    #[test]
    fn parser_extracts_a_designation_from_a_node_fragment() {
        let html = r#"<a href="javascript:__doPostBack('ctl00$phBody$treeView','t68')">68 - Atividades imobili&aacute;rias</a>"#;
        let finding =
            SiconfVerifier::parse_node_fragment(html, "68", CaeRevision::Rev4).expect("parses");
        assert_eq!(
            finding,
            VerifierFinding::Found {
                code: "68".to_owned(),
                designation: "Atividades imobiliárias".to_owned(),
                revision: CaeRevision::Rev4,
            }
        );
    }

    #[test]
    fn parser_does_not_match_a_longer_code_prefix() {
        // "68" must not match the "681 - …" node.
        let html = r##"<a href="#">681 - Compra, venda e arrendamento</a>"##;
        let finding =
            SiconfVerifier::parse_node_fragment(html, "68", CaeRevision::Rev4).expect("parses");
        assert_eq!(finding, VerifierFinding::NotFound);
    }

    /// Parse the checked-in SICONF TreeView fixture: the multi-node fragment resolves each code to its
    /// own designation (proving the parser selects the exact node, not a prefix), and an absent code
    /// is `NotFound`.
    #[test]
    fn parser_handles_the_checked_in_siconf_fixture() {
        let html = include_str!("../../fixtures/siconf_node.html");

        let div = SiconfVerifier::parse_node_fragment(html, "68", CaeRevision::Rev4).unwrap();
        assert_eq!(
            div,
            VerifierFinding::Found {
                code: "68".to_owned(),
                designation: "Atividades imobiliárias".to_owned(),
                revision: CaeRevision::Rev4,
            }
        );

        let sub = SiconfVerifier::parse_node_fragment(html, "68110", CaeRevision::Rev4).unwrap();
        assert!(
            matches!(&sub, VerifierFinding::Found { code, .. } if code == "68110"),
            "subclasse node resolves: {sub:?}"
        );

        let absent = SiconfVerifier::parse_node_fragment(html, "99999", CaeRevision::Rev4).unwrap();
        assert_eq!(absent, VerifierFinding::NotFound);
    }
}
