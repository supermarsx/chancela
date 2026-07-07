//! Artifact format + content-sniffing auto-detection (plan t23 §2.2).
//!
//! A fetched mirror artifact is turned into a [`CaeDataset`] by one of two JSON parsers, chosen by
//! sniffing the leading bytes (with an explicit [`CaeSourceFormat`] hint as an override):
//!
//! | Leading bytes | Format | Parser |
//! |---|---|---|
//! | `%PDF-…` | [`CaeSourceFormat::Pdf`] | **not a mirror format** — the Diário da República diploma pair is a two-artifact source obtained through the built-in official [`DrPdfSource`](super::DrPdfSource), never a single mirror URL, so this is a rejecting error on the mirror path |
//! | first non-space byte `{` | [`CaeSourceFormat::Envelope`] | [`CaeDataset::from_slice`] — today's `{schema_version, rev3, rev4, …}` envelope |
//! | first non-space byte `[` | [`CaeSourceFormat::SimpleJson`] | [`super::simple::parse_simple_json`] — the public flat `[{code, designation, revision, level?, parent?}]` mirror schema |
//! | anything else | — | a clear [`CaeError::Parse`] |
//!
//! **Ruling — why auto-detect distinguishes only Envelope vs SimpleJson.** A `%PDF` sniff *is*
//! recognised (so the error is specific), but the auto-detect/mirror path deliberately does not
//! parse a PDF: a complete catalog needs **both** revision diplomas plus per-artifact revision
//! disambiguation, which a single mirror URL cannot carry. The DR pair therefore stays the dedicated
//! [`DrPdfSource`](super::DrPdfSource) (both PDFs, digest-pinned), surfaced in a source chain as the
//! [`ChainEntry::Official`](super::chain::ChainEntry::Official) entry — not as a mirror URL.

use serde::{Deserialize, Serialize};

use crate::dataset::CaeDataset;
use crate::error::CaeError;

use super::simple;

/// The declared/expected format of a mirror artifact. `Auto` asks the parser to sniff the bytes;
/// the other variants pin the parser explicitly. Serializes as the bare variant name
/// (`"Auto"`/`"Envelope"`/`"SimpleJson"`/`"Pdf"`) for the settings contract (plan t23 §2.7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaeSourceFormat {
    /// Sniff the format from the leading bytes.
    #[default]
    Auto,
    /// The `CaeDataset` envelope JSON object.
    Envelope,
    /// The public flat `[{code, designation, revision, …}]` mirror array.
    SimpleJson,
    /// A Diário da República diploma PDF (not a mirror format — see the module ruling).
    Pdf,
}

/// Sniff the concrete format of raw artifact bytes, or `None` if the bytes are neither a PDF nor a
/// JSON object/array (leading whitespace is ignored). Never returns [`CaeSourceFormat::Auto`].
pub fn detect_format(bytes: &[u8]) -> Option<CaeSourceFormat> {
    if bytes.starts_with(b"%PDF") {
        return Some(CaeSourceFormat::Pdf);
    }
    // The first non-whitespace byte decides object (envelope) vs array (simple) JSON. JSON insignificant
    // whitespace is limited to space/tab/CR/LF, so this never misclassifies real content.
    let first = bytes
        .iter()
        .copied()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))?;
    match first {
        b'{' => Some(CaeSourceFormat::Envelope),
        b'[' => Some(CaeSourceFormat::SimpleJson),
        _ => None,
    }
}

/// Parse raw mirror-artifact bytes into a [`CaeDataset`], choosing the parser from `hint` (or by
/// sniffing when `hint` is [`CaeSourceFormat::Auto`]). The resulting dataset still has to clear the
/// structural-integrity and full-count fidelity gates before it may supersede anything — a wrong
/// derivation or a short array is rejected downstream, never trusted here.
///
/// A `Pdf` artifact (or `%PDF` sniff) is a rejecting [`CaeError::Parse`]: PDFs are obtained through
/// the two-diploma official [`DrPdfSource`](super::DrPdfSource), not this single-artifact mirror path.
pub fn parse_artifact(bytes: &[u8], hint: CaeSourceFormat) -> Result<CaeDataset, CaeError> {
    let format = match hint {
        CaeSourceFormat::Auto => detect_format(bytes).ok_or_else(|| {
            CaeError::Parse(
                "unrecognised CAE artifact: not a PDF, a JSON object (envelope), or a JSON array \
                 (simple mirror)"
                    .to_owned(),
            )
        })?,
        other => other,
    };
    match format {
        CaeSourceFormat::Envelope => CaeDataset::from_slice(bytes),
        CaeSourceFormat::SimpleJson => simple::parse_simple_json(bytes),
        CaeSourceFormat::Pdf => Err(CaeError::Parse(
            "PDF artifact is not a mirror format: the Diário da República diploma pair is obtained \
             via the built-in official source (both revision PDFs, digest-pinned), not a single \
             mirror URL"
                .to_owned(),
        )),
        // `Auto` was resolved to a concrete format above.
        CaeSourceFormat::Auto => unreachable!("Auto resolved to a concrete format"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_pdf() {
        assert_eq!(detect_format(b"%PDF-1.7\n..."), Some(CaeSourceFormat::Pdf));
    }

    #[test]
    fn sniffs_envelope_object() {
        assert_eq!(
            detect_format(b"  \n {\"schema_version\":1}"),
            Some(CaeSourceFormat::Envelope)
        );
    }

    #[test]
    fn sniffs_simple_array() {
        assert_eq!(
            detect_format(b"\n[{\"code\":\"A\"}]"),
            Some(CaeSourceFormat::SimpleJson)
        );
    }

    #[test]
    fn unrecognised_bytes_detect_none() {
        assert_eq!(detect_format(b"hello, not json"), None);
        assert_eq!(detect_format(b""), None);
    }

    #[test]
    fn auto_parse_rejects_garbage_with_clear_error() {
        let err = parse_artifact(b"not an artifact", CaeSourceFormat::Auto)
            .expect_err("garbage must not parse");
        assert!(matches!(err, CaeError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn pdf_on_the_mirror_path_is_rejected() {
        let err = parse_artifact(b"%PDF-1.7\n...", CaeSourceFormat::Auto)
            .expect_err("PDF is not a mirror");
        assert!(matches!(err, CaeError::Parse(_)), "got {err:?}");
    }
}
