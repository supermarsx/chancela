//! Conservative accessibility facts for the deterministic PDF writer.
//!
//! This module is deliberately a report surface, not a certification claim. The writer currently
//! emits useful text-extraction primitives (document language/title metadata, embedded fonts and
//! `/ToUnicode` CMaps) but it does not emit a PDF structure tree, tagged content, role maps, or
//! alternate text. Those missing pieces are material PDF/UA blockers, so `pdf_ua_claimed` remains
//! false until the writer genuinely produces tagged PDF.

use chancela_core::DocumentModel;

/// Deterministic title used only when the source model carries no usable title.
pub const FALLBACK_TITLE: &str = "Untitled Chancela document";
/// BCP-47 "undetermined" language tag used when the source tag is blank or implausible.
pub const FALLBACK_LANGUAGE: &str = "und";

/// A metadata value after deterministic normalisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataValue {
    /// The value the writer will emit in XMP/catalog metadata.
    pub value: String,
    /// Whether the source model supplied a non-blank value.
    pub source_present: bool,
    /// Whether the writer substituted a deterministic fallback.
    pub fallback_used: bool,
}

/// Accessibility-relevant metadata emitted by this writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessibilityMetadata {
    /// XMP `dc:title` value after fallback.
    pub title: MetadataValue,
    /// Catalog `/Lang` and XMP `dc:language` value after fallback/validation.
    pub language: MetadataValue,
}

/// Machine-checkable accessibility report for a document as emitted by this writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessibilityReport {
    /// Normalised metadata values that are emitted into the PDF.
    pub metadata: AccessibilityMetadata,
    /// The catalog carries `/Lang`.
    pub catalog_lang: bool,
    /// XMP carries `dc:title`.
    pub xmp_title: bool,
    /// XMP carries `dc:language`.
    pub xmp_language: bool,
    /// All text fonts are embedded.
    pub embedded_fonts: bool,
    /// Text fonts carry `/ToUnicode` CMaps.
    pub to_unicode_cmaps: bool,
    /// Content streams are emitted in `DocumentModel.blocks` order.
    pub content_streams_follow_model_order: bool,
    /// Whether the PDF catalog has a real structure tree.
    pub structure_tree_present: bool,
    /// Whether text is emitted as tagged marked content.
    pub tagged_content_present: bool,
    /// Whether visual layout artifacts are marked as artifacts.
    pub layout_artifacts_marked: bool,
    /// Whether the model/writer has an alternate-text surface for non-text content.
    pub alt_text_model_present: bool,
    /// True only when the writer has enough tagged-PDF machinery to claim PDF/UA.
    pub pdf_ua_claimed: bool,
    /// Ordered blockers preventing a PDF/UA claim.
    pub pdf_ua_blockers: Vec<PdfUaBlocker>,
}

/// Stable machine codes for missing PDF/UA prerequisites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfUaBlocker {
    MissingStructTreeRoot,
    ContentIsNotTagged,
    MissingRoleMap,
    NoAltTextModel,
    LayoutArtifactsNotMarked,
}

impl PdfUaBlocker {
    /// Stable code used in the deterministic JSON report.
    pub fn code(self) -> &'static str {
        match self {
            Self::MissingStructTreeRoot => "missing_struct_tree_root",
            Self::ContentIsNotTagged => "content_is_not_tagged",
            Self::MissingRoleMap => "missing_role_map",
            Self::NoAltTextModel => "no_alt_text_model",
            Self::LayoutArtifactsNotMarked => "layout_artifacts_not_marked",
        }
    }
}

impl AccessibilityReport {
    /// Render a deterministic, dependency-free JSON object for machines and snapshots.
    pub fn to_json(&self) -> String {
        let blockers = self
            .pdf_ua_blockers
            .iter()
            .map(|b| json_string(b.code()))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "{{\"version\":1,\
\"pdf_ua_claimed\":{pdf_ua_claimed},\
\"metadata\":{{\
\"title\":{{\"value\":{title},\"source_present\":{title_present},\"fallback_used\":{title_fallback}}},\
\"language\":{{\"value\":{language},\"source_present\":{language_present},\"fallback_used\":{language_fallback}}},\
\"catalog_lang\":{catalog_lang},\
\"xmp_title\":{xmp_title},\
\"xmp_language\":{xmp_language}\
}},\
\"text\":{{\"embedded_fonts\":{embedded_fonts},\"to_unicode_cmaps\":{to_unicode_cmaps}}},\
\"reading_order\":{{\
\"content_streams_follow_model_order\":{content_order},\
\"structure_tree_present\":{structure_tree},\
\"tagged_content_present\":{tagged_content},\
\"layout_artifacts_marked\":{artifacts_marked}\
}},\
\"alt_text_model_present\":{alt_text},\
\"pdf_ua_blockers\":[{blockers}]\
}}",
            pdf_ua_claimed = self.pdf_ua_claimed,
            title = json_string(&self.metadata.title.value),
            title_present = self.metadata.title.source_present,
            title_fallback = self.metadata.title.fallback_used,
            language = json_string(&self.metadata.language.value),
            language_present = self.metadata.language.source_present,
            language_fallback = self.metadata.language.fallback_used,
            catalog_lang = self.catalog_lang,
            xmp_title = self.xmp_title,
            xmp_language = self.xmp_language,
            embedded_fonts = self.embedded_fonts,
            to_unicode_cmaps = self.to_unicode_cmaps,
            content_order = self.content_streams_follow_model_order,
            structure_tree = self.structure_tree_present,
            tagged_content = self.tagged_content_present,
            artifacts_marked = self.layout_artifacts_marked,
            alt_text = self.alt_text_model_present,
        )
    }
}

/// Build the report for `doc` under the current writer implementation.
pub fn report(doc: &DocumentModel) -> AccessibilityReport {
    let blockers = vec![
        PdfUaBlocker::MissingStructTreeRoot,
        PdfUaBlocker::ContentIsNotTagged,
        PdfUaBlocker::MissingRoleMap,
        PdfUaBlocker::NoAltTextModel,
        PdfUaBlocker::LayoutArtifactsNotMarked,
    ];

    AccessibilityReport {
        metadata: metadata(doc),
        catalog_lang: true,
        xmp_title: true,
        xmp_language: true,
        embedded_fonts: true,
        to_unicode_cmaps: true,
        content_streams_follow_model_order: true,
        structure_tree_present: false,
        tagged_content_present: false,
        layout_artifacts_marked: false,
        alt_text_model_present: false,
        pdf_ua_claimed: blockers.is_empty(),
        pdf_ua_blockers: blockers,
    }
}

/// Normalise document metadata exactly as the writer emits it.
pub fn metadata(doc: &DocumentModel) -> AccessibilityMetadata {
    AccessibilityMetadata {
        title: metadata_title(&doc.title),
        language: metadata_language(&doc.language),
    }
}

fn metadata_title(raw: &str) -> MetadataValue {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        MetadataValue {
            value: FALLBACK_TITLE.to_string(),
            source_present: false,
            fallback_used: true,
        }
    } else {
        MetadataValue {
            value: trimmed.to_string(),
            source_present: true,
            fallback_used: false,
        }
    }
}

fn metadata_language(raw: &str) -> MetadataValue {
    let trimmed = raw.trim();
    if is_plausible_bcp47(trimmed) {
        MetadataValue {
            value: trimmed.to_string(),
            source_present: true,
            fallback_used: false,
        }
    } else {
        MetadataValue {
            value: FALLBACK_LANGUAGE.to_string(),
            source_present: !trimmed.is_empty(),
            fallback_used: true,
        }
    }
}

fn is_plausible_bcp47(s: &str) -> bool {
    !s.is_empty()
        && s.split('-').all(|part| {
            !part.is_empty() && part.len() <= 8 && part.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\u{20}' => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
