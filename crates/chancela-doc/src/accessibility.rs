//! Conservative accessibility facts for the deterministic PDF writer.
//!
//! This module is deliberately a report surface, not a certification claim. The writer currently
//! emits useful text-extraction primitives (document language/title metadata, embedded fonts and
//! `/ToUnicode` CMaps) plus a bounded tagged-PDF structure for the deterministic block set. That
//! structure is intentionally minimal and is not a full PDF/UA implementation, so
//! `pdf_ua_claimed` remains false.

use std::collections::BTreeSet;

use chancela_core::{Block, DocumentModel};

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

/// Explicit alternate-text/decorative-artifact coverage supplied alongside a document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AltTextModel {
    /// True when the caller asserts every non-text item is represented here as either alternate
    /// text or a decorative artifact.
    pub all_non_text_content_accounted_for: bool,
    /// Non-decorative non-text items and their human-readable alternatives.
    pub text_alternatives: Vec<TextAlternative>,
    /// Decorative or layout-only items that should not be exposed as reading content.
    pub decorative_artifacts: Vec<DecorativeArtifact>,
}

/// Alternate text for one non-decorative non-text item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextAlternative {
    /// Stable caller-defined target identifier.
    pub target: String,
    /// Human-readable alternate text.
    pub text: String,
}

impl TextAlternative {
    /// Build alternate text metadata for a caller-defined target.
    pub fn new(target: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            text: text.into(),
        }
    }
}

/// A decorative artifact entry for non-reading content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecorativeArtifact {
    /// Stable caller-defined target identifier.
    pub target: String,
}

impl DecorativeArtifact {
    /// Build decorative artifact metadata for a caller-defined target.
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
        }
    }

    /// Build decorative artifact metadata for a `DocumentModel.blocks` index.
    pub fn block(index: usize) -> Self {
        Self {
            target: block_target(index),
        }
    }
}

/// Accessibility report input. Plain `&DocumentModel` values are accepted and carry no
/// alternate-text/decorative metadata.
#[derive(Debug, Clone, Copy)]
pub struct AccessibilityInput<'a> {
    doc: &'a DocumentModel,
    alt_text_model: Option<&'a AltTextModel>,
}

impl<'a> AccessibilityInput<'a> {
    /// Start a report input from a document model.
    pub fn new(doc: &'a DocumentModel) -> Self {
        Self {
            doc,
            alt_text_model: None,
        }
    }

    /// Attach explicit alternate-text/decorative-artifact metadata.
    pub fn with_alt_text_model(mut self, alt_text_model: &'a AltTextModel) -> Self {
        self.alt_text_model = Some(alt_text_model);
        self
    }
}

impl<'a> From<&'a DocumentModel> for AccessibilityInput<'a> {
    fn from(doc: &'a DocumentModel) -> Self {
        Self::new(doc)
    }
}

/// Machine-checkable accessibility report for a document as emitted by this writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessibilityReport {
    /// Normalised metadata values that are emitted into the PDF.
    pub metadata: AccessibilityMetadata,
    /// The catalog carries `/Lang`.
    pub catalog_lang: bool,
    /// Catalog `/ViewerPreferences /DisplayDocTitle true` is emitted.
    pub display_doc_title: bool,
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
    /// Every page uses structure order for tab/annotation navigation (`/Tabs /S`).
    pub pages_use_structure_tab_order: bool,
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
    LimitedTaggedStructure,
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
            Self::LimitedTaggedStructure => "limited_tagged_structure",
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
            "{{\"version\":2,\
\"pdf_ua_claimed\":{pdf_ua_claimed},\
\"metadata\":{{\
\"title\":{{\"value\":{title},\"source_present\":{title_present},\"fallback_used\":{title_fallback}}},\
\"language\":{{\"value\":{language},\"source_present\":{language_present},\"fallback_used\":{language_fallback}}},\
\"catalog_lang\":{catalog_lang},\
\"display_doc_title\":{display_doc_title},\
\"xmp_title\":{xmp_title},\
\"xmp_language\":{xmp_language}\
}},\
\"text\":{{\"embedded_fonts\":{embedded_fonts},\"to_unicode_cmaps\":{to_unicode_cmaps}}},\
\"reading_order\":{{\
\"content_streams_follow_model_order\":{content_order},\
\"structure_tree_present\":{structure_tree},\
\"tagged_content_present\":{tagged_content},\
\"layout_artifacts_marked\":{artifacts_marked},\
\"pages_use_structure_tab_order\":{structure_tab_order}\
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
            display_doc_title = self.display_doc_title,
            xmp_title = self.xmp_title,
            xmp_language = self.xmp_language,
            embedded_fonts = self.embedded_fonts,
            to_unicode_cmaps = self.to_unicode_cmaps,
            content_order = self.content_streams_follow_model_order,
            structure_tree = self.structure_tree_present,
            tagged_content = self.tagged_content_present,
            artifacts_marked = self.layout_artifacts_marked,
            structure_tab_order = self.pages_use_structure_tab_order,
            alt_text = self.alt_text_model_present,
        )
    }
}

/// Build the report for the current writer implementation.
pub fn report<'a>(input: impl Into<AccessibilityInput<'a>>) -> AccessibilityReport {
    let input = input.into();
    let alt_text_model_present = input
        .alt_text_model
        .is_some_and(|model| has_meaningful_alt_text_model(input.doc, model));

    let mut blockers = Vec::new();
    if !alt_text_model_present {
        blockers.push(PdfUaBlocker::NoAltTextModel);
    }
    blockers.push(PdfUaBlocker::LimitedTaggedStructure);

    AccessibilityReport {
        metadata: metadata(input.doc),
        catalog_lang: true,
        display_doc_title: true,
        xmp_title: true,
        xmp_language: true,
        embedded_fonts: true,
        to_unicode_cmaps: true,
        content_streams_follow_model_order: true,
        structure_tree_present: true,
        tagged_content_present: true,
        layout_artifacts_marked: true,
        pages_use_structure_tab_order: true,
        alt_text_model_present,
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

fn has_meaningful_alt_text_model(doc: &DocumentModel, model: &AltTextModel) -> bool {
    if !model.all_non_text_content_accounted_for {
        return false;
    }
    if model
        .text_alternatives
        .iter()
        .any(|alt| alt.target.trim().is_empty() || alt.text.trim().is_empty())
    {
        return false;
    }
    if model
        .decorative_artifacts
        .iter()
        .any(|artifact| artifact.target.trim().is_empty())
    {
        return false;
    }

    let decorative_targets = model
        .decorative_artifacts
        .iter()
        .map(|artifact| artifact.target.trim())
        .collect::<BTreeSet<_>>();
    doc.blocks.iter().enumerate().all(|(index, block)| {
        !is_known_decorative_block(block)
            || decorative_targets.contains(block_target(index).as_str())
    })
}

fn is_known_decorative_block(block: &Block) -> bool {
    matches!(block, Block::PageBreak | Block::Rule)
}

fn block_target(index: usize) -> String {
    format!("block:{index}")
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
