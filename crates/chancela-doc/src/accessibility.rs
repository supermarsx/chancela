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
    /// Inter-word gaps are emitted as real U+0020 text glyphs, not only positioning offsets.
    pub inter_word_spaces_emitted: bool,
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
    /// Local heading hierarchy facts observed from the source model.
    pub heading_hierarchy: HeadingHierarchyReport,
    /// Local role-map coverage for custom structure roles this writer can emit.
    pub role_map: RoleMapCoverageReport,
    /// Local table/vote-table structure facts.
    pub table_semantics: TableSemanticsReport,
    /// Local decorative-layout artifact marking facts.
    pub artifact_marking: ArtifactMarkingReport,
    /// Explicit non-text alternate/decorative accounting supplied by the caller.
    pub non_text_content: NonTextContentReport,
    /// Whether the model/writer has an alternate-text surface for non-text content.
    pub alt_text_model_present: bool,
    /// True only when the writer has enough tagged-PDF machinery to claim PDF/UA.
    pub pdf_ua_claimed: bool,
    /// Ordered blockers preventing a PDF/UA claim.
    pub pdf_ua_blockers: Vec<PdfUaBlocker>,
}

/// Local facts about heading levels this writer can tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadingHierarchyReport {
    /// The document title is emitted as a tagged H1 when source title text exists.
    pub document_title_tagged_as_h1: bool,
    /// Count of non-empty body heading blocks.
    pub heading_count: usize,
    /// Highest body heading level observed, or 0 when there are no body headings.
    pub max_observed_level: u8,
    /// Body headings do not jump by more than one level after the document-title H1.
    pub no_skipped_levels: bool,
    /// Heading levels outside the writer's explicit H1-H3 role set.
    pub unsupported_levels: Vec<u8>,
}

/// Local coverage of custom structure roles by the writer's `/RoleMap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleMapCoverageReport {
    /// The writer emits a `/StructTreeRoot /RoleMap` dictionary.
    pub present: bool,
    /// Custom roles required by this document, in writer role-map order.
    pub required_custom_roles: Vec<String>,
    /// Required custom roles not covered by the writer role map.
    pub missing_custom_roles: Vec<String>,
    /// Every mapped target is a standard structure role.
    pub standard_targets_only: bool,
    /// Required custom roles are mapped to standard structure roles.
    pub complete: bool,
}

/// Local facts about table-like blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSemanticsReport {
    /// Count of key/value table blocks in the model.
    pub key_value_table_count: usize,
    /// Count of vote table blocks in the model.
    pub vote_table_count: usize,
    /// Key/value tables are emitted with standard table roles.
    pub key_value_tables_have_table_semantics: bool,
    /// Vote tables are emitted with standard table roles.
    pub vote_tables_have_table_semantics: bool,
    /// Vote table header cells are explicitly tagged as headers.
    pub vote_table_headers_tagged: bool,
    /// All table-like blocks have the local semantics this report tracks.
    pub complete: bool,
}

/// Local facts about layout-only drawing being marked as PDF artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMarkingReport {
    /// Every known layout-only drawing operation is scoped as `/Artifact`.
    pub layout_artifacts_marked: bool,
    /// Total known artifact drawing operations for this model.
    pub known_layout_artifact_count: usize,
    /// The fixed header separator rule.
    pub header_rule_artifact_count: usize,
    /// Horizontal rule blocks.
    pub horizontal_rule_artifact_count: usize,
    /// Vote-table divider rules.
    pub vote_table_rule_artifact_count: usize,
    /// Signature blank-line rules.
    pub signature_line_artifact_count: usize,
}

/// Local facts about non-text alternate text and decorative accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonTextContentReport {
    /// The caller supplied an alternate/decorative model.
    pub model_supplied: bool,
    /// The supplied model claims complete coverage of non-text content.
    pub all_non_text_content_accounted_for: bool,
    /// Number of non-decorative alternate text entries supplied.
    pub text_alternative_count: usize,
    /// Number of decorative artifact entries supplied.
    pub decorative_artifact_count: usize,
    /// Count of model blocks this writer treats as known decorative content.
    pub known_decorative_block_count: usize,
    /// Known decorative block targets absent from the supplied decorative entries.
    pub missing_decorative_artifacts: Vec<String>,
    /// Alternate text entries with blank target or text.
    pub invalid_text_alternative_count: usize,
    /// Decorative entries with blank targets.
    pub invalid_decorative_artifact_count: usize,
    /// The supplied accounting is complete for local known non-text content.
    pub complete: bool,
}

/// Stable machine codes for missing PDF/UA prerequisites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfUaBlocker {
    MissingStructTreeRoot,
    ContentIsNotTagged,
    MissingRoleMap,
    RoleMapIncomplete,
    HeadingHierarchySkipsLevels,
    UnsupportedHeadingLevel,
    KeyValueTablesNotTaggedAsTables,
    VoteTablesNotTaggedAsTables,
    VoteTableHeadersNotTagged,
    NoAltTextModel,
    NonTextContentNotAccountedFor,
    LayoutArtifactsNotMarked,
    /// Historical umbrella blocker retained for callers that matched on it. New reports use the
    /// local blocker codes above instead.
    LimitedTaggedStructure,
}

impl PdfUaBlocker {
    /// Stable code used in the deterministic JSON report.
    pub fn code(self) -> &'static str {
        match self {
            Self::MissingStructTreeRoot => "missing_struct_tree_root",
            Self::ContentIsNotTagged => "content_is_not_tagged",
            Self::MissingRoleMap => "missing_role_map",
            Self::RoleMapIncomplete => "role_map_incomplete",
            Self::HeadingHierarchySkipsLevels => "heading_hierarchy_skips_levels",
            Self::UnsupportedHeadingLevel => "unsupported_heading_level",
            Self::KeyValueTablesNotTaggedAsTables => "key_value_tables_not_tagged_as_tables",
            Self::VoteTablesNotTaggedAsTables => "vote_tables_not_tagged_as_tables",
            Self::VoteTableHeadersNotTagged => "vote_table_headers_not_tagged",
            Self::NoAltTextModel => "no_alt_text_model",
            Self::NonTextContentNotAccountedFor => "non_text_content_not_accounted_for",
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
            "{{\"version\":4,\
\"pdf_ua_claimed\":{pdf_ua_claimed},\
\"metadata\":{{\
\"title\":{{\"value\":{title},\"source_present\":{title_present},\"fallback_used\":{title_fallback}}},\
\"language\":{{\"value\":{language},\"source_present\":{language_present},\"fallback_used\":{language_fallback}}},\
\"catalog_lang\":{catalog_lang},\
\"display_doc_title\":{display_doc_title},\
\"xmp_title\":{xmp_title},\
\"xmp_language\":{xmp_language}\
}},\
\"text\":{{\"embedded_fonts\":{embedded_fonts},\"to_unicode_cmaps\":{to_unicode_cmaps},\"inter_word_spaces_emitted\":{spaces_emitted}}},\
\"reading_order\":{{\
\"content_streams_follow_model_order\":{content_order},\
\"structure_tree_present\":{structure_tree},\
\"tagged_content_present\":{tagged_content},\
\"layout_artifacts_marked\":{artifacts_marked},\
\"pages_use_structure_tab_order\":{structure_tab_order}\
}},\
\"tagged_structure\":{{\
\"heading_hierarchy\":{{\"document_title_tagged_as_h1\":{title_h1},\"heading_count\":{heading_count},\"max_observed_level\":{max_heading},\"no_skipped_levels\":{no_skipped_headings},\"unsupported_levels\":[{unsupported_headings}]}},\
\"role_map\":{{\"present\":{role_map_present},\"required_custom_roles\":[{required_roles}],\"missing_custom_roles\":[{missing_roles}],\"standard_targets_only\":{standard_role_targets},\"complete\":{role_map_complete}}},\
\"tables\":{{\"key_value_table_count\":{kv_table_count},\"vote_table_count\":{vote_table_count},\"key_value_tables_have_table_semantics\":{kv_tables_semantic},\"vote_tables_have_table_semantics\":{vote_tables_semantic},\"vote_table_headers_tagged\":{vote_headers_tagged},\"complete\":{table_semantics_complete}}},\
\"artifact_marking\":{{\"layout_artifacts_marked\":{artifact_layout_marked},\"known_layout_artifact_count\":{artifact_count},\"header_rule_artifact_count\":{header_artifacts},\"horizontal_rule_artifact_count\":{rule_artifacts},\"vote_table_rule_artifact_count\":{vote_rule_artifacts},\"signature_line_artifact_count\":{signature_artifacts}}}\
}},\
\"non_text_content\":{{\"model_supplied\":{non_text_model_supplied},\"all_non_text_content_accounted_for\":{non_text_all_accounted},\"text_alternative_count\":{text_alt_count},\"decorative_artifact_count\":{decorative_count},\"known_decorative_block_count\":{known_decorative_count},\"missing_decorative_artifacts\":[{missing_decorative}],\"invalid_text_alternative_count\":{invalid_text_alts},\"invalid_decorative_artifact_count\":{invalid_decorative},\"complete\":{non_text_complete}}},\
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
            spaces_emitted = self.inter_word_spaces_emitted,
            content_order = self.content_streams_follow_model_order,
            structure_tree = self.structure_tree_present,
            tagged_content = self.tagged_content_present,
            artifacts_marked = self.layout_artifacts_marked,
            structure_tab_order = self.pages_use_structure_tab_order,
            title_h1 = self.heading_hierarchy.document_title_tagged_as_h1,
            heading_count = self.heading_hierarchy.heading_count,
            max_heading = self.heading_hierarchy.max_observed_level,
            no_skipped_headings = self.heading_hierarchy.no_skipped_levels,
            unsupported_headings = json_u8_array(&self.heading_hierarchy.unsupported_levels),
            role_map_present = self.role_map.present,
            required_roles = json_string_array(&self.role_map.required_custom_roles),
            missing_roles = json_string_array(&self.role_map.missing_custom_roles),
            standard_role_targets = self.role_map.standard_targets_only,
            role_map_complete = self.role_map.complete,
            kv_table_count = self.table_semantics.key_value_table_count,
            vote_table_count = self.table_semantics.vote_table_count,
            kv_tables_semantic = self.table_semantics.key_value_tables_have_table_semantics,
            vote_tables_semantic = self.table_semantics.vote_tables_have_table_semantics,
            vote_headers_tagged = self.table_semantics.vote_table_headers_tagged,
            table_semantics_complete = self.table_semantics.complete,
            artifact_layout_marked = self.artifact_marking.layout_artifacts_marked,
            artifact_count = self.artifact_marking.known_layout_artifact_count,
            header_artifacts = self.artifact_marking.header_rule_artifact_count,
            rule_artifacts = self.artifact_marking.horizontal_rule_artifact_count,
            vote_rule_artifacts = self.artifact_marking.vote_table_rule_artifact_count,
            signature_artifacts = self.artifact_marking.signature_line_artifact_count,
            non_text_model_supplied = self.non_text_content.model_supplied,
            non_text_all_accounted = self.non_text_content.all_non_text_content_accounted_for,
            text_alt_count = self.non_text_content.text_alternative_count,
            decorative_count = self.non_text_content.decorative_artifact_count,
            known_decorative_count = self.non_text_content.known_decorative_block_count,
            missing_decorative =
                json_string_array(&self.non_text_content.missing_decorative_artifacts),
            invalid_text_alts = self.non_text_content.invalid_text_alternative_count,
            invalid_decorative = self.non_text_content.invalid_decorative_artifact_count,
            non_text_complete = self.non_text_content.complete,
            alt_text = self.alt_text_model_present,
        )
    }
}

/// Build the report for the current writer implementation.
pub fn report<'a>(input: impl Into<AccessibilityInput<'a>>) -> AccessibilityReport {
    let input = input.into();
    let heading_hierarchy = heading_hierarchy(input.doc);
    let role_map = role_map_coverage(input.doc);
    let table_semantics = table_semantics(input.doc);
    let artifact_marking = artifact_marking(input.doc);
    let non_text_content = non_text_content(input.doc, input.alt_text_model);
    let alt_text_model_present = non_text_content.complete;

    let mut blockers = Vec::new();
    if !heading_hierarchy.no_skipped_levels {
        blockers.push(PdfUaBlocker::HeadingHierarchySkipsLevels);
    }
    if !heading_hierarchy.unsupported_levels.is_empty() {
        blockers.push(PdfUaBlocker::UnsupportedHeadingLevel);
    }
    if !role_map.present {
        blockers.push(PdfUaBlocker::MissingRoleMap);
    } else if !role_map.complete {
        blockers.push(PdfUaBlocker::RoleMapIncomplete);
    }
    if !table_semantics.key_value_tables_have_table_semantics {
        blockers.push(PdfUaBlocker::KeyValueTablesNotTaggedAsTables);
    }
    if !table_semantics.vote_tables_have_table_semantics {
        blockers.push(PdfUaBlocker::VoteTablesNotTaggedAsTables);
    }
    if !table_semantics.vote_table_headers_tagged {
        blockers.push(PdfUaBlocker::VoteTableHeadersNotTagged);
    }
    if !artifact_marking.layout_artifacts_marked {
        blockers.push(PdfUaBlocker::LayoutArtifactsNotMarked);
    }
    if !non_text_content.complete && non_text_content.known_decorative_block_count > 0 {
        if non_text_content.model_supplied {
            blockers.push(PdfUaBlocker::NonTextContentNotAccountedFor);
        } else {
            blockers.push(PdfUaBlocker::NoAltTextModel);
        }
    }

    AccessibilityReport {
        metadata: metadata(input.doc),
        catalog_lang: true,
        display_doc_title: true,
        xmp_title: true,
        xmp_language: true,
        embedded_fonts: true,
        to_unicode_cmaps: true,
        inter_word_spaces_emitted: true,
        content_streams_follow_model_order: true,
        structure_tree_present: true,
        tagged_content_present: true,
        layout_artifacts_marked: true,
        pages_use_structure_tab_order: true,
        heading_hierarchy,
        role_map,
        table_semantics,
        artifact_marking,
        non_text_content,
        alt_text_model_present,
        pdf_ua_claimed: false,
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

fn has_words(s: &str) -> bool {
    s.split_whitespace().next().is_some()
}

fn heading_hierarchy(doc: &DocumentModel) -> HeadingHierarchyReport {
    let mut heading_count = 0usize;
    let mut max_observed_level = 0u8;
    let mut no_skipped_levels = true;
    let mut unsupported_levels = BTreeSet::new();
    let mut previous_level = 1u8;

    for block in &doc.blocks {
        let Block::Heading { level, text } = block else {
            continue;
        };
        if !has_words(text) {
            continue;
        }
        heading_count += 1;
        max_observed_level = max_observed_level.max(*level);
        if !(1..=3).contains(level) {
            unsupported_levels.insert(*level);
        }
        if *level > previous_level.saturating_add(1) {
            no_skipped_levels = false;
        }
        previous_level = *level;
    }

    HeadingHierarchyReport {
        document_title_tagged_as_h1: has_words(&doc.title),
        heading_count,
        max_observed_level,
        no_skipped_levels,
        unsupported_levels: unsupported_levels.into_iter().collect(),
    }
}

const ROLE_MAP_ENTRIES: &[(&str, &str)] = &[
    ("ChancelaDocument", "Document"),
    ("ChancelaDocumentTitle", "H1"),
    ("ChancelaHeaderMetadata", "P"),
    ("ChancelaHeading1", "H1"),
    ("ChancelaHeading2", "H2"),
    ("ChancelaHeading3", "H3"),
    ("ChancelaHeading", "H"),
    ("ChancelaParagraph", "P"),
    ("ChancelaKeyValue", "Div"),
    ("ChancelaVoteTable", "Div"),
    ("ChancelaSignatureBlock", "Div"),
];

pub(crate) fn role_map_entries() -> &'static [(&'static str, &'static str)] {
    ROLE_MAP_ENTRIES
}

fn role_map_coverage(doc: &DocumentModel) -> RoleMapCoverageReport {
    let required_custom_roles = required_custom_roles(doc);
    let missing_custom_roles = required_custom_roles
        .iter()
        .filter(|role| role_map_target(role).is_none())
        .cloned()
        .collect::<Vec<_>>();
    let standard_targets_only = ROLE_MAP_ENTRIES
        .iter()
        .all(|(_, target)| is_standard_structure_target(target));
    let complete = missing_custom_roles.is_empty() && standard_targets_only;

    RoleMapCoverageReport {
        present: true,
        required_custom_roles,
        missing_custom_roles,
        standard_targets_only,
        complete,
    }
}

fn is_standard_structure_target(role: &str) -> bool {
    matches!(role, "Document" | "Div" | "P" | "H" | "H1" | "H2" | "H3")
}

fn required_custom_roles(doc: &DocumentModel) -> Vec<String> {
    let mut needed = BTreeSet::new();
    needed.insert("ChancelaDocument");
    if has_words(&doc.title) {
        needed.insert("ChancelaDocumentTitle");
    }
    if has_words(&doc.entity_name)
        || doc.entity_nipc.as_deref().is_some_and(has_words)
        || has_words(&doc.subject)
    {
        needed.insert("ChancelaHeaderMetadata");
    }
    for block in &doc.blocks {
        match block {
            Block::Heading { level, text } if has_words(text) => {
                needed.insert(heading_custom_role(*level));
            }
            Block::Paragraph { runs } if runs.iter().any(|run| has_words(&run.text)) => {
                needed.insert("ChancelaParagraph");
            }
            Block::KeyValue { rows }
                if rows
                    .iter()
                    .any(|row| has_words(&row.key) || has_words(&row.value)) =>
            {
                needed.insert("ChancelaKeyValue");
            }
            Block::VoteTable { .. } => {
                needed.insert("ChancelaVoteTable");
            }
            Block::SignatureBlock { slots }
                if slots
                    .iter()
                    .any(|slot| has_words(&slot.role) || has_words(&slot.name)) =>
            {
                needed.insert("ChancelaSignatureBlock");
            }
            _ => {}
        }
    }

    ROLE_MAP_ENTRIES
        .iter()
        .filter(|(role, _)| needed.contains(role))
        .map(|(role, _)| (*role).to_string())
        .collect()
}

fn heading_custom_role(level: u8) -> &'static str {
    match level {
        1 => "ChancelaHeading1",
        2 => "ChancelaHeading2",
        3 => "ChancelaHeading3",
        _ => "ChancelaHeading",
    }
}

fn role_map_target(role: &str) -> Option<&'static str> {
    ROLE_MAP_ENTRIES
        .iter()
        .find(|(custom, _)| *custom == role)
        .map(|(_, target)| *target)
}

fn table_semantics(doc: &DocumentModel) -> TableSemanticsReport {
    let key_value_table_count = doc
        .blocks
        .iter()
        .filter(|block| matches!(block, Block::KeyValue { .. }))
        .count();
    let vote_table_count = doc
        .blocks
        .iter()
        .filter(|block| matches!(block, Block::VoteTable { .. }))
        .count();
    let key_value_tables_have_table_semantics = key_value_table_count == 0;
    let vote_tables_have_table_semantics = vote_table_count == 0;
    let vote_table_headers_tagged = vote_table_count == 0;
    let complete = key_value_tables_have_table_semantics
        && vote_tables_have_table_semantics
        && vote_table_headers_tagged;

    TableSemanticsReport {
        key_value_table_count,
        vote_table_count,
        key_value_tables_have_table_semantics,
        vote_tables_have_table_semantics,
        vote_table_headers_tagged,
        complete,
    }
}

fn artifact_marking(doc: &DocumentModel) -> ArtifactMarkingReport {
    let horizontal_rule_artifact_count = doc
        .blocks
        .iter()
        .filter(|block| matches!(block, Block::Rule))
        .count();
    let vote_table_rule_artifact_count = doc
        .blocks
        .iter()
        .filter(|block| matches!(block, Block::VoteTable { .. }))
        .count()
        * 2;
    let signature_line_artifact_count = doc
        .blocks
        .iter()
        .map(|block| match block {
            Block::SignatureBlock { slots } => slots.len(),
            _ => 0,
        })
        .sum::<usize>();
    let header_rule_artifact_count = 1;
    let known_layout_artifact_count = header_rule_artifact_count
        + horizontal_rule_artifact_count
        + vote_table_rule_artifact_count
        + signature_line_artifact_count;

    ArtifactMarkingReport {
        layout_artifacts_marked: true,
        known_layout_artifact_count,
        header_rule_artifact_count,
        horizontal_rule_artifact_count,
        vote_table_rule_artifact_count,
        signature_line_artifact_count,
    }
}

fn non_text_content(doc: &DocumentModel, model: Option<&AltTextModel>) -> NonTextContentReport {
    let known_decorative_targets = known_decorative_targets(doc);
    let known_decorative_block_count = known_decorative_targets.len();
    let Some(model) = model else {
        return NonTextContentReport {
            model_supplied: false,
            all_non_text_content_accounted_for: false,
            text_alternative_count: 0,
            decorative_artifact_count: 0,
            known_decorative_block_count,
            missing_decorative_artifacts: known_decorative_targets,
            invalid_text_alternative_count: 0,
            invalid_decorative_artifact_count: 0,
            complete: false,
        };
    };

    let invalid_text_alternative_count = model
        .text_alternatives
        .iter()
        .filter(|alt| alt.target.trim().is_empty() || alt.text.trim().is_empty())
        .count();
    let invalid_decorative_artifact_count = model
        .decorative_artifacts
        .iter()
        .filter(|artifact| artifact.target.trim().is_empty())
        .count();
    let decorative_targets = model
        .decorative_artifacts
        .iter()
        .map(|artifact| artifact.target.trim())
        .collect::<BTreeSet<_>>();
    let missing_decorative_artifacts = known_decorative_targets
        .into_iter()
        .filter(|target| !decorative_targets.contains(target.as_str()))
        .collect::<Vec<_>>();
    let complete = model.all_non_text_content_accounted_for
        && invalid_text_alternative_count == 0
        && invalid_decorative_artifact_count == 0
        && missing_decorative_artifacts.is_empty();

    NonTextContentReport {
        model_supplied: true,
        all_non_text_content_accounted_for: model.all_non_text_content_accounted_for,
        text_alternative_count: model.text_alternatives.len(),
        decorative_artifact_count: model.decorative_artifacts.len(),
        known_decorative_block_count,
        missing_decorative_artifacts,
        invalid_text_alternative_count,
        invalid_decorative_artifact_count,
        complete,
    }
}

fn known_decorative_targets(doc: &DocumentModel) -> Vec<String> {
    doc.blocks
        .iter()
        .enumerate()
        .filter(|(_, block)| is_known_decorative_block(block))
        .map(|(index, _)| block_target(index))
        .collect()
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

fn json_string_array(strings: &[String]) -> String {
    strings
        .iter()
        .map(|s| json_string(s))
        .collect::<Vec<_>>()
        .join(",")
}

fn json_u8_array(values: &[u8]) -> String {
    values
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",")
}
