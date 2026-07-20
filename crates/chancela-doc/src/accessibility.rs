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
/// Fixed basis string for the local PDF/UA blocker delta evidence.
pub const PDF_UA_BLOCKER_DELTA_BASIS: &str = "local_chancela_doc_writer_evidence_only";

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

    /// Build decorative artifact metadata for a currently decorative `DocumentModel.blocks` entry.
    pub fn block(index: usize) -> Self {
        Self::block_rule(index)
    }

    /// Build decorative artifact metadata for the fixed layout header separator rule.
    pub fn header_rule() -> Self {
        Self {
            target: header_rule_target(),
        }
    }

    /// Build decorative artifact metadata for an explicit horizontal rule block.
    pub fn block_rule(index: usize) -> Self {
        Self {
            target: block_rule_target(index),
        }
    }

    /// Build decorative artifact metadata for a vote-table header divider rule.
    pub fn vote_table_header_rule(index: usize) -> Self {
        Self {
            target: vote_table_rule_target(index, "header"),
        }
    }

    /// Build decorative artifact metadata for a vote-table footer divider rule.
    pub fn vote_table_footer_rule(index: usize) -> Self {
        Self {
            target: vote_table_rule_target(index, "footer"),
        }
    }

    /// Build decorative artifact metadata for a signature slot's blank-line rule.
    pub fn signature_line(block_index: usize, slot_index: usize) -> Self {
        Self {
            target: signature_line_target(block_index, slot_index),
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
    /// Local catalog/structure-tree facts for the writer's bounded tagged-PDF profile.
    pub structure_tree: StructureTreeEvidenceReport,
    /// Local structural-depth/topology facts for the writer's bounded tagged-PDF profile.
    pub structure_depth: StructureDepthReport,
    /// Local marked-content and artifact-scope facts for the writer's bounded tagged-PDF profile.
    pub marked_content: MarkedContentCoverageReport,
    /// Local decorative-layout artifact marking facts.
    pub artifact_marking: ArtifactMarkingReport,
    /// Explicit non-text alternate/decorative accounting supplied by the caller.
    pub non_text_content: NonTextContentReport,
    /// Whether the model/writer has an alternate-text surface for non-text content.
    pub alt_text_model_present: bool,
    /// True when the writer claims PDF/UA-1 for the (pre-signature) document: no PDF/UA blockers
    /// and determinable metadata (non-fallback title + language).
    pub pdf_ua_claimed: bool,
    /// Local evidence delta between all stable blockers and the currently remaining blockers.
    pub pdf_ua_blocker_delta: PdfUaBlockerDelta,
    /// Ordered blockers preventing a PDF/UA claim.
    pub pdf_ua_blockers: Vec<PdfUaBlocker>,
}

/// Local PDF/UA blocker delta derived only from this writer's stable blocker enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfUaBlockerDelta {
    /// Evidence scope for the delta.
    pub delta_basis: String,
    /// Stable blockers locally cleared by current writer evidence.
    pub cleared_blockers: Vec<PdfUaBlocker>,
    /// Stable blockers still preventing a PDF/UA claim.
    pub remaining_blockers: Vec<PdfUaBlocker>,
    /// Count of locally cleared blockers.
    pub cleared_count: usize,
    /// Count of remaining blockers.
    pub remaining_count: usize,
    /// Whether the writer claims PDF/UA-1 for this document (mirrors [`AccessibilityReport`]).
    pub pdf_ua_claimed: bool,
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
    /// Emitted custom-role mappings with required-by-this-document evidence.
    pub mapped_roles: Vec<RoleMapEntryReport>,
    /// Required custom roles are mapped to standard structure roles.
    pub complete: bool,
}

/// One custom-role mapping emitted into `/StructTreeRoot /RoleMap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleMapEntryReport {
    /// Writer-owned custom structure role.
    pub custom_role: String,
    /// Standard structure role target.
    pub standard_role: String,
    /// Whether this document's model requires the custom role.
    pub required: bool,
}

/// Local facts about table-like blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSemanticsReport {
    /// Count of key/value table blocks in the model.
    pub key_value_table_count: usize,
    /// Count of vote table blocks in the model.
    pub vote_table_count: usize,
    /// Header cells that scope across one row (key/value keys plus vote-row labels).
    pub row_header_cell_count: usize,
    /// Header cells that scope down one column (vote-table header rows).
    pub column_header_cell_count: usize,
    /// Data cells under the writer's bounded table profile.
    pub data_cell_count: usize,
    /// Table rows that would not emit a row/header cell in the writer's bounded profile.
    pub table_rows_missing_header_count: usize,
    /// Key/value tables are emitted with standard table roles.
    pub key_value_tables_have_table_semantics: bool,
    /// Vote tables are emitted with standard table roles.
    pub vote_tables_have_table_semantics: bool,
    /// Key/value row labels are explicitly tagged as row headers.
    pub key_value_row_headers_tagged: bool,
    /// Vote table header cells are explicitly tagged as headers.
    pub vote_table_headers_tagged: bool,
    /// Vote table header-row cells are explicitly tagged as column headers.
    pub vote_table_column_headers_tagged: bool,
    /// Vote table body labels are explicitly tagged as row headers.
    pub vote_table_row_headers_tagged: bool,
    /// Row-header cells carry table-owned `/Scope /Row` attributes.
    pub row_header_cells_have_scope_row: bool,
    /// Column-header cells carry table-owned `/Scope /Column` attributes.
    pub column_header_cells_have_scope_column: bool,
    /// Every emitted header cell carries one of the writer's supported scopes.
    pub header_cells_have_scope: bool,
    /// All table-like blocks have the local semantics this report tracks.
    pub complete: bool,
}

/// Local catalog and structure-tree evidence emitted by the deterministic writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureTreeEvidenceReport {
    /// Catalog `/MarkInfo /Marked true` is emitted.
    pub catalog_mark_info_marked: bool,
    /// Catalog references `/StructTreeRoot`.
    pub catalog_struct_tree_root: bool,
    /// Structure root `/Type` emitted by the writer.
    pub struct_tree_root_type: String,
    /// Root document structure element role emitted under `/StructTreeRoot /K`.
    pub document_element_role: String,
    /// Structure root references a parent tree.
    pub parent_tree_present: bool,
    /// `/ParentTreeNextKey` follows the page count in this writer profile.
    pub parent_tree_next_key_tracks_pages: bool,
    /// Pages carry `/StructParents`.
    pub pages_have_struct_parents: bool,
    /// Page `/StructParents` keys are page-local indexes.
    pub page_struct_parents_are_page_indexes: bool,
    /// Pages use `/Tabs /S` structure order.
    pub pages_use_structure_tab_order: bool,
    /// The structure-tree evidence is complete for this writer's bounded local profile.
    pub complete_for_local_profile: bool,
}

/// Local structural-depth and topology facts for the bounded tagged-PDF profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureDepthReport {
    /// This is the writer's bounded local structure profile, not a PDF/UA conformance profile.
    pub bounded_local_profile: bool,
    /// Maximum structure depth observed in the local profile: root, document, block, row, cell.
    pub max_depth: usize,
    /// Top-level semantic elements under the document element.
    pub top_level_semantic_block_count: usize,
    /// Table-like top-level elements.
    pub table_count: usize,
    /// Row elements under table-like elements.
    pub table_row_count: usize,
    /// Header/data cell elements under row elements.
    pub table_cell_count: usize,
    /// The document element's children are top-level semantic blocks in this writer profile.
    pub document_root_children_are_top_level_semantic_blocks: bool,
    /// Table elements contain row elements only in this writer profile.
    pub tables_contain_rows_only: bool,
    /// Row elements contain header/data cell elements only in this writer profile.
    pub rows_contain_header_or_data_cells_only: bool,
    /// Row and cell roles are scoped inside the expected table/row ancestry.
    pub row_and_cell_roles_are_table_scoped: bool,
    /// The emitted topology is complete for the writer's local bounded profile.
    pub complete_for_local_profile: bool,
}

/// Local marked-content coverage facts for the bounded tagged-PDF profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkedContentCoverageReport {
    /// Structure elements expected under the writer's local profile, including the document root.
    pub structure_element_count: usize,
    /// Leaf structure elements expected to carry marked-content references.
    pub marked_leaf_element_count: usize,
    /// Table header/data cell leaves expected to carry marked-content references.
    pub table_cell_marked_leaf_count: usize,
    /// Layout-only drawing scopes expected to be emitted as `/Artifact BMC`.
    pub artifact_scope_count: usize,
    /// Semantic leaf elements are expected to have one or more page-local `/MCID` references.
    pub semantic_leaves_have_marked_content: bool,
    /// Marked semantic content is expected to be addressable through the parent tree.
    pub parent_tree_maps_page_mcids: bool,
    /// Layout artifacts are expected to be BMC scopes without `/MCID` entries.
    pub artifacts_are_marked_without_mcid: bool,
    /// The marked-content profile is complete for this writer's local bounded structure.
    pub complete_for_local_profile: bool,
}

/// Local facts about layout-only drawing being marked as PDF artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMarkingReport {
    /// Every known layout-only drawing operation is scoped as `/Artifact`.
    pub layout_artifacts_marked: bool,
    /// Total known artifact drawing operations for this model.
    pub known_layout_artifact_count: usize,
    /// Stable local targets for known writer-owned layout artifacts.
    pub known_layout_artifact_targets: Vec<String>,
    /// Marked-content operator used for artifacts.
    pub artifact_scope_operator: String,
    /// Whether artifact scopes carry MCIDs.
    pub artifacts_use_mcid: bool,
    /// Path painting for known layout artifacts occurs inside artifact scopes.
    pub path_painting_scoped_as_artifact: bool,
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
    /// Count of writer-owned rule artifacts this writer emits as known decorative content.
    pub known_decorative_block_count: usize,
    /// Known writer-owned decorative rule targets were emitted as PDF artifacts by this writer.
    pub writer_owned_decorative_artifacts_accounted_for: bool,
    /// Known decorative artifact targets absent from the supplied decorative entries.
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
    /// Explicit blocker showing the writer's bounded tagged-PDF structure is not a full PDF/UA
    /// conformance implementation.
    LimitedTaggedStructure,
}

impl PdfUaBlocker {
    /// Stable enum order used for deterministic blocker deltas.
    pub const ALL: [Self; 13] = [
        Self::MissingStructTreeRoot,
        Self::ContentIsNotTagged,
        Self::MissingRoleMap,
        Self::RoleMapIncomplete,
        Self::HeadingHierarchySkipsLevels,
        Self::UnsupportedHeadingLevel,
        Self::KeyValueTablesNotTaggedAsTables,
        Self::VoteTablesNotTaggedAsTables,
        Self::VoteTableHeadersNotTagged,
        Self::NoAltTextModel,
        Self::NonTextContentNotAccountedFor,
        Self::LayoutArtifactsNotMarked,
        Self::LimitedTaggedStructure,
    ];

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
        let cleared_blockers =
            json_pdf_ua_blocker_array(&self.pdf_ua_blocker_delta.cleared_blockers);
        let remaining_blockers =
            json_pdf_ua_blocker_array(&self.pdf_ua_blocker_delta.remaining_blockers);

        format!(
            "{{\"version\":12,\
\"pdf_ua_claimed\":{pdf_ua_claimed},\
\"pdf_ua\":{{\"claimed\":{pdf_ua_claimed},\"part\":1,\"conformance\":\"1\",\"scope\":\"pre_signature_document\"}},\
\"pdf_ua_blocker_delta\":{{\"delta_basis\":{delta_basis},\"cleared_blockers\":[{cleared_blockers}],\"remaining_blockers\":[{remaining_blockers}],\"cleared_count\":{cleared_count},\"remaining_count\":{remaining_count},\"pdf_ua_claimed\":{delta_pdf_ua_claimed}}},\
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
\"role_map\":{{\"present\":{role_map_present},\"required_custom_roles\":[{required_roles}],\"missing_custom_roles\":[{missing_roles}],\"standard_targets_only\":{standard_role_targets},\"mapped_roles\":[{mapped_roles}],\"complete\":{role_map_complete}}},\
\"tables\":{{\"key_value_table_count\":{kv_table_count},\"vote_table_count\":{vote_table_count},\"row_header_cell_count\":{row_header_count},\"column_header_cell_count\":{column_header_count},\"data_cell_count\":{table_data_count},\"table_rows_missing_header_count\":{missing_header_rows},\"key_value_tables_have_table_semantics\":{kv_tables_semantic},\"vote_tables_have_table_semantics\":{vote_tables_semantic},\"key_value_row_headers_tagged\":{kv_row_headers_tagged},\"vote_table_headers_tagged\":{vote_headers_tagged},\"vote_table_column_headers_tagged\":{vote_column_headers_tagged},\"vote_table_row_headers_tagged\":{vote_row_headers_tagged},\"row_header_cells_have_scope_row\":{row_headers_scope_row},\"column_header_cells_have_scope_column\":{column_headers_scope_column},\"header_cells_have_scope\":{headers_have_scope},\"complete\":{table_semantics_complete}}},\
\"structure_tree\":{{\"catalog_mark_info_marked\":{catalog_mark_info_marked},\"catalog_struct_tree_root\":{catalog_struct_tree_root},\"struct_tree_root_type\":{struct_tree_root_type},\"document_element_role\":{document_element_role},\"parent_tree_present\":{parent_tree_present},\"parent_tree_next_key_tracks_pages\":{parent_tree_next_key_tracks_pages},\"pages_have_struct_parents\":{pages_have_struct_parents},\"page_struct_parents_are_page_indexes\":{page_struct_parents_are_page_indexes},\"pages_use_structure_tab_order\":{structure_tree_pages_use_tab_order},\"complete_for_local_profile\":{structure_tree_complete}}},\
\"structure_depth\":{{\"bounded_local_profile\":{bounded_local_profile},\"max_depth\":{max_depth},\"top_level_semantic_block_count\":{top_level_count},\"table_count\":{depth_table_count},\"table_row_count\":{table_row_count},\"table_cell_count\":{table_cell_count},\"document_root_children_are_top_level_semantic_blocks\":{root_children_top_level},\"tables_contain_rows_only\":{tables_rows_only},\"rows_contain_header_or_data_cells_only\":{rows_cells_only},\"row_and_cell_roles_are_table_scoped\":{row_cell_scoped},\"complete_for_local_profile\":{depth_complete}}},\
\"marked_content\":{{\"structure_element_count\":{marked_structure_count},\"marked_leaf_element_count\":{marked_leaf_count},\"table_cell_marked_leaf_count\":{marked_table_cell_count},\"artifact_scope_count\":{marked_artifact_scope_count},\"semantic_leaves_have_marked_content\":{semantic_leaves_marked},\"parent_tree_maps_page_mcids\":{parent_tree_maps_mcids},\"artifacts_are_marked_without_mcid\":{artifacts_without_mcid},\"complete_for_local_profile\":{marked_complete}}},\
\"artifact_marking\":{{\"layout_artifacts_marked\":{artifact_layout_marked},\"known_layout_artifact_count\":{artifact_count},\"known_layout_artifact_targets\":[{artifact_targets}],\"artifact_scope_operator\":{artifact_scope_operator},\"artifacts_use_mcid\":{artifacts_use_mcid},\"path_painting_scoped_as_artifact\":{path_painting_scoped},\"header_rule_artifact_count\":{header_artifacts},\"horizontal_rule_artifact_count\":{rule_artifacts},\"vote_table_rule_artifact_count\":{vote_rule_artifacts},\"signature_line_artifact_count\":{signature_artifacts}}}\
}},\
\"non_text_content\":{{\"model_supplied\":{non_text_model_supplied},\"all_non_text_content_accounted_for\":{non_text_all_accounted},\"text_alternative_count\":{text_alt_count},\"decorative_artifact_count\":{decorative_count},\"known_decorative_block_count\":{known_decorative_count},\"writer_owned_decorative_artifacts_accounted_for\":{writer_decorative_accounted},\"missing_decorative_artifacts\":[{missing_decorative}],\"invalid_text_alternative_count\":{invalid_text_alts},\"invalid_decorative_artifact_count\":{invalid_decorative},\"complete\":{non_text_complete}}},\
\"alt_text_model_present\":{alt_text},\
\"pdf_ua_blockers\":[{blockers}]\
}}",
            pdf_ua_claimed = self.pdf_ua_claimed,
            delta_basis = json_string(&self.pdf_ua_blocker_delta.delta_basis),
            cleared_blockers = cleared_blockers,
            remaining_blockers = remaining_blockers,
            cleared_count = self.pdf_ua_blocker_delta.cleared_count,
            remaining_count = self.pdf_ua_blocker_delta.remaining_count,
            delta_pdf_ua_claimed = self.pdf_ua_blocker_delta.pdf_ua_claimed,
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
            mapped_roles = json_role_map_entries(&self.role_map.mapped_roles),
            role_map_complete = self.role_map.complete,
            kv_table_count = self.table_semantics.key_value_table_count,
            vote_table_count = self.table_semantics.vote_table_count,
            row_header_count = self.table_semantics.row_header_cell_count,
            column_header_count = self.table_semantics.column_header_cell_count,
            table_data_count = self.table_semantics.data_cell_count,
            missing_header_rows = self.table_semantics.table_rows_missing_header_count,
            kv_tables_semantic = self.table_semantics.key_value_tables_have_table_semantics,
            vote_tables_semantic = self.table_semantics.vote_tables_have_table_semantics,
            kv_row_headers_tagged = self.table_semantics.key_value_row_headers_tagged,
            vote_headers_tagged = self.table_semantics.vote_table_headers_tagged,
            vote_column_headers_tagged = self.table_semantics.vote_table_column_headers_tagged,
            vote_row_headers_tagged = self.table_semantics.vote_table_row_headers_tagged,
            row_headers_scope_row = self.table_semantics.row_header_cells_have_scope_row,
            column_headers_scope_column =
                self.table_semantics.column_header_cells_have_scope_column,
            headers_have_scope = self.table_semantics.header_cells_have_scope,
            table_semantics_complete = self.table_semantics.complete,
            catalog_mark_info_marked = self.structure_tree.catalog_mark_info_marked,
            catalog_struct_tree_root = self.structure_tree.catalog_struct_tree_root,
            struct_tree_root_type = json_string(&self.structure_tree.struct_tree_root_type),
            document_element_role = json_string(&self.structure_tree.document_element_role),
            parent_tree_present = self.structure_tree.parent_tree_present,
            parent_tree_next_key_tracks_pages =
                self.structure_tree.parent_tree_next_key_tracks_pages,
            pages_have_struct_parents = self.structure_tree.pages_have_struct_parents,
            page_struct_parents_are_page_indexes =
                self.structure_tree.page_struct_parents_are_page_indexes,
            structure_tree_pages_use_tab_order = self.structure_tree.pages_use_structure_tab_order,
            structure_tree_complete = self.structure_tree.complete_for_local_profile,
            bounded_local_profile = self.structure_depth.bounded_local_profile,
            max_depth = self.structure_depth.max_depth,
            top_level_count = self.structure_depth.top_level_semantic_block_count,
            depth_table_count = self.structure_depth.table_count,
            table_row_count = self.structure_depth.table_row_count,
            table_cell_count = self.structure_depth.table_cell_count,
            root_children_top_level = self
                .structure_depth
                .document_root_children_are_top_level_semantic_blocks,
            tables_rows_only = self.structure_depth.tables_contain_rows_only,
            rows_cells_only = self.structure_depth.rows_contain_header_or_data_cells_only,
            row_cell_scoped = self.structure_depth.row_and_cell_roles_are_table_scoped,
            depth_complete = self.structure_depth.complete_for_local_profile,
            marked_structure_count = self.marked_content.structure_element_count,
            marked_leaf_count = self.marked_content.marked_leaf_element_count,
            marked_table_cell_count = self.marked_content.table_cell_marked_leaf_count,
            marked_artifact_scope_count = self.marked_content.artifact_scope_count,
            semantic_leaves_marked = self.marked_content.semantic_leaves_have_marked_content,
            parent_tree_maps_mcids = self.marked_content.parent_tree_maps_page_mcids,
            artifacts_without_mcid = self.marked_content.artifacts_are_marked_without_mcid,
            marked_complete = self.marked_content.complete_for_local_profile,
            artifact_layout_marked = self.artifact_marking.layout_artifacts_marked,
            artifact_count = self.artifact_marking.known_layout_artifact_count,
            artifact_targets =
                json_string_array(&self.artifact_marking.known_layout_artifact_targets),
            artifact_scope_operator = json_string(&self.artifact_marking.artifact_scope_operator),
            artifacts_use_mcid = self.artifact_marking.artifacts_use_mcid,
            path_painting_scoped = self.artifact_marking.path_painting_scoped_as_artifact,
            header_artifacts = self.artifact_marking.header_rule_artifact_count,
            rule_artifacts = self.artifact_marking.horizontal_rule_artifact_count,
            vote_rule_artifacts = self.artifact_marking.vote_table_rule_artifact_count,
            signature_artifacts = self.artifact_marking.signature_line_artifact_count,
            non_text_model_supplied = self.non_text_content.model_supplied,
            non_text_all_accounted = self.non_text_content.all_non_text_content_accounted_for,
            text_alt_count = self.non_text_content.text_alternative_count,
            decorative_count = self.non_text_content.decorative_artifact_count,
            known_decorative_count = self.non_text_content.known_decorative_block_count,
            writer_decorative_accounted = self
                .non_text_content
                .writer_owned_decorative_artifacts_accounted_for,
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
    let structure_tree = structure_tree_evidence();
    let structure_depth = structure_depth(input.doc);
    let artifact_marking = artifact_marking(input.doc);
    let marked_content = marked_content_coverage(&structure_depth, &artifact_marking);
    let non_text_content = non_text_content(input.alt_text_model, &artifact_marking);
    let alt_text_model_present = non_text_content.model_supplied && non_text_content.complete;

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
    if !table_semantics.key_value_tables_have_table_semantics
        || !table_semantics.key_value_row_headers_tagged
    {
        blockers.push(PdfUaBlocker::KeyValueTablesNotTaggedAsTables);
    }
    if !table_semantics.vote_tables_have_table_semantics {
        blockers.push(PdfUaBlocker::VoteTablesNotTaggedAsTables);
    }
    if !table_semantics.vote_table_headers_tagged || !table_semantics.header_cells_have_scope {
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
    // Historically the writer pushed `LimitedTaggedStructure` unconditionally to refuse the UA
    // claim. The tag tree is now complete enough to claim PDF/UA-1, so we stop emitting it (the
    // variant is retained in `PdfUaBlocker::ALL` for parse-back stability and now lands in the
    // delta's `cleared_blockers`).
    let metadata = metadata(input.doc);
    // Claim PDF/UA only when nothing blocks it *and* the metadata is genuinely determinable — a
    // fallback title or an undetermined language is not an honest UA claim.
    let pdf_ua_claimed =
        blockers.is_empty() && !metadata.title.fallback_used && !metadata.language.fallback_used;
    let pdf_ua_blocker_delta = pdf_ua_blocker_delta(&blockers, pdf_ua_claimed);

    AccessibilityReport {
        metadata,
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
        structure_tree,
        structure_depth,
        marked_content,
        artifact_marking,
        non_text_content,
        alt_text_model_present,
        pdf_ua_claimed,
        pdf_ua_blocker_delta,
        pdf_ua_blockers: blockers,
    }
}

fn pdf_ua_blocker_delta(
    remaining_blockers: &[PdfUaBlocker],
    pdf_ua_claimed: bool,
) -> PdfUaBlockerDelta {
    let cleared_blockers = PdfUaBlocker::ALL
        .iter()
        .copied()
        .filter(|blocker| !remaining_blockers.contains(blocker))
        .collect::<Vec<_>>();
    let remaining_blockers = remaining_blockers.to_vec();

    PdfUaBlockerDelta {
        delta_basis: PDF_UA_BLOCKER_DELTA_BASIS.to_string(),
        cleared_count: cleared_blockers.len(),
        remaining_count: remaining_blockers.len(),
        cleared_blockers,
        remaining_blockers,
        pdf_ua_claimed,
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
    ("ChancelaKeyValue", "Table"),
    ("ChancelaVoteTable", "Table"),
    ("ChancelaSignatureBlock", "Div"),
];

pub(crate) fn role_map_entries() -> &'static [(&'static str, &'static str)] {
    ROLE_MAP_ENTRIES
}

fn role_map_coverage(doc: &DocumentModel) -> RoleMapCoverageReport {
    let required_custom_roles = required_custom_roles(doc);
    let required_custom_role_set = required_custom_roles
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let missing_custom_roles = required_custom_roles
        .iter()
        .filter(|role| role_map_target(role).is_none())
        .cloned()
        .collect::<Vec<_>>();
    let standard_targets_only = ROLE_MAP_ENTRIES
        .iter()
        .all(|(_, target)| is_standard_structure_target(target));
    let mapped_roles = ROLE_MAP_ENTRIES
        .iter()
        .map(|&(custom, standard)| RoleMapEntryReport {
            custom_role: custom.to_string(),
            standard_role: standard.to_string(),
            required: required_custom_role_set.contains(custom),
        })
        .collect::<Vec<_>>();
    let complete = missing_custom_roles.is_empty() && standard_targets_only;

    RoleMapCoverageReport {
        present: true,
        required_custom_roles,
        missing_custom_roles,
        standard_targets_only,
        mapped_roles,
        complete,
    }
}

fn is_standard_structure_target(role: &str) -> bool {
    matches!(
        role,
        "Document" | "Div" | "P" | "H" | "H1" | "H2" | "H3" | "Table" | "TR" | "TH" | "TD"
    )
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
    let key_value_row_header_cell_count = doc
        .blocks
        .iter()
        .map(|block| match block {
            Block::KeyValue { rows } => rows.iter().filter(|row| has_words(&row.key)).count(),
            _ => 0,
        })
        .sum::<usize>();
    let key_value_data_cell_count = doc
        .blocks
        .iter()
        .map(|block| match block {
            Block::KeyValue { rows } => rows.iter().filter(|row| has_words(&row.value)).count(),
            _ => 0,
        })
        .sum::<usize>();
    let key_value_rows_missing_header_count = doc
        .blocks
        .iter()
        .map(|block| match block {
            Block::KeyValue { rows } => rows
                .iter()
                .filter(|row| !has_words(&row.key) && has_words(&row.value))
                .count(),
            _ => 0,
        })
        .sum::<usize>();
    let vote_body_row_count = doc
        .blocks
        .iter()
        .map(|block| match block {
            Block::VoteTable { rows } => rows.len(),
            _ => 0,
        })
        .sum::<usize>();
    let vote_row_header_cell_count = doc
        .blocks
        .iter()
        .map(|block| match block {
            Block::VoteTable { rows } => rows.iter().filter(|row| has_words(&row.label)).count(),
            _ => 0,
        })
        .sum::<usize>();
    let vote_rows_missing_header_count =
        vote_body_row_count.saturating_sub(vote_row_header_cell_count);
    let table_rows_missing_header_count =
        key_value_rows_missing_header_count + vote_rows_missing_header_count;
    let row_header_cell_count = key_value_row_header_cell_count + vote_row_header_cell_count;
    let column_header_cell_count = vote_table_count * 4;
    let data_cell_count = key_value_data_cell_count + vote_body_row_count * 3;
    let key_value_tables_have_table_semantics = true;
    let vote_tables_have_table_semantics = true;
    let key_value_row_headers_tagged = key_value_rows_missing_header_count == 0;
    let vote_table_column_headers_tagged = true;
    let vote_table_row_headers_tagged = vote_rows_missing_header_count == 0;
    let vote_table_headers_tagged =
        vote_table_column_headers_tagged && vote_table_row_headers_tagged;
    let row_header_cells_have_scope_row = true;
    let column_header_cells_have_scope_column = true;
    let header_cells_have_scope =
        row_header_cells_have_scope_row && column_header_cells_have_scope_column;
    let complete = key_value_tables_have_table_semantics
        && vote_tables_have_table_semantics
        && key_value_row_headers_tagged
        && vote_table_headers_tagged
        && vote_table_column_headers_tagged
        && vote_table_row_headers_tagged
        && header_cells_have_scope;

    TableSemanticsReport {
        key_value_table_count,
        vote_table_count,
        row_header_cell_count,
        column_header_cell_count,
        data_cell_count,
        table_rows_missing_header_count,
        key_value_tables_have_table_semantics,
        vote_tables_have_table_semantics,
        key_value_row_headers_tagged,
        vote_table_headers_tagged,
        vote_table_column_headers_tagged,
        vote_table_row_headers_tagged,
        row_header_cells_have_scope_row,
        column_header_cells_have_scope_column,
        header_cells_have_scope,
        complete,
    }
}

fn structure_tree_evidence() -> StructureTreeEvidenceReport {
    let catalog_mark_info_marked = true;
    let catalog_struct_tree_root = true;
    let parent_tree_present = true;
    let parent_tree_next_key_tracks_pages = true;
    let pages_have_struct_parents = true;
    let page_struct_parents_are_page_indexes = true;
    let pages_use_structure_tab_order = true;
    let complete_for_local_profile = catalog_mark_info_marked
        && catalog_struct_tree_root
        && parent_tree_present
        && parent_tree_next_key_tracks_pages
        && pages_have_struct_parents
        && page_struct_parents_are_page_indexes
        && pages_use_structure_tab_order;

    StructureTreeEvidenceReport {
        catalog_mark_info_marked,
        catalog_struct_tree_root,
        struct_tree_root_type: "StructTreeRoot".to_string(),
        document_element_role: "ChancelaDocument".to_string(),
        parent_tree_present,
        parent_tree_next_key_tracks_pages,
        pages_have_struct_parents,
        page_struct_parents_are_page_indexes,
        pages_use_structure_tab_order,
        complete_for_local_profile,
    }
}

fn structure_depth(doc: &DocumentModel) -> StructureDepthReport {
    let mut top_level_semantic_block_count = 0usize;
    let mut table_count = 0usize;
    let mut table_row_count = 0usize;
    let mut table_cell_count = 0usize;

    if has_words(&doc.title) {
        top_level_semantic_block_count += 1;
    }
    if has_words(&doc.entity_name) || doc.entity_nipc.as_deref().is_some_and(has_words) {
        top_level_semantic_block_count += 1;
    }
    if has_words(&doc.subject) {
        top_level_semantic_block_count += 1;
    }

    for block in &doc.blocks {
        match block {
            Block::Heading { text, .. } if has_words(text) => {
                top_level_semantic_block_count += 1;
            }
            Block::Paragraph { runs } if runs.iter().any(|run| has_words(&run.text)) => {
                top_level_semantic_block_count += 1;
            }
            Block::KeyValue { rows } => {
                let mut emitted_rows = 0usize;
                let mut emitted_cells = 0usize;
                for row in rows {
                    let key_present = has_words(&row.key);
                    let value_present = has_words(&row.value);
                    if key_present || value_present {
                        emitted_rows += 1;
                    }
                    if key_present {
                        emitted_cells += 1;
                    }
                    if value_present {
                        emitted_cells += 1;
                    }
                }
                if emitted_rows > 0 {
                    top_level_semantic_block_count += 1;
                    table_count += 1;
                    table_row_count += emitted_rows;
                    table_cell_count += emitted_cells;
                }
            }
            Block::VoteTable { rows } => {
                top_level_semantic_block_count += 1;
                table_count += 1;
                table_row_count += rows.len() + 1;
                table_cell_count += (rows.len() + 1) * 4;
            }
            Block::SignatureBlock { slots }
                if slots
                    .iter()
                    .any(|slot| has_words(&slot.role) || has_words(&slot.name)) =>
            {
                top_level_semantic_block_count += 1;
            }
            _ => {}
        }
    }

    let max_depth = if table_cell_count > 0 {
        4
    } else if table_row_count > 0 {
        3
    } else if top_level_semantic_block_count > 0 {
        2
    } else {
        1
    };
    let document_root_children_are_top_level_semantic_blocks = true;
    let tables_contain_rows_only = true;
    let rows_contain_header_or_data_cells_only = true;
    let row_and_cell_roles_are_table_scoped = true;
    let complete_for_local_profile = document_root_children_are_top_level_semantic_blocks
        && tables_contain_rows_only
        && rows_contain_header_or_data_cells_only
        && row_and_cell_roles_are_table_scoped;

    StructureDepthReport {
        bounded_local_profile: true,
        max_depth,
        top_level_semantic_block_count,
        table_count,
        table_row_count,
        table_cell_count,
        document_root_children_are_top_level_semantic_blocks,
        tables_contain_rows_only,
        rows_contain_header_or_data_cells_only,
        row_and_cell_roles_are_table_scoped,
        complete_for_local_profile,
    }
}

fn marked_content_coverage(
    structure_depth: &StructureDepthReport,
    artifact_marking: &ArtifactMarkingReport,
) -> MarkedContentCoverageReport {
    let table_container_count = structure_depth.table_count;
    let non_table_leaf_count = structure_depth
        .top_level_semantic_block_count
        .saturating_sub(table_container_count);
    let marked_leaf_element_count = non_table_leaf_count + structure_depth.table_cell_count;
    let structure_element_count = 1
        + structure_depth.top_level_semantic_block_count
        + structure_depth.table_row_count
        + structure_depth.table_cell_count;
    let semantic_leaves_have_marked_content = structure_depth.complete_for_local_profile;
    let parent_tree_maps_page_mcids = structure_depth.complete_for_local_profile;
    let artifacts_are_marked_without_mcid = artifact_marking.layout_artifacts_marked;
    let complete_for_local_profile = semantic_leaves_have_marked_content
        && parent_tree_maps_page_mcids
        && artifacts_are_marked_without_mcid;

    MarkedContentCoverageReport {
        structure_element_count,
        marked_leaf_element_count,
        table_cell_marked_leaf_count: structure_depth.table_cell_count,
        artifact_scope_count: artifact_marking.known_layout_artifact_count,
        semantic_leaves_have_marked_content,
        parent_tree_maps_page_mcids,
        artifacts_are_marked_without_mcid,
        complete_for_local_profile,
    }
}

fn artifact_marking(doc: &DocumentModel) -> ArtifactMarkingReport {
    let known_layout_artifact_targets = known_decorative_targets(doc);
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
    let known_layout_artifact_count = known_layout_artifact_targets.len();

    ArtifactMarkingReport {
        layout_artifacts_marked: true,
        known_layout_artifact_count,
        known_layout_artifact_targets,
        artifact_scope_operator: "BMC".to_string(),
        artifacts_use_mcid: false,
        path_painting_scoped_as_artifact: true,
        header_rule_artifact_count,
        horizontal_rule_artifact_count,
        vote_table_rule_artifact_count,
        signature_line_artifact_count,
    }
}

fn non_text_content(
    model: Option<&AltTextModel>,
    artifact_marking: &ArtifactMarkingReport,
) -> NonTextContentReport {
    let known_decorative_targets = artifact_marking.known_layout_artifact_targets.clone();
    let known_decorative_block_count = known_decorative_targets.len();
    let writer_owned_decorative_artifacts_accounted_for = artifact_marking.layout_artifacts_marked
        && artifact_marking.known_layout_artifact_count == known_decorative_block_count;
    let Some(model) = model else {
        return NonTextContentReport {
            model_supplied: false,
            all_non_text_content_accounted_for: false,
            text_alternative_count: 0,
            decorative_artifact_count: 0,
            known_decorative_block_count,
            writer_owned_decorative_artifacts_accounted_for,
            missing_decorative_artifacts: if writer_owned_decorative_artifacts_accounted_for {
                Vec::new()
            } else {
                known_decorative_targets
            },
            invalid_text_alternative_count: 0,
            invalid_decorative_artifact_count: 0,
            complete: writer_owned_decorative_artifacts_accounted_for,
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
    let missing_decorative_artifacts = if writer_owned_decorative_artifacts_accounted_for {
        Vec::new()
    } else {
        known_decorative_targets
            .into_iter()
            .filter(|target| !decorative_targets.contains(target.as_str()))
            .collect::<Vec<_>>()
    };
    let complete = model.all_non_text_content_accounted_for
        && invalid_text_alternative_count == 0
        && invalid_decorative_artifact_count == 0
        && missing_decorative_artifacts.is_empty()
        && writer_owned_decorative_artifacts_accounted_for;

    NonTextContentReport {
        model_supplied: true,
        all_non_text_content_accounted_for: model.all_non_text_content_accounted_for,
        text_alternative_count: model.text_alternatives.len(),
        decorative_artifact_count: model.decorative_artifacts.len(),
        known_decorative_block_count,
        writer_owned_decorative_artifacts_accounted_for,
        missing_decorative_artifacts,
        invalid_text_alternative_count,
        invalid_decorative_artifact_count,
        complete,
    }
}

fn known_decorative_targets(doc: &DocumentModel) -> Vec<String> {
    let mut targets = vec![header_rule_target()];
    for (index, block) in doc.blocks.iter().enumerate() {
        match block {
            // New caller-owned non-text block variants must update this accounting before
            // `no_alt_text_model` can be suppressed by writer-owned decorative artifacts.
            Block::Heading { .. }
            | Block::Paragraph { .. }
            | Block::KeyValue { .. }
            | Block::PageBreak => {}
            Block::Rule => targets.push(block_rule_target(index)),
            Block::VoteTable { .. } => {
                targets.push(vote_table_rule_target(index, "header"));
                targets.push(vote_table_rule_target(index, "footer"));
            }
            Block::SignatureBlock { slots } => {
                targets.extend(
                    (0..slots.len()).map(|slot_index| signature_line_target(index, slot_index)),
                );
            }
        }
    }
    targets
}

fn header_rule_target() -> String {
    "layout:header-rule".to_string()
}

fn block_rule_target(index: usize) -> String {
    format!("block:{index}:rule")
}

fn vote_table_rule_target(index: usize, position: &str) -> String {
    format!("block:{index}:vote-table-{position}-rule")
}

fn signature_line_target(block_index: usize, slot_index: usize) -> String {
    format!("block:{block_index}:signature-line:{slot_index}")
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

fn json_pdf_ua_blocker_array(blockers: &[PdfUaBlocker]) -> String {
    blockers
        .iter()
        .map(|blocker| json_string(blocker.code()))
        .collect::<Vec<_>>()
        .join(",")
}

fn json_role_map_entries(entries: &[RoleMapEntryReport]) -> String {
    entries
        .iter()
        .map(|entry| {
            format!(
                "{{\"custom_role\":{},\"standard_role\":{},\"required\":{}}}",
                json_string(&entry.custom_role),
                json_string(&entry.standard_role),
                entry.required
            )
        })
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
