//! # Document model — the render↔pdf seam (t48 / DOC-01, frozen contract §3.1)
//!
//! [`DocumentModel`] is a **PDF-agnostic, serde-serializable** document tree. It is the frozen
//! seam between the two Wave C executors: the template engine (`chancela-templates`) *produces*
//! it by rendering a sealed record through a `TemplateSpec`, and the PDF/A-2u writer
//! (`chancela-doc`) *consumes* it to lay out bytes. It is also independently useful — the web
//! preview renders it to HTML for on-screen review, and a future DOCX/HTML working-copy exporter
//! (DOC-02, Wave E) consumes the same model — so screen and PDF share one source of truth.
//!
//! ## FROZEN
//!
//! **Field order and variant order in this module are FROZEN for determinism.** Serde serializes
//! struct fields in declaration order, so the wire shape (and therefore any digest computed over
//! the rendered model, and any golden test) depends on that order. Do NOT reorder fields or
//! variants, and do NOT rename serialized keys. New fields must be appended (and, if optional for
//! backward compatibility, carry `#[serde(default)]`). New [`Block`] variants must be appended.
//! New [`LifecycleStage`] values must be appended (the enum is `#[non_exhaustive]`).
//!
//! ## Purity
//!
//! This module keeps `chancela-core` a leaf: it depends only on `serde` (already a core
//! dependency). There is **no clock, no network, no PDF/template dependency** here. `created_at`
//! is supplied by the caller as an ISO-8601 string — core never reads a clock, so a given record
//! + template always renders to an identical model (regeneration/re-verification, D3/§164).

use serde::{Deserialize, Serialize};

/// The template lifecycle stages (TPL / WFL). A stage names *where in a book's life* a document
/// sits — a `TemplateSpec` binds a family × stage to an ordered block layout. v1 ships the two
/// spine templates (`Ata` for the CSC general-meeting minutes and `TermoAbertura` for book
/// opening); the remaining stages are the fast-follow catalog breadth (§6) and are declared here
/// so the seam is stable before the templates land.
///
/// `#[non_exhaustive]`: consumers must handle an unknown stage (e.g. a `_ =>` arm), because the
/// catalog grows without a breaking change. Serialized with bare variant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LifecycleStage {
    /// Convocatória — the notice convening a meeting (TPL-20; fast-follow).
    Convocatoria,
    /// Termo de abertura — opens a book; its sealed form is the genesis of the hash chain
    /// (WFL-11 / TPL-10/11). Ships in v1.
    TermoAbertura,
    /// Reunião — the meeting proceedings / attendance stage (fast-follow).
    Reuniao,
    /// Deliberação — the voting/resolution stage (fast-follow).
    Deliberacao,
    /// Ata — the minute-book act itself (the v1 spine template).
    Ata,
    /// Certidão — a certified copy of a sealed ata (TPL-40; fast-follow).
    Certidao,
    /// Extrato — an extract of a sealed ata (TPL-40; fast-follow).
    Extrato,
    /// Termo de encerramento — closes a book (WFL-14; fast-follow).
    TermoEncerramento,
}

/// A styled text span within a [`Block::Paragraph`]. A run is the smallest unit of text with
/// uniform styling; a paragraph is a sequence of runs so a single sentence can mix regular,
/// **bold**, and *italic* text without block boundaries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Run {
    /// The literal text of the span (already interpolated; no template holes remain).
    pub text: String,
    /// Render bold.
    pub bold: bool,
    /// Render italic.
    pub italic: bool,
}

/// One row of a [`Block::KeyValue`] table — a labelled field (e.g. "Data" → "8 de julho de 2026").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KvRow {
    /// The field label (left column).
    pub key: String,
    /// The field value (right column).
    pub value: String,
}

/// One row of a [`Block::VoteTable`] — a deliberation and its vote tally. Counts are simple
/// non-negative integers; a template renders `VoteResult::Recorded { em_favor, contra,
/// abstencoes }` into these fields, and `Unanimous`/`ByShow` into the same shape at render time
/// (the model is deliberately arithmetic, not the domain's richer `VoteResult`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoteRow {
    /// The deliberation label (e.g. "Ponto 1 — Aprovação de contas").
    pub label: String,
    /// Votes in favour (a favor).
    pub favor: u32,
    /// Votes against (contra).
    pub against: u32,
    /// Abstentions (abstenções).
    pub abstain: u32,
}

/// One signature slot of a [`Block::SignatureBlock`] — a named role expected to sign. The
/// cryptographic artifact lives in `chancela-signing`; this is only the printed line
/// (role + name) that the PDF lays out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureSlot {
    /// The capacity/role of the signatory (e.g. "Presidente da mesa").
    pub role: String,
    /// The signatory's name (may be empty for a blank line to be signed on paper).
    pub name: String,
}

/// A structural block of the document, in reading order. Serde-tagged with `type` so the wire
/// shape is self-describing and stable (`{"type":"Heading","level":1,"text":"…"}`). Variant
/// order is FROZEN.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Block {
    /// A heading; `level` is 1-based (1 = document title-level section heading).
    Heading {
        /// Heading depth, 1-based.
        level: u8,
        /// Heading text (single line, already interpolated).
        text: String,
    },
    /// A body paragraph: a sequence of styled [`Run`]s.
    Paragraph {
        /// The styled spans, in order.
        runs: Vec<Run>,
    },
    /// A key/value table (e.g. the meeting header: date, place, channel).
    KeyValue {
        /// The rows, in order.
        rows: Vec<KvRow>,
    },
    /// A vote-tally table for the deliberations.
    VoteTable {
        /// The rows, in order.
        rows: Vec<VoteRow>,
    },
    /// The signature block: the roles/names expected to sign.
    SignatureBlock {
        /// The slots, in order.
        slots: Vec<SignatureSlot>,
    },
    /// A forced page break.
    PageBreak,
    /// A horizontal rule (visual separator).
    Rule,
}

/// A PDF-agnostic document tree: document metadata plus an ordered list of [`Block`]s. This is
/// the frozen seam (§3.1). Metadata fields come first (declaration order = wire order), then the
/// blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentModel {
    /// Document title (e.g. "Ata n.º 1 — Assembleia Geral").
    pub title: String,
    /// The legal person the document belongs to (e.g. "Encosto Estratégico Lda").
    pub entity_name: String,
    /// The entity's NIPC, when known.
    pub entity_nipc: Option<String>,
    /// A short subject/description line.
    pub subject: String,
    /// BCP-47 language tag; defaults to `"pt-PT"` (see [`DocumentModel::new`]). Recorded in the
    /// PDF/A XMP + `/Lang`.
    pub language: String,
    /// ISO-8601 creation timestamp, **supplied by the caller** (core reads no clock, so the model
    /// stays a pure/deterministic function of its inputs). `None` when the caller omits it.
    pub created_at: Option<String>,
    /// The document body, in reading order.
    pub blocks: Vec<Block>,
}

impl DocumentModel {
    /// Construct a model with `language` defaulted to `"pt-PT"` (UX-21) and no `created_at`.
    /// Callers that have a timestamp set [`DocumentModel::created_at`] afterwards (or build the
    /// struct literally) — core never invents one.
    pub fn new(
        title: impl Into<String>,
        entity_name: impl Into<String>,
        subject: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            entity_name: entity_name.into(),
            entity_nipc: None,
            subject: subject.into(),
            language: "pt-PT".to_string(),
            created_at: None,
            blocks: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small model exercising one of each block, used by the round-trip and shape tests.
    fn sample() -> DocumentModel {
        DocumentModel {
            title: "Ata n.º 1 — Assembleia Geral".to_string(),
            entity_name: "Encosto Estratégico Lda".to_string(),
            entity_nipc: Some("500000000".to_string()),
            subject: "Assembleia geral ordinária".to_string(),
            language: "pt-PT".to_string(),
            created_at: Some("2026-07-08T10:30:00Z".to_string()),
            blocks: vec![
                Block::Heading {
                    level: 1,
                    text: "Ata".to_string(),
                },
                Block::Paragraph {
                    runs: vec![
                        Run {
                            text: "Aos 8 dias reuniu ".to_string(),
                            bold: false,
                            italic: false,
                        },
                        Run {
                            text: "Amélia Marques".to_string(),
                            bold: true,
                            italic: false,
                        },
                    ],
                },
                Block::KeyValue {
                    rows: vec![KvRow {
                        key: "Data".to_string(),
                        value: "8 de julho de 2026".to_string(),
                    }],
                },
                Block::VoteTable {
                    rows: vec![VoteRow {
                        label: "Ponto 1".to_string(),
                        favor: 3,
                        against: 1,
                        abstain: 0,
                    }],
                },
                Block::SignatureBlock {
                    slots: vec![SignatureSlot {
                        role: "Presidente da mesa".to_string(),
                        name: "Amélia Marques".to_string(),
                    }],
                },
                Block::PageBreak,
                Block::Rule,
            ],
        }
    }

    #[test]
    fn round_trips_through_serde_json() {
        let model = sample();
        let json = serde_json::to_string(&model).expect("serialize");
        let back: DocumentModel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(model, back);
    }

    #[test]
    fn wire_shape_is_stable() {
        // The FROZEN wire shape: serde serializes struct fields in declaration order, so the
        // *serialized string* carries metadata keys and per-struct fields in declaration order
        // and each block tagged with `type`. This golden asserts on the string (not on a
        // `serde_json::Value`, whose BTreeMap would sort keys) so it proves the real determinism
        // guarantee web preview + future DOC-02 depend on.
        let json = serde_json::to_string(&sample()).expect("serialize");

        // Top-level metadata keys appear in declaration order.
        let ordered_keys = [
            "\"title\"",
            "\"entity_name\"",
            "\"entity_nipc\"",
            "\"subject\"",
            "\"language\"",
            "\"created_at\"",
            "\"blocks\"",
        ];
        let mut cursor = 0usize;
        for key in ordered_keys {
            let at = json[cursor..]
                .find(key)
                .unwrap_or_else(|| panic!("missing key {key} after offset {cursor} in {json}"));
            cursor += at + key.len();
        }

        // Each block variant is tagged with `type` first (internal tag), bare variant names, in
        // reading order.
        let ordered_tags = [
            "{\"type\":\"Heading\"",
            "{\"type\":\"Paragraph\"",
            "{\"type\":\"KeyValue\"",
            "{\"type\":\"VoteTable\"",
            "{\"type\":\"SignatureBlock\"",
            "{\"type\":\"PageBreak\"",
            "{\"type\":\"Rule\"",
        ];
        let mut cursor = 0usize;
        for tag in ordered_tags {
            let at = json[cursor..]
                .find(tag)
                .unwrap_or_else(|| panic!("missing block {tag} after offset {cursor} in {json}"));
            cursor += at + tag.len();
        }

        // A styled run keeps its field order/shape; a vote row keeps its arithmetic field names.
        assert!(json.contains("{\"text\":\"Amélia Marques\",\"bold\":true,\"italic\":false}"));
        assert!(json.contains("{\"label\":\"Ponto 1\",\"favor\":3,\"against\":1,\"abstain\":0}"));
    }

    #[test]
    fn new_defaults_language_to_pt_pt() {
        let m = DocumentModel::new("T", "Encosto Estratégico Lda", "S");
        assert_eq!(m.language, "pt-PT");
        assert_eq!(m.created_at, None);
        assert!(m.blocks.is_empty());
    }

    #[test]
    fn lifecycle_stage_uses_bare_serde_names() {
        assert_eq!(
            serde_json::to_string(&LifecycleStage::Ata).unwrap(),
            "\"Ata\""
        );
        assert_eq!(
            serde_json::to_string(&LifecycleStage::TermoAbertura).unwrap(),
            "\"TermoAbertura\""
        );
        let back: LifecycleStage = serde_json::from_str("\"Certidao\"").unwrap();
        assert_eq!(back, LifecycleStage::Certidao);
    }
}
