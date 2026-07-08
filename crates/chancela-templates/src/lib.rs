//! # chancela-templates — the template catalog engine (t48 / TPL-*, Wave C batch-0)
//!
//! Skeleton published by **t48-e0**. This crate owns the template *catalog as data* and the
//! minijinja prose rendering that turns a sealed record into a [`chancela_core::DocumentModel`]
//! (the frozen render↔pdf seam, §3.1). The document *structure* — which blocks, in what order,
//! the signature policy (TPL-04), the bound rule pack (TPL-30) — is registry data
//! ([`TemplateSpec`]); minijinja fills only the *prose fragments* (the fixed legal boilerplate
//! with `{{ field }}` holes). This keeps compliance in the rule pack, never the template
//! (WFL-31), while letting the prose be locale-authored content.
//!
//! **Status: seam types + signatures only.** Rendering, the registry assets, and the loader are
//! implemented by **t48-e1** — bodies here are `todo!()`. The types below are the frozen surface
//! (§3.2) that e1/e5 code against; do not drift their shapes.

use chancela_core::SignaturePolicyHint;
use chancela_core::{DocumentModel, EntityFamily, LifecycleStage, MeetingChannel};
use serde::Serialize;

/// A registry entry: one template, versioned, binding a family × stage to an ordered block
/// layout (§3.2). `id` carries a version suffix (e.g. `"csc-ata-ag/v1"`); the loader rejects
/// duplicate ids. Recorded verbatim in the `document.generated` ledger event, so a later
/// template edit never changes what a past seal produced (D4).
///
/// Derives `Serialize` (the picker DTO / event payload read it) but not `Deserialize` yet:
/// `signature_policy` reuses core's `SignaturePolicyHint`, which is `Serialize`-only. e1 chooses
/// the asset deserialization strategy (a wire DTO) when it lands the loader.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemplateSpec {
    /// Stable, versioned id (e.g. `"csc-ata-ag/v1"`). Unique across the registry.
    pub id: String,
    /// The entity family this template serves.
    pub family: EntityFamily,
    /// Where in the book lifecycle this template sits.
    pub stage: LifecycleStage,
    /// The meeting channels this template is valid for.
    pub channels: Vec<MeetingChannel>,
    /// The signature policy hint to prefer for documents rendered from this template (TPL-04).
    pub signature_policy: SignaturePolicyHint,
    /// The compliance rule pack bound to this template (TPL-30); the id, not the pack itself.
    pub rule_pack_id: String,
    /// The ordered block layout that produces the [`DocumentModel`].
    pub blocks: Vec<BlockSpec>,
    /// The locale the prose is authored in (v1: `"pt-PT"`, UX-21).
    pub locale: String,
}

/// A block in a [`TemplateSpec`]'s layout. Structural blocks map 1:1 to
/// [`chancela_core::Block`]; prose blocks ([`BlockSpec::Heading`], [`BlockSpec::Paragraph`])
/// carry a **minijinja template string** rendered against the record context to produce the
/// final text. Structured blocks ([`BlockSpec::KeyValue`], [`BlockSpec::VoteTable`],
/// [`BlockSpec::SignatureBlock`]) are populated from typed fields of the record by the renderer,
/// not by free-typing (TPL-03).
///
/// Skeleton shape — e1 may enrich the structured variants (e.g. per-row template strings) as it
/// lands the real renderer; the prose-carries-a-template-string principle is the frozen part.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind")]
pub enum BlockSpec {
    /// A heading whose text is a minijinja template.
    Heading {
        /// Heading depth, 1-based.
        level: u8,
        /// minijinja template for the heading text (e.g. `"Ata n.º {{ number }}"`).
        template: String,
    },
    /// A paragraph whose text is a minijinja template; the renderer splits the result into
    /// [`chancela_core::Run`]s.
    Paragraph {
        /// minijinja template for the paragraph body.
        template: String,
    },
    /// A key/value table populated from named record fields.
    KeyValue,
    /// The deliberation vote table, populated from the record's deliberation items.
    VoteTable,
    /// The signature block, populated from the record's signatory slots / signature policy.
    SignatureBlock,
    /// A forced page break.
    PageBreak,
    /// A horizontal rule.
    Rule,
}

/// The loaded, validated template catalog. Holds the specs keyed by id; e1 builds it from the
/// embedded assets and enforces id-uniqueness at load time.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    specs: Vec<TemplateSpec>,
}

impl Registry {
    /// All specs, in load order.
    pub fn specs(&self) -> &[TemplateSpec] {
        &self.specs
    }

    /// Look a spec up by its versioned id.
    pub fn get(&self, id: &str) -> Option<&TemplateSpec> {
        self.specs.iter().find(|s| s.id == id)
    }
}

/// Errors from loading the embedded template registry.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Two specs declared the same id (§3.2: the loader rejects duplicates).
    #[error("duplicate template id: {0}")]
    DuplicateId(String),
    /// An embedded asset failed to parse.
    #[error("failed to parse template asset {asset}: {source}")]
    Asset {
        /// The offending asset path.
        asset: String,
        /// The underlying parse error.
        #[source]
        source: serde_json::Error,
    },
}

/// Errors from rendering a [`TemplateSpec`] into a [`DocumentModel`].
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// A minijinja template failed to render (bad syntax or missing context field).
    #[error("template render failed: {0}")]
    Template(String),
    /// The record context was missing a field the template required.
    #[error("missing context field: {0}")]
    MissingField(String),
}

/// Load the embedded template catalog (§3.2). Later reads the RON/JSON assets under `assets/`,
/// validates id-uniqueness, and returns the [`Registry`]. **Implemented by t48-e1.**
pub fn load_registry() -> Result<Registry, RegistryError> {
    todo!("t48-e1: read embedded template assets, enforce id-uniqueness")
}

/// Render a [`TemplateSpec`] against a record context into the frozen [`DocumentModel`] seam:
/// minijinja fills the prose blocks from `ctx` (any `serde::Serialize` record serialized to
/// JSON), structured blocks are populated from typed fields. **Implemented by t48-e1** — this is
/// the signature e2/e5 code against.
pub fn render(spec: &TemplateSpec, ctx: &serde_json::Value) -> Result<DocumentModel, RenderError> {
    let _ = (spec, ctx);
    todo!("t48-e1: minijinja render prose + populate structured blocks → DocumentModel")
}
