//! chancela-law — the full-text Portuguese law corpus for the Legislação shelf.
//!
//! Embeds the complete text of the diplomas that ground the product, article by article, so a
//! citation resolves to the authentic statute — not a short editorial extract. It is the law
//! analogue of [`chancela_cae`]: a vendored authentic source + `PROVENANCE.md` + a reproducible
//! generator (`data/source/gen_law.py`) → committed JSON → `include_str!` → an indexed
//! [`LawCatalog`] (`OnceLock`, parsed once) with lookup + folded [`search`](LawCatalog::search),
//! plus a [`DreSource`] fetch trait for E1b / refresh.
//!
//! ## The authenticity gate (the whole point)
//! Embedding *wrong* statute text is worse than a reference-only link. So an article is only
//! [`Verification::Verified`] when its [`LawSource`] cites a complete authentic origin; the
//! [`LawCatalog`] build **and** `tests/authenticity.rs` refuse a `Verified` article without one.
//! Any article not yet authentically vendored ships [`Verification::Pending`] and renders the loud
//! marker [`UNVERIFIED_MARKER`] — never a fabricated/recalled body.
//!
//! ## Seeding status (t55-E1a)
//! This crate ships the buildable **skeleton**: the full in-scope diploma list (plan t55 §5) with
//! the app-cited articles pre-allocated `Pending` (CSC art. 255.º / 399.º first — the manager-
//! remuneration priority). E1b vendors the authentic Diário da República text per diploma, expands
//! each to its complete article set, and flips articles to `Verified`.
//!
//! ## Layers
//! - [`LawCatalog`] — immutable, indexed view ([`LawCatalog::embedded`] is the compiled-in corpus);
//!   [`diploma`](LawCatalog::diploma) / [`articles_for`](LawCatalog::articles_for) /
//!   [`article`](LawCatalog::article) / [`search`](LawCatalog::search).
//! - [`LawCorpus`] — the wire/file envelope shared by the embedded corpus and any fetched update.
//! - [`DreSource`] — the fetch-behind-trait ([`FileLawSource`], [`BytesLawSource`], and, behind the
//!   `network` feature, `HttpDreSource`).

mod corpus;
mod dataset;
mod error;
mod model;
mod source;

pub use corpus::{LawCatalog, LawCounts, LawMetadata, LawOrigin};
pub use dataset::{LAW_SCHEMA_VERSION, LawCorpus, LawProvenance};
pub use error::LawError;
pub use model::{DiplomaKind, LawArticle, LawDiploma, LawSource, UNVERIFIED_MARKER, Verification};
pub use source::{BytesLawSource, DreSource, ENV_LAW_URL, FileLawSource};

#[cfg(feature = "network")]
pub use source::HttpDreSource;
