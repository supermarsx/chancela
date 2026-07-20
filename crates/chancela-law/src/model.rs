//! The FROZEN corpus data model (the authoring contract for E1b + E2 api + E3 web).
//!
//! Everything here is plain, serde-round-tripping data so that a lawyer / E1b fills authentic text
//! and flips an article `Pending → Verified` **by editing `data/law_corpus.json`, not code**.
//!
//! ## The authenticity contract (the whole point)
//! - A [`LawArticle`] is [`Verification::Verified`] (human-approved authentic text),
//!   [`Verification::AutomatedReview`] (automatically-vendored authentic text, NOT human-approved),
//!   or [`Verification::Pending`] (no text).
//! - An article may be `Verified` **or** `AutomatedReview` **only** if its [`LawSource`] is
//!   *complete* — it cites a real origin (diploma + article + `dr_reference` + `url`). The corpus
//!   build ([`crate::LawCatalog`]) and the `tests/authenticity.rs` gate both refuse a body-bearing
//!   article without one, so no fabricated/recalled statute text can ever be presented as law.
//! - `Verified` additionally requires the HUMAN legal-approval workflow (the DRE capture manifest's
//!   `LEGAL_APPROVED_FOR_VERIFIED` marker); `AutomatedReview` makes the weaker, honest claim and
//!   bypasses none of that gate.
//! - A `Pending` article NEVER renders its (empty, never-guessed) `body`; it renders the loud
//!   marker [`UNVERIFIED_MARKER`] via [`LawArticle::display_body`].

use serde::{Deserialize, Serialize};

/// The loud placeholder a `Pending` article renders in place of body text. Kept in sync with
/// `data/source/gen_law.py`. Never a fabricated statute — an unverified article shows this.
pub const UNVERIFIED_MARKER: &str = "[NÃO VERIFICADO / fonte pendente]";

/// The legal instrument a diploma is. Serializes as the bare variant name (`"Codigo"`, …).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiplomaKind {
    /// A código (CSC, Código Civil, Código Cooperativo, …).
    Codigo,
    /// A decreto-lei.
    DecretoLei,
    /// A lei.
    Lei,
    /// A regulamento da União Europeia.
    RegulamentoUe,
    /// A diretiva da União Europeia.
    DiretivaUe,
}

/// Whether an article's `body` is human-approved authentic text (`Verified`), automated-review
/// authentic text (`AutomatedReview`), or still a placeholder (`Pending`). Serializes as
/// `"Verified"` / `"automated_review"` / `"Pending"`.
///
/// The three tiers make a strictly ordered, honest claim about the body:
/// `Verified` > `AutomatedReview` > `Pending`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verification {
    /// The `body` is authentic verbatim text with a complete [`LawSource`], **and** it has passed
    /// the HUMAN legal-approval workflow (the DRE capture manifest's `LEGAL_APPROVED_FOR_VERIFIED`
    /// marker with reviewer + legal both Approved). The strongest claim.
    Verified,
    /// The `body` is official statutory text that was vendored and reviewed by an **automated**
    /// process (browser / HTTP capture of the consolidated diploma plus automated fidelity checks),
    /// carrying a complete [`LawSource`] and a non-empty `body` exactly like [`Verified`] — **but it
    /// is NOT human-legally-approved**: no reviewer signed the `LEGAL_APPROVED_FOR_VERIFIED` marker.
    /// It is strictly weaker than [`Verified`] (which is human-approved) and strictly stronger than
    /// [`Pending`] (which has no text). **Human legal review is recommended before reliance.**
    ///
    /// It bypasses NOTHING in the human-`Verified` gate: it makes a weaker, honest claim, and the
    /// DRE capture manifest still lists these articles as pending human approval.
    #[serde(rename = "automated_review")]
    AutomatedReview,
    /// The `body` is not yet vendored; the article renders [`UNVERIFIED_MARKER`].
    Pending,
}

/// Per-article provenance — where the text was vendored from. The **completeness of this struct is
/// the authenticity gate**: an article can only be `Verified` when `diploma`, `article`,
/// `dr_reference` and `url` are all present (see [`LawSource::is_complete`]).
///
/// Note the name collision with the CAE precedent: this is the *data* struct (the frozen
/// `LawArticle::source`); the network fetch trait that mirrors `CaeSource` is [`crate::DreSource`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawSource {
    /// The diploma reference, e.g. `"Decreto-Lei n.º 262/86, de 2 de setembro"`.
    pub diploma: String,
    /// The article label, e.g. `"Artigo 255.º"`.
    pub article: String,
    /// The Diário da República publication citation, e.g. `"DR 1.ª série N.º 201, 02-09-1986"`.
    /// `None` while `Pending`. Required for `Verified`.
    pub dr_reference: Option<String>,
    /// The publication date (`YYYY-MM-DD`). `None` while `Pending`.
    pub dr_date: Option<String>,
    /// The authoritative URL (DRE ELI / `files.dre.pt` PDF / EUR-Lex). `None` while `Pending`.
    /// Required for `Verified`.
    pub url: Option<String>,
    /// sha256 (lowercase hex) of the vendored source artifact, when one was pinned. Additive and
    /// optional (like `CaeProvenance`); omitted from serialized output when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<String>,
    /// When the source was retrieved (RFC 3339). Additive/optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieved_at: Option<String>,
    /// The review method that produced an [`Verification::AutomatedReview`] body — e.g.
    /// `"automated-capture"`. Records that the text came from an automated (non-human) process.
    /// Additive/optional; a human-`Verified` or `Pending` article omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_method: Option<String>,
    /// The standing honest caveat carried by [`Verification::AutomatedReview`] text: automated
    /// review only, **NOT** human-legally-approved, human legal review recommended before reliance.
    /// Additive/optional; omitted from serialized output when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_note: Option<String>,
}

impl LawSource {
    /// A structural-only source for a `Pending` article: diploma + article known, authenticity
    /// fields still empty (so it is intentionally **not** [`complete`](Self::is_complete)).
    pub fn pending(diploma: impl Into<String>, article: impl Into<String>) -> Self {
        Self {
            diploma: diploma.into(),
            article: article.into(),
            dr_reference: None,
            dr_date: None,
            url: None,
            source_digest: None,
            retrieved_at: None,
            review_method: None,
            review_note: None,
        }
    }

    /// Whether this source cites a complete authentic origin — the precondition for a `Verified`
    /// article. Requires a non-empty `diploma`, `article`, `dr_reference` and `url`.
    pub fn is_complete(&self) -> bool {
        !self.diploma.trim().is_empty()
            && !self.article.trim().is_empty()
            && self
                .dr_reference
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
            && self.url.as_deref().is_some_and(|s| !s.trim().is_empty())
    }
}

/// One article of a diploma. The frozen unit E1b fills and E2/E3 render.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawArticle {
    /// The owning diploma's [`LawDiploma::id`] (denormalized so a hit carries its diploma).
    pub diploma_id: String,
    /// Canonical article key: `"255"`, `"270-A"`, `"1438-A"`, `"399"`.
    pub number: String,
    /// Printed label: `"Artigo 255.º"`, `"Artigo 270.º-A"`.
    pub label: String,
    /// The epígrafe, e.g. `"Remuneração dos gerentes"`. May be empty on a `Pending` slot whose
    /// epígrafe E1b will vendor from the authentic source.
    pub heading: String,
    /// The FULL verbatim article text once `Verified`; empty while `Pending`. Never displayed
    /// directly for a `Pending` article — use [`display_body`](Self::display_body).
    pub body: String,
    /// Per-article provenance; must be [`complete`](LawSource::is_complete) for `Verified`.
    pub source: LawSource,
    /// Whether `body` is authentic (`Verified`) or a placeholder (`Pending`).
    pub verification: Verification,
    /// Related articles, as `"<diploma_id>:<number>"` keys (e.g. `"csc:399"`). Optional.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_refs: Vec<String>,
}

impl LawArticle {
    /// Whether this article is HUMAN-approved authentic text ([`Verification::Verified`]). This is
    /// the strict human-approval predicate — an [`Verification::AutomatedReview`] article is **not**
    /// `is_verified()`, because it makes the weaker, honest automated-review claim.
    pub fn is_verified(&self) -> bool {
        matches!(self.verification, Verification::Verified)
    }

    /// Whether this article is automated-review authentic text ([`Verification::AutomatedReview`]):
    /// vendored + automatically reviewed, but NOT human-legally-approved.
    pub fn is_automated_review(&self) -> bool {
        matches!(self.verification, Verification::AutomatedReview)
    }

    /// Whether this article carries a rendered `body` (either human-`Verified` or
    /// automated-review), as opposed to a `Pending` placeholder.
    pub fn has_body_text(&self) -> bool {
        !matches!(self.verification, Verification::Pending)
    }

    /// The body to render/return: the verbatim text when the article carries body text
    /// ([`Verification::Verified`] or [`Verification::AutomatedReview`]), otherwise the loud
    /// [`UNVERIFIED_MARKER`]. **Never** returns a `Pending` article's raw (un-sourced) body.
    pub fn display_body(&self) -> &str {
        if self.has_body_text() {
            &self.body
        } else {
            UNVERIFIED_MARKER
        }
    }
}

/// One diploma and its articles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawDiploma {
    /// Stable slug, aligned with `LAW_MANIFEST` / `diplomas.ts` ids (`"csc"`, `"cc"`,
    /// `"dl-268-94"`, `"lei-24-2012"`, `"cod-cooperativo"`, …).
    pub id: String,
    /// The kind of instrument.
    pub kind: DiplomaKind,
    /// The diploma number, e.g. `"262/86"`, `"24/2012"`, `"910/2014"`.
    pub number: String,
    /// Human-facing title (PT).
    pub title: String,
    /// The formal legal reference (PT), e.g. `"Decreto-Lei n.º 262/86, de 2 de setembro"`.
    pub reference: String,
    /// Stable official landing page (DRE ELI resolver / DRE consolidada / EUR-Lex).
    pub official_url: String,
    /// The `data.dre.pt` / EUR-Lex ELI when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eli: Option<String>,
    /// The diploma's articles, priority-cited first.
    pub articles: Vec<LawArticle>,
}
