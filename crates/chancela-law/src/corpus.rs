//! Immutable, indexed view over the corpus plus the integrity + **authenticity** build gate
//! (mirrors [`chancela_cae::CaeCatalog`]).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dataset::{LAW_SCHEMA_VERSION, LawCorpus, LawProvenance};
use crate::error::LawError;
use crate::model::{LawArticle, LawDiploma, Verification};

/// Where the active corpus was loaded from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LawOrigin {
    Embedded,
    Cache,
}

/// Per-corpus counts (the structural handle for E2/tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawCounts {
    pub diplomas: u32,
    pub articles: u32,
    /// Human-approved authentic articles ([`Verification::Verified`]).
    pub verified: u32,
    /// Automated-review authentic articles ([`Verification::AutomatedReview`]) — vendored + auto
    /// reviewed, NOT human-legally-approved. Additive/defaulted so older serialized counts parse.
    #[serde(default)]
    pub automated_review: u32,
    /// Placeholder articles with no vendored text ([`Verification::Pending`]).
    pub pending: u32,
}

/// Provenance + integrity metadata for a loaded corpus.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawMetadata {
    pub schema_version: u32,
    pub generated_at: String,
    pub source_note: String,
    pub digest: String,
    pub origin: LawOrigin,
    pub counts: LawCounts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<LawProvenance>,
}

/// Immutable, indexed view over the corpus's diplomas + articles plus provenance metadata.
#[derive(Clone, Debug)]
pub struct LawCatalog {
    diplomas: Vec<LawDiploma>,
    /// `diploma_id` → index into `diplomas`.
    diploma_index: HashMap<String, usize>,
    /// `(diploma_id, article_number)` → `(diploma index, article index)`.
    article_index: HashMap<(String, String), (usize, usize)>,
    metadata: LawMetadata,
}

impl LawCatalog {
    /// The compiled-in corpus, parsed and validated once (`OnceLock` over the embedded JSON).
    ///
    /// Panics only if the embedded corpus is corrupt or violates the authenticity gate — a
    /// build-time invariant the tests guarantee, so callers treat this as infallible.
    pub fn embedded() -> &'static LawCatalog {
        static EMBEDDED: OnceLock<LawCatalog> = OnceLock::new();
        EMBEDDED.get_or_init(|| {
            let corpus = LawCorpus::embedded().expect("embedded law corpus must parse");
            LawCatalog::from_corpus(corpus).expect("embedded law corpus must pass integrity")
        })
    }

    /// Build + validate a catalog from a corpus. Enforces the **authenticity gate** (no `Verified`
    /// article without a complete [`LawSource`](crate::LawSource)) plus structural integrity
    /// (unique article keys per diploma, matching `diploma_id`). Reports [`LawOrigin::Embedded`].
    pub fn from_corpus(corpus: LawCorpus) -> Result<Self, LawError> {
        Self::from_corpus_with_origin(corpus, LawOrigin::Embedded)
    }

    pub(crate) fn from_corpus_with_origin(
        corpus: LawCorpus,
        origin: LawOrigin,
    ) -> Result<Self, LawError> {
        let counts = validate(&corpus)?;
        let digest = compute_digest(&corpus);
        let provenance = corpus.provenance;

        let diplomas = corpus.diplomas;
        let mut diploma_index = HashMap::with_capacity(diplomas.len());
        let mut article_index = HashMap::new();
        for (di, d) in diplomas.iter().enumerate() {
            diploma_index.insert(d.id.clone(), di);
            for (ai, a) in d.articles.iter().enumerate() {
                article_index.insert((d.id.clone(), a.number.clone()), (di, ai));
            }
        }

        Ok(Self {
            diplomas,
            diploma_index,
            article_index,
            metadata: LawMetadata {
                schema_version: corpus.schema_version,
                generated_at: corpus.generated_at,
                source_note: corpus.source_note,
                digest,
                origin,
                counts,
                provenance,
            },
        })
    }

    /// All diplomas, in corpus order.
    pub fn diplomas(&self) -> &[LawDiploma] {
        &self.diplomas
    }

    /// Resolve a diploma by its slug.
    pub fn diploma(&self, id: &str) -> Option<&LawDiploma> {
        self.diploma_index.get(id).map(|&i| &self.diplomas[i])
    }

    /// The articles of a diploma, in stored order. Empty slice if the diploma is unknown.
    pub fn articles_for(&self, diploma_id: &str) -> &[LawArticle] {
        self.diploma(diploma_id)
            .map(|d| d.articles.as_slice())
            .unwrap_or(&[])
    }

    /// Resolve one article by diploma slug + canonical number (`"255"`, `"270-A"`).
    pub fn article(&self, diploma_id: &str, number: &str) -> Option<&LawArticle> {
        self.article_index
            .get(&(diploma_id.to_owned(), number.to_owned()))
            .map(|&(di, ai)| &self.diplomas[di].articles[ai])
    }

    /// Accent+case-folded substring search over `label + heading + body + diploma.title +
    /// diploma.reference`, returning matching articles in corpus order. Searches article **bodies**
    /// ("everything") once vendored; a `Pending` article (empty body) still matches on its heading
    /// / label / diploma text. Blank query → no results. Fold matches `diplomas.ts::foldForSearch`.
    pub fn search(&self, query: &str) -> Vec<&LawArticle> {
        let needle = fold(query.trim());
        if needle.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for d in &self.diplomas {
            let diploma_ctx = fold(&format!("{} {}", d.title, d.reference));
            for a in &d.articles {
                let hay = format!("{} {} {} {}", a.label, a.heading, a.body, diploma_ctx);
                if fold(&hay).contains(&needle) {
                    out.push(a);
                }
            }
        }
        out
    }

    /// The active corpus's provenance + integrity metadata.
    pub fn metadata(&self) -> &LawMetadata {
        &self.metadata
    }
}

impl Default for LawCatalog {
    fn default() -> Self {
        Self::embedded().clone()
    }
}

/// Validate the corpus and return its counts. The **authenticity gate**: a `Verified` article MUST
/// have a complete [`LawSource`](crate::LawSource). Also enforces unique `(diploma_id, number)`
/// keys and that each article's `diploma_id` matches its owning diploma.
fn validate(corpus: &LawCorpus) -> Result<LawCounts, LawError> {
    let mut seen: HashMap<(&str, &str), ()> = HashMap::new();
    let mut counts = LawCounts {
        diplomas: 0,
        articles: 0,
        verified: 0,
        automated_review: 0,
        pending: 0,
    };
    for d in &corpus.diplomas {
        counts.diplomas += 1;
        for a in &d.articles {
            counts.articles += 1;
            if a.diploma_id != d.id {
                return Err(LawError::Integrity(format!(
                    "article {} declares diploma_id {:?} but sits under diploma {:?}",
                    a.label, a.diploma_id, d.id
                )));
            }
            if seen.insert((&d.id, &a.number), ()).is_some() {
                return Err(LawError::Integrity(format!(
                    "duplicate article key {}:{}",
                    d.id, a.number
                )));
            }
            match a.verification {
                Verification::Verified => {
                    if !a.source.is_complete() {
                        return Err(LawError::Integrity(format!(
                            "article {}:{} is Verified but its source is incomplete \
                             (needs diploma + article + dr_reference + url)",
                            d.id, a.number
                        )));
                    }
                    if a.body.trim().is_empty() {
                        return Err(LawError::Integrity(format!(
                            "article {}:{} is Verified but its body is empty",
                            d.id, a.number
                        )));
                    }
                    counts.verified += 1;
                }
                Verification::AutomatedReview => {
                    // AutomatedReview carries real vendored text, so it is held to the SAME
                    // structural authenticity gate as Verified (complete source + non-empty body).
                    // It only makes a weaker claim about *who* reviewed it (an automated process,
                    // not a human legal reviewer) — that distinction lives in the tier itself and
                    // the source's review_method/review_note, not in a relaxed source check.
                    if !a.source.is_complete() {
                        return Err(LawError::Integrity(format!(
                            "article {}:{} is AutomatedReview but its source is incomplete \
                             (needs diploma + article + dr_reference + url)",
                            d.id, a.number
                        )));
                    }
                    if a.body.trim().is_empty() {
                        return Err(LawError::Integrity(format!(
                            "article {}:{} is AutomatedReview but its body is empty",
                            d.id, a.number
                        )));
                    }
                    counts.automated_review += 1;
                }
                Verification::Pending => counts.pending += 1,
            }
        }
    }
    Ok(counts)
}

/// A deterministic, order-independent sha256 of the corpus content (lowercase hex).
fn compute_digest(corpus: &LawCorpus) -> String {
    let mut rows: Vec<String> = Vec::new();
    for d in &corpus.diplomas {
        for a in &d.articles {
            rows.push(format!(
                "{}\t{}\t{}\t{}\t{:?}\t{}",
                d.id, a.number, a.label, a.heading, a.verification, a.body
            ));
        }
    }
    rows.sort();
    let mut hasher = Sha256::new();
    hasher.update(corpus.schema_version.to_le_bytes());
    for row in rows {
        hasher.update(row.as_bytes());
        hasher.update(b"\n");
    }
    let mut hex = String::with_capacity(64);
    for b in hasher.finalize() {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Accent+case fold for accent-insensitive search — the same fold idiom as
/// `chancela-cae`'s `fold` and `diplomas.ts::foldForSearch` (NFD → strip diacritics → lowercase).
fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ã' | 'ä' | 'Á' | 'À' | 'Â' | 'Ã' | 'Ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'i',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' | 'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'o',
            'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'u',
            'ç' | 'Ç' => 'c',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

/// `LAW_SCHEMA_VERSION` is re-exported at the crate root; assert the corpus matches so a silent
/// schema drift is caught at compile-adjacent test time rather than at runtime.
const _: () = assert!(LAW_SCHEMA_VERSION == 1);
