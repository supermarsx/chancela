//! Lightweight, backend-neutral full-search primitives.
//!
//! This crate deliberately has no database, async-runtime, HTTP, or Chancela-domain dependency.
//! The store persists [`SearchDocument`] values for both SQLite and PostgreSQL; the API's dedicated
//! worker projects domain state into them and applies [`IndexOperation`] batches. Query requests
//! use this in-memory inverted index, keeping request reads independent of database-specific FTS
//! extensions and keeping the normal build graph small.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

/// Bounded operational controls shared by the API and dedicated full-search projector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SearchSettings {
    pub enabled: bool,
    pub index_threads: u32,
    pub batch_size: u32,
    pub interval_seconds: u32,
    pub queue_capacity: u32,
    pub result_limit: u32,
    pub snippet_chars: u32,
    pub facet_limit: u32,
    pub max_content_chars: u32,
    pub max_total_content_chars: u64,
    pub event_retention_days: u32,
    pub min_query_chars: u8,
}

impl Default for SearchSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            index_threads: 2,
            batch_size: 256,
            interval_seconds: 30,
            queue_capacity: 64,
            result_limit: 100,
            snippet_chars: 240,
            facet_limit: 50,
            max_content_chars: 200_000,
            max_total_content_chars: 25_000_000,
            event_retention_days: 3_650,
            min_query_chars: 2,
        }
    }
}

/// Invalid shared search runtime policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchSettingsError(String);

impl std::fmt::Display for SearchSettingsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SearchSettingsError {}

impl SearchSettings {
    pub fn validate(&self) -> Result<(), SearchSettingsError> {
        for (field, value, min, max) in [
            ("search.index_threads", self.index_threads, 2, 16),
            ("search.batch_size", self.batch_size, 16, 5_000),
            ("search.interval_seconds", self.interval_seconds, 5, 86_400),
            ("search.queue_capacity", self.queue_capacity, 1, 1_024),
            ("search.result_limit", self.result_limit, 1, 500),
            ("search.snippet_chars", self.snippet_chars, 32, 2_000),
            ("search.facet_limit", self.facet_limit, 1, 200),
            (
                "search.max_content_chars",
                self.max_content_chars,
                1_000,
                1_000_000,
            ),
            (
                "search.event_retention_days",
                self.event_retention_days,
                1,
                36_500,
            ),
        ] {
            if !(min..=max).contains(&value) {
                return Err(SearchSettingsError(format!(
                    "{field} must be between {min} and {max}, got {value}"
                )));
            }
        }
        if !(2..=8).contains(&self.min_query_chars) {
            return Err(SearchSettingsError(format!(
                "search.min_query_chars must be between 2 and 8, got {}",
                self.min_query_chars
            )));
        }
        if !(100_000..=100_000_000).contains(&self.max_total_content_chars) {
            return Err(SearchSettingsError(format!(
                "search.max_total_content_chars must be between 100000 and 100000000, got {}",
                self.max_total_content_chars
            )));
        }
        Ok(())
    }
}

/// Minimal non-secret settings needed before an external projector hydrates the corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalSearchProjectorConfig {
    pub enabled: bool,
    pub index_threads: u32,
    pub interval_seconds: u32,
}

impl From<&SearchSettings> for ExternalSearchProjectorConfig {
    fn from(settings: &SearchSettings) -> Self {
        Self {
            enabled: settings.enabled,
            index_threads: settings.index_threads,
            interval_seconds: settings.interval_seconds,
        }
    }
}

/// A searchable corpus family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchKind {
    Act,
    Entity,
    Book,
    Template,
    LawArticle,
    OperationalAction,
    LedgerEvent,
    FollowUp,
    ImportedDocument,
    PaperBook,
    OcrDraft,
    GeneratedDocument,
}

impl SearchKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Act => "act",
            Self::Entity => "entity",
            Self::Book => "book",
            Self::Template => "template",
            Self::LawArticle => "law_article",
            Self::OperationalAction => "operational_action",
            Self::LedgerEvent => "ledger_event",
            Self::FollowUp => "follow_up",
            Self::ImportedDocument => "imported_document",
            Self::PaperBook => "paper_book",
            Self::OcrDraft => "ocr_draft",
            Self::GeneratedDocument => "generated_document",
        }
    }
}

impl std::fmt::Display for SearchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One durable search projection. IDs are namespace-qualified (`act:<uuid>`, `event:<seq>`, …), so
/// unrelated source families can never overwrite one another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchDocument {
    pub id: String,
    pub kind: SearchKind,
    /// Isolation metadata. Global reference data deliberately leaves this absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub book_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub book_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act_id: Option<String>,
    pub title: String,
    pub body: String,
    /// True when the worker intentionally indexed only the configured leading portion of the
    /// source. The source record remains intact; callers can label this hit as partial content.
    #[serde(default)]
    pub content_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub law: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Optional stable dotted permission id for source families whose rows have heterogeneous
    /// domain gates (for example Action Center actionables). The API interprets it fail-closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_permission: Option<String>,
    /// RFC 3339 timestamp or ISO date. Lexical ordering is chronological for both canonical forms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    /// Stable source revision/digest. It participates in equality so a worker can detect changed
    /// projections without rewriting identical rows.
    pub source_version: String,
    /// Full-fidelity searchable fields for callers whose effective authority is not classified as
    /// guest/read-only-minimal. Keeping this projection explicit lets the API select a privacy tier
    /// before candidate scoring, snippets, filters, or facets are produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<SearchDocumentContent>,
}

/// The fields whose visibility and searchability vary with the caller's read-redaction tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchDocumentContent {
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub content_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub book_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub law: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Search projection selected only after the API has authorized the source row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchAccess {
    Public,
    Privileged,
}

/// Incremental mutation sent by the worker to both the durable and in-memory index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexOperation {
    Upsert(Box<SearchDocument>),
    Delete(String),
}

/// Durable command consumed by either the embedded indexer or a separately deployed projector.
///
/// Commands carry a monotonically increasing generation in [`SearchProjectionControl`], so two
/// identical consecutive requests (for example two explicit rebuilds) remain distinguishable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchProjectionCommand {
    /// Reconcile the durable projection with the current authoritative sources.
    #[default]
    Reconcile,
    /// Rebuild the complete projection even when source digests look unchanged.
    Rebuild,
    /// Stop projection work while retaining the last completed generation for queries.
    Pause,
}

impl SearchProjectionCommand {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reconcile => "reconcile",
            Self::Rebuild => "rebuild",
            Self::Pause => "pause",
        }
    }
}

impl std::fmt::Display for SearchProjectionCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Optimistic source snapshot token used by a projector build.
///
/// A projector captures this before reading its corpus. Publication succeeds only if every field
/// still matches, which rejects a mixed/stale build after an authoritative commit, destructive
/// fence, or newer operator command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchProjectionCheckpoint {
    pub source_revision: u64,
    pub fence_token: u64,
    pub command_generation: u64,
}

/// Cross-process projector lease stored beside the durable projection control row.
///
/// `lease_id` is an opaque fencing token minted for each acquisition. A previous holder cannot
/// heartbeat or publish after expiry/takeover even when it reuses the same human-readable owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchProjectorLease {
    pub lease_id: String,
    pub owner: String,
    pub heartbeat_at: String,
    pub expires_at_unix_ms: i64,
    pub checkpoint: SearchProjectionCheckpoint,
}

/// Durable cross-process projection coordination state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchProjectionControl {
    pub checkpoint: SearchProjectionCheckpoint,
    /// Checkpoint of the last generation that committed all projection rows and lifecycle state.
    /// `None` means no completed generation is safe for the current store (fresh install, restore,
    /// destructive fence, or an interrupted initial build).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_checkpoint: Option<SearchProjectionCheckpoint>,
    pub command: SearchProjectionCommand,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<SearchProjectorLease>,
    pub updated_at: String,
}

/// Why an attempted compare-and-swap projection publication was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchProjectionPublishRejection {
    /// The lease expired, was released, or was replaced by another projector instance.
    LeaseLost,
    /// An authoritative transaction committed after the projector captured its corpus checkpoint.
    SourceChanged,
    /// A destructive/security fence changed while the projector was building.
    FenceChanged,
    /// A newer pause/rebuild/reconcile command superseded the in-flight build.
    CommandChanged,
    /// Projection work is durably paused.
    Paused,
}

/// Result of the atomic, lease-validated durable projection publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum SearchProjectionPublishOutcome {
    Published {
        checkpoint: SearchProjectionCheckpoint,
        generation: u64,
        document_count: u64,
    },
    Rejected {
        reason: SearchProjectionPublishRejection,
        control: SearchProjectionControl,
    },
}

/// Durable lifecycle/progress state. The API adds live queue depth and computes freshness from the
/// configured interval, but every rebuild/error boundary survives process restart here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchIndexState {
    pub phase: SearchIndexPhase,
    /// Durable fail-closed tombstone installed before authoritative data is reset or restored.
    #[serde(default)]
    pub projection_fenced: bool,
    pub generation: u64,
    pub document_count: u64,
    /// Number of current projections whose searchable body was capped by policy.
    #[serde(default)]
    pub truncated_document_count: u64,
    /// Total searchable body characters retained in the completed durable generation.
    #[serde(default)]
    pub indexed_content_chars: u64,
    /// True when the corpus-wide character budget truncated one or more projections.
    #[serde(default)]
    pub content_budget_exhausted: bool,
    pub processed: u64,
    pub total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_at: Option<String>,
    pub updated_at: String,
}

impl Default for SearchIndexState {
    fn default() -> Self {
        Self {
            phase: SearchIndexPhase::Starting,
            projection_fenced: false,
            generation: 0,
            document_count: 0,
            truncated_document_count: 0,
            indexed_content_chars: 0,
            content_budget_exhausted: false,
            processed: 0,
            total: 0,
            last_event_seq: None,
            last_started_at: None,
            last_completed_at: None,
            last_error: None,
            error_at: None,
            updated_at: "1970-01-01T00:00:00Z".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchIndexPhase {
    Starting,
    Idle,
    Reconciling,
    Rebuilding,
    Paused,
    Disabled,
    Error,
    ShuttingDown,
}

impl SearchIndexPhase {
    #[must_use]
    pub const fn is_partial(self) -> bool {
        matches!(self, Self::Starting | Self::Reconciling | Self::Rebuilding)
    }
}

/// Exact metadata filters. Text values are case/diacritic folded before comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchFilters {
    pub kinds: BTreeSet<SearchKind>,
    pub tenant_id: Option<String>,
    pub entity_id: Option<String>,
    pub book_id: Option<String>,
    pub act_id: Option<String>,
    pub author: Option<String>,
    pub law: Option<String>,
    pub status: Option<String>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    pub text: String,
    pub filters: SearchFilters,
    pub offset: usize,
    pub limit: usize,
    pub snippet_chars: usize,
    /// Maximum distinct values retained per facet. Highest counts win, then lexical value.
    pub facet_limit: usize,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            text: String::new(),
            filters: SearchFilters::default(),
            offset: 0,
            limit: 100,
            snippet_chars: 240,
            facet_limit: 50,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchHit {
    pub id: String,
    pub kind: SearchKind,
    pub title: String,
    pub snippet: String,
    pub content_truncated: bool,
    pub score: u32,
    pub tenant_id: Option<String>,
    pub entity_id: Option<String>,
    pub entity_name: Option<String>,
    pub book_id: Option<String>,
    pub book_label: Option<String>,
    pub act_id: Option<String>,
    pub author: Option<String>,
    pub law: Option<String>,
    pub status: Option<String>,
    pub occurred_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SearchFacets {
    pub kind: BTreeMap<String, usize>,
    pub date: BTreeMap<String, usize>,
    /// Stable entity id -> display label + authorized result count.
    pub entity: BTreeMap<String, LabeledFacetCount>,
    /// Stable book id -> display label + authorized result count.
    pub book: BTreeMap<String, LabeledFacetCount>,
    pub author: BTreeMap<String, usize>,
    pub law: BTreeMap<String, usize>,
    pub status: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LabeledFacetCount {
    pub label: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchPage {
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
    pub hits: Vec<SearchHit>,
    pub facets: SearchFacets,
    /// True when high-cardinality facet-key discovery exceeded its bounded candidate budget. Counts
    /// on returned keys are still exact (a second pass recomputes them); undisplayed keys may exist.
    pub facets_truncated: bool,
}

#[derive(Debug, Clone)]
struct IndexedDocument {
    document: SearchDocument,
    public: IndexedContent,
    privileged: Option<IndexedContent>,
    tokens: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct IndexedContent {
    normalized_title: String,
    normalized_body: String,
    tokens: BTreeSet<String>,
}

impl IndexedContent {
    fn new(title: &str, body: &str) -> Self {
        let normalized_title = normalize(title);
        let normalized_body = normalize(body);
        let tokens = tokenize(&format!("{normalized_title} {normalized_body}"))
            .into_iter()
            .collect();
        Self {
            normalized_title,
            normalized_body,
            tokens,
        }
    }

    fn matches_token(&self, query_token: &str) -> bool {
        self.tokens.contains(query_token)
            || (query_token.chars().count() >= 3
                && self.tokens.iter().any(|token| token.contains(query_token)))
    }
}

impl IndexedDocument {
    fn new(document: SearchDocument) -> Self {
        let public = IndexedContent::new(&document.title, &document.body);
        let privileged = document
            .privileged
            .as_ref()
            .map(|content| IndexedContent::new(&content.title, &content.body));
        let mut tokens = public.tokens.clone();
        if let Some(content) = &privileged {
            tokens.extend(content.tokens.iter().cloned());
        }
        Self {
            document,
            public,
            privileged,
            tokens,
        }
    }

    fn projection(&self, access: SearchAccess) -> (&IndexedContent, SearchContentRef<'_>) {
        if access == SearchAccess::Privileged
            && let (Some(indexed), Some(content)) =
                (&self.privileged, self.document.privileged.as_ref())
        {
            return (indexed, SearchContentRef::Privileged(content));
        }
        (&self.public, SearchContentRef::Public(&self.document))
    }
}

#[derive(Clone, Copy)]
enum SearchContentRef<'a> {
    Public(&'a SearchDocument),
    Privileged(&'a SearchDocumentContent),
}

#[derive(Clone, Copy)]
struct RankedCandidate<'a> {
    score: u32,
    indexed: &'a IndexedDocument,
    access: SearchAccess,
}

impl PartialEq for RankedCandidate<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score && self.indexed.document.id == other.indexed.document.id
    }
}

impl Eq for RankedCandidate<'_> {}

impl PartialOrd for RankedCandidate<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RankedCandidate<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .cmp(&self.score)
            .then_with(|| {
                other
                    .indexed
                    .document
                    .occurred_at
                    .cmp(&self.indexed.document.occurred_at)
            })
            .then_with(|| self.indexed.document.id.cmp(&other.indexed.document.id))
    }
}

impl<'a> SearchContentRef<'a> {
    fn title(self) -> &'a str {
        match self {
            Self::Public(document) => &document.title,
            Self::Privileged(content) => &content.title,
        }
    }

    fn body(self) -> &'a str {
        match self {
            Self::Public(document) => &document.body,
            Self::Privileged(content) => &content.body,
        }
    }

    fn content_truncated(self) -> bool {
        match self {
            Self::Public(document) => document.content_truncated,
            Self::Privileged(content) => content.content_truncated,
        }
    }

    fn entity_name(self) -> Option<&'a str> {
        match self {
            Self::Public(document) => document.entity_name.as_deref(),
            Self::Privileged(content) => content.entity_name.as_deref(),
        }
    }

    fn book_label(self) -> Option<&'a str> {
        match self {
            Self::Public(document) => document.book_label.as_deref(),
            Self::Privileged(content) => content.book_label.as_deref(),
        }
    }

    fn author(self) -> Option<&'a str> {
        match self {
            Self::Public(document) => document.author.as_deref(),
            Self::Privileged(content) => content.author.as_deref(),
        }
    }

    fn law(self) -> Option<&'a str> {
        match self {
            Self::Public(document) => document.law.as_deref(),
            Self::Privileged(content) => content.law.as_deref(),
        }
    }

    fn status(self) -> Option<&'a str> {
        match self {
            Self::Public(document) => document.status.as_deref(),
            Self::Privileged(content) => content.status.as_deref(),
        }
    }
}

/// Mutable inverted index. Upsert/delete are proportional to one document; query candidate
/// selection intersects token postings before ranking, avoiding a full corpus scan for ordinary
/// terms even at tens of thousands of books/acts.
#[derive(Debug, Default)]
pub struct InMemoryIndex {
    documents: HashMap<String, IndexedDocument>,
    postings: HashMap<String, BTreeSet<String>>,
    grams: HashMap<String, BTreeSet<String>>,
    ordered_ids: BTreeSet<String>,
}

impl InMemoryIndex {
    #[must_use]
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    pub fn upsert(&mut self, document: SearchDocument) {
        self.delete(&document.id);
        let indexed = IndexedDocument::new(document);
        let id = indexed.document.id.clone();
        for token in &indexed.tokens {
            self.postings
                .entry(token.clone())
                .or_default()
                .insert(id.clone());
            for gram in token_grams(token) {
                self.grams.entry(gram).or_default().insert(id.clone());
            }
        }
        self.ordered_ids.insert(id.clone());
        self.documents.insert(id, indexed);
    }

    pub fn delete(&mut self, id: &str) -> bool {
        let Some(previous) = self.documents.remove(id) else {
            return false;
        };
        let mut empty = Vec::new();
        for token in previous.tokens {
            if let Some(ids) = self.postings.get_mut(&token) {
                ids.remove(id);
                if ids.is_empty() {
                    empty.push(token.clone());
                }
            }
            for gram in token_grams(&token) {
                let remove_gram = if let Some(ids) = self.grams.get_mut(&gram) {
                    ids.remove(id);
                    ids.is_empty()
                } else {
                    false
                };
                if remove_gram {
                    self.grams.remove(&gram);
                }
            }
        }
        for token in empty {
            self.postings.remove(&token);
        }
        self.ordered_ids.remove(id);
        true
    }

    pub fn apply(&mut self, operations: impl IntoIterator<Item = IndexOperation>) {
        for operation in operations {
            match operation {
                IndexOperation::Upsert(document) => self.upsert(*document),
                IndexOperation::Delete(id) => {
                    self.delete(&id);
                }
            }
        }
    }

    pub fn replace(&mut self, documents: impl IntoIterator<Item = SearchDocument>) {
        self.documents.clear();
        self.postings.clear();
        self.grams.clear();
        self.ordered_ids.clear();
        for document in documents {
            self.upsert(document);
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<SearchDocument> {
        let mut documents: Vec<SearchDocument> = self
            .documents
            .values()
            .map(|indexed| indexed.document.clone())
            .collect();
        documents.sort_by(|left, right| left.id.cmp(&right.id));
        documents
    }

    /// Deterministic ids without cloning document bodies, used by incremental reconciliation to
    /// find deletions while keeping peak memory proportional to the explicit corpus budget.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        self.ordered_ids.iter().cloned().collect()
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&SearchDocument> {
        self.documents.get(id).map(|indexed| &indexed.document)
    }

    #[must_use]
    pub fn search(&self, query: &SearchQuery) -> SearchPage {
        self.search_with_access(query, |_| Some(SearchAccess::Privileged))
    }

    /// Search while applying a caller-owned authorization predicate before a row contributes to
    /// either hits or facets. This ordering is load-bearing: a forbidden row cannot leak through a
    /// facet count even when it is outside the returned page.
    #[must_use]
    pub fn search_with(
        &self,
        query: &SearchQuery,
        mut allowed: impl FnMut(&SearchDocument) -> bool,
    ) -> SearchPage {
        self.search_with_access(query, |document| {
            allowed(document).then_some(SearchAccess::Public)
        })
    }

    /// Search while selecting the caller-visible content tier before text scoring, metadata
    /// filtering, snippets, or facets. `None` excludes a row entirely; forbidden/private fields
    /// therefore cannot influence any observable result aggregate.
    #[must_use]
    pub fn search_with_access(
        &self,
        query: &SearchQuery,
        mut access: impl FnMut(&SearchDocument) -> Option<SearchAccess>,
    ) -> SearchPage {
        let normalized_query = normalize(query.text.trim());
        let query_tokens = tokenize(&normalized_query);
        // One-character fuzzy/prefix queries would require scanning the complete token vocabulary
        // while producing very low-signal results. Treat them as no match; the API returns a
        // client-actionable validation error before reaching this seam.
        if !normalized_query.is_empty()
            && query_tokens.iter().any(|token| token.chars().count() < 2)
        {
            return SearchPage {
                total: 0,
                offset: query.offset,
                limit: query.limit.max(1),
                has_more: false,
                hits: Vec::new(),
                facets: SearchFacets::default(),
                facets_truncated: false,
            };
        }
        let Some(candidates) = self.candidate_ids(&query_tokens) else {
            return SearchPage {
                total: 0,
                offset: query.offset,
                limit: query.limit.max(1),
                has_more: false,
                hits: Vec::new(),
                facets: SearchFacets::default(),
                facets_truncated: false,
            };
        };
        let limit = query.limit.max(1);
        let retained_limit = query.offset.saturating_add(limit);
        let mut ranked = BinaryHeap::with_capacity(retained_limit.min(candidates.len()));
        let mut total = 0usize;
        let mut facets = SearchFacets::default();
        let mut facets_truncated = false;
        let facet_capacity = query.facet_limit.max(1).saturating_mul(4).clamp(4, 4_096);

        for id in candidates {
            let Some(indexed) = self.documents.get(id) else {
                continue;
            };
            let Some(access) = access(&indexed.document) else {
                continue;
            };
            let (indexed_content, content) = indexed.projection(access);
            if !matches_filters(&indexed.document, content, &query.filters) {
                continue;
            }
            if !query_tokens.is_empty()
                && !query_tokens
                    .iter()
                    .all(|token| indexed_content.matches_token(token))
            {
                continue;
            }
            let score = score(indexed_content, &normalized_query, &query_tokens);
            if !normalized_query.is_empty() && score == 0 {
                continue;
            }
            add_facets(
                &mut facets,
                &indexed.document,
                content,
                facet_capacity,
                &mut facets_truncated,
            );
            total = total.saturating_add(1);
            if retained_limit == 0 {
                continue;
            }
            let candidate = RankedCandidate {
                score,
                indexed,
                access,
            };
            if ranked.len() < retained_limit {
                ranked.push(candidate);
            } else if ranked
                .peek()
                .is_some_and(|worst| candidate.cmp(worst) == Ordering::Less)
            {
                ranked.pop();
                ranked.push(candidate);
            }
        }
        facets_truncated |= facets.exceeds(query.facet_limit.max(1));
        facets.reset_selected_counts();
        for id in candidates {
            let Some(indexed) = self.documents.get(id) else {
                continue;
            };
            let Some(access) = access(&indexed.document) else {
                continue;
            };
            let (indexed_content, content) = indexed.projection(access);
            if !matches_filters(&indexed.document, content, &query.filters) {
                continue;
            }
            if !query_tokens.is_empty()
                && !query_tokens
                    .iter()
                    .all(|token| indexed_content.matches_token(token))
            {
                continue;
            }
            add_selected_facets(&mut facets, &indexed.document, content);
        }
        facets.truncate(query.facet_limit.max(1));

        let mut ranked = ranked.into_vec();
        ranked.sort();
        let hits = ranked
            .into_iter()
            .skip(query.offset)
            .take(limit)
            .map(|candidate| {
                let RankedCandidate {
                    score,
                    indexed,
                    access,
                } = candidate;
                let (_, content) = indexed.projection(access);
                SearchHit {
                    id: indexed.document.id.clone(),
                    kind: indexed.document.kind,
                    title: content.title().to_owned(),
                    snippet: snippet(content.body(), &query_tokens, query.snippet_chars.max(32)),
                    content_truncated: content.content_truncated(),
                    score,
                    tenant_id: indexed.document.tenant_id.clone(),
                    entity_id: indexed.document.entity_id.clone(),
                    entity_name: content.entity_name().map(str::to_owned),
                    book_id: indexed.document.book_id.clone(),
                    book_label: content.book_label().map(str::to_owned),
                    act_id: indexed.document.act_id.clone(),
                    author: content.author().map(str::to_owned),
                    law: content.law().map(str::to_owned),
                    status: content.status().map(str::to_owned),
                    occurred_at: indexed.document.occurred_at.clone(),
                }
            })
            .collect::<Vec<_>>();

        SearchPage {
            total,
            offset: query.offset,
            limit,
            has_more: query.offset.saturating_add(hits.len()) < total,
            hits,
            facets,
            facets_truncated,
        }
    }

    fn candidate_ids(&self, query_tokens: &[String]) -> Option<&BTreeSet<String>> {
        if query_tokens.is_empty() {
            return Some(&self.ordered_ids);
        }
        let mut candidate: Option<&BTreeSet<String>> = None;
        for query_token in query_tokens {
            // A 3-gram narrows arbitrary substring search without scanning the complete token
            // vocabulary or cloning result-id sets. The tier-specific token check below verifies
            // the full query token and intersects every term.
            let token_ids = if let Some(gram) = first_token_gram(query_token) {
                self.grams.get(&gram)?
            } else {
                self.postings.get(query_token)?
            };
            if candidate.is_none_or(|existing| token_ids.len() < existing.len()) {
                candidate = Some(token_ids);
            }
        }
        candidate
    }
}

impl SearchFacets {
    fn reset_selected_counts(&mut self) {
        for count in self.kind.values_mut() {
            *count = 0;
        }
        for count in self.date.values_mut() {
            *count = 0;
        }
        for value in self.entity.values_mut() {
            value.count = 0;
        }
        for value in self.book.values_mut() {
            value.count = 0;
        }
        for count in self.author.values_mut() {
            *count = 0;
        }
        for count in self.law.values_mut() {
            *count = 0;
        }
        for count in self.status.values_mut() {
            *count = 0;
        }
    }

    fn exceeds(&self, limit: usize) -> bool {
        self.kind.len() > limit
            || self.date.len() > limit
            || self.entity.len() > limit
            || self.book.len() > limit
            || self.author.len() > limit
            || self.law.len() > limit
            || self.status.len() > limit
    }

    fn truncate(&mut self, limit: usize) {
        truncate_facet(&mut self.kind, limit);
        truncate_facet(&mut self.date, limit);
        truncate_labeled_facet(&mut self.entity, limit);
        truncate_labeled_facet(&mut self.book, limit);
        truncate_facet(&mut self.author, limit);
        truncate_facet(&mut self.law, limit);
        truncate_facet(&mut self.status, limit);
    }
}

fn increment_selected(map: &mut BTreeMap<String, usize>, value: Option<&str>) {
    if let Some(count) = value.and_then(|value| map.get_mut(value)) {
        *count += 1;
    }
}

fn increment_labeled_selected(map: &mut BTreeMap<String, LabeledFacetCount>, id: Option<&str>) {
    if let Some(value) = id.and_then(|id| map.get_mut(id)) {
        value.count += 1;
    }
}

fn add_selected_facets(
    facets: &mut SearchFacets,
    document: &SearchDocument,
    content: SearchContentRef<'_>,
) {
    increment_selected(&mut facets.kind, Some(document.kind.as_str()));
    increment_selected(
        &mut facets.date,
        document
            .occurred_at
            .as_deref()
            .map(|value| value.get(..10).unwrap_or(value)),
    );
    increment_labeled_selected(&mut facets.entity, document.entity_id.as_deref());
    increment_labeled_selected(&mut facets.book, document.book_id.as_deref());
    increment_selected(&mut facets.author, content.author());
    increment_selected(&mut facets.law, content.law());
    increment_selected(&mut facets.status, content.status());
}

fn truncate_labeled_facet(facet: &mut BTreeMap<String, LabeledFacetCount>, limit: usize) {
    if facet.len() <= limit {
        return;
    }
    let mut ranked: Vec<(String, LabeledFacetCount)> = std::mem::take(facet).into_iter().collect();
    ranked.sort_by(|(left_id, left), (right_id, right)| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left_id.cmp(right_id))
    });
    facet.extend(ranked.into_iter().take(limit));
}

fn truncate_facet(facet: &mut BTreeMap<String, usize>, limit: usize) {
    if facet.len() <= limit {
        return;
    }
    let mut ranked: Vec<(String, usize)> = std::mem::take(facet).into_iter().collect();
    ranked.sort_by(|(left_value, left_count), (right_value, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_value.cmp(right_value))
    });
    facet.extend(ranked.into_iter().take(limit));
}

/// Unicode NFKD case/diacritic folding shared by indexing, filters, snippets, and query terms.
#[must_use]
pub fn normalize(value: &str) -> String {
    value
        .nfkd()
        .flat_map(char::to_lowercase)
        .filter(|character| !is_combining_mark(*character))
        .map(|character| {
            if character.is_whitespace() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn tokenize(value: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .filter_map(|token| {
            let token = token.to_owned();
            seen.insert(token.clone()).then_some(token)
        })
        .collect()
}

fn token_grams(value: &str) -> BTreeSet<String> {
    let characters = value.chars().collect::<Vec<_>>();
    characters
        .windows(3)
        .map(|window| window.iter().collect())
        .collect()
}

fn first_token_gram(value: &str) -> Option<String> {
    let mut characters = value.chars();
    Some(
        [characters.next()?, characters.next()?, characters.next()?]
            .into_iter()
            .collect(),
    )
}

fn score(indexed: &IndexedContent, phrase: &str, tokens: &[String]) -> u32 {
    if phrase.is_empty() {
        return 1;
    }
    let mut score = 0u32;
    if indexed.normalized_title == phrase {
        score += 500;
    } else if indexed.normalized_title.contains(phrase) {
        score += 180;
    }
    if indexed.normalized_body.contains(phrase) {
        score += 90;
    }
    for token in tokens {
        if indexed
            .normalized_title
            .split_whitespace()
            .any(|word| word == token)
        {
            score += 60;
        } else if indexed.normalized_title.contains(token) {
            score += 30;
        }
        let occurrences = indexed.normalized_body.matches(token).count().min(10) as u32;
        score += occurrences * 6;
    }
    score
}

fn matches_filters(
    document: &SearchDocument,
    content: SearchContentRef<'_>,
    filters: &SearchFilters,
) -> bool {
    if !filters.kinds.is_empty() && !filters.kinds.contains(&document.kind) {
        return false;
    }
    for (actual, expected) in [
        (&document.tenant_id, &filters.tenant_id),
        (&document.entity_id, &filters.entity_id),
        (&document.book_id, &filters.book_id),
        (&document.act_id, &filters.act_id),
    ] {
        if expected
            .as_deref()
            .is_some_and(|expected| actual.as_deref() != Some(expected))
        {
            return false;
        }
    }
    for (actual, expected) in [
        (content.author(), filters.author.as_deref()),
        (content.law(), filters.law.as_deref()),
        (content.status(), filters.status.as_deref()),
    ] {
        if let Some(expected) = expected {
            let expected = normalize(expected);
            if actual.is_none_or(|actual| normalize(actual) != expected) {
                return false;
            }
        }
    }
    if filters.date_from.as_ref().is_some_and(|from| {
        document
            .occurred_at
            .as_ref()
            .is_none_or(|actual| actual.as_str() < from.as_str())
    }) {
        return false;
    }
    if filters.date_to.as_ref().is_some_and(|to| {
        document
            .occurred_at
            .as_ref()
            .is_none_or(|actual| actual.as_str() > to.as_str())
    }) {
        return false;
    }
    true
}

fn increment(
    map: &mut BTreeMap<String, usize>,
    value: Option<&str>,
    capacity: usize,
    truncated: &mut bool,
) {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return;
    };
    if let Some(count) = map.get_mut(value) {
        *count += 1;
        return;
    }
    let mut replacement_count = 1;
    if map.len() >= capacity {
        *truncated = true;
        let Some((victim, count)) = map
            .iter()
            .min_by(|(left_value, left_count), (right_value, right_count)| {
                left_count
                    .cmp(right_count)
                    .then_with(|| right_value.cmp(left_value))
            })
            .map(|(value, count)| (value.clone(), *count))
        else {
            return;
        };
        map.remove(&victim);
        replacement_count = count.saturating_add(1);
    }
    map.insert(value.to_owned(), replacement_count);
}

fn increment_labeled(
    map: &mut BTreeMap<String, LabeledFacetCount>,
    id: Option<&str>,
    label: Option<&str>,
    capacity: usize,
    truncated: &mut bool,
) {
    let Some(id) = id.filter(|id| !id.trim().is_empty()) else {
        return;
    };
    if let Some(entry) = map.get_mut(id) {
        entry.count += 1;
        return;
    }
    let label = label
        .filter(|label| !label.trim().is_empty())
        .unwrap_or(id)
        .to_owned();
    let mut replacement_count = 1;
    if map.len() >= capacity {
        *truncated = true;
        let Some((victim, count)) = map
            .iter()
            .min_by(|(left_id, left), (right_id, right)| {
                left.count
                    .cmp(&right.count)
                    .then_with(|| right.label.cmp(&left.label))
                    .then_with(|| right_id.cmp(left_id))
            })
            .map(|(id, value)| (id.clone(), value.count))
        else {
            return;
        };
        map.remove(&victim);
        replacement_count = count.saturating_add(1);
    }
    map.insert(
        id.to_owned(),
        LabeledFacetCount {
            label,
            count: replacement_count,
        },
    );
}

fn add_facets(
    facets: &mut SearchFacets,
    document: &SearchDocument,
    content: SearchContentRef<'_>,
    capacity: usize,
    truncated: &mut bool,
) {
    increment(
        &mut facets.kind,
        Some(document.kind.as_str()),
        capacity,
        truncated,
    );
    increment(
        &mut facets.date,
        document
            .occurred_at
            .as_deref()
            .map(|value| value.get(..10).unwrap_or(value)),
        capacity,
        truncated,
    );
    increment_labeled(
        &mut facets.entity,
        document.entity_id.as_deref(),
        content.entity_name(),
        capacity,
        truncated,
    );
    increment_labeled(
        &mut facets.book,
        document.book_id.as_deref(),
        content.book_label(),
        capacity,
        truncated,
    );
    increment(&mut facets.author, content.author(), capacity, truncated);
    increment(&mut facets.law, content.law(), capacity, truncated);
    increment(&mut facets.status, content.status(), capacity, truncated);
}

fn snippet(body: &str, tokens: &[String], max_chars: usize) -> String {
    if body.chars().count() <= max_chars {
        return body.to_owned();
    }
    let match_byte = first_matching_word_byte(body, tokens).unwrap_or(0);
    let match_char = body[..match_byte].chars().count();
    let total_chars = body.chars().count();
    let half = max_chars / 2;
    let start_char = match_char.saturating_sub(half);
    let end_char = start_char.saturating_add(max_chars).min(total_chars);
    let mut out = String::new();
    if start_char > 0 {
        out.push('…');
    }
    out.extend(body.chars().skip(start_char).take(end_char - start_char));
    if end_char < total_chars {
        out.push('…');
    }
    out
}

fn first_matching_word_byte(body: &str, tokens: &[String]) -> Option<usize> {
    if tokens.is_empty() {
        return Some(0);
    }
    let mut word_start = None;
    for (byte, character) in body.char_indices() {
        if character.is_alphanumeric() {
            word_start.get_or_insert(byte);
        } else if let Some(start) = word_start.take() {
            let folded = normalize(&body[start..byte]);
            if tokens.iter().any(|token| folded.contains(token)) {
                return Some(start);
            }
        }
    }
    word_start.and_then(|start| {
        let folded = normalize(&body[start..]);
        tokens
            .iter()
            .any(|token| folded.contains(token))
            .then_some(start)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(id: &str, kind: SearchKind, title: &str, body: &str) -> SearchDocument {
        SearchDocument {
            id: id.to_owned(),
            kind,
            tenant_id: Some("tenant-a".to_owned()),
            entity_id: Some("entity-a".to_owned()),
            entity_name: Some("Sociedade Árvore".to_owned()),
            book_id: Some("book-a".to_owned()),
            book_label: Some("Livro 1".to_owned()),
            act_id: (kind == SearchKind::Act).then(|| id.trim_start_matches("act:").to_owned()),
            title: title.to_owned(),
            body: body.to_owned(),
            content_truncated: false,
            author: Some("Amélia".to_owned()),
            law: Some("CSC art. 63.º".to_owned()),
            status: Some("sealed".to_owned()),
            required_permission: None,
            occurred_at: Some("2026-07-26T10:00:00Z".to_owned()),
            source_version: "v1".to_owned(),
            privileged: None,
        }
    }

    #[test]
    fn normalization_folds_case_diacritics_and_combining_marks() {
        assert_eq!(normalize("  REUNIÃO  Amélia  "), "reuniao amelia");
        assert_eq!(normalize("Ac\u{0327}a\u{0303}o"), "acao");
    }

    #[test]
    fn title_rank_snippet_filters_and_facets_are_deterministic() {
        let mut index = InMemoryIndex::default();
        index.upsert(document(
            "act:1",
            SearchKind::Act,
            "Reunião extraordinária",
            &format!("{} decisão sobre capital social", "prefixo ".repeat(80)),
        ));
        index.upsert(document(
            "act:2",
            SearchKind::Act,
            "Capital social",
            "A reunião ordinária aprovou o relatório.",
        ));
        index.upsert(document(
            "book:1",
            SearchKind::Book,
            "Livro de atas",
            "Reunião extraordinária arquivada.",
        ));

        let page = index.search(&SearchQuery {
            text: "reuniao extraordinaria".to_owned(),
            filters: SearchFilters {
                kinds: [SearchKind::Act].into_iter().collect(),
                author: Some("AMELIA".to_owned()),
                ..SearchFilters::default()
            },
            offset: 0,
            limit: 10,
            snippet_chars: 80,
            facet_limit: 10,
        });

        assert_eq!(page.total, 1);
        assert_eq!(page.hits[0].id, "act:1");
        assert!(
            page.hits[0].snippet.contains("decisão") || page.hits[0].snippet.contains("prefixo")
        );
        assert_eq!(page.facets.kind.get("act"), Some(&1));
        assert_eq!(page.facets.author.get("Amélia"), Some(&1));
        assert_eq!(page.facets.date.get("2026-07-26"), Some(&1));
        assert_eq!(
            page.facets.entity.get("entity-a"),
            Some(&LabeledFacetCount {
                label: "Sociedade Árvore".to_owned(),
                count: 1,
            })
        );
        assert_eq!(
            page.facets.book.get("book-a"),
            Some(&LabeledFacetCount {
                label: "Livro 1".to_owned(),
                count: 1,
            })
        );
    }

    #[test]
    fn incremental_upsert_and_delete_keep_postings_consistent() {
        let mut index = InMemoryIndex::default();
        index.upsert(document("act:1", SearchKind::Act, "Primeira", "alpha"));
        assert_eq!(
            index
                .search(&SearchQuery {
                    text: "alpha".to_owned(),
                    ..SearchQuery::default()
                })
                .total,
            1
        );
        index.upsert(document("act:1", SearchKind::Act, "Segunda", "beta"));
        assert_eq!(
            index
                .search(&SearchQuery {
                    text: "alpha".to_owned(),
                    ..SearchQuery::default()
                })
                .total,
            0
        );
        assert!(index.delete("act:1"));
        assert!(index.is_empty());
        assert!(index.postings.is_empty());
    }

    #[test]
    fn fifty_thousand_documents_remain_bounded_by_requested_page() {
        let started = std::time::Instant::now();
        let mut index = InMemoryIndex::default();
        for i in 0..50_000 {
            index.upsert(document(
                &format!("book:{i}"),
                SearchKind::Book,
                &format!("Livro {i}"),
                if i % 100 == 0 {
                    "assembleia geral capacidade"
                } else {
                    "arquivo ordinário"
                },
            ));
        }
        let page = index.search(&SearchQuery {
            text: "assembleia capacidade".to_owned(),
            limit: 25,
            ..SearchQuery::default()
        });
        assert_eq!(page.total, 500);
        assert_eq!(page.hits.len(), 25);
        assert!(page.has_more);
        assert_eq!(index.len(), 50_000);
        let posting_memberships: usize = index.postings.values().map(BTreeSet::len).sum();
        assert!(
            posting_memberships < 300_000,
            "the lightweight postings representation grew unexpectedly: {posting_memberships}"
        );
        let gram_memberships: usize = index.grams.values().map(BTreeSet::len).sum();
        assert!(
            gram_memberships < 1_500_000,
            "the bounded substring accelerator grew unexpectedly: {gram_memberships}"
        );
        let prefix_started = std::time::Instant::now();
        let prefix_page = index.search(&SearchQuery {
            text: "liv".to_owned(),
            limit: 25,
            ..SearchQuery::default()
        });
        assert_eq!(prefix_page.total, 50_000);
        assert_eq!(prefix_page.hits.len(), 25);
        assert!(
            prefix_started.elapsed() < std::time::Duration::from_secs(10),
            "50k high-cardinality vocabulary prefix query exceeded its generous regression ceiling: {:?}",
            prefix_started.elapsed()
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "50k index+query capacity fixture exceeded its generous regression ceiling: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn short_queries_do_not_scan_the_vocabulary_and_forbidden_rows_do_not_leak_facets() {
        let mut index = InMemoryIndex::default();
        index.upsert(document(
            "act:allowed",
            SearchKind::Act,
            "Assembleia permitida",
            "capital",
        ));
        let mut forbidden = document(
            "act:forbidden",
            SearchKind::Act,
            "Assembleia secreta",
            "capital",
        );
        forbidden.entity_name = Some("Entidade secreta".to_owned());
        index.upsert(forbidden);

        let one_character = index.search(&SearchQuery {
            text: "a".to_owned(),
            ..SearchQuery::default()
        });
        assert_eq!(one_character.total, 0);

        let authorized = index.search_with(
            &SearchQuery {
                text: "assembleia".to_owned(),
                ..SearchQuery::default()
            },
            |document| document.id == "act:allowed",
        );
        assert_eq!(authorized.total, 1);
        assert_eq!(authorized.hits[0].id, "act:allowed");
        assert!(
            authorized
                .facets
                .entity
                .values()
                .all(|facet| facet.label != "Entidade secreta")
        );
    }

    #[test]
    fn privacy_tier_is_selected_before_matching_snippets_filters_and_facets() {
        let mut index = InMemoryIndex::default();
        let mut private = document("act:private", SearchKind::Act, "<redacted>", "<redacted>");
        private.author = None;
        private.privileged = Some(SearchDocumentContent {
            title: "Sentinela privada 917".to_owned(),
            body: "Deliberação confidencial 918".to_owned(),
            content_truncated: false,
            entity_name: Some("Entidade privada 919".to_owned()),
            book_label: Some("Livro privado 920".to_owned()),
            author: Some("Autora privada 921".to_owned()),
            law: private.law.clone(),
            status: private.status.clone(),
        });
        index.upsert(private);

        let query = SearchQuery {
            text: "confidencial 918".to_owned(),
            ..SearchQuery::default()
        };
        let guest = index.search_with_access(&query, |_| Some(SearchAccess::Public));
        assert_eq!(guest.total, 0);
        assert!(guest.hits.is_empty());
        assert!(guest.facets.entity.is_empty());
        assert!(guest.facets.author.is_empty());

        let owner = index.search_with_access(&query, |_| Some(SearchAccess::Privileged));
        assert_eq!(owner.total, 1);
        assert_eq!(owner.hits[0].title, "Sentinela privada 917");
        assert!(owner.hits[0].snippet.contains("confidencial 918"));
        assert_eq!(
            owner.facets.entity.get("entity-a"),
            Some(&LabeledFacetCount {
                label: "Entidade privada 919".to_owned(),
                count: 1,
            })
        );
        assert_eq!(owner.facets.author.get("Autora privada 921"), Some(&1));
    }

    #[test]
    fn distinct_facet_accumulators_and_concurrent_queries_stay_bounded_and_deterministic() {
        let capacity = 40;
        let mut scalar = BTreeMap::new();
        let mut labeled = BTreeMap::new();
        let mut truncated = false;
        for value in 0..25_000 {
            let id = format!("entity-{value:05}");
            increment(&mut scalar, Some(&id), capacity, &mut truncated);
            increment_labeled(
                &mut labeled,
                Some(&id),
                Some(&format!("Entidade {value:05}")),
                capacity,
                &mut truncated,
            );
            assert!(scalar.len() <= capacity);
            assert!(labeled.len() <= capacity);
        }
        assert!(truncated);

        let mut index = InMemoryIndex::default();
        for value in 0..10_000 {
            let mut row = document(
                &format!("act:{value:05}"),
                SearchKind::Act,
                &format!("Ata concorrente {value:05}"),
                "capacidade paralela",
            );
            row.entity_id = Some(format!("entity-{value:05}"));
            row.entity_name = Some(format!("Entidade {value:05}"));
            index.upsert(row);
        }
        let index = std::sync::Arc::new(index);
        let query = SearchQuery {
            text: "capacidade".to_owned(),
            offset: 123,
            limit: 25,
            facet_limit: 10,
            ..SearchQuery::default()
        };
        let expected = index.search(&query);
        assert_eq!(expected.total, 10_000);
        assert_eq!(expected.hits.len(), 25);
        assert!(expected.facets.entity.len() <= 10);
        assert!(expected.facets_truncated);
        assert!(
            expected
                .facets
                .entity
                .values()
                .all(|facet| facet.count == 1),
            "bounded key discovery must not expose Space-Saving estimates as exact counts"
        );

        let workers = (0..8)
            .map(|_| {
                let index = std::sync::Arc::clone(&index);
                let query = query.clone();
                std::thread::spawn(move || index.search(&query))
            })
            .collect::<Vec<_>>();
        for worker in workers {
            assert_eq!(worker.join().expect("query worker"), expected);
        }
    }
}
