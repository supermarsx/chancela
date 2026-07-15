//! SQLite schema for the durable system of record (t30.md §2, "Tables").
//!
//! The DDL is expressed as idempotent `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT
//! EXISTS` statements so [`crate::Store::open`] can run it on every boot — a fresh database is
//! created and an existing one is left untouched. Real schema migrations (when the layout ever
//! changes) key off the `schema_version` row in `meta`.
//!
//! ## Model (t30.md §D2)
//!
//! Aggregates are stored **document-in-relational**: `(id, …scope cols…, json)` where `json` is
//! the serde serialization of the domain value. This keeps "relational" honest (real tables,
//! transactions, indices for scoped retrieval) while avoiding a brittle per-field column schema
//! that the fast-evolving ENT/LEG domain would force constant migrations on. The `events` table
//! stores the hash-chain fields directly so a per-`scope` / per-`kind` retrieval is indexed and
//! the chain order (`seq`) is the primary key (ARC-14 append-only event table).

/// The schema version recorded in `meta` and asserted by [`crate::Store::open`].
///
/// Bump this only alongside a real migration step.
/// - **v1** — the initial durable layout (meta/events/entities/books/acts/registry_extracts).
/// - **v2** — adds the `documents` table (Wave C, t48-e4): generated PDF/A documents preserved
///   alongside their sealed act (plan t48 §3.3/§3.4/D4). Forward-only: an existing v1 database
///   gains the table via the idempotent [`ALL`] DDL and has its stamp advanced on next open.
/// - **v3** — adds the `imported_books` isolation namespace (t54-E2): per-book bundle imports are
///   held here (verdict + provenance + the retained, read-only bundle bytes) so a foreign book
///   chain is **never merged into the live global spine** (which would require re-hashing and
///   destroy tamper-evidence). Forward-only, additive: existing databases gain the table via [`ALL`].
/// - **v4** — adds the qualified-signing tables (t57-S3): `signed_documents` preserves the SIGNED
///   PDF variant + signature metadata for an act's sealed document (alongside the unsigned
///   `documents` row), and `pending_cmd_sessions` holds an in-flight two-phase Chave Móvel Digital
///   signing session (the non-secret `CmdSignSession` + `PreparedSignature` serde blobs) across the
///   `initiate`→`confirm` request pair. **Neither table ever stores a PIN or an OTP.** Forward-only,
///   additive: existing databases gain the tables via [`ALL`] and advance their stamp on next open.
/// - **v5** — adds `imported_documents`: bounded, validated, non-canonical evidence imports. These
///   rows preserve uploaded bytes and metadata without replacing the canonical PDF/A `documents`
///   row or any `signed_documents` variant, and without making PDF/A/legal/signature-validity claims.
/// - **v6** — adds `follow_ups`: first-class act-scoped task rows for post-deliberation work,
///   persisted outside sealed act JSON and audited through ledger events.
/// - **v7** — adds `signed_documents.timestamp_trust_report_json`: a nullable, non-secret
///   technical timestamp-trust diagnostic report captured at signing completion when the RFC 3161
///   token, policy/QTST and certificate-path inputs are available.
/// - **v8** — adds `paper_book_imports`: preserved historical paper-book package bytes and
///   metadata. These rows are non-canonical evidence only and carry OCR hook status, not OCR output.
/// - **v9** — adds `paper_book_ocr_drafts`: non-authoritative OCR draft results linked to
///   preserved paper-book imports. These rows are review aids only and make no canonical or legal
///   text claim.
/// - **v10** — adds paper-book non-canonical linking metadata: validated source page ranges,
///   original paper-book ata number ranges, and digital-continuation planning inputs. These fields
///   remain non-canonical metadata and do not create act, document, or signature rows.
/// - **v11** — adds operator review metadata to `imported_documents`: a bounded non-canonical
///   review status plus reviewer/timestamp/note fields. These transitions never run OCR or
///   conversion and never claim legal acceptance.
/// - **v12** — adds `paper_book_ocr_conversion_dossiers`: metadata-only, non-canonical dossiers
///   for accepted paper-book OCR drafts. They never store raw OCR text and never create acts,
///   documents, signed documents, archive packages, signatures, seals, PDF/A, or PDF/UA outputs.
/// - **v13** — adds `generated_document_dispatch_evidence`: operator-recorded, metadata-only
///   dispatch evidence for generated absent-owner communications. It never mutates `documents`,
///   `acts`, or preserved PDF bytes, and never stores evidence bytes.
/// - **v14** — adds `paper_book_ocr_conversion_execution_artifacts`: reviewed, metadata-only
///   execution artifacts binding accepted OCR evidence, an optional dossier, and the mutable draft
///   act created from that OCR. They carry explicit no-claim flags and never store raw OCR text.
/// - **v15** — adds `imported_document_review_history`: append-only imported-document review
///   decisions so the review workflow is auditable beyond the latest metadata projection.
/// - **v16** — adds the non-ledger sidecar stores so a multi-node cluster keeps them consistent
///   across nodes instead of as per-node JSON files (wp16 P3b, plan §8.2): `users`, `roles`,
///   `delegations` (document-in-relational `(id, json)` rows mirroring `users.json` / `roles.json` /
///   `delegations.json`), `settings` (a single settings document mirroring `settings.json`), and
///   `provider_credentials` (the encrypted `provider-credentials.enc.json` records as opaque
///   ciphertext blobs + non-secret metadata). Forward-only, additive: existing databases gain the
///   tables via [`ALL`] and advance their stamp on next open. This phase only makes the store
///   *capable* of holding them; the file-based loaders in `chancela-api` are switched in a later,
///   coordinated phase.
/// - **v17** — adds user_templates (user-authored template storage): a document-in-relational
///   `(id, json)` table mirroring the four domain aggregates, holding the operator-authored
///   `TemplateSpecDto` JSON. Forward-only, additive: existing databases gain the table via [`ALL`]
///   and advance their stamp on next open.
/// - **v18** — adds `subject_keys`: the per-subject Data-Encryption-Key (DEK) wrapping table for
///   GDPR crypto-erasure (wp26). One row per data subject holding the **opaque** wrapped DEK blob
///   produced by the API's secretstore crypto layer (never plaintext; the store never interprets
///   it), its key version, and a nullable `erased_at`. Crypto-erasure destroys the DEK by
///   overwriting `wrapped_dek` with an empty blob and stamping `erased_at`, making every ciphertext
///   sealed under that DEK (live rows and backups alike) cryptographically irrecoverable.
///   Forward-only, additive: existing databases gain the table via [`ALL`] and advance their stamp
///   on next open.
/// - **v19** — adds `tenants`: the tenant / organizational-group aggregate above `Entity` (wp26
///   tenancy, spec 05 DAT-01). A document-in-relational `(id, json)` table mirroring the other
///   aggregates, holding the API's serialized [`chancela_core::Tenant`] value (opaque to the store).
///   The entity→tenant link rides **inside** `entities.json` as a `#[serde(default)]` `tenant_id`
///   field (there is **no** new column on `entities` and no ALTER — the store is additive-only), so
///   pre-tenancy entities migrate cleanly to a singleton default tenant. Forward-only, additive:
///   existing databases gain the table via [`ALL`] and advance their stamp on next open.
pub const SCHEMA_VERSION: i64 = 19;

/// `meta` — small key/value table for the `schema_version` stamp and the app version.
pub const CREATE_META: &str = "\
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;";

/// `events` — the append-only, hash-chained ledger (ARC-14). `seq` is the chain order and the
/// primary key; the chaining fields (`prev_hash`, `hash`, `payload_digest`) are stored as BLOBs.
/// `links` holds the serialized `Vec<ChainLink>` (multi-chain membership, t41).
pub const CREATE_EVENTS: &str = "\
CREATE TABLE IF NOT EXISTS events (
    seq            INTEGER PRIMARY KEY,
    id             TEXT NOT NULL,
    actor          TEXT NOT NULL,
    justification  TEXT,
    timestamp      TEXT NOT NULL,
    scope          TEXT NOT NULL,
    kind           TEXT NOT NULL,
    payload_digest BLOB NOT NULL,
    prev_hash      BLOB NOT NULL,
    hash           BLOB NOT NULL,
    links          TEXT NOT NULL DEFAULT '[]'
) STRICT;";

/// Index over `events.scope` — enables per-scope retrieval and verification-by-filter (D5: the
/// cheaper per-scope detection path, without the deferred independent per-scope chain).
pub const CREATE_EVENTS_SCOPE_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_events_scope ON events (scope);";

/// Index over `events.kind` — feeds kind-filtered audit queries.
pub const CREATE_EVENTS_KIND_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_events_kind ON events (kind);";

/// `entities` — one row per [`chancela_core::Entity`]; the value lives in `json`.
pub const CREATE_ENTITIES: &str = "\
CREATE TABLE IF NOT EXISTS entities (
    id   TEXT PRIMARY KEY,
    json TEXT NOT NULL
) STRICT;";

/// `books` — one row per [`chancela_core::Book`]; `entity_id` is indexed for the books-of-an-entity feed.
pub const CREATE_BOOKS: &str = "\
CREATE TABLE IF NOT EXISTS books (
    id        TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    json      TEXT NOT NULL
) STRICT;";

/// Index over `books.entity_id`.
pub const CREATE_BOOKS_ENTITY_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_books_entity ON books (entity_id);";

/// `acts` — one row per [`chancela_core::Act`]; `book_id` is indexed for the acts-in-a-book feed.
pub const CREATE_ACTS: &str = "\
CREATE TABLE IF NOT EXISTS acts (
    id      TEXT PRIMARY KEY,
    book_id TEXT NOT NULL,
    json    TEXT NOT NULL
) STRICT;";

/// Index over `acts.book_id`.
pub const CREATE_ACTS_BOOK_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_acts_book ON acts (book_id);";

/// `registry_extracts` — one row per imported certidão, keyed by the owning entity id.
pub const CREATE_REGISTRY_EXTRACTS: &str = "\
CREATE TABLE IF NOT EXISTS registry_extracts (
    entity_id TEXT PRIMARY KEY,
    json      TEXT NOT NULL
) STRICT;";

/// `documents` — one row per generated PDF/A document bound to a sealed act (schema v2, Wave C,
/// plan t48 §3.4/D4). Unlike the four aggregate tables this is **not** document-in-relational JSON:
/// the payload is opaque PDF bytes (`pdf_bytes` BLOB), so the metadata that the api's endpoints and
/// the seal response need is broken out into typed columns rather than a serde `json` blob.
///
/// - `id` — the document id (primary key; the upsert is idempotent on it).
/// - `act_id` — the owning act, indexed for the `GET /v1/acts/{id}/document` lookup (mirrors how
///   `acts.book_id` is the indexed scope column — one indexed scope column per table).
/// - `template_id` — the versioned spec id recorded verbatim (e.g. `csc-ata-ag/v1`).
/// - `pdf_digest` — lowercase-hex sha-256 of `pdf_bytes` (bound into the `document.generated` event).
/// - `profile` — the rule-pack / profile string the document was produced under.
/// - `created_at` — RFC 3339 text, the inscription-ordering field (mirrors `events.timestamp`);
///   the by-act read returns the most recent row.
/// - `pdf_bytes` — the PDF/A-2u bytes themselves.
pub const CREATE_DOCUMENTS: &str = "\
CREATE TABLE IF NOT EXISTS documents (
    id          TEXT PRIMARY KEY,
    act_id      TEXT NOT NULL,
    template_id TEXT NOT NULL,
    pdf_digest  TEXT NOT NULL,
    profile     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    pdf_bytes   BLOB NOT NULL
) STRICT;";

/// Index over `documents.act_id` — feeds the by-act document retrieval (one act → its documents).
pub const CREATE_DOCUMENTS_ACT_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_documents_act ON documents (act_id);";

/// `imported_books` — the per-book **import isolation namespace** (schema v3, t54-E2).
///
/// A per-book bundle (`chancela-book-bundle/v1`) imported via `Store::import_book` is recorded here
/// with its verify-before-trust verdict and provenance. The whole bundle's bytes are retained in
/// `bundle_bytes` as a **read-only** copy under the bundle's **ORIGINAL** entity/book ids — it is
/// deliberately **not** re-inserted into the live `events`/aggregate tables: a foreign book chain
/// carries its own global `seq`/`prev_hash`, and forcing it onto this instance's global spine would
/// require re-hashing every event (destroying the tamper-evidence — the same reason id-rename/merge
/// is forbidden). So an import is an isolated, self-verifying holding record, never a live-spine merge.
///
/// - `import_id` — a fresh uuid minted for this import (primary key).
/// - `entity_id` / `book_id` — the bundle's ORIGINAL ids (never renamed).
/// - `source_instance_id` — the exporting install's stable id (provenance).
/// - `bundle_digest` — the manifest's self-digest (lowercase hex).
/// - `verdict` — `'verified'` (book chain re-verified clean) or `'quarantined'` (a broken/forged
///   chain or a tampered member — isolated, never trusted as valid).
/// - `break_json` — the serialized `ChainBreak` when quarantined, else NULL.
/// - `collided` — 1 when `book_id` already existed live/imported at import time.
/// - `imported_at` — RFC 3339 text.
/// - `bundle_bytes` — the retained, read-only `.zip` bundle (the isolation vehicle).
pub const CREATE_IMPORTED_BOOKS: &str = "\
CREATE TABLE IF NOT EXISTS imported_books (
    import_id          TEXT PRIMARY KEY,
    entity_id          TEXT NOT NULL,
    book_id            TEXT NOT NULL,
    source_instance_id TEXT NOT NULL,
    bundle_digest      TEXT NOT NULL,
    verdict            TEXT NOT NULL,
    break_json         TEXT,
    collided           INTEGER NOT NULL,
    imported_at        TEXT NOT NULL,
    bundle_bytes       BLOB NOT NULL
) STRICT;";

/// Index over `imported_books.book_id` — feeds the collision check and the per-book import feed.
pub const CREATE_IMPORTED_BOOKS_BOOK_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_imported_books_book ON imported_books (book_id);";

/// `signed_documents` — the SIGNED PDF variant + qualified-signature metadata for a sealed act's
/// document (schema v4, t57-S3).
///
/// One row per act (`act_id` primary key): the qualified signature is a single post-seal artifact
/// over the act's unsigned PDF/A. It lives **alongside** the unsigned `documents` row (never
/// replacing it) so both variants are retrievable. Like `documents`, the payload is opaque PDF bytes
/// (`signed_pdf_bytes` BLOB) so the metadata is broken out into typed columns rather than a serde
/// `json` blob.
///
/// **This table never stores a PIN or an OTP** — only public signature material (the signer
/// certificate DER, the produced signed PDF, the CMS-derived metadata).
///
/// - `act_id` — the owning act (primary key; the upsert is idempotent on it).
/// - `document_id` — the source unsigned `documents` row this signature covers.
/// - `signed_pdf_digest` — lowercase-hex sha-256 of `signed_pdf_bytes` (bound into `document.signed`).
/// - `signature_family` — the signing family (e.g. `ChaveMovelDigital`).
/// - `evidentiary_level` — the evidentiary weight actually carried (e.g. `Qualified`; SIG-01).
/// - `trusted_list_status` — the signer issuer's TSL status at signing time, or NULL.
/// - `signer_cert_subject` — the signer leaf certificate subject DN, or NULL.
/// - `signing_time` — RFC 3339, the authoritative CAdES signed-attributes signing time.
/// - `signed_at` — RFC 3339, when the api completed the signature (storage metadata).
/// - `signer_cert_der` — the signer leaf certificate (DER).
/// - `timestamp_token_der` — an optional RFC 3161 timestamp token (DER), or NULL (B-B has none).
/// - `timestamp_trust_report_json` — optional technical timestamp-trust diagnostic report JSON.
/// - `signer_capacity_evidence_json` — optional declared signer-capacity evidence JSON; this is
///   request/operator evidence only and does not imply SCAP or authority verification.
/// - `signed_pdf_bytes` — the signed PDF/A bytes.
pub const CREATE_SIGNED_DOCUMENTS: &str = "\
CREATE TABLE IF NOT EXISTS signed_documents (
    act_id              TEXT PRIMARY KEY,
    document_id         TEXT NOT NULL,
    signed_pdf_digest   TEXT NOT NULL,
    signature_family    TEXT NOT NULL,
    evidentiary_level   TEXT NOT NULL,
    trusted_list_status TEXT,
    signer_cert_subject TEXT,
    signing_time        TEXT NOT NULL,
    signed_at           TEXT NOT NULL,
    signer_cert_der     BLOB NOT NULL,
    timestamp_token_der BLOB,
    timestamp_trust_report_json TEXT,
    signer_capacity_evidence_json TEXT,
    signed_pdf_bytes    BLOB NOT NULL
) STRICT;";

/// `pending_cmd_sessions` — an in-flight two-phase Chave Móvel Digital signing session (schema v4,
/// t57-S3), persisted so the `initiate`→`confirm` request pair survives across the two stateless
/// requests (and a restart).
///
/// **This table never stores a PIN or an OTP.** `session_json` is the serde form of the non-secret
/// `chancela_signing::CmdSignSession` (SCMD process id, public account id, signer cert + chain,
/// trusted-list status, ByteRange digest, signing time); `prepared_json` is the serde form of the
/// non-secret `chancela_pades::PreparedSignature` (prepared PDF bytes + ByteRange digest). Both are
/// opaque JSON to the store (the crypto types live above it in the DAG).
///
/// - `session_id` — a fresh uuid minted at initiate (primary key).
/// - `act_id` — the act being signed, indexed for the by-act pending lookup.
/// - `actor` — the acting username that initiated (session gating: only it may confirm).
/// - `status` — `'otp_pending'` while awaiting the OTP.
/// - `masked_phone` — the citizen phone with the middle digits masked (non-secret, for the UI).
/// - `doc_name` — the human-readable document label used at initiate.
/// - `signer_capacity_evidence_json` — optional declared signer-capacity evidence JSON preserved
///   through initiate/confirm without parsing display text.
/// - `session_json` — the non-secret `CmdSignSession` serde blob.
/// - `prepared_json` — the non-secret `PreparedSignature` serde blob.
/// - `created_at` / `expires_at` — RFC 3339 (single-use, TTL-bounded).
pub const CREATE_PENDING_CMD_SESSIONS: &str = "\
CREATE TABLE IF NOT EXISTS pending_cmd_sessions (
    session_id   TEXT PRIMARY KEY,
    act_id       TEXT NOT NULL,
    actor        TEXT NOT NULL,
    status       TEXT NOT NULL,
    masked_phone TEXT NOT NULL,
    doc_name     TEXT NOT NULL,
    signer_capacity_evidence_json TEXT,
    session_json TEXT NOT NULL,
    prepared_json TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL
) STRICT;";

/// Index over `pending_cmd_sessions.act_id` — feeds the by-act pending-session lookup.
pub const CREATE_PENDING_CMD_SESSIONS_ACT_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_pending_cmd_sessions_act ON pending_cmd_sessions (act_id);";

/// `imported_documents` — validated, **non-canonical** document evidence imports (schema v5).
///
/// These records preserve uploaded document bytes after the API's structural validation screen, but
/// they deliberately live outside `documents` / `signed_documents`: an import is supporting evidence,
/// not the canonical generated PDF/A nor a qualified signed variant. The metadata is enough to list,
/// read, digest-check, and audit the import; the ledger event stores only this metadata, never bytes.
///
/// - `id` — fresh UUID minted by the API (primary key).
/// - `act_id` — optional owning act scope; NULL means a global, unlinked evidence import.
/// - `filename` — optional sanitized display name (never a path).
/// - `declared_content_type` — caller/header MIME type, when supplied.
/// - `detected_content_type` — API structural detector result.
/// - `sha256` / `size_bytes` — digest and size of `bytes`.
/// - `imported_at` / `imported_by` — storage metadata.
/// - `operator_review_status` — bounded operator review transition state for the preserved
///   non-canonical evidence row.
/// - `operator_reviewed_at` / `operator_reviewed_by` / `operator_review_note` — optional review
///   metadata. These fields do not imply OCR, conversion, or legal acceptance.
/// - `operator_acknowledged_guardrail_ids_json` — JSON list of acknowledged guardrail ids for the
///   latest operator review decision.
/// - `bytes` — the retained uploaded document bytes.
pub const CREATE_IMPORTED_DOCUMENTS: &str = "\
CREATE TABLE IF NOT EXISTS imported_documents (
    id                    TEXT PRIMARY KEY,
    act_id                TEXT,
    filename              TEXT,
    declared_content_type TEXT,
    detected_content_type TEXT NOT NULL,
    sha256                TEXT NOT NULL,
    size_bytes            INTEGER NOT NULL,
    imported_at           TEXT NOT NULL,
    imported_by           TEXT NOT NULL,
    operator_review_status TEXT NOT NULL DEFAULT 'operator_review_required',
    operator_reviewed_at  TEXT,
    operator_reviewed_by  TEXT,
    operator_review_note  TEXT,
    operator_acknowledged_guardrail_ids_json TEXT NOT NULL DEFAULT '[]',
    bytes                 BLOB NOT NULL
) STRICT;";

/// Index over `imported_documents.act_id` — feeds the act-scoped evidence feed.
pub const CREATE_IMPORTED_DOCUMENTS_ACT_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_imported_documents_act ON imported_documents (act_id);";

/// Index over `imported_documents.imported_at` — keeps the global list ordered without scanning.
pub const CREATE_IMPORTED_DOCUMENTS_IMPORTED_AT_IDX: &str = "CREATE INDEX IF NOT EXISTS idx_imported_documents_imported_at ON imported_documents (imported_at);";

/// `imported_document_review_history` - append-only technical review decisions for imported
/// document evidence. These rows preserve operator decisions and guardrail acknowledgements only;
/// they do not store bytes and do not claim OCR, conversion, certification, or legal acceptance.
pub const CREATE_IMPORTED_DOCUMENT_REVIEW_HISTORY: &str = "\
CREATE TABLE IF NOT EXISTS imported_document_review_history (
    id                                      INTEGER PRIMARY KEY,
    imported_document_id                    TEXT NOT NULL,
    review_status                           TEXT NOT NULL,
    reviewed_at                             TEXT,
    reviewed_by                             TEXT,
    review_note                             TEXT,
    acknowledged_guardrail_ids_json         TEXT NOT NULL DEFAULT '[]'
) STRICT;";

/// Index over `imported_document_review_history.imported_document_id` - feeds document read views.
pub const CREATE_IMPORTED_DOCUMENT_REVIEW_HISTORY_DOCUMENT_IDX: &str = "CREATE INDEX IF NOT EXISTS idx_imported_document_review_history_document ON imported_document_review_history (imported_document_id, id);";

/// `generated_document_dispatch_evidence` — metadata-only operator dispatch evidence for generated
/// absent-owner communications (schema v13).
///
/// These rows are deliberately separate from `documents` and `acts`: recording evidence must never
/// rewrite a sealed act or the generated PDF/A bytes. The idempotency key is deterministic from the
/// normalized request and scoped by generated document id, so exact retries can return the existing
/// record without appending a second ledger event. The row stores only locators/metadata, never
/// evidence bytes and never delivery/legal-sufficiency assertions.
pub const CREATE_GENERATED_DOCUMENT_DISPATCH_EVIDENCE: &str = "\
CREATE TABLE IF NOT EXISTS generated_document_dispatch_evidence (
    document_id          TEXT NOT NULL,
    idempotency_key      TEXT NOT NULL,
    act_id               TEXT NOT NULL,
    template_id          TEXT NOT NULL,
    actor                TEXT NOT NULL,
    dispatched_at        TEXT NOT NULL,
    channel              TEXT,
    reference            TEXT,
    evidence_reference   TEXT,
    imported_document_id TEXT,
    recipients_json      TEXT NOT NULL,
    operator_note        TEXT,
    recorded_at          TEXT NOT NULL,
    PRIMARY KEY (document_id, idempotency_key)
) STRICT;";

/// Index over `generated_document_dispatch_evidence.act_id` — supports act-scoped evidence/status
/// reads without scanning every generated document's evidence rows.
pub const CREATE_GENERATED_DOCUMENT_DISPATCH_EVIDENCE_ACT_IDX: &str = "CREATE INDEX IF NOT EXISTS idx_generated_document_dispatch_evidence_act ON generated_document_dispatch_evidence (act_id);";

/// `paper_book_imports` — preserved historical paper-book import packages (schema v8).
///
/// This table retains the operator-supplied scan/package bytes with fixity and descriptive
/// metadata after the API re-runs paper-book import validation. It deliberately does not create
/// canonical minutes, generated documents, signed variants, or OCR text. `ocr_status` is only a
/// hook/status marker for later asynchronous work. The page/number range fields are
/// operator-visible linking metadata only: they preserve original paper-book numbering and the
/// source-package page span so a later digital continuation can be planned without converting the
/// scan into a canonical digital act.
pub const CREATE_PAPER_BOOK_IMPORTS: &str = "\
CREATE TABLE IF NOT EXISTS paper_book_imports (
    import_id       TEXT PRIMARY KEY,
    entity_ref      TEXT NOT NULL,
    entity_name     TEXT NOT NULL,
    entity_nipc     TEXT NOT NULL,
    book_ref        TEXT NOT NULL,
    date_from       TEXT NOT NULL,
    date_to         TEXT NOT NULL,
    page_count      INTEGER NOT NULL,
    page_from       INTEGER NOT NULL DEFAULT 1,
    page_to         INTEGER NOT NULL DEFAULT 1,
    original_number_from INTEGER,
    original_number_to   INTEGER,
    sha256          TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    content_type    TEXT NOT NULL,
    source_filename TEXT,
    notes           TEXT,
    imported_at     TEXT NOT NULL,
    imported_by     TEXT NOT NULL,
    ocr_status      TEXT NOT NULL,
    bytes           BLOB NOT NULL
) STRICT;";

pub const CREATE_PAPER_BOOK_IMPORTS_BOOK_REF_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_paper_book_imports_book_ref ON paper_book_imports (book_ref);";

pub const CREATE_PAPER_BOOK_IMPORTS_IMPORTED_AT_IDX: &str = "CREATE INDEX IF NOT EXISTS idx_paper_book_imports_imported_at ON paper_book_imports (imported_at);";

/// `paper_book_ocr_drafts` — non-authoritative OCR draft result rows for preserved paper imports.
///
/// These rows are deliberately separate from the preserved package row: they may contain extracted
/// text or only a digest of external OCR text, page spans, OCR engine metadata, confidence, and
/// operator review status. They are never canonical minutes, legal text, or evidence of signature
/// validity. Ledger events should reference metadata only and must not carry `extracted_text`.
pub const CREATE_PAPER_BOOK_OCR_DRAFTS: &str = "\
CREATE TABLE IF NOT EXISTS paper_book_ocr_drafts (
    draft_id       TEXT PRIMARY KEY,
    import_id      TEXT NOT NULL,
    extracted_text TEXT,
    text_digest    TEXT,
    page_spans_json TEXT NOT NULL,
    confidence     REAL,
    engine_name    TEXT NOT NULL,
    engine_version TEXT,
    created_at     TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    review_status  TEXT NOT NULL,
    reviewed_at    TEXT,
    reviewed_by    TEXT,
    review_note    TEXT,
    superseded_by  TEXT
) STRICT;";

pub const CREATE_PAPER_BOOK_OCR_DRAFTS_IMPORT_IDX: &str = "CREATE INDEX IF NOT EXISTS idx_paper_book_ocr_drafts_import ON paper_book_ocr_drafts (import_id);";

pub const CREATE_PAPER_BOOK_OCR_DRAFTS_CREATED_AT_IDX: &str = "CREATE INDEX IF NOT EXISTS idx_paper_book_ocr_drafts_created_at ON paper_book_ocr_drafts (created_at);";

/// `paper_book_ocr_conversion_dossiers` — metadata-only dossier rows for accepted OCR drafts.
///
/// These rows are deliberately non-canonical and non-legal-validity-conferring. They bind one
/// preserved paper-book import to one accepted OCR draft and retain only review/digest/page-span
/// metadata. They do not store raw OCR extracted text and do not create canonical book/act,
/// document, signed-document, archive-package, signature, seal, PDF/A, or PDF/UA outputs.
pub const CREATE_PAPER_BOOK_OCR_CONVERSION_DOSSIERS: &str = "\
CREATE TABLE IF NOT EXISTS paper_book_ocr_conversion_dossiers (
    dossier_id             TEXT PRIMARY KEY,
    import_id              TEXT NOT NULL,
    draft_id               TEXT NOT NULL,
    source_text_digest     TEXT,
    source_page_spans_json TEXT NOT NULL,
    source_review_status   TEXT NOT NULL,
    source_reviewed_at     TEXT,
    source_reviewed_by     TEXT,
    created_at             TEXT NOT NULL,
    created_by             TEXT NOT NULL
) STRICT;";

pub const CREATE_PAPER_BOOK_OCR_CONVERSION_DOSSIERS_IMPORT_DRAFT_IDX: &str = "CREATE UNIQUE INDEX IF NOT EXISTS idx_paper_book_ocr_conversion_dossiers_import_draft ON paper_book_ocr_conversion_dossiers (import_id, draft_id);";

pub const CREATE_PAPER_BOOK_OCR_CONVERSION_DOSSIERS_IMPORT_CREATED_AT_IDX: &str = "CREATE INDEX IF NOT EXISTS idx_paper_book_ocr_conversion_dossiers_import_created_at ON paper_book_ocr_conversion_dossiers (import_id, created_at);";

/// `paper_book_ocr_conversion_execution_artifacts` — reviewed execution artifacts for accepted OCR
/// draft promotion into mutable act drafts.
///
/// These rows bind a preserved paper-book import, accepted OCR draft, optional conversion dossier,
/// and target mutable `Draft` act. They are deliberately not canonical/legal conversion records:
/// every canonical/legal/PDF/signature/archive claim flag is stored explicitly as false. Raw OCR
/// text is never stored here.
pub const CREATE_PAPER_BOOK_OCR_CONVERSION_EXECUTION_ARTIFACTS: &str = "\
CREATE TABLE IF NOT EXISTS paper_book_ocr_conversion_execution_artifacts (
    artifact_id                           TEXT PRIMARY KEY,
    import_id                             TEXT NOT NULL,
    draft_id                              TEXT NOT NULL,
    dossier_id                            TEXT,
    source_text_digest                    TEXT,
    source_page_spans_json                TEXT NOT NULL,
    source_review_status                  TEXT NOT NULL,
    source_reviewed_at                    TEXT,
    source_reviewed_by                    TEXT,
    target_act_id                         TEXT NOT NULL,
    target_act_state                      TEXT NOT NULL,
    mutable_draft_act_created             INTEGER NOT NULL,
    created_at                            TEXT NOT NULL,
    created_by                            TEXT NOT NULL,
    canonical_conversion_claimed          INTEGER NOT NULL DEFAULT 0,
    canonical_minutes_claimed             INTEGER NOT NULL DEFAULT 0,
    canonical_act_created                 INTEGER NOT NULL DEFAULT 0,
    canonical_document_created            INTEGER NOT NULL DEFAULT 0,
    signed_document_created               INTEGER NOT NULL DEFAULT 0,
    archive_package_created               INTEGER NOT NULL DEFAULT 0,
    pdfa_created                          INTEGER NOT NULL DEFAULT 0,
    pdfua_created                         INTEGER NOT NULL DEFAULT 0,
    signature_created                     INTEGER NOT NULL DEFAULT 0,
    seal_created                          INTEGER NOT NULL DEFAULT 0,
    archive_certification_claimed         INTEGER NOT NULL DEFAULT 0,
    legal_validity_claimed                INTEGER NOT NULL DEFAULT 0,
    source_extracted_text_in_artifact     INTEGER NOT NULL DEFAULT 0,
    source_extracted_text_in_ledger_event INTEGER NOT NULL DEFAULT 0
) STRICT;";

pub const CREATE_PAPER_BOOK_OCR_CONVERSION_EXECUTION_ARTIFACTS_IMPORT_DRAFT_ACT_IDX: &str = "CREATE UNIQUE INDEX IF NOT EXISTS idx_paper_book_ocr_conversion_execution_artifacts_import_draft_act ON paper_book_ocr_conversion_execution_artifacts (import_id, draft_id, target_act_id);";

pub const CREATE_PAPER_BOOK_OCR_CONVERSION_EXECUTION_ARTIFACTS_IMPORT_DRAFT_IDX: &str = "CREATE INDEX IF NOT EXISTS idx_paper_book_ocr_conversion_execution_artifacts_import_draft ON paper_book_ocr_conversion_execution_artifacts (import_id, draft_id, created_at);";

/// `follow_ups` — first-class task/follow-up rows tied to an act. These deliberately live outside
/// the sealed [`chancela_core::Act`] JSON so post-deliberation task management never mutates the
/// frozen evidentiary payload.
///
/// - `id` — fresh UUID minted by the API (primary key).
/// - `act_id` — owning act scope, indexed for `GET /v1/acts/{id}/follow-ups`.
/// - `agenda_number` / `deliberation_index` — optional anchors into the act's agenda or structured
///   deliberation list. They are references only; the act JSON is not touched.
/// - `title` / `detail` — task text.
/// - `due_date` — optional ISO `YYYY-MM-DD` date.
/// - `assignee` / `assignee_display` — optional assignee stable/display labels.
/// - `status` — `Open` or `Completed`.
/// - `created_*` / `completed_*` — audit metadata.
pub const CREATE_FOLLOW_UPS: &str = "\
CREATE TABLE IF NOT EXISTS follow_ups (
    id                 TEXT PRIMARY KEY,
    act_id             TEXT NOT NULL,
    agenda_number      INTEGER,
    deliberation_index INTEGER,
    title              TEXT NOT NULL,
    detail             TEXT,
    due_date           TEXT,
    assignee           TEXT,
    assignee_display   TEXT,
    status             TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    created_by         TEXT NOT NULL,
    completed_at       TEXT,
    completed_by       TEXT
) STRICT;";

/// Index over `follow_ups.act_id` — feeds the act-scoped task feed.
pub const CREATE_FOLLOW_UPS_ACT_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_follow_ups_act ON follow_ups (act_id);";

/// Index over `follow_ups.status` — keeps open/completed filtering cheap when the API grows it.
pub const CREATE_FOLLOW_UPS_STATUS_IDX: &str =
    "CREATE INDEX IF NOT EXISTS idx_follow_ups_status ON follow_ups (status);";

/// `users` — the user directory sidecar moved into the shared store (schema v16, wp16 P3b).
///
/// Document-in-relational like the four domain aggregates: `(id, json)` where `json` is the API's
/// serialized `User` value (opaque to the store). This mirrors the on-disk `users.json` array so a
/// later api-wiring phase can load/persist the directory from the shared database, keeping every
/// cluster node consistent instead of reading a per-node file. The store never interprets `json`.
pub const CREATE_USERS: &str = "\
CREATE TABLE IF NOT EXISTS users (
    id   TEXT PRIMARY KEY,
    json TEXT NOT NULL
) STRICT;";

/// `roles` — the role-catalog sidecar (`roles.json`) moved into the shared store (schema v16, wp16
/// P3b). One `(id, json)` row per role definition; `json` is the API's serialized role value.
pub const CREATE_ROLES: &str = "\
CREATE TABLE IF NOT EXISTS roles (
    id   TEXT PRIMARY KEY,
    json TEXT NOT NULL
) STRICT;";

/// `delegations` — the scoped-delegation sidecar (`delegations.json`) moved into the shared store
/// (schema v16, wp16 P3b). One `(id, json)` row per delegation (active **or** revoked — the file
/// retains both); `json` is the API's serialized `StoredDelegation`.
pub const CREATE_DELEGATIONS: &str = "\
CREATE TABLE IF NOT EXISTS delegations (
    id   TEXT PRIMARY KEY,
    json TEXT NOT NULL
) STRICT;";

/// `settings` — the single settings document (`settings.json`) moved into the shared store (schema
/// v16, wp16 P3b). A single-row table keyed by a fixed singleton id ([`crate::SETTINGS_SINGLETON_ID`]);
/// `json` is the API's serialized `Settings` document (opaque to the store).
pub const CREATE_SETTINGS: &str = "\
CREATE TABLE IF NOT EXISTS settings (
    id   TEXT PRIMARY KEY,
    json TEXT NOT NULL
) STRICT;";

/// `provider_credentials` — the encrypted provider-credential sidecar
/// (`provider-credentials.enc.json`) moved into the shared store (schema v16, wp16 P3b).
///
/// One row per `(mode, provider_id)` record, mirroring the sidecar file's `records` list.
/// `record_blob` is the **OPAQUE** serialized `EncryptedCredentialRecord`: it already holds only
/// AEAD ciphertext envelopes (never a plaintext secret), and the store treats it as opaque bytes
/// (`BLOB`). The XChaCha20-Poly1305 / AAD crypto envelope stays entirely in `chancela-api`'s
/// secretstore — only its **storage** moves from a file to this DB row; the store neither encrypts,
/// decrypts, nor parses it. The non-secret `key_version` / `updated_at` metadata is broken out into
/// typed columns for the status/rotation surfaces, exactly as the sidecar record carries them.
pub const CREATE_PROVIDER_CREDENTIALS: &str = "\
CREATE TABLE IF NOT EXISTS provider_credentials (
    mode        TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    updated_at  TEXT NOT NULL,
    record_blob BLOB NOT NULL,
    PRIMARY KEY (mode, provider_id)
) STRICT;";

/// `user_templates` — the user-authored template store (schema v17). Document-in-relational like
/// the four domain aggregates: `(id, json)` where `json` is the API's serialized `TemplateSpecDto`
/// value (opaque to the store). Holds operator-authored templates alongside the built-in registry;
/// the store never interprets `json`.
pub const CREATE_USER_TEMPLATES: &str = "\
CREATE TABLE IF NOT EXISTS user_templates (
    id   TEXT PRIMARY KEY,
    json TEXT NOT NULL
) STRICT;";

/// `subject_keys` — the per-subject Data-Encryption-Key (DEK) wrapping table (schema v18, wp26 GDPR
/// crypto-erasure).
///
/// One row per data subject. `wrapped_dek` is the **OPAQUE** wrapped-DEK blob produced by the API's
/// secretstore crypto layer (XChaCha20-Poly1305 envelope over the subject DEK, wrapped by the
/// internally-derived root): it never holds a plaintext key, and the store neither wraps, unwraps,
/// nor interprets it — exactly like `provider_credentials.record_blob`, only its **storage** lives
/// here. `key_version` is the non-secret rotation marker. `erased_at` is NULL while the subject's
/// DEK is live; crypto-erasure overwrites `wrapped_dek` with an **empty** blob and stamps
/// `erased_at` (RFC 3339), after which — combined with `VACUUM` — the wrapping bytes no longer exist
/// and every ciphertext sealed under that DEK becomes irrecoverable.
pub const CREATE_SUBJECT_KEYS: &str = "\
CREATE TABLE IF NOT EXISTS subject_keys (
    subject_id  TEXT PRIMARY KEY,
    wrapped_dek BLOB NOT NULL,
    key_version INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    erased_at   TEXT
) STRICT;";

/// `tenants` — one row per [`chancela_core::Tenant`] (schema v19, wp26 tenancy). Document-in-relational
/// `(id, json)` mirroring the aggregate tables; `json` is the API's serialized `Tenant` value, opaque
/// to the store. The entity→tenant link is **not** here — it rides inside `entities.json`; this table
/// only names/holds the tenants themselves. Additive: no ALTER to `entities`.
pub const CREATE_TENANTS: &str = "\
CREATE TABLE IF NOT EXISTS tenants (
    id   TEXT PRIMARY KEY,
    json TEXT NOT NULL
) STRICT;";

/// Every DDL statement, in dependency order, for [`crate::Store::open`] to execute on boot.
pub const ALL: &[&str] = &[
    CREATE_META,
    CREATE_EVENTS,
    CREATE_EVENTS_SCOPE_IDX,
    CREATE_EVENTS_KIND_IDX,
    CREATE_ENTITIES,
    CREATE_BOOKS,
    CREATE_BOOKS_ENTITY_IDX,
    CREATE_ACTS,
    CREATE_ACTS_BOOK_IDX,
    CREATE_REGISTRY_EXTRACTS,
    CREATE_DOCUMENTS,
    CREATE_DOCUMENTS_ACT_IDX,
    CREATE_IMPORTED_BOOKS,
    CREATE_IMPORTED_BOOKS_BOOK_IDX,
    CREATE_SIGNED_DOCUMENTS,
    CREATE_PENDING_CMD_SESSIONS,
    CREATE_PENDING_CMD_SESSIONS_ACT_IDX,
    CREATE_IMPORTED_DOCUMENTS,
    CREATE_IMPORTED_DOCUMENTS_ACT_IDX,
    CREATE_IMPORTED_DOCUMENTS_IMPORTED_AT_IDX,
    CREATE_IMPORTED_DOCUMENT_REVIEW_HISTORY,
    CREATE_IMPORTED_DOCUMENT_REVIEW_HISTORY_DOCUMENT_IDX,
    CREATE_GENERATED_DOCUMENT_DISPATCH_EVIDENCE,
    CREATE_GENERATED_DOCUMENT_DISPATCH_EVIDENCE_ACT_IDX,
    CREATE_PAPER_BOOK_IMPORTS,
    CREATE_PAPER_BOOK_IMPORTS_BOOK_REF_IDX,
    CREATE_PAPER_BOOK_IMPORTS_IMPORTED_AT_IDX,
    CREATE_PAPER_BOOK_OCR_DRAFTS,
    CREATE_PAPER_BOOK_OCR_DRAFTS_IMPORT_IDX,
    CREATE_PAPER_BOOK_OCR_DRAFTS_CREATED_AT_IDX,
    CREATE_PAPER_BOOK_OCR_CONVERSION_DOSSIERS,
    CREATE_PAPER_BOOK_OCR_CONVERSION_DOSSIERS_IMPORT_DRAFT_IDX,
    CREATE_PAPER_BOOK_OCR_CONVERSION_DOSSIERS_IMPORT_CREATED_AT_IDX,
    CREATE_PAPER_BOOK_OCR_CONVERSION_EXECUTION_ARTIFACTS,
    CREATE_PAPER_BOOK_OCR_CONVERSION_EXECUTION_ARTIFACTS_IMPORT_DRAFT_ACT_IDX,
    CREATE_PAPER_BOOK_OCR_CONVERSION_EXECUTION_ARTIFACTS_IMPORT_DRAFT_IDX,
    CREATE_FOLLOW_UPS,
    CREATE_FOLLOW_UPS_ACT_IDX,
    CREATE_FOLLOW_UPS_STATUS_IDX,
    CREATE_USERS,
    CREATE_ROLES,
    CREATE_DELEGATIONS,
    CREATE_SETTINGS,
    CREATE_PROVIDER_CREDENTIALS,
    CREATE_USER_TEMPLATES,
    CREATE_SUBJECT_KEYS,
    CREATE_TENANTS,
];
