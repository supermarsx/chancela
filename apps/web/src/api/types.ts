/**
 * TypeScript mirrors of the pinned REST/JSON contract (plan t5 §2.1–§2.7).
 *
 * These types are the client-side half of a cross-language contract: the Rust API
 * (t5-a1) serialises the same shapes. Enum members use the *variant name strings*
 * exactly as serde emits them; dates are ISO `YYYY-MM-DD` strings; ledger timestamps
 * are RFC 3339; digests/hashes are lowercase hex strings. Do not "improve" these
 * names — they must match the wire format byte for byte.
 */

// --- Enums (§2.1) — string unions matching serde default (variant name) ---------

export const ENTITY_KINDS = [
  'SociedadeEmNomeColetivo',
  'SociedadePorQuotas',
  'SociedadeUnipessoalPorQuotas',
  'SociedadeAnonima',
  'SociedadeEmComanditaSimples',
  'SociedadeEmComanditaPorAcoes',
  'Condominio',
  'Associacao',
  'Fundacao',
  'Cooperativa',
] as const;
export type EntityKind = (typeof ENTITY_KINDS)[number];

export type EntityFamily =
  'CommercialCompany' | 'Condominium' | 'Association' | 'Foundation' | 'Cooperative';

export const BOOK_KINDS = [
  'AssembleiaGeral',
  'GerenciaAdministracao',
  'ConselhoFiscal',
  'Condominio',
] as const;
export type BookKind = (typeof BOOK_KINDS)[number];

export type BookState = 'Created' | 'Open' | 'Closed';

export const NUMBERING_SCHEMES = ['Sequential', 'LooseLeaf'] as const;
export type NumberingScheme = (typeof NUMBERING_SCHEMES)[number];

export const CLOSING_REASONS = ['BookFull', 'EntityDissolved', 'MigrationToSuccessor'] as const;
export type ClosingReason = (typeof CLOSING_REASONS)[number];

export const MEETING_CHANNELS = ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'] as const;
export type MeetingChannel = (typeof MEETING_CHANNELS)[number];

export const DISPATCH_CHANNELS = [
  'RegisteredLetter',
  'RegisteredLetterAR',
  'Email',
  'HandDelivery',
  'Publication',
  'Portal',
] as const;
export type DispatchChannel = (typeof DISPATCH_CHANNELS)[number];

// Ordered lifecycle (WFL). `advance_to` walks Draft → … → Signing; Sealed/Archived
// are reached only via the seal/archive endpoints, never `advance`.
export const ACT_STATES = [
  'Draft',
  'Review',
  'Convened',
  'Deliberated',
  'TextApproved',
  'Signing',
  'Sealed',
  'Archived',
] as const;
export type ActState = (typeof ACT_STATES)[number];

// Document lifecycle stage (plan t48 §3.1, frozen in `chancela-core::document_model`).
// Bare serde variant names; a template is bound to a family × stage. Used to filter the
// template catalog (`GET /v1/templates?stage=`). `#[non_exhaustive]` server-side → new
// stages may append; the UI tolerates an unknown string by rendering it verbatim.
export const LIFECYCLE_STAGES = [
  'Convocatoria',
  'TermoAbertura',
  'Reuniao',
  'Deliberacao',
  'Ata',
  'Certidao',
  'Extrato',
  'TermoEncerramento',
] as const;
export type LifecycleStage = (typeof LIFECYCLE_STAGES)[number];

export const ATTACHMENT_KINDS = [
  'Convocatoria',
  'Agenda',
  'Proxy',
  'AttendanceList',
  'Report',
  'Exhibit',
  'Other',
] as const;
export type AttachmentKind = (typeof ATTACHMENT_KINDS)[number];

// Settings (§2.8) — configuration document enums. Wire strings are pinned by the
// server's serde encodings; `theme` is lowercase, `locale` is a BCP-47 tag.
//
// The 14 supported locales (contract F1, t19-e1): the backend's `Locale` enum accepts
// exactly these BCP-47 tags in this casing and rejects any other with `422`. `pt-PT`
// is the default. Language subtag lowercase, region subtag UPPER — note the two
// easy-to-miss variants `sv-FI` (Finland-Swedish) and `en-GB`.
export const LOCALES = [
  'pt-PT',
  'pt-BR',
  'da-DK',
  'de-DE',
  'fr-FR',
  'fi-FI',
  'sv-FI',
  'it-IT',
  'nl-NL',
  'pl-PL',
  'en-GB',
  'en-US',
  'sv-SE',
  'es-ES',
] as const;
export type Locale = (typeof LOCALES)[number];

export const SIGNATURE_FAMILIES = [
  'CartaoCidadao',
  'ChaveMovelDigital',
  'OtherQualified',
  'Manual',
] as const;
export type SignatureFamily = (typeof SIGNATURE_FAMILIES)[number];

export const THEME_MODES = ['system', 'light', 'dark'] as const;
export type ThemeMode = (typeof THEME_MODES)[number];

export const SIGNATORY_CAPACITIES = [
  'Chair',
  'Secretary',
  'Member',
  'Manager',
  'Administrator',
  'Attorney',
  'CondoOwner',
] as const;
export type SignatoryCapacity = (typeof SIGNATORY_CAPACITIES)[number];

export type Severity = 'Warning' | 'Error';
export type LegalBasisVerification = 'Verified' | 'Pending';

// CAE — Classificação Portuguesa das Atividades Económicas (plan t14 §2.7). The wire
// strings are the bare serde variant names from `chancela-cae`.
export const CAE_ROLES = ['Principal', 'Secundario'] as const;
export type CaeRole = (typeof CAE_ROLES)[number];

export const CAE_LEVELS = ['Seccao', 'Divisao', 'Grupo', 'Classe', 'Subclasse'] as const;
export type CaeLevel = (typeof CAE_LEVELS)[number];

export const CAE_REVISIONS = ['Rev3', 'Rev4'] as const;
export type CaeRevision = (typeof CAE_REVISIONS)[number];

// --- Resource DTOs (§2.3–§2.7) --------------------------------------------------

// The per-family compliance profile the server derives from an entity's kind
// (plan t31 §2.2, `profile_for`). Read-only: computed server-side, surfaced on the
// entity wire so the UI can label the rule pack, allowed channels, and calendar
// presets without re-deriving them.
export type SignaturePolicyHint =
  'QualifiedPreferred' | 'QualifiedOrHandwritten' | 'ManualAttested';

export interface EntityCalendarPreset {
  id: string;
  label: string;
  months_after_fiscal_year_end: number | null;
}

export interface EntityProfile {
  family: EntityFamily;
  rule_pack_id: string;
  allowed_channels: MeetingChannel[];
  signature_policy: SignaturePolicyHint;
  template_family: string;
  calendar_presets: EntityCalendarPreset[];
}

// Statute overlay overrides (plan t31 §2.3, ENT-03). Any field may be null when the
// statute does not tighten that dimension. Set/cleared via `PATCH /v1/entities/{id}`.
export interface StatuteQuorum {
  min_present: number;
}

export interface StatuteMajority {
  numerator: number;
  denominator: number;
}

export interface StatuteOverrides {
  quorum: StatuteQuorum | null;
  majority: StatuteMajority | null;
  convocation_notice_days: number | null;
}

export interface EntityBookStateCounts {
  created: number;
  open: number;
  closed: number;
}

/** List-only backend activity rollup from the full book state and ledger. */
export interface EntityActivitySummary {
  last_book: BookView | null;
  book_state_counts: EntityBookStateCounts;
  last_change: LedgerEventView | null;
}

export interface RegistryChangeSummary {
  label: string;
  date: string | null;
  reference: string | null;
}

export interface EntityRegistrySummary {
  imported: boolean;
  matricula: string | null;
  data_constituicao: string | null;
  capital: string | null;
  cae: CaeRefView[];
  retrieved_at: string;
  valid_until: string | null;
  expired: boolean | null;
  last_registry_change: RegistryChangeSummary | null;
}

export interface Entity {
  id: string;
  name: string;
  nipc: string;
  /** `false` ⇒ the NIPC failed control-digit validation and was stored via the override (t25). */
  nipc_validated: boolean;
  seat: string;
  family: EntityFamily;
  kind: EntityKind;
  /** Fiscal year end as `MM-DD`; absent/null means the backend's Dec 31 default. */
  fiscal_year_end?: string | null;
  /** Per-family compliance profile derived from `kind` (t31). */
  profile: EntityProfile;
  /** Statute overlay, or `null` when the entity uses the family default (t31). */
  statute: StatuteOverrides | null;
  /** Present on `GET /v1/entities`; omitted by create/detail responses. */
  activity_summary?: EntityActivitySummary;
  /** Present on GET /v1/entities; null when no certidão has been imported. */
  registry_summary?: EntityRegistrySummary | null;
}

export interface BookView {
  id: string;
  entity_id: string;
  kind: BookKind;
  state: BookState;
  purpose: string | null;
  numbering_scheme: NumberingScheme | null;
  opening_date: string | null;
  closing_date: string | null;
  closing_reason: ClosingReason | null;
  last_ata_number: number;
  predecessor: string | null;
  required_signatories_abertura: string[] | null;
  required_signatories_encerramento: string[] | null;
}

/** `GET /v1/books/{id}/legal-hold` — retention-disposal override for a book. */
export interface BookLegalHoldView {
  legal_hold: boolean;
  reason: string | null;
  actor: string | null;
  set_at: string | null;
}

/** `PUT /v1/books/{id}/legal-hold` body. `actor` is optional; session attribution wins. */
export interface SetBookLegalHoldBody {
  reason: string;
  actor?: string;
}

/** `DELETE /v1/books/{id}/legal-hold` body. Optional because session attribution is enough. */
export interface ClearBookLegalHoldBody {
  actor?: string;
}

export interface ActAttachment {
  label: string;
  kind: AttachmentKind;
  digest: string | null;
  /** Marks the attachment as beginning-of-proof evidence (t31). Optional on write. */
  beginning_of_proof?: boolean;
}

export interface ActSignatory {
  name: string;
  /** Optional contact email for coordinating this signatory. Optional on write. */
  email?: string | null;
  capacity: SignatoryCapacity;
  signed: boolean;
  /** Per-mil quota share for condominium owners, or null (t31). Optional on write. */
  permilage?: number | null;
}

// --- Structured act content (plan t31 §2.4) -------------------------------------
//
// The mesa (bureau), agenda, referenced documents, and per-item deliberations an ata
// records. All additive: an old-shape act deserializes with empty mesa/agenda/etc.

export interface ActMesa {
  presidente: string | null;
  secretarios: string[];
}

export interface ActAgendaItem {
  number: number;
  text: string;
}

export interface ActDocumentReference {
  label: string;
  reference: string | null;
}

export interface ActMemberStatement {
  member: string;
  text: string;
}

/** A recorded vote — either unanimous or a tallied count (internally tagged on `type`). */
export type ActVoteResult =
  | { type: 'Unanimous' }
  | { type: 'Recorded'; em_favor: number; contra: number; abstencoes: number };

export interface ActDeliberationItem {
  agenda_number: number | null;
  text: string;
  vote: ActVoteResult | null;
  statements: ActMemberStatement[];
}

export interface ActConveningRecipient {
  name: string;
  channel: DispatchChannel | null;
  reference: string | null;
  dispatched_at: string | null;
}

export interface ActSecondCall {
  date: string | null;
  time: string | null;
  reduced_quorum: boolean;
}

export interface ActConvening {
  convener: string | null;
  convener_capacity: SignatoryCapacity | null;
  dispatch_date: string | null;
  antecedence_days: number | null;
  channel: DispatchChannel | null;
  evidence_reference: string | null;
  recipients: ActConveningRecipient[];
  second_call: ActSecondCall | null;
}

export interface ActSealMetadata {
  rule_pack_id: string;
  version: string;
  family: EntityFamily;
  profile: EntityKind;
}

export const AI_HUMAN_VERIFICATION_STATUSES = [
  'pending_human_verification',
  'accepted_by_human',
  'rejected_by_human',
] as const;
export type AiHumanVerificationStatus = (typeof AI_HUMAN_VERIFICATION_STATUSES)[number];

export interface AiHumanVerificationView {
  status: AiHumanVerificationStatus;
  actor: string | null;
  reviewed_at: string | null;
  note: string | null;
}

export interface AiProvenanceView {
  source: string;
  tool: string | null;
  statement_source: string | null;
  human_verification: AiHumanVerificationView;
}

export interface ActView {
  id: string;
  book_id: string;
  title: string;
  channel: MeetingChannel;
  meeting_date: string | null;
  meeting_time: string | null;
  place: string | null;
  mesa: ActMesa;
  agenda: ActAgendaItem[];
  attendance_reference: string | null;
  members_present: number | null;
  members_represented: number | null;
  referenced_documents: ActDocumentReference[];
  deliberations: string;
  deliberation_items: ActDeliberationItem[];
  telematic_evidence: string | null;
  attachments: ActAttachment[];
  signatories: ActSignatory[];
  state: ActState;
  ata_number: number | null;
  payload_digest: string | null;
  seal_event_seq: number | null;
  seal_metadata: ActSealMetadata | null;
  retifies: string | null;
  convening?: ActConvening;
  ai_provenance?: AiProvenanceView | null;
}

export interface ComplianceIssue {
  rule_id: string;
  severity: Severity;
  message: string;
  legal_basis?: ComplianceLegalBasis[];
}

export interface ComplianceLegalBasis {
  source_id: string;
  source_label: string;
  article: string | null;
  article_label: string | null;
  citation: string;
  verification: LegalBasisVerification;
  source_url: string | null;
  source_complete: boolean;
}

export interface ConveningAdvisory {
  code: string;
  severity: Severity;
  message: string;
  threshold_id: string;
  actual_days: number | null;
  minimum_days: number | null;
}

export interface ComplianceReport {
  /** The dispatched family rule-pack id (t31 — no longer always `csc-art63/v2`). */
  rule_pack: string;
  /** The compliance family the pack belongs to (t31). */
  family: EntityFamily;
  /** Whether a statute overlay contributed issues (t31). */
  statute_overlay: boolean;
  issues: ComplianceIssue[];
  errors: number;
  warnings: number;
  seal_allowed: boolean;
  /** Warning-only convening advisories; omitted by the API when empty. */
  convening_advisories?: ConveningAdvisory[];
}

export interface SealResult {
  act: ActView;
  ata_number: number;
  event_seq: number;
  payload_digest: string;
  acknowledged_warnings: ComplianceIssue[];
  /**
   * The document generated by the seal (plan t48 §3.3, additive). `null` when the
   * entity family has no template for the Ata stage — the seal still succeeds, but no
   * PDF/A is produced (documented fallback, t48-e5).
   */
  document?: SealDocument | null;
}

/** The seal's generated-document summary (`SealResponse.document`, t48-e5). */
export interface SealDocument {
  id: string;
  pdf_digest: string;
  template_id: string;
}

// --- Generated documents (plan t48 §3.1–§3.3) -----------------------------------
//
// The render↔pdf seam, frozen in `chancela-core::document_model` (t48-e0). A
// `DocumentModel` is a PDF-agnostic block tree the server renders from the current act
// record; the web preview renders it to HTML so screen and PDF/A share one source of
// truth. NEVER fabricate content client-side — render only what the endpoint returns.

/** One inline text run: `text` plus bold/italic styling (t48-e0). */
export interface Run {
  text: string;
  bold: boolean;
  italic: boolean;
}

/** A two-column key/value row (t48-e0). */
export interface KvRow {
  key: string;
  value: string;
}

/** A tallied vote row: label plus favor/against/abstain counts (t48-e0). */
export interface VoteRow {
  label: string;
  favor: number;
  against: number;
  abstain: number;
}

/** A signature slot: the signer's role and name (t48-e0). */
export interface SignatureSlot {
  role: string;
  name: string;
}

/**
 * A document block — a `type`-tagged union mirroring `chancela-core::Block` (t48-e0).
 * Field/variant order is frozen server-side; new variants append.
 */
export type Block =
  | { type: 'Heading'; level: number; text: string }
  | { type: 'Paragraph'; runs: Run[] }
  | { type: 'KeyValue'; rows: KvRow[] }
  | { type: 'VoteTable'; rows: VoteRow[] }
  | { type: 'SignatureBlock'; slots: SignatureSlot[] }
  | { type: 'PageBreak' }
  | { type: 'Rule' };

/**
 * The rendered document (`GET /v1/acts/{id}/document/preview`, t48-e5). Metadata plus
 * an ordered block tree. `entity_nipc` / `created_at` are optional; `language` is a
 * BCP-47 tag (default `pt-PT`).
 */
export interface DocumentModel {
  title: string;
  entity_name: string;
  entity_nipc?: string | null;
  subject: string;
  language: string;
  created_at?: string | null;
  blocks: Block[];
}

/**
 * One template-catalog entry (`GET /v1/templates?family=&stage=`, t48-e5). Informational
 * for v1 — metadata is copied from the authored template asset. `signature_policy` is a
 * preference hint, not signature validation or a legal-validity conclusion.
 */
export interface TemplateSummary {
  id: string;
  family: EntityFamily;
  stage: LifecycleStage;
  channels: MeetingChannel[];
  signature_policy: SignaturePolicyHint;
  rule_pack_id: string;
  locale: string;
}

/** The persisted PDF's metadata inside the DOC-03 bundle (t48-e5). */
export interface DocumentBundleDocument {
  id: string;
  template_id: string;
  pdf_digest: string;
  profile: string;
  created_at: string;
}

/** The PDF descriptor inside the DOC-03 bundle (t48-e5). */
export interface DocumentBundlePdf {
  media_type: string;
  byte_length: number;
  download: string;
}

export interface DocumentBundleValidationFinding {
  severity: 'error' | 'warning' | 'info' | string;
  code: string;
  message: string;
}

export interface DocumentBundleSignedPdfSignalReport {
  validation_status: string;
  signed_pdf_signal: boolean;
  has_signature_dictionary_marker: boolean;
  signature_marker_count: number;
  has_byte_range: boolean;
  byte_range_marker_count: number;
  byte_range: [number, number, number, number] | null;
  byte_range_complete: boolean | null;
  byte_range_digest_sha256: string | null;
  signed_revision_bytes: number | null;
  covered_bytes: number | null;
  excluded_bytes: number | null;
  has_contents_marker: boolean;
  cryptographic_validation_performed: boolean;
  pades_profile: string | null;
  validation_error: string | null;
}

export interface DocumentBundleValidationReport {
  report_kind: 'document_bundle_validation' | string;
  scope: 'generated_document_bundle' | string;
  status: 'technical_consistent' | 'technical_warning' | 'technical_error' | string;
  legal_notice: string;
  bundle_document_consistency: {
    route_act_id: string;
    stored_document_act_id: string;
    act_id_matches_document: boolean;
    document_id_present: boolean;
    template_id_present: boolean;
    created_at_present: boolean;
    profile_matches_expected: boolean;
    attachments_manifest_count: number;
  };
  canonical_pdf: {
    present: boolean;
    media_type: string;
    byte_length: number;
    download: string;
    pdf_header_present: boolean;
    version: string | null;
    eof_marker_present: boolean;
    startxref_present: boolean;
    pdfa_identification_markers_present: boolean;
  };
  fixity: {
    canonical_pdf_sha256: string;
    stored_pdf_digest: string;
    canonical_pdf_digest_matches_metadata: boolean;
    attachment_count: number;
    attachments_with_digest: number;
    attachments_without_digest: number;
    signed_pdf_sha256: string | null;
    stored_signed_pdf_digest: string | null;
    signed_pdf_digest_matches_metadata: boolean | null;
  };
  signed_document: {
    present: boolean;
    status: string;
    document_id: string | null;
    document_id_matches_canonical: boolean | null;
    byte_length: number | null;
    signed_pdf_digest: string | null;
    signed_pdf_digest_matches_metadata: boolean | null;
    download: string | null;
    signing_time: string | null;
    signed_at: string | null;
    stored_signature_family: string | null;
    stored_evidentiary_level: string | null;
    trusted_list_status: string | null;
    signer_cert_subject_present: boolean | null;
    timestamp_token_present: boolean | null;
    structural_validation: DocumentBundleSignedPdfSignalReport | null;
  };
  non_certification: {
    legal_validity_claimed: false;
    pdfa_conformance_certified: false;
    pdfua_conformance_claimed: false;
    qualified_signature_claimed: false;
    dglab_certification_claimed: false;
    production_ltv_claimed: false;
    trust_provider_validation_performed: false;
  };
  findings: DocumentBundleValidationFinding[];
}

/**
 * The DOC-03 preservation bundle (`GET /v1/acts/{id}/document/bundle`, t48-e5). 404
 * until sealed (and 404 for a sealed act whose family has no template). `validation_report`
 * is local technical evidence only; it does not certify legal validity or qualified signatures.
 */
export interface DocumentBundle {
  act_id: string;
  document: DocumentBundleDocument;
  pdf: DocumentBundlePdf;
  attachments_manifest: unknown[];
  validation_report: DocumentBundleValidationReport;
}

// --- Arbitrary PDF/PAdES technical validation ----------------------------------

export interface PdfSignatureValidationBody {
  content_base64: string;
  filename?: string | null;
  declared_sha256?: string | null;
  declared_size_bytes?: number | null;
}

export type PdfValidationStatus = 'unsigned' | 'valid' | 'invalid' | 'indeterminate';

export interface PdfStructureReport {
  is_pdf: boolean;
  header_offset: number | null;
  version: string | null;
  has_eof_marker: boolean;
  has_startxref: boolean;
}

export interface PdfByteRangeReport {
  byte_range: [number, number, number, number];
  covered_len: number;
  total_len: number;
  signed_revision_len: number;
  excluded_len: number | null;
  covers_whole_file_except_contents: boolean;
  covers_signed_revision_except_contents: boolean;
  has_later_incremental_updates: boolean;
  digest_sha256: string | null;
}

export interface CadesTechnicalReport {
  status: string;
  attrs_ok: boolean;
  signing_certificate_v2_present: boolean;
  signer_cert_sha256: string;
  signer_cert_subject: string | null;
  signing_time: string | null;
}

export interface SignatureTimestampReport {
  signature_timestamp_present: boolean;
  status_scope: string;
}

export interface DssTechnicalReport {
  present: boolean;
  vri_count: number;
  vri_tu_count: number;
  vri_has_tu: boolean;
  certificate_count: number;
  ocsp_count: number;
  crl_count: number;
  revocation_evidence_present: boolean;
  certificate_sha256: string[];
  ocsp_sha256: string[];
  crl_sha256: string[];
  status_scope: string;
}

export interface DocTimeStampValidationReport {
  index: number;
  object_id: string;
  byte_range: [number, number, number, number] | null;
  document_digest_sha256: string | null;
  token_imprint_sha256: string | null;
  token_hash_algorithm: string | null;
  status: string;
  failure_reason: string | null;
}

export interface DocTimeStampTechnicalReport {
  present: boolean;
  count: number;
  token_count: number;
  token_sha256: string[];
  all_imprints_valid: boolean;
  validations: DocTimeStampValidationReport[];
  status_scope: string;
}

export interface PdfSignatureTechnicalReport {
  status: PdfValidationStatus;
  validation_performed: boolean;
  validation_error: string | null;
  signed_pdf_signal: boolean;
  signature_marker_count: number;
  byte_range_marker_count: number;
  has_contents_marker: boolean;
  pades_profile: string | null;
  byte_range: PdfByteRangeReport | null;
  cades: CadesTechnicalReport | null;
  timestamp: SignatureTimestampReport;
  dss: DssTechnicalReport;
  doc_timestamp: DocTimeStampTechnicalReport;
}

export interface TrustValidationReport {
  status: string;
  performed: boolean;
  live_trusted_list_validation_performed: boolean;
  ama_integration_performed: boolean;
  message: string;
}

export interface RevocationValidationReport {
  status: string;
  live_fetch_performed: boolean;
  freshness_validation_performed: boolean;
  embedded_evidence_inspected: boolean;
  embedded_revocation_evidence_present: boolean;
  message: string;
}

export interface QualificationValidationReport {
  status: string;
  qualified_status_claimed: boolean;
  legal_validity_claimed: boolean;
  legal_effect_assessed: boolean;
  message: string;
}

export interface PdfSignatureValidationFinding {
  severity: 'error' | 'warning' | 'info' | string;
  code: string;
  message: string;
}

export interface PdfSignatureValidationResponse {
  report_kind: 'pdf_signature_validation' | string;
  scope: 'local_technical_pdf_pades_evidence' | string;
  legal_notice: string;
  status: PdfValidationStatus;
  filename: string | null;
  sha256: string;
  size_bytes: number;
  declared_sha256: string | null;
  declared_size_bytes: number | null;
  structure: PdfStructureReport;
  signature: PdfSignatureTechnicalReport;
  trust: TrustValidationReport;
  revocation: RevocationValidationReport;
  qualification: QualificationValidationReport;
  findings: PdfSignatureValidationFinding[];
}

export interface DocumentImportValidationFinding {
  severity: 'error' | 'warning' | 'info' | string;
  code: string;
  message: string;
}

export interface DocumentImportFixityReport {
  size_bytes: number;
  sha256: string;
  declared_size_bytes: number | null;
  declared_sha256: string | null;
  size_matches_declared: boolean | null;
  sha256_matches_declared: boolean | null;
}

export interface DocumentImportContentTypeReport {
  declared: string | null;
  detected: string;
  declared_matches_detected: boolean | null;
}

export interface DocumentEvidenceClassificationReport {
  family: string;
  classification: string;
  non_canonical: boolean;
  warning: string;
  canonical_conversion_performed: boolean;
  canonical_pdfa_generated: boolean;
  legal_validity_claimed: boolean;
}

export interface DocumentImportPdfARecognitionReport {
  is_pdfa_ish: boolean;
  part: string | null;
  conformance: string | null;
  part_values: string[];
  conformance_values: string[];
  duplicate_metadata: boolean;
  odd_metadata: boolean;
}

export interface DocumentImportPdfRecognitionReport {
  is_pdf: boolean;
  header_offset: number | null;
  version: string | null;
  has_eof_marker: boolean;
  has_startxref: boolean;
  pdfa: DocumentImportPdfARecognitionReport;
}

export interface LegacyWordDocRecognitionReport {
  is_ole_cfb: boolean;
  is_legacy_word_doc: boolean;
  filename_extension_doc: boolean;
  declared_content_type_msword: boolean;
  declared_content_type_generic: boolean;
  filename_extension_conflict: boolean;
  declared_content_type_conflict: boolean;
  macro_execution_performed: boolean;
  conversion_performed: boolean;
  canonical_pdfa_generated: boolean;
}

export interface ImageRecognitionReport {
  is_image: boolean;
  format: string | null;
  width: number | null;
  height: number | null;
  declared_content_type_image: boolean;
  filename_extension_image: boolean;
  conversion_performed: boolean;
  canonical_pdfa_generated: boolean;
}

export interface TextDocumentRecognitionReport {
  is_supported_text: boolean;
  kind: string | null;
  utf8_valid: boolean;
  has_nul: boolean;
  declared_content_type_text: boolean;
  filename_extension_text: boolean;
  structure_validation_performed: boolean;
  conversion_performed: boolean;
  canonical_pdfa_generated: boolean;
}

export interface ZipBundleRecognitionReport {
  is_zip: boolean;
  readable: boolean;
  entry_count: number;
  unsafe_entry_count: number;
  unsafe_entry_names: string[];
  total_uncompressed_size: number | null;
  extraction_performed: boolean;
  canonical_pdfa_generated: boolean;
  validation_error: string | null;
}

/** `POST /v1/documents/import/validate` read-only validation report. */
export interface DocumentImportValidationReport {
  report_kind: 'document_import_validation' | string;
  scope: 'non_canonical_import_candidate' | string;
  legal_notice: string;
  filename: string | null;
  size_bytes: number;
  sha256: string;
  fixity: DocumentImportFixityReport;
  content_type: DocumentImportContentTypeReport;
  classification: DocumentEvidenceClassificationReport;
  preservation_policy?: DocumentPreservationPolicyReport;
  pdf: DocumentImportPdfRecognitionReport;
  legacy_word: LegacyWordDocRecognitionReport;
  image: ImageRecognitionReport;
  text: TextDocumentRecognitionReport;
  zip_bundle: ZipBundleRecognitionReport;
  signature: DocumentBundleSignedPdfSignalReport;
  can_accept_non_canonical_import: boolean;
  findings: DocumentImportValidationFinding[];
}

/** Body for `POST /v1/documents/import`: validated again server-side before persistence. */
export interface ImportDocumentBody {
  content_base64: string;
  content_type?: string | null;
  filename?: string | null;
  act_id?: string | null;
}

export type ImportedDocumentReviewStatus =
  | 'operator_review_required'
  | 'ocr_review_required'
  | 'canonical_conversion_review_required'
  | 'reviewed_non_canonical_original_only'
  | 'rejected_non_canonical_evidence'
  | string;

export type ImportedDocumentReviewPatchStatus =
  'reviewed_non_canonical_original_only' | 'rejected_non_canonical_evidence';

export type ImportedDocumentCanonicalRecordStatus = 'not_canonical_record' | string;

export type ImportedDocumentSignedArtifactStatus = 'not_signed_artifact' | string;

export type ImportedDocumentReviewGuardrail =
  | 'preserved_original_bytes_remain_non_canonical_evidence'
  | 'canonical_pdfa_record_is_not_replaced'
  | 'signed_pdf_artifact_is_not_created_or_validated'
  | 'ocr_or_conversion_output_is_not_promoted_to_canonical_records'
  | string;

/** Body for `PATCH /v1/documents/imported/{id}/review`: metadata-only review transition. */
export interface ImportedDocumentReviewBody {
  review_status: ImportedDocumentReviewPatchStatus;
  review_note?: string | null;
}

export interface DocumentPreservationPolicyReport {
  review_state: string;
  requires_operator_review: boolean;
  requires_ocr_review: boolean;
  canonical_record_status?: ImportedDocumentCanonicalRecordStatus;
  signed_artifact_status?: ImportedDocumentSignedArtifactStatus;
  review_guardrail_checklist?: ImportedDocumentReviewGuardrail[];
  canonical_conversion_status: string;
  original_bytes_preservation_status: string;
  preservation_action: string;
  canonical_conversion_performed: boolean;
  canonical_pdfa_generated: boolean;
  legal_acceptance_claimed: boolean;
}

/** Non-canonical imported document metadata. Raw bytes are fetched via `bytes_download`. */
export interface ImportedDocumentView {
  id: string;
  act_id: string | null;
  filename: string | null;
  size_bytes: number;
  sha256: string;
  declared_content_type: string | null;
  detected_content_type: string;
  evidence_family: string;
  classification: string;
  imported_at: string;
  imported_by: string;
  /** Optional additive review metadata; older API responses omit it. */
  operator_review_status?: ImportedDocumentReviewStatus | null;
  operator_reviewed_at?: string | null;
  operator_reviewed_by?: string | null;
  operator_review_note?: string | null;
  operator_review_notice?: string | null;
  non_canonical: boolean;
  requires_ocr_review?: boolean;
  canonical_record_status?: ImportedDocumentCanonicalRecordStatus;
  signed_artifact_status?: ImportedDocumentSignedArtifactStatus;
  review_guardrail_checklist?: ImportedDocumentReviewGuardrail[];
  canonical_conversion_status?: string;
  canonical_conversion_performed?: boolean;
  legal_acceptance_claimed?: boolean;
  preservation_policy?: DocumentPreservationPolicyReport;
  legal_notice: string;
  bytes_download: string;
}

/** PKI audit attestation joined onto a ledger event when the actor's session held an
 *  unlocked attestation key (t29). `null` when the event was not attested. */
export interface LedgerEventAttestation {
  username: string;
  fingerprint: string;
  algorithm: string;
}

export interface LedgerEventView {
  id: string;
  seq: number;
  actor: string;
  justification: string | null;
  timestamp: string;
  scope: string;
  kind: string;
  payload_digest: string;
  prev_hash: string;
  hash: string;
  /** Canonical chain ids this event belongs to, including `global`. */
  chains: string[];
  attestation: LedgerEventAttestation | null;
}

/** Query params for `GET /v1/ledger/events`. */
export interface LedgerQueryParams {
  chain?: string;
  scope?: string;
  limit?: number;
}

/** Query params for `GET /v1/ledger/archive/document`, which streams a PDF/A. */
export interface LedgerArchiveDocumentParams extends LedgerQueryParams {
  kind?: string;
  actor?: string;
  from?: string;
  to?: string;
}

export interface LedgerVerify {
  valid: boolean;
  length: number;
  error?: string | null;
}

export interface Dashboard {
  entities: number;
  books_open: number;
  books_total: number;
  acts_total: number;
  acts_draft: number;
  acts_awaiting_signature: number;
  acts_sealed: number;
  unresolved_compliance: number;
  ledger_length: number;
  ledger_valid: boolean;
  current_work: DashboardCurrentWork;
  alerts: DashboardAlert[];
  reminders: DashboardReminder[];
  recent_events: LedgerEventView[];
}

export type NotificationTriageStatus = 'unread' | 'read' | 'dismissed' | 'acknowledged';

export interface NotificationTriageEntry {
  owner?: string;
  notification_id: string;
  status: Exclude<NotificationTriageStatus, 'unread'>;
  updated_at: string;
}

export interface NotificationTriageResponse {
  entries: NotificationTriageEntry[];
  durable: boolean;
  max_entries_per_owner: number;
}

export interface NotificationTriageUpdateBody {
  status: NotificationTriageStatus;
}

export interface NotificationTriageUpdateResponse {
  status: NotificationTriageStatus;
  entry: NotificationTriageEntry | null;
  durable: boolean;
}

export interface DashboardCurrentWork {
  open_books: DashboardOpenBook[];
  act_counts_by_state: DashboardActStateCounts;
}

export interface DashboardActStateCounts {
  Draft: number;
  Review: number;
  Convened: number;
  Deliberated: number;
  TextApproved: number;
  Signing: number;
  Sealed: number;
  Archived: number;
}

export interface DashboardOpenBook {
  book_id: string;
  entity_id: string;
  entity_name: string | null;
  kind: BookKind;
  purpose: string | null;
  opening_date: string | null;
  last_ata_number: number;
  total_acts: number;
  open_acts: number;
  next_ata_number: number;
  links: DashboardTargetLinks;
}

export type DashboardAlertLabel = 'Advisory' | 'ReviewRequired';

export interface DashboardAlert {
  code: string;
  label: DashboardAlertLabel;
  severity?: 'Info' | 'Warning' | 'Error' | string;
  category: string;
  message: string;
  params: Record<string, string>;
  target: DashboardAlertTarget;
  source: string | null;
  law_refs?: DashboardLawReference[];
  action?: DashboardAction | null;
  recommended_next_steps?: string[];
  i18n?: DashboardI18n | null;
}

export interface DashboardAlertTarget {
  entity_id: string | null;
  book_id: string | null;
  act_id: string | null;
  links: DashboardTargetLinks;
}

export interface DashboardTargetLinks {
  entity: string | null;
  book: string | null;
  act: string | null;
  ledger: string | null;
}

export interface DashboardLawReference {
  diploma_id: string;
  article: string;
  label: string;
  heading: string;
  verification: string;
  source_url: string | null;
  source_complete: boolean;
}

export interface DashboardAction {
  kind: string;
  label_key: string;
  api_href: string | null;
  route: string | null;
}

export interface DashboardI18n {
  title_key: string;
  body_key: string;
  action_key: string | null;
}

export type DashboardReminderSeverity = 'Advisory' | 'Info' | 'Warning';
export type DashboardReminderStatus = 'Upcoming' | 'DueSoon' | 'Overdue';

export interface DashboardReminder {
  due_date: string;
  severity: DashboardReminderSeverity;
  status: DashboardReminderStatus;
  reason: string;
  entity_id: string;
  entity_name: string;
  source_rule: string;
  source_profile: string;
  params?: Record<string, string>;
  law_refs?: DashboardLawReference[];
  action?: DashboardAction | null;
  recommended_next_steps?: string[];
  i18n?: DashboardI18n | null;
}

// --- Registry / certidão permanente (§2.7, plan t11) ----------------------------
//
// The certidão permanente import surface. `legal_form` is a normalized, EntityKind
// -aligned variant string (e.g. `SociedadePorQuotas`, `Fundacao`) or `null` when the
// natureza jurídica could not be mapped; `forma_juridica` always carries the raw
// Portuguese text. Provenance carries only the MASKED access code (`****-****-NNNN`)
// — the full código de acesso is a secret and never crosses the wire back to the UI.

export interface RegistryProvenanceView {
  access_code_masked: string;
  retrieved_at: string;
  source_url: string;
  raw_digest: string;
  /** Conservatória / oficial / validity metadata parsed from the certidão (t21). */
  conservatoria: string | null;
  oficial: string | null;
  subscribed_on: string | null;
  valid_until: string | null;
  /** Computed against today: `true` past `valid_until`, `null` when unknown/unparseable (t21). */
  expired: boolean | null;
}

export interface RegistryOfficerView {
  name: string;
  role: string | null;
  appointment_date: string | null;
  cessation_date: string | null;
  source_event: string | null;
}

// --- Structured inscription layer (plan t21 §2.7-v2) ----------------------------
//
// The parsed structure behind each inscrição's raw `text`. Every field is best-effort:
// a certidão the parser only partially understands still carries its full `text`, and
// `detail`/`payload` fall back to `null`. These mirror the `chancela-registry` model.

export interface AddressView {
  lines: string[];
  distrito: string | null;
  concelho: string | null;
  freguesia: string | null;
  postal_code: string | null;
  locality: string | null;
}

export interface MoneyView {
  amount_text: string;
  currency: string | null;
}

export interface PersonView {
  name: string;
  nif: string | null;
  estado_civil: string | null;
  nacionalidade: string | null;
  residencia: AddressView | null;
}

export interface QuotaView {
  amount: MoneyView;
  titular: PersonView;
}

export interface OrganMemberView {
  name: string;
  nif: string | null;
  cargo: string | null;
  nacionalidade: string | null;
  residencia: AddressView | null;
}

export interface OrganView {
  name: string;
  members: OrganMemberView[];
}

/** Discriminated union on `type` mirroring the server's `InscriptionPayloadView`. */
export type InscriptionPayloadView =
  | {
      type: 'Constitution';
      firma: string | null;
      nipc: string | null;
      natureza_juridica: string | null;
      sede: AddressView | null;
      objecto: string | null;
      capital: MoneyView | null;
      capital_realization_note: string | null;
      fiscal_year_end: string | null;
      socios: QuotaView[];
      forma_de_obrigar: string | null;
      orgaos: OrganView[];
      deliberation_date: string | null;
    }
  | { type: 'Designation'; orgaos: OrganView[]; deliberation_date: string | null }
  | {
      type: 'Cessation';
      members: OrganMemberView[];
      cause: string | null;
      date: string | null;
    }
  | {
      type: 'ContractAmendment';
      new_firma: string | null;
      new_sede: AddressView | null;
      new_objecto: string | null;
      new_capital: MoneyView | null;
      deliberation_date: string | null;
    };

export interface ApresentacaoView {
  number: string | null;
  date: string | null;
  time: string | null;
  act_kinds: string[];
}

export interface RegistryOfficialSignatureView {
  conservatoria: string | null;
  oficial: string | null;
}

export interface InscriptionDetailView {
  apresentacao: ApresentacaoView | null;
  payload: InscriptionPayloadView | null;
  signatures: RegistryOfficialSignatureView[];
}

export interface RegistryAnnotationView {
  number: string | null;
  date: string | null;
  publication_url: string | null;
  text: string;
}

export interface RegistryEventView {
  number: string | null;
  kind_hint: string | null;
  apresentacao: string | null;
  date: string | null;
  text: string;
  /** Structured detail parsed from `text`, or `null` when unstructured (t21). */
  detail: InscriptionDetailView | null;
}

/**
 * A single role-tagged CAE from a certidão, enriched by the server against the CAE
 * catalog (plan t14 §2.7). `designation`/`level`/`revision` are `null` when the code is
 * not catalogued — a certidão may legitimately carry a withdrawn or mistyped code, so
 * the null case is rendered honestly rather than hidden.
 */
export interface CaeRefView {
  code: string;
  role: CaeRole;
  designation: string | null;
  level: CaeLevel | null;
  revision: CaeRevision | null;
}

export interface RegistryExtractView {
  matricula: string | null;
  nipc: string | null;
  firma: string | null;
  forma_juridica: string | null;
  /** Normalized EntityKind-aligned variant name, or null when unmapped. */
  legal_form: string | null;
  sede: string | null;
  cae: CaeRefView[];
  objeto: string | null;
  capital: string | null;
  data_constituicao: string | null;
  orgaos: RegistryOfficerView[];
  inscricoes: RegistryEventView[];
  /** Averbamentos / anotações on the matrícula (t21). */
  anotacoes: RegistryAnnotationView[];
  provenance: RegistryProvenanceView;
}

export interface RegistryConflict {
  field: string;
  current: string | null;
  incoming: string | null;
}

export interface RegistryImportReport {
  entity: Entity;
  extract: RegistryExtractView;
  applied: string[];
  conflicts: RegistryConflict[];
  /** Non-fatal import advisories, e.g. an expired certidão (t21). PT text; UI localizes. */
  warnings: string[];
}

// --- CAE catalog + lookup (§2.7, plan t14) --------------------------------------
//
// The CAE library endpoints. A `CaeNode` is one classification node (código +
// designação at a given level/revision); `GET /v1/cae/{code}` returns the resolved
// node plus its `hierarchy` (secção → … → self). The catalog metadata (origin,
// generation stamp, per-revision counts) surfaces the auto-update state.

export interface CaeNode {
  code: string;
  designation: string;
  level: CaeLevel;
  revision: CaeRevision;
}

export interface CaeEntryView extends CaeNode {
  /** Secção → … → self, each a plain node. */
  hierarchy: CaeNode[];
}

export interface CaeLevelCounts {
  seccao: number;
  divisao: number;
  grupo: number;
  classe: number;
  subclasse: number;
}

/** Provenance of a refreshed catalog (t23) — omitted for embedded/cache origins. */
export interface CaeProvenance {
  source_kind: 'DiarioRepublica' | 'Mirror';
  source_url: string;
  artifact_digest: string;
  retrieved_at: string;
  parser_version: string;
}

export interface CaeCatalogView {
  origin: 'Embedded' | 'Cache';
  schema_version: number;
  generated_at: string;
  source_note: string;
  digest: string;
  counts: { rev3: CaeLevelCounts; rev4: CaeLevelCounts };
  /** Set only when the catalog came from a refresh (t23); absent for embedded/cache. */
  provenance?: CaeProvenance;
}

/** One failed source while walking the refresh chain (t23). */
export interface CaeSourceFailure {
  source: string;
  error: string;
}

/** Result of `POST /v1/cae/refresh` — `updated` is false for a same/older dataset. */
export interface CaeRefreshResult {
  updated: boolean;
  metadata: CaeCatalogView;
  note: string;
  /** Label of the source that superseded, or `null` (up to date / legacy path) (t23). */
  source: string | null;
  /** Per-source failures collected while walking the chain; empty on a clean run (t23). */
  failures: CaeSourceFailure[];
}

/** One current official CAE version as INE SMI publishes it (t33-e2). */
export interface CaeVersion {
  version: string;
  designation: string;
}

/** `GET /v1/cae/updates` — the INE SMI update-availability signal (t33-e2). RFC-3339
 *  `checked_at`; `502 {error}` when SMI is unreachable/unparseable. */
export interface CaeUpdates {
  rev3: CaeVersion;
  rev4: CaeVersion;
  checked_at: string;
}

// --- TSL trust catalog (§ signatures/trust) -------------------------------------
//
// Read-only surface over the parsed Portuguese Trusted List. The backend does not fetch live TSL
// data from these endpoints: it parses a cached XML if present, otherwise the bundled fixture, and
// reports XML-DSig validation status explicitly.

export const TSL_SOURCE_KINDS = ['Cache', 'Fixture'] as const;
export type TslSourceKind = (typeof TSL_SOURCE_KINDS)[number];

export const TSL_SIGNATURE_STATUSES = ['Valid', 'Invalid'] as const;
export type TslSignatureStatus = (typeof TSL_SIGNATURE_STATUSES)[number];

export const TSL_SERVICE_STATUS_KINDS = ['Granted', 'Withdrawn', 'Other'] as const;
export type TslServiceStatusKind = (typeof TSL_SERVICE_STATUS_KINDS)[number];

export interface TslSourceView {
  kind: TslSourceKind;
  path: string | null;
  note: string;
}

export interface TslValidationView {
  checked_at: string;
  signature: TslSignatureStatus;
  error: string | null;
}

export type TslRefreshSourceKind = 'Url' | 'File';
export type TslRefreshOutcome = 'Success' | 'Failed';

export interface TslRefreshStatusView {
  attempted_at: string;
  source_kind: TslRefreshSourceKind;
  source_url: string | null;
  source_path: string | null;
  target_path: string | null;
  outcome: TslRefreshOutcome;
  validation: TslValidationView;
  providers: number | null;
  services: number | null;
  ca_qc_services: number | null;
  qualified_esignature_services: number | null;
  trusted_esignature_services: number | null;
  error: string | null;
}

export interface TslRefreshRequest {
  url?: string;
  path?: string;
}

export interface TslSummaryView {
  source: TslSourceView;
  last_refresh: TslRefreshStatusView | null;
  scheme_operator_name: string;
  scheme_name: string;
  scheme_territory: string;
  sequence_number: number | null;
  issue_date_time: string | null;
  next_update: string | null;
  stale: boolean;
  validation: TslValidationView;
  providers: number;
  services: number;
  ca_qc_services: number;
  qualified_esignature_services: number;
  trusted_esignature_services: number;
}

export interface TslServiceStatusView {
  kind: TslServiceStatusKind;
  uri: string | null;
}

export interface TslIdentitySummaryView {
  certificates: number;
  subject_names: string[];
  subject_key_ids: string[];
}

export interface TslProviderAnalysisView {
  services: number;
  granted_services: number;
  withdrawn_services: number;
  other_status_services: number;
  services_with_history: number;
  services_with_supply_points: number;
  ca_qc_services: number;
  qualified_esignature_services: number;
  trusted_esignature_services: number;
  duplicate_service_names: string[];
}

export interface TslServiceSummaryView {
  id: string;
  provider_id: string;
  provider_name: string;
  name: string;
  service_type: string;
  status: TslServiceStatusView;
  status_starting_time: string | null;
  status_starting_time_raw: string | null;
  ca_qc: boolean;
  qualified_for_esignatures: boolean;
  trusted_for_esignatures: boolean;
  additional_service_info: string[];
  service_supply_points: string[];
  history_count: number;
  identities: TslIdentitySummaryView;
}

export interface TslProviderView {
  id: string;
  name: string;
  trade_names: string[];
  information_uris: string[];
  analysis: TslProviderAnalysisView;
  services: TslServiceSummaryView[];
}

export interface TslCatalogView {
  summary: TslSummaryView;
  providers: TslProviderView[];
}

export interface TslCatalogSearchParams {
  search?: string;
  service_type?: string;
  status?: string;
  history?: string;
  supply_point?: string;
  limit?: number;
}

export interface TslProviderDetailView {
  provider: TslProviderView;
  summary: TslSummaryView;
}

export interface TslDigitalIdentityView {
  kind: string;
  value: string;
  sha256: string | null;
  byte_length: number | null;
}

export interface TslServiceHistoryView {
  name: string;
  service_type: string;
  status: TslServiceStatusView;
  status_starting_time: string | null;
  status_starting_time_raw: string | null;
  additional_service_info: string[];
  service_supply_points: string[];
  identities: TslIdentitySummaryView;
}

export interface TslServiceDetailView extends TslServiceSummaryView {
  digital_identities: TslDigitalIdentityView[];
  history: TslServiceHistoryView[];
  summary: TslSummaryView;
}

// --- TSA diagnostics/catalog (§ signatures/trust) -------------------------------
//
// Read-only TSA tooling over the configured RFC 3161 endpoint plus an offline fixture probe.
// No live TSA request is made by this surface.

export const TSA_STATUS_KINDS = ['Ready', 'Unconfigured', 'Error'] as const;
export type TsaStatusKind = (typeof TSA_STATUS_KINDS)[number];

export const TSA_PROBE_KINDS = ['Fixture'] as const;
export type TsaProbeKind = (typeof TSA_PROBE_KINDS)[number];

export const TSA_PROBE_STATUSES = ['Passed', 'Failed'] as const;
export type TsaProbeStatus = (typeof TSA_PROBE_STATUSES)[number];

export interface TsaProfileView {
  protocol: string;
  hash_algorithm: string;
  request_content_type: string;
  response_content_type: string;
  nonce_policy: string;
  cert_req_default: boolean;
  accepted_policy: string;
}

export interface TsaAcceptedHashView {
  algorithm: string;
  input: string;
  digest: string;
}

export interface TsaTimestampMetadataView {
  gen_time: string;
  policy: string;
  serial_number: string;
  token_sha256: string;
  token_bytes: number;
  tsa_certificate_embedded: boolean;
}

export interface TsaProbeView {
  kind: TsaProbeKind;
  status: TsaProbeStatus;
  checked_at: string;
  request_der_sha256: string;
  response_der_sha256: string;
  request_matches_fixture: boolean;
  error: string | null;
}

export interface TsaTslDiagnosticsView {
  source: TslSourceView;
  signature: TslSignatureStatus;
  error: string | null;
}

export interface TsaSummaryView {
  configured_url: string | null;
  status: TsaStatusKind;
  status_message: string;
  profile: TsaProfileView;
  accepted_hash: TsaAcceptedHashView;
  timestamp: TsaTimestampMetadataView | null;
  last_probe: TsaProbeView;
  tsl: TsaTslDiagnosticsView;
  records: number;
  granted_records: number;
  trusted_records: number;
  policy_analysis: TsaPolicyAnalysisView;
}

export interface TsaPolicyAnalysisView {
  accepted_policy: string;
  fixture_policy: string | null;
  fixture_policy_accepted: boolean;
  qualified_timestamp_records: number;
  trusted_qualified_timestamp_records: number;
  advisory: boolean;
}

export interface TsaRecordView {
  id: string;
  provider_id: string;
  provider_name: string;
  name: string;
  service_type: string;
  status: TslServiceStatusView;
  status_starting_time: string | null;
  status_starting_time_raw: string | null;
  qualified_timestamp_service: boolean;
  granted: boolean;
  effective: boolean;
  trusted: boolean;
  additional_service_info: string[];
  service_supply_points: string[];
  history_count: number;
  identities: TslIdentitySummaryView;
  analysis: TsaRecordAnalysisView;
}

export interface TsaRecordAnalysisView {
  classification: string;
  trust_basis: string;
  blocking_reasons: string[];
}

export interface TsaCatalogView {
  summary: TsaSummaryView;
  records: TsaRecordView[];
}

export type TsaCatalogSearchParams = TslCatalogSearchParams;

// --- Law archive (t27, FROZEN §law-v1) — the local "mini law archive" -----------
//
// The backend law store (t27, chancela-api — `.orchestration/logs/t27-e1.md`) exposes
// `GET /v1/law` (200 bare array of LawEntryView, manifest merged with store state),
// `POST /v1/law/{id}/fetch` (download the official PDF → CHANCELA_DATA_DIR/laws/,
// digest-pinned → 200 LawEntryView), `GET /v1/law/{id}/pdf` (serve stored bytes) and
// `DELETE /v1/law/{id}/pdf` (200 LawEntryView). The UI feature-detects `/v1/law` and
// degrades to links-only when absent.
//
// IMPORTANT — the manifest is its own curation (9 diplomas, its own ids; only the two CAE
// diplomas carry a non-null `pdf_url`, i.e. are archivable). Our display shelf
// (`features/legislacao/diplomas.ts`, 16 finer-grained entries) is the DISPLAY source of
// truth; the manifest is the authority for STORED state. We look up the manifest by id and
// only offer archive actions where a matching server entry exists AND its `pdf_url` is
// non-null; everywhere else the card is links-only. The id-scheme reconciliation (our
// per-article ids vs the server's per-diploma ids) is a future t27-web concern.

/** A law-archive manifest entry, exactly the frozen §law-v1 `LawEntryView`. */
export interface LawEntryView {
  /** The server's diploma id (its own id scheme — not necessarily a `Diploma.id`). */
  id: string;
  title: string;
  ref: string;
  articles: string[];
  why: string;
  official_url: string;
  /** The pinned official PDF the store can fetch, or `null` (not archivable → 409 on fetch). */
  pdf_url: string | null;
  last_amended: string | null;
  reviewed_on: string;
  /** Whether the PDF bytes are stored locally and servable at `/v1/law/{id}/pdf`. */
  stored: boolean;
  /** sha-256 (64-hex) of the stored bytes, when stored. */
  stored_digest: string | null;
  /** Byte length of the stored PDF, when stored. */
  stored_bytes: number | null;
  /** RFC-3339 timestamp of when the PDF was fetched, when stored. */
  retrieved_at: string | null;
}

// --- Law corpus reader (t55-E2, FROZEN corpus-v1) — full-text statute reader ------
//
// The read-only, full-text corpus endpoints (`chancela-api::law`, t55-E2), distinct from
// the PDF archive above: `GET /v1/law/corpus` (provenance/integrity metadata + per-diploma
// summaries), `GET /v1/law/corpus/{diploma}` (a diploma + its full article set), `GET
// /v1/law/corpus/{diploma}/{article}` (one article's full text + citation), and `GET
// /v1/law/corpus/search?q=&limit=` (accent/case-insensitive full-text search). All gated
// `law.read@Global`. The **authenticity contract** is on the wire: every article/hit carries
// its `verification` (`Verified`/`Pending`) + `verified` boolean; a `Pending` article's `body`
// is the loud unverified marker, NEVER an un-sourced body — the reader badges the two apart
// and never presents `Pending` text as authoritative law. These mirror the server views
// byte-for-byte. Optional (`skip_serializing_if`) fields are omitted from the wire when absent.

/** Whether a corpus article's body is authentically vendored or still a placeholder. */
export const LAW_VERIFICATIONS = ['Verified', 'Pending'] as const;
export type LawVerification = (typeof LAW_VERIFICATIONS)[number];

/** The legal instrument a corpus diploma is (bare serde variant names). */
export const LAW_DIPLOMA_KINDS = [
  'Codigo',
  'DecretoLei',
  'Lei',
  'RegulamentoUe',
  'DiretivaUe',
] as const;
export type LawDiplomaKind = (typeof LAW_DIPLOMA_KINDS)[number];

/** Where the active corpus was loaded from. */
export type LawCorpusOrigin = 'Embedded' | 'Cache';

/** Per-corpus counts surfaced on the corpus metadata. */
export interface LawCounts {
  diplomas: number;
  articles: number;
  verified: number;
  pending: number;
}

/** Provenance of an obtained corpus (mirrors `CaeProvenance`); absent for the embedded corpus. */
export interface LawCorpusProvenance {
  source_kind: string;
  source_url: string;
  artifact_digest: string;
  retrieved_at: string;
  parser_version: string;
}

/**
 * One article's provenance/citation. `diploma`, `article` and `complete` are always present;
 * the authenticity fields (`dr_reference`, `dr_date`, `url`, `source_digest`, `retrieved_at`)
 * are omitted from the wire while an article is `Pending`. `complete` is the server's
 * `is_complete()` — the precondition a `Verified` article must satisfy.
 */
export interface LawSourceView {
  diploma: string;
  article: string;
  dr_reference?: string;
  dr_date?: string;
  url?: string;
  source_digest?: string;
  retrieved_at?: string;
  complete: boolean;
}

/**
 * One corpus article with its full (display) text + authenticity + citation. `body` is the
 * verbatim text once `Verified`, or the loud unverified marker while `Pending` — never a raw
 * un-sourced body. `cross_refs` is omitted from the wire when empty.
 */
export interface LawArticleView {
  diploma_id: string;
  number: string;
  label: string;
  heading: string;
  body: string;
  verification: LawVerification;
  verified: boolean;
  cross_refs?: string[];
  source: LawSourceView;
}

/**
 * A diploma summary (no article bodies): the element of `GET /v1/law/corpus` and the header of
 * a diploma detail, with per-diploma authenticity counts. `eli` is omitted when absent.
 */
export interface LawDiplomaSummaryView {
  id: string;
  kind: LawDiplomaKind;
  number: string;
  title: string;
  ref: string;
  official_url: string;
  eli?: string;
  article_count: number;
  verified_count: number;
  pending_count: number;
}

/**
 * `GET /v1/law/corpus` — the embedded corpus' provenance/integrity metadata plus a per-diploma
 * summary list. `provenance` is present only on an obtained corpus (the embedded corpus omits it).
 */
export interface LawCorpusView {
  schema_version: number;
  generated_at: string;
  source_note: string;
  digest: string;
  origin: LawCorpusOrigin;
  counts: LawCounts;
  provenance?: LawCorpusProvenance;
  diplomas: LawDiplomaSummaryView[];
}

/**
 * `GET /v1/law/corpus/{diploma}` — a diploma with its full article set. The server `flatten`s
 * the summary onto the body, so the wire shape is every {@link LawDiplomaSummaryView} field plus
 * `articles`.
 */
export interface LawDiplomaDetailView extends LawDiplomaSummaryView {
  articles: LawArticleView[];
}

/** One search hit: the matched article, its owning diploma, a context snippet, and authenticity. */
export interface LawSearchHitView {
  diploma_id: string;
  diploma_title: string;
  number: string;
  label: string;
  heading: string;
  /** A `…`-elided context window around the first match. */
  snippet: string;
  verification: LawVerification;
  verified: boolean;
}

/** `GET /v1/law/corpus/search` — the echoed query, hit count, and ranked hits. */
export interface LawSearchView {
  query: string;
  count: number;
  results: LawSearchHitView[];
}

/** One selected corpus article reference to normalize for draft/compliance citation use. */
export interface LawCitationRef {
  diploma_id: string;
  article: string;
}

/** `POST /v1/law/citations/resolve` request body. Bounded server-side. */
export interface LawCitationRequest {
  references: LawCitationRef[];
}

/**
 * Draft/compliance-friendly legal-basis metadata derived from the corpus. `verification` and
 * `source_complete` are carried through without upgrading pending DRE entries.
 */
export interface LawCitationView {
  source_id: string;
  source_label: string;
  article: string;
  article_label: string;
  citation: string;
  verification: LawVerification;
  source_url: string | null;
  source_complete: boolean;
  dr_reference?: string;
  source_digest?: string;
  retrieved_at?: string;
}

/** Read-only citation report; `legal_notice` is non-authoritative wording from the API. */
export interface LawCitationReport {
  legal_notice: string;
  count: number;
  citations: LawCitationView[];
}

// --- Users + session (§2.8, plan t14; auth t41/t29) -----------------------------
//
// User accounts identify the actor behind every ledger mutation AND gate access to it:
// since t41 every mutation requires a session, and since t29 a user may hold an optional
// sign-in secret (argon2id) and a PKI audit-attestation key. No secret material ever
// crosses the wire (`UserView` carries only booleans + a key fingerprint). A session is an
// in-memory token (`X-Chancela-Session`) minted by `POST /v1/session` that resolves the
// current user; a password is a local tamper speed-bump, not at-rest encryption.

export interface UserView {
  id: string;
  username: string;
  display_name: string;
  /** Optional contact email associated with this user. Omitted when unset. */
  email?: string;
  created_at: string;
  active: boolean;
  /** Whether a sign-in secret is set (t29). No secret material ever crosses the wire. */
  has_secret: boolean;
  /** Whether a PKI audit-attestation key is provisioned (t29). */
  has_attestation_key: boolean;
  /** Whether a recovery phrase is set (t51). No phrase material ever crosses the wire. */
  has_recovery_phrase: boolean;
  /** 32-hex fingerprint of the attestation key; omitted when none (t29). */
  attestation_key_fingerprint?: string;
}

export interface CreateUserBody {
  username: string;
  display_name?: string;
  email?: string;
}

export interface UpdateUserBody {
  display_name?: string;
  email?: string | null;
  active?: boolean;
}

// --- RBAC permissions (§ t64-E3, FROZEN for the E5 web permissions context) ------
//
// The web half of the frozen `chancela-api::session` permission DTOs. A grant is one
// `(permission, scope)` pair the signed-in principal effectively holds, tagged by how it
// arrived (`role` ∪ `delegation`). `scope` is a serde-`kind`-tagged union: `global` covers
// everything, `entity` covers that entity (and its books), `book` covers that one book —
// so `can(perm, scope)` maps to the server's `has_permission` semantics. These mirror the
// server views byte-for-byte and are consumed both by the `GET /v1/session/permissions`
// endpoint (`SessionPermissions`) and by the first-paint `SessionView.permissions` embed.

/** A grant's provenance: a role assignment or a delegation (t64-E3). */
export const PERMISSION_SOURCES = ['role', 'delegation'] as const;
export type PermissionSource = (typeof PERMISSION_SOURCES)[number];

/**
 * The scope a grant/assignment is held at — a `kind`-tagged union mirroring the server's
 * `ScopeView` (t64-E3). `global` carries no id; `entity`/`book` carry the target uuid.
 */
export type PermissionScope =
  { kind: 'global' } | { kind: 'entity'; id: string } | { kind: 'book'; id: string };

/**
 * One effective grant: a dotted permission id (e.g. `entity.read`), the scope it is held
 * at, and whether it arrived via a role or a delegation (t64-E3, FROZEN for E5).
 */
export interface PermissionGrant {
  /** The dotted permission id, e.g. `"entity.read"`. */
  permission: string;
  scope: PermissionScope;
  source: PermissionSource;
}

/** One role assignment the user holds: the role id and the scope it is held at (t64-E3). */
export interface RoleAssignmentView {
  role_id: string;
  scope: PermissionScope;
}

/**
 * `GET /v1/session/permissions` (t64-E3, FROZEN for E5) — the current principal's identity,
 * the role assignments they hold (with scopes), and the flattened effective `(permission,
 * scope)` grant set (role ∪ delegation), each tagged by `source`. Requires any valid session.
 */
export interface SessionPermissions {
  user_id: string;
  username: string;
  role_assignments: RoleAssignmentView[];
  permissions: PermissionGrant[];
}

// --- RBAC management DTOs (§ t64-E4, FROZEN for the E6 role/delegation UI) --------
//
// The web half of the frozen `chancela-api::{roles,delegations}` management DTOs. The
// server is the real guard: every write re-enforces the subset invariant, protected-Owner,
// last-Owner and delegation hold-via-role rules regardless of what the UI offers. These
// mirror the server views byte-for-byte.
//
// `ScopeInput` (the write shape) is IDENTICAL to `PermissionScope` (the read shape): a
// serde-`kind`-tagged union `{"kind":"global"|"entity"|"book","id"?}`. We reuse
// `PermissionScope` for both so the scope picker maps directly onto the wire.

/** A role rendered for the web (`GET /v1/roles`, t64-E4). `permissions` are dotted verb ids
 *  in the role's deterministic order; `protected` marks the locked, undeletable Owner. */
export interface RoleView {
  id: string;
  name: string;
  permissions: string[];
  protected: boolean;
}

/** One verb in the permission catalog (`GET /v1/permissions`), tagged with whether it is a
 *  non-delegable meta-permission (a `role.` / `delegation.` verb). Drives the matrix editor. */
export interface PermissionInfo {
  permission: string;
  meta: boolean;
}

/** Response of `GET /v1/permissions`: the whole frozen verb catalog, in declaration order. */
export interface PermissionCatalogView {
  permissions: PermissionInfo[];
}

/** Body of `POST /v1/roles` (t64-E4). Unknown verb ids are rejected server-side (422). */
export interface CreateRoleBody {
  name: string;
  permissions: string[];
}

/** Body of `PATCH /v1/roles/{id}` (t64-E4). Absent fields leave that facet unchanged; a
 *  protected role refuses any edit (403). */
export interface PatchRoleBody {
  name?: string;
  permissions?: string[];
}

/** Body of `POST`/`DELETE /v1/users/{id}/roles` — the `(role, scope)` assignment to add or
 *  remove (t64-E4). The scope uses the same tagged union as {@link PermissionScope}. */
export interface RoleAssignmentInput {
  role_id: string;
  scope: PermissionScope;
}

/**
 * A delegation rendered for the web (`GET`/`POST /v1/delegations`, t64-E4). `from`/`to` are
 * user ids; `permission` is a dotted verb id; `scope` the tagged union. `revoked` is the
 * derived active/inactive flag; `expires_at`/`revoked_at`/`revoked_by` are present only when
 * set. An expired or revoked delegation contributes nothing (the server re-checks).
 */
export interface DelegationView {
  id: string;
  from: string;
  to: string;
  permission: string;
  scope: PermissionScope;
  granted_at: string;
  expires_at?: string;
  revoked: boolean;
  revoked_at?: string;
  revoked_by?: string;
}

/**
 * Body of `POST /v1/delegations` (t64-E4). `to` is the grantee user id; `permission` a dotted
 * verb id the grantor holds VIA A ROLE at `scope` (meta verbs are non-delegable); `expires_at`
 * is an optional RFC-3339 timestamp (omit ⇒ until-revoked). The server 403s a permission the
 * grantor does not hold via a role, and 422s a malformed `expires_at`.
 */
export interface GrantDelegationBody {
  to: string;
  permission: string;
  scope: PermissionScope;
  expires_at?: string;
}

// --- API keys (§ integration API-key lifecycle) ---------------------------------
//
// Management endpoints are interactive-session-only and gated by `user.manage`. Secrets are
// deliberately split: list/revoke return only metadata; create/rotate return plaintext once.

/** Persisted per-key rate-limit policy. Omitted on a key when the server default applies. */
export interface ApiKeyRateLimit {
  /** Sustained requests per minute. */
  rpm: number;
  /** Token-bucket burst capacity. */
  burst: number;
}

export type ApiKeyGrantView =
  | { kind: 'role'; role_id: string; scope: PermissionScope }
  | { kind: 'permissions'; permissions: string[]; scope: PermissionScope };

export interface ApiKeyView {
  id: string;
  name: string;
  /** Non-secret display prefix (`chk_<prefix>`), safe to show and log. */
  prefix: string;
  grant: ApiKeyGrantView;
  created_by: string;
  created_at: string;
  expires_at?: string;
  revoked: boolean;
  active: boolean;
  rate_limit?: ApiKeyRateLimit;
}

export interface CreateApiKeyBody {
  name: string;
  grant: ApiKeyGrantView;
  expires_at?: string;
  rate_limit?: ApiKeyRateLimit;
}

/** `POST /v1/api-keys` response: full secret shown once plus flattened key metadata. */
export type ApiKeyCreated = ApiKeyView & {
  /** Full `chk_...` plaintext secret. Never returned again and never stored in list cache. */
  secret: string;
};

/** `POST /v1/api-keys/{id}/rotate` response: same one-time-secret shape as create. */
export type ApiKeyRotated = ApiKeyCreated;

/**
 * `GET /v1/session` — the active user, or `null` when signed out.
 *
 * `permissions` is the signed-in principal's effective `(permission, scope)` grant set,
 * embedded additively for the web's first paint so it can gate its UI without a second
 * round-trip (t64-E3 / E5). Always present on the wire — an EMPTY array when signed out
 * (the server serialises a plain `Vec`, never omitting it). The authoritative, fuller
 * shape (identity + role assignments) is `GET /v1/session/permissions`.
 */
export interface SessionView {
  user: UserView | null;
  permissions: PermissionGrant[];
}

/**
 * One sign-in-eligible user in the UNAUTHENTICATED roster (`GET /v1/session/roster`,
 * t45-e1). Deliberately minimal — EXACTLY these four keys; it never carries secret
 * material, the attestation fingerprint, `created_at` or `active`. `has_secret` tells the
 * sign-in surface whether to prompt for a password.
 */
export interface RosterUser {
  id: string;
  username: string;
  display_name: string;
  has_secret: boolean;
}

/**
 * `GET /v1/session/roster` (unauthenticated, t45-e1) — the signed-out sign-in roster
 * that breaks the chicken-and-egg lockout: it lets the UI decide onboarding-vs-sign-in
 * and list the users it may sign in as WITHOUT the auth-gated `GET /v1/users`.
 * `onboarding_required` is true iff no user exists at all (the first-run bootstrap is
 * available → show the wizard). `users` holds active users only.
 */
export interface SessionRoster {
  onboarding_required: boolean;
  users: RosterUser[];
}

/**
 * Stable password policy rule ids returned by `GET /v1/session/password-policy` (t68).
 * The server remains authoritative; the UI uses these machine ids for the live checklist
 * and localised labels.
 */
export const PASSWORD_POLICY_RULE_CODES = [
  'length',
  'lowercase',
  'uppercase',
  'digit',
  'special',
  'not_username',
  'not_common',
  'no_repeats',
  'no_sequential',
] as const;
export type PasswordPolicyRuleCode = (typeof PASSWORD_POLICY_RULE_CODES)[number];

/** One checklist row in the password policy view. */
export interface PasswordRuleView {
  code: PasswordPolicyRuleCode;
  requirement: string;
}

/**
 * `GET /v1/session/password-policy` (t68) — the active server password-strength policy.
 * Exempt/unauthenticated so onboarding can render it before any user exists.
 */
export interface PasswordPolicyView {
  min_length: number;
  require_lowercase: boolean;
  require_uppercase: boolean;
  require_digit: boolean;
  require_special: boolean;
  forbid_username: boolean;
  forbid_common: boolean;
  max_identical_run: number;
  max_sequential_run: number;
  allow_weak_passwords: boolean;
  rules: PasswordRuleView[];
}

export interface CreateSessionBody {
  user_id: string;
  /** Required only for users with a sign-in secret (t29); 401/429 on failure. */
  password?: string;
}

// Sign-in secret + attestation-key management bodies (t29). `current_password` is
// required only when a secret already exists (verified server-side, 401 on mismatch).
//
// Cross-user authorization (t51): mutating ANOTHER user's secret/key requires a proof of
// authority — EITHER the target's verified `current_password` OR a valid one-time
// `recovery_phrase`. Both are additive optional fields; self-service (editing your own
// account) leaves them unset exactly as before. A missing/wrong cross-user proof is a
// **403** (distinct from the 401 session/self-service-wrong-password errors).
export interface SetSecretBody {
  password: string;
  current_password?: string;
  /** Cross-user reset proof: a valid one-time recovery phrase (t51). */
  recovery_phrase?: string;
}

export interface RemoveSecretBody {
  current_password?: string;
  recovery_phrase?: string;
}

export interface AttestationKeyBody {
  current_password?: string;
  /** Accepted for cross-user *remove*; recovery cannot *generate* a key (403, t51). */
  recovery_phrase?: string;
}

/**
 * `POST /v1/users/{id}/recovery` (t51) — issue/rotate a 160-bit recovery phrase. Subject to
 * the same cross-user proof rules: self-service proves the current password when one is set;
 * a cross-user caller proves the target's current password OR an existing recovery phrase.
 */
export interface IssueRecoveryBody {
  current_password?: string;
  recovery_phrase?: string;
}

/**
 * The response of `POST /v1/users/{id}/recovery`: the updated `UserView` PLUS the freshly
 * generated `recovery_phrase`, returned **exactly once**. The phrase is stored server-side
 * only as an argon2id verifier — it can never be retrieved again, so the UI must show it
 * once and never persist it.
 */
export interface RecoveryIssued extends UserView {
  recovery_phrase: string;
}

export const DSR_REQUEST_TYPES = ['export', 'rectification', 'erasure', 'restriction'] as const;
export type DsrRequestType = (typeof DSR_REQUEST_TYPES)[number];

export const DSR_REQUEST_STATUSES = ['pending', 'completed'] as const;
export type DsrRequestStatus = (typeof DSR_REQUEST_STATUSES)[number];

export const DSR_REQUEST_OUTCOMES = [
  'fulfilled',
  'partially_fulfilled',
  'rejected',
  'no_action_required',
] as const;
export type DsrRequestOutcome = (typeof DSR_REQUEST_OUTCOMES)[number];

export interface DsrAffectedRecord {
  collection: string;
  action: string;
  count: number;
}

/** One tracked DSR/privacy lifecycle request for a subject user. */
export interface DsrRequestView {
  id: string;
  subject_user_id: string;
  request_type: DsrRequestType;
  status: DsrRequestStatus;
  created_at: string;
  created_by: string;
  completed_at?: string;
  completed_by?: string;
  outcome?: DsrRequestOutcome;
  executed_at?: string;
  executed_by?: string;
  execution_notes?: string;
  affected_records?: DsrAffectedRecord[];
  retention_review?: string;
  legal_basis_review?: string;
}

/** Body of `POST /v1/privacy/users/{id}/dsr-requests`. */
export interface CreateDsrRequestBody {
  request_type: DsrRequestType;
}

// --- Privacy/compliance registers ----------------------------------------------

export const PRIVACY_RISK_LEVELS = ['low', 'medium', 'high', 'critical'] as const;
export type PrivacyRiskLevel = (typeof PRIVACY_RISK_LEVELS)[number];

export const PRIVACY_RECORD_STATUSES = ['draft', 'active', 'under_review', 'retired'] as const;
export type PrivacyRecordStatus = (typeof PRIVACY_RECORD_STATUSES)[number];

export const RETENTION_POLICY_STATUSES = ['draft', 'active', 'suspended', 'retired'] as const;
export type RetentionPolicyStatus = (typeof RETENTION_POLICY_STATUSES)[number];

export const RETENTION_DISPOSAL_ACTIONS = [
  'review',
  'archive',
  'anonymize',
  'delete',
  'legal_hold',
  'no_action',
] as const;
export type RetentionDisposalAction = (typeof RETENTION_DISPOSAL_ACTIONS)[number];

interface PrivacyRegisterRecordBase {
  purpose: string;
  legal_basis: string;
  data_categories: string[];
  subprocessors: string[];
  risk_level: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

/** One GDPR processor register record (`GET /v1/privacy/processors`). */
export interface ProcessorRecordView extends PrivacyRegisterRecordBase {
  id: string;
  name: string;
}

/** One DPIA register record (`GET /v1/privacy/dpias`). */
export interface DpiaRecordView extends PrivacyRegisterRecordBase {
  id: string;
  title: string;
}

/** One breach-response playbook register record (`GET /v1/privacy/breach-playbooks`). */
export interface BreachPlaybookView {
  id: string;
  title: string;
  scope: string;
  detection_channels: string[];
  containment_steps: string[];
  notification_roles: string[];
  authority_notification_window?: string;
  subject_notification_guidance?: string;
  risk_level: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
  review_notes?: string;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

/** One transfer-control register record (`GET /v1/privacy/transfer-controls`). */
export interface TransferControlView {
  id: string;
  name: string;
  purpose: string;
  legal_basis: string;
  data_categories: string[];
  recipient: string;
  destination_country: string;
  transfer_mechanism: string;
  safeguards: string[];
  risk_level: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
  review_notes?: string;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

/** One bounded retention policy register record (`GET /v1/privacy/retention-policies`). */
export interface RetentionPolicyView {
  id: string;
  name: string;
  scope: string;
  category: string;
  schedule_id: string;
  retention_period: string;
  legal_basis: string;
  disposal_action: RetentionDisposalAction;
  status: RetentionPolicyStatus;
  active: boolean;
  notes?: string;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

/** Body of `POST /v1/privacy/retention-policies`. */
export interface CreateRetentionPolicyBody {
  id?: string;
  name: string;
  scope: string;
  category: string;
  schedule_id: string;
  retention_period: string;
  legal_basis: string;
  disposal_action: RetentionDisposalAction;
  status: RetentionPolicyStatus;
  active: boolean;
  notes?: string;
}

/** Body of `PATCH /v1/privacy/retention-policies/{id}`. */
export interface PatchRetentionPolicyBody {
  name?: string;
  scope?: string;
  category?: string;
  schedule_id?: string;
  retention_period?: string;
  legal_basis?: string;
  disposal_action?: RetentionDisposalAction;
  status?: RetentionPolicyStatus;
  active?: boolean;
  notes?: string;
}

/** Body of `POST /v1/privacy/retention-policies/dry-run`. */
export interface RetentionDryRunBody {
  scope: string;
  category: string;
  record_id?: string;
}

export interface RetentionDryRunCandidate {
  scope: string;
  category: string;
  record_id?: string;
}

export interface RetentionDryRunMatch {
  policy_id: string;
  name: string;
  scope: string;
  category: string;
  schedule_id: string;
  retention_period: string;
  disposal_action: RetentionDisposalAction;
  status: RetentionPolicyStatus;
  active: boolean;
  destructive_action: boolean;
  would_execute: boolean;
  reason: string;
}

export interface RetentionDryRunReport {
  mode: 'dry_run';
  execution_supported: boolean;
  destructive_execution_supported: boolean;
  candidate: RetentionDryRunCandidate;
  matched_count: number;
  matches: RetentionDryRunMatch[];
}

/** Body of `POST /v1/privacy/processors`. */
export interface CreateProcessorRecordBody {
  name: string;
  purpose: string;
  legal_basis: string;
  data_categories: string[];
  subprocessors: string[];
  risk_level: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
}

/** Body of `PATCH /v1/privacy/processors/{id}`. */
export interface PatchProcessorRecordBody {
  name?: string;
  purpose?: string;
  legal_basis?: string;
  data_categories?: string[];
  subprocessors?: string[];
  risk_level?: PrivacyRiskLevel;
  status?: PrivacyRecordStatus;
}

/** Body of `POST /v1/privacy/dpias`. */
export interface CreateDpiaRecordBody {
  title: string;
  purpose: string;
  legal_basis: string;
  data_categories: string[];
  subprocessors: string[];
  risk_level: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
}

/** Body of `PATCH /v1/privacy/dpias/{id}`. */
export interface PatchDpiaRecordBody {
  title?: string;
  purpose?: string;
  legal_basis?: string;
  data_categories?: string[];
  subprocessors?: string[];
  risk_level?: PrivacyRiskLevel;
  status?: PrivacyRecordStatus;
}

/** Body of `POST /v1/privacy/breach-playbooks`. */
export interface CreateBreachPlaybookBody {
  title: string;
  scope: string;
  detection_channels: string[];
  containment_steps: string[];
  notification_roles: string[];
  authority_notification_window?: string;
  subject_notification_guidance?: string;
  risk_level: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
  review_notes?: string;
}

/** Body of `PATCH /v1/privacy/breach-playbooks/{id}`. */
export interface PatchBreachPlaybookBody {
  title?: string;
  scope?: string;
  detection_channels?: string[];
  containment_steps?: string[];
  notification_roles?: string[];
  authority_notification_window?: string;
  subject_notification_guidance?: string;
  risk_level?: PrivacyRiskLevel;
  status?: PrivacyRecordStatus;
  review_notes?: string;
}

/** Body of `POST /v1/privacy/transfer-controls`. */
export interface CreateTransferControlBody {
  name: string;
  purpose: string;
  legal_basis: string;
  data_categories: string[];
  recipient: string;
  destination_country: string;
  transfer_mechanism: string;
  safeguards: string[];
  risk_level: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
  review_notes?: string;
}

/** Body of `PATCH /v1/privacy/transfer-controls/{id}`. */
export interface PatchTransferControlBody {
  name?: string;
  purpose?: string;
  legal_basis?: string;
  data_categories?: string[];
  recipient?: string;
  destination_country?: string;
  transfer_mechanism?: string;
  safeguards?: string[];
  risk_level?: PrivacyRiskLevel;
  status?: PrivacyRecordStatus;
  review_notes?: string;
}

/** One role assignment embedded in the non-secret DSR user export. */
export interface UserDsrRoleAssignment {
  role_id: string;
  scope: PermissionScope;
  role_name?: string;
  permissions: string[];
}

/** The exported user profile plus non-secret authorization context. */
export interface UserDsrExportUser extends UserView {
  role_assignments: UserDsrRoleAssignment[];
}

/** Non-secret JSON payload returned by `GET /v1/privacy/users/{id}/export`. */
export interface UserDsrExport {
  exported_at: string;
  scope: string;
  format_version: number;
  redaction_notes: string[];
  exclusions: string[];
  user: UserDsrExportUser;
  ledger_event_refs: LedgerEventView[];
}

/** `GET /v1/ledger/attestations/{seq}` — a server-verified attestation, or 404. */
export interface AttestationVerifyView {
  attestation: {
    event_seq: number;
    event_id: string;
    event_hash: string;
    username: string;
    fingerprint: string;
    algorithm: string;
    signature: string;
    created_at: string;
  };
  valid: boolean;
  reason?: string;
}

/** `POST /v1/session` — the issued token plus the now-active user. */
export interface SessionResult {
  token: string;
  user: UserView;
}

// --- Request bodies (§2.3–§2.7) -------------------------------------------------

export interface CreateEntityBody {
  name: string;
  nipc: string;
  seat: string;
  kind: EntityKind;
  /** Create even when the NIPC fails control-digit validation (stored unvalidated) (t25). */
  allow_invalid_nipc?: boolean;
  /** Fiscal year end as `MM-DD`; `null`/omitted means the backend's Dec 31 default. */
  fiscal_year_end?: string | null;
}

/**
 * `PATCH /v1/entities/{id}` — set/clear `statute` and/or `fiscal_year_end`; omitted fields
 * are left untouched.
 */
export interface UpdateEntityBody {
  statute?: StatuteOverrides | null;
  fiscal_year_end?: string | null;
}

export interface OpenBookBody {
  entity_id: string;
  kind: BookKind;
  purpose: string;
  numbering_scheme?: NumberingScheme;
  opening_date: string;
  required_signatories: string[];
  predecessor?: string;
  actor?: string;
}

export interface CloseBookBody {
  reason: ClosingReason;
  closing_date: string;
  required_signatories: string[];
  actor?: string;
}

export interface DraftActBody {
  book_id: string;
  title: string;
  channel: MeetingChannel;
  ai_provenance?: AiProvenanceInput | null;
  convening?: ActConvening | null;
  retifies?: string;
}

export interface AiProvenanceInput {
  source: string;
  tool?: string | null;
  statement_source?: string | null;
}

export interface UpdateActBody {
  title?: string;
  channel?: MeetingChannel;
  meeting_date?: string | null;
  meeting_time?: string | null;
  place?: string | null;
  mesa?: ActMesa;
  agenda?: ActAgendaItem[];
  attendance_reference?: string | null;
  members_present?: number | null;
  members_represented?: number | null;
  referenced_documents?: ActDocumentReference[];
  deliberations?: string;
  deliberation_items?: ActDeliberationItem[];
  telematic_evidence?: string | null;
  attachments?: ActAttachment[];
  signatories?: ActSignatory[];
  convening?: ActConvening | null;
}

export interface AdvanceActBody {
  to: ActState;
  actor?: string;
}

export type HumanVerificationDecision = 'accept' | 'reject';

export interface VerifyAiHumanReviewBody {
  decision: HumanVerificationDecision;
  note?: string | null;
  actor?: string;
}

export interface SealActBody {
  actor?: string;
  acknowledge_warnings?: boolean;
}

export type FollowUpStatus = 'Open' | 'Completed';

/** A mutable act-scoped task row, stored outside `ActView` so sealed act JSON stays immutable. */
export interface FollowUpView {
  id: string;
  act_id: string;
  agenda_number: number | null;
  deliberation_index: number | null;
  title: string;
  detail: string | null;
  due_date: string | null;
  assignee: string | null;
  assignee_display: string | null;
  status: FollowUpStatus;
  created_at: string;
  created_by: string;
  completed_at: string | null;
  completed_by: string | null;
}

export interface CreateFollowUpBody {
  actor?: string;
  agenda_number?: number | null;
  deliberation_index?: number | null;
  title: string;
  detail?: string | null;
  due_date?: string | null;
  assignee?: string | null;
  assignee_display?: string | null;
}

export interface PatchFollowUpBody {
  actor?: string;
  title?: string;
  detail?: string | null;
  due_date?: string | null;
  assignee?: string | null;
  assignee_display?: string | null;
  agenda_number?: number | null;
  deliberation_index?: number | null;
}

export interface CompleteFollowUpBody {
  actor?: string;
}

// Registry (§2.7). `code` is the 12-digit código de acesso — a SECRET carried only
// in the request body, never persisted or cached client-side.
export interface RegistryLookupBody {
  code: string;
  email?: string;
}

export interface ImportFromRegistryBody {
  code: string;
  email?: string;
}

export interface RegistryImportBody {
  code: string;
  email?: string;
  overwrite?: boolean;
}

export type RegistryAutoUpdateWeekday =
  'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday' | 'sunday';

export type RegistryAutoUpdateCadence =
  | { kind: 'interval_hours'; hours: number }
  | { kind: 'daily'; hour_utc: number }
  | { kind: 'weekly'; weekday: RegistryAutoUpdateWeekday; hour_utc: number };

export interface RegistryAutoUpdateEntityDefaults {
  enabled: boolean;
  /** Empty means every entity profile is eligible; today profiles are EntityKind names. */
  enabled_profiles: string[];
}

export interface RegistryAutoUpdateSettings {
  enabled: boolean;
  cadence: RegistryAutoUpdateCadence;
  stale_threshold_hours: number;
  min_backoff_minutes: number;
  max_backoff_minutes: number;
  max_attempts_per_run: number;
  entity_defaults: RegistryAutoUpdateEntityDefaults;
}

export type RegistryAutoUpdateStatus =
  'idle' | 'due' | 'queued' | 'running' | 'completed' | 'failed' | 'manual_required';

export interface RegistryAutoUpdateDueItem {
  entity_id: string;
  entity_name: string;
  entity_profile: string;
  retrieved_at: string;
  age_hours: number | null;
  stale_threshold_hours: number;
  code_masked: string;
  status: RegistryAutoUpdateStatus;
  reason: string;
  next_allowed_at: string | null;
}

export interface RegistryAutoUpdateSkippedCounts {
  disabled: number;
  fresh: number;
  backoff: number;
  running: number;
  orphaned: number;
  capped: number;
}

export interface RegistryAutoUpdateDuePlan {
  generated_at: string;
  dry_run_only: boolean;
  config: RegistryAutoUpdateSettings;
  due: RegistryAutoUpdateDueItem[];
  skipped: RegistryAutoUpdateSkippedCounts;
  notes: string[];
}

export interface RegistryAutoUpdateAttemptBody {
  force?: boolean;
  dry_run?: boolean;
  reason?: string;
}

export interface RegistryAutoUpdateAttemptView {
  accepted: boolean;
  entity_id: string;
  status: RegistryAutoUpdateStatus;
  generated_at: string;
  dry_run_only: boolean;
  reason: string;
  last_attempt_at: string | null;
  next_allowed_at: string | null;
  failure_count: number;
  audit_event_seq: number | null;
}

// --- Settings document (§2.8) ---------------------------------------------------
//
// Whole-document GET/PUT: the client always sends the entire `Settings` (no PATCH
// merge). Every field has a server-side serde default, so a partial body still
// deserializes to a complete document — but the UI holds and sends the full shape.

export interface OrganizationSettings {
  name: string | null;
  default_actor: string;
}

export interface DocumentSettings {
  locale: Locale;
  numbering_scheme_default: NumberingScheme;
}

/**
 * Chave Móvel Digital (CMD) remote-signing configuration (t57-S3). `env` selects the AMA
 * environment (`preprod`/`prod`); `application_id` is the AMA-issued ApplicationId or `null`
 * when unset; `ama_cert_configured` reports whether the AMA signing certificate is provisioned.
 * The full CMD settings UI lands in a later slice — this field is modelled to keep the wire
 * contract green.
 */
export interface SigningCmdSettings {
  env: string;
  application_id: string | null;
  ama_cert_configured: boolean;
}

export type SigningProviderMode = 'CMD' | 'CC' | 'CSC_QTSP' | 'LOCAL_PKCS12';

export interface SigningProviderMetadata {
  id: string;
  mode: SigningProviderMode;
  label: string;
  configured: boolean;
  production_blocked: boolean;
  local_only: boolean;
  note: string;
}

export interface TrustRefreshCadence {
  kind: 'manual' | 'interval_hours' | 'daily';
  hours?: number;
  hour_utc?: number;
}

export interface TrustRefreshSettings {
  enabled: boolean;
  cadence: TrustRefreshCadence;
}

export interface TslSourceSettings {
  id: string;
  name: string;
  enabled: boolean;
  url: string | null;
  path: string | null;
  country: string | null;
  scheme: string | null;
  digest: string | null;
  timeout_seconds: number;
  max_bytes: number;
  refresh: TrustRefreshSettings;
}

export interface TsaProviderSettings {
  id: string;
  name: string;
  enabled: boolean;
  url: string | null;
  path: string | null;
  default: boolean;
  policy: string | null;
  digest: string;
  timeout_seconds: number;
  max_bytes: number;
}

export interface SigningSettings {
  preferred_family: SignatureFamily;
  tsa_url: string | null;
  tsl_url: string | null;
  tsl_sources: TslSourceSettings[];
  tsa_providers: TsaProviderSettings[];
  require_qualified_for_seal: boolean;
  cmd: SigningCmdSettings;
  providers: SigningProviderMetadata[];
}

export const PLATFORM_LOG_LEVELS = ['trace', 'debug', 'info', 'warn', 'error', 'off'] as const;
export type PlatformLogLevel = (typeof PLATFORM_LOG_LEVELS)[number];

export const PLATFORM_EMITTED_LOG_LEVELS = ['trace', 'debug', 'info', 'warn', 'error'] as const;
export type PlatformEmittedLogLevel = (typeof PLATFORM_EMITTED_LOG_LEVELS)[number];

export const PLATFORM_SERVICE_IDS = ['app', 'api', 'mcp_stdio'] as const;
export type PlatformServiceId = (typeof PLATFORM_SERVICE_IDS)[number];

export const PLATFORM_CONTROLLABLE_SERVICE_IDS = ['api', 'mcp_stdio'] as const;
export type PlatformControllableServiceId = (typeof PLATFORM_CONTROLLABLE_SERVICE_IDS)[number];

export const PLATFORM_SERVICE_ACTIONS = ['start', 'stop', 'restart'] as const;
export type PlatformServiceAction = (typeof PLATFORM_SERVICE_ACTIONS)[number];

export type PlatformServiceDesiredState = 'running' | 'stopped';
export type PlatformControlOutcomeKind = 'unsupported' | 'restart_required' | 'supervisor_required';

export interface PlatformServiceLastAction {
  action: PlatformServiceAction;
  requested_at: string;
  requested_by: string;
  outcome: PlatformControlOutcomeKind;
  message: string;
}

export interface PlatformAuditEvent extends PlatformServiceLastAction {
  service_id: PlatformServiceId;
  desired_state: PlatformServiceDesiredState;
}

export interface PlatformLoggingSettings {
  global: PlatformLogLevel;
  app: PlatformLogLevel;
  api: PlatformLogLevel;
  mcp: PlatformLogLevel;
  service_overrides: Partial<Record<PlatformServiceId, PlatformLogLevel>>;
}

export interface PlatformServiceControlSettings {
  enabled: boolean;
  desired_state: PlatformServiceDesiredState;
  last_action: PlatformServiceLastAction | null;
}

export interface PlatformSettings {
  logging: PlatformLoggingSettings;
  api_server: PlatformServiceControlSettings;
  mcp_stdio_server: PlatformServiceControlSettings;
  audit: PlatformAuditEvent[];
}

export type PlatformServiceKind = 'api' | 'mcp';
export type PlatformRuntimeStatus = 'running' | 'unknown';

export interface PlatformActionCapability {
  action: PlatformServiceAction;
  supported: boolean;
  outcome: PlatformControlOutcomeKind;
  limitation: string;
}

export interface PlatformServiceStatus {
  id: PlatformControllableServiceId;
  kind: PlatformServiceKind;
  label: string;
  configured: boolean;
  enabled: boolean;
  desired_state: PlatformServiceDesiredState;
  actual_runtime_status: PlatformRuntimeStatus;
  controllable_actions: PlatformActionCapability[];
  logging_level: PlatformLogLevel;
  last_action: PlatformServiceLastAction | null;
  limitations: string[];
}

export interface PlatformServicesResponse {
  services: PlatformServiceStatus[];
}

export interface PlatformControlResult {
  kind: PlatformControlOutcomeKind;
  supported: boolean;
  applied_to_settings: boolean;
  desired_state: PlatformServiceDesiredState;
  actual_runtime_status: PlatformRuntimeStatus;
  message: string;
  limitations: string[];
}

export interface PlatformControlResponse {
  service: PlatformServiceStatus;
  action: PlatformServiceAction;
  result: PlatformControlResult;
}

export type JsonValue =
  string | number | boolean | null | { [key: string]: JsonValue } | JsonValue[];

export interface PlatformLogEntry {
  id: string;
  seq: number;
  timestamp: string;
  service_id: PlatformServiceId;
  level: PlatformEmittedLogLevel;
  target: string;
  message: string;
  context?: JsonValue;
}

export interface PlatformLogsQueryParams {
  service_id?: PlatformServiceId;
  level?: PlatformEmittedLogLevel;
  tail?: number;
}

export interface PlatformLogsResponse {
  logs: PlatformLogEntry[];
  tail: number;
  order: 'chronological';
  limitations: string[];
}

// --- Qualified CMD signing (§ t57) ----------------------------------------------
//
// The two-phase Chave Móvel Digital signing flow (frozen `chancela-api::signature`
// DTOs, t57-S3). A sealed act's unsigned PDF/A is turned into a **qualified** CMD-signed
// PDF across two requests: `initiate` (phone + PIN → dispatches the SMS OTP) then
// `confirm` (session_id + OTP → the signed PDF). The PIN and OTP are transient secrets
// carried ONLY in the request body — never persisted or echoed back on any of these types.

/** The act's derived finalization status (server-owned; the seal is never blocked). */
export const FINALIZATION_STATUSES = [
  'rascunho',
  'finalizado',
  'aguarda_assinatura_qualificada',
  'finalizado_qualificado',
] as const;
export type FinalizationStatus = (typeof FINALIZATION_STATUSES)[number];

/** The act's signature state (unsigned → pending/aguarda-OTP → signed). */
export const SIGNATURE_STATUSES = ['unsigned', 'pending', 'signed'] as const;
export type SignatureStatus = (typeof SIGNATURE_STATUSES)[number];

/** The signed-variant detail surfaced once an act carries a qualified signature. */
export interface SignedSignatureInfo {
  family: string;
  evidentiary_level: string;
  trusted_list_status: string | null;
  signer_cert_subject: string | null;
  signing_time: string;
  signed_at: string;
  signed_pdf_digest: string;
  timestamp_token: boolean;
  /** The `GET .../document/signed` path for the signed PDF. */
  download: string;
}

/** The in-flight pending-session detail (carries no secret). */
export interface PendingSignatureInfo {
  session_id: string;
  masked_phone: string;
  expires_at: string;
}

export type LongTermEvidenceStatus =
  | 'not_configured'
  | 'timestamped'
  | 'lt_local_technical_evidence'
  | 'lt_local_technical_evidence_partial'
  | 'lt_production_not_claimed'
  | 'lt_not_implemented'
  | 'lta_local_technical_evidence'
  | 'lta_local_technical_evidence_partial'
  | 'lta_not_implemented';

export interface DssEvidenceStatus {
  present: boolean;
  vri_count: number;
  certificate_count: number;
  ocsp_count: number;
  crl_count: number;
  certificate_sha256: string[];
  ocsp_sha256: string[];
  crl_sha256: string[];
  revocation_evidence_present: boolean;
  inspection_status: string;
}

export interface DocTimeStampValidationEvidenceStatus {
  index: number;
  object_id: string;
  byte_range: [number, number, number, number] | null;
  document_digest_sha256: string | null;
  token_imprint_sha256: string | null;
  token_hash_algorithm: string | null;
  status: 'valid' | 'failed' | 'unsupported' | string;
  failure_reason: string | null;
}

export interface DocTimeStampEvidenceStatus {
  present: boolean;
  count: number;
  token_sha256: string[];
  validations: DocTimeStampValidationEvidenceStatus[];
  all_imprints_valid: boolean;
  inspection_status: string;
}

export interface RenewalPolicyEvidenceStatus {
  status: 'not_configured' | string;
  action: 'manual_review' | string;
}

export interface TimestampQtstMatchEvidenceStatus {
  provider_name: string;
  service_name: string;
  granted_and_effective: boolean;
  trust_anchor_count: number;
}

export interface TimestampTrustEvidenceStatus {
  decision: 'accepted' | 'rejected';
  policy_oid: string;
  policy_oid_accepted: boolean | null;
  tsa_certificate_embedded: boolean;
  embedded_certificate_count: number;
  qtst_status: 'granted' | 'withdrawn' | 'unknown';
  qtst_authenticated: boolean;
  qtst_matches: TimestampQtstMatchEvidenceStatus[];
  trust_anchor_count: number;
  certificate_path_valid: boolean;
  certificate_path_anchor_index: number | null;
  certificate_path_len: number | null;
  failure_reasons: string[];
  status_scope: string;
}

/** Technical PAdES evidence observed for the act; not a legal B-LT/B-LTA conformance claim. */
export interface SignatureEvidenceStatus {
  current_level: string;
  timestamp_evidence_present: boolean;
  dss_revocation_evidence_present: boolean;
  dss_revocation_evidence_status: string;
  dss: DssEvidenceStatus;
  doc_timestamp: DocTimeStampEvidenceStatus;
  local_b_lt_style_evidence_present: boolean;
  production_b_lt_status: string;
  live_revocation_fetching: boolean;
  legal_b_lt_claimed: boolean;
  legal_b_lta_claimed: boolean;
  renewal_policy: RenewalPolicyEvidenceStatus;
  long_term_status: LongTermEvidenceStatus[];
  timestamp_trust?: TimestampTrustEvidenceStatus;
  status_scope: string;
}

/** `GET /v1/acts/{id}/signature` — the act's signature status + derived finalization. */
export interface SignatureStatusView {
  status: SignatureStatus;
  finalization: FinalizationStatus;
  require_qualified_for_seal: boolean;
  /** Present only when `status === 'signed'`. */
  signed?: SignedSignatureInfo;
  /** Present only when `status === 'pending'`. */
  pending?: PendingSignatureInfo;
  /** Technical evidence profile; deliberately does not imply B-LT/B-LTA support. */
  evidence: SignatureEvidenceStatus;
}

/**
 * `POST /v1/acts/{id}/signature/cmd/initiate` — phase 1. The `pin` is a transient
 * knowledge factor: it is sent once and never stored client-side beyond this request.
 */
export interface CmdInitiateBody {
  phone: string;
  pin: string;
  capacity?: string;
  actor?: string;
}

/** The initiate response — no secret (no PIN, no OTP, no SCMD process id). */
export interface CmdInitiateResult {
  session_id: string;
  masked_phone: string;
  status: string;
  expires_at: string;
  family: string;
  evidentiary_level: string;
}

/**
 * `POST /v1/acts/{id}/signature/cmd/confirm` — phase 2. The `otp` is a transient
 * possession factor: it is sent once and never stored client-side beyond this request.
 */
export interface CmdConfirmBody {
  session_id: string;
  otp: string;
  actor?: string;
}

/** The confirm response — the produced qualified signature's metadata. */
export interface CmdConfirmResult {
  document_id: string;
  act_id: string;
  family: string;
  evidentiary_level: string;
  trusted_list_status: string | null;
  signed_at: string;
  signed_pdf_digest: string;
  timestamp_token: boolean;
  finalization: FinalizationStatus;
}

// --- Qualified Cartão de Cidadão signing (§ t58, desktop / co-located) -----------
//
// The SYNCHRONOUS smartcard signing flow (frozen `chancela-api::signature::cc` DTOs,
// t58-e2). A sealed act's unsigned PDF/A is turned into a **qualified** Cartão de Cidadão
// signed PDF in a single request: `POST /v1/acts/{id}/signature/cc/sign`. There is NO PIN
// in the body — the PIN is entered at the reader by the Autenticação.gov middleware and
// never enters the web app. CC signing only works on the desktop where the API process is
// co-located with the card reader; a remote/browser server refuses with 409. The response
// REUSES the CMD `CmdConfirmResult` shape (only `family` differs: `"CartaoDeCidadao"`), so
// no new web-asserted contract type is introduced.

/**
 * `POST /v1/acts/{id}/signature/cc/sign` — the whole CC signing request body. Both fields
 * are optional and carry NO secret (the PIN lives only at the reader). `capacity` records
 * the signatory's stated capacity; `actor` an explicit actor override.
 */
export interface CcSignBody {
  capacity?: string;
  actor?: string;
}

/** The CC sign response — the produced qualified signature's metadata (same shape as CMD). */
export type CcSignResult = CmdConfirmResult;

// --- Local PKCS#12/PFX software-certificate signing -----------------------------

/**
 * `POST /v1/acts/{id}/signature/local/pkcs12/sign` — advanced local software-certificate
 * signing. The encrypted PFX bytes and passphrase are transient request inputs only; the
 * web app must never persist them in storage or query cache.
 */
export interface LocalPkcs12SignBody {
  pkcs12_base64: string;
  passphrase: string;
  friendly_name?: string;
  capacity?: string;
  actor?: string;
}

/** The produced local signature metadata. This is technical evidence, not a qualified claim. */
export interface LocalPkcs12SignResult {
  document_id: string;
  act_id: string;
  family: string;
  evidentiary_level: string;
  trusted_list_status: string | null;
  signing_time: string;
  signed_at: string;
  signed_pdf_digest: string;
  signer_cert_subject: string | null;
  signer_cert_sha256: string;
  certificate_chain_count: number;
  timestamp_token: boolean;
  finalization: FinalizationStatus;
  qualification_claimed: boolean;
  legal_status_claimed: boolean;
  status_scope: string;
  notice: string;
}

/**
 * `POST /v1/acts/{id}/signature/dss/attach` — append caller-supplied DER evidence to an
 * existing signed PDF. Base64 fields are technical/local evidence only; no production/legal LTV
 * claim is made.
 */
export interface DssAttachBody {
  certificates?: string[];
  ocsp_responses?: string[];
  crls?: string[];
  actor?: string;
}

export interface DssAttachResult {
  document_id: string;
  act_id: string;
  signed_pdf_digest: string;
  timestamp_token: boolean;
  evidence: SignatureEvidenceStatus;
  evidentiary_level: string;
  production_b_lt_status: string;
  legal_b_lt_claimed: boolean;
  status_scope: string;
}

// --- Generic remote qualified signing (§ t59) -----------------------------------
//
// The provider-agnostic two-phase remote-signing surface (frozen `chancela-api::signature`
// generic DTOs, t59-S3). It unifies Chave Móvel Digital and every configured CSC QTSP behind
// ONE seam: `GET /v1/signature/providers` enumerates the offered providers, and
// `POST /v1/acts/{id}/signature/remote/{provider}/initiate|confirm` drives the same two-phase
// activation flow as CMD. CMD keeps its dedicated `/signature/cmd/*` path (t57); CSC providers
// use this generic path. The credential (PIN) and the activation (OTP/SAD) are transient
// secrets carried ONLY in the request body — never persisted or echoed back on any type here.

/**
 * One row of `GET /v1/signature/providers` — a non-secret picker entry (t59). `id` is the
 * `{provider}` path segment (`"cmd"`, `"multicert"`, …); `family` is `ChaveMovelDigital` for
 * CMD or `QualifiedCertificate` for a CSC QTSP; `configured` reports whether the provider's
 * credentials resolve (never the secret itself) — an unconfigured provider is offered disabled.
 */
export interface SignatureProviderView {
  id: string;
  family: string;
  label: string;
  evidentiary_level: string;
  configured: boolean;
}

/**
 * `POST /v1/acts/{id}/signature/remote/{provider}/initiate` — phase 1. `user_ref` is the
 * signer's non-secret account reference at the provider (the citizen mobile for CMD, the
 * user/credential reference for a CSC QTSP); `credential` is the transient PIN (sent once,
 * never stored; may be empty for an out-of-band user-authorized provider).
 */
export interface RemoteInitiateBody {
  user_ref: string;
  credential?: string;
  capacity?: string;
  actor?: string;
}

/** The generic initiate response — no secret. `activation_hint` is a non-secret UI hint (a
 *  masked phone for CMD, or how to authorize for a CSC provider). */
export interface RemoteInitiateResult {
  session_id: string;
  provider_id: string;
  family: string;
  evidentiary_level: string;
  status: string;
  activation_hint: string;
  expires_at: string;
}

/**
 * `POST /v1/acts/{id}/signature/remote/{provider}/confirm` — phase 2. `activation` is the
 * transient possession factor (the SMS OTP for CMD; the OTP/SAD for a CSC QTSP): sent once,
 * never stored client-side beyond this request.
 */
export interface RemoteConfirmBody {
  session_id: string;
  activation: string;
  actor?: string;
}

/** The generic confirm response — the CMD confirm shape plus the resolved `provider_id`. */
export interface RemoteConfirmResult extends CmdConfirmResult {
  provider_id: string;
}

// --- External signer invitation tracking ---------------------------------------

export type ExternalSignerInviteStatus =
  'pending' | 'accepted' | 'declined' | 'expired' | 'revoked';
export type ExternalSignerInviteDecision = 'accept' | 'decline';

export interface CreateExternalSignerInviteBody {
  recipient_name: string;
  recipient_email: string;
  provider_hint?: string;
  expires_at: string;
  purpose: string;
  actor?: string;
}

/** Public invite metadata. The plaintext token and token hash are never listed. */
export interface ExternalSignerInviteView {
  id: string;
  act_id: string;
  recipient_name: string;
  recipient_email: string;
  provider_hint?: string;
  purpose: string;
  status: ExternalSignerInviteStatus;
  workflow: string;
  token_hint: string;
  created_at: string;
  created_by: string;
  expires_at: string;
  revoked_at?: string;
  revoked_by?: string;
  responded_at?: string;
}

/** Create response; `token` is returned exactly once and must not be cached as list data. */
export interface CreateExternalSignerInviteResult {
  invite: ExternalSignerInviteView;
  token: string;
}

export interface ExternalSignerInviteActPublicView {
  id: string;
  title: string;
  state: string;
  meeting_date?: string;
  ata_number?: number;
  entity_name: string;
  book_kind: string;
}

export interface ExternalSignerInviteArtifactPublicView {
  kind: string;
  method: 'POST';
  path: string;
  content_type: string;
  filename: string;
  notice: string;
}

export interface ExternalSignerInviteDocumentPublicView {
  id: string;
  template_id: string;
  profile: string;
  pdf_digest: string;
  artifact: ExternalSignerInviteArtifactPublicView;
}

/**
 * Public token-holder envelope. This is acknowledgement/tracking metadata only: it never contains
 * token material, document bytes, canonical PDF URLs, or a qualified-signature completion claim.
 */
export interface ExternalSignerInvitePublicView {
  invite_id: string;
  act: ExternalSignerInviteActPublicView;
  document?: ExternalSignerInviteDocumentPublicView;
  recipient_name: string;
  provider_hint?: string;
  purpose: string;
  status: ExternalSignerInviteStatus;
  workflow: string;
  created_at: string;
  expires_at: string;
  responded_at?: string;
  notice: string;
}

export interface AppearanceSettings {
  theme: ThemeMode;
  leather_texture: boolean;
  texture_intensity: number;
  /** Leather-grain texture on the buttons (contract F1, t19-e1). Default `true`. */
  button_texture: boolean;
}

export const REGISTERED_ENTITY_COLUMNS = [
  'Name',
  'Nipc',
  'Seat',
  'Type',
  'Matricula',
  'Constitution',
  'Capital',
  'Cae',
  'Registry',
  'LastRegistryChange',
  'FiscalYearEnd',
  'LastBook',
  'LastActivity',
  'Actions',
] as const;
export type RegisteredEntityColumn = (typeof REGISTERED_ENTITY_COLUMNS)[number];

export interface UiSettings {
  registered_entity_columns: RegisteredEntityColumn[];
}

/**
 * The CAE catalog section (contract F1b, t19-e1b). `cae_update_url` is the remote
 * `CaeDataset` URL the "Atualizar catálogo" refresh fetches from; `null` (the default)
 * means unset — a refresh then returns a friendly `422` pointing the operator here.
 * Validated http(s) when non-empty (else `422` on PUT), like the trust URLs.
 */
export const CAE_SOURCE_FORMATS = ['Auto', 'Envelope', 'SimpleJson', 'Pdf'] as const;
export type CaeSourceFormat = (typeof CAE_SOURCE_FORMATS)[number];

/** One entry of the ordered, strict fidelity-gated CAE refresh chain (t23). */
export interface CaeSourceEntry {
  url: string;
  format: CaeSourceFormat;
  /** Optional pinned sha-256 (64-hex) of the fetched artifact, or null (t23). */
  digest: string | null;
}

/** Preferred built-in official CAE source (t37). Default `Ine`; `DiarioRepublica` uses the
 *  digest-pinned diploma pair directly. INE is not a viable bulk obtainer, so with `Ine` the
 *  refresh records INE's failure and the Diário da República fulfils it. */
export const PREFERRED_OFFICIAL_SOURCES = ['Ine', 'DiarioRepublica'] as const;
export type PreferredOfficialSource = (typeof PREFERRED_OFFICIAL_SOURCES)[number];

export interface CatalogSettings {
  cae_update_url: string | null;
  /** Ordered fallback chain of strict, fidelity-gated CAE sources (t23). */
  cae_sources: CaeSourceEntry[];
  /** Prepend the built-in official Diário da República source pair to the chain (t23). */
  cae_official_source: boolean;
  /** Which built-in official source leads the chain; default `Ine` (t37). */
  preferred_official_source: PreferredOfficialSource;
}

/** First-run onboarding state (t29). No schema bump — serde-defaulted. */
export interface OnboardingSettings {
  completed: boolean;
  completed_at: string | null;
}

/** Tenant-level gate for AI features and the MCP surface. Defaults disabled. */
export interface AiSettings {
  enabled: boolean;
}

export interface Settings {
  schema_version: number;
  organization: OrganizationSettings;
  documents: DocumentSettings;
  catalog: CatalogSettings;
  signing: SigningSettings;
  platform: PlatformSettings;
  registry_auto_update: RegistryAutoUpdateSettings;
  appearance: AppearanceSettings;
  ui: UiSettings;
  onboarding: OnboardingSettings;
  ai: AiSettings;
}

/** The server's default document (contract §2.8) — used as the pre-load fallback so
 *  the UI and the live appearance layer have a complete shape before the first GET
 *  resolves. Kept byte-for-byte in step with the frozen default in t8-e1. */
export const DEFAULT_SETTINGS: Settings = {
  schema_version: 1,
  organization: { name: null, default_actor: 'api' },
  documents: { locale: 'pt-PT', numbering_scheme_default: 'Sequential' },
  catalog: {
    cae_update_url: null,
    cae_sources: [],
    cae_official_source: false,
    preferred_official_source: 'Ine',
  },
  signing: {
    // Default flipped to the recommended Chave Móvel Digital (t57 Slice 1, matching the backend
    // `SignatureFamily::default` + `contracts/settings.json`).
    preferred_family: 'ChaveMovelDigital',
    // The official admin-configurable defaults the backend now returns (contract F1);
    // the client's optimistic default mirrors them so it matches before the first GET.
    // NOTE: the TSA endpoint is plain http — RFC 3161 timestamping uses http, and the
    // backend/contract default is http, so the web default must NOT "upgrade" it to https.
    tsa_url: 'http://ts.cartaodecidadao.pt/tsa/server',
    tsl_url: 'https://www.gns.gov.pt/media/TSLPT.xml',
    tsl_sources: [
      {
        id: 'pt-gns',
        name: 'Portugal GNS Trusted List',
        enabled: true,
        url: 'https://www.gns.gov.pt/media/TSLPT.xml',
        path: null,
        country: 'PT',
        scheme: 'eidas',
        digest: null,
        timeout_seconds: 30,
        max_bytes: 26214400,
        refresh: { enabled: false, cadence: { kind: 'daily', hour_utc: 3 } },
      },
      {
        id: 'eu-lotl',
        name: 'EU List of Trusted Lists',
        enabled: false,
        url: 'https://ec.europa.eu/tools/lotl/eu-lotl.xml',
        path: null,
        country: 'EU',
        scheme: 'lotl',
        digest: null,
        timeout_seconds: 30,
        max_bytes: 26214400,
        refresh: { enabled: false, cadence: { kind: 'daily', hour_utc: 2 } },
      },
    ],
    tsa_providers: [
      {
        id: 'pt-cc',
        name: 'Portugal Cartao de Cidadao TSA',
        enabled: true,
        url: 'http://ts.cartaodecidadao.pt/tsa/server',
        path: null,
        default: true,
        policy: null,
        digest: 'sha256',
        timeout_seconds: 30,
        max_bytes: 1048576,
      },
    ],
    require_qualified_for_seal: false,
    cmd: { env: 'preprod', application_id: null, ama_cert_configured: false },
    providers: [
      {
        id: 'cmd',
        mode: 'CMD',
        label: 'Chave Móvel Digital (CMD/SCMD)',
        configured: false,
        production_blocked: true,
        local_only: false,
        note: 'Missing AMA ApplicationId/certificate; defaults to pre-production.',
      },
      {
        id: 'cc',
        mode: 'CC',
        label: 'Cartão de Cidadão',
        configured: false,
        production_blocked: false,
        local_only: true,
        note: 'Requires a co-located desktop process and card reader; no PIN is stored.',
      },
      {
        id: 'csc_qtsp',
        mode: 'CSC_QTSP',
        label: 'CSC/QTSP remote provider',
        configured: false,
        production_blocked: true,
        local_only: false,
        note: 'No CSC/QTSP provider is configured in the environment.',
      },
      {
        id: 'soft_pkcs12',
        mode: 'LOCAL_PKCS12',
        label: 'Local soft certificate (PKCS#12/PFX)',
        configured: false,
        production_blocked: true,
        local_only: true,
        note: 'Local-only test/operator material; private key and passphrase are never captured in settings.',
      },
    ],
  },
  platform: {
    logging: {
      global: 'info',
      app: 'info',
      api: 'info',
      mcp: 'info',
      service_overrides: {},
    },
    api_server: { enabled: true, desired_state: 'running', last_action: null },
    mcp_stdio_server: { enabled: false, desired_state: 'stopped', last_action: null },
    audit: [],
  },
  registry_auto_update: {
    enabled: false,
    cadence: { kind: 'interval_hours', hours: 24 },
    stale_threshold_hours: 24 * 30,
    min_backoff_minutes: 60,
    max_backoff_minutes: 24 * 60,
    max_attempts_per_run: 10,
    entity_defaults: { enabled: false, enabled_profiles: [] },
  },
  appearance: {
    theme: 'system',
    leather_texture: true,
    texture_intensity: 60,
    button_texture: true,
  },
  ui: {
    registered_entity_columns: ['Name', 'Nipc', 'Type', 'LastActivity', 'Actions'],
  },
  onboarding: { completed: false, completed_at: null },
  ai: { enabled: false },
};

export interface HealthResponse {
  status?: string;
  version?: string;
  /** Server-driven integrity signal (t54-E3). `"broken"` ⇒ a chain failed to verify. */
  integrity?: 'ok' | 'broken';
  /** Whether the instance is in read-only degraded mode (a broken chain, t54-E3). */
  degraded?: boolean;
}

// --- Chain integrity + recovery + data management (t54, FROZEN E3 DTOs) ----------
//
// The web halves of the frozen `chancela-api` recovery/data-management contract
// (`.orchestration/logs/t54-E3.md`). Hashes are lowercase-hex strings; timestamps are
// RFC 3339; chain ids are canonical strings (`"global"` | `"application"` |
// `"company:{uuid}"` | `"book:{uuid}"`). Every field mirrors the server view byte-for-byte.

/** The precise kind of a chain break (mirrors `chancela-ledger::BreakKind`). */
export type BreakKind =
  | 'BadGenesis'
  | 'SequenceBroken'
  | 'LinkBroken'
  | 'HashMismatch'
  | 'ChainSequenceBroken'
  | 'ChainLinkBroken'
  | 'ChainGenesisWrong';

/** The exact location + nature of the first break on a chain. */
export interface ChainBreakView {
  chain: string;
  kind: BreakKind;
  global_seq: number | null;
  chain_seq: number | null;
  event_id: string | null;
  expected_hash: string | null;
  actual_hash: string | null;
  message: string;
}

/** Per-chain verify status; `first_break` is the exact location when `verified` is false. */
export interface ChainStatusView {
  chain: string;
  genesis_kind: string | null;
  length: number;
  head: string | null;
  verified: boolean;
  first_break: ChainBreakView | null;
}

export interface ReanchorSegmentView {
  chain: string;
  from_chain_seq: number;
  to_chain_seq: number;
}

/** A permanent record of a re-anchor: what was rebuilt, by whom, and the overwritten state. */
export interface ReanchorRecordView {
  actor: string;
  at: string;
  reason: string;
  affected: ReanchorSegmentView[];
  original_global_head: string | null;
  new_global_head: string;
  pre_reanchor_digest: string;
}

/** `GET /v1/ledger/integrity` — the multi-chain integrity report. */
export interface IntegrityReportView {
  healthy: boolean;
  degraded: boolean;
  global: ChainStatusView;
  chains: ChainStatusView[];
  reanchored_segments: ReanchorRecordView[];
}

/** The step-up re-auth proof carried by every destructive server op (§8-F). One of the
 *  two proofs is supplied; a valid session token alone is never enough (403). */
export interface ReAuth {
  password?: string;
  recovery_phrase?: string;
}

/** `POST /v1/ledger/recovery/reanchor` request (reason required; reauth required, t54-R1). */
export interface ReanchorBody {
  reason: string;
  reauth: ReAuth;
  actor?: string;
}

/** `POST /v1/ledger/recovery/reanchor` response. */
export interface ReanchorResult {
  record: ReanchorRecordView;
  integrity: IntegrityReportView;
}

/** `POST /v1/ledger/recovery/restore` request. `archive` is an absolute path or a bare
 *  name resolved under `<data_dir>/backups/`. */
export interface RestoreBody {
  archive: string;
  actor?: string;
}

/** `POST /v1/ledger/recovery/restore` response — whole-store restore outcome. */
export interface RestoreOutcomeView {
  restored_from: string;
  ledger_length: number;
  ledger_head: string | null;
  chain_verified: boolean;
  integrity: IntegrityReportView;
}

// --- Hot backup (§3.2, plan t30) ------------------------------------------------
//
// The `POST /v1/backup` response — the manifest of a hot backup archive. Mirrors the
// server's `chancela_store::BackupManifest` byte-for-byte: `created_at`/`retrieved_at`
// are RFC 3339; `store_schema_version` is the snapshotted DB schema version; `ledger_head`
// is a lowercase-hex chain head, or `null` for an empty ledger; `files` are the per-member
// sha256 digests of the zip's contents (the SQLite snapshot plus each bundled sidecar).
// Server-response-modelled: the web app does not yet drive a backup, but the shape is
// pinned client-side so a wire change breaks the contract test on whichever side moved.

/** One member file inside a {@link BackupManifest}, with its sha256 for restore integrity. */
export interface BackupFile {
  /** The archive member name (e.g. `chancela.db`, `settings.json`). */
  name: string;
  /** Lowercase-hex (64-char) sha256 of the member's bytes. */
  sha256: string;
  /** The member's size in bytes. */
  bytes: number;
}

/** `POST /v1/backup` — the manifest of a hot backup archive (frozen contract §3.2, t30). */
export interface BackupManifest {
  /** Absolute path to the written `backups/chancela-backup-<utc>.zip`. */
  path: string;
  /** Total size of the zip archive in bytes. */
  bytes: number;
  /** When the backup was taken (UTC, RFC 3339). */
  created_at: string;
  /** The application version that produced the backup. */
  app_version: string;
  /** The store schema version of the snapshotted database. */
  store_schema_version: number;
  /** Number of events in the ledger at snapshot time. */
  ledger_length: number;
  /** The chain head hash as lowercase hex, or `null` for an empty ledger. */
  ledger_head: string | null;
  /** Whether the snapshotted chain verified at backup time. */
  ledger_verified: boolean;
  /** Per-file digests of the archive members (the db plus each bundled sidecar). */
  files: BackupFile[];
}

/** Import collision policy (§2.5). `refuse` is the safe default. */
export type CollisionPolicy = 'refuse' | 'quarantine_copy';

/** The verdict of verifying an imported bundle before trusting it. */
export type ImportVerdictView =
  { status: 'Verified' } | { status: 'Quarantined'; break?: ChainBreakView };

/** `POST /v1/books/import` response — the honest Verified|Quarantined outcome + provenance. */
export interface ImportOutcomeView {
  import_id: string;
  entity_id: string;
  book_id: string;
  verdict: ImportVerdictView;
  source_instance_id: string;
  bundle_digest: string;
  collided: boolean;
}

export interface PaperBookImportIdentity {
  entity_ref: string;
  entity_name: string;
  entity_nipc: string;
  book_ref: string;
}

export interface PaperBookImportDateSpan {
  from: string;
  to: string;
}

export interface PaperBookImportPackage {
  page_count: number;
  source_page_range: PaperBookPageRange;
  source_filename: string | null;
  digest: string | null;
  notes_present: boolean;
  notes_truncated: boolean;
}

export interface PaperBookPageRange {
  from: number;
  to: number;
}

export interface PaperBookOriginalAtaNumberRange {
  from: number;
  to: number;
}

export interface PaperBookLinkingEvidence {
  source_page_range: PaperBookPageRange;
  original_ata_number_range: PaperBookOriginalAtaNumberRange | null;
  non_canonical: boolean;
  planning_evidence_only: boolean;
  canonical_act_created: boolean;
  canonical_document_created: boolean;
  signature_created: boolean;
  legal_acceptance_claimed: boolean;
}

export interface PaperBookContinuationRecommendation {
  recommendation: string;
  recommended_action: string;
  recommended_next_ata_number: number | null;
  action_metadata: string[];
  requires_operator_review: boolean;
  canonical_act_created: boolean;
  canonical_document_created: boolean;
  signature_created: boolean;
  legal_acceptance_claimed: boolean;
}

export interface PaperBookImportClassification {
  classification: 'historical_paper_book_non_canonical_evidence';
  non_canonical: boolean;
  historical_evidence: boolean;
  preservation_status: 'not_preserved_by_validation' | 'preserved_non_canonical_package';
  canonical_minutes_claimed: boolean;
  legal_validity_claimed: boolean;
  signature_validity_claimed: boolean;
  qualified_signature_claimed: boolean;
}

export interface PaperBookImportFinding {
  severity: 'info' | 'warning' | 'error';
  code: string;
  message: string;
}

/** `POST /v1/books/paper-import/validate` read-only validation report. */
export interface PaperBookImportReport {
  report_kind: 'paper_book_import_validation';
  dry_run: boolean;
  legal_notice: string;
  identity: PaperBookImportIdentity;
  date_span: PaperBookImportDateSpan;
  package: PaperBookImportPackage;
  linking_evidence: PaperBookLinkingEvidence;
  continuation: PaperBookContinuationRecommendation;
  candidate_classification: PaperBookImportClassification;
  can_accept_as_import_candidate: boolean;
  required_operator_actions: string[];
  findings: PaperBookImportFinding[];
}

export interface PaperBookImportValidateBody {
  entity_ref: string;
  entity_name: string;
  entity_nipc: string;
  book_ref: string;
  date_from: string;
  date_to: string;
  page_count: number;
  page_from?: number | null;
  page_to?: number | null;
  original_ata_number_from?: number | null;
  original_ata_number_to?: number | null;
  source_filename?: string | null;
  digest?: string | null;
  notes?: string | null;
}

export interface PaperBookImportPreserveBody extends PaperBookImportValidateBody {
  content_base64: string;
  content_type: string;
  declared_sha256: string;
  size_bytes: number;
}

export interface PaperBookPreservation {
  status: 'preserved_non_canonical_package';
  non_canonical: boolean;
  sha256: string;
  size_bytes: number;
  content_type: string;
  imported_at: string;
  imported_by: string;
  ocr_status: PaperBookOcrStatus;
  bytes_in_ledger_event: boolean;
  legal_validity_claimed: boolean;
}

/** `POST /v1/books/paper-import` preservation report. */
export interface PaperBookImportPreservationReport extends Omit<
  PaperBookImportReport,
  'report_kind' | 'dry_run'
> {
  report_kind: 'paper_book_import_preservation';
  dry_run: false;
  import_id: string;
  preservation: PaperBookPreservation;
}

export type PaperBookOcrStatus =
  'disabled' | 'not_run' | 'not_started' | 'queued' | 'running' | 'completed' | 'failed' | string;

export interface PaperBookOcrStatusUpdateBody {
  status: PaperBookOcrStatus;
}

export interface PaperBookOcrStatusView {
  import_id: string;
  previous_ocr_status: PaperBookOcrStatus;
  ocr_status: PaperBookOcrStatus;
  status_notice: string;
  ocr_text_stored: boolean;
  authoritative_text_claimed: boolean;
  legal_validity_claimed: boolean;
  legal_notice: string;
}

/** Preserved historical paper-book package metadata. Raw bytes are fetched via `bytes_download`. */
export interface PaperBookImportView {
  import_id: string;
  entity_ref: string;
  entity_name: string;
  entity_nipc: string;
  book_ref: string;
  date_from: string;
  date_to: string;
  /** Optional additive metadata for APIs that preserve the source package page span. */
  page_from?: number | null;
  page_to?: number | null;
  original_ata_number_from?: number | null;
  original_ata_number_to?: number | null;
  linking_evidence?: PaperBookLinkingEvidence | null;
  continuation?: PaperBookContinuationRecommendation | null;
  page_count: number;
  sha256: string;
  size_bytes: number;
  content_type: string;
  source_filename: string | null;
  notes: string | null;
  imported_at: string;
  imported_by: string;
  ocr_status: PaperBookOcrStatus;
  ocr_status_notice: string;
  ocr_text_stored: boolean;
  authoritative_text_claimed: boolean;
  non_canonical: boolean;
  legal_validity_claimed: boolean;
  signature_validity_claimed: boolean;
  qualified_signature_claimed: boolean;
  /** Optional additive review marker. Older APIs omit it; the UI then renders a placeholder. */
  manual_review_state?: string | null;
  legal_notice: string;
  bytes_download: string;
}

/** `POST /v1/books/{id}/start-over` request (forward-writing lifecycle op; reason + a
 *  fresh-book opening spec). Non-destructive: the old book is archived + chained. */
export interface StartOverBookBody {
  reason: string;
  purpose: string;
  opening_date: string;
  required_signatories: string[];
  numbering_scheme?: NumberingScheme;
  actor?: string;
}

export interface ReinitBookView {
  scope: 'Book';
  archive_path: string;
  archived_bundle_digest: string;
  old_book_id: string;
  new_book_id: string;
}

/** `POST /v1/books/{id}/start-over` response — the archived old book + the fresh successor. */
export interface StartOverBookResult {
  reinit: ReinitBookView;
  new_book: BookView;
}

// --- Data status (`GET /v1/data/status`) ---------------------------------------

/** Backend persistence mode for the current instance. */
export const DATA_PERSISTENCE_MODES = ['durable', 'in_memory', 'fallback_in_memory'] as const;
export type DataPersistenceMode = (typeof DATA_PERSISTENCE_MODES)[number];

/** How a usage row was measured. */
export const DATA_USAGE_BASES = ['filesystem', 'sqlite_logical_payload', 'sqlite_file'] as const;
export type DataUsageBasis = (typeof DATA_USAGE_BASES)[number];

export interface DataPersistenceStatus {
  mode: DataPersistenceMode;
  data_dir_configured: boolean;
  durable_store_open: boolean;
  database_encryption_configured: boolean;
  store_schema_version: number | null;
  ledger_length: number;
  ledger_verified: boolean | null;
  degraded: boolean;
}

export interface DataDirStatus {
  path: string | null;
  exists: boolean | null;
  is_directory: boolean | null;
}

export interface DataPermissionCheck {
  ok: boolean;
  checked: boolean;
  message: string;
}

export interface DataPermissionStatus {
  read_dir: DataPermissionCheck;
  create_file: DataPermissionCheck;
  write_file: DataPermissionCheck;
  delete_probe_file: DataPermissionCheck;
  sqlite_store_open: DataPermissionCheck;
}

export interface DataUsageConcern {
  id: string;
  label: string;
  bytes: number;
  basis: DataUsageBasis;
  exact: boolean;
  file_count: number;
  directory_count: number;
  row_count?: number;
  relative_roots: string[];
}

export interface DataUsageStatus {
  total_bytes: number;
  filesystem: DataUsageConcern[];
  sqlite_logical: DataUsageConcern[];
  scan_errors: string[];
}

/** Read-only storage, data-directory and usage telemetry for Settings → Dados. */
export interface DataStatusResponse {
  generated_at: string;
  persistence: DataPersistenceStatus;
  data_dir: DataDirStatus;
  permissions: DataPermissionStatus;
  usage: DataUsageStatus;
}

/** Bounded storage-maintenance targets under the configured data directory. */
export type DataCleanupTarget = 'crash' | 'exports';

/** `POST /v1/data/cleanup` request for non-domain storage maintenance. */
export interface DataCleanupBody {
  target: DataCleanupTarget;
}

/** `POST /v1/data/cleanup` response. */
export interface DataCleanupResult {
  target: DataCleanupTarget;
  data_dir: string | null;
  deleted_bytes: number;
  deleted_files: number;
  deleted_directories: number;
  skipped: string[];
}

/** The destructive data-management scope (§2.11). */
export type ResetScope = 'backend_domain' | 'backend_factory';

/** `POST /v1/data/reset` request. `confirm_phrase` must equal the exact server phrase
 *  (`LIMPAR DADOS` / `REPOR FÁBRICA`); export-first is mandatory unless factory + an
 *  explicit `skip_export_confirm`. `reauth` is the step-up proof (§8-F). */
export interface ResetDataBody {
  scope: ResetScope;
  confirm_phrase: string;
  export_first: boolean;
  skip_export_confirm?: boolean;
  reauth: ReAuth;
  actor?: string;
}

/** `POST /v1/data/reset` response. `export_archive` is the retained export-first archive. */
export interface ResetOutcomeView {
  scope: 'BackendDomain' | 'BackendFactory';
  export_archive: string | null;
  cleared: string[];
}

/** `POST /v1/data/start-over` request (whole-instance archive-then-fresh; phrase `RECOMEÇAR`). */
export interface StartOverInstanceBody {
  reason: string;
  confirm_phrase: string;
  reauth: ReAuth;
  actor?: string;
}

/** `POST /v1/data/start-over` response. */
export interface StartOverInstanceView {
  scope: 'Instance';
  archive_path: string;
  archived_bundle_digest: string;
}

/** The exact type-to-confirm phrases the server enforces (frozen, §2.9 / E3). */
export const RESET_PHRASE = {
  backend_domain: 'LIMPAR DADOS',
  backend_factory: 'REPOR FÁBRICA',
  instance: 'RECOMEÇAR',
} as const;
