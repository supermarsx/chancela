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

/**
 * A user's language preference (t71): `'auto'` keeps following the environment, anything else
 * pins a locale.
 *
 * `'auto'` is stored as `'auto'` and never resolved to the detected locale and written back —
 * that would quietly convert "follow my environment" into "pin me to whatever I first loaded
 * with". Detection happens at render time, every time. Server-rendered output (documents,
 * e-mail) has no browser to detect from, so `'auto'` falls back to the platform default.
 */
export const LANGUAGE_AUTO = 'auto';
export type UserLanguage = typeof LANGUAGE_AUTO | Locale;

export const SIGNATURE_FAMILIES = [
  'CartaoCidadao',
  'ChaveMovelDigital',
  'OtherQualified',
  'Manual',
] as const;
export type SignatureFamily = (typeof SIGNATURE_FAMILIES)[number];

export const THEME_MODES = ['system', 'light', 'dark'] as const;
export type ThemeMode = (typeof THEME_MODES)[number];

/**
 * The capacities offered when choosing who **signs** an act or a book. A subset of the
 * capacities the API models — see `ATTENDEE_ONLY_CAPACITIES`.
 */
export const SIGNATORY_CAPACITIES = [
  'Chair',
  'Secretary',
  'Member',
  'Manager',
  'Administrator',
  'Attorney',
  'CondoOwner',
] as const;

/**
 * Capacities an **attendance row** can carry that a signature slot is not offered
 * (`crates/chancela-core/src/act.rs`). Which of the full set an entity actually offers is
 * decided server-side per legal type and arrives as `EntityProfile.attendee_qualities` — a
 * sociedade anónima offers `Shareholder`, a sociedade por quotas `Member`.
 */
export const ATTENDEE_ONLY_CAPACITIES = [
  'Shareholder',
  'Associate',
  'Cooperator',
  'StatutoryAuditor',
  'Guest',
  'Other',
] as const;

export type SignatoryCapacity =
  (typeof SIGNATORY_CAPACITIES)[number] | (typeof ATTENDEE_ONLY_CAPACITIES)[number];

export const PRESENCE_MODES = ['InPerson', 'Represented', 'Absent'] as const;
export type PresenceMode = (typeof PRESENCE_MODES)[number];

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
  /** The qualidades an attendance row may be recorded under for this legal type (t28). */
  attendee_qualities: SignatoryCapacity[];
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
  /** Owning tenant boundary; always present on entity reads. */
  tenant_id: string;
  /** Optional company-group membership; `null` means the entity is currently ungrouped. */
  group_id: string | null;
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

export interface EntityChronologyEvent {
  date: string | null;
  kind: string;
  description: string;
  source_inscription: string;
  actors: string[];
}

export interface EntityChronologyMermaid {
  shareholders: string;
  organs: string;
  relationships: string;
}

export interface EntityChronologyGraphNode {
  id: string;
  label: string;
  kind: string;
  category: string | null;
  source_inscription: string | null;
  source_date: string | null;
}

export interface EntityChronologyGraphEdge {
  id: string;
  from: string;
  to: string;
  label: string;
  kind: string;
  source_inscription: string | null;
  source_date: string | null;
}

export interface EntityChronologyGraph {
  nodes: EntityChronologyGraphNode[];
  edges: EntityChronologyGraphEdge[];
  warnings: string[];
}

export interface EntityChronologyGraphBundle {
  shareholders: EntityChronologyGraph;
  organs: EntityChronologyGraph;
  relationships: EntityChronologyGraph;
}

export interface EntityChronologyEventKindCount {
  kind: string;
  count: number;
}

export interface EntityChronologyGraphCount {
  nodes: number;
  edges: number;
  warnings: number;
}

export interface EntityChronologyGraphAnalytics {
  shareholders: EntityChronologyGraphCount;
  organs: EntityChronologyGraphCount;
  relationships: EntityChronologyGraphCount;
}

export interface EntityChronologyAnalytics {
  total_events: number;
  dated_events: number;
  undated_events: number;
  event_kinds: EntityChronologyEventKindCount[];
  source_inscription_count: number;
  source_inscriptions: string[];
  graph: EntityChronologyGraphAnalytics;
}

export interface EntityChronologySealedActSource {
  kind: 'sealed_act' | string;
  act_id: string;
  book_id: string;
  ata_number: number | null;
  payload_digest: string | null;
  seal_event_seq: number | null;
}

export interface EntityChronologySealedActProjectionEvent {
  date: string | null;
  kind: string;
  description: string;
  act_id: string;
  book_id: string;
  ata_number: number | null;
  act_state: ActState | string;
  source: EntityChronologySealedActSource;
}

export interface EntityChronologySealedActProjectionGraphNode {
  id: string;
  label: string;
  kind: string;
  source: EntityChronologySealedActSource;
}

export interface EntityChronologySealedActProjectionGraphEdge {
  id: string;
  from: string;
  to: string;
  label: string;
  kind: string;
  source: EntityChronologySealedActSource;
}

export interface EntityChronologySealedActProjection {
  events: EntityChronologySealedActProjectionEvent[];
  graph: {
    nodes: EntityChronologySealedActProjectionGraphNode[];
    edges: EntityChronologySealedActProjectionGraphEdge[];
  };
  provenance: EntityChronologySealedActSource[];
  legal_validity_claimed: false;
  authority_certified_claimed: false;
}

export interface EntityChronologyView {
  events: EntityChronologyEvent[];
  mermaid: EntityChronologyMermaid;
  graph: EntityChronologyGraphBundle;
  analytics: EntityChronologyAnalytics;
  sealed_act_projection?: EntityChronologySealedActProjection | null;
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
  required_signatory_records_abertura?: BookTermoSignatory[] | null;
  required_signatory_records_encerramento?: BookTermoSignatory[] | null;
}

export interface BookTermoSignatory {
  name: string;
  capacity: SignatoryCapacity | null;
  email: string | null;
}

/** `GET /v1/books/{id}/legal-hold` — retention-disposal override for a book. */
export interface BookLegalHoldView {
  legal_hold: boolean;
  reason: string | null;
  actor: string | null;
  set_at: string | null;
  operator_workflow?: BookLegalHoldOperatorWorkflow;
}

export interface BookLegalHoldOperatorWorkflow {
  status: 'blocked_by_legal_hold' | 'advisory_only' | string;
  disposal_review_blocked: boolean;
  review_note: string;
  next_step: string;
  destructive_disposal_completed: false;
  disposal_approved: false;
  legal_compliance_claimed: false;
}

/**
 * Query for `GET /v1/books/{id}/archive/package` — the only two knobs the endpoint accepts.
 * `legal_hold` stamps an export-time-only hold into the package (the server never persists it,
 * and rejects the request with 422 when the reason is missing or blank); a hold already
 * persisted on the book travels in the package regardless of this flag.
 */
export interface BookArchivePackageParams {
  legal_hold?: boolean;
  legal_hold_reason?: string;
}

export type ArchivePackageFileRole =
  'pdf_a' | 'signing_report' | 'evidence_report' | 'metadata' | 'other' | string;

export type ArchivePreservationLevel = 'BitLevel' | 'Managed' | string;

export interface ArchiveFileChecksum {
  algorithm: string;
  hex_digest: string;
}

export interface LocalDglabInterchangeProducerMetadata {
  name: string;
  system: string;
}

export interface LocalDglabInterchangeClassificationMetadata {
  scheme: string | null;
  code: string | null;
  title: string | null;
  sensitivity: string | null;
}

export interface LocalDglabInterchangeRightsMetadata {
  holder: string | null;
  license: string | null;
  access_note: string | null;
}

export interface LocalDglabInterchangeRetentionInstructions {
  schedule_id: string | null;
  review_after: string | null;
  legal_hold: boolean;
}

export interface LocalDglabInterchangeFileFixitySummary {
  algorithm: string;
  file_count: number;
  total_byte_len: number;
}

export interface LocalDglabInterchangeFileEntry {
  path: string;
  role: ArchivePackageFileRole;
  content_type: string;
  byte_len: number;
  checksum: ArchiveFileChecksum;
  act_id: string | null;
  document_id: string | null;
}

/** `GET /v1/books/{id}/archive/local-dglab-interchange-manifest` JSON scaffold. */
export interface LocalDglabInterchangeManifest {
  schema: 'chancela-local-dglab-interchange-manifest/v1' | string;
  profile: 'chancela-local-dglab-interchange-manifest/v1' | string;
  package_id: string;
  source_manifest_path: string;
  official_dglab_interchange: false;
  dglab_certification_claimed: false;
  external_dglab_approval_obtained: false;
  legal_archive_certified: false;
  destructive_disposal_performed: false;
  producer: LocalDglabInterchangeProducerMetadata;
  package_type: string;
  package_version: string;
  preservation_level: ArchivePreservationLevel;
  local_classification: LocalDglabInterchangeClassificationMetadata;
  rights: LocalDglabInterchangeRightsMetadata;
  languages: string[];
  retention: LocalDglabInterchangeRetentionInstructions;
  file_fixity_summary: LocalDglabInterchangeFileFixitySummary;
  evidence_index_path: string | null;
  files: LocalDglabInterchangeFileEntry[];
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

/**
 * The voting weight one attendance row carries — the externally tagged core enum. Companies
 * weight by capital (in minor units, i.e. cents); condominiums by permilagem (‰, 0..=1000).
 */
export type ActAttendanceWeight = { Capital: number } | { Permilage: number };

/**
 * One row of the structured lista de presenças (G2). Coexists with the `members_present` /
 * `members_represented` counts, which stay the fallback when nobody is named.
 *
 * `represented_by` must be set **iff** `presence` is `Represented` — the API rejects any other
 * combination with a 422.
 */
export interface ActAttendee {
  name: string;
  quality: SignatoryCapacity;
  /**
   * Free-text qualidade. Accepted **only** alongside `quality: 'Other'` (the API 422s
   * otherwise), so that reporting over `quality` stays a closed set.
   */
  quality_note: string | null;
  presence: PresenceMode;
  represented_by: string | null;
  weight: ActAttendanceWeight | null;
}

export interface ActConveningRecipient {
  name: string;
  contact: string | null;
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

/** The lawful ground on which a meeting was held with no convocatória. */
export type NoConveningBasis = 'AssembleiaUniversal' | 'Other';

/**
 * Recorded instead of `convening` when there was no convening notice at all. Deliberately not a
 * bare "skip convening" flag: the ata recites this basis, so it has to say something.
 */
export interface ActConveningWaiver {
  basis: NoConveningBasis;
  grounds: string | null;
  all_agreed_to_meet: boolean;
  all_agreed_to_agenda: boolean;
  evidence_reference: string | null;
}

export interface DispatchActConveningBody {
  actor?: string;
  dispatched_at: string;
  channel?: DispatchChannel | null;
  reference?: string | null;
  recipients?: string[] | null;
}

export interface ActManualSignatureOriginalReference {
  storage_reference: string;
  custodian?: string | null;
  note?: string | null;
}

export interface ActSealMetadata {
  rule_pack_id: string;
  version: string;
  family: EntityFamily;
  profile: EntityKind;
  manual_signature_original_reference?: ActManualSignatureOriginalReference | null;
  /** Digest of the canonical Ata PDF/A frozen when the act entered `Signing`. */
  signing_snapshot_digest?: string | null;
  /** Digest of the signed PDF accepted as electronic signing evidence, when present. */
  signed_pdf_digest?: string | null;
  /** Digest of the local technical validation report bound at seal, when present. */
  signature_validation_report_digest?: string | null;
}

export type WrittenResolutionReviewStatus = 'reviewed' | 'needs_follow_up';

export interface WrittenResolutionEvidenceStatusView {
  status: 'not_applicable' | 'missing' | 'referenced_only' | 'bound_present' | string;
  boundary: string;
  signed_signatory_slots: number;
  digested_attachments: number;
  checklist_items: number;
  digested_checklist_items: number;
  referenced_checklist_items: number;
  bound_count: number;
  referenced_only_count: number;
  review_receipts: number;
  latest_review_status: WrittenResolutionReviewStatus | null;
  reviewed_evidence_locators: number;
  reviewed_evidence_digests: number;
}

export interface WrittenResolutionEvidenceItemView {
  label: string;
  reference: string | null;
  digest: string | null;
  note: string | null;
}

export interface WrittenResolutionReviewEvidenceLocatorView {
  label: string;
  locator: string | null;
  digest: string | null;
}

export interface WrittenResolutionReviewReceiptView {
  reviewer: string;
  reviewed_at: string;
  status: WrittenResolutionReviewStatus;
  guardrail_acknowledgements: string[];
  evidence?: WrittenResolutionReviewEvidenceLocatorView[];
  note: string | null;
  consent_proof_claimed: false;
  quorum_proof_claimed: false;
  identity_proof_claimed: false;
  legal_acceptance_claimed: false;
  legal_sufficiency_claimed: false;
  external_validation_claimed: false;
  automatic_approval_claimed: false;
  authority_certified_claimed: false;
}

export interface WrittenResolutionEvidenceView {
  status: WrittenResolutionEvidenceStatusView;
  checklist?: WrittenResolutionEvidenceItemView[];
  review_receipts?: WrittenResolutionReviewReceiptView[];
  note: string | null;
}

export interface WrittenResolutionEvidenceItemInput {
  label: string;
  reference?: string | null;
  digest?: string | null;
  note?: string | null;
}

export interface WrittenResolutionReviewEvidenceLocatorInput {
  label: string;
  locator?: string | null;
  digest?: string | null;
}

export interface WrittenResolutionReviewReceiptInput {
  reviewer: string;
  reviewed_at: string;
  status: WrittenResolutionReviewStatus;
  guardrail_acknowledgements: string[];
  evidence: WrittenResolutionReviewEvidenceLocatorInput[];
  note?: string | null;
  consent_proof_claimed: false;
  quorum_proof_claimed: false;
  identity_proof_claimed: false;
  legal_acceptance_claimed: false;
  legal_sufficiency_claimed: false;
  external_validation_claimed: false;
  automatic_approval_claimed: false;
  authority_certified_claimed: false;
}

export interface WrittenResolutionEvidenceInput {
  checklist?: WrittenResolutionEvidenceItemInput[];
  review_receipts?: WrittenResolutionReviewReceiptInput[];
  note?: string | null;
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

export interface AiStatementSourceView {
  path: string;
  source_type: string;
  source_label: string;
  human_verified: boolean;
  human_verification_status: AiHumanVerificationStatus;
  authoritative_source_claimed: boolean;
  legal_validity_claimed: boolean;
}

export interface AiProvenanceView {
  source: string;
  tool: string | null;
  statement_source: string | null;
  statement_sources?: AiStatementSourceView[];
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
  written_resolution_evidence?: WrittenResolutionEvidenceView | null;
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
  convening_waiver?: ActConveningWaiver;
  /** Skip-serialized when empty, so an act with nobody named carries no `attendees` key. */
  attendees?: ActAttendee[];
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
  written_resolution_evidence_status?: WrittenResolutionEvidenceStatusView;
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

export type GeneratedDocumentDispatchEvidenceStatusCode =
  'required_pending' | 'operator_evidence_partial' | 'operator_evidence_covered' | string;

export interface GeneratedDocumentDispatchEvidenceStatus {
  status: GeneratedDocumentDispatchEvidenceStatusCode;
  required: boolean;
  evidence_attached: boolean;
  dispatch_completed: boolean;
  completion_basis: string;
  required_recipients: string[];
  recorded_recipients: string[];
  missing_recipients: string[];
  note: string;
}

export interface GeneratedDocumentView {
  id: string;
  act_id: string;
  template_id: string;
  pdf_digest: string;
  profile: string;
  created_at: string;
  download: string;
  dispatch_evidence_status?: GeneratedDocumentDispatchEvidenceStatus | null;
}

export interface GeneratedDocumentDispatchEvidenceRequest {
  actor: string;
  dispatched_at: string;
  channel?: DispatchChannel | null;
  reference?: string | null;
  recipients?: string[] | null;
  evidence_reference?: string | null;
  imported_document_id?: string | null;
  operator_note?: string | null;
}

export interface GeneratedDocumentDispatchEvidenceRecord {
  document_id: string;
  idempotency_key: string;
  act_id: string;
  template_id: string;
  actor: string;
  dispatched_at: string;
  channel: string | null;
  reference: string | null;
  evidence_reference: string | null;
  imported_document_id: string | null;
  recipients: string[];
  operator_note: string | null;
  recorded_at: string;
  sending_performed_by_chancela: boolean;
  delivery_confirmed: boolean;
  legal_sufficiency_claimed: boolean;
  legal_notice_completion_claimed: boolean;
  bytes_in_payload: boolean;
}

export interface GeneratedDocumentDispatchEvidenceResponse {
  evidence: GeneratedDocumentDispatchEvidenceRecord;
  dispatch_evidence_status: GeneratedDocumentDispatchEvidenceStatus;
}

export interface GeneratedDocumentDispatchEvidenceList {
  document_id: string;
  act_id: string;
  template_id: string;
  dispatch_evidence_status: GeneratedDocumentDispatchEvidenceStatus;
  evidence: GeneratedDocumentDispatchEvidenceRecord[];
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

export type TemplateLawReferenceSource = 'RulePack' | 'ThresholdRegistry' | string;
export type TemplateLawReferenceVerification = LegalBasisVerification;

/**
 * Structured legal citation candidate exposed with a template summary. These are provenance
 * anchors for discovery and drafting support only; `verification` must be rendered honestly and
 * never upgraded into a legal-validity claim.
 */
export interface TemplateLawReference {
  source_id: string;
  source_label: string;
  article?: string | null;
  citation: string;
  source: TemplateLawReferenceSource;
  verification: TemplateLawReferenceVerification;
  threshold_id?: string | null;
}

export type TemplateSource = 'builtin' | 'user' | string;

/**
 * One template-catalog entry (`GET /v1/templates?family=&stage=`, t48-e5/wp23). Metadata is copied
 * from the authored template asset; `editable`/`source` identify whether it is a read-only built-in
 * or a user-authored template that can be managed through the template API.
 */
export interface TemplateSummary {
  id: string;
  family: EntityFamily;
  stage: LifecycleStage;
  channels: MeetingChannel[];
  signature_policy: SignaturePolicyHint;
  rule_pack_id: string;
  law_references: TemplateLawReference[];
  locale: string;
  editable: boolean;
  source: TemplateSource;
}

export interface TemplateErrorBody {
  code: string;
  field?: string;
  message: string;
}

export interface TemplateImportVerdict {
  ok: boolean;
  error?: TemplateErrorBody;
}

/**
 * One key/value row inside an authored `KeyValue` block (`KvRowSpec`, wp23). Both `key` and
 * `value` are minijinja template strings rendered against the record context — not resolved text.
 */
export interface TemplateKvRowSpec {
  key: string;
  value: string;
}

/**
 * An authored template block (`BlockSpec`, wp23) — a `kind`-tagged union mirroring
 * `chancela-templates::BlockSpec`. Unlike the rendered {@link Block}, prose blocks here carry
 * *minijinja template strings* (not resolved text); structural blocks project typed record fields.
 * `#[serde(deny_unknown_fields)]` server-side, so authored JSON must match these shapes exactly.
 */
export type TemplateBlockSpec =
  | { kind: 'Heading'; level: number; template: string }
  | { kind: 'Paragraph'; items?: string | null; template: string }
  | { kind: 'KeyValue'; items?: string | null; rows: TemplateKvRowSpec[] }
  | {
      kind: 'VoteTable';
      items: string;
      label: string;
      vote_field?: string;
      unanimous_total?: string | null;
    }
  | { kind: 'SignatureBlock'; source: string; role: string; name: string }
  | { kind: 'PageBreak' }
  | { kind: 'Rule' };

/**
 * The canonical authored template spec (`TemplateSpecDto`, wp23) — the request body for
 * `POST`/`PUT /v1/templates` and the payload of `GET /v1/templates/{id}/export`. `law_references`
 * are SERVER-DERIVED and therefore NEVER authored, stored, or re-imported (they are absent here).
 * `id` must match `^user-[a-z0-9-]+/v[0-9]+$`; `blocks` is non-empty.
 */
export interface TemplateSpec {
  id: string;
  family: EntityFamily;
  stage: LifecycleStage;
  channels: MeetingChannel[];
  signature_policy: SignaturePolicyHint;
  rule_pack_id: string;
  blocks: TemplateBlockSpec[];
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

export interface DocumentBundleEvidencePaths {
  canonical_pdf_download: string;
  signed_pdf_download: string | null;
  attachments_manifest_json_pointer: string;
  validation_report_json_pointer: string;
}

export interface DocumentBundlePdfAccessibilityEvidenceIndex {
  evidence_kind: string;
  metadata_schema: string;
  bundle_report_json_pointer: string;
  archive_path_pattern: string;
  evidence_status: string;
  status_scope: string;
  pdf_ua_claimed: boolean;
  dglab_certification_claimed: false;
  legal_validity_claimed: false;
  pdf_ua_blockers: string[];
}

export interface DocumentBundleEvidenceIndex {
  index_kind: string;
  status_scope: string;
  document_id: string;
  act_id: string;
  bundle_paths: DocumentBundleEvidencePaths;
  pdf_accessibility?: DocumentBundlePdfAccessibilityEvidenceIndex;
  external_validator_reports?: JsonValue;
  generated_dispatch_evidence?: JsonValue[];
}

export interface PdfAccessibilityEvidenceReport {
  evidence_kind: string;
  metadata_schema: string;
  status_scope: string;
  evidence_status: string;
  document_id: string;
  act_id: string | null;
  template_id: string;
  report_source: string;
  pdf_ua_claimed: boolean;
  dglab_certification_claimed: false;
  legal_validity_claimed: false;
  report_version: number | null;
  pdf_ua_blockers: string[];
  accessibility_report_json?: JsonValue;
  unavailable_reason?: string | null;
}

export interface DocumentBundleValidationReport {
  report_kind: 'document_bundle_validation' | string;
  scope: 'generated_document_bundle' | string;
  status: 'technical_consistent' | 'technical_warning' | 'technical_error' | string;
  evidence_index?: DocumentBundleEvidenceIndex;
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
  pdf_accessibility?: PdfAccessibilityEvidenceReport;
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
  vri_tu_keys: string[];
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

export interface LocalTechnicalRenewalPlanReport {
  status: 'available' | 'not_applicable' | 'unavailable' | string;
  scope: string;
  notice: string;
  signature_timestamp_present: boolean;
  dss_revocation_evidence_present: boolean;
  dss_validation_time_present: boolean;
  doc_timestamp_present: boolean;
  doc_timestamp_imprints_valid: boolean;
  missing_inputs: string[];
  next_action: string;
  has_local_evidence_gap: boolean;
  all_local_planning_inputs_present: boolean;
  production_long_term_profile_claimed: boolean;
  legal_ltv_claimed: boolean;
}

export interface SignatureLocalRenewalPlanReport {
  index: number;
  object_id: string;
  signed_revision_len: number;
  vri_key_sha256: string;
  dss_vri_present: boolean;
  dss_vri_validation_time_present: boolean;
  local_technical_renewal_plan: LocalTechnicalRenewalPlanReport;
}

export interface MultiSignatureLocalRenewalPlanReport {
  status: 'available' | 'not_applicable' | 'unavailable' | string;
  scope: string;
  notice: string;
  signature_count: number;
  signatures: SignatureLocalRenewalPlanReport[];
  signatures_with_local_evidence_gaps: number[];
  next_action: string;
  has_local_evidence_gap: boolean;
  all_local_planning_inputs_present: boolean;
  production_long_term_profile_claimed: boolean;
  legal_ltv_claimed: boolean;
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
  local_technical_renewal_plan: LocalTechnicalRenewalPlanReport;
  multi_signature_local_renewal_plan: MultiSignatureLocalRenewalPlanReport;
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

// --- Arbitrary ASiC technical inspection ---------------------------------------

export interface AsicSignatureInspectionBody {
  content_base64: string;
  filename?: string | null;
  declared_sha256?: string | null;
  declared_size_bytes?: number | null;
}

export type AsicInspectionStatus = 'valid' | 'invalid';

export interface AsicMemberPathsReport {
  all: string[];
  payloads: string[];
  manifests: string[];
  cades_signatures: string[];
  xades_signatures: string[];
  unsupported_meta_inf: string[];
}

export interface AsicBlockerReport {
  id: string;
  message: string;
  member_path: string | null;
}

export interface AsicManifestSignatureReferenceReport {
  uri: string;
  member_present: boolean;
  member_kind: string | null;
}

export interface AsicManifestDataObjectReferenceReport {
  uri: string;
  mime_type: string | null;
  payload_present: boolean;
  sha256_digest: string;
  digest_matches: boolean | null;
}

export interface AsicManifestDiagnosticReport {
  path: string;
  size: number;
  signature_references: AsicManifestSignatureReferenceReport[];
  data_object_references: AsicManifestDataObjectReferenceReport[];
  blockers: AsicBlockerReport[];
}

export interface AsicSignatureDiagnosticReport {
  path: string;
  member_kind: string;
  size: number;
  referenced_by_manifest_paths: string[];
  blockers: AsicBlockerReport[];
}

export interface AsicProfileInspectionReport {
  container_kind: string;
  mimetype: string;
  signature_profile: string;
  profile_shape: string;
  bounded_profile: string | null;
  bounded_supported_candidate: boolean;
  member_paths: AsicMemberPathsReport;
  blockers: AsicBlockerReport[];
  manifest_diagnostics: AsicManifestDiagnosticReport[];
  signature_diagnostics: AsicSignatureDiagnosticReport[];
}

export interface AsicCadesSignedContentReport {
  kind: string;
  member_path: string;
  sha256: string;
}

export interface AsicCadesValidationReport {
  status: string;
  validation_performed: boolean;
  validation_error: string | null;
  cryptographically_valid: boolean;
  signed_content: AsicCadesSignedContentReport;
  signer_cert_sha256: string | null;
  signer_cert_subject: string | null;
  signing_time: string | null;
  has_signature_timestamp: boolean;
  evidence_scope: string;
  trust_validation: string;
  revocation_validation: string;
  legal_validity_claimed: boolean;
  qualified_signature_claimed: boolean;
}

export interface AsicTechnicalSignatureReport {
  path: string;
  kind: string;
  valid: boolean;
  manifest_path: string | null;
  covered_data_objects: string[];
  signer_cert_sha256: string | null;
  signer_cert_subject: string | null;
  signing_time: string | null;
  xades_level: string | null;
  has_signature_timestamp: boolean;
  signature_timestamp_trust_validation: string;
  failure_reasons: string[];
  evidence_scope: string;
  trust_validation: string;
  revocation_validation: string;
  provider_validation: string;
  provider_approval_claimed: boolean;
  legal_validity_claimed: boolean;
  qualified_signature_claimed: boolean;
  qes_claimed: boolean;
}

export interface AsicTechnicalArchiveTimestampReport {
  manifest_path: string;
  timestamp_path: string;
  valid: boolean;
  imprint_matches_manifest: boolean;
  references_valid: boolean;
  covered_members: string[];
  gen_time: string | null;
  timestamp_trust_validation: string;
  b_lta_claimed: boolean;
  legal_validity_claimed: boolean;
  failure_reasons: string[];
}

export interface AsicEmbeddedEvidenceIndicatorReport {
  code: string;
  source_path: string;
  evidence_kind: string;
  message: string;
}

export interface AsicEmbeddedEvidenceBlockerReport {
  code: string;
  source_path: string;
  message: string;
}

export interface AsicEmbeddedEvidenceReport {
  evidence_scope: string;
  indicators: AsicEmbeddedEvidenceIndicatorReport[];
  blockers: AsicEmbeddedEvidenceBlockerReport[];
  trust_validation: string;
  revocation_validation: string;
  timestamp_trust_validation: string;
  live_tsl_fetching: boolean;
  live_tsa_fetching: boolean;
  live_ocsp_fetching: boolean;
  live_crl_fetching: boolean;
  b_lt_claimed: boolean;
  b_lta_claimed: boolean;
  ltv_claimed: boolean;
  legal_validity_claimed: boolean;
  qualified_signature_claimed: boolean;
}

export interface AsicTechnicalValidationReport {
  validation_performed: boolean;
  cryptographically_valid: boolean;
  all_signatures_valid: boolean;
  container_failure_reasons: string[];
  signatures: AsicTechnicalSignatureReport[];
  archive_timestamps: AsicTechnicalArchiveTimestampReport[];
  embedded_evidence: AsicEmbeddedEvidenceReport;
}

export interface AsicInspectionFinding {
  severity: 'error' | 'warning' | 'info' | string;
  code: string;
  message: string;
}

export interface AsicSignatureInspectionResponse {
  report_kind: 'asic_signature_inspection' | string;
  scope: 'local_technical_asic_signature_evidence' | string;
  legal_notice: string;
  status: AsicInspectionStatus;
  filename: string | null;
  sha256: string;
  size_bytes: number;
  declared_sha256: string | null;
  declared_size_bytes: number | null;
  legal_validity_claimed: boolean;
  qualified_signature_claimed: boolean;
  qualified_electronic_signature_claimed: boolean;
  qes_claimed: boolean;
  trust_validation: string;
  trust_anchor_validation: string;
  revocation_validation: string;
  live_provider_calls: boolean;
  live_tsl_fetching: boolean;
  live_tsa_fetching: boolean;
  live_ocsp_fetching: boolean;
  live_crl_fetching: boolean;
  provider_approval_claimed: boolean;
  xades_validation_performed: boolean;
  b_lt_claimed: boolean;
  b_lta_claimed: boolean;
  ltv_claimed: boolean;
  production_asic_compliance_claimed: boolean;
  production_xades_conformance_claimed: boolean;
  eidas_legal_effect_claimed: boolean;
  signing_performed: boolean;
  storage_mutation_performed: boolean;
  archive_mutation_performed: boolean;
  technical_validation: AsicTechnicalValidationReport;
  profile: AsicProfileInspectionReport;
  cades: AsicCadesValidationReport | null;
  findings: AsicInspectionFinding[];
}

// --- External validator technical report metadata ------------------------------

/** Raw external-validator report fixity summary. Bytes are never listed inline. */
export interface ExternalValidatorRawReportSummary {
  preservation_status: 'raw_report_attached' | 'raw_report_manifest_only' | string;
  path?: string | null;
  suggested_path?: string | null;
  content_type: string;
  sha256: string;
  size_bytes: number;
  source_filename?: string | null;
}

/** Raw-report bytes attached to an operator-supplied technical metadata report. */
export interface ExternalValidatorRawReportUpload {
  content_base64: string;
  content_type: string;
  sha256: string;
  size_bytes: number;
  source_filename?: string | null;
}

/** `POST /v1/external-validator-reports` JSON document with optional raw report bytes. */
export type ExternalValidatorReportUploadBody = Record<string, unknown> & {
  raw_report?: ExternalValidatorRawReportUpload;
};

export type ExternalValidatorReportUploadRequest = string | ExternalValidatorReportUploadBody;

/** Redacted metadata summary for a stored external-validator JSON report. */
export interface ExternalValidatorReportSummary {
  case_id: string | null;
  validator_family: string | null;
  path?: string | null;
  archive_path?: string | null;
  suggested_archive_path?: string | null;
  suggested_path?: string | null;
  content_type: string | null;
  sha256?: string | null;
  digest?: string | null;
  size_bytes?: number | null;
  stored_at?: string | null;
  raw_report?: ExternalValidatorRawReportSummary | null;
  [key: string]: unknown;
}

/** `GET /v1/external-validator-reports` response. Raw report bytes are not exposed. */
export interface ExternalValidatorReportsResponse {
  storage: string;
  status: string;
  count: number;
  malformed_count: number;
  duplicate_suggested_path_count: number;
  reports: ExternalValidatorReportSummary[];
}

/** `POST /v1/external-validator-reports` response for an accepted raw JSON report. */
export interface ExternalValidatorReportUploadResponse {
  storage: string;
  status: string;
  report: ExternalValidatorReportSummary;
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

export interface DocumentCanonicalConversionPreflightReport {
  report_kind: 'legacy_imported_document_canonical_conversion_preflight' | string;
  scope: 'local_metadata_only' | string;
  status: 'not_attempted' | 'blocked' | string;
  source_format: 'legacy_word_doc' | 'ole_compound_file' | 'not_legacy_doc_or_ole' | string;
  review_state: string;
  bounded_evidence_status: string;
  evidence_basis: string[];
  blockers: string[];
  next_step: string;
  local_metadata_only: boolean;
  original_bytes_preserved: boolean;
  canonical_conversion_performed: false;
  canonical_pdfa_generated: false;
  signature_validation_performed: false;
  ocr_performed: false;
  legal_acceptance_claimed: false;
  external_provider_contacted: false;
  canonical_record_replaced: false;
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
  canonical_conversion_preflight: DocumentCanonicalConversionPreflightReport;
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
  acknowledged_guardrail_ids: ImportedDocumentReviewGuardrail[];
  review_note?: string | null;
}

export interface ImportedDocumentReviewHistoryEntry {
  decision_index: number;
  review_status: ImportedDocumentReviewStatus;
  reviewed_at?: string | null;
  reviewed_by?: string | null;
  review_note?: string | null;
  acknowledged_guardrail_ids: ImportedDocumentReviewGuardrail[];
  bytes_in_payload: false;
  ocr_performed: false;
  canonical_conversion_performed: false;
  canonical_pdfa_generated: false;
  signed_artifact_created_or_validated: false;
  legal_acceptance_claimed: false;
  certification_claimed: false;
}

export interface DocumentPreservationPolicyReport {
  review_state: string;
  requires_operator_review: boolean;
  requires_ocr_review: boolean;
  canonical_record_status: ImportedDocumentCanonicalRecordStatus;
  signed_artifact_status: ImportedDocumentSignedArtifactStatus;
  review_guardrail_checklist: ImportedDocumentReviewGuardrail[];
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
  operator_review_status: ImportedDocumentReviewStatus;
  operator_reviewed_at: string | null;
  operator_reviewed_by: string | null;
  operator_review_note: string | null;
  acknowledged_guardrail_ids: ImportedDocumentReviewGuardrail[];
  review_history: ImportedDocumentReviewHistoryEntry[];
  operator_review_notice: string;
  non_canonical: boolean;
  requires_ocr_review: boolean;
  canonical_record_status: ImportedDocumentCanonicalRecordStatus;
  signed_artifact_status: ImportedDocumentSignedArtifactStatus;
  review_guardrail_checklist: ImportedDocumentReviewGuardrail[];
  canonical_conversion_status: string;
  canonical_conversion_performed: boolean;
  canonical_conversion_preflight: DocumentCanonicalConversionPreflightReport;
  legal_acceptance_claimed: boolean;
  preservation_policy: DocumentPreservationPolicyReport;
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

export type LedgerOrder = 'desc';

export type LedgerArchiveDocumentFormat = 'pdfa' | 'json' | 'txt' | 'csv' | 'html';
export type LedgerArchiveDocumentScope = 'current_page' | 'all_filtered';

/** Query params for `GET /v1/ledger/events` and the paged `/v1/ledger/events/page`. */
export interface LedgerQueryParams {
  q?: string;
  chain?: string;
  scope?: string;
  kind?: string;
  actor?: string;
  from?: string;
  to?: string;
  before_seq?: number;
  limit?: number;
  order?: LedgerOrder;
}

export interface LedgerEventsPage {
  events: LedgerEventView[];
  next_cursor: number | null;
  has_more: boolean;
  limit: number;
  order?: LedgerOrder;
}

/** Query params for `GET /v1/ledger/archive/document`. */
export interface LedgerArchiveDocumentParams extends Omit<LedgerQueryParams, 'before_seq'> {
  format?: LedgerArchiveDocumentFormat;
  export_scope?: LedgerArchiveDocumentScope;
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
  /** Failed connector sync jobs visible to the globally authorized operator. */
  failed_sync_jobs: number;
  /** Queued/running/retryable durable backup jobs visible to the globally authorized operator. */
  pending_backup_jobs: number;
  ledger_length: number;
  ledger_valid: boolean;
  current_work: DashboardCurrentWork;
  alerts: DashboardAlert[];
  reminders: DashboardReminder[];
  recent_events: LedgerEventView[];
}

// --- Tenant operator surfaces --------------------------------------------------

/** A tenant-local company group. Groups organise entities; they are not authorization scopes. */
export interface CompanyGroupView {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
  archived_at?: string;
  member_count: number;
  template_library_count: number;
}

export interface CreateCompanyGroupBody {
  name: string;
  description?: string;
}

export interface PatchCompanyGroupBody {
  name?: string;
  description?: string | null;
}

/** An immutable revision of one group-owned shared template library. */
export interface GroupTemplateLibraryRevision {
  group_id: string;
  library_id: string;
  tenant_id: string;
  revision: number;
  template_ids: string[];
  created_at: string;
  created_by: string;
}

export interface GroupTemplateLibraryView {
  id: string;
  group_id: string;
  tenant_id: string;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
  archived_at?: string;
  current_revision: GroupTemplateLibraryRevision | null;
}

export interface CreateGroupTemplateLibraryBody {
  name: string;
  description?: string;
  template_ids: string[];
}

export interface PatchGroupTemplateLibraryBody {
  name?: string;
  description?: string | null;
}

export interface AppendGroupTemplateLibraryRevisionBody {
  template_ids: string[];
}

export interface GroupReminderView {
  id: string;
  act_id: string;
  title: string;
  due_date: string | null;
  overdue: boolean;
  assignee: string | null;
}

export interface GroupDashboardView {
  group: CompanyGroupView;
  member_entities: Entity[];
  books_total: number;
  books_by_state: Record<string, number>;
  acts_total: number;
  acts_by_state: Record<string, number>;
  reminders_open: number;
  reminders_overdue: number;
  reminders: GroupReminderView[];
  recent_audit_events: LedgerEventView[];
}

export type ConnectorJobPurpose = 'sync' | 'backup';
export type ConnectorKind =
  'web_dav' | 'microsoft_graph' | 'google_drive' | 'sftp' | 'ftps' | 'smb' | 's3';
export type ConnectorSecretReference = `CHANCELA_CONNECTOR_SECRET_${string}`;

export interface WebDavTargetConfig {
  kind: 'web_dav';
  id: string;
  base_url: string;
  auth:
    | { mode: 'basic'; username: string; password_ref: ConnectorSecretReference }
    | { mode: 'bearer'; token_ref: ConnectorSecretReference };
  timeout_seconds: number;
  allow_insecure_http: boolean;
}

export interface MicrosoftGraphTargetConfig {
  kind: 'microsoft_graph';
  id: string;
  drive_id: string;
  parent_item_id: string;
  token_ref: ConnectorSecretReference;
  api_base_url: string;
  timeout_seconds: number;
  allow_insecure_http: boolean;
}

export interface GoogleDriveTargetConfig {
  kind: 'google_drive';
  id: string;
  parent_folder_id: string;
  token_ref: ConnectorSecretReference;
  api_base_url: string;
  timeout_seconds: number;
  allow_insecure_http: boolean;
}

export interface SftpTargetConfig {
  kind: 'sftp';
  id: string;
  host: string;
  port: number;
  username: string;
  password_ref: ConnectorSecretReference;
  host_key_sha256: string;
  root: string;
  timeout_seconds: number;
}

export interface FtpsTargetConfig {
  kind: 'ftps';
  id: string;
  host: string;
  port: number;
  username: string;
  password_ref: ConnectorSecretReference;
  root: string;
  timeout_seconds: number;
}

export interface SmbTargetConfig {
  kind: 'smb';
  id: string;
  host: string;
  port: number;
  share: string;
  username: string;
  domain: string;
  password_ref: ConnectorSecretReference;
  root: string;
  timeout_seconds: number;
  allow_unencrypted: boolean;
}

export interface S3TargetConfig {
  kind: 's3';
  id: string;
  bucket: string;
  prefix: string;
  region: string;
  endpoint_url: string | null;
  force_path_style: boolean;
  access_key_ref: ConnectorSecretReference;
  secret_key_ref: ConnectorSecretReference;
  session_token_ref: ConnectorSecretReference | null;
  timeout_seconds: number;
  allow_insecure_http: boolean;
}

export type ConnectorTargetConfig =
  | WebDavTargetConfig
  | MicrosoftGraphTargetConfig
  | GoogleDriveTargetConfig
  | SftpTargetConfig
  | FtpsTargetConfig
  | SmbTargetConfig
  | S3TargetConfig;

export interface ConnectorTargetView {
  schema_version: number;
  id: string;
  repository_id: string;
  tenant_id: string;
  name: string;
  enabled: boolean;
  purposes: ConnectorJobPurpose[];
  kind: ConnectorKind;
  config: ConnectorTargetConfig;
  credential_storage: 'environment_or_confined_file_reference';
  created_at: string;
  updated_at: string;
  archived_at: string | null;
}

export interface CreateConnectorTargetBody {
  name: string;
  enabled: boolean;
  purposes: ConnectorJobPurpose[];
  config: ConnectorTargetConfig;
}

export interface PatchConnectorTargetBody {
  name?: string;
  enabled?: boolean;
  purposes?: ConnectorJobPurpose[];
  config?: ConnectorTargetConfig;
}

export type ConnectorProbeState = 'ready' | 'degraded' | 'unavailable';
export type ConnectorCapability =
  | 'upload'
  | 'download'
  | 'list'
  | 'search'
  | 'create_folder'
  | 'revisions'
  | 'multipart_upload'
  | 'atomic_replace'
  | 'resumable_upload'
  | 'source_checksum'
  | 'remote_checksum'
  | 'offline';
export type ConnectorErrorClass =
  | 'cancelled'
  | 'configuration'
  | 'authentication'
  | 'not_found'
  | 'conflict'
  | 'rate_limited'
  | 'transient'
  | 'permanent'
  | 'integrity';

export interface ConnectorStatusView {
  target_id: string;
  kind: ConnectorKind;
  state: ConnectorProbeState;
  capabilities: ConnectorCapability[];
  detail: string;
}

export interface ConnectorProbeView {
  target_id: string;
  checked_at: string;
  status: ConnectorStatusView | null;
  error_class: ConnectorErrorClass | null;
  error: string | null;
}

export type ConnectorJobState =
  'queued' | 'running' | 'retry_scheduled' | 'recovered' | 'succeeded' | 'failed' | 'cancelled';
export type ConnectorChecksumEvidence = 'source_only' | 'sent_to_provider' | 'remote_confirmed';

export interface ConnectorJobReceiptView {
  completed_unix_millis: number;
  connector: ConnectorKind;
  provider_object_id: string | null;
  provider_revision: string | null;
  etag: string | null;
  remote_bytes: number;
  checksum_evidence: ConnectorChecksumEvidence;
}

export interface ConnectorJobView {
  id: string;
  tenant_id: string;
  target_id: string;
  repository_id: string;
  purpose: ConnectorJobPurpose;
  destination: string;
  content_type: string;
  source_sha256: string;
  bytes: number;
  created_unix_millis: number;
  state: ConnectorJobState;
  attempt: number;
  not_before_unix_millis: number | null;
  error_class: ConnectorErrorClass | null;
  detail: string;
  receipt: ConnectorJobReceiptView | null;
}

export interface ConnectorJobListView {
  jobs: ConnectorJobView[];
  next_before_created_unix_millis: number | null;
}

export interface ListConnectorJobsParams {
  limit?: number;
  before_created_unix_millis?: number;
}

export type ConnectorRunArtifact =
  | { kind: 'act_document'; act_id: string; variant: 'canonical' | 'signed' }
  | { kind: 'latest_instance_backup' };

export interface RunConnectorTargetBody {
  request_id: string;
  purpose: ConnectorJobPurpose;
  artifact: ConnectorRunArtifact;
  destination: string;
}

export type RepositoryEncryptionMode = 'standard' | 'zero_knowledge';

export interface SplitKeyRecoveryPolicy {
  threshold: number;
  share_count: number;
  /** Public custodian labels only. Recovery shares never cross the API boundary. */
  custodian_labels: string[];
}

export interface KeyCustodyPolicy {
  bring_your_own_key: boolean;
  webauthn_prf_unsealing: boolean;
  split_key_recovery: SplitKeyRecoveryPolicy | null;
}

export type ZeroKnowledgeScope =
  { kind: 'tenant'; tenant_id: string } | { kind: 'repository'; repository_id: string };

export interface RepositoryPolicy {
  repository_id: string;
  tenant_id: string;
  name: string;
  encryption_mode: RepositoryEncryptionMode;
  zk_scope: ZeroKnowledgeScope | null;
  custody: KeyCustodyPolicy;
  gdpr_obligations_remain: true;
  created_at: string;
  updated_at: string;
}

export interface TenantRepositoryPolicy {
  tenant_id: string;
  encryption_mode: RepositoryEncryptionMode;
  custody: KeyCustodyPolicy;
  gdpr_obligations_remain: true;
  created_at: string;
  updated_at: string;
}

/**
 * `GET /v1/tenants/{id}/repository-policy`. Zero-knowledge custody is opt-in, so a tenant with
 * no policy is a normal state, not a missing resource: `policy` is `null` until it opts in.
 */
export interface TenantRepositoryPolicyView {
  policy: TenantRepositoryPolicy | null;
}

export interface StoredRepositoryPolicy {
  policy: RepositoryPolicy;
  policy_source: 'tenant' | 'repository';
}

export interface PutTenantRepositoryPolicyBody {
  encryption_mode: RepositoryEncryptionMode;
  custody: KeyCustodyPolicy;
  gdpr_obligations_remain: true;
}

export interface CreateRepositoryBody {
  name: string;
  inherit_tenant_policy: boolean;
  encryption_mode?: RepositoryEncryptionMode;
  custody?: KeyCustodyPolicy;
  gdpr_obligations_remain?: true;
}

export interface PatchRepositoryBody {
  name?: string;
  inherit_tenant_policy?: boolean;
  encryption_mode?: RepositoryEncryptionMode;
  custody?: KeyCustodyPolicy;
  gdpr_obligations_remain?: true;
}

export type ContentEncryptionAlgorithm = 'aes256_gcm';
export type KeyWrappingAlgorithm =
  | 'aes256_kw_byok'
  | 'hkdf_sha256_aes256_kw_webauthn_prf'
  | 'aes256_kw_split_recovery'
  | 'rsa_oaep_sha256_recipient';
export type KeyRecipientKind =
  'bring_your_own_key' | 'webauthn_credential' | 'split_recovery_plan' | 'external_recipient';

export interface WrappedContentEncryptionKey {
  slot_id: string;
  recipient_kind: KeyRecipientKind;
  recipient_id: string;
  algorithm: KeyWrappingAlgorithm;
  key_reference: string;
  wrapped_cek_base64: string;
  created_at: string;
}

export interface EncryptedMetadataEnvelope {
  algorithm: ContentEncryptionAlgorithm;
  nonce_base64: string;
  ciphertext_base64: string;
  ciphertext_sha256: string;
}

export interface OpaqueBlobManifest {
  schema_version: 1;
  associated_data: { repository_id: string; object_id: string; version: number };
  algorithm: ContentEncryptionAlgorithm;
  nonce_base64: string;
  ciphertext_sha256: string;
  ciphertext_len: number;
  encrypted_metadata: EncryptedMetadataEnvelope | null;
  wrapped_keys: WrappedContentEncryptionKey[];
  created_at: string;
}

export interface PendingZkUploadView {
  upload_id: string;
  repository_id: string;
  object_id: string;
  version: number;
  ciphertext_upload_url: string;
  created_at: string;
}

export interface ZkObjectVersionView {
  archive_id: string;
  tenant_id: string;
  manifest: OpaqueBlobManifest;
  ciphertext_url: string;
  committed_at: string;
}

export type ReadabilityPackageBody =
  | {
      mode: 'client_decrypted_archive';
      book_id: string;
      archive_base64: string;
      archive_sha256: string;
      reauth: ReAuth;
    }
  | {
      mode: 'encrypted_archive_with_portable_key_package';
      book_id: string;
      portable_key_package_jwe: string;
      recipient_instructions: string;
      reauth: ReAuth;
    };

export type NotificationTriageStatus = 'unread' | 'read' | 'dismissed' | 'acknowledged';

export interface NotificationSnapshotAction {
  href: string;
  label: string;
}

/**
 * A client-authored display copy of a notification, sent with a `dismissed` triage PATCH so the
 * Dismissed tab can show the item for the full retention window even after the dashboard condition
 * that generated it has cleared. The server stores it opaquely (length-capped, control-char-free)
 * and echoes it back on GET; it never interprets the fields.
 */
export interface NotificationSnapshot {
  kind: string;
  tone: string;
  badge: string;
  title: string;
  detail: string;
  timestamp?: string;
  action?: NotificationSnapshotAction;
}

export interface NotificationTriageEntry {
  owner?: string;
  notification_id: string;
  status: Exclude<NotificationTriageStatus, 'unread'>;
  updated_at: string;
  /** For a dismissed entry, the dismissal instant that starts the retention clock. */
  dismissed_at?: string;
  snapshot?: NotificationSnapshot;
}

export interface NotificationTriageResponse {
  entries: NotificationTriageEntry[];
  durable: boolean;
  max_entries_per_owner: number;
}

export interface NotificationTriageUpdateBody {
  status: NotificationTriageStatus;
  snapshot?: NotificationSnapshot;
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
  review_method: string | null;
  review_note: string | null;
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
export type DashboardReminderStatus = 'Upcoming' | 'DueSoon' | 'Overdue' | 'Pending';

export interface DashboardProfileCalendarNoClaimFlags {
  local_advisory_only: boolean;
  legal_deadline_authority_claimed: boolean;
  legal_calendar_authority_claimed: boolean;
  legal_compliance_claimed: boolean;
  compliance_status_claimed: boolean;
  workflow_completion_claimed: boolean;
  external_delivery_claimed: boolean;
  external_calendar_sync_claimed: boolean;
  webhook_delivery_claimed: boolean;
  legal_review_claimed: boolean;
  dre_verification_claimed: boolean;
  provider_effect_claimed: boolean;
  certification_claimed: boolean;
}

export interface DashboardProfileCalendarDueRule {
  kind: string;
  months_after_fiscal_year_end: number | null;
  default_fiscal_year_end: string | null;
  annual_fixed_month: number | null;
  annual_fixed_day: number | null;
  unsupported_reason: string | null;
}

export interface DashboardProfileCalendarEvaluation {
  local_due_date_rule_configured: boolean;
  local_due_date_calculated: boolean;
  legal_deadline_calculated: boolean;
  fiscal_year_end: string | null;
  due_year: number | null;
  due_basis: string | null;
  unsupported_reason: string | null;
}

export interface DashboardProfileCalendarPlan {
  preset_id: string;
  preset_label: string;
  rule_kind: string;
  support_status: string;
  review_status: string;
  source_status: string;
  due_rule: DashboardProfileCalendarDueRule;
  evaluation: DashboardProfileCalendarEvaluation;
  no_claims: DashboardProfileCalendarNoClaimFlags;
}

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
  profile_calendar_plan?: DashboardProfileCalendarPlan;
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

export type TrustIdentifierMatchField =
  | 'certificate_sha256'
  | 'subject_key_id'
  | 'subject_name'
  | 'provider'
  | 'service'
  | 'supply_point'
  | 'catalog';

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
  identifier_match?: TrustIdentifierMatchField[];
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
  identifier?: string;
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
  identifier_match?: TrustIdentifierMatchField[];
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

/**
 * Whether a corpus article's body is human-approved authentic text (`Verified`), automated-review
 * authentic text (`automated_review` — vendored + auto-reviewed, NOT human-legally-approved), or
 * still a placeholder (`Pending`). Serializes byte-for-byte as the `chancela_law::Verification`
 * serde values.
 */
export const LAW_VERIFICATIONS = ['Verified', 'automated_review', 'Pending'] as const;
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
  /** Automated-review authentic articles (vendored + auto-reviewed, NOT human-legally-approved). */
  automated_review: number;
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
  /**
   * The automated process that produced an `automated_review` body (e.g. `"automated-capture"`).
   * Present only on automated-review sources; a human-`Verified` or `Pending` source omits it.
   */
  review_method?: string;
  /**
   * The standing honest caveat carried by `automated_review` text (automated review only, NOT
   * human-legally-approved, human legal review recommended). Present only for that tier.
   */
  review_note?: string;
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
  /**
   * Automated-review authentic articles (vendored + auto-reviewed, NOT human-legally-approved) —
   * distinct from both `verified_count` and `pending_count` so a reader can badge the tier honestly.
   */
  automated_review_count: number;
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
// opaque token (`X-Chancela-Session`) minted by `POST /v1/session` that resolves the
// current user; a password is required for account creation and sign-in. It is a local
// tamper speed-bump, not at-rest encryption.

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
  /**
   * Whether the user has a **confirmed** TOTP second factor (t95 P1-C). A boolean only — the
   * secret, provisioning URI and backup codes never cross the wire. A pending (unconfirmed)
   * enrolment reads `false`.
   */
  has_totp: boolean;
  /**
   * Whether this account is required to hold a second factor (t95 §2.3). Enforced as
   * enrol-on-next-sign-in, never a hard lockout.
   */
  two_factor_required: boolean;
  /** 32-hex fingerprint of the attestation key; omitted when none (t29). */
  attestation_key_fingerprint?: string;
  /** The user's language preference (t71); `'auto'` for one who has never chosen. */
  language: UserLanguage;
  /**
   * The scoped role assignments this user holds (t103) — the **raw** `(role_id, scope)` pairs.
   *
   * No role name and no permission set: enriching would cost the server an async registry read on
   * a conversion used by every user handler, and the enriched shape already exists on the DSR
   * export path (`UserDsrExport.user.role_assignments`). Render an id with
   * `roleNameLabel(id, name)` from `api/labels.ts`.
   *
   * Match on `role_id`, never on a display name: names are translatable, and a retired id still
   * resolves to a label while matching no live role (t87).
   */
  role_assignments: RoleAssignmentView[];
}

export interface CreateUserBody {
  username: string;
  display_name?: string;
  email?: string;
  password: string;
  /**
   * t71: the `(role, scope)` to grant in the SAME request as the create, so the operator never
   * lands on a created-but-roleless account. The server applies exactly the checks
   * `POST /v1/users/{id}/roles` applies (`role.assign` @ scope **plus** the subset invariant)
   * before writing anything — a refused role creates no user. Omitted ⇒ the server's historical
   * `Gestor@Global` default.
   */
  role?: { role_id: string; scope: PermissionScope };
  /**
   * t71: send the new account a welcome e-mail. The message carries **no** password, token or
   * link (no credential-delivery mechanism with expiry exists) — it only announces the account.
   * A send failure never fails the create.
   */
  send_welcome_email?: boolean;
  /**
   * t71: the new account's language preference. Also the language the welcome e-mail renders
   * in; `'auto'` falls back to the platform default, since a server-rendered message has no
   * browser to detect from.
   */
  language?: UserLanguage;
}

export interface UpdateUserBody {
  display_name?: string;
  email?: string | null;
  active?: boolean;
  /** t71: `'auto'` is a real value here — it restores "keep detecting", it does not clear. */
  language?: UserLanguage;
  /**
   * t103/t107: require this account to hold a second factor, enforced as enrol-on-next-sign-in
   * (never a hard lockout). An administrative action gated `user.manage`; the server refuses
   * with `422` unless `auth.two_factor.totp_enabled` is on instance-wide.
   */
  two_factor_required?: boolean;
}

// --- RBAC permissions (§ t64-E3, FROZEN for the E5 web permissions context) ------
//
// The web half of the frozen `chancela-api::session` permission DTOs. A grant is one
// `(permission, scope)` pair the signed-in principal effectively holds, tagged by how it
// arrived (`role` ∪ `delegation`). `scope` is a serde-`kind`-tagged union: `global` covers
// everything while each resource scope carries its opaque id. Wider grants cover narrower
// resources only through authoritative parent relations, so `can(perm, scope)` maps to the
// server's `has_permission` semantics without widening. These mirror the server views
// byte-for-byte and are consumed both by the `GET /v1/session/permissions` endpoint
// (`SessionPermissions`) and by the first-paint `SessionView.permissions` embed.

/** A grant's provenance: a role assignment or a delegation (t64-E3). */
export const PERMISSION_SOURCES = ['role', 'delegation'] as const;
export type PermissionSource = (typeof PERMISSION_SOURCES)[number];

/** Frozen scope discriminants accepted and returned by the authorization API. */
export const PERMISSION_SCOPE_KINDS = [
  'global',
  'tenant',
  'entity',
  'book',
  'act',
  'folder',
  'template_library',
  'archive',
  'integration',
  'repository',
] as const;
export type PermissionScopeKind = (typeof PERMISSION_SCOPE_KINDS)[number];
export type ResourcePermissionScopeKind = Exclude<PermissionScopeKind, 'global'>;

/**
 * The scope a grant/assignment is held at — the complete `kind`-tagged union mirroring the
 * server's `ScopeView`/`ScopeInput`. `global` carries no id; every resource scope carries its
 * opaque UUID. The original global/entity/book wire variants remain unchanged.
 */
export type PermissionScope =
  | { kind: 'global' }
  | {
      [Kind in ResourcePermissionScopeKind]: { kind: Kind; id: string };
    }[ResourcePermissionScopeKind];

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
// serde-`kind`-tagged union `{"kind":"global"|<resource kind>,"id"?}`. We reuse
// `PermissionScope` for both so the scope picker maps directly onto the wire.

/** Read-only seeded-role drift diagnostics from `GET /v1/roles`. */
export interface SeededRoleDriftView {
  missing_default_permissions: string[];
  requires_manual_review: boolean;
}

/** Explicit admin-guided seeded-role drift reconciliation proposal/apply result. */
export interface SeededRoleReconciliationView {
  role_id: string;
  role_name: string;
  current_permissions: string[];
  missing_default_permissions: string[];
  proposed_permissions: string[];
  applied_permissions: string[];
  applied: boolean;
  requires_manual_review: boolean;
}

/** A role rendered for the web (`GET /v1/roles`, t64-E4). `permissions` are dotted verb ids
 *  in the role's deterministic order; `protected` marks the locked, undeletable Owner. */
export interface RoleView {
  id: string;
  name: string;
  permissions: string[];
  protected: boolean;
  /** Present for editable seeded roles; never means the server auto-reconciled permissions. */
  seeded_role_drift?: SeededRoleDriftView | null;
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
 * One delegated **função**, with the authority it currently carries. `permissions` is resolved
 * live by the server from the role catalog, so it always shows what the delegation conveys *now* —
 * a função edited after the grant moves the delegate's authority with it. `known` is false for a
 * função that has since left the catalog (it then conveys nothing).
 */
export interface DelegatedRoleView {
  id: string;
  name: string;
  permissions: string[];
  known: boolean;
}

/**
 * A delegation rendered for the web (`GET`/`POST /v1/delegations`, t64-E4; role-shaped t44).
 * `from`/`to` are user ids; `roles` the delegated funções; `scope` the tagged union. `revoked` is
 * terminal and `suspended` is a reversible pause — both make the delegation convey nothing, and the
 * server enforces that where authority resolves, not by omitting the row. `starts_at` is the
 * RFC-3339 start timestamp; `legal_basis` is operator-supplied local evidence/rationale and may be
 * absent on legacy records; `expires_at`/`revoked_at`/`revoked_by` are present only when set.
 */
export interface DelegationView {
  id: string;
  from: string;
  to: string;
  /** The delegated funções. Empty **only** on a legacy permission-shaped record. */
  roles: DelegatedRoleView[];
  /** Legacy: the primary verb of a pre-t44 permission-shaped record. Absent on role-shaped ones. */
  permission?: string;
  /** Every verb this delegation currently conveys — the flat view of `roles`. */
  permissions: string[];
  scope: PermissionScope;
  granted_at: string;
  starts_at: string;
  expires_at?: string;
  legal_basis?: string;
  revoked: boolean;
  /** Reversibly paused: conveys nothing until resumed. */
  suspended: boolean;
  revoked_at?: string;
  revoked_by?: string;
}

/**
 * Body of `POST /v1/delegations` (t64-E4; role-shaped t44). A delegation assigns a **função**, not
 * hand-picked permissions: `to` is the grantee user id and `roles` the ids of the funções to hand
 * over. `starts_at` and `expires_at` are optional RFC-3339 timestamps (omit `starts_at` ⇒ grant
 * time; omit `expires_at` ⇒ until-revoked); `legal_basis` is required operator-supplied local
 * evidence/rationale. The funções share one scope, one lifetime and one legal basis, and are
 * revoked as one unit.
 *
 * The server validates **every permission inside every função** independently and refuses the
 * delegation **entirely** (403, naming the offending verb) if any one is meta or not held by the
 * grantor via a role — never a partial grant. It 422s malformed timestamps, an empty `roles` array,
 * a missing/blank/overlong `legal_basis`, and any permission-shaped body.
 */
export interface GrantDelegationBody {
  to: string;
  /** The funções to delegate (role ids). At least one. */
  roles: string[];
  scope: PermissionScope;
  starts_at?: string;
  expires_at?: string;
  legal_basis: string;
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

// --- Companion pairing / device enrollment (wp27-e4 backend, e5 UI) --------------
//
// The desktop operator mints a short-lived pairing code (rendered as a QR / deep-link),
// the phone exchanges it for a companion session, and the resulting device shows up in a
// per-operator list that can be revoked. The desktop never calls `exchange` (that is the
// phone's unauthenticated request), so no `exchange` shape lives in this client.

/** Optional body of `POST /v1/pairing/codes`. */
export interface MintPairingCodeBody {
  /** Human label for the device that will redeem this code (e.g. "Telemóvel da Amélia"). */
  label?: string;
}

/** `POST /v1/pairing/codes` response — the one-time code plus its expiry. */
export interface PairingCodeMinted {
  /** The single-use pairing code (rendered as a QR / deep-link by the desktop UI). */
  code: string;
  /** RFC 3339 expiry instant. */
  expires_at: string;
  /** Seconds until expiry (the code TTL), for a countdown without clock-skew math. */
  expires_in_secs: number;
  /** The resolved device label bound to this code. */
  label: string;
}

/** One enrolled companion device (`GET /v1/pairing/devices`). */
export interface PairingDeviceView {
  device_id: string;
  label: string;
  /** RFC 3339 enrollment instant. */
  created_at: string;
  /** Whether the device has been revoked. */
  revoked: boolean;
  /** RFC 3339 revoke instant, or `null` while active. */
  revoked_at: string | null;
}

/** `GET /v1/pairing/devices` response. */
export interface PairingDevices {
  devices: PairingDeviceView[];
}

/** `POST /v1/api-keys/{id}/rotate` response: same one-time-secret shape as create. */
export type ApiKeyRotated = ApiKeyCreated;

// --- Provider-credential entries (wp13) -----------------------------------------
//
// Operator-facing management of the encrypted, multi-key/priority/failover provider
// credential store (`/v1/signature/provider-credentials`). Secrets are WRITE-ONLY by
// construction: no response type carries a secret value — only a per-field `configured`
// flag plus non-secret entry metadata (label/priority/enabled/endpoint/selectors).

/** The stable wire mode string for a credential record (matches the backend `as_str`). */
export type CredentialMode = 'cmd' | 'csc' | 'scap' | 'pkcs12';

/** How honestly the store protects secrets at rest (surfaced truthfully in the UI banner). */
export type CredentialProtectionLevel = 'confidential' | 'obfuscation';

/** One non-secret field in a response: its name and whether a value is configured. */
export interface ProviderCredentialFieldView {
  field_name: string;
  configured: boolean;
}

/** Metadata-only view of one credential entry (no secret value ever appears). */
export interface ProviderCredentialEntryView {
  entry_id: string;
  label: string;
  priority: number;
  enabled: boolean;
  endpoint?: string;
  selectors: Record<string, string>;
  fields: ProviderCredentialFieldView[];
  created_at: string;
  updated_at: string;
}

/** One `(mode, provider_id)` group's entries in the management list. */
export interface ProviderCredentialGroupView {
  mode: CredentialMode;
  provider_id: string;
  entries: ProviderCredentialEntryView[];
}

/** Sanitized reason the credential store cannot accept a secret at all. */
export type CredentialStorageFailure =
  | 'missing_key_source'
  | 'not_persistent'
  | 'ambiguous_operator_key'
  | 'invalid_operator_key'
  | 'missing_root_envelope'
  | 'invalid_root_envelope'
  | 'store_unavailable';

/**
 * `GET /v1/signature/provider-credentials` — the whole management list (metadata only).
 *
 * The storage triple carries one invariant the UI depends on: `protection_level` is present
 * exactly when `can_store` is true. An absent level therefore means "nothing can be stored",
 * never "stored with weaker protection" — the distinction the banner used to get wrong.
 * `can_store` is absent on a server predating t36; treat that as "storable" so an older server
 * keeps its previous (protection-level-driven) banner rather than claiming a blocked store.
 */
export interface ProviderCredentialsListView {
  strict: boolean;
  protection_level?: CredentialProtectionLevel;
  can_store?: boolean;
  storage_failure?: CredentialStorageFailure;
  providers: ProviderCredentialGroupView[];
}

/** The result of a single-entry mutation (create/update/delete). Secrets never appear. */
export interface ProviderCredentialEntryMutationResponse {
  mode: CredentialMode;
  provider_id: string;
  entry?: ProviderCredentialEntryView;
  deleted: boolean;
}

/** The entries of one record after a bulk operation (reorder). */
export interface ProviderCredentialEntryListResponse {
  mode: CredentialMode;
  provider_id: string;
  entries: ProviderCredentialEntryView[];
}

/** `POST …/entries` body — create an entry. `set` maps field name → write-only secret. */
export interface CreateProviderCredentialEntryBody {
  label?: string;
  enabled?: boolean;
  priority?: number;
  endpoint?: string;
  selectors?: Record<string, string>;
  set: Record<string, string>;
}

/** `PATCH …/entries/{entry_id}` body — partial update; absent = unchanged. */
export interface UpdateProviderCredentialEntryBody {
  label?: string;
  enabled?: boolean;
  priority?: number;
  endpoint?: string;
  selectors?: Record<string, string>;
  set?: Record<string, string>;
  clear?: string[];
}

/** `POST …/entries/reorder` body — the new priority order (a permutation of entry ids). */
export interface ReorderProviderCredentialEntriesBody {
  order: string[];
}

/** `POST /v1/acts/{id}/signature/local/pkcs12/sign-stored` body — carries NO secret material. */
export interface SignStoredPkcs12Body {
  provider_id: string;
  entry_id?: string;
  capacity?: string;
  actor?: string;
  seal?: SealAppearanceBody;
}

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
  /**
   * The wall this session must clear before it is a full session (t95 P2). Recomputed from the
   * user record on every `GET /v1/session`, so it survives a page reload and clears the instant the
   * underlying condition does — this is the single source of truth the `AuthGate` wall reads.
   * Absent (`undefined`) for an ordinary session, so the pre-t95 wire shape is unchanged.
   */
  required_action?: RequiredAction;
}

/**
 * `GET /v1/session/roster` (unauthenticated, t45-e1; narrowed by t33-e2) — ONE boolean.
 * `onboarding_required` is true iff no user exists at all (the first-run bootstrap is
 * available → show the wizard), which is all a signed-out client needs to decide
 * onboarding-vs-sign-in without the auth-gated `GET /v1/users`.
 *
 * It used to also return `users: RosterUser[]` (`{id, username, display_name, has_secret}`).
 * That was user enumeration: any anonymous caller could read the full valid-account list.
 * Sign-in is now by typed identifier — `POST /v1/session {username, password}` — so no
 * client needs the list, and `RosterUser` no longer exists.
 */
export interface SessionRoster {
  onboarding_required: boolean;
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

/**
 * `POST /v1/session`. Address the user by `username` — the identifier the operator types,
 * resolved server-side — or by `user_id` when the caller already holds it (the onboarding
 * wizard and the signed-in account switcher do). `username` wins if both are sent.
 *
 * On failure the server answers a single opaque `401 "credenciais inválidas"`: an unknown
 * username and a wrong password are deliberately indistinguishable, in wording and in
 * timing. Never surface the raw message in a way that implies otherwise.
 */
export type CreateSessionBody = { password: string } & (
  { username: string; user_id?: never } | { user_id: string; username?: never }
);

/**
 * `POST /v1/session/challenge` — completes a two-step sign-in issued by the challenge arm of
 * {@link CreateSessionOutcome}. `challenge_id` is the opaque handle from that response; `code` is a
 * TOTP or a backup code (the server decides by shape). Both are credentials: never log them, never
 * put them in a URL, drop them from state the moment they are consumed. On success the server
 * answers a {@link SessionResult}; on a wrong/spent/expired code or the attempt cap, a single opaque
 * `401` (indistinguishable, as with sign-in) — surface it as an inline field reject, never a
 * sign-out.
 */
export interface CompleteChallengeBody {
  challenge_id: string;
  code: string;
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

// --- Two-factor (TOTP) — frozen contract from t107 (t95 §2.3) --------------------
//
// The web half of the `GET /v1/users/{id}/two-factor` + enrol/confirm/disable/backup-codes
// endpoints. Self-scoped enrolment (`require_self` — a session that IS the target; API keys
// refused); the status read is also visible to an admin (`user.manage`) for another account,
// but `backup_codes_remaining` is `null` cross-user. The `has_totp` / `two_factor_required`
// booleans on `UserView` are the at-a-glance state; this is the fuller per-user read.

/**
 * `GET /v1/users/{id}/two-factor` — the second-factor state of one account.
 *
 * `enrolled` means a secret exists; `confirmed` means it has been activated with a code (an
 * enrolled-but-unconfirmed secret does not yet gate sign-in). `backup_codes_remaining` is
 * present only when the viewer is the account holder — an administrator reading another user's
 * state gets `null`, because how many recovery codes someone has left is theirs to know.
 */
export interface TwoFactorStatus {
  enrolled: boolean;
  confirmed: boolean;
  confirmed_at?: string;
  /** Self only; `null` when an administrator reads another account's state. */
  backup_codes_remaining?: number | null;
  required: boolean;
}

/**
 * `POST /v1/users/{id}/two-factor/totp/enrol` — begins enrolment. Returns the shared `secret`
 * and a `provisioning_uri` (the `otpauth://` URL an authenticator app scans) **shown exactly
 * once**; the factor is NOT active until confirmed. Neither value is persisted client-side.
 */
export interface TotpEnrolment {
  secret: string;
  provisioning_uri: string;
  confirmed: false;
}

/**
 * `POST /v1/users/{id}/two-factor/totp/confirm` `{ code }` and
 * `POST /v1/users/{id}/two-factor/backup-codes` — activation and regeneration both return the
 * ten backup codes **shown exactly once**. `401` on a wrong confirmation code.
 */
export interface BackupCodes {
  backup_codes: string[];
  backup_codes_remaining: number;
}

export interface TotpConfirmBody {
  code: string;
}

// --- Active sessions — frozen contract from t107 (t95, funded) -------------------
//
// Self-scoped: `GET /v1/sessions` returns the CALLER's own sessions, never a path parameter's,
// so this is only meaningful on one's own account — an administrator viewing another user never
// sees that user's device list. The token/digest never crosses the wire; `session_id` (an opaque
// uuid) is the only handle.

/**
 * One active sign-in (`GET /v1/sessions`). `device` and `ip` are **omitted** when unknown — a
 * session predating the enrichment, or a request with no user-agent / no resolvable IP — so the
 * panel must render their absence gracefully. `ip` is a **truncated network** (e.g.
 * `198.51.100.0`), never a full host: a full IP is personal data and this product is
 * privacy-conscious. Exactly one entry in the list carries `current: true`.
 */
export interface SessionInfo {
  session_id: string;
  device?: string;
  ip?: string;
  issued_at: string;
  last_seen_at: string;
  expires_at: string;
  current: boolean;
}

export interface SessionListResponse {
  sessions: SessionInfo[];
}

/**
 * `DELETE /v1/sessions/{session_id}` and `POST /v1/sessions/revoke-others` both answer with the
 * count revoked. A revoked session is rejected on its **next request** (not merely delisted), so
 * the other tabs are genuinely signed out. Revoking the `current` session signs the caller out.
 */
export interface RevokedResponse {
  revoked: number;
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

export const PRIVACY_ADVISORY_REVIEW_STATUSES = [
  'no_receipt',
  'current',
  'due_soon',
  'overdue',
  'under_review',
] as const;
export type PrivacyAdvisoryReviewStatus = (typeof PRIVACY_ADVISORY_REVIEW_STATUSES)[number];

export const RETENTION_POLICY_STATUSES = ['draft', 'active', 'suspended', 'retired'] as const;
export type RetentionPolicyStatus = (typeof RETENTION_POLICY_STATUSES)[number];

export const RETENTION_EXECUTION_STATUSES = ['awaiting_review', 'blocked', 'executed'] as const;
export type RetentionExecutionStatus = (typeof RETENTION_EXECUTION_STATUSES)[number];

export const RETENTION_EXECUTION_DECISION_STATES = ['open', 'review_closed'] as const;
export type RetentionExecutionDecisionState = (typeof RETENTION_EXECUTION_DECISION_STATES)[number];

export const RETENTION_REVIEW_CLOSURE_DECISIONS = [
  'review_evidence_acknowledged',
  'bounded_evidence_acknowledged',
  'blocked_evidence_acknowledged',
] as const;
export type RetentionReviewClosureDecision = (typeof RETENTION_REVIEW_CLOSURE_DECISIONS)[number];

export const RETENTION_CANDIDATE_DISPOSITIONS = [
  'evidence_acknowledged',
  'follow_up_required',
  'blocked_follow_up',
] as const;
export type RetentionCandidateDisposition = (typeof RETENTION_CANDIDATE_DISPOSITIONS)[number];

export const RETENTION_EVIDENCE_STATES = [
  'review_queued',
  'blocked',
  'bounded_archive_recorded',
  'bounded_no_action_recorded',
  'prior_bounded_evidence_available',
] as const;
export type RetentionEvidenceState = (typeof RETENTION_EVIDENCE_STATES)[number];

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

/** One breach-response playbook register record (`GET /v1/privacy/breach-playbooks`). */
export type BreachEvidenceKind = 'review' | 'drill';
export type DpiaEvidenceKind = 'review' | 'drill';

export interface DpiaEvidenceReceipt {
  id: string;
  evidence_type: DpiaEvidenceKind;
  recorded_at: string;
  recorded_by: string;
  occurred_at?: string;
  notes?: string;
  authority_filing_completed: false;
  legal_review_accepted: false;
  legal_certification_completed: false;
  external_delivery_completed: false;
  dpia_completed: false;
  compliance_certification_completed: false;
}

export interface BreachPlaybookEvidenceReceipt {
  id: string;
  evidence_type: BreachEvidenceKind;
  recorded_at: string;
  recorded_by: string;
  occurred_at?: string;
  notes?: string;
  authority_notified: false;
  subjects_notified: false;
}

export interface TransferControlEvidenceReceipt {
  id: string;
  recorded_at: string;
  recorded_by: string;
  reviewed_at?: string;
  notes?: string;
  transfer_approved: false;
  data_transfer_executed: false;
}

export interface PrivacyAdvisoryReviewSummary {
  status: PrivacyAdvisoryReviewStatus;
  last_reviewed_at?: string;
  last_drill_at?: string;
  next_review_due_at?: string;
  days_until_due?: number;
  review_interval_days: number;
  receipt_count: number;
  review_receipt_count: number;
  drill_receipt_count: number;
  local_advisory_only: true;
  authority_notification_claimed: false;
  subject_notification_claimed: false;
  transfer_approval_claimed: false;
  transfer_execution_claimed: false;
  external_delivery_configured: false;
  legal_completion_claimed: false;
}

export interface DpiaAdvisoryReviewSummary extends PrivacyAdvisoryReviewSummary {
  authority_filing_claimed: false;
  legal_acceptance_claimed: false;
  legal_certification_claimed: false;
  external_delivery_claimed: false;
  completion_claimed: false;
  compliance_certification_claimed: false;
}

/** One DPIA register record (`GET /v1/privacy/dpias`). */
export interface DpiaRecordView extends PrivacyRegisterRecordBase {
  id: string;
  title: string;
  evidence_receipts: DpiaEvidenceReceipt[];
  advisory_review: DpiaAdvisoryReviewSummary;
}

export type DpiaTemplateFieldType =
  'text' | 'textarea' | 'checklist' | 'date' | 'evidence_reference' | 'review_note';

export interface DpiaTemplateChecklistItem {
  id: string;
  label: string;
  field_type: DpiaTemplateFieldType;
  required: boolean;
}

export interface DpiaTemplateSection {
  id: string;
  title: string;
  description: string;
  prompts: string[];
  checklist: DpiaTemplateChecklistItem[];
}

export interface DpiaTemplateNoClaims {
  authority_filing_completed: false;
  authority_approval_obtained: false;
  cnpd_filing_completed: false;
  edpb_filing_completed: false;
  cnpd_or_edpb_approval_obtained: false;
  legal_review_accepted: false;
  legal_validation_completed: false;
  external_validation_completed: false;
  external_legal_validation_completed: false;
  external_delivery_completed: false;
  dpia_completed: false;
  dpia_completion_certified: false;
  compliance_certification_completed: false;
  transfer_approval_claimed: false;
  transfer_execution_claimed: false;
  authority_notification_claimed: false;
  subject_notification_claimed: false;
  automated_risk_scoring_performed: false;
  risk_score_authority_claimed: false;
  automated_legal_decision_made: false;
  register_mutation_performed: false;
  external_call_performed: false;
  raw_register_contents_included: false;
  processor_names_included: false;
  data_subjects_included: false;
  recipients_included: false;
  personal_data_included: false;
  secrets_included: false;
}

/** Static local/offline DPIA guidance pack (`GET /v1/privacy/dpia-template`). */
export interface DpiaTemplateView {
  schema: 'chancela-privacy-dpia-template/v1' | string;
  template_id: 'privacy-dpia-guidance/v1' | string;
  title: string;
  version: number;
  language: string;
  scope: 'local_offline_guidance_only' | string;
  local_offline_guidance_only: true;
  sections: DpiaTemplateSection[];
  operator_actions: string[];
  no_claims: DpiaTemplateNoClaims;
}

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
  evidence_receipts: BreachPlaybookEvidenceReceipt[];
  advisory_review: PrivacyAdvisoryReviewSummary;
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
  evidence_receipts: TransferControlEvidenceReceipt[];
  advisory_review: PrivacyAdvisoryReviewSummary;
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

export type RetentionExecutionIntent = 'review_only' | 'execute_supported';

export interface RetentionExecutionEvidenceBody {
  label: string;
  value: string;
}

export interface RetentionExecutionApprovalBody {
  approval_reference: string;
  policy_id: string;
  disposal_action: RetentionDisposalAction;
  approved_by: string;
  approved_at?: string;
}

export interface RetentionExecutionRequestBody {
  requested_policy_id?: string;
  execution_mode?: RetentionExecutionIntent;
  operator_notes?: string;
  evidence?: RetentionExecutionEvidenceBody[];
  approval?: RetentionExecutionApprovalBody;
}

export interface RetentionReviewClosureEvidence {
  label: string;
  value: string;
}

export interface RetentionReviewClosureEffectFlags {
  destructive_disposal_completed: false;
  full_erasure_completed: false;
  legal_hold_mutated: false;
  retention_policy_mutated: false;
}

export type CloseRetentionExecutionReviewBody = (
  | {
      review_closure_decision: RetentionReviewClosureDecision;
      review_closure_note: string;
      review_closure_evidence?: RetentionReviewClosureEvidence[];
    }
  | {
      review_closure_decision: RetentionReviewClosureDecision;
      review_closure_note?: string;
      review_closure_evidence: RetentionReviewClosureEvidence[];
    }
) &
  Partial<RetentionReviewClosureEffectFlags>;

/** Body of `POST /v1/privacy/retention-policies/dry-run`. */
export interface RetentionDryRunBody {
  scope: string;
  category: string;
  record_id?: string;
  execution_request?: RetentionExecutionRequestBody;
}

export type RetentionDueCandidateFinding =
  | {
      code?: string;
      message?: string;
      severity?: string;
    }
  | string;

export interface RetentionDueCandidatePriorExecution {
  execution_id: string;
  execution_status: RetentionExecutionStatus;
  outcome: RetentionExecutionOutcome;
  evidence_state: RetentionEvidenceState;
  evidence_next_step: string;
  requested_at: string;
  executed_at?: string;
  bounded_executor: boolean;
  targets_acted_count: number;
  destructive_disposal_completed: boolean;
  full_erasure_completed: boolean;
  next_step: string;
}

export interface RetentionCandidateResolutionSummary {
  id: string;
  candidate_fingerprint: string;
  recorded_at: string;
  recorded_by: string;
  disposition: RetentionCandidateDisposition;
  evidence_count: number;
  note?: string;
  evidence_only: true;
  destructive_disposal_completed: false;
  disposal_completed: false;
  full_erasure_completed: false;
  erasure_completed: false;
  legal_hold_mutated: false;
  legal_hold_resolved: false;
  retention_policy_mutated: false;
  retention_policy_changed: false;
  legal_completion_claimed: false;
  legal_disposal_completed: false;
  next_step: string;
}

export interface RetentionDueCandidate {
  candidate_id: string;
  candidate_fingerprint: string;
  scope: string;
  category: string;
  record_id: string;
  book_id: string;
  entity_id: string;
  closing_date: string;
  due_date: string | null;
  overdue: boolean;
  policy_id: string;
  policy_name: string;
  schedule_id: string;
  retention_period: string;
  disposal_action: string;
  destructive_action: boolean;
  legal_hold_blockers: unknown[];
  required_approvals: unknown[];
  blockers: unknown[];
  findings: RetentionDueCandidateFinding[];
  outcome: string;
  status: string;
  candidate_evidence_state: RetentionEvidenceState;
  evidence_next_step: string;
  would_execute: false;
  destructive_disposal_completed: false;
  full_erasure_completed: false;
  prior_execution?: RetentionDueCandidatePriorExecution;
  candidate_resolution_record_count: number;
  latest_resolution?: RetentionCandidateResolutionSummary;
  next_step: string;
}

export interface RetentionDueCandidatesSuppressionSummary {
  suppressed_by_bounded_evidence_count: number;
  note: string;
}

export interface RetentionDueCandidatesReport {
  generated_at: string;
  scope: 'book_archive';
  category: 'documents';
  /** Active, unsuppressed due candidates only. */
  candidate_count: number;
  suppressed_candidate_count: number;
  suppressed_by_bounded_evidence_count: number;
  candidate_resolution_record_count: number;
  candidates_with_resolution_count: number;
  suppression_summary?: RetentionDueCandidatesSuppressionSummary;
  candidates: RetentionDueCandidate[];
}

export interface RetentionCandidateResolutionSnapshot {
  candidate_id: string;
  candidate_fingerprint: string;
  scope: string;
  category: string;
  record_id: string;
  book_id: string;
  entity_id: string;
  closing_date: string;
  due_date?: string;
  overdue: boolean;
  policy_id: string;
  policy_name: string;
  schedule_id: string;
  retention_period: string;
  disposal_action: RetentionDisposalAction;
  destructive_action: boolean;
  outcome: string;
  status: string;
  candidate_evidence_state: RetentionEvidenceState;
  legal_hold_blocker_count: number;
  required_approval_count: number;
  blocker_count: number;
  finding_count: number;
}

export interface RetentionCandidateResolutionRecord extends RetentionCandidateResolutionSummary {
  candidate_id: string;
  evidence: RetentionReviewClosureEvidence[];
  candidate: RetentionCandidateResolutionSnapshot;
}

export interface RetentionCandidateResolutionBody {
  candidate_fingerprint: string;
  disposition: RetentionCandidateDisposition;
  note?: string;
  evidence?: RetentionReviewClosureEvidence[];
  destructive_disposal_completed?: false;
  disposal_completed?: false;
  full_erasure_completed?: false;
  erasure_completed?: false;
  legal_hold_mutated?: false;
  legal_hold_resolved?: false;
  retention_policy_mutated?: false;
  retention_policy_changed?: false;
  legal_completion_claimed?: false;
  legal_disposal_completed?: false;
}

export type RetentionOperatorReviewDecision = 'review_required' | 'blocked' | 'execution_recorded';

export type RetentionExecutionOutcome =
  | 'blocked_missing_policy'
  | 'blocked_stale_policy'
  | 'blocked_policy_mismatch'
  | 'blocked_legal_hold'
  | 'blocked_destructive_action'
  | 'blocked_approval_mismatch'
  | 'blocked_missing_target'
  | 'manual_review_required'
  | 'bounded_archive_recorded'
  | 'bounded_no_action_recorded'
  | 'already_executed';

export type RetentionOperatorWorkflowStatus = 'blocked' | 'awaiting_manual_review';

export interface RetentionExecutionRequestedPolicy {
  id?: string;
  found: boolean;
  name?: string;
  scope?: string;
  category?: string;
  schedule_id?: string;
  retention_period?: string;
  disposal_action?: RetentionDisposalAction;
  status?: RetentionPolicyStatus;
  active?: boolean;
  stale: boolean;
  matches_candidate: boolean;
  destructive_action: boolean;
}

export interface RetentionMatchedRecordsSummary {
  scope: string;
  category: string;
  record_id?: string;
  record_count: number;
  policy_match_count: number;
  destructive_policy_count: number;
  policy_ids: string[];
}

export interface RetentionLegalHoldBlocker {
  policy_id: string;
  name: string;
  schedule_id: string;
  retention_period: string;
  reason: string;
}

export interface RetentionWorkflowBlocker {
  code: string;
  message: string;
  policy_id?: string;
}

export interface RetentionRequiredApproval {
  code: string;
  required_from: string;
  reason: string;
}

export interface RetentionOperatorWorkflow {
  status: RetentionOperatorWorkflowStatus;
  blockers: RetentionWorkflowBlocker[];
  required_approvals: RetentionRequiredApproval[];
  next_step: string;
}

export interface RetentionOperatorEvidence {
  label: string;
  value: string;
}

export interface RetentionExecutionApproval {
  approval_reference: string;
  policy_id: string;
  disposal_action: RetentionDisposalAction;
  approved_by: string;
  approved_at?: string;
}

export interface RetentionExecutionTargetEvidence {
  target_type: string;
  target_id: string;
  action: string;
  reason_code: string;
  detail: string;
}

export interface RetentionExecutionBlockerMetadata {
  code: string;
  detail: string;
  policy_id?: string;
}

export interface RetentionExecutionResult {
  bounded_executor: boolean;
  executed_at?: string;
  executed_by?: string;
  targets_considered: RetentionExecutionTargetEvidence[];
  targets_acted: RetentionExecutionTargetEvidence[];
  targets_skipped: RetentionExecutionTargetEvidence[];
  reason_codes: string[];
  next_step: string;
  destructive_disposal_completed: boolean;
  full_erasure_completed: boolean;
  blocker_metadata: RetentionExecutionBlockerMetadata[];
}

export interface RetentionExecutionRecord extends RetentionReviewClosureEffectFlags {
  id: string;
  requested_at: string;
  actor: string;
  execution_intent: RetentionExecutionIntent;
  execution_status: RetentionExecutionStatus;
  operator_review_decision: RetentionOperatorReviewDecision;
  decision_state: RetentionExecutionDecisionState;
  review_closure_decision?: RetentionReviewClosureDecision;
  review_closure_evidence: RetentionReviewClosureEvidence[];
  review_closed_by?: string;
  review_closed_at?: string;
  review_closure_note?: string;
  requested_policy: RetentionExecutionRequestedPolicy;
  candidate: RetentionDryRunCandidate;
  matched_records_summary: RetentionMatchedRecordsSummary;
  legal_hold_blockers: RetentionLegalHoldBlocker[];
  operator_notes?: string;
  audit_evidence: RetentionOperatorEvidence[];
  approval?: RetentionExecutionApproval;
  outcome: RetentionExecutionOutcome;
  block_reason: string;
  evidence_state: RetentionEvidenceState;
  evidence_next_step: string;
  workflow: RetentionOperatorWorkflow;
  execution_result: RetentionExecutionResult;
  would_execute: boolean;
}

export interface RetentionDryRunReport {
  mode: 'dry_run' | 'execution_request';
  execution_supported: boolean;
  destructive_execution_supported: boolean;
  candidate: RetentionDryRunCandidate;
  matched_count: number;
  matches: RetentionDryRunMatch[];
  execution_record?: RetentionExecutionRecord;
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
  evidence_receipt?: DpiaEvidenceReceiptBody;
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
  evidence_receipt?: DpiaEvidenceReceiptBody;
}

export interface DpiaEvidenceReceiptBody {
  evidence_type?: DpiaEvidenceKind;
  occurred_at?: string;
  notes?: string;
  authority_filing_completed?: false;
  legal_review_accepted?: false;
  legal_certification_completed?: false;
  external_delivery_completed?: false;
  dpia_completed?: false;
  compliance_certification_completed?: false;
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
  evidence_receipt?: BreachEvidenceReceiptBody;
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
  evidence_receipt?: BreachEvidenceReceiptBody;
}

export interface BreachEvidenceReceiptBody {
  evidence_type?: BreachEvidenceKind;
  occurred_at?: string;
  notes?: string;
  authority_notified?: false;
  subjects_notified?: false;
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
  evidence_receipt?: TransferEvidenceReceiptBody;
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
  evidence_receipt?: TransferEvidenceReceiptBody;
}

export interface TransferEvidenceReceiptBody {
  reviewed_at?: string;
  notes?: string;
  transfer_approved?: false;
  data_transfer_executed?: false;
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

/**
 * The wall a freshly signed-in (or reloaded) session must clear before it can do anything else
 * (t95 P2). Wire values are the server's snake_case `RequiredAction` variants:
 * - `change_password` — the account was created with an admin-chosen password (welcome-email path)
 *   and must change it now; cleared on the first successful self `set_secret`.
 * - `enrol_two_factor` — the account is required to hold a second factor and has none; it may reach
 *   only the TOTP enrol/confirm endpoints (enrol-on-next-sign-in, never a hard lockout).
 * Password change takes priority when both apply. Enforced per-request by the server (403 while
 * walled); surfaced here and on {@link SessionView} so the client can route straight to the wall.
 */
export type RequiredAction = 'change_password' | 'enrol_two_factor';

/** A factor that can satisfy a two-step sign-in challenge. `totp` is always offered; `backup_code`
 *  only when the account still has unspent recovery codes. The server decides which was supplied by
 *  the code's shape, so both ride the same {@link CompleteChallengeBody} `code` field. */
export type TwoFactorMethod = 'totp' | 'backup_code';

/**
 * The challenge arm of {@link CreateSessionOutcome} (`POST /v1/session`) when the account has a
 * confirmed second factor. Carries **no token** — the session does not exist yet — only an opaque
 * `challenge_id` (a process-local, never-persisted handle that grants nothing on its own), the
 * factors that satisfy it, and an rfc3339 `expires_at`. Complete it at `POST /v1/session/challenge`.
 */
export interface TwoFactorChallengeView {
  challenge_id: string;
  /** Accepted factors, in preference order (`"totp"` first). */
  methods: TwoFactorMethod[];
  /** rfc3339 UTC instant after which the challenge is spent and the user must re-enter the password. */
  expires_at: string;
}

/** `POST /v1/session` — the issued token plus the now-active user, and (only when the account is
 *  walled) the {@link RequiredAction} it must clear first. Also the success shape of
 *  `POST /v1/session/challenge`. */
export interface SessionResult {
  token: string;
  user: UserView;
  /** Present only when the freshly minted session is walled; omitted on an ordinary sign-in. */
  required_action?: RequiredAction;
}

/**
 * The untagged `POST /v1/session` outcome: either an authenticated {@link SessionResult} (carries
 * `token`), or a {@link TwoFactorChallengeView} wrapper (carries `two_factor_challenge`) when the
 * account has a confirmed second factor. Discriminate by which key is present —
 * `'two_factor_challenge' in outcome` selects the challenge arm, otherwise it is the token arm.
 * A wrong password never reaches the challenge arm (it is a uniform opaque 401, as before).
 */
export type CreateSessionOutcome = SessionResult | { two_factor_challenge: TwoFactorChallengeView };

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
  required_signatories: BookTermoSignatoryInput[];
  predecessor?: string;
  actor?: string;
}

export interface CloseBookBody {
  reason: ClosingReason;
  closing_date: string;
  required_signatories: BookTermoSignatoryInput[];
  actor?: string;
}

export type BookTermoSignatoryInput = string | BookTermoSignatory;

export interface DraftActBody {
  book_id: string;
  title: string;
  channel: MeetingChannel;
  ai_provenance?: AiProvenanceInput | null;
  convening?: ActConvening | null;
  convening_waiver?: ActConveningWaiver | null;
  retifies?: string;
}

export interface AiProvenanceInput {
  source: string;
  tool?: string | null;
  statement_source?: string | null;
  statement_sources?: AiStatementSourceInput[];
}

export interface AiStatementSourceInput {
  path: string;
  source_type: string;
  source_label: string;
  human_verified?: boolean;
  human_verification_status?: AiHumanVerificationStatus;
  authoritative_source_claimed?: boolean;
  legal_validity_claimed?: boolean;
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
  written_resolution_evidence?: WrittenResolutionEvidenceInput | null;
  deliberations?: string;
  deliberation_items?: ActDeliberationItem[];
  telematic_evidence?: string | null;
  attachments?: ActAttachment[];
  signatories?: ActSignatory[];
  convening?: ActConvening | null;
  convening_waiver?: ActConveningWaiver | null;
  attendees?: ActAttendee[];
}

export interface AdvanceActBody {
  to: ActState;
  actor?: string;
  /** Optional Ata template selected only while atomically entering `Signing`. */
  template_id?: string;
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
  /** Explicit alternate evidence when no accepted signed PDF is present. */
  manual_signature_original_reference?: ActManualSignatureOriginalReference;
  /** Optional assertion that must match the already-frozen Signing snapshot template. */
  template_id?: string;
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

export interface WorkflowReminderSourceSettings {
  profile_calendar: boolean;
  act_follow_ups: boolean;
  attendance_hygiene: boolean;
  privacy_control_reviews: boolean;
}

export interface WorkflowReminderSettings {
  enabled: boolean;
  dashboard_limit: number;
  due_soon_days: number;
  attendance_lookahead_days: number;
  sources: WorkflowReminderSourceSettings;
}

export interface WorkflowSettings {
  reminders: WorkflowReminderSettings;
}

export interface RetainedExportCleanupSettings {
  minimum_age_days: number;
  keep_latest: number;
}

export interface BackupRecoveryPolicySettings {
  max_drill_age_days: number;
  target_rpo_minutes: number;
  target_rto_minutes: number;
}

export interface DataManagementSettings {
  retained_export_cleanup: RetainedExportCleanupSettings;
  backup_recovery: BackupRecoveryPolicySettings;
  /** Operator declaration of the shared-mounted zero-knowledge object root. Optional and omitted
   *  from the wire while unset, so an older document cannot open the interlock by omission.
   *  `CHANCELA_ZK_SHARED_OBJECT_ROOT` wins when both are set. Resolved once at startup — writing it
   *  takes effect at the next restart, which the UI states rather than implying it is live. */
  zk_shared_object_root?: string | null;
}

/** Where the running process got its declared ZK object root. */
export type ZkSharedRootSource = 'environment' | 'settings' | 'unset';

/** `GET /v1/zk-repositories/storage-status` — the LIVE state of the fail-closed object-root
 *  interlock, as resolved at process start. Compare `declared_root` against the saved setting to
 *  tell whether a restart is still outstanding. */
export interface ZkStorageStatus {
  ready: boolean;
  reason: string | null;
  requires_shared_root: boolean;
  declared_root: string | null;
  source: ZkSharedRootSource;
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
  /**
   * The absolute `https://` URL this instance is reached at (t95 P0-3). The origin of every
   * emailed link — invitations, and later recovery — and **never** derived from a request's `Host`
   * header. `null` until an operator configures it; while `null`, every link-issuing feature is
   * unavailable and says so. Always present on the wire (serialized as `null` when unset).
   */
  public_base_url: string | null;
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

// ---------------------------------------------------------------------------------------------
// Server environment overrides (t14) — `GET`/`PUT /v1/platform/env`.
//
// The server declares the authoritative registry of every process env var it reads
// (`chancela-api/src/env_overrides.rs`); the panel renders whatever the server *declares* instead of
// a hardcoded row list, and finally gets the live resolved values it never had. Treatment is tiered
// ("as they should", not "every var an editable box"): Tier A editable; Tier B secrets display-only
// (never echoed — only `configured`); Tier C security boundaries editable behind an acknowledgement
// the server enforces with a `422`, ceilings narrow-only; Tier D derived / read-only. Everything is
// restart-to-apply, surfaced as `restart_pending`.
// ---------------------------------------------------------------------------------------------

/** Treatment tier: A editable · B secret (display-only) · C boundary (ack-gated) · D derived. */
export const SERVER_ENV_TIERS = ['A', 'B', 'C', 'D'] as const;
export type ServerEnvVarTier = (typeof SERVER_ENV_TIERS)[number];

/** Which layer supplied the value the live process resolved. */
export const SERVER_ENV_SOURCES = ['override', 'env', 'default'] as const;
export type ServerEnvVarSource = (typeof SERVER_ENV_SOURCES)[number];

/** The section the web groups a var under. */
export const SERVER_ENV_GROUPS = [
  'logging',
  'network',
  'session',
  'rate_limit',
  'hsts',
  'cors',
  'database',
  'credentials',
  'cache',
  'cluster',
  'postgres_tls',
  'trust',
  'signing',
  'csc',
  'cmd',
  'scap',
  'connectors',
  'storage',
  'paper_book',
  'mcp',
] as const;
export type ServerEnvVarGroup = (typeof SERVER_ENV_GROUPS)[number];

/** The validator kind the web reads to pick an input control. */
export const SERVER_ENV_VALIDATOR_KINDS = [
  'free_text',
  'path',
  'bool',
  'unsigned',
  'enum',
  'http_url',
  'socket_addr',
  'host_list',
  'duration',
] as const;
export type ServerEnvValidatorKind = (typeof SERVER_ENV_VALIDATOR_KINDS)[number];

export interface ServerEnvValidatorView {
  kind: ServerEnvValidatorKind;
  /** Allowed literals for `kind: 'enum'`; `null` otherwise. */
  allowed: string[] | null;
}

/**
 * One env var as rendered by `GET /v1/platform/env`: the declared classification joined with the
 * value the live process resolved. Secrets never carry a value — only `configured`.
 */
export interface ServerEnvVarView {
  name: string;
  group: ServerEnvVarGroup;
  tier: ServerEnvVarTier;
  /** The panel presents an editor (Tier A/C and not typed-slice-excluded). */
  editable: boolean;
  /** Holds (or points at) a secret — value is never echoed. */
  secret: boolean;
  /** A security boundary — a change needs acknowledgement. */
  boundary: boolean;
  /** A ceiling an override may only tighten, never loosen. */
  narrow_only: boolean;
  /** Editing requires acknowledging the risk; the server enforces a `422` otherwise. */
  acknowledgement_required: boolean;
  /** Non-null → managed by a typed settings slice; shown read-only with a cross-link (the reason). */
  excluded_typed_slice: string | null;
  source: ServerEnvVarSource;
  /** The live process currently has a value (the only signal for secrets). */
  configured: boolean;
  /** The resolved value. `null` for secrets (never echoed) and when unset. */
  effective_value: string | null;
  /** The persisted override, if any. `null` for secrets and when no override is set. */
  override_value: string | null;
  /** The code default. `null` for secrets and vars with no default. */
  default_value: string | null;
  /** The stored override differs from the live value → takes effect on next restart. */
  restart_pending: boolean;
  validator: ServerEnvValidatorView;
}

/** `GET /v1/platform/env`, and the body a successful `PUT` returns. */
export interface ServerEnvResponse {
  vars: ServerEnvVarView[];
  restart_pending: boolean;
  /** Where the override file lives (informational; under `CHANCELA_DATA_DIR`). */
  overrides_path: string;
  generated_at: string;
}

/**
 * `PUT /v1/platform/env` — replace the non-secret override map. The map is the complete desired set
 * (keys absent from it are cleared). Only Tier A/C vars may appear. Any boundary var that changes
 * must have its name in `acknowledge`, or the server returns `422`.
 */
export interface ServerEnvUpdateRequest {
  overrides: Record<string, string>;
  acknowledge: string[];
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

export interface PlatformLogRetentionMetadata {
  retention_limit: number;
  retained_count: number;
  oldest_seq: number | null;
  newest_seq: number | null;
  dropped_before_seq: number | null;
  durable: boolean;
  basis: 'data_dir' | 'memory';
  source: 'platform-logs.json' | 'process_memory';
}

export interface PlatformLogsResponse {
  logs: PlatformLogEntry[];
  tail: number;
  order: 'chronological';
  retention: PlatformLogRetentionMetadata;
  limitations: string[];
}

// --- Qualified CMD signing (§ t57) ----------------------------------------------
//
// The two-phase Chave Móvel Digital signing flow (frozen `chancela-api::signature`
// DTOs, t57-S3). A Signing act's frozen PDF/A is turned into a CMD-signed PDF across two
// requests: `initiate` (phone + PIN → dispatches the SMS OTP) then
// `confirm` (session_id + OTP → the signed PDF). The PIN and OTP are transient secrets
// carried ONLY in the request body — never persisted or echoed back on any of these types.

/** The act's derived finalization status (server-owned). */
export const FINALIZATION_STATUSES = [
  'rascunho',
  'em_assinatura',
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
  /** Additive provider metadata; absent on older servers. */
  provider_id?: string;
  family?: string;
  activation_hint?: string;
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

export interface LocalTechnicalRenewalPlanEvidenceStatus {
  status: 'available' | 'not_applicable' | 'unavailable' | string;
  scope: string;
  notice: string;
  signature_timestamp_present: boolean;
  dss_revocation_evidence_present: boolean;
  dss_validation_time_present: boolean;
  doc_timestamp_present: boolean;
  doc_timestamp_imprints_valid: boolean;
  missing_inputs: string[];
  next_action: string;
  has_local_evidence_gap: boolean;
  all_local_planning_inputs_present: boolean;
  production_long_term_profile_claimed: boolean;
  legal_ltv_claimed: boolean;
}

export interface SignatureLocalRenewalPlanEvidenceStatus {
  index: number;
  object_id: string;
  signed_revision_len: number;
  vri_key_sha256: string;
  dss_vri_present: boolean;
  dss_vri_validation_time_present: boolean;
  local_technical_renewal_plan: LocalTechnicalRenewalPlanEvidenceStatus;
}

export interface MultiSignatureLocalRenewalPlanEvidenceStatus {
  status: 'available' | 'not_applicable' | 'unavailable' | string;
  scope: string;
  notice: string;
  signature_count: number;
  signatures: SignatureLocalRenewalPlanEvidenceStatus[];
  signatures_with_local_evidence_gaps: number[];
  next_action: string;
  has_local_evidence_gap: boolean;
  all_local_planning_inputs_present: boolean;
  production_long_term_profile_claimed: boolean;
  legal_ltv_claimed: boolean;
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
  local_technical_renewal_plan: LocalTechnicalRenewalPlanEvidenceStatus;
  multi_signature_local_renewal_plan: MultiSignatureLocalRenewalPlanEvidenceStatus;
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

// --- Visible-seal appearance (§ t67-e9 / e12) -----------------------------------
//
// The optional visible-seal appearance carried by a sign request (mirrors the backend
// `chancela-api::signature::SealAppearanceRequest`). Absent, or with `invisible` at its `true`
// default, keeps the backward-compatible invisible signature widget. When `invisible` is `false`
// the geometry (`page`/`x`/`y`/`w`/`h`) and exactly ONE content source (`template` OR
// `image_base64` + `image_format`) place a real seal. The coordinate convention is frozen: `page`
// is 0-based; units are PDF points; the origin is the page's bottom-left with `y` increasing UP;
// `x`/`y` are the seal rectangle's LOWER-LEFT corner; `w`/`h` are its size (both > 0). The visual
// seal designer (`features/signing/seal-designer`) produces this shape from an on-screen box.

/** The raster format of a seal image (backend `SealImageFormatRequest`, lowercase on the wire). */
export type SealImageFormat = 'png' | 'jpeg';

/** The decoded-byte cap the server enforces on a seal image (mirrors `SEAL_IMAGE_MAX_BYTES`). */
export const SEAL_IMAGE_MAX_BYTES = 2 * 1024 * 1024;

/**
 * A predefined text-seal template (backend `SealTemplateRequest`, serde tag `kind`, snake_case).
 * The caller supplies the exact strings to draw — nothing is inferred server-side.
 */
export type SealTemplateBody =
  | { kind: 'name_date'; name: string; date: string }
  | { kind: 'signed_by'; heading: string; name: string; date: string };

/**
 * Optional visible-seal appearance on a sign request. `template` and `image_base64` are mutually
 * exclusive; `image_format` is required with `image_base64`. All fields default server-side, so a
 * bare `{ invisible: false, ... }` visible spec, or an omitted `seal`, are both valid.
 */
export interface SealAppearanceBody {
  invisible?: boolean;
  /** 0-based target page index. */
  page?: number;
  /** Lower-left `x` in PDF points (origin bottom-left). */
  x?: number;
  /** Lower-left `y` in PDF points (origin bottom-left, y-up). */
  y?: number;
  /** Seal width in points (> 0 when visible). */
  w?: number;
  /** Seal height in points (> 0 when visible). */
  h?: number;
  template?: SealTemplateBody;
  /** Base64-encoded raster image; mutually exclusive with `template`; needs `image_format`. */
  image_base64?: string;
  image_format?: SealImageFormat;
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
  /** Optional visible-seal appearance (t67-e12); baked into the prepared PAdES revision. */
  seal?: SealAppearanceBody;
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

// --- Qualified Cartão de Cidadão signing (§ t58 / t67, desktop / co-located) ------
//
// The SYNCHRONOUS smartcard signing flow (frozen `chancela-api::signature::cc` DTOs,
// t58-e2, extended by t67-e8). A sealed act's unsigned PDF/A is turned into a **qualified**
// Cartão de Cidadão signed PDF in a single request: `POST /v1/acts/{id}/signature/cc/sign`.
// CC signing only works on the desktop where the API process is co-located with the card
// reader; a remote/browser server refuses with 409. The optional `pin` is a **co-location-
// gated** transient in-app PIN: when present it is threaded once to the card login (one
// in-app entry replaces the reader dialog); when absent the classic protected-authentication
// path runs and the PIN is entered at the reader. The PIN rides ONLY in this request body —
// never persisted, echoed, or logged. The response REUSES the CMD `CmdConfirmResult` shape
// (only `family` differs: `"CartaoDeCidadao"`), so no new web-asserted contract type appears.

/**
 * `POST /v1/acts/{id}/signature/cc/sign` — the whole CC signing request body. `capacity` records
 * the signatory's stated capacity; `actor` an explicit actor override; `pin` the optional transient
 * in-app PIN (co-location-gated). None are required.
 */
export interface CcSignBody {
  capacity?: string;
  actor?: string;
  /**
   * Optional transient in-app Cartão de Cidadão PIN (co-location-gated). Sent once and never stored
   * client-side beyond this request — no localStorage/sessionStorage/URL/query-cache. Absent ⇒ the
   * PIN is entered at the reader (protected authentication).
   */
  pin?: string;
  /** Optional visible-seal appearance (t67-e12); baked into the signed PAdES revision. */
  seal?: SealAppearanceBody;
}

/** The CC sign response — the produced qualified signature's metadata (same shape as CMD). */
export type CcSignResult = CmdConfirmResult;

// --- In-app Cartão de Cidadão batch signing (§ t67, desktop / co-located) ---------
//
// `POST /v1/signature/cc/batch-sign` signs a set of already-sealed acts with the Cartão de
// Cidadão under ONE signer authentication where the card allows it (frozen
// `chancela-api::batch_signing` DTOs, t67-e8). The optional `pin` is a transient in-app PIN,
// co-location-gated exactly like the single CC path: present ⇒ one PIN covers the whole batch
// (`auth_mode: "single_auth"`); absent ⇒ the reader prompts per document (`"per_document_auth"`).
// The batch NEVER claims a single PIN when the signer will be prompted per document. The PIN rides
// ONLY in this request body; the response and every per-document result are PIN-free, and one
// document's failure never aborts the batch.

/** Upper bound the server accepts for a single CC batch (mirrors `MAX_CC_BATCH_ACTS`). */
export const MAX_CC_BATCH_ACTS = 200;

/** How many times the signer authenticated to cover a batch. Never overstated by the server. */
export type CcBatchAuthMode = 'single_auth' | 'per_document_auth';

/**
 * `POST /v1/signature/cc/batch-sign` body. `pin` is the optional transient in-app PIN — sent once,
 * never stored client-side beyond this request (no localStorage/sessionStorage/URL/query-cache).
 */
export interface CcBatchSignBody {
  act_ids: string[];
  capacity?: string;
  pin?: string;
  actor?: string;
}

/**
 * Declared signer-capacity evidence preserved with a batch. Request/operator evidence only — no
 * SCAP or authority verification. Mirrors `chancela-api::signature::SignerCapacityEvidence`.
 */
export interface SignerCapacityEvidence {
  requested_provider_capacity: string;
  source: string;
  verification_status: string;
  verification_source: string | null;
  verified_at: string | null;
  authority_reference: string | null;
  status_scope: string;
}

/** One document's outcome in a batch: the produced signature facts (success) or a PIN-free error. */
export interface CcBatchDocResult {
  act_id: string;
  status: 'signed' | 'error';
  document_id?: string;
  signed_pdf_digest?: string;
  signed_at?: string;
  timestamp_token?: boolean;
  error?: string;
}

/** The batch response — honest authentication accounting plus every per-document outcome. No PIN. */
export interface CcBatchSignResponse {
  family: string;
  auth_mode: CcBatchAuthMode;
  auth_events: number;
  trusted_list_status: string | null;
  requested: number;
  signed: number;
  failed: number;
  signer_capacity_evidence?: SignerCapacityEvidence;
  results: CcBatchDocResult[];
}

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
  /** Optional visible-seal appearance (t67-e12); baked into the signed PAdES revision. */
  seal?: SealAppearanceBody;
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

// --- Official Autenticação.gov handoff import -----------------------------------

export const OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS = [
  'official_import_preserves_uploaded_signed_pdf_as_technical_evidence',
  'official_import_trust_validation_not_performed',
  'official_import_qualified_status_not_claimed',
  'official_import_legal_status_not_claimed',
  'official_import_no_secret_factor_collected',
] as const;
export type OfficialSignatureImportGuardrail =
  (typeof OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS)[number];

/**
 * `POST /v1/acts/{id}/signature/official/import` — user-mediated import of a PDF already
 * signed through Autenticação.gov / official provider handoff. The PDF bytes are stored as
 * technical evidence only; provider/source/filename are client-declared trace context, never
 * authority for trust-list, qualified-status, or legal-completion claims.
 */
export interface OfficialSignatureImportBody {
  signed_pdf_base64: string;
  provider?: string;
  source?: string;
  filename?: string;
  acknowledged_guardrail_ids: OfficialSignatureImportGuardrail[];
}

export interface OfficialSignatureLegalValidation {
  pades_valid: boolean;
  byte_range_covers_whole_file: boolean;
  sealed_pdf_prefix_match: boolean;
  trust_validation: string;
  trust_validation_performed: boolean;
  qualified_status_claimed: boolean;
  legal_status_claimed: boolean;
}

/** Technical evidence response for an official handoff import; no qualified/legal claim. */
export interface OfficialSignatureImportResult {
  document_id: string;
  act_id: string;
  family: string;
  evidentiary_level: string;
  trusted_list_status: string | null;
  legal_validation: OfficialSignatureLegalValidation;
  signing_time: string;
  signed_at: string;
  signed_pdf_digest: string;
  timestamp_token: boolean;
  finalization: FinalizationStatus;
  qualification_claimed: boolean;
  client_metadata_authoritative: boolean;
  guardrail_ids: OfficialSignatureImportGuardrail[];
  acknowledged_guardrail_ids: OfficialSignatureImportGuardrail[];
  acknowledgement_notice: string;
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

// --- Local technical XAdES / ASiC signing tools (§ t67-e10/e13) -----------------
//
// The signing-format selector routes to three local technical tools distinct from the act-signing
// lanes above: `POST /v1/signature/xades/sign` and `POST /v1/signature/asic/sign` take a transient
// co-located PKCS#12 signer + content and RETURN a document (never persisted, never changing act
// state). Honest scope: local technical evidence — no trusted-list, qualified-signature, or legal
// claim. Both are co-location-gated (409 when the API is not co-located with the private key); only
// levels B and T are accepted (LT/LTA are rejected by the backend), which the UI reflects honestly.

/** Shared co-located PKCS#12 signer material. Transient: never persisted client-side. */
export interface Pkcs12SignerMaterial {
  pkcs12_base64: string;
  passphrase: string;
  friendly_name?: string;
}

/** The tagged software-certificate signer for the XAdES/SCAP sign bodies. */
export type SoftPkcs12Signer = { kind: 'soft_pkcs12' } & Pkcs12SignerMaterial;

/** XAdES packaging: `detached` (hash content by URI) or `enveloping` (embed as `<ds:Object>`). */
export type XadesPackaging = 'detached' | 'enveloping';

/**
 * The level the local XAdES/ASiC endpoints accept. Only `B` and `T` are wired; `LT`/`LTA` are
 * rejected by the backend, so they are never sent — the selector reflects this honestly.
 */
export type LocalSignatureLevel = 'B' | 'T';

/** `POST /v1/signature/xades/sign` body. The produced XML is returned to the caller only. */
export interface XadesSignBody {
  content_base64: string;
  content_name?: string;
  packaging?: XadesPackaging;
  level?: LocalSignatureLevel;
  signer: SoftPkcs12Signer;
}

/** `POST /v1/signature/xades/sign` response — the produced XAdES + honest technical scope. */
export interface XadesSignResponse {
  report_kind: string;
  scope: string;
  legal_notice: string;
  xades_base64: string;
  xades_sha256: string;
  level: string;
  packaging: string;
  content_sha256: string;
  signer_cert_subject: string | null;
  signer_cert_sha256: string;
  signature_algorithm: string;
}

/** The ASiC container form. */
export type AsicContainer = 'asic_s_xades' | 'asic_e_multi';

/** The role an ASiC-E signer plays (ignored for ASiC-S, which is always XAdES). */
export type AsicSignerRole = 'cades' | 'xades';

/** A payload member of an ASiC container. */
export interface AsicPayloadBody {
  name: string;
  content_base64: string;
  mime_type?: string;
}

/** A co-located software-certificate ASiC signer. */
export interface AsicSignerBody extends Pkcs12SignerMaterial {
  role?: AsicSignerRole;
}

/** `POST /v1/signature/asic/sign` body. The produced container is returned to the caller only. */
export interface AsicSignBody {
  container: AsicContainer;
  payloads: AsicPayloadBody[];
  signers: AsicSignerBody[];
  xades_level?: LocalSignatureLevel;
  archive_timestamp?: boolean;
}

/** `POST /v1/signature/asic/sign` response — the produced container + honest technical scope. */
export interface AsicSignResponse {
  report_kind: string;
  scope: string;
  legal_notice: string;
  asic_base64: string;
  asic_sha256: string;
  container: string;
  xades_level: string;
  payload_count: number;
  cades_signature_count: number;
  xades_signature_count: number;
  archive_timestamp: boolean;
}

// --- SCAP professional-attribute signing (§ t67-e10/e13) ------------------------
//
// The AMA SCAP surface: list attribute providers, fetch a citizen's professional attributes, and
// attach a selected attribute at signing time (a co-located PKCS#12 produces a CAdES attribute-
// qualified signature over content). The HONESTY invariant is load-bearing: the default `preprod`
// transport is the offline mock, which can ONLY report a DECLARED capacity — `verified` is always
// `false` and `verification_status` is `declared_capacity_by_provider`. A `verified_by_scap` status
// is reachable ONLY through the real `prod` transport on a live Granted decision. The UI must NEVER
// render a declared/mock attribute as verified — it keys the label strictly off `verification.verified`.

/** The SCAP transport/environment. `preprod` = offline mock (declared-only); `prod` = real AMA. */
export type ScapEnvironment = 'preprod' | 'prod';

/** `POST /v1/scap/providers` body. */
export interface ScapProvidersBody {
  environment?: ScapEnvironment;
}

/** One attribute provider SCAP knows about. */
export interface AttributeProviderView {
  id: string;
  name: string;
  attribute_names: string[];
}

/** `POST /v1/scap/providers` response. */
export interface ScapProvidersResponse {
  report_kind: string;
  environment: string;
  transport: string;
  providers: AttributeProviderView[];
}

/** `POST /v1/scap/attributes` body. */
export interface ScapAttributesBody {
  citizen_id: string;
  full_name?: string;
  environment?: ScapEnvironment;
}

/** A sub-attribute (name/value pair) of a professional attribute. */
export interface ScapSubAttributeView {
  name: string;
  value: string;
}

/** A professional attribute SCAP reports for a citizen. */
export interface ProfessionalAttributeView {
  provider_id: string;
  provider_name: string;
  name: string;
  valid_from: string | null;
  valid_until: string | null;
  sub_attributes: ScapSubAttributeView[];
}

/** `POST /v1/scap/attributes` response. */
export interface ScapAttributesResponse {
  report_kind: string;
  environment: string;
  transport: string;
  citizen_id: string;
  attributes: ProfessionalAttributeView[];
}

/** `POST /v1/scap/sign` body — attach a reported attribute and produce a CAdES signature. */
export interface ScapSignBody {
  citizen_id: string;
  full_name?: string;
  provider_id: string;
  attribute_name: string;
  content_base64: string;
  signer: SoftPkcs12Signer;
  environment?: ScapEnvironment;
}

/**
 * The honesty status of a SCAP capacity claim. `verified` is `true` ONLY on a real Granted SCAP
 * verification; the mock/declared path always reports `false` with `verification_status`
 * `declared_capacity_by_provider` and `status_scope` `declared_capacity_evidence_only`.
 */
export interface ScapVerification {
  verified: boolean;
  verification_status: string;
  status_scope: string;
  attribute_name: string;
  provider_id: string;
}

/** `POST /v1/scap/sign` response — the CAdES signature + honest capacity status. */
export interface ScapSignResponse {
  report_kind: string;
  environment: string;
  transport: string;
  legal_notice: string;
  verification: ScapVerification;
  content_sha256: string;
  signature_base64: string;
  signature_sha256: string;
  signer_cert_subject: string | null;
  signer_cert_sha256: string;
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
 * `manifest` is local-only readiness/capability metadata; provider listing does not contact the
 * live provider, validate trust lists, determine qualified status, or assert legal validity.
 */
export interface SignatureProviderView {
  id: string;
  family: string;
  label: string;
  evidentiary_level: string;
  configured: boolean;
  manifest?: SignatureProviderManifest;
}

export interface SignatureProviderManifest {
  readiness: SignatureProviderReadiness;
  capabilities: SignatureProviderCapabilities;
  boundaries: SignatureProviderBoundaries;
  evidence_basis: string[];
}

export interface SignatureProviderReadiness {
  configured: boolean;
  environment: string | null;
  sandbox: boolean | null;
  production_blocked: boolean;
  missing_local_config: string[];
  authorization_mode: string | null;
}

export interface SignatureProviderCapabilities {
  remote_single_initiate_confirm: boolean;
  remote_batch_repeated_per_document_initiate: boolean;
  provider_native_batch_claimed: false;
  single_otp_pin_sad_batch_claimed: false;
}

export interface SignatureProviderBoundaries {
  live_provider_checked: false;
  provider_approval_claimed: false;
  legal_validity_claimed: false;
  qualified_status_determined_at_listing: false;
  trust_list_validation_performed_at_listing: false;
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
  /** Optional visible-seal appearance (t67-e12); baked into the prepared PAdES revision. */
  seal?: SealAppearanceBody;
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

// --- Repeated remote-session batch initiate ------------------------------------
//
// `POST /v1/signature/remote/{provider}/batch-initiate` opens one independent
// pending remote signing session per valid act. This is not a provider-native multi-document
// authorization seam: each pending row returns its own `session_id`, activation hint and expiry,
// and must be confirmed through the normal single-document remote confirm endpoint. The
// credential is a transient request input only and is never echoed by these response types.

/** Upper bound the server accepts for a repeated remote-session initiate batch. */
export const MAX_REMOTE_BATCH_ACTS = 200;

/** The remote batch seam always reports one activation per document. */
export type RemoteBatchAuthMode = 'per_document_activation';

/** One requested act either has a pending session or a redacted per-document error. */
export type RemoteBatchInitiateResultStatus = 'pending' | 'error';

/**
 * `POST /v1/signature/remote/{provider}/batch-initiate` body. `user_ref` is the non-secret
 * account reference at the provider; `credential` is transient and must not be persisted.
 */
export interface RemoteBatchInitiateBody {
  act_ids: string[];
  user_ref: string;
  credential?: string;
  capacity?: string;
  actor?: string;
  /** Optional visible-seal appearance; baked independently into each prepared PAdES revision. */
  seal?: SealAppearanceBody;
}

/** One per-act outcome from repeated remote-session initiate. Pending rows carry no secret. */
export interface RemoteBatchInitiateResult {
  act_id: string;
  status: RemoteBatchInitiateResultStatus;
  session_id?: string;
  provider_id?: string;
  family?: string;
  pending_status?: 'activation_pending';
  activation_hint?: string;
  expires_at?: string;
  error?: string;
}

/** Summary and ordered per-act results for repeated remote-session initiate. */
export interface RemoteBatchInitiateResponse {
  provider_id: string;
  family: string;
  evidentiary_level: string;
  auth_mode: RemoteBatchAuthMode;
  requested: number;
  pending: number;
  failed: number;
  initiate_events: number;
  results: RemoteBatchInitiateResult[];
}

// --- External signer invitation tracking ---------------------------------------

export type ExternalSignerInviteStatus =
  'pending' | 'accepted' | 'declined' | 'expired' | 'revoked';
export type ExternalSignerInviteDecision = 'accept' | 'decline';

export interface CreateExternalSignerInviteBody {
  recipient_name: string;
  recipient_email: string;
  provider_hint?: string;
  external_envelope_id?: string;
  external_slot_id?: string;
  expires_at: string;
  purpose: string;
  actor?: string;
}

export type ExternalSigningOrderPolicy = 'parallel' | 'sequential';
export type ExternalSignerIdentityRequirement =
  | 'contact_control'
  | 'provider_identity_assertion'
  | 'government_id_check'
  | 'representative_capacity';
export type ExternalSignerSlotStatus =
  'pending' | 'initiated' | 'signed' | 'declined' | 'revoked' | 'expired';

export interface CreateExternalSigningEnvelopeSlotBody {
  signer_label: string;
  contact_hint?: string;
  identity_requirements?: ExternalSignerIdentityRequirement[];
  required?: boolean;
}

export interface CreateExternalSigningEnvelopeBody {
  order_policy?: ExternalSigningOrderPolicy;
  slots: CreateExternalSigningEnvelopeSlotBody[];
  actor?: string;
}

export interface UpdateExternalSigningEnvelopeEvidenceBody {
  label: string;
  reference: string;
  identity_requirement?: ExternalSignerIdentityRequirement;
  digest?: string;
}

export interface UpdateExternalSigningEnvelopeSlotBody {
  id: string;
  status: ExternalSignerSlotStatus;
  evidence?: UpdateExternalSigningEnvelopeEvidenceBody[];
}

export interface UpdateExternalSigningEnvelopeBody {
  slots?: UpdateExternalSigningEnvelopeSlotBody[];
  complete?: boolean;
  actor?: string;
}

export interface ExternalSigningEnvelopeEvidenceView {
  label: string;
  reference: string;
  identity_requirement?: ExternalSignerIdentityRequirement;
  digest?: string;
}

export interface ExternalSigningEnvelopeSlotView {
  id: string;
  signer_label: string;
  contact_hint?: string;
  identity_requirements?: ExternalSignerIdentityRequirement[];
  required: boolean;
  status: ExternalSignerSlotStatus;
  evidence: ExternalSigningEnvelopeEvidenceView[];
}

export interface ExternalSigningEnvelopeCompletionSummaryView {
  completed: boolean;
  required_slot_count: number;
  signed_required_slot_count: number;
  blocking_required_slot_ids: string[];
}

export interface ExternalSigningEnvelopeView {
  id: string;
  act_id: string;
  order_policy: ExternalSigningOrderPolicy;
  slots: ExternalSigningEnvelopeSlotView[];
  completed: boolean;
  completion: ExternalSigningEnvelopeCompletionSummaryView;
  notice: string;
}

export interface ExternalSignerInviteEnvelopeView {
  id: string;
  slot_id: string;
  order_policy?: ExternalSigningOrderPolicy;
  slot_status?: ExternalSignerSlotStatus;
  technical_upload_auto_sign?: ExternalSignerInviteEnvelopeAutoSignView;
}

export interface ExternalSignerInviteEnvelopeAutoSignView {
  status: 'blocked' | string;
  reason: string;
}

export interface ExternalSignerInviteRespondOptions {
  signed_pdf_base64?: string;
  filename?: string;
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
  external_envelope?: ExternalSignerInviteEnvelopeView;
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

export interface ExternalSignerInviteSignedArtifactPublicView {
  family: string;
  evidentiary_level: string;
  signed_pdf_digest: string;
  timestamp_token: boolean;
  status_scope: string;
  qualification_claimed: boolean;
  legal_status_claimed: boolean;
  notice: string;
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
  external_envelope?: ExternalSignerInviteEnvelopeView;
  created_at: string;
  expires_at: string;
  responded_at?: string;
  signed_artifact?: ExternalSignerInviteSignedArtifactPublicView;
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

/** Transport security for the outbound SMTP session (t23). `starttls` is the default; `none` is
 *  only accepted by the backend alongside an explicit `allow_insecure` acknowledgement. */
export const SMTP_ENCRYPTIONS = ['starttls', 'implicit_tls', 'none'] as const;
export type SmtpEncryption = (typeof SMTP_ENCRYPTIONS)[number];

/** Outbound email (SMTP) relay configuration (t23).
 *
 *  NOTE the absence of a password field: it is deliberate and load-bearing. The relay password is
 *  write-only, stored AEAD-encrypted server-side, and is never part of the settings document in
 *  either direction. It is set through `PUT /v1/settings/email/password` and observed only as
 *  `EmailStatusView.password_configured`. */
export interface EmailSettings {
  enabled: boolean;
  host: string | null;
  port: number;
  encryption: SmtpEncryption;
  username: string | null;
  from_address: string | null;
  from_name: string | null;
  /** Name announced in EHLO; null falls back to the `from_address` domain. */
  helo_name: string | null;
  /** Explicit operator acknowledgement that `encryption: 'none'` sends credentials in the clear.
   *  The backend rejects the combination without it. */
  allow_insecure: boolean;
}

/** `GET /v1/settings/email/status` — metadata only; by construction it cannot carry the password. */
export interface EmailStatusView {
  password_configured: boolean;
  deliverable: boolean;
  encrypted: boolean;
  warnings: string[];
}

/** Where an SMTP session failed. Distinct stages point at distinct fixes (t23). */
export const SMTP_STAGES = [
  'connect',
  'tls',
  'greeting',
  'ehlo',
  'starttls',
  'auth',
  'mail_from',
  'rcpt_to',
  'data',
  'quit',
] as const;
export type SmtpStage = (typeof SMTP_STAGES)[number];

/** What kind of SMTP failure it was (t23). */
export const SMTP_FAILURE_KINDS = [
  'dns',
  'unreachable',
  'tls',
  'tls_unsupported',
  'timeout',
  'rejected',
  'protocol',
  'configuration',
] as const;
export type SmtpFailureKind = (typeof SMTP_FAILURE_KINDS)[number];

/** A structured SMTP failure carrying the relay's real reply, so the UI can show `535 5.7.8 …`
 *  rather than a generic "could not send". */
export interface SmtpFailure {
  stage: SmtpStage;
  kind: SmtpFailureKind;
  /** The SMTP reply code, when the relay actually answered. */
  code?: number;
  /** The RFC 3463 enhanced status code, when the reply carried one. */
  enhanced_code?: string;
  /** The relay's reply text verbatim, or the OS/TLS error when it never replied. */
  detail: string;
  /** Whether the session was already inside TLS when it failed. */
  tls: boolean;
}

/** How one protocol stage ended (t70). `refused` is the client declining — an unimplemented AUTH
 *  mechanism, a STARTTLS downgrade, an address needing SMTPUTF8 — and is deliberately distinct from
 *  `failed`, because nothing is wrong with the relay and the fix is on this side. */
export const SMTP_STEP_OUTCOMES = ['ok', 'failed', 'skipped', 'refused'] as const;
export type SmtpStepOutcome = (typeof SMTP_STEP_OUTCOMES)[number];

/** One stage of the session, with the relay's own reply and its duration (t70).
 *
 *  Timing is per stage on purpose: a relay that refuses in 3ms and one that swallows the connection
 *  for 20s are different problems, and a single "failed" hides that. */
export interface SmtpTraceStep {
  stage: SmtpStage;
  outcome: SmtpStepOutcome;
  /** The relay's SMTP reply code for this stage, when it answered. */
  code?: number;
  /** The RFC 3463 enhanced status code, when the reply carried one. */
  enhanced_code?: string;
  /** The relay's reply text verbatim, or — for `skipped`/`refused` — the client's own reason. */
  detail?: string;
  /** Milliseconds from the start of the session to the moment this stage began. */
  started_ms: number;
  /** How long the stage took. */
  duration_ms: number;
}

/** What the TLS handshake negotiated (t70). Present only when a handshake succeeded.
 *
 *  "Is it encrypted?" is a yes/no already visible elsewhere; *which* protocol version and *whose*
 *  certificate is what distinguishes a working relay from one quietly serving a self-signed
 *  certificate or an interception box. */
export interface SmtpTlsDetail {
  protocol?: string;
  cipher_suite?: string;
  peer_subject?: string;
  peer_issuer?: string;
}

/** One line of the conversation (t70). Client lines carrying credentials are placeholders, never
 *  the real line — see `SmtpTrace`. */
export interface SmtpTranscriptLine {
  direction: 'client' | 'server';
  text: string;
  at_ms: number;
}

/** The full diagnostic record of one SMTP session (t70) — enough to debug a relay without server
 *  access, which is the normal situation for a self-hosted deployment.
 *
 *  **It never contains the relay password.** Two independent server-side mechanisms guarantee that:
 *  credential-bearing lines are recorded as fixed placeholders rather than reaching the recorder at
 *  all, and every stored line is additionally scrubbed of the password and its base64 encodings for
 *  the pathological case of a relay echoing the credential back in its own reply. */
export interface SmtpTrace {
  host: string;
  port: number;
  /** The peer address the connection actually landed on — a hostname resolving somewhere
   *  unexpected is invisible otherwise. */
  resolved_address?: string;
  encryption: SmtpEncryption;
  helo_name: string;
  /** Whether TLS was *actually* established, as observed — not what the configuration asked for. */
  tls_established: boolean;
  tls?: SmtpTlsDetail;
  /** The extensions the relay advertised in EHLO, verbatim. "Offered no AUTH" and "offered only
   *  CRAM-MD5" are different problems with the same symptom. */
  advertised_capabilities: string[];
  /** The AUTH mechanism chosen, e.g. `PLAIN`. Absent when no authentication ran. */
  auth_mechanism?: string;
  steps: SmtpTraceStep[];
  transcript: SmtpTranscriptLine[];
  total_ms: number;
}

/** `POST /v1/settings/email/test` — a relay rejection is a 200 with `ok: false`, not an HTTP error. */
export interface EmailTestResult {
  ok: boolean;
  tls: boolean;
  authenticated: boolean;
  accepted_detail?: string;
  failure?: SmtpFailure;
  /** The full protocol trace (t70). Present on success as well as failure: a send that works but
   *  runs unencrypted, or takes 19 seconds, is worth seeing. */
  trace: SmtpTrace;
}

/** Tenant-level gate for AI features and the MCP surface. Defaults disabled. */
export interface AiSettings {
  enabled: boolean;
}

/**
 * Connector outbound-egress allowlist (t21) — a containment boundary, not a preference.
 *
 * Entries are exact hostnames or IP/CIDR ranges; no scheme, port, path, or wildcard. When the
 * deployment sets `CHANCELA_CONNECTOR_ALLOWED_HOSTS` that list is a ceiling this one can only
 * narrow. An empty list means "no runtime allowlist" — it never means "allow everything".
 */
export interface ConnectorSettings {
  allowed_hosts: string[];
  /** Read-only mirror of the deployment ceiling, stamped by the server on GET. */
  environment_ceiling?: string[] | null;
}

export interface Settings {
  schema_version: number;
  organization: OrganizationSettings;
  documents: DocumentSettings;
  catalog: CatalogSettings;
  signing: SigningSettings;
  platform: PlatformSettings;
  registry_auto_update: RegistryAutoUpdateSettings;
  workflow: WorkflowSettings;
  data_management: DataManagementSettings;
  connectors: ConnectorSettings;
  appearance: AppearanceSettings;
  ui: UiSettings;
  onboarding: OnboardingSettings;
  ai: AiSettings;
  email: EmailSettings;
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
        note: 'No CSC/QTSP provider is configured in protected storage or environment.',
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
    public_base_url: null,
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
  workflow: {
    reminders: {
      enabled: true,
      dashboard_limit: 5,
      due_soon_days: 45,
      attendance_lookahead_days: 45,
      sources: {
        profile_calendar: true,
        act_follow_ups: true,
        attendance_hygiene: true,
        privacy_control_reviews: true,
      },
    },
  },
  data_management: {
    retained_export_cleanup: {
      minimum_age_days: 30,
      keep_latest: 5,
    },
    backup_recovery: {
      max_drill_age_days: 90,
      target_rpo_minutes: 24 * 60,
      target_rto_minutes: 4 * 60,
    },
    // Absent by default: the interlock stays closed until an operator declares the shared mount.
  },
  connectors: { allowed_hosts: [] },
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
  // Mirrors `EmailSettings::default()`: off, submission port, STARTTLS, nothing acknowledged.
  email: {
    enabled: false,
    host: null,
    port: 587,
    encryption: 'starttls',
    username: null,
    from_address: null,
    from_name: null,
    helo_name: null,
    allow_insecure: false,
  },
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

/** `POST /v1/ledger/recovery/restore/preflight` request. `passphrase` is transient. */
export interface RestorePreflightBody {
  archive: string;
  passphrase?: string;
  actor?: string;
}

/** Secret-free manifest summary returned by restore preflight. */
export interface RestorePreflightManifest {
  path: string;
  schema: number | string | null;
  version: number | string | null;
  app_version: string | null;
  store_schema_version: number | null;
  ledger_length: number;
  ledger_verified: boolean;
  member_count: number;
  sidecar_member_count: number;
  db_member_present: boolean;
  total_member_bytes: number;
}

/** Non-mutating restore readiness report. No archive hashes or key material are rendered. */
export interface RestorePreflightView {
  ok: boolean;
  ready: boolean;
  encrypted: boolean;
  archive: string;
  manifest: RestorePreflightManifest;
  ledger_verified: boolean;
  findings: string[];
  errors: string[];
  next_step: string;
}

/** `POST /v1/ledger/recovery/restore` response — whole-store restore outcome. */
export interface RestoreOutcomeView {
  restored_from: string;
  ledger_length: number;
  ledger_head: string | null;
  chain_verified: boolean;
  integrity: IntegrityReportView;
}

/** Secret-free manifest evidence persisted in a non-destructive backup recovery drill receipt. */
export interface BackupRecoveryDrillManifestEvidence {
  schema: string;
  version: number;
  store_schema_version: number;
  ledger_length: number;
  ledger_verified: boolean;
  member_count: number;
  sidecar_member_count: number;
  db_member_present: boolean;
  total_member_bytes: number;
}

export type BackupRecoveryDrillIsolatedRestoreStatus = 'verified' | 'failed' | 'not_recorded';

/** Secret-free isolated snapshot verification evidence persisted with a recovery drill receipt. */
export interface BackupRecoveryDrillIsolatedRestoreVerification {
  status: BackupRecoveryDrillIsolatedRestoreStatus;
  db_snapshot_materialized: boolean;
  db_snapshot_opened: boolean;
  state_loaded: boolean;
  ledger_verified: boolean;
  cleanup_verified: boolean;
  entity_count: number;
  book_count: number;
  act_count: number;
  sidecar_root_count: number;
  sidecar_materialized_file_count: number;
  sidecar_materialized_bytes: number;
  sqlcipher_encryption_verified: boolean | null;
  findings: string[];
  errors: string[];
  next_step: string;
}

/** `POST /v1/backup/recovery-drills` request. `passphrase` is transient and never persisted. */
export interface BackupRecoveryDrillBody {
  archive: string;
  passphrase?: string;
  operator_notes?: string;
  custody_location?: string;
  restore_executed?: boolean;
  live_db_swapped?: boolean;
  sidecars_staged?: boolean;
  ledger_restored_appended?: boolean;
  data_deleted?: boolean;
  offsite_custody_proven?: boolean;
  legal_archive_certified?: boolean;
}

/** Bounded custody receipt for a preflight-only backup recovery drill. */
export interface BackupRecoveryDrillReceipt {
  id: string;
  created_at: string;
  archive: string;
  preflight_ok: boolean;
  preflight_ready: boolean;
  encrypted: boolean | null;
  ledger_verified: boolean;
  manifest: BackupRecoveryDrillManifestEvidence | null;
  isolated_restore_verified: boolean;
  isolated_restore_verification: BackupRecoveryDrillIsolatedRestoreVerification;
  operator_notes?: string;
  custody_location?: string;
  restore_executed: false;
  live_db_swapped: false;
  sidecars_staged: false;
  ledger_restored_appended: false;
  data_deleted: false;
  offsite_custody_proven: false;
  legal_archive_certified: false;
}

export type BackupRecoveryFreshnessStatus = 'no_receipt' | 'fresh' | 'stale' | 'failed';

export interface BackupRecoveryFreshnessReview {
  generated_at: string;
  policy: BackupRecoveryPolicySettings;
  status: BackupRecoveryFreshnessStatus;
  latest_receipt_id: string | null;
  latest_receipt_at: string | null;
  latest_receipt_age_days: number | null;
  latest_receipt_preflight_ready: boolean | null;
  latest_receipt_isolated_restore_verified: boolean | null;
  restore_performed: false;
  db_swap_performed: false;
  offsite_custody_verified: false;
  rpo_rto_certified: false;
  production_backup_policy_certified: false;
}

/** `GET /v1/backup/recovery-drills` response. */
export interface BackupRecoveryDrillList {
  receipts: BackupRecoveryDrillReceipt[];
  durable: boolean;
  max_receipts: number;
  freshness: BackupRecoveryFreshnessReview;
}

export type SyncHandoffReadinessStatus =
  'blocked' | 'missing_local_evidence' | 'local_review_ready';

/** Local-only readiness status for `GET /v1/sync/handoff-preflight`. */
export interface SyncHandoffReadiness {
  status: SyncHandoffReadinessStatus;
  local_handoff_review_ready: boolean;
  production_sync_ready: false;
  external_connector_ready: false;
  active_sync_performed: false;
}

export interface SyncHandoffDataStatus {
  data_dir_configured: boolean;
  durable_store_open: boolean;
  ledger_length: number;
  ledger_healthy: boolean;
  ledger_degraded: boolean;
  global_chain_verified: boolean;
  global_chain_first_break: string | null;
  boot_chain_status_ok: boolean | null;
}

export interface SyncHandoffBackupCandidateSummary {
  file_name: string;
  bytes: number;
  modified_at: string | null;
}

export interface SyncHandoffBackupDirectoryEvidence {
  relative_path: 'backups';
  scanned: boolean;
  present: boolean;
  untrusted_candidate_file_count: number;
  total_candidate_bytes: number;
  latest_candidate_file: SyncHandoffBackupCandidateSummary | null;
  validation_performed: false;
  validated_manifest_evidence_present: false;
  scan_error: string | null;
}

export interface SyncHandoffRecoveryDrillSummary {
  id: string;
  created_at: string;
  archive_label: string;
  preflight_ok: boolean;
  preflight_ready: boolean;
  encrypted: boolean | null;
  ledger_verified: boolean;
  manifest_evidence_present: boolean;
  manifest_ledger_verified: boolean | null;
  manifest_ledger_length: number | null;
  manifest_member_count: number | null;
  manifest_db_member_present: boolean | null;
  manifest_sidecar_member_count: number | null;
  manifest_total_member_bytes: number | null;
  isolated_restore_verified: boolean;
  isolated_restore_status: string;
  isolated_snapshot_ledger_verified: boolean;
  isolated_snapshot_cleanup_verified: boolean;
  verified_manifest_and_isolated_snapshot: boolean;
  restore_executed: false;
  live_db_swapped: false;
  sidecars_staged: false;
  ledger_restored_appended: false;
  data_deleted: false;
  offsite_custody_proven: false;
  legal_archive_certified: false;
}

export interface SyncHandoffBackupEvidence {
  backup_route: '/v1/backup';
  recovery_drill_route: '/v1/backup/recovery-drills';
  durable_receipts: boolean;
  backup_directory: SyncHandoffBackupDirectoryEvidence;
  recovery_drill_receipt_count: number;
  verified_recovery_drill_evidence: boolean;
  latest_recovery_drill: SyncHandoffRecoveryDrillSummary | null;
}

export interface SyncHandoffBookBundleEvidence {
  export_route: '/v1/books/{id}/export';
  import_preflight_route: '/v1/books/import/preflight';
  import_confirmation_route: '/v1/books/import';
  import_preflight_read_only: true;
  max_import_bundle_bytes: number;
  collision_policies: ['refuse', 'quarantine_copy'];
  durable_store_required: true;
  durable_store_available: boolean;
  retained_export_relative_path: 'exports';
  book_count: number;
  open_book_count: number;
  closed_book_count: number;
}

export interface SyncHandoffArchiveDglabEvidence {
  archive_package_route: '/v1/books/{id}/archive/package';
  local_dglab_manifest_route: '/v1/books/{id}/archive/local-dglab-interchange-manifest';
  local_dglab_manifest_read_only: true;
  local_dglab_manifest_route_available: boolean;
  book_count: number;
  closed_book_count: number;
  sealed_or_archived_act_count: number;
  preserved_document_count: number;
  signed_document_count: number;
  external_validator_report_metadata_count: number;
  dglab_certification_claimed: false;
  archive_certification_claimed: false;
}

export interface SyncHandoffNoClaims {
  active_sync_implemented: false;
  /** The connector protocol is implemented even though this preflight never executes it. */
  connector_protocol_implemented: true;
  background_job_configured: false;
  upload_or_download_performed: false;
  import_performed: false;
  records_mutated: false;
  production_sync_readiness_claimed: false;
  external_connector_compatibility_claimed: false;
  legal_validity_claimed: false;
  dglab_certification_claimed: false;
  archive_certification_claimed: false;
  signing_notarization_attestation_claimed: false;
  deployment_readiness_claimed: false;
}

/** Read-only local sync/handoff preflight report. No active sync or provider call is performed. */
export interface SyncHandoffPreflightReport {
  report_kind: 'sync_handoff_preflight';
  endpoint: '/v1/sync/handoff-preflight';
  generated_at: string;
  readiness: SyncHandoffReadiness;
  data_status: SyncHandoffDataStatus;
  backup: SyncHandoffBackupEvidence;
  book_bundles: SyncHandoffBookBundleEvidence;
  archive_dglab: SyncHandoffArchiveDglabEvidence;
  no_claims: SyncHandoffNoClaims;
  blockers: string[];
  missing_evidence: string[];
  operator_actions: string[];
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

/** `POST /v1/books/import/preflight` response — non-mutating preview with no import id. */
export interface BookImportPreflightView {
  ok: boolean;
  ready: boolean;
  would_import: boolean;
  would_record_ledger_event: false;
  would_store_import_record: false;
  policy: CollisionPolicy;
  entity_id: string | null;
  book_id: string | null;
  verdict: ImportVerdictView | null;
  source_instance_id: string | null;
  bundle_digest: string | null;
  collided: boolean;
  manifest_file_count: number | null;
  manifest_total_bytes: number | null;
  zip_member_count: number | null;
  event_count: number | null;
  book_chain_verified: boolean | null;
  book_chain_length: number | null;
  signature_present: boolean | null;
  errors: string[];
  findings: string[];
  next_step: string;
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

export interface PaperBookCanonicalConversionPreflightEvidence {
  ocr_text_present: boolean;
  ocr_text_digest: string | null;
  operator_review_recorded: boolean;
  candidate_digest_present: boolean;
  package_fixity_recorded: boolean;
  source_page_range_valid: boolean;
  source_page_range: PaperBookPageRange;
  page_range_reviewed: boolean;
  legal_acceptance_recorded: boolean;
}

export interface PaperBookCanonicalConversionPreflightBlocker {
  code: string;
  field: string;
  message: string;
}

export interface PaperBookCanonicalConversionPreflight {
  status: 'not_attempted' | 'blocked' | 'allowed' | string;
  preflight_requested: boolean;
  scope: string;
  evidence_source: string;
  evidence: PaperBookCanonicalConversionPreflightEvidence;
  blockers: PaperBookCanonicalConversionPreflightBlocker[];
  allowed_next_action: string | null;
  raw_ocr_text_in_report: boolean;
  canonical_act_created: boolean;
  canonical_document_created: boolean;
  signature_created: boolean;
  signing_requested: boolean;
  signature_validity_claimed: boolean;
  qualified_signature_claimed: boolean;
  legal_validity_claimed: boolean;
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
  canonical_conversion_preflight: PaperBookCanonicalConversionPreflight;
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
  canonical_conversion_preflight?: {
    ocr_text_present?: boolean;
    ocr_text_digest?: string | null;
    operator_review_recorded?: boolean;
    package_fixity_recorded?: boolean;
    page_range_reviewed?: boolean;
    legal_acceptance_recorded?: boolean;
  } | null;
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

export const PAPER_BOOK_OCR_DRAFT_REVIEW_STATUSES = [
  'unreviewed',
  'accepted',
  'rejected',
  'superseded',
] as const;
export type PaperBookOcrDraftReviewPatchStatus =
  (typeof PAPER_BOOK_OCR_DRAFT_REVIEW_STATUSES)[number];
export type PaperBookOcrDraftReviewStatus = PaperBookOcrDraftReviewPatchStatus | string;

export interface PaperBookOcrDraftPageSpanBody {
  start_page: number;
  end_page: number;
}

export interface PaperBookOcrDraftPageSpanView {
  start_page: number;
  end_page: number;
}

export interface PaperBookOcrDraftCreateBody {
  extracted_text?: string | null;
  text_digest?: string | null;
  page_spans: PaperBookOcrDraftPageSpanBody[];
  confidence?: number | null;
  engine_name: string;
  engine_version?: string | null;
}

export interface PaperBookOcrDraftReviewBody {
  review_status: PaperBookOcrDraftReviewPatchStatus;
  review_note?: string | null;
  superseded_by?: string | null;
}

export interface PaperBookOcrEngineView {
  name: string;
  version: string | null;
}

/** Non-authoritative OCR text/review aid linked to a preserved paper-book import. */
export interface PaperBookOcrDraftView {
  draft_id: string;
  import_id: string;
  extracted_text: string | null;
  text_digest: string | null;
  page_spans: PaperBookOcrDraftPageSpanView[];
  confidence: number | null;
  engine: PaperBookOcrEngineView;
  created_at: string;
  created_by: string;
  review_status: PaperBookOcrDraftReviewStatus;
  reviewed_at: string | null;
  reviewed_by: string | null;
  review_note: string | null;
  superseded_by: string | null;
  draft_notice: string;
  non_canonical: boolean;
  authoritative_text_claimed: boolean;
  canonical_minutes_claimed: boolean;
  canonical_act_created: boolean;
  canonical_document_created: boolean;
  signature_created: boolean;
  legal_validity_claimed: boolean;
  legal_notice: string;
}

/** Reviewed OCR conversion execution evidence bound to a mutable draft act only. */
export interface PaperBookOcrConversionExecutionArtifactView {
  artifact_id: string;
  import_id: string;
  draft_id: string;
  dossier_id: string | null;
  source_text_digest: string | null;
  source_page_spans: PaperBookOcrDraftPageSpanView[];
  source_review_status: PaperBookOcrDraftReviewStatus;
  source_reviewed_at: string | null;
  source_reviewed_by: string | null;
  target_act_id: string;
  target_act_state: 'Draft' | string;
  mutable_draft_act_created: boolean;
  created_at: string;
  created_by: string;
  artifact_notice: string;
  reviewed_conversion_execution_artifact: boolean;
  non_canonical: boolean;
  canonical_conversion_claimed: boolean;
  canonical_minutes_claimed: boolean;
  canonical_act_created: boolean;
  canonical_document_created: boolean;
  signed_document_created: boolean;
  archive_package_created: boolean;
  archive_certification_claimed: boolean;
  pdfa_created: boolean;
  pdfua_created: boolean;
  signature_created: boolean;
  seal_created: boolean;
  legal_validity_claimed: boolean;
  source_extracted_text_in_artifact: boolean;
  source_extracted_text_in_ledger_event: boolean;
  legal_notice: string;
}

/** `POST /v1/books/paper-import/{id}/ocr-drafts/{draft_id}/canonical-draft` result. */
export interface PaperBookOcrDraftCanonicalDraftResponse {
  import_id: string;
  draft_id: string;
  act: ActView;
  conversion_execution_artifact?: PaperBookOcrConversionExecutionArtifactView;
  draft_act_created: boolean;
  act_state: 'Draft' | string;
  notice: string;
  ocr_text_copied_to_deliberations: boolean;
  ocr_text_in_ledger_event: boolean;
  non_canonical: boolean;
  authoritative_text_claimed: boolean;
  canonical_conversion_claimed: boolean;
  canonical_minutes_claimed: boolean;
  canonical_act_created: boolean;
  canonical_document_created: boolean;
  signed_document_created: boolean;
  archive_package_created: boolean;
  archive_certification_claimed: boolean;
  pdfa_created: boolean;
  pdfua_created: boolean;
  signature_created: boolean;
  seal_created: boolean;
  legal_validity_claimed: boolean;
  legal_notice: string;
}

/** `POST /v1/books/paper-import/{id}/ocr-drafts/{draft_id}/conversion-dossier` result. */
export interface PaperBookOcrConversionDossierView {
  dossier_id: string;
  import_id: string;
  draft_id: string;
  conversion_execution_artifacts?: PaperBookOcrConversionExecutionArtifactView[];
  source_text_digest: string | null;
  source_page_spans: PaperBookOcrDraftPageSpanView[];
  source_review_status: PaperBookOcrDraftReviewStatus;
  source_reviewed_at: string | null;
  source_reviewed_by: string | null;
  created_at: string;
  created_by: string;
  dossier_notice: string;
  metadata_only: boolean;
  non_canonical: boolean;
  act_created: boolean;
  canonical_act_created: boolean;
  canonical_minutes_claimed: boolean;
  canonical_document_created: boolean;
  signed_document_created: boolean;
  archive_package_created: boolean;
  archive_certification_claimed?: boolean;
  pdfa_created: boolean;
  pdfua_created: boolean;
  signature_created: boolean;
  seal_created: boolean;
  legal_validity_claimed: boolean;
  source_extracted_text_in_response: boolean;
  source_extracted_text_in_ledger_event: boolean;
  legal_notice: string;
}

/** `POST /v1/books/paper-import/{id}/ocr/run` local OCR outcome. */
export interface PaperBookOcrRunView {
  import_id: string;
  previous_ocr_status: PaperBookOcrStatus;
  ocr_status: PaperBookOcrStatus;
  command_configured: boolean;
  command_exit_success: boolean;
  command_exit_code: number | null;
  timed_out: boolean;
  failure_reason: string | null;
  stdout_bytes_captured: number;
  stdout_truncated: boolean;
  engine: PaperBookOcrEngineView;
  draft: PaperBookOcrDraftView | null;
  status_notice: string;
  draft_notice: string;
  non_canonical: boolean;
  authoritative_text_claimed: boolean;
  canonical_minutes_claimed: boolean;
  canonical_act_created: boolean;
  canonical_document_created: boolean;
  signature_created: boolean;
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

export interface PaperBookOcrCanonicalRehearsalImportEvidence {
  import_present: boolean;
  preserved_package_present: boolean;
  book_ref: string;
  ocr_status: PaperBookOcrStatus;
  page_count: number;
  source_page_range: PaperBookPageRange;
  original_ata_number_range: PaperBookOriginalAtaNumberRange | null;
  package_digest_present: boolean;
  package_size_bytes: number;
  source_filename_present: boolean;
  bytes_in_report: boolean;
  non_canonical: boolean;
}

export interface PaperBookOcrCanonicalRehearsalConfidenceBuckets {
  known_count: number;
  unknown_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface PaperBookOcrCanonicalRehearsalOcrEvidence {
  draft_count: number;
  accepted_draft_count: number;
  unreviewed_draft_count: number;
  rejected_draft_count: number;
  superseded_draft_count: number;
  selected_accepted_draft_id: string | null;
  selected_accepted_draft_text_digest_present: boolean;
  selected_accepted_draft_extracted_text_present: boolean;
  selected_accepted_draft_page_span_count: number;
  selected_accepted_draft_page_span_pages: number;
  operator_review_recorded: boolean;
  raw_ocr_text_in_report: boolean;
  confidence_buckets: PaperBookOcrCanonicalRehearsalConfidenceBuckets;
}

export interface PaperBookOcrCanonicalRehearsalDossierEvidence {
  dossier_count: number;
  metadata_only_dossier_present: boolean;
  selected_dossier_id: string | null;
  selected_dossier_source_digest_present: boolean;
  selected_dossier_page_span_count: number;
  selected_dossier_page_span_pages: number;
  bound_execution_artifact_count: number;
  selected_bound_execution_artifact_count: number;
  mutable_draft_act_artifact_present: boolean;
  source_extracted_text_in_response: boolean;
  source_extracted_text_in_ledger_event: boolean;
}

export interface PaperBookOcrCanonicalRehearsalReadiness {
  status: 'blocked' | 'local_rehearsal_ready' | string;
  scope: 'local_rehearsal_only' | string;
  evidence_source: string;
  blockers: PaperBookCanonicalConversionPreflightBlocker[];
  next_local_action: string | null;
}

export interface PaperBookOcrCanonicalRehearsalNoClaims {
  records_mutated: boolean;
  external_ocr_called: boolean;
  external_validator_called: boolean;
  external_legal_service_called: boolean;
  canonical_conversion_claimed: boolean;
  ocr_accuracy_claimed: boolean;
  legal_review_claimed: boolean;
  legal_validity_claimed: boolean;
  canonical_minutes_claimed: boolean;
  canonical_act_created: boolean;
  canonical_document_created: boolean;
  sealed_document_created: boolean;
  signed_document_created: boolean;
  archive_package_created: boolean;
  archive_certification_claimed: boolean;
  pdfa_created: boolean;
  pdfa_certification_claimed: boolean;
  pdfua_created: boolean;
  pdfua_certification_claimed: boolean;
  signature_created: boolean;
  signing_requested: boolean;
  signature_validity_claimed: boolean;
  qualified_signature_claimed: boolean;
  dglab_certification_claimed: boolean;
  raw_ocr_text_in_report: boolean;
}

/** `GET /v1/books/paper-import/{id}/ocr-canonical-rehearsal` local report. */
export interface PaperBookOcrCanonicalRehearsalReport {
  report_kind: 'paper_book_ocr_canonical_rehearsal';
  dry_run: true;
  rehearsal_scope: 'local_ocr_canonical_conversion_rehearsal' | string;
  legal_notice: string;
  import_id: string;
  source_import: PaperBookOcrCanonicalRehearsalImportEvidence;
  ocr_evidence: PaperBookOcrCanonicalRehearsalOcrEvidence;
  dossier_evidence: PaperBookOcrCanonicalRehearsalDossierEvidence;
  readiness: PaperBookOcrCanonicalRehearsalReadiness;
  no_claims: PaperBookOcrCanonicalRehearsalNoClaims;
  required_operator_actions: string[];
  findings: PaperBookImportFinding[];
}

/** `POST /v1/books/{id}/start-over` request (forward-writing lifecycle op; reason + a
 *  fresh-book opening spec). Non-destructive: the old book is archived + chained. */
export interface StartOverBookBody {
  reason: string;
  purpose: string;
  opening_date: string;
  required_signatories: BookTermoSignatoryInput[];
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

export const DATA_DURABLE_BACKEND_FAMILIES = ['sqlite', 'postgres'] as const;
export type DataDurableBackendFamily = (typeof DATA_DURABLE_BACKEND_FAMILIES)[number];

export const DATA_SIDECAR_STORAGE_MODES = ['file', 'database', 'in_memory'] as const;
export type DataSidecarStorageMode = (typeof DATA_SIDECAR_STORAGE_MODES)[number];

export const DATA_DATABASE_FORMATS = [
  'missing',
  'plaintext_sqlite',
  'non_plaintext_or_encrypted',
] as const;
export type DataDatabaseFormat = (typeof DATA_DATABASE_FORMATS)[number];

export const DATA_KEY_CONFIG_STATUSES = ['unconfigured', 'empty', 'configured'] as const;
export type DataKeyConfigStatus = (typeof DATA_KEY_CONFIG_STATUSES)[number];

export const DATA_KEY_OPS_PLANS = [
  'create_plaintext_store',
  'open_plaintext_store',
  'key_required_for_non_plaintext_store',
  'reject_empty_key',
  'sqlcipher_build_required',
  'create_encrypted_store',
  'open_encrypted_store',
  'refuse_plaintext_to_encrypted_migration',
] as const;
export type DataKeyOpsPlan = (typeof DATA_KEY_OPS_PLANS)[number];

export type DataDatabaseEncryptionKeySource =
  | 'none'
  | 'operator_env'
  | 'operator_key_file'
  | 'programmatic'
  | 'hardware_derived_fallback'
  | string;

export interface DataHardwareDerivedFallbackStatus {
  available: boolean;
  selected: boolean;
  fail_closed_if_requested: boolean;
  status: string;
  message: string;
}

export interface DataKeyOpsMigrationStep {
  order: number;
  title: string;
  detail: string;
  source_destructive: boolean;
}

export interface DataKeyOpsMigrationEvidence {
  plan: DataKeyOpsPlan | string;
  database_format: DataDatabaseFormat | string;
  key_config: DataKeyConfigStatus | string;
  sqlcipher_available: boolean;
  database_file: string;
}

export interface DataKeyOpsMigrationPlan {
  required: boolean;
  status: string;
  summary: string;
  steps: DataKeyOpsMigrationStep[];
  evidence: DataKeyOpsMigrationEvidence;
}

export interface DataKeyOpsStatus {
  sqlcipher_available: boolean;
  key_config: DataKeyConfigStatus | string;
  database_file: string;
  database_format: DataDatabaseFormat | string;
  plan: DataKeyOpsPlan | string;
  migration_plan: DataKeyOpsMigrationPlan;
}

export interface DataDatabaseEncryptionStatus {
  configured: boolean;
  sqlcipher_available: boolean;
  sqlcipher_backed: boolean;
  key_source: DataDatabaseEncryptionKeySource;
  hardware_derived_fallback: DataHardwareDerivedFallbackStatus;
  database_format: DataDatabaseFormat | string | null;
  key_ops_plan: DataKeyOpsPlan | string | null;
  plaintext_migration_pending: boolean;
  plaintext_migration_blocked: boolean;
  key_ops: DataKeyOpsStatus | null;
  key_ops_error?: string;
}

/** How a usage row was measured. */
export const DATA_USAGE_BASES = [
  'filesystem',
  'logical_payload',
  'sidecar_logical_payload',
  'sqlite_logical_payload',
  'sqlite_file',
] as const;
export type DataUsageBasis = (typeof DATA_USAGE_BASES)[number];

export const DATA_PAYLOAD_ESTIMATE_METHODS = ['local_loaded_payload_estimate'] as const;
export type DataPayloadEstimateMethod = (typeof DATA_PAYLOAD_ESTIMATE_METHODS)[number];

export interface DataPersistenceStatus {
  mode: DataPersistenceMode;
  data_dir_configured: boolean;
  durable_store_open: boolean;
  active_backend_family: DataDurableBackendFamily | null;
  sidecar_storage_mode: DataSidecarStorageMode;
  database_encryption_configured: boolean;
  database_encryption: DataDatabaseEncryptionStatus;
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
  durable_store_open: DataPermissionCheck;
  sqlite_store_open: DataPermissionCheck;
}

export interface DataPayloadStats {
  table_name: string;
  estimated_payload_bytes: number;
  row_count: number;
  average_bytes_per_row: number | null;
  estimate_method: DataPayloadEstimateMethod;
  estimate_basis: DataUsageBasis;
}

export interface DataUsageConcern {
  id: string;
  kind?: string;
  label: string;
  bytes: number;
  basis: DataUsageBasis;
  exact: boolean;
  file_count: number;
  directory_count: number;
  row_count?: number;
  payload_stats?: DataPayloadStats;
  relative_roots: string[];
}

export interface DataUsageStatus {
  total_bytes: number;
  filesystem: DataUsageConcern[];
  logical_payload: DataUsageConcern[];
  sidecars: DataUsageConcern[];
  largest_payload_table?: DataPayloadStats;
  sqlite_logical: DataUsageConcern[];
  sqlite_largest_payload_table?: DataPayloadStats;
  scan_errors: string[];
}

export interface DataKeyRotationReceiptEvidence {
  operation: string;
  requested_key_config: string;
  sqlcipher_available: boolean;
  checkpointed_before_rekey: boolean;
  checkpointed_after_rekey: boolean;
  post_rekey_integrity_checked: boolean;
}

export interface DataKeyRotationReceiptNoClaims {
  current_key_persisted: boolean;
  replacement_key_persisted: boolean;
  key_fingerprint_persisted: boolean;
  database_path_persisted: boolean;
  sqlcipher_at_rest_certified: boolean;
  plaintext_migration_performed: boolean;
  legal_disposal_or_erasure_certified: boolean;
}

export interface DataKeyRotationReceipt {
  schema_version: number;
  receipt_id: string;
  rotated_at: string;
  actor_user_id: string | null;
  mode: string;
  status: DataKeyRotationExecutionStatus;
  backend_family: DataDurableBackendFamily | null;
  rekey_executed: boolean;
  ledger_integrity_verified: boolean;
  ledger_length: number;
  evidence: DataKeyRotationReceiptEvidence;
  no_claims: DataKeyRotationReceiptNoClaims;
}

export interface DataKeyRotationReceiptStatus {
  latest_receipt: DataKeyRotationReceipt | null;
  history: DataKeyRotationReceipt[];
  history_count: number;
  history_limit: number;
  read_error?: string;
}

/** Read-only storage, data-directory and usage telemetry for Settings → Dados. */
export interface DataStatusResponse {
  generated_at: string;
  persistence: DataPersistenceStatus;
  data_dir: DataDirStatus;
  permissions: DataPermissionStatus;
  usage: DataUsageStatus;
  key_rotation: DataKeyRotationReceiptStatus;
}

/** Bounded storage-maintenance targets under the configured data directory. */
export type DataCleanupTarget = 'crash' | 'exports' | 'platform_logs';

/** `POST /v1/data/cleanup` request for non-domain storage maintenance. */
export interface DataCleanupBody {
  target: DataCleanupTarget;
  dry_run?: boolean;
  minimum_age_days?: number;
  keep_latest?: number;
  preview_token?: string;
}

/** `POST /v1/data/cleanup` response. */
export interface DataCleanupResult {
  target: DataCleanupTarget;
  data_dir: string | null;
  dry_run: boolean;
  preview_token?: string;
  deleted_bytes: number;
  deleted_files: number;
  deleted_directories: number;
  would_delete_bytes: number;
  would_delete_files: number;
  would_delete_directories: number;
  skipped: string[];
}

/** `POST /v1/data/key-rotation/preflight` request. Key material is transient. */
export interface DataKeyRotationPreflightBody {
  current_key?: string;
  new_key: string;
}

/** Secret-free data-key rotation preflight status. */
export type DataKeyRotationPreflightStatus =
  | 'ready'
  | 'store_missing'
  | 'plaintext_store_not_rotatable'
  | 'current_key_required'
  | 'reject_empty_current_key'
  | 'reject_empty_new_key'
  | 'sqlcipher_build_required'
  | string;

/** Non-secret evidence attached to a data-key rotation preflight decision. */
export interface DataKeyRotationPreflightEvidence {
  database_format: string;
  current_key_config: string;
  requested_key_config: string;
  sqlcipher_available: boolean;
  database_file: string;
}

/** Secret-free readiness report for a SQLCipher data-key rotation request. */
export interface DataKeyRotationPreflight {
  ready: boolean;
  status: DataKeyRotationPreflightStatus;
  next_action: string;
  evidence: DataKeyRotationPreflightEvidence;
}

/** `POST /v1/data/key-rotation` request. Execution uses only the replacement key. */
export interface DataKeyRotationExecuteBody {
  new_key: string;
}

/** Secret-free status returned after SQLCipher accepts a data-key rekey request. */
export type DataKeyRotationExecutionStatus = 'rekey_applied' | string;

/** Non-secret evidence attached to a completed data-key rotation execution. */
export interface DataKeyRotationExecutionEvidence {
  operation: string;
  requested_key_config: string;
  sqlcipher_available: boolean;
  checkpointed_before_rekey: boolean;
  checkpointed_after_rekey: boolean;
  post_rekey_integrity_checked: boolean;
}

/** Secret-free execution result for an accepted SQLCipher data-key rekey request. */
export interface DataKeyRotationExecution {
  status: DataKeyRotationExecutionStatus;
  rekey_executed: boolean;
  ledger_integrity_verified: boolean;
  ledger_length: number;
  evidence: DataKeyRotationExecutionEvidence;
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
