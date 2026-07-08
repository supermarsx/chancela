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

export interface Entity {
  id: string;
  name: string;
  nipc: string;
  /** `false` ⇒ the NIPC failed control-digit validation and was stored via the override (t25). */
  nipc_validated: boolean;
  seat: string;
  family: EntityFamily;
  kind: EntityKind;
  /** Per-family compliance profile derived from `kind` (t31). */
  profile: EntityProfile;
  /** Statute overlay, or `null` when the entity uses the family default (t31). */
  statute: StatuteOverrides | null;
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

export interface ActAttachment {
  label: string;
  kind: AttachmentKind;
  digest: string | null;
  /** Marks the attachment as beginning-of-proof evidence (t31). Optional on write. */
  beginning_of_proof?: boolean;
}

export interface ActSignatory {
  name: string;
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
  retifies: string | null;
}

export interface ComplianceIssue {
  rule_id: string;
  severity: Severity;
  message: string;
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
}

export interface SealResult {
  act: ActView;
  ata_number: number;
  event_seq: number;
  payload_digest: string;
  acknowledged_warnings: ComplianceIssue[];
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
  attestation: LedgerEventAttestation | null;
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
  recent_events: LedgerEventView[];
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
}

export interface UpdateUserBody {
  display_name?: string;
  active?: boolean;
}

/** `GET /v1/session` — the active user, or `null` when signed out. */
export interface SessionView {
  user: UserView | null;
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

export interface CreateSessionBody {
  user_id: string;
  /** Required only for users with a sign-in secret (t29); 401/429 on failure. */
  password?: string;
}

// Sign-in secret + attestation-key management bodies (t29). `current_password` is
// required only when a secret already exists (verified server-side, 401 on mismatch).
export interface SetSecretBody {
  password: string;
  current_password?: string;
}

export interface RemoveSecretBody {
  current_password?: string;
}

export interface AttestationKeyBody {
  current_password?: string;
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
}

/** `PATCH /v1/entities/{id}` — set (`{...}`), clear (`null`), or leave (omit) the statute overlay (t31). */
export interface UpdateEntityBody {
  statute?: StatuteOverrides | null;
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
  retifies?: string;
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
}

export interface AdvanceActBody {
  to: ActState;
  actor?: string;
}

export interface SealActBody {
  actor?: string;
  acknowledge_warnings?: boolean;
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

export interface SigningSettings {
  preferred_family: SignatureFamily;
  tsa_url: string | null;
  tsl_url: string | null;
  require_qualified_for_seal: boolean;
}

export interface AppearanceSettings {
  theme: ThemeMode;
  leather_texture: boolean;
  texture_intensity: number;
  /** Leather-grain texture on the buttons (contract F1, t19-e1). Default `true`. */
  button_texture: boolean;
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

export interface Settings {
  schema_version: number;
  organization: OrganizationSettings;
  documents: DocumentSettings;
  catalog: CatalogSettings;
  signing: SigningSettings;
  appearance: AppearanceSettings;
  onboarding: OnboardingSettings;
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
    preferred_family: 'CartaoCidadao',
    // The official admin-configurable defaults the backend now returns (contract F1);
    // the client's optimistic default mirrors them so it matches before the first GET.
    tsa_url: 'https://ts.cartaodecidadao.pt/tsa/server',
    tsl_url: 'https://www.gns.gov.pt/media/TSLPT.xml',
    require_qualified_for_seal: false,
  },
  appearance: {
    theme: 'system',
    leather_texture: true,
    texture_intensity: 60,
    button_texture: true,
  },
  onboarding: { completed: false, completed_at: null },
};

export interface HealthResponse {
  status?: string;
  version?: string;
}
