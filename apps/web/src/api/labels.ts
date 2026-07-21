/**
 * Enum display labels for the contract enums (§2.1).
 *
 * These labels are UI chrome and are localized (ruling 5): the source of truth is the
 * per-locale catalog under `enum.<map>.<Variant>` keys (see `src/i18n/locales`). To keep
 * every call site unchanged, each `Record<Enum, string>` here is a thin shim that
 * resolves a lookup (`entityKindLabels[kind]`, or `optionsFrom(order, map)`) through the
 * catalog's non-React `t()` for the active locale. Legal-basis strings for compliance
 * issues stay on the API side (UX-21) — these are UI labels only.
 */
import {
  t,
  LABELLED_LEDGER_EVENT_KINDS,
  LABELLED_DASHBOARD_ALERT_SOURCES,
  LABELLED_DASHBOARD_REMINDER_RULES,
  SEEDED_ROLE_NAMES,
  normalizeAlertSource,
} from '../i18n';
import type { MessageKey } from '../i18n';
import type {
  ActState,
  AttachmentKind,
  BookKind,
  BookState,
  CaeLevel,
  CaeRevision,
  CaeRole,
  ClosingReason,
  DispatchChannel,
  EntityFamily,
  EntityKind,
  LifecycleStage,
  Locale,
  MeetingChannel,
  NumberingScheme,
  PresenceMode,
  Severity,
  SignatoryCapacity,
  SignatureFamily,
  SignaturePolicyHint,
  ThemeMode,
} from './types';

/**
 * A live label map: `map[variant]` resolves `enum.<ns>.<variant>` in the active locale.
 * Backed by a Proxy so indexed access and `optionsFrom(order, map)` both stay working
 * without materializing a per-locale object; nothing enumerates these maps (verified),
 * so the empty target is fine.
 */
function enumLabels<K extends string>(ns: string): Record<K, string> {
  return new Proxy({} as Record<K, string>, {
    get(_target, prop) {
      if (typeof prop !== 'string') return undefined;
      return t(`enum.${ns}.${prop}` as MessageKey);
    },
  });
}

export const entityKindLabels = enumLabels<EntityKind>('entityKind');
export const entityFamilyLabels = enumLabels<EntityFamily>('entityFamily');
export const lifecycleStageLabels = enumLabels<LifecycleStage>('lifecycleStage');
export const bookKindLabels = enumLabels<BookKind>('bookKind');
export const bookStateLabels = enumLabels<BookState>('bookState');
export const numberingSchemeLabels = enumLabels<NumberingScheme>('numberingScheme');
export const closingReasonLabels = enumLabels<ClosingReason>('closingReason');
export const meetingChannelLabels = enumLabels<MeetingChannel>('meetingChannel');
export const dispatchChannelLabels = enumLabels<DispatchChannel>('dispatchChannel');
export const actStateLabels = enumLabels<ActState>('actState');
export const attachmentKindLabels = enumLabels<AttachmentKind>('attachmentKind');
export const signatoryCapacityLabels = enumLabels<SignatoryCapacity>('signatoryCapacity');
/**
 * The same capacities as they read on an attendance roll — "na qualidade de …". `Member` is
 * "Sócio" here and "Membro" under a signature block; see `i18n/attendeeQualityLabels.ts`.
 */
export const attendeeQualityLabels = enumLabels<SignatoryCapacity>('attendeeQuality');
export const presenceModeLabels = enumLabels<PresenceMode>('presenceMode');
export const severityLabels = enumLabels<Severity>('severity');
export const localeLabels = enumLabels<Locale>('locale');
export const signatureFamilyLabels = enumLabels<SignatureFamily>('signatureFamily');
export const signaturePolicyLabels = enumLabels<SignaturePolicyHint>('signaturePolicy');
export const themeModeLabels = enumLabels<ThemeMode>('themeMode');
export const caeRoleLabels = enumLabels<CaeRole>('caeRole');
export const caeLevelLabels = enumLabels<CaeLevel>('caeLevel');
export const caeRevisionLabels = enumLabels<CaeRevision>('caeRevision');

// --- Registry — certidão permanente (§2.7) --------------------------------------

const KNOWN_LEGAL_FORMS = new Set<string>([
  'SociedadePorQuotas',
  'SociedadeUnipessoalPorQuotas',
  'SociedadeAnonima',
  'SociedadeEmNomeColetivo',
  'SociedadeEmComanditaSimples',
  'SociedadeEmComanditaPorAcoes',
  'Cooperativa',
  'Fundacao',
  'Associacao',
]);

/**
 * Render a certidão's normalized `legal_form` variant in the active locale, falling
 * back to the raw wire string for anything unmapped so the display never breaks on a
 * new variant.
 */
export function legalFormLabel(form: string): string {
  return KNOWN_LEGAL_FORMS.has(form) ? t(`enum.legalForm.${form}` as MessageKey) : form;
}

const KNOWN_REGISTRY_FIELDS = new Set<string>(['name', 'seat', 'nipc', 'kind']);

/** Entity fields the import cross-check reports as `applied`/`conflict` (§2.7). */
export function registryFieldLabel(field: string): string {
  return KNOWN_REGISTRY_FIELDS.has(field) ? t(`enum.registryField.${field}` as MessageKey) : field;
}

// --- Ledger event kinds (§2.4) ---------------------------------------------------

/**
 * Render a ledger event `kind` as readable copy in the active locale. The dotted wire
 * identifier stays the filter/export value and the `title` of whatever renders the label;
 * only the primary line an operator reads is localized.
 *
 * Server-side kinds grow over time, so an unmapped kind degrades to its raw identifier —
 * never blank, never `undefined`.
 */
export function ledgerEventKindLabel(kind: string): string {
  const trimmed = kind.trim();
  if (!trimmed) return kind;
  return LABELLED_LEDGER_EVENT_KINDS.has(trimmed)
    ? t(`enum.ledgerEventKind.${trimmed}` as MessageKey)
    : trimmed;
}

// --- Dashboard actionable provenance ---------------------------------------------

/**
 * Render a `DashboardAlert.source` as readable copy. The wire value names the data scope the
 * check ran over (`entities.books` → the entity's books) or the rule pack that raised the
 * alert (`csc-art63/v2`); the version suffix is dropped before the lookup so a newer pack
 * inherits the name.
 *
 * An unmapped source degrades to its raw identifier — never blank, never `undefined`.
 */
export function dashboardAlertSourceLabel(source: string): string {
  const trimmed = source.trim();
  if (!trimmed) return source;
  const normalized = normalizeAlertSource(trimmed);
  return LABELLED_DASHBOARD_ALERT_SOURCES.has(normalized)
    ? t(`enum.dashboardAlertSource.${normalized}` as MessageKey)
    : trimmed;
}

/**
 * Render a `DashboardReminder.source_rule` as readable copy, or `undefined` when the rule has
 * no name and the caller should keep its raw `rule / profile` rendering.
 *
 * Profile-calendar reminders carry an authored `preset_label` on the payload — that is the
 * reminder's own name, so it wins over the map rather than being duplicated into it.
 */
export function dashboardReminderRuleLabel(
  rule: string,
  presetLabel?: string | null,
): string | undefined {
  const authored = presetLabel?.trim();
  if (authored) return authored;
  const trimmed = rule.trim();
  if (!trimmed) return undefined;
  return LABELLED_DASHBOARD_REMINDER_RULES.has(trimmed)
    ? t(`enum.dashboardReminderRule.${trimmed}` as MessageKey)
    : undefined;
}

// --- Role names (t87) ------------------------------------------------------------

/**
 * Render a role's display name in the active locale.
 *
 * **Seeded** roles carry a stable id and a canonical English `name` (the server stores English —
 * see `crates/chancela-authz/src/role.rs`), so their name is UI chrome and is localized through
 * `enum.roleName.*`. **Custom** roles are operator-authored data and are returned verbatim in every
 * locale — a translation layer that mangled someone's "Gerente da filial" would be a real defect.
 *
 * Two things separate the cases:
 *
 * - the id must be a seeded one (`SEEDED_ROLE_NAMES`); a custom role's id is a random UUID; and
 * - the stored name must still be the canonical English one. An operator who renames a seeded role
 *   has authored a name, so theirs wins — otherwise the rename would silently appear to do nothing.
 *
 * A **retired** id (a merged-away duplicate that only past ledger events still name) has no stored
 * name to compare against and always resolves to its label, so history stays readable.
 *
 * `name` is optional because some call sites hold only an id (a `RoleAssignmentView`, or a role that
 * has left the catalog). An unknown id with no name degrades to the raw id — never blank, never
 * `undefined`.
 */
export function roleNameLabel(id: string, name?: string | null): string {
  const authored = name?.trim();
  const entry = SEEDED_ROLE_NAMES[id.trim()];
  if (entry && (entry.retired || !authored || authored === entry.canonicalName)) {
    return t(`enum.roleName.${entry.slug}` as MessageKey);
  }
  return authored || id;
}

/** Whether `id` is a seeded role whose id has been retired (kept only so old events stay readable). */
export function isRetiredRoleId(id: string): boolean {
  return SEEDED_ROLE_NAMES[id.trim()]?.retired === true;
}

// --- CAE — Classificação das Atividades Económicas (§2.7, plan t14) --------------

/** Build `<Select>` options from a labels map, preserving the given key order. */
export function optionsFrom<K extends string>(
  order: readonly K[],
  labels: Record<K, string>,
): { value: string; label: string }[] {
  return order.map((k) => ({ value: k, label: labels[k] }));
}
