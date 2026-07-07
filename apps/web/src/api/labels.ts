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
import { t } from '../i18n';
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
  EntityFamily,
  EntityKind,
  Locale,
  MeetingChannel,
  NumberingScheme,
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
export const bookKindLabels = enumLabels<BookKind>('bookKind');
export const bookStateLabels = enumLabels<BookState>('bookState');
export const numberingSchemeLabels = enumLabels<NumberingScheme>('numberingScheme');
export const closingReasonLabels = enumLabels<ClosingReason>('closingReason');
export const meetingChannelLabels = enumLabels<MeetingChannel>('meetingChannel');
export const actStateLabels = enumLabels<ActState>('actState');
export const attachmentKindLabels = enumLabels<AttachmentKind>('attachmentKind');
export const signatoryCapacityLabels = enumLabels<SignatoryCapacity>('signatoryCapacity');
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

// --- CAE — Classificação das Atividades Económicas (§2.7, plan t14) --------------

/** Build `<Select>` options from a labels map, preserving the given key order. */
export function optionsFrom<K extends string>(
  order: readonly K[],
  labels: Record<K, string>,
): { value: string; label: string }[] {
  return order.map((k) => ({ value: k, label: labels[k] }));
}
