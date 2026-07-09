/**
 * Configurações — the end-to-end configuration surface (user request: "make the
 * whole app fully configurable end to end and allow the user to configure it too").
 *
 * It consumes the frozen §2.8 settings document (GET/PUT /v1/settings), holds a full
 * working copy, and — for the Aparência section — previews changes *live* as the
 * operator edits (theme, grain intensity, re-roll), reverting any unsaved preview to
 * the committed settings when leaving the page. Saving PUTs the whole document; the
 * mutation updates the shared cache optimistically, so the global appearance layer
 * (mounted in the shell) stays in step everywhere else in the app.
 *
 * Sections are reached through a segmented sub-nav (the Ferramentas idiom, via the shared
 * `<SubNav>`): Aparência · Identidade · Documentos · Assinaturas · Gestão · Sobre. The
 * active section is deep-linkable (`?sec=`); the working copy spans all of them, so the
 * save flow stays a single whole-document PUT (global draft) reachable from every section.
 */
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useHealth, useLedgerVerify, useSettings, useUpdateSettings } from '../../api/hooks';
import { useAutosave } from '../../hooks/useAutosave';
import { useToast } from '../../ui';
import {
  localeLabels,
  numberingSchemeLabels,
  optionsFrom,
  signatureFamilyLabels,
  themeModeLabels,
} from '../../api/labels';
import {
  DEFAULT_SETTINGS,
  LOCALES,
  NUMBERING_SCHEMES,
  REGISTERED_ENTITY_COLUMNS,
  SIGNATURE_FAMILIES,
  THEME_MODES,
  type AiSettings,
  type AppearanceSettings,
  type CatalogSettings,
  type DocumentSettings,
  type Locale,
  type NumberingScheme,
  type OrganizationSettings,
  type RegisteredEntityColumn,
  type RegistryAutoUpdateSettings,
  type Settings,
  type SignatureFamily,
  type SigningProviderMetadata,
  type SigningSettings,
  type ThemeMode,
  type UiSettings,
} from '../../api/types';
import { UI_VERSION } from '../../api/versionCheck';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { grainStore } from '../../theme/grainStore';
import { applyAppearance, applyLocale } from '../../theme/appearance';
import { LivrosIntegridadeSection } from '../recovery/LivrosIntegridadeSection';
import { GestaoDadosSection } from '../recovery/GestaoDadosSection';
import { FuncoesSection } from '../rbac/FuncoesSection';
import { DelegacoesSection } from '../rbac/DelegacoesSection';
import { ApiKeysSection } from './ApiKeysSection';
import { PrivacyComplianceSection } from './PrivacyComplianceSection';
import { RegistryAutoUpdateSection } from './RegistryAutoUpdateSection';
import { useCan } from '../session/permissions';
import {
  Badge,
  Button,
  ButtonLink,
  Card,
  ErrorNote,
  Field,
  FieldHelp,
  Icon,
  IconButton,
  InlineWarning,
  Input,
  Loading,
  PageHeader,
  Select,
  SubNav,
  Toggle,
} from '../../ui';
import { EditUserPanel } from '../users/EditUserPage';
import { NewUserPanel } from '../users/NewUserPage';
import { UsersList } from '../users/UserListPage';

/** Trim to a value or `null` (the contract's "unset" for nullable strings). */
const orNull = (s: string): string | null => (s.trim() === '' ? null : s.trim());

type SettingsWithMaybeAi = Omit<Settings, 'ai' | 'signing' | 'registry_auto_update' | 'ui'> & {
  ai?: Partial<AiSettings> | null;
  ui?: Partial<UiSettings> | null;
  registry_auto_update?: Partial<RegistryAutoUpdateSettings> | null;
  signing: Omit<SigningSettings, 'providers'> & Partial<Pick<SigningSettings, 'providers'>>;
};

function withSettingsDefaults(settings: SettingsWithMaybeAi): Settings {
  return {
    ...settings,
    signing: {
      ...DEFAULT_SETTINGS.signing,
      ...settings.signing,
      cmd: { ...DEFAULT_SETTINGS.signing.cmd, ...(settings.signing.cmd ?? {}) },
      providers: settings.signing.providers ?? DEFAULT_SETTINGS.signing.providers,
    },
    ai: { ...DEFAULT_SETTINGS.ai, ...(settings.ai ?? {}) },
    ui: {
      ...DEFAULT_SETTINGS.ui,
      ...(settings.ui ?? {}),
      registered_entity_columns:
        settings.ui?.registered_entity_columns ?? DEFAULT_SETTINGS.ui.registered_entity_columns,
    },
    registry_auto_update: {
      ...DEFAULT_SETTINGS.registry_auto_update,
      ...(settings.registry_auto_update ?? {}),
      cadence:
        settings.registry_auto_update?.cadence ?? DEFAULT_SETTINGS.registry_auto_update.cadence,
      entity_defaults: {
        ...DEFAULT_SETTINGS.registry_auto_update.entity_defaults,
        ...(settings.registry_auto_update?.entity_defaults ?? {}),
        enabled_profiles:
          settings.registry_auto_update?.entity_defaults?.enabled_profiles ??
          DEFAULT_SETTINGS.registry_auto_update.entity_defaults.enabled_profiles,
      },
    },
  };
}

/**
 * Normalise the whole working copy to the wire shape (empty → null for nullables; a
 * blank actor falls back to the server default so the audit event stays attributed).
 * Pure, so both the debounced autosave and an explicit "Guardar agora" persist an
 * identical document, and change-detection compares the *normalised* form (so typing a
 * trailing space that normalises away never triggers a save).
 */
function toWireBody(draft: Settings): Settings {
  return {
    ...draft,
    organization: {
      name: orNull(draft.organization.name ?? ''),
      // The audit actor is attributed from the session (topbar picker), not entered here;
      // the stored default is passed through, falling back to the system actor.
      default_actor: draft.organization.default_actor.trim() || 'api',
    },
    catalog: {
      // Pass through the strict-chain fields untouched (the CAE-source editor is t23-e3);
      // only the legacy single URL is edited here.
      ...draft.catalog,
      cae_update_url: orNull(draft.catalog.cae_update_url ?? ''),
    },
    signing: {
      ...draft.signing,
      tsa_url: orNull(draft.signing.tsa_url ?? ''),
      tsl_url: orNull(draft.signing.tsl_url ?? ''),
    },
    ai: {
      enabled: draft.ai.enabled === true,
    },
    registry_auto_update: {
      ...draft.registry_auto_update,
      entity_defaults: {
        ...draft.registry_auto_update.entity_defaults,
        enabled_profiles: draft.registry_auto_update.entity_defaults.enabled_profiles
          .map((profile) => profile.trim())
          .filter(Boolean),
      },
    },
  };
}

/** The sub-tabs, in order. Each label reuses its section card title (identical text).
 *  The array is appended cleanly by peers (t60 Utilizadores, t62 Administração). */
type SettingsSection =
  | 'aparencia'
  | 'identidade'
  | 'documentos'
  | 'assinaturas'
  | 'gestao'
  | 'privacidade'
  | 'utilizadores'
  | 'chaves-api'
  | 'funcoes'
  | 'delegacoes'
  | 'integridade'
  | 'dados'
  | 'sobre';

type SettingsSectionNav =
  | { id: SettingsSection; label: MessageKey; icon: ReactNode; literal?: never }
  | { id: SettingsSection; label?: never; icon: ReactNode; literal: string };

const SETTINGS_SECTIONS: SettingsSectionNav[] = [
  { id: 'aparencia', label: 'settings.appearance.cardTitle', icon: <Icon.Palette /> },
  { id: 'identidade', label: 'settings.identity.cardTitle', icon: <Icon.IdCard /> },
  { id: 'documentos', label: 'settings.documents.cardTitle', icon: <Icon.FileText /> },
  { id: 'assinaturas', label: 'settings.signing.cardTitle', icon: <Icon.PenNib /> },
  { id: 'gestao', label: 'settings.management.cardTitle', icon: <Icon.Sliders /> },
  { id: 'privacidade', literal: 'Privacidade', icon: <Icon.Seal /> },
  { id: 'utilizadores', label: 'settings.users.cardTitle', icon: <Icon.Users /> },
  { id: 'chaves-api', label: 'settings.apiKeys.cardTitle', icon: <Icon.Seal /> },
  { id: 'funcoes', label: 'rbac.funcoes.tab', icon: <Icon.Scale /> },
  { id: 'delegacoes', label: 'rbac.delegacoes.tab', icon: <Icon.ArrowRight /> },
  { id: 'integridade', label: 'integrity.cardTitle', icon: <Icon.Layers /> },
  { id: 'dados', label: 'data.cardTitle', icon: <Icon.Archive /> },
  { id: 'sobre', label: 'settings.about.cardTitle', icon: <Icon.Info /> },
];

/** The sub-tabs that manage their OWN data (not the settings working copy), so the
 *  autosave savebar is not shown for them. The RBAC tabs (Funções, Delegações) self-gate
 *  their own `role.manage`/`delegation.*` affordances, so they are standalone too. */
const STANDALONE_SECTIONS: readonly SettingsSection[] = [
  'utilizadores',
  'privacidade',
  'funcoes',
  'delegacoes',
  'integridade',
  'dados',
  'chaves-api',
];

/**
 * Whether autosave is enabled. Autosave is always-on today (t49) — there is no
 * server-side disable toggle yet (a deferred t60 slice needing an `autosave_enabled`
 * settings field). The persistent "Guardar agora" flush is therefore hidden: it would
 * only ever return when a future toggle turns autosave OFF (`!autosaveEnabled`). A failed
 * save still exposes a retry affordance regardless (see the savebar), so nothing is stuck.
 * When the field lands, replace this constant with `draft.<…>.autosave_enabled ?? true`.
 */
const AUTOSAVE_ENABLED = true;

const ENTITY_COLUMN_LABEL_KEYS: Record<RegisteredEntityColumn, MessageKey> = {
  Name: 'entities.columns.name',
  Nipc: 'entities.columns.nipc',
  Seat: 'entities.columns.seat',
  Type: 'entities.columns.type',
  Matricula: 'entities.columns.matricula',
  Constitution: 'entities.columns.constitution',
  Capital: 'entities.columns.capital',
  Cae: 'entities.columns.cae',
  Registry: 'entities.columns.registry',
  LastRegistryChange: 'entities.columns.lastRegistryChange',
  FiscalYearEnd: 'entities.columns.fiscalYearEnd',
  LastBook: 'entities.columns.lastBook',
  LastActivity: 'entities.columns.lastActivity',
  Actions: 'entities.columns.actions',
};

const isSettingsSection = (v: string | null): v is SettingsSection =>
  SETTINGS_SECTIONS.some((s) => s.id === v);

function providerModeLabel(provider: SigningProviderMetadata, t: ReturnType<typeof useT>): string {
  switch (provider.mode) {
    case 'CMD':
      return t('settings.signing.providerMode.cmd');
    case 'CC':
      return t('settings.signing.providerMode.cc');
    case 'CSC_QTSP':
      return t('settings.signing.providerMode.cscQtsp');
    case 'LOCAL_PKCS12':
      return t('settings.signing.providerMode.localPkcs12');
  }
}

function providerStatus(
  provider: SigningProviderMetadata,
  t: ReturnType<typeof useT>,
): {
  tone: 'ok' | 'error' | 'accent' | 'warn';
  label: string;
} {
  if (provider.production_blocked) {
    return { tone: 'error', label: t('settings.signing.providerStatus.productionBlocked') };
  }
  if (provider.configured)
    return { tone: 'ok', label: t('settings.signing.providerStatus.configured') };
  if (provider.local_only)
    return { tone: 'accent', label: t('settings.signing.providerStatus.localOnly') };
  return { tone: 'warn', label: t('settings.signing.providerStatus.unconfigured') };
}

export function SettingsPage() {
  const t = useT();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  // Aparência is the default and carries no `sec` param (so `/configuracoes` lands on it).
  const secParam = params.get('sec');
  const section: SettingsSection = isSettingsSection(secParam) ? secParam : 'aparencia';
  const selectedUser = section === 'utilizadores' ? params.get('user') : null;
  const selectSection = (next: SettingsSection) =>
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        if (next === 'aparencia') p.delete('sec');
        else p.set('sec', next);
        if (next !== 'utilizadores') p.delete('user');
        return p;
      },
      { replace: true },
    );
  const selectUser = (next: string | null) =>
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        p.set('sec', 'utilizadores');
        if (next) p.set('user', next);
        else p.delete('user');
        return p;
      },
      { replace: true },
    );
  const settings = useSettings();
  const health = useHealth();
  const ledger = useLedgerVerify();
  const save = useUpdateSettings();
  // Writing the settings document requires `settings.manage` (PUT /v1/settings, t64-E3).
  // Without it the whole-document autosave is suspended and the working-copy sections are
  // disabled-with-explanation; the standalone sub-tabs (Utilizadores/Integridade/Dados)
  // gate their OWN actions, and "Sobre" is read-only info — so only the editable sections
  // lock. Reads (`settings.read`) still render everything.
  const can = useCan();
  const canManageSettings = can('settings.manage');
  // Lock only the editable working-copy sections (not the self-gating standalone sub-tabs,
  // nor the read-only "Sobre").
  const editingLocked =
    !canManageSettings && !STANDALONE_SECTIONS.includes(section) && section !== 'sobre';

  // The committed (persisted) document, tracked in a ref so the unmount cleanup can
  // restore it if the operator navigated away mid-preview without saving.
  const committed = useMemo(
    () => withSettingsDefaults(settings.data ?? DEFAULT_SETTINGS),
    [settings.data],
  );
  const committedRef = useRef(committed);
  committedRef.current = committed;

  // Full working copy, seeded once when the document first loads.
  const [draft, setDraft] = useState<Settings | null>(null);
  useEffect(() => {
    if (settings.data && !draft) setDraft(withSettingsDefaults(settings.data));
  }, [settings.data, draft]);

  // Live preview: apply the draft appearance/locale as it is edited so the operator
  // sees the theme switch, grain fade and language flip immediately.
  useEffect(() => {
    if (!draft) return;
    applyAppearance(draft.appearance);
    applyLocale(draft.documents.locale);
    // Keyed on the appearance/locale slices only; `draft` as a whole would re-apply
    // on unrelated edits (org name, etc.).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft?.appearance, draft?.documents.locale]);

  // On leaving the page, drop any unsaved preview and restore the committed look.
  useEffect(() => {
    return () => {
      applyAppearance(committedRef.current.appearance);
      applyLocale(committedRef.current.documents.locale);
    };
  }, []);

  // The normalised wire document the operator's edits currently amount to. Autosave
  // debounces every edit across all sub-tabs and PUTs this whole document (the §2.8
  // contract is a single whole-document PUT); the optimistic `useUpdateSettings` keeps
  // the shared cache — and thus the global appearance layer — in step. A committed save
  // raises a normal success toast (no inline "Guardado" — the save bar stays hidden on a
  // clean form); a failure raises an error toast AND keeps an inline error + retry, and
  // the fields stay editable so it self-heals on the next edit or a manual retry.
  const body = useMemo(() => (draft ? toWireBody(draft) : null), [draft]);
  const autosave = useAutosave<Settings | null>({
    value: body,
    enabled: !!draft && canManageSettings,
    onSave: (b) => (b ? save.mutateAsync(b) : Promise.resolve()),
    onSuccess: () => toast.success(t('toast.settings.saved')),
    onError: (e) => toast.error(e),
  });

  if (settings.isLoading || !draft) return <Loading />;
  if (settings.error) return <ErrorNote error={settings.error} />;

  const setOrganization = <K extends keyof OrganizationSettings>(
    key: K,
    value: OrganizationSettings[K],
  ) => setDraft((d) => (d ? { ...d, organization: { ...d.organization, [key]: value } } : d));
  const setDocuments = <K extends keyof DocumentSettings>(key: K, value: DocumentSettings[K]) =>
    setDraft((d) => (d ? { ...d, documents: { ...d.documents, [key]: value } } : d));
  const setCatalog = <K extends keyof CatalogSettings>(key: K, value: CatalogSettings[K]) =>
    setDraft((d) => (d ? { ...d, catalog: { ...d.catalog, [key]: value } } : d));
  const setSigning = <K extends keyof SigningSettings>(key: K, value: SigningSettings[K]) =>
    setDraft((d) => (d ? { ...d, signing: { ...d.signing, [key]: value } } : d));
  const setAppearance = <K extends keyof AppearanceSettings>(
    key: K,
    value: AppearanceSettings[K],
  ) => setDraft((d) => (d ? { ...d, appearance: { ...d.appearance, [key]: value } } : d));
  const setAi = <K extends keyof AiSettings>(key: K, value: AiSettings[K]) =>
    setDraft((d) => (d ? { ...d, ai: { ...d.ai, [key]: value } } : d));
  const setUi = <K extends keyof UiSettings>(key: K, value: UiSettings[K]) =>
    setDraft((d) => (d ? { ...d, ui: { ...d.ui, [key]: value } } : d));
  const setRegistryAutoUpdate = (registry_auto_update: RegistryAutoUpdateSettings) =>
    setDraft((d) => (d ? { ...d, registry_auto_update } : d));

  const toggleEntityColumn = (column: RegisteredEntityColumn, checked: boolean) => {
    const current = draft.ui.registered_entity_columns;
    const next = checked
      ? REGISTERED_ENTITY_COLUMNS.filter(
          (candidate) => candidate === column || current.includes(candidate),
        )
      : current.filter((candidate) => candidate !== column);
    setUi('registered_entity_columns', next.length > 0 ? next : ['Actions']);
  };

  const a = draft.appearance;

  return (
    <div className="stack">
      <PageHeader
        crumbs={t('settings.breadcrumb')}
        title={t('settings.page.title')}
        lede={t('settings.page.lede')}
      >
        <SubNav
          items={SETTINGS_SECTIONS.map((s) => ({
            id: s.id,
            label: 'literal' in s ? s.literal : t(s.label),
            icon: s.icon,
          }))}
          active={section}
          onSelect={selectSection}
          ariaLabel={t('settings.subnav.aria')}
        />
      </PageHeader>

      {/* Honest disable-with-explanation for the editable settings when the user lacks
          `settings.manage`: the working-copy sections are inerted (a disabled fieldset) and
          this note explains why. Standalone sub-tabs manage their own gating. */}
      {editingLocked ? (
        <InlineWarning tone="info" title={t('perm.denied.title')}>
          {t('perm.denied.body')}
        </InlineWarning>
      ) : null}

      {/* One section at a time; the working copy spans all of them and the save bar below
          is always reachable. The panel replays the route-enter fade on each switch. */}
      <fieldset className="settings-fieldset" disabled={editingLocked}>
        <div className="route-transition settings-section" key={section}>
          {/* Aparência --------------------------------------------------------------- */}
          {section === 'aparencia' ? (
            <Card title={t('settings.appearance.cardTitle')}>
              <div className="form">
                <Field
                  label={t('settings.appearance.theme.label')}
                  htmlFor="set-theme"
                  hint={t('settings.appearance.theme.hint')}
                  help={t('settings.appearance.theme.help')}
                >
                  <Select
                    id="set-theme"
                    value={a.theme}
                    onChange={(e) => setAppearance('theme', e.target.value as ThemeMode)}
                    options={optionsFrom(THEME_MODES, themeModeLabels)}
                  />
                </Field>

                <Toggle
                  label={
                    <>
                      {t('settings.appearance.leatherBg.label')}{' '}
                      <FieldHelp text={t('settings.appearance.leatherBg.help')} />
                    </>
                  }
                  checked={a.leather_texture}
                  onChange={(v) => setAppearance('leather_texture', v)}
                />

                <Toggle
                  label={
                    <>
                      {t('settings.appearance.leatherButtons.label')}{' '}
                      <FieldHelp text={t('settings.appearance.leatherButtons.help')} />
                    </>
                  }
                  checked={a.button_texture}
                  onChange={(v) => setAppearance('button_texture', v)}
                />

                <Field
                  label={t('settings.appearance.intensity.label', { value: a.texture_intensity })}
                  htmlFor="set-intensity"
                  hint={t('settings.appearance.intensity.hint')}
                  help={t('settings.appearance.intensity.help')}
                >
                  <input
                    id="set-intensity"
                    className="control control--range"
                    type="range"
                    min={0}
                    max={100}
                    step={1}
                    value={a.texture_intensity}
                    disabled={!a.leather_texture}
                    onChange={(e) => setAppearance('texture_intensity', Number(e.target.value))}
                  />
                </Field>

                <div className="form__actions">
                  <Button
                    type="button"
                    variant="secondary"
                    icon={<Icon.Shuffle />}
                    disabled={!a.leather_texture}
                    onClick={() => grainStore.reroll()}
                  >
                    {t('settings.appearance.reroll')}
                  </Button>
                </div>
              </div>
            </Card>
          ) : null}

          {/* Identidade -------------------------------------------------------------- */}
          {section === 'identidade' ? (
            <Card title={t('settings.identity.cardTitle')}>
              <div className="form">
                <Field
                  label={t('settings.identity.orgName.label')}
                  htmlFor="set-org-name"
                  hint={t('settings.identity.orgName.hint')}
                  help={t('settings.identity.orgName.help')}
                >
                  <Input
                    id="set-org-name"
                    value={draft.organization.name ?? ''}
                    placeholder={t('settings.identity.orgName.placeholder')}
                    onChange={(e) => setOrganization('name', e.target.value)}
                  />
                </Field>
                <p className="field__hint">{t('settings.identity.actorNote')}</p>
              </div>
            </Card>
          ) : null}

          {/* Documentos -------------------------------------------------------------- */}
          {section === 'documentos' ? (
            <Card title={t('settings.documents.cardTitle')}>
              <div className="form">
                <Field
                  label={t('settings.documents.locale.label')}
                  htmlFor="set-locale"
                  hint={t('settings.documents.locale.hint')}
                  help={t('settings.documents.locale.help')}
                >
                  <Select
                    id="set-locale"
                    value={draft.documents.locale}
                    onChange={(e) => setDocuments('locale', e.target.value as Locale)}
                    options={optionsFrom(LOCALES, localeLabels)}
                  />
                </Field>
                <Field
                  label={t('settings.documents.numbering.label')}
                  htmlFor="set-numbering"
                  hint={t('settings.documents.numbering.hint')}
                  help={t('settings.documents.numbering.help')}
                >
                  <Select
                    id="set-numbering"
                    value={draft.documents.numbering_scheme_default}
                    onChange={(e) =>
                      setDocuments('numbering_scheme_default', e.target.value as NumberingScheme)
                    }
                    options={optionsFrom(NUMBERING_SCHEMES, numberingSchemeLabels)}
                  />
                </Field>
                <Field
                  label={t('settings.documents.caeUrl.label')}
                  htmlFor="set-cae-url"
                  hint={t('settings.documents.caeUrl.hint')}
                  help={t('settings.documents.caeUrl.help')}
                >
                  <Input
                    id="set-cae-url"
                    type="url"
                    value={draft.catalog.cae_update_url ?? ''}
                    placeholder={t('settings.documents.caeUrl.placeholder')}
                    onChange={(e) => setCatalog('cae_update_url', e.target.value)}
                  />
                </Field>
              </div>
            </Card>
          ) : null}

          {/* Assinaturas ------------------------------------------------------------- */}
          {section === 'assinaturas' ? (
            <Card title={t('settings.signing.cardTitle')}>
              <div className="form">
                <Field
                  label={t('settings.signing.family.label')}
                  htmlFor="set-family"
                  hint={t('settings.signing.family.hint')}
                  help={t('settings.signing.family.help')}
                >
                  <Select
                    id="set-family"
                    value={draft.signing.preferred_family}
                    onChange={(e) =>
                      setSigning('preferred_family', e.target.value as SignatureFamily)
                    }
                    options={optionsFrom(SIGNATURE_FAMILIES, signatureFamilyLabels)}
                  />
                </Field>
                <Field
                  label={t('settings.signing.tsaUrl.label')}
                  htmlFor="set-tsa"
                  hint={t('settings.signing.officialHint')}
                  help={t('settings.signing.tsaUrl.help')}
                >
                  <div className="input-reset">
                    <Input
                      id="set-tsa"
                      type="url"
                      value={draft.signing.tsa_url ?? ''}
                      placeholder={t('settings.signing.tsaUrl.placeholder')}
                      onChange={(e) => setSigning('tsa_url', e.target.value)}
                    />
                    <IconButton
                      type="button"
                      variant="ghost"
                      icon={<Icon.Refresh />}
                      label={t('settings.signing.reset')}
                      disabled={
                        (draft.signing.tsa_url ?? '') === (DEFAULT_SETTINGS.signing.tsa_url ?? '')
                      }
                      onClick={() => setSigning('tsa_url', DEFAULT_SETTINGS.signing.tsa_url ?? '')}
                    />
                  </div>
                </Field>
                <Field
                  label={t('settings.signing.tslUrl.label')}
                  htmlFor="set-tsl"
                  hint={t('settings.signing.officialHint')}
                  help={t('settings.signing.tslUrl.help')}
                >
                  <div className="input-reset">
                    <Input
                      id="set-tsl"
                      type="url"
                      value={draft.signing.tsl_url ?? ''}
                      placeholder={t('settings.signing.tslUrl.placeholder')}
                      onChange={(e) => setSigning('tsl_url', e.target.value)}
                    />
                    <IconButton
                      type="button"
                      variant="ghost"
                      icon={<Icon.Refresh />}
                      label={t('settings.signing.reset')}
                      disabled={
                        (draft.signing.tsl_url ?? '') === (DEFAULT_SETTINGS.signing.tsl_url ?? '')
                      }
                      onClick={() => setSigning('tsl_url', DEFAULT_SETTINGS.signing.tsl_url ?? '')}
                    />
                  </div>
                </Field>
                <Toggle
                  label={
                    <>
                      {t('settings.signing.requireQualified.label')}{' '}
                      <FieldHelp text={t('settings.signing.requireQualified.help')} />
                    </>
                  }
                  checked={draft.signing.require_qualified_for_seal}
                  onChange={(v) => setSigning('require_qualified_for_seal', v)}
                />
                <p className="field__hint">{t('settings.signing.requireQualified.hint')}</p>
                <p className="field__hint">{t('settings.signing.note')}</p>

                <div className="stack--tight">
                  <p className="card__label">{t('settings.signing.providers.title')}</p>
                  <p className="field__hint">{t('settings.signing.providers.hint')}</p>
                  <dl className="deflist">
                    {draft.signing.providers.map((provider) => {
                      const status = providerStatus(provider, t);
                      return (
                        <div key={provider.id}>
                          <dt>
                            {provider.label}
                            <span className="muted"> · {providerModeLabel(provider, t)}</span>
                          </dt>
                          <dd>
                            <span className="row-wrap">
                              <Badge tone={status.tone}>{status.label}</Badge>
                              {provider.configured && provider.production_blocked ? (
                                <Badge tone="warn">
                                  {t('settings.signing.providerStatus.incomplete')}
                                </Badge>
                              ) : null}
                              {provider.local_only ? (
                                <Badge tone="accent">
                                  {t('settings.signing.providerStatus.localOnly')}
                                </Badge>
                              ) : null}
                            </span>
                            <span className="field__hint">{provider.note}</span>
                          </dd>
                        </div>
                      );
                    })}
                  </dl>
                </div>

                {/* Chave Móvel Digital — read-only config. The non-secret selectors (env,
                  ApplicationId) plus the "AMA cert configured?" flag come from the server; the
                  AMA secret material itself is supplied via environment variables, never the
                  settings document, so it is surfaced here for transparency, not edited. */}
                <div className="stack--tight">
                  <p className="card__label">{t('settings.signing.cmd.title')}</p>
                  <p className="field__hint">{t('settings.signing.cmd.intro')}</p>
                  <dl className="deflist">
                    <div>
                      <dt>{t('settings.signing.cmd.env')}</dt>
                      <dd>
                        {draft.signing.cmd.env === 'prod'
                          ? t('settings.signing.cmd.envProd')
                          : t('settings.signing.cmd.envPreprod')}
                      </dd>
                    </div>
                    <div>
                      <dt>{t('settings.signing.cmd.applicationId')}</dt>
                      <dd className="mono">
                        {draft.signing.cmd.application_id ?? t('settings.signing.cmd.unset')}
                      </dd>
                    </div>
                    <div>
                      <dt>{t('settings.signing.cmd.amaCert')}</dt>
                      <dd>
                        {draft.signing.cmd.ama_cert_configured ? (
                          <Badge tone="ok">{t('settings.signing.cmd.configured')}</Badge>
                        ) : (
                          <Badge tone="warn">{t('settings.signing.cmd.notConfigured')}</Badge>
                        )}
                      </dd>
                    </div>
                  </dl>
                </div>
              </div>
            </Card>
          ) : null}

          {/* Gestão ------------------------------------------------------------------ */}
          {section === 'gestao' ? (
            <div className="stack">
              <Card title={t('settings.management.cardTitle')}>
                <div className="form">
                  {canManageSettings ? (
                    <>
                      <Toggle
                        label={t('settings.management.ai.label')}
                        checked={draft.ai.enabled}
                        onChange={(v) => setAi('enabled', v)}
                      />
                      <p className="field__hint">{t('settings.management.ai.hint')}</p>
                    </>
                  ) : null}
                  <p className="field__hint">{t('settings.management.note')}</p>
                  <div className="row-wrap">
                    <ButtonLink to="/configuracoes?sec=utilizadores" icon={<Icon.Users />}>
                      {t('settings.management.usersLink')}
                    </ButtonLink>
                    <ButtonLink to="/ferramentas" icon={<Icon.Wrench />}>
                      {t('settings.management.toolsLink')}
                    </ButtonLink>
                  </div>
                </div>
              </Card>
              <RegistryAutoUpdateSection
                value={draft.registry_auto_update}
                onChange={setRegistryAutoUpdate}
              />
              <Card title={t('settings.entityTable.title')}>
                <div className="form">
                  <p className="field__hint">{t('settings.entityTable.hint')}</p>
                  <div
                    className="checkbox-grid"
                    role="group"
                    aria-label={t('settings.entityTable.columns.aria')}
                  >
                    {REGISTERED_ENTITY_COLUMNS.map((column) => (
                      <Toggle
                        key={column}
                        label={t(ENTITY_COLUMN_LABEL_KEYS[column])}
                        checked={draft.ui.registered_entity_columns.includes(column)}
                        onChange={(checked) => toggleEntityColumn(column, checked)}
                      />
                    ))}
                  </div>
                </div>
              </Card>
            </div>
          ) : null}

          {/* Utilizadores ------------------------------------------------------------ */}
          {/* The roster, create flow and edit/access managers are all hosted inside this
            settings sub-tab. Legacy `/utilizadores/*` routes redirect here. */}
          {section === 'utilizadores' ? (
            <div className="stack">
              <UsersList />
              {selectedUser ? (
                <div className="stack">
                  <div className="form__actions">
                    <Button
                      type="button"
                      variant="secondary"
                      icon={<Icon.Users />}
                      onClick={() => selectUser(null)}
                    >
                      {t('users.breadcrumb.self')}
                    </Button>
                  </div>
                  {selectedUser === 'novo' ? (
                    <NewUserPanel onCreated={(user) => selectUser(user.id)} />
                  ) : (
                    <EditUserPanel id={selectedUser} />
                  )}
                </div>
              ) : null}
            </div>
          ) : null}

          {/* Chaves API ------------------------------------------------------------- */}
          {section === 'chaves-api' ? <ApiKeysSection /> : null}

          {/* Privacidade e conformidade ------------------------------------------- */}
          {section === 'privacidade' ? <PrivacyComplianceSection /> : null}

          {/* Funções e permissões (t64-E6) ------------------------------------------ */}
          {section === 'funcoes' ? <FuncoesSection /> : null}

          {/* Delegações (t64-E6) ---------------------------------------------------- */}
          {section === 'delegacoes' ? <DelegacoesSection /> : null}

          {/* Livros & Integridade ---------------------------------------------------- */}
          {section === 'integridade' ? <LivrosIntegridadeSection /> : null}

          {/* Gestão de Dados --------------------------------------------------------- */}
          {section === 'dados' ? <GestaoDadosSection /> : null}

          {/* Sobre ------------------------------------------------------------------- */}
          {section === 'sobre' ? (
            <Card title={t('settings.about.cardTitle')}>
              <dl className="deflist">
                <div>
                  <dt>{t('settings.about.serverVersion')}</dt>
                  <dd className="mono">{health.data?.version ?? '—'}</dd>
                </div>
                <div>
                  <dt>{t('settings.about.uiVersion')}</dt>
                  <dd className="mono">
                    {UI_VERSION}
                    {health.data?.version && health.data.version !== UI_VERSION && (
                      <>
                        {' '}
                        <Badge tone="error">{t('settings.about.serverOutdated')}</Badge>
                      </>
                    )}
                  </dd>
                </div>
                <div>
                  <dt>{t('settings.about.ledger')}</dt>
                  <dd>
                    {ledger.data ? (
                      ledger.data.valid ? (
                        <Badge tone="ok">
                          {t('settings.about.ledger.valid', { count: ledger.data.length })}
                        </Badge>
                      ) : (
                        <Badge tone="error">{t('settings.about.ledger.compromised')}</Badge>
                      )
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </dd>
                </div>
                <div>
                  <dt>{t('settings.about.schemaVersion')}</dt>
                  <dd className="mono">{draft.schema_version}</dd>
                </div>
              </dl>
            </Card>
          ) : null}
        </div>
      </fieldset>

      {/* Save bar ------------------------------------------------------------------ */}
      {/* Edits across every sub-tab persist automatically (debounced whole-document PUT).
          A committed save confirms with a normal success toast (not an inline block), so
          there is no persistent status block to clutter a clean form. The bar therefore
          renders ONLY when it has something to act on:
            • Autosave ON (today): a *failed* save — an inline error plus a retry. Success
              is the toast; a clean or in-flight form shows nothing (no "Guardar agora").
            • Autosave OFF (a future toggle): whenever there are unsaved changes, to host
              the "Guardar agora" flush; a clean form shows nothing.
          The standalone sub-tabs (Utilizadores, Integridade, Dados…) manage their own data
          and never touch the settings document, so the bar is hidden there entirely. */}
      {!STANDALONE_SECTIONS.includes(section) &&
      (AUTOSAVE_ENABLED ? autosave.status === 'error' : autosave.isDirty) ? (
        <Card>
          <div className="stack--tight">
            {autosave.status === 'error' ? <ErrorNote error={autosave.error} /> : null}
            <div className="row-wrap settings-savebar">
              {/* In manual mode the bar carries a live status beside the flush button;
                  success never shows inline (it is a toast), so there is no "Guardado". */}
              {!AUTOSAVE_ENABLED ? (
                <span className="settings-autosave muted" role="status" aria-live="polite">
                  {autosave.status === 'saving'
                    ? t('common.saving')
                    : autosave.status === 'dirty'
                      ? t('settings.autosave.pending')
                      : autosave.status === 'error'
                        ? t('settings.autosave.error')
                        : ''}
                </span>
              ) : null}
              {/* Persistent manual flush only when autosave is OFF (never today). When it is
                  ON, the only manual control is an error-state retry, so a failed save is
                  always recoverable without a standing "Guardar agora" button. */}
              {!AUTOSAVE_ENABLED ? (
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.Save />}
                  disabled={!autosave.isDirty || autosave.isSaving}
                  onClick={() => autosave.flush()}
                >
                  {t('settings.saveNow')}
                </Button>
              ) : (
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.Refresh />}
                  disabled={autosave.isSaving}
                  onClick={() => autosave.flush()}
                >
                  {t('settings.autosave.retry')}
                </Button>
              )}
            </div>
          </div>
        </Card>
      ) : null}
    </div>
  );
}
