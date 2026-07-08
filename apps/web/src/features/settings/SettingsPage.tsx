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
import { useEffect, useMemo, useRef, useState } from 'react';
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
  SIGNATURE_FAMILIES,
  THEME_MODES,
  type AppearanceSettings,
  type CatalogSettings,
  type DocumentSettings,
  type Locale,
  type NumberingScheme,
  type OrganizationSettings,
  type Settings,
  type SignatureFamily,
  type SigningSettings,
  type ThemeMode,
} from '../../api/types';
import { UI_VERSION } from '../../api/versionCheck';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { grainStore } from '../../theme/grainStore';
import { applyAppearance, applyLocale } from '../../theme/appearance';
import {
  Badge,
  Button,
  ButtonLink,
  Card,
  ErrorNote,
  Field,
  Icon,
  Input,
  Loading,
  PageHeader,
  Select,
  SubNav,
  Toggle,
} from '../../ui';

/** Trim to a value or `null` (the contract's "unset" for nullable strings). */
const orNull = (s: string): string | null => (s.trim() === '' ? null : s.trim());

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
  };
}

/** The sub-tabs, in order. Each label reuses its section card title (identical text). */
type SettingsSection =
  'aparencia' | 'identidade' | 'documentos' | 'assinaturas' | 'gestao' | 'sobre';

const SETTINGS_SECTIONS: { id: SettingsSection; label: MessageKey }[] = [
  { id: 'aparencia', label: 'settings.appearance.cardTitle' },
  { id: 'identidade', label: 'settings.identity.cardTitle' },
  { id: 'documentos', label: 'settings.documents.cardTitle' },
  { id: 'assinaturas', label: 'settings.signing.cardTitle' },
  { id: 'gestao', label: 'settings.management.cardTitle' },
  { id: 'sobre', label: 'settings.about.cardTitle' },
];

const isSettingsSection = (v: string | null): v is SettingsSection =>
  SETTINGS_SECTIONS.some((s) => s.id === v);

export function SettingsPage() {
  const t = useT();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  // Aparência is the default and carries no `sec` param (so `/configuracoes` lands on it).
  const secParam = params.get('sec');
  const section: SettingsSection = isSettingsSection(secParam) ? secParam : 'aparencia';
  const selectSection = (next: SettingsSection) =>
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        if (next === 'aparencia') p.delete('sec');
        else p.set('sec', next);
        return p;
      },
      { replace: true },
    );
  const settings = useSettings();
  const health = useHealth();
  const ledger = useLedgerVerify();
  const save = useUpdateSettings();

  // The committed (persisted) document, tracked in a ref so the unmount cleanup can
  // restore it if the operator navigated away mid-preview without saving.
  const committed = settings.data ?? DEFAULT_SETTINGS;
  const committedRef = useRef(committed);
  committedRef.current = committed;

  // Full working copy, seeded once when the document first loads.
  const [draft, setDraft] = useState<Settings | null>(null);
  useEffect(() => {
    if (settings.data && !draft) setDraft(settings.data);
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
  // the shared cache — and thus the global appearance layer — in step. Success shows a
  // subtle inline "Guardado" (no toast — autosave is high-frequency); only an error
  // raises a toast, and the fields stay editable so it self-heals on the next edit or a
  // "Guardar agora" retry.
  const body = useMemo(() => (draft ? toWireBody(draft) : null), [draft]);
  const autosave = useAutosave<Settings | null>({
    value: body,
    enabled: !!draft,
    onSave: (b) => (b ? save.mutateAsync(b) : Promise.resolve()),
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

  const a = draft.appearance;

  return (
    <div className="stack">
      <PageHeader
        crumbs={t('settings.breadcrumb')}
        title={t('settings.page.title')}
        lede={t('settings.page.lede')}
      >
        <SubNav
          items={SETTINGS_SECTIONS.map((s) => ({ id: s.id, label: t(s.label) }))}
          active={section}
          onSelect={selectSection}
          ariaLabel={t('settings.subnav.aria')}
        />
      </PageHeader>

      {/* One section at a time; the working copy spans all of them and the save bar below
          is always reachable. The panel replays the route-enter fade on each switch. */}
      <div className="route-transition settings-section" key={section}>
        {/* Aparência --------------------------------------------------------------- */}
        {section === 'aparencia' ? (
          <Card title={t('settings.appearance.cardTitle')}>
            <div className="form">
              <Field
                label={t('settings.appearance.theme.label')}
                htmlFor="set-theme"
                hint={t('settings.appearance.theme.hint')}
              >
                <Select
                  id="set-theme"
                  value={a.theme}
                  onChange={(e) => setAppearance('theme', e.target.value as ThemeMode)}
                  options={optionsFrom(THEME_MODES, themeModeLabels)}
                />
              </Field>

              <Toggle
                label={t('settings.appearance.leatherBg.label')}
                checked={a.leather_texture}
                onChange={(v) => setAppearance('leather_texture', v)}
              />

              <Toggle
                label={t('settings.appearance.leatherButtons.label')}
                checked={a.button_texture}
                onChange={(v) => setAppearance('button_texture', v)}
              />

              <Field
                label={t('settings.appearance.intensity.label', { value: a.texture_intensity })}
                htmlFor="set-intensity"
                hint={t('settings.appearance.intensity.hint')}
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
              <Field label={t('settings.signing.family.label')} htmlFor="set-family">
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
              >
                <div className="input-reset">
                  <Input
                    id="set-tsa"
                    type="url"
                    value={draft.signing.tsa_url ?? ''}
                    placeholder={t('settings.signing.tsaUrl.placeholder')}
                    onChange={(e) => setSigning('tsa_url', e.target.value)}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Refresh />}
                    disabled={
                      (draft.signing.tsa_url ?? '') === (DEFAULT_SETTINGS.signing.tsa_url ?? '')
                    }
                    onClick={() => setSigning('tsa_url', DEFAULT_SETTINGS.signing.tsa_url ?? '')}
                  >
                    {t('settings.signing.reset')}
                  </Button>
                </div>
              </Field>
              <Field
                label={t('settings.signing.tslUrl.label')}
                htmlFor="set-tsl"
                hint={t('settings.signing.officialHint')}
              >
                <div className="input-reset">
                  <Input
                    id="set-tsl"
                    type="url"
                    value={draft.signing.tsl_url ?? ''}
                    placeholder={t('settings.signing.tslUrl.placeholder')}
                    onChange={(e) => setSigning('tsl_url', e.target.value)}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Refresh />}
                    disabled={
                      (draft.signing.tsl_url ?? '') === (DEFAULT_SETTINGS.signing.tsl_url ?? '')
                    }
                    onClick={() => setSigning('tsl_url', DEFAULT_SETTINGS.signing.tsl_url ?? '')}
                  >
                    {t('settings.signing.reset')}
                  </Button>
                </div>
              </Field>
              <Toggle
                label={t('settings.signing.requireQualified.label')}
                checked={draft.signing.require_qualified_for_seal}
                onChange={(v) => setSigning('require_qualified_for_seal', v)}
              />
              <p className="field__hint">{t('settings.signing.note')}</p>
            </div>
          </Card>
        ) : null}

        {/* Gestão ------------------------------------------------------------------ */}
        {section === 'gestao' ? (
          <Card title={t('settings.management.cardTitle')}>
            <div className="form">
              <p className="field__hint">{t('settings.management.note')}</p>
              <div className="row-wrap">
                <ButtonLink to="/utilizadores" icon={<Icon.Users />}>
                  {t('settings.management.usersLink')}
                </ButtonLink>
                <ButtonLink to="/ferramentas" icon={<Icon.Wrench />}>
                  {t('settings.management.toolsLink')}
                </ButtonLink>
              </div>
            </div>
          </Card>
        ) : null}

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

      {/* Autosave status bar ------------------------------------------------------- */}
      {/* Edits across every sub-tab persist automatically (debounced whole-document
          PUT). The inline status keeps the operator informed without toast spam; only a
          failed save raises a toast (via the hook's onError) and surfaces an inline note
          plus a "Guardar agora" retry. The button also lets an operator flush a pending
          debounce immediately. */}
      <Card>
        <div className="stack--tight">
          {autosave.status === 'error' ? <ErrorNote error={autosave.error} /> : null}
          <div className="row-wrap settings-savebar">
            <span className="settings-autosave muted" role="status" aria-live="polite">
              {autosave.status === 'saving' ? (
                t('common.saving')
              ) : autosave.status === 'dirty' ? (
                t('settings.autosave.pending')
              ) : autosave.status === 'saved' ? (
                <>
                  <Icon.Check /> {t('settings.autosave.saved')}
                </>
              ) : autosave.status === 'error' ? (
                t('settings.autosave.error')
              ) : (
                ''
              )}
            </span>
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Save />}
              disabled={!autosave.isDirty || autosave.isSaving}
              onClick={() => autosave.flush()}
            >
              {t('settings.saveNow')}
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
