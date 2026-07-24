import { useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import { useDeleteTemplate, useExportTemplate, useTemplates } from '../../api/hooks';
import { ColumnPicker } from '../tableColumns/ColumnPicker';
import { useTableColumns, type TableColumnsSpec } from '../tableColumns/useTableColumns';
import {
  entityFamilyLabels,
  lifecycleStageLabels,
  meetingChannelLabels,
  signaturePolicyLabels,
} from '../../api/labels';
import {
  LIFECYCLE_STAGES,
  MEETING_CHANNELS,
  type EntityFamily,
  type LifecycleStage,
  type MeetingChannel,
  type SignaturePolicyHint,
  type TemplateSummary,
} from '../../api/types';
import { useT, type MessageKey } from '../../i18n';
import { useTemplatesCatalogT } from '../../i18n/templatesCatalogFallback';
import {
  ButtonLink,
  Badge,
  Card,
  ConfirmActionModal,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  InlineWarning,
  Input,
  PageHeader,
  Select,
  SkeletonRegion,
  SkeletonTable,
  useToast,
} from '../../ui';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import { GateButton } from '../session/permissions';
import {
  DEFAULT_TEMPLATE_COLUMNS,
  TEMPLATE_COLUMNS,
  loadTemplateColumns,
  type TemplateColumn,
} from './templateColumns';
import { templateDisplayName } from './templateNames';
import { TemplateImportDialog } from './TemplateImportDialog';
import { TemplatesTable } from './TemplatesTable';
import { useTemplateEditor } from './useTemplateEditor';
import './templatesCatalog.css';

/** The header each optional column answers to — the same label the table renders. */
const TEMPLATE_COLUMN_LABEL_KEYS: Record<TemplateColumn, MessageKey> = {
  Family: 'templates.card.family',
  Stage: 'templates.card.stage',
  Channels: 'templates.card.channels',
  Signature: 'templates.card.signature',
  RulePack: 'templates.card.rulePack',
  LawSource: 'documents.metadata.legalSource',
  Origin: 'templates.table.source',
};

/**
 * The templates table's column spec (t37). Migrated off the device-local `localStorage` to the
 * per-user server store, seeded once from the legacy value (see the mount effect below). `Name` and
 * `Actions` are structural (rendered by the table itself, never in the toggle set), so the store
 * needs the `Name` anchor: a "hide every optional column" choice must persist as a non-empty array,
 * which the server would otherwise fold to "no override".
 */
const TEMPLATES_COLUMN_SPEC: TableColumnsSpec<TemplateColumn> = {
  table: 'templates',
  columns: TEMPLATE_COLUMNS,
  hideable: TEMPLATE_COLUMNS,
  fallback: DEFAULT_TEMPLATE_COLUMNS,
  anchor: 'Name',
};

/** Order-insensitive set comparison of two column selections. */
function sameColumns(a: readonly TemplateColumn[], b: readonly TemplateColumn[]): boolean {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((column) => set.has(column));
}

const ENTITY_FAMILIES: readonly EntityFamily[] = [
  'CommercialCompany',
  'Condominium',
  'Association',
  'Foundation',
  'Cooperative',
];

/** Keep the hundred-plus shipped templates scannable without rendering one enormous table body. */
const TEMPLATES_PAGE_SIZE = 25;

function searchText(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

type TemplateOriginFilter = '' | 'builtin' | 'user';

function templateMatches(
  template: TemplateSummary,
  query: string,
  translatedOrigin: string,
): boolean {
  if (!query) return true;
  const channelParts = template.channels.flatMap((channel) => [
    channel,
    meetingChannelLabels[channel],
  ]);
  const lawReferenceParts = (template.law_references ?? []).flatMap((reference) => [
    reference.source_id,
    reference.source_label,
    reference.article ?? '',
    reference.citation,
    reference.source,
    reference.verification,
    reference.threshold_id ?? '',
  ]);
  return [
    template.id,
    // Searching "conselho fiscal" must find the template now that the name is what is shown.
    templateDisplayName(template.id),
    template.locale,
    template.family,
    template.stage,
    template.rule_pack_id,
    template.signature_policy,
    template.source,
    translatedOrigin,
    entityFamilyLabels[template.family],
    lifecycleStageLabels[template.stage],
    signaturePolicyLabels[template.signature_policy],
    ...channelParts,
    ...lawReferenceParts,
  ].some((part) => searchText(part).includes(query));
}

/** Derive the export filename from the response `Content-Disposition`, or `<id>.json`. */
function exportFilename(id: string, headers: Headers): string {
  const disposition = headers.get('content-disposition') ?? '';
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition);
  if (match?.[1]) return decodeURIComponent(match[1].trim());
  return `${id.replace(/[\\/]/g, '-')}.json`;
}

function sortTemplates(a: TemplateSummary, b: TemplateSummary): number {
  return (
    a.family.localeCompare(b.family) ||
    a.stage.localeCompare(b.stage) ||
    a.rule_pack_id.localeCompare(b.rule_pack_id) ||
    a.locale.localeCompare(b.locale) ||
    a.id.localeCompare(b.id)
  );
}

export function TemplatesCatalogPage() {
  const t = useT();
  const ct = useTemplatesCatalogT();
  const toast = useToast();
  const templates = useTemplates();
  const exportTemplate = useExportTemplate();
  const deleteTemplate = useDeleteTemplate();
  const [importing, setImporting] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<TemplateSummary | null>(null);
  const [query, setQuery] = useState('');
  const deferredQuery = useDeferredValue(query);
  const [family, setFamily] = useState<EntityFamily | ''>('');
  const [stage, setStage] = useState<LifecycleStage | ''>('');
  const [locale, setLocale] = useState('');
  const [channel, setChannel] = useState<MeetingChannel | ''>('');
  const [signaturePolicy, setSignaturePolicy] = useState<SignaturePolicyHint | ''>('');
  const [rulePack, setRulePack] = useState('');
  const [origin, setOrigin] = useState<TemplateOriginFilter>('');
  const [page, setPage] = useState(1);
  // The visible columns are now a per-user server preference (t37), resolved through the shared
  // mechanism; the legacy device-local `localStorage` value is migrated once on first load below.
  const columns = useTableColumns(TEMPLATES_COLUMN_SPEC);
  const seededRef = useRef(false);
  useEffect(() => {
    if (seededRef.current || columns.loading) return;
    seededRef.current = true;
    // Only seed when the user has no server override yet AND the legacy device choice differs from
    // the product default — otherwise there is nothing meaningful to carry over.
    if (columns.overridden) return;
    const legacy = loadTemplateColumns();
    if (!sameColumns(legacy, DEFAULT_TEMPLATE_COLUMNS)) columns.set(legacy);
  }, [columns]);

  const allTemplates = useMemo(
    () => [...(templates.data ?? [])].sort(sortTemplates),
    [templates.data],
  );
  // Create / edit / fork are full pages now (t56); the controller navigates rather than opening a
  // modal, so it needs no id list or in-flight download state.
  const editor = useTemplateEditor();
  const locales = useMemo(
    () => Array.from(new Set(allTemplates.map((template) => template.locale))).sort(),
    [allTemplates],
  );
  const channels = useMemo(
    () =>
      MEETING_CHANNELS.filter((value) =>
        allTemplates.some((template) => template.channels.includes(value)),
      ),
    [allTemplates],
  );
  const signaturePolicies = useMemo(
    () => Array.from(new Set(allTemplates.map((template) => template.signature_policy))).sort(),
    [allTemplates],
  );
  const rulePacks = useMemo(
    () => Array.from(new Set(allTemplates.map((template) => template.rule_pack_id))).sort(),
    [allTemplates],
  );
  const normalizedQuery = searchText(deferredQuery.trim());
  const filtered = allTemplates.filter(
    (template) =>
      (!family || template.family === family) &&
      (!stage || template.stage === stage) &&
      (!locale || template.locale === locale) &&
      (!channel || template.channels.includes(channel)) &&
      (!signaturePolicy || template.signature_policy === signaturePolicy) &&
      (!rulePack || template.rule_pack_id === rulePack) &&
      (!origin || template.source === origin) &&
      templateMatches(
        template,
        normalizedQuery,
        template.source === 'user' ? t('templates.source.user') : t('templates.source.builtin'),
      ),
  );
  const hasFilters =
    query.trim() !== '' ||
    family !== '' ||
    stage !== '' ||
    locale !== '' ||
    channel !== '' ||
    signaturePolicy !== '' ||
    rulePack !== '' ||
    origin !== '';
  const pageCount = Math.max(1, Math.ceil(filtered.length / TEMPLATES_PAGE_SIZE));
  const currentPage = Math.min(page, pageCount);

  // Every filter change starts at the first matching row. Without this, a search made while on a
  // later page can truthfully have matches but momentarily show an empty page.
  useEffect(() => {
    setPage(1);
  }, [channel, deferredQuery, family, locale, origin, rulePack, signaturePolicy, stage]);

  function clearFilters() {
    setQuery('');
    setFamily('');
    setStage('');
    setLocale('');
    setChannel('');
    setSignaturePolicy('');
    setRulePack('');
    setOrigin('');
  }

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  async function onExport(template: TemplateSummary) {
    try {
      const download = await exportTemplate.mutateAsync(template.id);
      showSaveResult(
        await saveBlobAs({
          blob: download.blob,
          filename: exportFilename(template.id, download.headers),
          contentType: download.contentType || 'application/json',
          preferBrowserSavePicker: true,
        }),
      );
    } catch (err) {
      toast.error(err);
    }
  }

  async function onConfirmDelete(template: TemplateSummary) {
    await deleteTemplate.mutateAsync(template.id);
    toast.success(t('templates.toast.deleted', { id: template.id }));
    setDeleteTarget(null);
  }

  return (
    // `wide-page` widens the shell measure: the full column set does not fit the prose measure.
    <div className="stack wide-page templates-catalog-page">
      <PageHeader
        title={t('templates.title')}
        lede={t('templates.lede')}
        actions={
          <>
            <GateButton
              perm="template.manage"
              type="button"
              variant="secondary"
              icon={<Icon.Plus />}
              onClick={editor.create}
            >
              {t('templates.actions.new')}
            </GateButton>
            <GateButton
              perm="template.manage"
              type="button"
              variant="secondary"
              icon={<Icon.Tray />}
              onClick={() => setImporting(true)}
            >
              {t('templates.actions.import')}
            </GateButton>
            <ButtonLink to="/books" variant="primary" icon={<Icon.ArrowRight />}>
              {t('templates.openAct')}
            </ButtonLink>
          </>
        }
      />

      <InlineWarning tone="info" title={t('templates.noteTitle')}>
        {t('templates.noteBody')}
      </InlineWarning>

      <Card
        title={t('templates.catalog.title')}
        actions={
          allTemplates.length > 0 ? (
            <span aria-live="polite">
              <Badge>
                {t('templates.count', {
                  shown: filtered.length,
                  total: allTemplates.length,
                })}
              </Badge>
            </span>
          ) : null
        }
      >
        {templates.isLoading ? (
          <SkeletonRegion>
            <SkeletonTable cols={columns.visible.length + 2} />
          </SkeletonRegion>
        ) : templates.error ? (
          <ErrorNote error={templates.error} />
        ) : !templates.data || allTemplates.length === 0 ? (
          <EmptyState title={ct('templates.catalog.empty.title')}>
            <p>{ct('templates.catalog.empty.body')}</p>
          </EmptyState>
        ) : (
          <div
            className="stack templates-catalog__body"
            role="region"
            aria-label={t('templates.catalog.title')}
          >
            <div
              className="stack--tight templates-filters"
              role="search"
              aria-label={t('templates.filters.title')}
            >
              <div className="templates-filterbar filter">
                <div className="templates-filterbar__primary">
                  <Field label={t('templates.search.label')} htmlFor="templates-search">
                    <Input
                      id="templates-search"
                      value={query}
                      type="search"
                      placeholder={t('templates.search.placeholder')}
                      onChange={(event) => setQuery(event.target.value)}
                    />
                  </Field>
                  <Field label={t('templates.family.label')} htmlFor="templates-family">
                    <Select
                      id="templates-family"
                      value={family}
                      options={[
                        { value: '', label: t('templates.family.all') },
                        ...ENTITY_FAMILIES.map((value) => ({
                          value,
                          label: entityFamilyLabels[value],
                        })),
                      ]}
                      onChange={(event) => setFamily(event.target.value as EntityFamily | '')}
                    />
                  </Field>
                  <Field label={t('templates.stage.label')} htmlFor="templates-stage">
                    <Select
                      id="templates-stage"
                      value={stage}
                      options={[
                        { value: '', label: t('templates.stage.all') },
                        ...LIFECYCLE_STAGES.map((value) => ({
                          value,
                          label: lifecycleStageLabels[value],
                        })),
                      ]}
                      onChange={(event) => setStage(event.target.value as LifecycleStage | '')}
                    />
                  </Field>
                  <Field label={t('templates.table.source')} htmlFor="templates-origin">
                    <Select
                      id="templates-origin"
                      value={origin}
                      options={[
                        { value: '', label: ct('templates.catalog.source.all') },
                        { value: 'builtin', label: t('templates.source.builtin') },
                        { value: 'user', label: t('templates.source.user') },
                      ]}
                      onChange={(event) => setOrigin(event.target.value as TemplateOriginFilter)}
                    />
                  </Field>
                  <IconButton
                    className="templates-filterbar__clear"
                    icon={<Icon.Close />}
                    label={t('templates.clearFilters')}
                    disabled={!hasFilters}
                    onClick={clearFilters}
                  />
                </div>
              </div>

              <details className="templates-advanced-filters filter-advanced">
                <summary>{t('templates.filters.advanced')}</summary>
                <div className="templates-advanced-filters__body filter filter-advanced__body">
                  <Field label={t('templates.locale.label')} htmlFor="templates-locale">
                    <Select
                      id="templates-locale"
                      value={locale}
                      options={[
                        { value: '', label: t('templates.locale.all') },
                        ...locales.map((value) => ({ value, label: value })),
                      ]}
                      onChange={(event) => setLocale(event.target.value)}
                    />
                  </Field>
                  <Field label={t('templates.channel.label')} htmlFor="templates-channel">
                    <Select
                      id="templates-channel"
                      value={channel}
                      options={[
                        { value: '', label: t('templates.channel.all') },
                        ...channels.map((value) => ({
                          value,
                          label: meetingChannelLabels[value],
                        })),
                      ]}
                      onChange={(event) => setChannel(event.target.value as MeetingChannel | '')}
                    />
                  </Field>
                  <Field label={t('templates.signature.label')} htmlFor="templates-signature">
                    <Select
                      id="templates-signature"
                      value={signaturePolicy}
                      options={[
                        { value: '', label: t('templates.signature.all') },
                        ...signaturePolicies.map((value) => ({
                          value,
                          label: signaturePolicyLabels[value],
                        })),
                      ]}
                      onChange={(event) =>
                        setSignaturePolicy(event.target.value as SignaturePolicyHint | '')
                      }
                    />
                  </Field>
                  <Field label={t('templates.rulePack.label')} htmlFor="templates-rule-pack">
                    <Select
                      id="templates-rule-pack"
                      value={rulePack}
                      options={[
                        { value: '', label: t('templates.rulePack.all') },
                        ...rulePacks.map((value) => ({ value, label: value })),
                      ]}
                      onChange={(event) => setRulePack(event.target.value)}
                    />
                  </Field>
                </div>
              </details>
            </div>

            {/* Column visibility sits with the results, as it does on Books and Entities. */}
            <ColumnPicker
              columns={TEMPLATE_COLUMNS}
              label={t('templates.columns.label')}
              hint={t('templates.columns.hint')}
              isVisible={columns.isVisible}
              onToggle={columns.toggle}
              columnLabel={(column) => t(TEMPLATE_COLUMN_LABEL_KEYS[column])}
            />

            {filtered.length === 0 ? (
              <EmptyState title={t('templates.empty.title')}>
                <p>{t('templates.empty.body')}</p>
              </EmptyState>
            ) : (
              <TemplatesTable
                templates={filtered}
                visibleColumns={columns.visible}
                page={currentPage}
                pageSize={TEMPLATES_PAGE_SIZE}
                onPageChange={setPage}
                onEdit={editor.edit}
                onClone={editor.clone}
                onExport={(template) => void onExport(template)}
                onDelete={setDeleteTarget}
                exportPending={exportTemplate.isPending}
              />
            )}
          </div>
        )}
      </Card>

      {importing ? <TemplateImportDialog onClose={() => setImporting(false)} /> : null}

      <ConfirmActionModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        title={t('templates.actions.delete')}
        danger
        intro={deleteTarget ? t('templates.delete.confirm', { id: deleteTarget.id }) : ''}
        confirmLabel={t('templates.actions.delete')}
        pendingLabel={t('templates.actions.delete')}
        pending={deleteTemplate.isPending}
        onConfirm={async () => {
          if (deleteTarget) await onConfirmDelete(deleteTarget);
        }}
      />
    </div>
  );
}
