import { useMemo, useState } from 'react';
import { useDeleteTemplate, useExportTemplate, useTemplates } from '../../api/hooks';
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
import {
  ButtonLink,
  Card,
  ConfirmActionModal,
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
import { TemplateEditorForm } from './TemplateEditorForm';
import {
  TEMPLATE_COLUMNS,
  loadTemplateColumns,
  saveTemplateColumns,
  type TemplateColumn,
} from './templateColumns';
import { templateDisplayName } from './templateNames';
import { TemplateImportDialog } from './TemplateImportDialog';
import { TemplatesTable } from './TemplatesTable';
import { useTemplateEditor } from './useTemplateEditor';

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

const ENTITY_FAMILIES: readonly EntityFamily[] = [
  'CommercialCompany',
  'Condominium',
  'Association',
  'Foundation',
  'Cooperative',
];

function searchText(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function templateMatches(template: TemplateSummary, query: string): boolean {
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
  const toast = useToast();
  const templates = useTemplates();
  const exportTemplate = useExportTemplate();
  const deleteTemplate = useDeleteTemplate();
  const [importing, setImporting] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<TemplateSummary | null>(null);
  const [query, setQuery] = useState('');
  const [family, setFamily] = useState<EntityFamily | ''>('');
  const [stage, setStage] = useState<LifecycleStage | ''>('');
  const [locale, setLocale] = useState('');
  const [channel, setChannel] = useState<MeetingChannel | ''>('');
  const [signaturePolicy, setSignaturePolicy] = useState<SignaturePolicyHint | ''>('');
  const [rulePack, setRulePack] = useState('');
  // Read once on mount: the stored set is this device's, and nothing else writes it.
  const [columns, setColumns] = useState<TemplateColumn[]>(loadTemplateColumns);

  const allTemplates = useMemo(
    () => [...(templates.data ?? [])].sort(sortTemplates),
    [templates.data],
  );
  const editor = useTemplateEditor(
    useMemo(() => allTemplates.map((row) => row.id), [allTemplates]),
  );
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
  const normalizedQuery = searchText(query.trim());
  const filtered = allTemplates.filter(
    (template) =>
      (!family || template.family === family) &&
      (!stage || template.stage === stage) &&
      (!locale || template.locale === locale) &&
      (!channel || template.channels.includes(channel)) &&
      (!signaturePolicy || template.signature_policy === signaturePolicy) &&
      (!rulePack || template.rule_pack_id === rulePack) &&
      templateMatches(template, normalizedQuery),
  );
  const hasFilters =
    query.trim() !== '' ||
    family !== '' ||
    stage !== '' ||
    locale !== '' ||
    channel !== '' ||
    signaturePolicy !== '' ||
    rulePack !== '';

  function toggleColumn(column: TemplateColumn, checked: boolean) {
    setColumns((current) => {
      const next = TEMPLATE_COLUMNS.filter((candidate) =>
        candidate === column ? checked : current.includes(candidate),
      );
      saveTemplateColumns(next);
      return next;
    });
  }

  function clearFilters() {
    setQuery('');
    setFamily('');
    setStage('');
    setLocale('');
    setChannel('');
    setSignaturePolicy('');
    setRulePack('');
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
    <div className="stack wide-page">
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
            <ButtonLink to="/livros" variant="primary" icon={<Icon.ArrowRight />}>
              {t('templates.openAct')}
            </ButtonLink>
          </>
        }
      />

      <InlineWarning tone="info" title={t('templates.noteTitle')}>
        {t('templates.noteBody')}
      </InlineWarning>

      <Card title={t('templates.filters.title')}>
        <div
          className="stack--tight templates-filters"
          role="search"
          aria-label={t('templates.filters.title')}
        >
          <fieldset className="templates-controls">
            <legend className="sr-only">{t('templates.filters.title')}</legend>
            <div className="templates-filterbar filter">
              <div className="templates-controls__primary templates-filterbar__primary">
                <div className="templates-controls__search templates-filterbar__search">
                  <Field label={t('templates.search.label')} htmlFor="templates-search">
                    <div className="templates-search-control">
                      <span className="templates-search-control__icon" aria-hidden="true">
                        <Icon.Search />
                      </span>
                      <Input
                        id="templates-search"
                        value={query}
                        type="search"
                        placeholder={t('templates.search.placeholder')}
                        onChange={(event) => setQuery(event.target.value)}
                      />
                    </div>
                  </Field>
                </div>
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
                <div className="templates-controls__actions templates-filterbar__clear">
                  <IconButton
                    icon={<Icon.Close />}
                    label={t('templates.clearFilters')}
                    disabled={!hasFilters}
                    onClick={clearFilters}
                  />
                </div>
              </div>
            </div>

            <details className="templates-controls__advanced templates-advanced-filters filter-advanced">
              <summary>{t('templates.filters.advanced')}</summary>
              <div className="templates-controls__filters templates-advanced-filters__body filter filter-advanced__body">
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
          </fieldset>
        </div>
      </Card>

      <section className="stack--tight" aria-labelledby="templates-catalog-title">
        <div className="templates-results-head">
          <h3 id="templates-catalog-title" className="panel__title">
            {t('templates.catalog.title')}
          </h3>
          <span className="muted">
            {t('templates.count', {
              shown: filtered.length,
              total: allTemplates.length,
            })}
          </span>
        </div>

        {/* Column visibility sits with the RESULTS, not with the search: it decides what the
            table shows, not which rows it holds. "Fonte legal" is off by default — a badge, a
            citation, a source line and sometimes a pending note per reference, which squeezed
            the other columns to slivers — and the template's own page always carries it in
            full, so nothing is out of reach. */}
        <details className="templates-columns filter-advanced">
          <summary>{t('templates.columns.label')}</summary>
          <fieldset className="templates-columns__body filter-advanced__body">
            <legend className="sr-only">{t('templates.columns.label')}</legend>
            <p className="field__hint">{t('templates.columns.hint')}</p>
            <div className="row-wrap">
              {TEMPLATE_COLUMNS.map((column) => (
                <label key={column} className="checkline">
                  <input
                    type="checkbox"
                    checked={columns.includes(column)}
                    onChange={(event) => toggleColumn(column, event.target.checked)}
                  />
                  {t(TEMPLATE_COLUMN_LABEL_KEYS[column])}
                </label>
              ))}
            </div>
          </fieldset>
        </details>

        {templates.isLoading ? (
          <SkeletonRegion>
            <SkeletonTable cols={columns.length + 2} />
          </SkeletonRegion>
        ) : templates.error ? (
          <ErrorNote error={templates.error} />
        ) : (
          <TemplatesTable
            templates={filtered}
            visibleColumns={columns}
            onEdit={editor.edit}
            onClone={editor.clone}
            onExport={(template) => void onExport(template)}
            onDelete={setDeleteTarget}
            editPending={editor.pending}
            exportPending={exportTemplate.isPending}
          />
        )}
      </section>

      {editor.state ? (
        <TemplateEditorForm
          mode={editor.state.mode}
          initialSpec={editor.state.mode === 'create' ? null : editor.state.spec}
          sourceId={editor.state.mode === 'fork' ? editor.state.sourceId : undefined}
          sourceIsBuiltin={editor.state.mode === 'fork' ? editor.state.sourceIsBuiltin : undefined}
          onClose={editor.close}
        />
      ) : null}

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
