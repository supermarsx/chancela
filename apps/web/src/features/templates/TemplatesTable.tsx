/**
 * The Minutas catalog as a ledger-style table.
 *
 * The catalog used to be a card grid, which read as a wall of boxes once the built-in
 * corpus grew past a hundred documents: nothing lined up, so two templates could not be
 * compared without scrolling. A table lines the metadata up in columns and keeps every
 * per-row action the cards carried (edit / export / delete for user templates, plus an
 * explicit read-only preview and "escolher ata" for all of them).
 *
 * Sorting is deliberately small — four label columns, one state, no data grid. Rows keep
 * the catalog's own order (family → stage → rule pack → locale → id) until the reader
 * picks a column, so the default view is still the curated one.
 *
 * Which columns appear is the operator's choice (`templateColumns.ts`); `Name` and `Actions`
 * are structural and always render. A sort on a column that is then hidden is released rather
 * than left applied invisibly.
 */
import { useMemo, useState, type CSSProperties } from 'react';
import { Link } from 'react-router-dom';
import {
  entityFamilyLabels,
  lifecycleStageLabels,
  meetingChannelLabels,
  signaturePolicyLabels,
} from '../../api/labels';
import type { TemplateLawReference, TemplateSummary } from '../../api/types';
import { useT, type TFunction } from '../../i18n';
import { useTemplatesCatalogT } from '../../i18n/templatesCatalogFallback';
import { Badge, EmptyState, Icon, IconButton, Table, Tooltip, Truncate } from '../../ui';
import { GateIconButton } from '../session/permissions';
import type { TemplateColumn } from './templateColumns';
import { hasTemplateName, templateDisplayName } from './templateNames';
import { templateDetailPath, templatePreviewPath } from './templateRoutes';

type SortColumn = 'Name' | 'Family' | 'Stage' | 'Origin';
type SortDirection = 'asc' | 'desc';
interface SortState {
  column: SortColumn;
  direction: SortDirection;
}

/** Fixed-shape column widths; Name remains the one fluid, text-bearing column. */
const COLUMN_WIDTH_REM: Record<TemplateColumn, number> = {
  Family: 10,
  Stage: 8,
  Channels: 13,
  Signature: 14,
  RulePack: 11,
  LawSource: 18,
  Origin: 10,
};

/** Name + the maximum user-template action set, plus the currently visible metadata columns. */
function tableFloor(columns: readonly TemplateColumn[]): string {
  const fixed = columns.reduce((total, column) => total + COLUMN_WIDTH_REM[column], 0);
  return `${15 + 12.5 + fixed}rem`;
}

function lawReferenceKey(reference: TemplateLawReference, index: number): string {
  return [
    reference.source_id,
    reference.article ?? '',
    reference.citation,
    reference.threshold_id ?? '',
    index,
  ].join(':');
}

function lawReferenceTone(reference: TemplateLawReference): 'ok' | 'warn' {
  return reference.verification === 'Verified' ? 'ok' : 'warn';
}

function lawReferenceBadgeKey(
  reference: TemplateLawReference,
): 'legislacao.corpus.badge.verified' | 'legislacao.corpus.badge.pending' {
  return reference.verification === 'Verified'
    ? 'legislacao.corpus.badge.verified'
    : 'legislacao.corpus.badge.pending';
}

function lawReferenceSourceText(reference: TemplateLawReference): string {
  const article = reference.article?.trim();
  return [reference.source_label, article ? `art. ${article}` : ''].filter(Boolean).join(' · ');
}

function sourceLabel(template: TemplateSummary, t: TFunction): string {
  return template.source === 'user' ? t('templates.source.user') : t('templates.source.builtin');
}

/** The text a column sorts on — the rendered label, never the raw enum variant. */
function sortValue(template: TemplateSummary, column: SortColumn, t: TFunction): string {
  if (column === 'Family') return entityFamilyLabels[template.family];
  if (column === 'Stage') return lifecycleStageLabels[template.stage];
  if (column === 'Origin') return sourceLabel(template, t);
  return templateDisplayName(template.id);
}

function sortRows(
  templates: TemplateSummary[],
  sort: SortState | null,
  t: TFunction,
): TemplateSummary[] {
  if (!sort) return templates;
  const factor = sort.direction === 'asc' ? 1 : -1;
  return [...templates].sort(
    (left, right) =>
      factor *
      (sortValue(left, sort.column, t).localeCompare(sortValue(right, sort.column, t), 'pt') ||
        left.id.localeCompare(right.id)),
  );
}

function ariaSort(sort: SortState | null, column: SortColumn): 'ascending' | 'descending' | 'none' {
  if (sort?.column !== column) return 'none';
  return sort.direction === 'asc' ? 'ascending' : 'descending';
}

/**
 * A sortable column header. The button carries the column name and `aria-sort` on the
 * `<th>` carries the state, which is how assistive tech announces "sorted ascending"
 * without any extra copy to translate.
 */
function SortableHeader({
  column,
  label,
  sort,
  onSort,
}: {
  column: SortColumn;
  label: string;
  sort: SortState | null;
  onSort: (column: SortColumn) => void;
}) {
  const active = sort?.column === column;
  return (
    <th scope="col" data-template-column={column} aria-sort={ariaSort(sort, column)}>
      <button type="button" className="templates-table__sort" onClick={() => onSort(column)}>
        <span>{label}</span>
        <span className="templates-table__sort-marker" aria-hidden="true">
          {active && sort.direction === 'desc' ? <Icon.ArrowDown /> : <Icon.ArrowUp />}
        </span>
      </button>
    </th>
  );
}

export function TemplatesTable({
  templates,
  visibleColumns,
  onEdit,
  onClone,
  onExport,
  onDelete,
  page = 1,
  pageSize = 25,
  onPageChange,
  editPending = false,
  exportPending = false,
}: {
  templates: TemplateSummary[];
  /** The optional columns to render; `Name` and `Actions` are structural and always shown. */
  visibleColumns: readonly TemplateColumn[];
  onEdit: (template: TemplateSummary) => void;
  onClone: (template: TemplateSummary) => void;
  onExport: (template: TemplateSummary) => void;
  onDelete: (template: TemplateSummary) => void;
  /** One-based page over the fully filtered and sorted result set. */
  page?: number;
  pageSize?: number;
  onPageChange?: (page: number) => void;
  /** The spec download backing "editar" / "duplicar" is in flight. */
  editPending?: boolean;
  exportPending?: boolean;
}) {
  const t = useT();
  const ct = useTemplatesCatalogT();
  const [sort, setSort] = useState<SortState | null>(null);
  const shows = (column: TemplateColumn) => visibleColumns.includes(column);
  // A sort whose column the operator has since hidden is unreachable, so it is released
  // rather than left reordering the rows by something no longer on screen.
  const activeSort =
    sort && (sort.column === 'Name' || shows(sort.column as TemplateColumn)) ? sort : null;
  const rows = useMemo(() => sortRows(templates, activeSort, t), [templates, activeSort, t]);
  const pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
  const safePage = Math.min(Math.max(1, page), pageCount);
  const pageStart = (safePage - 1) * pageSize;
  const visibleRows = rows.slice(pageStart, pageStart + pageSize);
  const detailLabel = t('templates.detail.open');
  const previewLabel = ct('templates.catalog.preview.action');

  function toggleSort(column: SortColumn) {
    onPageChange?.(1);
    setSort((current) =>
      current?.column === column && current.direction === 'asc'
        ? { column, direction: 'desc' }
        : { column, direction: 'asc' },
    );
  }

  if (rows.length === 0) {
    return (
      <EmptyState title={t('templates.empty.title')}>
        <p>{t('templates.empty.body')}</p>
      </EmptyState>
    );
  }

  return (
    <div
      className="templates-table"
      style={{ '--templates-table-floor': tableFloor(visibleColumns) } as CSSProperties}
    >
      <Table
        caption={t('templates.catalog.title')}
        head={
          <tr>
            <SortableHeader
              column="Name"
              label={t('templates.card.id')}
              sort={activeSort}
              onSort={toggleSort}
            />
            {shows('Family') ? (
              <SortableHeader
                column="Family"
                label={t('templates.card.family')}
                sort={activeSort}
                onSort={toggleSort}
              />
            ) : null}
            {shows('Stage') ? (
              <SortableHeader
                column="Stage"
                label={t('templates.card.stage')}
                sort={activeSort}
                onSort={toggleSort}
              />
            ) : null}
            {shows('Channels') ? (
              <th scope="col" data-template-column="Channels">
                {t('templates.card.channels')}
              </th>
            ) : null}
            {shows('Signature') ? (
              <th scope="col" data-template-column="Signature">
                {t('templates.card.signature')}
              </th>
            ) : null}
            {shows('RulePack') ? (
              <th scope="col" data-template-column="RulePack">
                {t('templates.card.rulePack')}
              </th>
            ) : null}
            {shows('LawSource') ? (
              <th scope="col" data-template-column="LawSource">
                {t('documents.metadata.legalSource')}
              </th>
            ) : null}
            {shows('Origin') ? (
              <SortableHeader
                column="Origin"
                label={t('templates.table.source')}
                sort={activeSort}
                onSort={toggleSort}
              />
            ) : null}
            <th scope="col" data-template-column="Actions">
              <span className="sr-only">{t('templates.table.actions')}</span>
            </th>
          </tr>
        }
      >
        {visibleRows.map((template) => {
          const lawReferences = template.law_references ?? [];
          const isUser = template.source === 'user';
          return (
            <tr key={template.id}>
              <td data-template-column="Name">
                {/* Name first, id second: the `/vN` pins provenance, so it is demoted, not
                    dropped. An unnamed template keeps the id as its only label. */}
                <Link
                  className="templates-table__open"
                  to={templateDetailPath(template.id)}
                  aria-label={detailLabel}
                >
                  {hasTemplateName(template.id) ? (
                    <span className="templates-table__name">
                      {templateDisplayName(template.id)}
                    </span>
                  ) : null}
                  <code className="templates-table__id">{template.id}</code>
                </Link>
              </td>
              {shows('Family') ? (
                <td data-template-column="Family">
                  <Truncate text={entityFamilyLabels[template.family]} />
                </td>
              ) : null}
              {shows('Stage') ? (
                <td data-template-column="Stage">
                  <Truncate text={lifecycleStageLabels[template.stage]} />
                </td>
              ) : null}
              {shows('Channels') ? (
                <td data-template-column="Channels">
                  {template.channels.length > 0 ? (
                    <Truncate
                      text={template.channels
                        .map((value) => meetingChannelLabels[value])
                        .join(', ')}
                    />
                  ) : (
                    <span className="muted">{t('templates.channels.none')}</span>
                  )}
                </td>
              ) : null}
              {shows('Signature') ? (
                <td data-template-column="Signature">
                  <Truncate text={signaturePolicyLabels[template.signature_policy]} />
                </td>
              ) : null}
              {shows('RulePack') ? (
                <td data-template-column="RulePack">
                  <code className="templates-table__code">{template.rule_pack_id}</code>
                </td>
              ) : null}
              {shows('LawSource') ? (
                <td data-template-column="LawSource">
                  {lawReferences.length > 0 ? (
                    <div className="stack--tight">
                      {lawReferences.map((reference, index) => (
                        <div key={lawReferenceKey(reference, index)} className="stack--tight">
                          <span className="templates-table__badges">
                            <Badge tone={lawReferenceTone(reference)}>
                              {t(lawReferenceBadgeKey(reference))}
                            </Badge>
                            <span className="mono">{reference.citation}</span>
                          </span>
                          <span className="muted">
                            {t('legislacao.corpus.article.source')}:{' '}
                            {lawReferenceSourceText(reference)}
                          </span>
                          {reference.verification === 'Pending' ? (
                            <span className="muted">{t('legislacao.citations.pendingNote')}</span>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
              ) : null}
              {shows('Origin') ? (
                <td data-template-column="Origin">
                  <span className="templates-table__badges">
                    <Badge tone={isUser ? 'accent' : 'neutral'}>{sourceLabel(template, t)}</Badge>
                    <Badge tone="accent">{template.locale}</Badge>
                  </span>
                </td>
              ) : null}
              <td data-template-column="Actions">
                <span className="templates-table__actions">
                  <Tooltip label={previewLabel}>
                    <Link
                      className="btn btn--ghost btn--icon btn--iconOnly"
                      to={templatePreviewPath(template.id)}
                      aria-label={previewLabel}
                    >
                      <span className="btn__icon" aria-hidden="true">
                        <Icon.FileText />
                      </span>
                    </Link>
                  </Tooltip>
                  {/* "Editar" is offered on a BUILT-IN too, and opens a fork dialog rather
                      than an in-place editor (see `useTemplateEditor`). Withholding it left
                      the operator no route at all from a shipped template to an editable one. */}
                  <GateIconButton
                    perm="template.manage"
                    icon={<Icon.Pencil />}
                    label={t('templates.actions.edit')}
                    disabled={editPending}
                    onClick={() => onEdit(template)}
                  />
                  <GateIconButton
                    perm="template.manage"
                    icon={<Icon.Copy />}
                    label={t('templates.actions.clone')}
                    disabled={editPending}
                    onClick={() => onClone(template)}
                  />
                  {isUser ? (
                    <>
                      <GateIconButton
                        perm="template.manage"
                        icon={<Icon.Archive />}
                        label={t('templates.actions.export')}
                        disabled={exportPending}
                        onClick={() => onExport(template)}
                      />
                      <GateIconButton
                        perm="template.manage"
                        icon={<Icon.Trash />}
                        label={t('templates.actions.delete')}
                        onClick={() => onDelete(template)}
                      />
                    </>
                  ) : null}
                </span>
              </td>
            </tr>
          );
        })}
      </Table>
      {pageCount > 1 ? (
        <nav className="templates-pagination" aria-label={ct('templates.catalog.pagination.aria')}>
          <span className="muted" aria-live="polite">
            {ct('templates.catalog.pagination.range', {
              from: pageStart + 1,
              to: Math.min(pageStart + pageSize, rows.length),
              total: rows.length,
            })}
            {' · '}
            {ct('templates.catalog.pagination.page', {
              current: safePage,
              total: pageCount,
            })}
          </span>
          <span className="templates-pagination__actions">
            <IconButton
              icon={<Icon.ArrowLeft />}
              label={ct('templates.catalog.pagination.previous')}
              disabled={safePage === 1}
              onClick={() => onPageChange?.(safePage - 1)}
            />
            <IconButton
              icon={<Icon.ArrowRight />}
              label={ct('templates.catalog.pagination.next')}
              disabled={safePage === pageCount}
              onClick={() => onPageChange?.(safePage + 1)}
            />
          </span>
        </nav>
      ) : null}
    </div>
  );
}
