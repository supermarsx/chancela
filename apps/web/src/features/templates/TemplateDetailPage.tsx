/**
 * One template, on its own page.
 *
 * The catalog used to be a dead end: a row could be sorted and filtered but never opened, so
 * the only way to see what a template actually IS was to export its JSON and read it. This is
 * the ninth surface on the shared `<SubNav>` + path-segment idiom (`ui/SubNav.tsx`), matching the
 * entity and book detail pages rather than inventing a second sub-tab convention.
 *
 * Five sections, in the order the questions get asked:
 *   Identificação — id, version, family, stage, channels, signature policy, rule pack, origin;
 *   Pré-visualização — the authored structure in document form, with merge fields unresolved;
 *   Fonte legal   — the law references, in full. This is where they belong now that the
 *                   catalog table hides that column by default (`templateColumns.ts`);
 *   Blocos        — the authored block structure, in document order;
 *   Campos        — the record fields the blocks read (`templatePlaceholders.ts`).
 *
 * The route id is URL-encoded because a template id contains a slash (`csc-ata-ag/v1`), which
 * `useParams` hands back decoded — the same encoding the API client already applies.
 *
 * There is no `GET /v1/templates/{id}`: metadata comes from the catalog list and the body from
 * the export endpoint, so this page joins two reads that the API does not join for it.
 */
import { useEffect, type ReactNode } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useTemplateBodyPreview, useTemplateBundle, useTemplates } from '../../api/hooks';
import {
  entityFamilyLabels,
  lifecycleStageLabels,
  meetingChannelLabels,
  signaturePolicyLabels,
} from '../../api/labels';
import type { TemplateBlockSpec, TemplateSummary } from '../../api/types';
import { useT, type MessageKey, type TFunction } from '../../i18n';
import { useTemplatesCatalogT } from '../../i18n/templatesCatalogFallback';
import {
  Badge,
  ButtonLink,
  Card,
  EmptyState,
  ErrorNote,
  Icon,
  InlineWarning,
  PageHeader,
  Skeleton,
  SkeletonDeflist,
  SubNav,
  Table,
} from '../../ui';
import { useSectionNav } from '../../app/navPath';
import { GateButton } from '../session/permissions';
import { TemplateEditPage } from './TemplateEditPage';
import { templateIdBase, templateIdVersion } from './templateFork';
import {
  TemplateAuthoredPreview,
  type TemplateNarrativePreviewState,
} from './TemplateAuthoredPreview';
import { hasTemplateName, templateDisplayName } from './templateNames';
import { templatePlaceholders } from './templatePlaceholders';
import { useTemplateEditor } from './useTemplateEditor';

/**
 * `edit` is a SECTION of the template route, not a segment reserved beside `:sec?` (t109, on the
 * lead's ruling). A path names *where you are*; the editor is the same record in a different pane,
 * which is exactly what a section is. The practical reason is stronger than the aesthetic one: a
 * special-cased `/edit` sitting next to `/templates/:id/:sec?` would silently shadow any future
 * section that happened to be spelled `edit`, and route-shadowing bugs of that shape are invisible
 * in review. A closed set with one more member cannot shadow anything, and `edit` inherits the
 * existing unknown-segment fallback and deep-link-on-first-paint behaviour for free.
 */
type TemplateSection = 'identification' | 'preview' | 'source' | 'blocks' | 'fields' | 'edit';

/** The sections shown in the SubNav strip — the five READ views. See `EDIT_SECTION` below. */
const TEMPLATE_SECTIONS: {
  id: TemplateSection;
  label: MessageKey | null;
  icon: ReactNode;
}[] = [
  { id: 'identification', label: 'templates.detail.section.overview', icon: <Icon.Layers /> },
  { id: 'preview', label: null, icon: <Icon.FileText /> },
  { id: 'source', label: 'documents.metadata.legalSource', icon: <Icon.Scale /> },
  { id: 'blocks', label: 'templates.editor.field.blocks.label', icon: <Icon.Layers /> },
  { id: 'fields', label: 'templates.detail.section.placeholders', icon: <Icon.Search /> },
];

/**
 * `edit` is a member of the validated section set but deliberately NOT of the SubNav strip.
 *
 * The strip is offered identically for every template, and a built-in must never be offered
 * in-place editing — its spec digest is pinned and bound into past `document.generated` events,
 * so rewriting it retroactively changes what a seal meant. Putting `edit` in the strip would
 * advertise it on built-ins. It is reached by the Editar button (which diverts a built-in to the
 * fork dialog) and by deep link (which is gated below, on the section rather than the button).
 */
const EDIT_SECTION = 'edit' as const;

const isTemplateSection = (value: string | undefined): value is TemplateSection =>
  value === EDIT_SECTION || TEMPLATE_SECTIONS.some((section) => section.id === value);

/**
 * A one-line summary of a block, in the block's OWN terms.
 *
 * Block kinds and their minijinja source are authored artefacts, not UI chrome: they are
 * rendered verbatim in every locale, the same boundary `TRANSLATIONS.md` documents for the
 * legislation shelf. Inventing a Danish word for `VoteTable` would name something that does
 * not exist in the file.
 */
function blockSummary(block: TemplateBlockSpec): string {
  switch (block.kind) {
    case 'Heading':
      return block.template;
    case 'Paragraph':
      return block.template;
    case 'KeyValue':
      return block.rows.map((row) => row.key).join(' · ');
    case 'VoteTable':
      return block.label;
    case 'SignatureBlock':
      return `${block.role} · ${block.name}`;
    case 'NarrativeBody':
      return 'NarrativeBody';
    default:
      return '';
  }
}

/**
 * Compile the bundle's real narrative seed once and pass it to the shared authored renderer.
 *
 * A template can contain more than one `NarrativeBody` marker; compilation still happens once and
 * the same authoritative result is inserted at every authored marker in document order.
 */
function TemplateDetailAuthoredPreview({
  template,
  blocks,
  bodyMarkdown,
}: {
  template: TemplateSummary;
  blocks: TemplateBlockSpec[];
  bodyMarkdown: string;
}) {
  const preview = useTemplateBodyPreview();
  const mutate = preview.mutate;

  useEffect(() => {
    if (bodyMarkdown.trim()) mutate({ source: bodyMarkdown });
  }, [bodyMarkdown, mutate]);

  const title = hasTemplateName(template.id) ? templateDisplayName(template.id) : template.id;
  const narrative: TemplateNarrativePreviewState = !bodyMarkdown.trim()
    ? { status: 'empty' }
    : preview.isIdle || preview.isPending
      ? { status: 'loading' }
      : preview.error
        ? {
            status: 'error',
            diagnostic:
              preview.error instanceof Error ? preview.error.message : String(preview.error),
          }
        : { status: 'ready', blocks: preview.data?.blocks ?? [] };

  return (
    <TemplateAuthoredPreview
      title={title}
      templateId={template.id}
      locale={template.locale}
      blocks={blocks}
      narrative={narrative}
    />
  );
}

function DefRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function sourceLabel(template: TemplateSummary, t: TFunction): string {
  return template.source === 'user' ? t('templates.source.user') : t('templates.source.builtin');
}

export function TemplateDetailPage() {
  const t = useT();
  const ct = useTemplatesCatalogT();
  const { id = '' } = useParams();
  // Identificação is the default and carries no segment, so `/templates/:id` still lands on it.
  // The base is sliced off the RAW pathname, so the `%2F` inside an id like `csc-ata-ag/v1`
  // is carried through untouched rather than re-encoded from the decoded `useParams` value.
  const { section, select: selectSection } = useSectionNav<TemplateSection>({
    depth: 2,
    parse: (raw) => (isTemplateSection(raw) ? raw : 'identification'),
    fallback: 'identification',
  });

  const templates = useTemplates();
  const template = (templates.data ?? []).find((row) => row.id === id);
  const bundle = useTemplateBundle(id, template !== undefined);
  // Keep the existing spec-state vocabulary below while retaining the bundle's narrative seed
  // for the read-only preview.
  const spec = {
    data: bundle.data?.spec,
    error: bundle.error,
    isLoading: bundle.isLoading,
  };
  // Edit / duplicate are full pages now (t56); the controller navigates rather than opening a modal.
  const editor = useTemplateEditor();

  // The edit section is a full-width page of its own rather than a panel inside this one: a
  // template body is canonical BlockSpec JSON and needs the whole measure. It is a separate
  // component, so it owns its own loading, draft and unsaved-changes state — and it re-checks
  // that the template is user-authored itself, because a deep link reaches it without passing
  // any button. Every hook above has already run, so this early return is unconditional in
  // hook order.
  if (section === EDIT_SECTION) return <TemplateEditPage />;

  if (templates.isLoading) {
    return (
      <div className="stack">
        <PageHeader
          crumbs={<Link to="/templates">{t('templates.title')}</Link>}
          title={<Skeleton width="18rem" height="1.6rem" />}
        />
        <Card title={t('templates.detail.section.overview')}>
          <SkeletonDeflist />
        </Card>
      </div>
    );
  }
  if (templates.error) return <ErrorNote error={templates.error} />;
  if (!template) {
    return (
      <div className="stack">
        <PageHeader
          crumbs={<Link to="/templates">{t('templates.title')}</Link>}
          // The id as typed, not the message: it is the one thing the operator can check.
          title={<code className="mono">{id}</code>}
        />
        <EmptyState title={t('templates.detail.notFound.title')}>
          <p>{t('templates.detail.notFound.body')}</p>
          <p>
            <Link to="/templates">{t('templates.title')}</Link>
          </p>
        </EmptyState>
      </div>
    );
  }

  const isUser = template.source === 'user';
  const name = hasTemplateName(template.id) ? templateDisplayName(template.id) : template.id;
  const lawReferences = template.law_references ?? [];
  const placeholders = spec.data ? templatePlaceholders(spec.data) : [];

  return (
    <div className="stack">
      <PageHeader
        crumbs={
          <>
            <Link to="/templates">{t('templates.title')}</Link> · {template.id}
          </>
        }
        title={name}
        actions={
          <>
            <GateButton
              perm="template.manage"
              type="button"
              variant="secondary"
              icon={<Icon.Pencil />}
              onClick={() => editor.edit(template)}
            >
              {t('templates.actions.edit')}
            </GateButton>
            <GateButton
              perm="template.manage"
              type="button"
              variant="secondary"
              icon={<Icon.Copy />}
              onClick={() => editor.clone(template)}
            >
              {t('templates.actions.clone')}
            </GateButton>
            <ButtonLink to="/books" variant="primary" icon={<Icon.ArrowRight />}>
              {t('templates.openAct')}
            </ButtonLink>
          </>
        }
      >
        <SubNav
          items={TEMPLATE_SECTIONS.map((s) => ({
            id: s.id,
            label: s.label ? t(s.label) : ct('templates.catalog.preview.action'),
            icon: s.icon,
          }))}
          active={section}
          onSelect={selectSection}
          ariaLabel={t('templates.detail.subnav.aria')}
        />
      </PageHeader>

      {/* A user template is offered by every picker but refused by the seal. Stated on the
          template itself, not only in the dialog that created it — an operator who comes back
          to a copy tomorrow gets the same answer as the one who forked it today. */}
      {isUser ? (
        <InlineWarning tone="warn" title={t('templates.fork.limit.title')}>
          <p>{t('templates.fork.limit.body')}</p>
        </InlineWarning>
      ) : null}

      <div className="route-transition stack" key={section}>
        {section === 'identification' ? (
          <Card title={t('templates.detail.section.overview')}>
            <dl className="deflist">
              <DefRow label={t('templates.card.id')}>
                <code className="mono">{templateIdBase(template.id)}</code>
              </DefRow>
              <DefRow label={t('templates.detail.version')}>
                <code className="mono">{templateIdVersion(template.id) || '—'}</code>
              </DefRow>
              <DefRow label={t('templates.card.family')}>
                {entityFamilyLabels[template.family]}
              </DefRow>
              <DefRow label={t('templates.card.stage')}>
                {lifecycleStageLabels[template.stage]}
              </DefRow>
              <DefRow label={t('templates.card.channels')}>
                {template.channels.length > 0 ? (
                  <span className="templates-table__badges">
                    {template.channels.map((channel) => (
                      <Badge key={channel}>{meetingChannelLabels[channel]}</Badge>
                    ))}
                  </span>
                ) : (
                  <span className="muted">{t('templates.channels.none')}</span>
                )}
              </DefRow>
              <DefRow label={t('templates.card.signature')}>
                {signaturePolicyLabels[template.signature_policy]}
              </DefRow>
              <DefRow label={t('templates.card.rulePack')}>
                <code className="mono">{template.rule_pack_id}</code>
              </DefRow>
              <DefRow label={t('templates.locale.label')}>
                <Badge tone="accent">{template.locale}</Badge>
              </DefRow>
              <DefRow label={t('templates.table.source')}>
                <Badge tone={isUser ? 'accent' : 'neutral'}>{sourceLabel(template, t)}</Badge>
              </DefRow>
            </dl>
          </Card>
        ) : null}

        {section === 'preview' ? (
          <Card title={ct('templates.catalog.preview.title')}>
            <p className="field__hint">{ct('templates.catalog.preview.hint')}</p>
            {spec.isLoading ? (
              <SkeletonDeflist />
            ) : spec.error ? (
              <p className="muted">{t('templates.detail.spec.error')}</p>
            ) : (spec.data?.blocks ?? []).length === 0 ? (
              <p className="muted">{t('templates.detail.blocks.empty')}</p>
            ) : (
              <TemplateDetailAuthoredPreview
                template={template}
                blocks={spec.data?.blocks ?? []}
                bodyMarkdown={bundle.data?.body_markdown ?? ''}
              />
            )}
          </Card>
        ) : null}

        {section === 'source' ? (
          <Card title={t('documents.metadata.legalSource')}>
            {lawReferences.length === 0 ? (
              <p className="muted">{t('templates.detail.lawSource.empty')}</p>
            ) : (
              <div className="stack--tight">
                {lawReferences.map((reference, index) => (
                  <div
                    key={`${reference.source_id}:${reference.citation}:${index}`}
                    className="stack--tight"
                  >
                    <span className="templates-table__badges">
                      <Badge tone={reference.verification === 'Verified' ? 'ok' : 'warn'}>
                        {t(
                          reference.verification === 'Verified'
                            ? 'legislacao.corpus.badge.verified'
                            : 'legislacao.corpus.badge.pending',
                        )}
                      </Badge>
                      <span className="mono">{reference.citation}</span>
                    </span>
                    <span className="muted">
                      {t('legislacao.corpus.article.source')}: {reference.source_label}
                      {reference.article ? ` · art. ${reference.article}` : ''}
                    </span>
                    {reference.verification === 'Pending' ? (
                      <span className="muted">{t('legislacao.citations.pendingNote')}</span>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </Card>
        ) : null}

        {section === 'blocks' ? (
          <Card title={t('templates.editor.field.blocks.label')}>
            {spec.isLoading ? (
              <SkeletonDeflist />
            ) : spec.error ? (
              <p className="muted">{t('templates.detail.spec.error')}</p>
            ) : (spec.data?.blocks ?? []).length === 0 ? (
              <p className="muted">{t('templates.detail.blocks.empty')}</p>
            ) : (
              <Table
                caption={t('templates.editor.field.blocks.label')}
                head={
                  <tr>
                    <th scope="col">#</th>
                    <th scope="col">{t('templates.card.id')}</th>
                    <th scope="col">{t('templates.detail.section.overview')}</th>
                  </tr>
                }
              >
                {(spec.data?.blocks ?? []).map((block, index) => (
                  <tr key={`${block.kind}:${index}`}>
                    <td className="mono">{index + 1}</td>
                    <td>
                      <code className="templates-table__code">{block.kind}</code>
                    </td>
                    <td>
                      <span className="mono">{blockSummary(block)}</span>
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
        ) : null}

        {section === 'fields' ? (
          <Card title={t('templates.detail.section.placeholders')}>
            <p className="field__hint">{t('templates.detail.placeholders.intro')}</p>
            {spec.isLoading ? (
              <SkeletonDeflist />
            ) : spec.error ? (
              <p className="muted">{t('templates.detail.spec.error')}</p>
            ) : placeholders.length === 0 ? (
              <p className="muted">{t('templates.detail.placeholders.empty')}</p>
            ) : (
              <span className="templates-table__badges">
                {placeholders.map((placeholder) => (
                  <code key={placeholder} className="templates-table__code">
                    {placeholder}
                  </code>
                ))}
              </span>
            )}
          </Card>
        ) : null}
      </div>
    </div>
  );
}
