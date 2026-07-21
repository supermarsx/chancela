/**
 * One template, on its own page.
 *
 * The catalog used to be a dead end: a row could be sorted and filtered but never opened, so
 * the only way to see what a template actually IS was to export its JSON and read it. This is
 * the ninth surface on the shared `<SubNav>` + `?sec=` idiom (`ui/SubNav.tsx`), matching the
 * entity and book detail pages rather than inventing a second sub-tab convention.
 *
 * Four sections, in the order the questions get asked:
 *   Identificação — id, version, family, stage, channels, signature policy, rule pack, origin;
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
import type { ReactNode } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { useTemplateSpec, useTemplates } from '../../api/hooks';
import {
  entityFamilyLabels,
  lifecycleStageLabels,
  meetingChannelLabels,
  signaturePolicyLabels,
} from '../../api/labels';
import type { TemplateBlockSpec, TemplateSummary } from '../../api/types';
import { useT, type MessageKey, type TFunction } from '../../i18n';
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
import { GateButton } from '../session/permissions';
import { TemplateEditorForm } from './TemplateEditorForm';
import { templateIdBase, templateIdVersion } from './templateFork';
import { hasTemplateName, templateDisplayName } from './templateNames';
import { templatePlaceholders } from './templatePlaceholders';
import { useTemplateEditor } from './useTemplateEditor';

type TemplateSection = 'identificacao' | 'fonte' | 'blocos' | 'campos';

const TEMPLATE_SECTIONS: { id: TemplateSection; label: MessageKey; icon: ReactNode }[] = [
  { id: 'identificacao', label: 'templates.detail.section.overview', icon: <Icon.Layers /> },
  { id: 'fonte', label: 'documents.metadata.legalSource', icon: <Icon.Scale /> },
  { id: 'blocos', label: 'templates.editor.field.blocks.label', icon: <Icon.Layers /> },
  { id: 'campos', label: 'templates.detail.section.placeholders', icon: <Icon.Search /> },
];

const isTemplateSection = (value: string | null): value is TemplateSection =>
  TEMPLATE_SECTIONS.some((section) => section.id === value);

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
    default:
      return '';
  }
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
  const { id = '' } = useParams();
  const [params, setParams] = useSearchParams();
  const secParam = params.get('sec');
  // Identificação is the default and carries no `sec` param, so `/minutas/:id` still lands on it.
  const section: TemplateSection = isTemplateSection(secParam) ? secParam : 'identificacao';
  const selectSection = (next: TemplateSection) =>
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      if (next === 'identificacao') p.delete('sec');
      else p.set('sec', next);
      return p;
    });

  const templates = useTemplates();
  const template = (templates.data ?? []).find((row) => row.id === id);
  const spec = useTemplateSpec(id, template !== undefined);
  const editor = useTemplateEditor((templates.data ?? []).map((row) => row.id));

  if (templates.isLoading) {
    return (
      <div className="stack">
        <PageHeader
          crumbs={<Link to="/minutas">{t('templates.title')}</Link>}
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
          crumbs={<Link to="/minutas">{t('templates.title')}</Link>}
          // The id as typed, not the message: it is the one thing the operator can check.
          title={<code className="mono">{id}</code>}
        />
        <EmptyState title={t('templates.detail.notFound.title')}>
          <p>{t('templates.detail.notFound.body')}</p>
          <p>
            <Link to="/minutas">{t('templates.title')}</Link>
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
            <Link to="/minutas">{t('templates.title')}</Link> · {template.id}
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
              disabled={editor.pending}
              onClick={() => editor.edit(template)}
            >
              {t('templates.actions.edit')}
            </GateButton>
            <GateButton
              perm="template.manage"
              type="button"
              variant="secondary"
              icon={<Icon.Copy />}
              disabled={editor.pending}
              onClick={() => editor.clone(template)}
            >
              {t('templates.actions.clone')}
            </GateButton>
            <ButtonLink to="/livros" variant="primary" icon={<Icon.ArrowRight />}>
              {t('templates.openAct')}
            </ButtonLink>
          </>
        }
      >
        <SubNav
          items={TEMPLATE_SECTIONS.map((s) => ({ id: s.id, label: t(s.label), icon: s.icon }))}
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
        {section === 'identificacao' ? (
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

        {section === 'fonte' ? (
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

        {section === 'blocos' ? (
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

        {section === 'campos' ? (
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

      {editor.state ? (
        <TemplateEditorForm
          mode={editor.state.mode}
          initialSpec={editor.state.mode === 'create' ? null : editor.state.spec}
          sourceId={editor.state.mode === 'fork' ? editor.state.sourceId : undefined}
          sourceIsBuiltin={editor.state.mode === 'fork' ? editor.state.sourceIsBuiltin : undefined}
          onClose={editor.close}
        />
      ) : null}
    </div>
  );
}
