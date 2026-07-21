/**
 * TemplateEditPage — a user template's own full-width editing surface (t109).
 *
 * ## Why a page rather than the modal
 *
 * A template body is the widest content in the app: canonical `BlockSpec` JSON with nested
 * minijinja. The modal (`TemplateEditorForm`) gave it a 12-row textarea inside a dialog whose
 * measure is the prose measure. This page opts into `.wide-page` (the shared shell opt-out,
 * `theme.css:148` — not a new mechanism) and gives the body the room it needs. The modal is
 * kept for **create** and **fork**, where the operator is answering "what is this template?"
 * rather than writing its body.
 *
 * ## Built-ins are never editable here
 *
 * This page refuses any template whose `source` is not `user`, and says why. Every shipped
 * spec's digest is pinned and bound into the `document.generated` ledger event, so editing a
 * built-in in place retroactively changes what a past seal meant. The route into a built-in's
 * body is the FORK dialog on the detail page, which is where this page sends the operator.
 * `useTemplateEditor` remains the one place that ruling is made for the catalog and the detail
 * page; this page is a third surface and re-states it rather than assuming a caller checked.
 *
 * ## There is NO preview pane, deliberately — see the log
 *
 * A live "markdown to PDF" preview would have to come from the server, through the same compile
 * path that runs at generation, because the client must never render document content and
 * placeholders must resolve (and be markdown-escaped) server-side. **No such endpoint exists for
 * templates.** `GET /v1/acts/{id}/document/preview?template_id=` resolves ids through
 * `registry().get(tid)` only (`chancela-api/src/documents.rs:4727`), so it returns 404 for every
 * `user-…` id — the exact templates this page edits — and it needs an act to supply a context.
 * `POST /v1/templates/import?dry_run=true` returns `{ok, error?}`, a validation verdict with no
 * rendered output. Faking it client-side would show an operator a document that disagrees with
 * what the server would actually generate, which on an evidentiary product is worse than showing
 * nothing. The gap is reported, not worked around.
 */
import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import type { TemplateBlockSpec, TemplateSpec } from '../../api/types';
import { useTemplateSpec, useTemplates, useUpdateTemplate } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { useUnsavedChanges } from '../../hooks/useUnsavedChanges';
import { useT } from '../../i18n';
import {
  Button,
  ButtonLink,
  Card,
  EmptyState,
  ErrorNote,
  Icon,
  InlineWarning,
  PageHeader,
  Skeleton,
  SkeletonDeflist,
  useToast,
} from '../../ui';
import { mappedTemplateError } from './TemplateEditorForm';
import { TemplateSpecFields } from './TemplateSpecFields';
import { templateDetailPath } from './templateRoutes';
import { hasTemplateName, templateDisplayName } from './templateNames';

export function TemplateEditPage() {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();
  const { id = '' } = useParams();

  const templates = useTemplates();
  const template = (templates.data ?? []).find((row) => row.id === id);
  const isUser = template?.source === 'user';
  // The body is only fetched once the catalog says this template exists AND is editable, so
  // opening the page against a built-in never even reads its spec.
  const spec = useTemplateSpec(id, template !== undefined && isUser);
  const updateTemplate = useUpdateTemplate();

  const [draft, setDraft] = useState<TemplateSpec | null>(null);
  const [blocksText, setBlocksText] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  // Seed the draft once the body arrives. Keyed on the loaded spec rather than on `id` so a
  // refetch that returns the same body cannot silently discard typing in progress.
  useEffect(() => {
    if (!spec.data || draft !== null) return;
    setDraft(spec.data);
    setBlocksText(JSON.stringify(spec.data.blocks, null, 2));
  }, [spec.data, draft]);

  const dirty = useMemo(() => {
    if (!spec.data || !draft) return false;
    return (
      JSON.stringify({ ...draft, blocks: [] }) !== JSON.stringify({ ...spec.data, blocks: [] }) ||
      blocksText !== JSON.stringify(spec.data.blocks, null, 2)
    );
  }, [draft, spec.data, blocksText]);

  // Warns before a reload or a route change would throw the edit away (t52's registry).
  useUnsavedChanges(dirty);

  const backToTemplate = templateDetailPath(id);

  if (templates.isLoading) {
    return (
      <div className="stack wide-page">
        <PageHeader
          crumbs={<Link to="/templates">{t('templates.title')}</Link>}
          title={<Skeleton width="18rem" height="1.6rem" />}
        />
        <Card title={t('templates.editor.title.edit')}>
          <SkeletonDeflist />
        </Card>
      </div>
    );
  }
  if (templates.error) return <ErrorNote error={templates.error} />;

  if (!template) {
    return (
      <div className="stack wide-page">
        <PageHeader
          crumbs={<Link to="/templates">{t('templates.title')}</Link>}
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

  const name = hasTemplateName(template.id) ? templateDisplayName(template.id) : template.id;

  // A built-in reached by URL, not by a button — the buttons already divert to the fork dialog.
  // It is refused HERE too, because a route is a thing people bookmark, type and share.
  if (!isUser) {
    return (
      <div className="stack wide-page">
        <PageHeader
          crumbs={
            <>
              <Link to="/templates">{t('templates.title')}</Link> · {template.id}
            </>
          }
          title={name}
        />
        <InlineWarning tone="info" title={t('templates.fork.builtin.title')}>
          <p>{t('templates.fork.builtin.body')}</p>
        </InlineWarning>
        <p>
          <Link to={backToTemplate}>{t('templates.actions.edit')}</Link>
        </p>
      </div>
    );
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!draft || updateTemplate.isPending) return;
    setFormError(null);

    let blocks: TemplateBlockSpec[];
    try {
      const parsed = JSON.parse(blocksText) as unknown;
      if (!Array.isArray(parsed) || parsed.length === 0) {
        setFormError(t('templates.error.no_blocks'));
        return;
      }
      blocks = parsed as TemplateBlockSpec[];
    } catch {
      setFormError(t('templates.error.malformed'));
      return;
    }

    const payload: TemplateSpec = {
      id: draft.id.trim(),
      family: draft.family,
      stage: draft.stage,
      channels: draft.channels,
      signature_policy: draft.signature_policy,
      rule_pack_id: draft.rule_pack_id.trim(),
      blocks,
      locale: draft.locale,
    };

    try {
      const updated = await updateTemplate.mutateAsync({
        id: payload.id,
        rawJson: JSON.stringify(payload),
      });
      toast.success(t('templates.toast.updated', { id: updated.id }));
      // The draft is dropped so `dirty` goes false before the route changes; otherwise the
      // unsaved-changes guard would challenge a navigation that follows a successful save.
      setDraft(null);
      void navigate(backToTemplate);
    } catch (err) {
      setFormError(
        mappedTemplateError(
          t,
          err instanceof ApiError ? err.code : undefined,
          err instanceof Error ? err.message : String(err),
        ),
      );
      toast.error(err);
    }
  }

  return (
    <div className="stack wide-page">
      <PageHeader
        crumbs={
          <>
            <Link to="/templates">{t('templates.title')}</Link> ·{' '}
            <Link to={backToTemplate}>{template.id}</Link>
          </>
        }
        title={name}
        actions={
          <ButtonLink to={backToTemplate} variant="ghost" icon={<Icon.ArrowRight />}>
            {t('templates.actions.cancel')}
          </ButtonLink>
        }
      />

      {/* The same warning the fork dialog and the detail page carry, for the same reason: an
          operator about to invest an afternoon in a body must know before they type that the
          seal will refuse it. Adjacent to the work, not at the end of it. */}
      <InlineWarning tone="warn" title={t('templates.fork.limit.title')}>
        <p>{t('templates.fork.limit.body')}</p>
      </InlineWarning>

      {spec.isLoading ? (
        <Card title={t('templates.editor.title.edit')}>
          <SkeletonDeflist />
        </Card>
      ) : spec.error ? (
        <ErrorNote error={spec.error} />
      ) : draft ? (
        <Card title={t('templates.editor.title.edit')}>
          <form className="form" onSubmit={submit}>
            <p className="field__hint">{t('templates.editor.intro')}</p>

            <TemplateSpecFields
              spec={draft}
              onSpecChange={(next) => setDraft((current) => (current ? next(current) : current))}
              blocksText={blocksText}
              onBlocksTextChange={setBlocksText}
              idLocked
              // The whole point of the page: the body gets the vertical room the modal denied it.
              blocksRows={28}
              idPrefix="tpl-page"
            />

            {formError ? (
              <InlineWarning tone="error" title={t('templates.import.invalid')}>
                <p>{formError}</p>
              </InlineWarning>
            ) : null}

            <div className="row-wrap">
              <Button
                type="submit"
                variant="primary"
                icon={<Icon.Save />}
                disabled={updateTemplate.isPending || !blocksText.trim()}
              >
                {t('templates.actions.save')}
              </Button>
              <ButtonLink to={backToTemplate} variant="ghost">
                {t('templates.actions.cancel')}
              </ButtonLink>
            </div>
          </form>
        </Card>
      ) : null}
    </div>
  );
}
