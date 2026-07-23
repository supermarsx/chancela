/**
 * TemplateEditPage — a user template's own full-width editing surface (t109 + t56).
 *
 * ## Why a page rather than a modal
 *
 * A template is the widest authoring surface in the app: the structured spec (canonical `BlockSpec`
 * JSON) AND a narrative body written with a WYSIWYG beside a live preview. None of that fits a dialog
 * whose measure is the prose measure, so this page opts into `.wide-page` (the shared shell opt-out,
 * `theme.css` — not a new mechanism) and gives both the room they need. Create and fork are pages
 * too now (`TemplateCreatePage`); the edit modal is gone.
 *
 * ## Built-ins are never editable here
 *
 * This page refuses any template whose `source` is not `user`, and says why. Every shipped spec's
 * digest is pinned and bound into the `document.generated` ledger event, so editing a built-in in
 * place retroactively changes what a past seal meant. The route into a built-in's body is the FORK
 * page, which is where the buttons send the operator. This page re-states the ruling rather than
 * assuming a caller checked (a route is bookmarked, typed and shared).
 *
 * ## WYSIWYG body + live preview (t56)
 *
 * The narrative body — the markdown seed that rides the `chancela.template-bundle` envelope as
 * `body_markdown` — is edited with the ata's `MarkdownBodyEditor` (a pure consumer), with a live
 * side-by-side PREVIEW compiled by the server's own stateless `POST /v1/templates/body/preview`. The
 * client never renders document content itself, and merge tags appear in LITERAL token form because
 * the preview is unresolved (there is no act context). The structured `blocks[]` array stays a
 * canonical-JSON textarea (`TemplateSpecFields`): the WYSIWYG edits the prose body only, never the
 * block structure. Both halves are persisted through the bundle envelope on save.
 */
import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import type { TemplateBlockSpec, TemplateSpec } from '../../api/types';
import { useTemplateBundle, useTemplates, useUpdateTemplate } from '../../api/hooks';
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
import { mappedTemplateError } from './templateErrors';
import { TemplateSpecFields } from './TemplateSpecFields';
import { TemplateBodyEditor } from './TemplateBodyEditor';
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
  // Both authored halves — spec + narrative body — are fetched once the catalog says this template
  // exists AND is editable, so opening the page against a built-in never even reads it. The bundle
  // reader preserves the t48 fork crash-fix (spec is unwrapped from the `.spec` envelope half).
  const bundle = useTemplateBundle(id, template !== undefined && isUser);
  const updateTemplate = useUpdateTemplate();

  const [draft, setDraft] = useState<TemplateSpec | null>(null);
  const [blocksText, setBlocksText] = useState('');
  const [body, setBody] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  // Seed the draft once the bundle arrives. Keyed on the loaded data rather than on `id` so a
  // refetch that returns the same body cannot silently discard typing in progress.
  useEffect(() => {
    if (!bundle.data || draft !== null) return;
    setDraft(bundle.data.spec);
    setBlocksText(JSON.stringify(bundle.data.spec.blocks, null, 2));
    setBody(bundle.data.body_markdown);
  }, [bundle.data, draft]);

  const dirty = useMemo(() => {
    if (!bundle.data || !draft) return false;
    return (
      JSON.stringify({ ...draft, blocks: [] }) !==
        JSON.stringify({ ...bundle.data.spec, blocks: [] }) ||
      blocksText !== JSON.stringify(bundle.data.spec.blocks, null, 2) ||
      body !== bundle.data.body_markdown
    );
  }, [draft, bundle.data, blocksText, body]);

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

  // A built-in reached by URL, not by a button — the buttons already divert to the fork page.
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
      // Persist BOTH halves through the bundle envelope: the spec AND the narrative body seed, so an
      // edited (or unchanged, forked) body is never dropped on save.
      const updated = await updateTemplate.mutateAsync({
        id: payload.id,
        bundle: { spec: payload, body_markdown: body },
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

      {/* The same warning the fork page and the detail page carry, for the same reason: an operator
          about to invest an afternoon in a body must know before they type that the seal will refuse
          it. Adjacent to the work, not at the end of it. */}
      <InlineWarning tone="warn" title={t('templates.fork.limit.title')}>
        <p>{t('templates.fork.limit.body')}</p>
      </InlineWarning>

      {bundle.isLoading ? (
        <Card title={t('templates.editor.title.edit')}>
          <SkeletonDeflist />
        </Card>
      ) : bundle.error ? (
        <ErrorNote error={bundle.error} />
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

            <TemplateBodyEditor
              spec={draft}
              value={body}
              onChange={setBody}
              disabled={updateTemplate.isPending}
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
