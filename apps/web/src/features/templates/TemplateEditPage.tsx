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
 * The first tab follows the authoring flow: structured document blocks, then the narrative-body
 * WYSIWYG beside the server-compiled preview. Metadata lives in a separate compact properties tab.
 * Canonical block JSON remains available only as a validated advanced escape hatch. Both authored
 * halves are persisted through the bundle envelope on save.
 */
import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import type { TemplateBlockSpec, TemplateBundleView, TemplateSpec } from '../../api/types';
import { useTemplateBundle, useTemplates, useUpdateTemplate } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { useUnsavedChanges } from '../../hooks/useUnsavedChanges';
import { useT } from '../../i18n';
import { useTemplatesEditorT } from '../../i18n/templatesEditorFallback';
import {
  Button,
  ButtonLink,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  Input,
  InlineWarning,
  PageHeader,
  Skeleton,
  SkeletonDeflist,
  useToast,
} from '../../ui';
import { mappedTemplateError } from './templateErrors';
import { TemplateSpecFields } from './TemplateSpecFields';
import { TemplateBlocksEditor, parseTemplateBlocksText } from './TemplateBlocksEditor';
import { TemplateBodyEditor } from './TemplateBodyEditor';
import { TemplateEditorTabs, type UserTemplateEditorTab } from './TemplateEditorTabs';
import { TemplateVersionHistory } from './TemplateVersionHistory';
import { normalizeTemplateVersionName } from './templateVersionNames';
import { templateDetailPath } from './templateRoutes';
import { hasTemplateName, templateDisplayName } from './templateNames';
import { PermissionDeniedNote, useCan } from '../session/permissions';

export function TemplateEditPage() {
  const t = useT();
  const et = useTemplatesEditorT();
  const toast = useToast();
  const navigate = useNavigate();
  const { id = '' } = useParams();
  const can = useCan();
  const canManageTemplates = can('template.manage');

  const templates = useTemplates();
  const template = (templates.data ?? []).find((row) => row.id === id);
  const isUser = template?.source === 'user';
  // Both authored halves — spec + narrative body — are fetched once the catalog says this template
  // exists AND is editable, so opening the page against a built-in never even reads it. The bundle
  // reader preserves the t48 fork crash-fix (spec is unwrapped from the `.spec` envelope half).
  const bundle = useTemplateBundle(id, canManageTemplates && template !== undefined && isUser);
  const updateTemplate = useUpdateTemplate();

  const [draft, setDraft] = useState<TemplateSpec | null>(null);
  const [blocksText, setBlocksText] = useState('');
  const [body, setBody] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [versionName, setVersionName] = useState('');
  const [versionNameError, setVersionNameError] = useState<string | null>(null);
  const [restoreReloading, setRestoreReloading] = useState(false);
  const [tab, setTab] = useState<UserTemplateEditorTab>('content');

  const seedFromBundle = useCallback((next: TemplateBundleView) => {
    setDraft(next.spec);
    setBlocksText(JSON.stringify(next.spec.blocks, null, 2));
    setBody(next.body_markdown);
  }, []);

  // Seed the draft once the bundle arrives. Keyed on the loaded data rather than on `id` so a
  // refetch that returns the same body cannot silently discard typing in progress.
  useEffect(() => {
    if (!bundle.data || bundle.error || restoreReloading || draft !== null) return;
    seedFromBundle(bundle.data);
  }, [bundle.data, bundle.error, draft, restoreReloading, seedFromBundle]);

  const dirty = useMemo(() => {
    if (!bundle.data || !draft) return false;
    return (
      JSON.stringify({ ...draft, blocks: [] }) !==
        JSON.stringify({ ...bundle.data.spec, blocks: [] }) ||
      blocksText !== JSON.stringify(bundle.data.spec.blocks, null, 2) ||
      body !== bundle.data.body_markdown ||
      versionName.trim() !== ''
    );
  }, [draft, bundle.data, blocksText, body, versionName]);

  // The body-placement hint follows structured block edits immediately. If advanced JSON is
  // temporarily invalid, keep the last valid spec visible rather than inventing a block list.
  const authoredSpec = useMemo(() => {
    if (!draft) return null;
    const parsed = parseTemplateBlocksText(blocksText);
    return parsed.blocks ? { ...draft, blocks: parsed.blocks } : draft;
  }, [draft, blocksText]);

  // Warns before a reload or a route change would throw the edit away (t52's registry).
  useUnsavedChanges(dirty);

  const backToTemplate = templateDetailPath(id);

  function handleVersionRestored() {
    // The restore response is metadata-only. Drop every local authored half, then force a fresh
    // bundle read before returning to the editor; otherwise the old cached body could briefly
    // become the new dirty baseline.
    setRestoreReloading(true);
    setDraft(null);
    setBlocksText('');
    setBody('');
    setVersionName('');
    setVersionNameError(null);
    setFormError(null);

    void bundle.refetch().then(
      (refreshed) => {
        if (refreshed.data && !refreshed.error) {
          seedFromBundle(refreshed.data);
          setTab('content');
        }
        setRestoreReloading(false);
      },
      () => setRestoreReloading(false),
    );
  }

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

  // The catalog's Edit action is permission-gated, but a URL can be typed or bookmarked. Mirror
  // that global gate at the route boundary and never mount the editor/history queries for a reader.
  if (!canManageTemplates) {
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
        <PermissionDeniedNote />
        <p>
          <Link to={backToTemplate}>{t('templates.detail.open')}</Link>
        </p>
      </div>
    );
  }

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
    setVersionNameError(null);

    const normalizedVersionName = normalizeTemplateVersionName(versionName);
    if (normalizedVersionName.tooLong) {
      setVersionNameError(et('templates.editor.saveName.tooLong'));
      return;
    }

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
        ...(normalizedVersionName.value ? { versionName: normalizedVersionName.value } : {}),
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
      ) : bundle.data ? (
        <Card title={t('templates.editor.title.edit')}>
          <div className="stack">
            <p className="field__hint">{t('templates.editor.intro')}</p>

            <TemplateEditorTabs active={tab} onSelect={setTab} showVersions />

            {tab === 'versions' ? (
              <div className="route-transition" key={tab}>
                <TemplateVersionHistory
                  templateId={id}
                  enabled
                  onRestored={handleVersionRestored}
                  restoreBlockedReason={
                    dirty ? et('templates.editor.versions.restoreBlockedDirty') : undefined
                  }
                  hideHeading
                />
              </div>
            ) : restoreReloading || !draft || !authoredSpec ? (
              <SkeletonDeflist />
            ) : (
              <form className="form" onSubmit={submit}>
                <div className="route-transition stack" key={tab}>
                  {tab === 'content' ? (
                    <>
                      <TemplateBlocksEditor
                        value={blocksText}
                        onChange={setBlocksText}
                        idPrefix="tpl-page-blocks"
                      />
                      <TemplateBodyEditor
                        spec={authoredSpec}
                        value={body}
                        onChange={setBody}
                        disabled={updateTemplate.isPending}
                        idPrefix="tpl-page"
                      />
                    </>
                  ) : (
                    <TemplateSpecFields
                      spec={draft}
                      onSpecChange={(next) =>
                        setDraft((current) => (current ? next(current) : current))
                      }
                      idLocked
                      idPrefix="tpl-page"
                    />
                  )}
                </div>

                {formError ? (
                  <InlineWarning tone="error" title={t('templates.import.invalid')}>
                    <p>{formError}</p>
                  </InlineWarning>
                ) : null}

                <div className="template-editor__save-bar">
                  <Field
                    label={et('templates.editor.saveName.label')}
                    htmlFor="tpl-page-version-name"
                    hint={et('templates.editor.saveName.hint')}
                    error={versionNameError}
                  >
                    <Input
                      id="tpl-page-version-name"
                      value={versionName}
                      placeholder={et('templates.editor.saveName.placeholder')}
                      disabled={updateTemplate.isPending}
                      onChange={(event) => {
                        setVersionName(event.target.value);
                        if (versionNameError) setVersionNameError(null);
                      }}
                    />
                  </Field>
                  <div className="row-wrap template-editor__save-actions">
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
                </div>
              </form>
            )}
          </div>
        </Card>
      ) : null}
    </div>
  );
}
