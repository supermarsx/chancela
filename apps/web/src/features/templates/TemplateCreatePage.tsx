/**
 * TemplateCreatePage — the full-page CREATE and FORK surface (t56).
 *
 * ## Why a page, not a modal
 *
 * Authoring a template means answering "what is this template?" (the structured spec fields) AND
 * writing its narrative body with a WYSIWYG and a live preview. That does not fit a dialog whose
 * measure is the prose measure, so — like the edit page (t109) and the ata editor (t53) — it opts
 * into the shared `.wide-page` shell and gives the body the room it needs. The retired modal
 * (`TemplateEditorForm`) is gone; this is the one create/fork surface.
 *
 * ## Create vs fork
 *
 * Both are the same route. A bare `/templates/new` starts from a blank spec. `/templates/new?fork=<id>`
 * seeds the draft from an existing template's spec AND body — the ONLY way to change a built-in,
 * whose frozen spec digest is bound into past seals. The fork copies the source verbatim under a
 * fresh `user-…/v1` id (`templateFork.ts`), so it behaves like the template it came from.
 *
 * The seed is read through the shared bundle query (`useTemplateBundle` → `templateSpecFromExport`),
 * which preserves the t48 fork crash-fix (the export is the `chancela.template-bundle` envelope; its
 * spec lives under `.spec`, never at the root). The body rides as `body_markdown` and is posted back
 * through the bundle envelope, so a forked body is never silently dropped.
 */
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import type { TemplateBlockSpec, TemplateSpec } from '../../api/types';
import { useCreateTemplate, useTemplateBundle, useTemplates } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { useUnsavedChanges } from '../../hooks/useUnsavedChanges';
import { useT } from '../../i18n';
import { useTemplatesEditorT } from '../../i18n/templatesEditorFallback';
import {
  Button,
  ButtonLink,
  Card,
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
import {
  TemplateBlocksEditor,
  parseTemplateBlocksText,
  withNarrativeBodyPlacement,
} from './TemplateBlocksEditor';
import { TemplateBodyEditor } from './TemplateBodyEditor';
import { TemplateEditorTabs, type TemplateEditorTab } from './TemplateEditorTabs';
import { forkTemplateSpec, forkedTemplateId } from './templateFork';
import { templateDetailPath } from './templateRoutes';
import { PermissionDeniedNote, useCan } from '../session/permissions';

/** A new template places its narrative editor by default; no raw-structure repair is required. */
function blankSpec(): TemplateSpec {
  return {
    id: '',
    family: 'CommercialCompany',
    stage: 'Ata',
    channels: [],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: '',
    blocks: [{ kind: 'NarrativeBody' }],
    locale: 'pt-PT',
  };
}

export function TemplateCreatePage() {
  const t = useT();
  const et = useTemplatesEditorT();
  const toast = useToast();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const forkId = params.get('fork');
  const isFork = forkId !== null && forkId !== '';
  const can = useCan();
  const canManageTemplates = can('template.manage');

  const templates = useTemplates(undefined, undefined, canManageTemplates);
  const source = isFork ? (templates.data ?? []).find((row) => row.id === forkId) : undefined;
  const sourceIsBuiltin = source !== undefined && source.source !== 'user';
  const existingIds = useMemo(() => (templates.data ?? []).map((row) => row.id), [templates.data]);
  // The seed spec + body for a fork; only fetched when forking and once the catalog resolved the id.
  const bundle = useTemplateBundle(
    forkId ?? '',
    canManageTemplates && isFork && templates.data !== undefined,
  );
  const createTemplate = useCreateTemplate();

  const [draft, setDraft] = useState<TemplateSpec | null>(null);
  const [blocksText, setBlocksText] = useState('');
  const [body, setBody] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [tab, setTab] = useState<TemplateEditorTab>('content');
  // The seeded baseline, captured once so `dirty` measures real edits (not the pre-filled fork).
  const baselineRef = useRef<string | null>(null);
  const savedRef = useRef(false);

  // Seed the draft once: immediately for a blank create, or when the fork bundle arrives.
  useEffect(() => {
    if (!canManageTemplates) return;
    if (draft !== null) return;
    if (!isFork) {
      const seed = blankSpec();
      setDraft(seed);
      setBlocksText(JSON.stringify(seed.blocks, null, 2));
      setBody('');
      baselineRef.current = JSON.stringify({
        spec: { ...seed, blocks: [] },
        blocks: seed.blocks,
        body: '',
      });
      return;
    }
    if (!bundle.data) return;
    const seed = forkTemplateSpec(bundle.data.spec, forkedTemplateId(forkId ?? '', existingIds));
    setDraft(seed);
    setBlocksText(JSON.stringify(seed.blocks, null, 2));
    setBody(bundle.data.body_markdown);
    baselineRef.current = JSON.stringify({
      spec: { ...seed, blocks: [] },
      blocks: seed.blocks,
      body: bundle.data.body_markdown,
    });
  }, [canManageTemplates, draft, isFork, bundle.data, forkId, existingIds]);

  const dirty = useMemo(() => {
    if (!draft || baselineRef.current === null) return false;
    let blocks: unknown;
    try {
      blocks = JSON.parse(blocksText);
    } catch {
      blocks = blocksText;
    }
    return JSON.stringify({ spec: { ...draft, blocks: [] }, blocks, body }) !== baselineRef.current;
  }, [draft, blocksText, body]);

  const authoredSpec = useMemo(() => {
    if (!draft) return null;
    const parsed = parseTemplateBlocksText(blocksText);
    return parsed.blocks ? { ...draft, blocks: parsed.blocks } : draft;
  }, [draft, blocksText]);

  useUnsavedChanges(dirty && !savedRef.current);

  const title = isFork ? t('templates.editor.title.fork') : t('templates.editor.title.create');

  // New/fork buttons are gated in the catalog, but a direct URL bypasses those affordances.
  // Fail closed here too: no catalog/fork-bundle authoring read, draft, preview, or late POST.
  if (!canManageTemplates) {
    return (
      <div className="stack wide-page">
        <PageHeader crumbs={<Link to="/templates">{t('templates.title')}</Link>} title={title} />
        <PermissionDeniedNote />
        <p>
          <Link to="/templates">{t('templates.title')}</Link>
        </p>
      </div>
    );
  }

  if (isFork && templates.isLoading) {
    return (
      <div className="stack wide-page">
        <PageHeader
          crumbs={<Link to="/templates">{t('templates.title')}</Link>}
          title={<Skeleton width="18rem" height="1.6rem" />}
        />
        <Card title={title}>
          <SkeletonDeflist />
        </Card>
      </div>
    );
  }
  if (templates.error) return <ErrorNote error={templates.error} />;
  if (isFork && bundle.error) return <ErrorNote error={bundle.error} />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!draft || createTemplate.isPending) return;
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

    const spec: TemplateSpec = {
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
      const created = await createTemplate.mutateAsync({ spec, body_markdown: body });
      toast.success(t('templates.toast.created', { id: created.id }));
      // Mark saved so the unsaved-changes guard does not challenge the navigation that follows.
      savedRef.current = true;
      void navigate(templateDetailPath(created.id));
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

  function addBodyPlacement() {
    const next = withNarrativeBodyPlacement(blocksText);
    if (next !== null) setBlocksText(next);
  }

  const canSubmit =
    draft !== null &&
    draft.id.trim().length > 0 &&
    draft.rule_pack_id.trim().length > 0 &&
    blocksText.trim().length > 0;

  return (
    <div className="stack wide-page template-editor-page">
      <PageHeader
        crumbs={<Link to="/templates">{t('templates.title')}</Link>}
        title={title}
        actions={
          <ButtonLink to="/templates" variant="ghost" icon={<Icon.ArrowRight />}>
            {t('templates.actions.cancel')}
          </ButtonLink>
        }
      />

      {/* Said HERE, before a single field is filled in — not at the sealing step, where it would
          arrive after the work rather than before it. */}
      {isFork ? (
        <>
          {sourceIsBuiltin ? (
            <InlineWarning tone="info" title={t('templates.fork.builtin.title')}>
              <p>{t('templates.fork.builtin.body')}</p>
            </InlineWarning>
          ) : null}
          <InlineWarning tone="warn" title={t('templates.fork.limit.title')}>
            <p>{t('templates.fork.limit.body')}</p>
          </InlineWarning>
          {forkId ? (
            <p className="field__hint">{t('templates.fork.source', { id: forkId })}</p>
          ) : null}
        </>
      ) : null}

      {isFork && !draft ? (
        <Card title={title}>
          <SkeletonDeflist />
        </Card>
      ) : draft && authoredSpec ? (
        <Card title={title}>
          <form className="form" onSubmit={submit}>
            <p className="field__hint">{t('templates.editor.intro')}</p>

            <TemplateEditorTabs
              active={tab}
              onSelect={(next) => {
                if (next !== 'versions') setTab(next);
              }}
            />

            <div className="route-transition stack" key={tab}>
              {tab === 'content' ? (
                <TemplateBodyEditor
                  spec={authoredSpec}
                  value={body}
                  onChange={setBody}
                  onAddBodyPlacement={addBodyPlacement}
                  disabled={createTemplate.isPending}
                  idPrefix="tpl-new"
                />
              ) : (
                <>
                  <TemplateSpecFields
                    spec={draft}
                    onSpecChange={(next) =>
                      setDraft((current) => (current ? next(current) : current))
                    }
                    idLocked={false}
                    idPrefix="tpl-new"
                  />
                  <details className="template-editor__document-structure">
                    <summary>{et('templates.editor.structure.summary')}</summary>
                    <div className="stack--tight template-editor__document-structure-body">
                      <p className="field__hint">{et('templates.editor.structure.hint')}</p>
                      <TemplateBlocksEditor
                        value={blocksText}
                        onChange={setBlocksText}
                        idPrefix="tpl-new-blocks"
                      />
                    </div>
                  </details>
                </>
              )}
            </div>

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
                disabled={createTemplate.isPending || !canSubmit}
              >
                {t('templates.actions.save')}
              </Button>
              <ButtonLink to="/templates" variant="ghost">
                {t('templates.actions.cancel')}
              </ButtonLink>
            </div>
          </form>
        </Card>
      ) : null}
    </div>
  );
}
