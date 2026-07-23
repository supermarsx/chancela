/**
 * Import a user-authored template — from a JSON file OR pasted JSON (wp23-e6, envelope t43).
 *
 * Follows the book-import verify-then-confirm UX (`LivrosIntegridadeSection`): providing the JSON
 * (picking a `.json` file, or pasting and pressing Validar) reads its text verbatim and runs a
 * NON-persisting dry-run preflight (`useImportTemplate({ dryRun: true })`). The verdict is shown
 * honestly — valid, or invalid with the mapped reason — and Confirm stays disabled until the dry-run
 * passes. Confirming commits the same bytes (`dryRun: false`), toasts, and refreshes the catalog. The
 * text is passed byte-for-byte so a re-exported template (bundle or bare spec) round-trips exactly.
 *
 * The input accepts the t43 `chancela.template-bundle` envelope AND a legacy bare spec; the server
 * decides which, and its rejection is surfaced code-for-code (the five bundle codes carry their own
 * messages via {@link useTemplateImportT}; the rest fall back to the catalog via
 * {@link mappedTemplateError}). Reject, never transform: an unrepresentable bundle is refused with
 * its reason, never silently dropped or altered.
 */
import { useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import type { TemplateImportVerdict, TemplateSummary } from '../../api/types';
import { useImportTemplate } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { useT } from '../../i18n';
import {
  TEMPLATE_IMPORT_BUNDLE_ERROR_CODES,
  useTemplateImportT,
  type TemplateImportCopyKey,
} from '../../i18n/templateImportFallback';
import { Button, Field, Icon, InlineWarning, TextArea, useToast } from '../../ui';
import { useFocusTrap } from '../../ui/useFocusTrap';
import { mappedTemplateError } from './TemplateEditorForm';

function ImportModal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const trapRef = useFocusTrap<HTMLDivElement>(true);
  const titleId = useRef(`tpl-import-${Math.random().toString(36).slice(2)}`).current;
  return createPortal(
    <div className="modal-backdrop" onClick={onClose}>
      <div
        ref={trapRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="modal__head">
          <h2 className="modal__title" id={titleId}>
            {title}
          </h2>
        </header>
        {children}
      </div>
    </div>,
    document.body,
  );
}

type ImportSource = 'file' | 'paste';

export function TemplateImportDialog({ onClose }: { onClose: () => void }) {
  const t = useT();
  const it = useTemplateImportT();
  const toast = useToast();
  const importTemplate = useImportTemplate();

  const [source, setSource] = useState<ImportSource>('file');
  const [pasteText, setPasteText] = useState('');
  const [rawJson, setRawJson] = useState<string | null>(null);
  const [filename, setFilename] = useState<string | null>(null);
  const [verdict, setVerdict] = useState<TemplateImportVerdict | null>(null);
  const [preflighting, setPreflighting] = useState(false);
  const [committing, setCommitting] = useState(false);

  /** Map a rejection code to its honest message: the bundle codes here, the rest from the catalog. */
  function importErrorMessage(code: string | undefined, fallback: string): string {
    if (code && TEMPLATE_IMPORT_BUNDLE_ERROR_CODES.has(code)) {
      return it(`templates.import.error.${code}` as TemplateImportCopyKey);
    }
    return mappedTemplateError(t, code, fallback);
  }

  function failVerdict(err: unknown) {
    setVerdict({
      ok: false,
      error: {
        code: err instanceof ApiError && err.code ? err.code : 'malformed',
        message: err instanceof Error ? err.message : String(err),
      },
    });
    toast.error(err);
  }

  /** Run the non-persisting dry-run over `text`, echoing `label` as the source being verified. */
  async function preflight(text: string, label: string) {
    setVerdict(null);
    setFilename(label);
    setRawJson(text);
    setPreflighting(true);
    try {
      const result = await importTemplate.mutateAsync({ rawJson: text, dryRun: true });
      setVerdict(result as TemplateImportVerdict);
    } catch (err) {
      failVerdict(err);
    } finally {
      setPreflighting(false);
    }
  }

  async function onSelectFile(file: File) {
    await preflight(await file.text(), file.name);
  }

  function switchSource(next: ImportSource) {
    if (next === source) return;
    setSource(next);
    // A verdict is about the JSON that produced it; switching the source clears the stale answer so
    // Confirm cannot commit bytes the operator is no longer looking at.
    setVerdict(null);
    setRawJson(null);
    setFilename(null);
  }

  async function onConfirm() {
    if (!rawJson || !verdict?.ok || committing) return;
    setCommitting(true);
    try {
      const summary = (await importTemplate.mutateAsync({ rawJson })) as TemplateSummary;
      toast.success(t('templates.toast.imported', { id: summary.id }));
      onClose();
    } catch (err) {
      failVerdict(err);
    } finally {
      setCommitting(false);
    }
  }

  const busy = preflighting || committing;
  const canConfirm = Boolean(verdict?.ok) && !busy;

  return (
    <ImportModal title={t('templates.import.title')} onClose={onClose}>
      <div className="modal__body stack--tight">
        <p className="field__hint">{it('templates.import.hint')}</p>

        <div className="row-wrap" role="group" aria-label={t('templates.import.title')}>
          <Button
            type="button"
            variant={source === 'file' ? 'secondary' : 'ghost'}
            aria-pressed={source === 'file'}
            disabled={busy}
            onClick={() => switchSource('file')}
          >
            {it('templates.import.source.file')}
          </Button>
          <Button
            type="button"
            variant={source === 'paste' ? 'secondary' : 'ghost'}
            aria-pressed={source === 'paste'}
            disabled={busy}
            onClick={() => switchSource('paste')}
          >
            {it('templates.import.source.paste')}
          </Button>
        </div>

        {source === 'file' ? (
          <div className="row-wrap">
            <label className="btn btn--secondary btn--icon file-btn">
              <span className="btn__icon">
                <Icon.Tray />
              </span>
              {t('templates.import.pickFile')}
              <input
                type="file"
                accept=".json,application/json"
                className="sr-only"
                disabled={busy}
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (file) void onSelectFile(file);
                  event.target.value = '';
                }}
              />
            </label>
            {filename ? <span className="field__hint mono">{filename}</span> : null}
          </div>
        ) : (
          <div className="stack--tight">
            <Field label={it('templates.import.paste.label')} htmlFor="templates-import-paste">
              <TextArea
                id="templates-import-paste"
                rows={10}
                spellCheck={false}
                value={pasteText}
                placeholder={it('templates.import.paste.placeholder')}
                disabled={busy}
                onChange={(event) => setPasteText(event.target.value)}
              />
            </Field>
            <div className="row-wrap">
              <Button
                type="button"
                variant="secondary"
                icon={<Icon.Check />}
                disabled={busy || pasteText.trim() === ''}
                onClick={() => void preflight(pasteText, it('templates.import.source.paste'))}
              >
                {it('templates.import.paste.validate')}
              </Button>
            </div>
          </div>
        )}

        {preflighting ? (
          <InlineWarning tone="info" title={t('templates.import.preflight')}>
            <p>{t('templates.import.preflight')}</p>
          </InlineWarning>
        ) : verdict ? (
          verdict.ok ? (
            <InlineWarning tone="info" title={t('templates.import.valid')}>
              <p>{t('templates.import.valid')}</p>
            </InlineWarning>
          ) : (
            <InlineWarning tone="error" title={t('templates.import.invalid')}>
              <p>{importErrorMessage(verdict.error?.code, verdict.error?.message ?? '')}</p>
            </InlineWarning>
          )
        ) : null}

        <div className="modal__foot">
          <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>
            {t('templates.actions.cancel')}
          </Button>
          <Button
            type="button"
            variant="primary"
            icon={<Icon.Check />}
            disabled={!canConfirm}
            onClick={() => void onConfirm()}
          >
            {t('templates.import.confirm')}
          </Button>
        </div>
      </div>
    </ImportModal>
  );
}
