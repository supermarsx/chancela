/**
 * Import a user-authored template from a JSON file (wp23-e6).
 *
 * Follows the book-import verify-then-confirm UX (`LivrosIntegridadeSection`): picking a `.json`
 * file reads its text verbatim and runs a NON-persisting dry-run preflight
 * (`useImportTemplate({ dryRun: true })`). The verdict is shown honestly — valid, or invalid with
 * the mapped `templates.error.<code>` message — and the Confirm button stays disabled until the
 * dry-run passes. Confirming commits the same bytes (`dryRun: false`), toasts, and refreshes the
 * catalog. The file text is passed byte-for-byte so a re-exported template round-trips exactly.
 */
import { useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import type { TemplateImportVerdict, TemplateSummary } from '../../api/types';
import { useImportTemplate } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { useT } from '../../i18n';
import { Button, Icon, InlineWarning, useToast } from '../../ui';
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

export function TemplateImportDialog({ onClose }: { onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const importTemplate = useImportTemplate();

  const [rawJson, setRawJson] = useState<string | null>(null);
  const [filename, setFilename] = useState<string | null>(null);
  const [verdict, setVerdict] = useState<TemplateImportVerdict | null>(null);
  const [preflighting, setPreflighting] = useState(false);
  const [committing, setCommitting] = useState(false);

  async function onSelectFile(file: File) {
    setVerdict(null);
    setFilename(file.name);
    const text = await file.text();
    setRawJson(text);
    setPreflighting(true);
    try {
      const result = await importTemplate.mutateAsync({ rawJson: text, dryRun: true });
      setVerdict(result as TemplateImportVerdict);
    } catch (err) {
      setVerdict({
        ok: false,
        error: {
          code: err instanceof ApiError && err.code ? err.code : 'malformed',
          message: err instanceof Error ? err.message : String(err),
        },
      });
      toast.error(err);
    } finally {
      setPreflighting(false);
    }
  }

  async function onConfirm() {
    if (!rawJson || !verdict?.ok || committing) return;
    setCommitting(true);
    try {
      const summary = (await importTemplate.mutateAsync({ rawJson })) as TemplateSummary;
      toast.success(t('templates.toast.imported', { id: summary.id }));
      onClose();
    } catch (err) {
      setVerdict({
        ok: false,
        error: {
          code: err instanceof ApiError && err.code ? err.code : 'malformed',
          message: err instanceof Error ? err.message : String(err),
        },
      });
      toast.error(err);
    } finally {
      setCommitting(false);
    }
  }

  const busy = preflighting || committing;
  const canConfirm = Boolean(verdict?.ok) && !busy;

  return (
    <ImportModal title={t('templates.import.title')} onClose={onClose}>
      <div className="modal__body stack--tight">
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
              <p>
                {mappedTemplateError(t, verdict.error?.code, verdict.error?.message ?? '')}
              </p>
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
