/**
 * The shared confirm gate for destructive / sensitive server operations (t54-E4).
 *
 * It combines the two frozen safety rails the server enforces into ONE reusable dialog so
 * every dangerous action confirms the same way (t62 admin reuses it verbatim):
 *
 *  - **Type-to-confirm phrase** (`phrase`) — the operator must re-type the EXACT phrase the
 *    server expects (`LIMPAR DADOS` / `REPOR FÁBRICA` / `RECOMEÇAR`). The confirm button
 *    stays disabled until the typed text matches byte-for-byte; the server re-checks it too
 *    (a 422 mismatch is surfaced inline).
 *  - **Step-up re-auth** (`requireReauth`) — the acting user re-proves identity with their
 *    password OR a one-time recovery phrase (§8-F). A valid session token alone is never
 *    enough: the server answers a missing/wrong proof with a uniform **403
 *    STEP_UP_REQUIRED**, which this modal renders as an honest inline re-auth error without
 *    revealing which proof was tried.
 *  - **Export-first safety rail** (`exportFirst`) — a wipe/factory-reset ALWAYS offers (and
 *    by default performs) a whole-instance export before clearing, so nothing is ever a
 *    silent evidence-erasure. `'enforced'` locks it on; `'skippable'` allows opting out only
 *    behind a second, separately-checked "I have my own backup" confirmation.
 *
 * The parent owns the mutation: `onConfirm` receives the gathered gate args (the chosen
 * `reauth` proof, the export-first decision) and returns the mutation promise. Parent-specific
 * inputs (a reason, an archive name) are injected as `children` and gated with `canConfirm`.
 * Nothing here is silently destructive — the copy is scary-but-clear and the button label
 * spells out the pending action.
 */
import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { ReAuth } from '../api/types';
import { ApiError } from '../api/client';
import { useT } from '../i18n';
import { Button } from './index';
import { useToast } from './toast';

/** How the export-first safety rail is presented (§2.11 / §8-E). */
export type ExportFirstMode = 'none' | 'enforced' | 'skippable';

/** The gate values gathered by the modal and handed to the parent's mutation. */
export interface ConfirmActionArgs {
  /** The step-up proof, or `{}` when `requireReauth` is false. */
  reauth: ReAuth;
  /** Whether to take the export-first archive (always true unless a `skippable` opt-out). */
  exportFirst: boolean;
  /** Set with the opt-out so the server honours a `false` export_first (factory only). */
  skipExportConfirm: boolean;
}

export interface ConfirmActionModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  /** Honest, scary-but-clear explanation of exactly what the action does. */
  intro: ReactNode;
  confirmLabel: string;
  pendingLabel: string;
  /** Red / danger styling for a truly destructive op. */
  danger?: boolean;
  /** The exact type-to-confirm phrase; omit for a single-confirm (no phrase gate). */
  phrase?: string;
  /** Require password / recovery-phrase step-up re-auth (§8-F). */
  requireReauth?: boolean;
  /** The export-first rail; defaults to `'none'`. */
  exportFirst?: ExportFirstMode;
  /** The parent mutation's in-flight flag. */
  pending?: boolean;
  /** Additional gate the parent controls (e.g. a required reason is non-empty). */
  canConfirm?: boolean;
  /** Parent-specific inputs rendered above the shared gate (reason, archive name…). */
  children?: ReactNode;
  /** Runs the actual mutation; resolves on success (the modal then closes), rejects on error. */
  onConfirm: (args: ConfirmActionArgs) => Promise<void>;
}

export function ConfirmActionModal({
  open,
  onClose,
  title,
  intro,
  confirmLabel,
  pendingLabel,
  danger = false,
  phrase,
  requireReauth = false,
  exportFirst = 'none',
  pending = false,
  canConfirm = true,
  children,
  onConfirm,
}: ConfirmActionModalProps) {
  const t = useT();
  const toast = useToast();
  const [typed, setTyped] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [password, setPassword] = useState('');
  const [recovery, setRecovery] = useState('');
  const [doExport, setDoExport] = useState(true);
  const [skipConfirmed, setSkipConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const bodyRef = useRef<HTMLFormElement>(null);
  const titleId = useRef(`confirm-${Math.random().toString(36).slice(2)}`).current;

  // Reset the gathered state whenever the dialog (re)opens, and focus the first field.
  useEffect(() => {
    if (!open) return;
    setTyped('');
    setUseRecovery(false);
    setPassword('');
    setRecovery('');
    setDoExport(true);
    setSkipConfirmed(false);
    setError(null);
    setSubmitting(false);
    const id = window.setTimeout(() => {
      const first = bodyRef.current?.querySelector<HTMLElement>(
        'input:not([type=checkbox]), textarea',
      );
      first?.focus();
    }, 0);
    return () => window.clearTimeout(id);
  }, [open]);

  const busy = pending || submitting;

  // Close on Escape while open (never mid-submit — a destructive op must not be abandoned
  // in an unknown state).
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, busy, onClose]);

  if (!open) return null;

  const phraseOk = phrase === undefined || typed === phrase;
  const reauthValue = useRecovery ? recovery.trim() : password;
  const reauthOk = !requireReauth || reauthValue.length > 0;
  const exportOk = exportFirst !== 'skippable' || doExport || skipConfirmed;
  const ready = phraseOk && reauthOk && exportOk && canConfirm && !busy;

  const buildReauth = (): ReAuth =>
    !requireReauth ? {} : useRecovery ? { recovery_phrase: recovery.trim() } : { password };

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!ready) return;
    setError(null);
    setSubmitting(true);
    try {
      await onConfirm({
        reauth: buildReauth(),
        exportFirst: exportFirst === 'skippable' ? doExport : true,
        skipExportConfirm: exportFirst === 'skippable' && !doExport && skipConfirmed,
      });
      onClose();
    } catch (err) {
      // 403 → step-up proof missing/wrong; render the honest re-auth error inline. Any
      // other error surfaces its server message inline AND toasts (the R7 consistency spine).
      if (err instanceof ApiError && err.status === 403) {
        setError(t('confirm.reauth.required'));
      } else {
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
        toast.error(err);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      className="modal-backdrop"
      onClick={() => {
        if (!busy) onClose();
      }}
    >
      <div
        className={`modal${danger ? ' modal--danger' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="modal__head">
          <h2 className="modal__title" id={titleId}>
            {title}
          </h2>
        </header>
        <form className="modal__body" onSubmit={submit} ref={bodyRef}>
          <div className="modal__intro">{intro}</div>

          {children}

          {phrase !== undefined ? (
            <div className="field">
              <label className="field__label" htmlFor={`${titleId}-phrase`}>
                {t('confirm.phraseLabel', { phrase })}
              </label>
              <input
                id={`${titleId}-phrase`}
                className="control mono"
                value={typed}
                autoComplete="off"
                autoCapitalize="characters"
                spellCheck={false}
                placeholder={phrase}
                onChange={(e) => setTyped(e.target.value)}
              />
              {typed.length > 0 && !phraseOk ? (
                <p className="field__error" role="alert">
                  {t('confirm.phraseMismatch')}
                </p>
              ) : null}
            </div>
          ) : null}

          {requireReauth ? (
            <div className="field">
              <label className="field__label" htmlFor={`${titleId}-reauth`}>
                {useRecovery ? t('confirm.reauth.recovery') : t('confirm.reauth.password')}
              </label>
              {useRecovery ? (
                <input
                  id={`${titleId}-reauth`}
                  className="control"
                  type="text"
                  value={recovery}
                  autoComplete="off"
                  onChange={(e) => setRecovery(e.target.value)}
                />
              ) : (
                <input
                  id={`${titleId}-reauth`}
                  className="control"
                  type="password"
                  value={password}
                  autoComplete="current-password"
                  onChange={(e) => setPassword(e.target.value)}
                />
              )}
              <p className="field__hint">
                {t('confirm.reauth.hint')}{' '}
                <button
                  type="button"
                  className="linkish"
                  onClick={() => {
                    setUseRecovery((v) => !v);
                    setError(null);
                  }}
                >
                  {useRecovery ? t('confirm.reauth.usePassword') : t('confirm.reauth.useRecovery')}
                </button>
              </p>
            </div>
          ) : null}

          {exportFirst === 'enforced' ? (
            <p className="modal__note">
              <input type="checkbox" checked disabled aria-hidden="true" />{' '}
              {t('confirm.exportFirst.enforced')}
            </p>
          ) : null}

          {exportFirst === 'skippable' ? (
            <div className="stack--tight">
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={doExport}
                  onChange={(e) => {
                    setDoExport(e.target.checked);
                    if (e.target.checked) setSkipConfirmed(false);
                  }}
                />
                {t('confirm.exportFirst.label')}
              </label>
              {!doExport ? (
                <label className="checkline checkline--warn">
                  <input
                    type="checkbox"
                    checked={skipConfirmed}
                    onChange={(e) => setSkipConfirmed(e.target.checked)}
                  />
                  {t('confirm.exportFirst.skipConfirm')}
                </label>
              ) : null}
            </div>
          ) : null}

          {error ? (
            <p className="field__error" role="alert">
              {error}
            </p>
          ) : null}

          <div className="modal__foot">
            <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button
              type="submit"
              variant={danger ? 'primary' : 'secondary'}
              className={danger ? 'btn--danger' : undefined}
              disabled={!ready}
            >
              {busy ? pendingLabel : confirmLabel}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
