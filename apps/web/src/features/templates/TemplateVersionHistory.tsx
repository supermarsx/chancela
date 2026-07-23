import { useId, useState, type FormEvent } from 'react';
import {
  useDeleteTemplateVersion,
  useRenameTemplateVersion,
  useRestoreTemplateVersion,
  useTemplateVersions,
} from '../../api/hooks';
import type { TemplateSummary, TemplateVersionEntry } from '../../api/types';
import { useTemplatesVersionHistoryT } from '../../i18n/templatesVersionHistoryFallback';
import {
  Button,
  ConfirmActionModal,
  DateTime,
  EmptyState,
  ErrorNote,
  Input,
  InlineWarning,
  SkeletonRegion,
  SkeletonTable,
  Table,
  useToast,
} from '../../ui';
import './templateVersionHistory.css';
import { normalizeTemplateVersionName } from './templateVersionNames';

type PendingAction =
  | { kind: 'delete'; entry: TemplateVersionEntry }
  | { kind: 'restore'; entry: TemplateVersionEntry }
  | null;

export interface TemplateVersionHistoryProps {
  /** The user-template id whose global save history should be shown. */
  templateId: string;
  /** Allows a mounted-but-hidden tab to avoid fetching until selected. */
  enabled?: boolean;
  /** Lets the editor replace its local draft/read model after an exact restore. */
  onRestored?: (template: TemplateSummary) => void;
  /** Visible reason that restore is unavailable while the surrounding editor has local work. */
  restoreBlockedReason?: string;
  /** Hide the component's visual heading when the surrounding tab already supplies one. */
  hideHeading?: boolean;
}

/**
 * Standalone version-history UI for a user template. It owns all server state and confirmations,
 * while the editor only needs to pass `templateId` and optionally refresh its draft on restore.
 */
export function TemplateVersionHistory({
  templateId,
  enabled = true,
  onRestored,
  restoreBlockedReason,
  hideHeading = false,
}: TemplateVersionHistoryProps) {
  const t = useTemplatesVersionHistoryT();
  const toast = useToast();
  const history = useTemplateVersions(templateId, enabled);
  const rename = useRenameTemplateVersion(templateId);
  const remove = useDeleteTemplateVersion(templateId);
  const restore = useRestoreTemplateVersion(templateId);
  const [editing, setEditing] = useState<TemplateVersionEntry | null>(null);
  const [draftName, setDraftName] = useState('');
  const [nameError, setNameError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction>(null);
  const titleId = useId();
  const renameErrorId = useId();
  const restoreBlockedId = useId();

  function beginRename(entry: TemplateVersionEntry) {
    setEditing(entry);
    setDraftName(entry.name ?? '');
    setNameError(null);
  }

  function cancelRename() {
    if (rename.isPending) return;
    setEditing(null);
    setDraftName('');
    setNameError(null);
  }

  async function submitRename(event: FormEvent) {
    event.preventDefault();
    if (!editing || rename.isPending) return;
    const normalized = normalizeTemplateVersionName(draftName);
    if (normalized.tooLong) {
      setNameError(t('templates.versions.renameTooLong'));
      return;
    }
    setNameError(null);
    try {
      await rename.mutateAsync({ versionId: editing.id, name: normalized.value || null });
      toast.success(t('templates.versions.renamed'));
      cancelRename();
    } catch (error) {
      toast.error(error);
    }
  }

  async function confirmPendingAction() {
    if (!pendingAction) return;
    if (pendingAction.kind === 'delete') {
      await remove.mutateAsync(pendingAction.entry.id);
      toast.success(t('templates.versions.deleted'));
      setPendingAction(null);
      return;
    }
    // Defend the mutation boundary as well as the button: the reason can become active after a
    // restore confirmation was opened, and that must never turn into silent local-data loss.
    if (restoreBlockedReason) {
      setPendingAction(null);
      return;
    }
    const restored = await restore.mutateAsync(pendingAction.entry.id);
    toast.success(t('templates.versions.restored'));
    onRestored?.(restored);
    setPendingAction(null);
  }

  const actionPending = pendingAction?.kind === 'delete' ? remove.isPending : restore.isPending;

  return (
    <section
      className="template-version-history"
      aria-labelledby={hideHeading ? undefined : titleId}
      aria-label={hideHeading ? t('templates.versions.title') : undefined}
    >
      {!hideHeading ? <h2 id={titleId}>{t('templates.versions.title')}</h2> : null}

      {history.isLoading ? (
        <SkeletonRegion>
          <SkeletonTable cols={4} />
        </SkeletonRegion>
      ) : null}
      {history.error ? <ErrorNote error={history.error} /> : null}

      {history.data ? (
        <p className="template-version-history__retention">
          {t('templates.versions.retention', { count: history.data.history_limit })}
        </p>
      ) : null}

      {restoreBlockedReason ? (
        <div id={restoreBlockedId}>
          <InlineWarning tone="warn" title={t('templates.versions.restoreBlockedTitle')}>
            <p>{restoreBlockedReason}</p>
          </InlineWarning>
        </div>
      ) : null}

      {history.data?.entries.length === 0 ? (
        <EmptyState title={t('templates.versions.empty')} />
      ) : null}

      {history.data && history.data.entries.length > 0 ? (
        <Table
          className="template-version-history__table"
          caption={t('templates.versions.caption')}
          head={
            <tr>
              <th scope="col">{t('templates.versions.name')}</th>
              <th scope="col">{t('templates.versions.savedAt')}</th>
              <th scope="col">{t('templates.versions.actor')}</th>
              <th scope="col">{t('templates.versions.actions')}</th>
            </tr>
          }
        >
          {history.data.entries.map((entry) => {
            const isEditing = editing?.id === entry.id;
            return (
              <tr key={entry.id}>
                <td className="template-version-history__name">
                  {isEditing ? (
                    <form className="template-version-history__rename" onSubmit={submitRename}>
                      <label className="sr-only" htmlFor={`template-version-name-${entry.id}`}>
                        {t('templates.versions.renameLabel')}
                      </label>
                      <Input
                        id={`template-version-name-${entry.id}`}
                        value={draftName}
                        autoFocus
                        aria-invalid={!!nameError}
                        aria-describedby={nameError ? renameErrorId : undefined}
                        onChange={(event) => {
                          setDraftName(event.target.value);
                          if (nameError) setNameError(null);
                        }}
                      />
                      <div className="template-version-history__rename-actions">
                        <Button type="submit" variant="secondary" disabled={rename.isPending}>
                          {rename.isPending
                            ? t('templates.versions.renamePending')
                            : t('templates.versions.renameSave')}
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          disabled={rename.isPending}
                          onClick={cancelRename}
                        >
                          {t('templates.versions.renameCancel')}
                        </Button>
                      </div>
                      <p className="field__hint">{t('templates.versions.renameHint')}</p>
                      {nameError ? (
                        <p id={renameErrorId} className="field__error" role="alert">
                          {nameError}
                        </p>
                      ) : null}
                    </form>
                  ) : (
                    <span className={entry.name ? undefined : 'muted'}>
                      {entry.name || t('templates.versions.unnamed')}
                    </span>
                  )}
                </td>
                <td>
                  <DateTime value={entry.created_at} evidentiary />
                </td>
                <td className="mono">{entry.created_by}</td>
                <td>
                  <div className="template-version-history__actions">
                    <Button
                      type="button"
                      variant="ghost"
                      disabled={isEditing || actionPending}
                      onClick={() => beginRename(entry)}
                    >
                      {t('templates.versions.rename')}
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      disabled={isEditing || actionPending || !!restoreBlockedReason}
                      aria-describedby={restoreBlockedReason ? restoreBlockedId : undefined}
                      onClick={() => setPendingAction({ kind: 'restore', entry })}
                    >
                      {t('templates.versions.restore')}
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      disabled={isEditing || actionPending}
                      onClick={() => setPendingAction({ kind: 'delete', entry })}
                    >
                      {t('templates.versions.delete')}
                    </Button>
                  </div>
                </td>
              </tr>
            );
          })}
        </Table>
      ) : null}

      <ConfirmActionModal
        open={pendingAction !== null}
        onClose={() => setPendingAction(null)}
        title={
          pendingAction?.kind === 'delete'
            ? t('templates.versions.deleteTitle')
            : t('templates.versions.restoreTitle')
        }
        intro={
          pendingAction?.kind === 'delete'
            ? t('templates.versions.deleteIntro')
            : t('templates.versions.restoreIntro')
        }
        confirmLabel={
          pendingAction?.kind === 'delete'
            ? t('templates.versions.deleteConfirm')
            : t('templates.versions.restoreConfirm')
        }
        pendingLabel={
          pendingAction?.kind === 'delete'
            ? t('templates.versions.deletePending')
            : t('templates.versions.restorePending')
        }
        danger={pendingAction?.kind === 'delete'}
        pending={actionPending}
        onConfirm={confirmPendingAction}
      />
    </section>
  );
}
