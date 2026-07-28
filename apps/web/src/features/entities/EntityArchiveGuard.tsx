/**
 * **The confirm step in front of retiring an entity from new authorship (t84).**
 *
 * `POST /v1/entities/{id}/archive` landed complete and tested server-side with no way to reach it
 * from the web app. This module is that way in, and it is the ONLY one: both directions of the
 * toggle run through `requestToggle`, so no screen can acquire a second opinion about when the
 * dialog is owed.
 *
 * # Archiving is guarded; unarchiving is not — and that is the server's ruling, not this file's
 *
 * `confirmation.rs`'s `ROUTE_GUARD` gates `/v1/entities/{id}/archive` on
 * `ConfirmationAction::EntityArchive` and marks `/v1/entities/{id}/unarchive` explicitly
 * `NotGuarded`: *"Granting the ability to start work back is not the dangerous direction, and it is
 * separately ledgered."* So the guard reads the entity's CURRENT state and lets a return to active
 * authorship through untouched — the same asymmetry `DeactivateUserGuard` follows for
 * `user.disable`, and for the same reason: a prompt with no severity behind it devalues the ones
 * that have some.
 *
 * How hard the archive dialog is to pass is likewise the server's decision. Strictness and framing
 * come from `GET /v1/confirmation-policy` via {@link GuardedActionModal}; today `entity.archive` is
 * floored at a plain `confirm` and classed `Consequential` (NOT `Destructive`), so the dialog is
 * deliberately not red. An operator who raises the level gets the stricter dialog with no change
 * here.
 *
 * `entity.archive` is both the confirmation-action id and the permission id. They are separate
 * namespaces that happen to share a spelling: the string below feeds the policy lookup, while the
 * *permission* of the same name gates the control that calls `requestToggle` (see `EntitiesPage`).
 *
 * # Why the copy insists on what archiving does NOT do
 *
 * Archiving withdraws the invitation to *start* work and withdraws nothing else — nothing is hidden
 * and nothing is removed, and the default listing keeps returning archived rows. The dialog spends
 * a whole paragraph on what is kept, because an operator who reads "archive" as "delete" will
 * either avoid a safe action or, worse, learn to expect that this product removes records. See
 * `i18n/entityArchiveFallback.ts`.
 */
import { useState, type ReactElement } from 'react';
import { useArchiveEntity, useUnarchiveEntity } from '../../api/hooks';
import type { Entity } from '../../api/types';
import { useEntityArchiveT } from '../../i18n/entityArchiveFallback';
import { GuardedActionModal, useGuardedActionPolicy, useToast } from '../../ui';

export interface EntityArchiveGuard {
  /**
   * Call in place of a direct mutation. Runs the unarchive immediately, or — for an archive —
   * opens the dialog and issues NO request until it is confirmed. When the policy resolves
   * `entity.archive` to `off`, the archive runs immediately too, which is what `off` means.
   */
  requestToggle: () => void;
  /** Render anywhere in the screen; renders nothing until the dialog is open. */
  dialog: ReactElement;
  /** Whether either direction is in flight, for the caller's own control state. */
  pending: boolean;
}

/**
 * @param entity  The row the control acts on; its `archived` decides which way the click goes.
 */
export function useEntityArchiveGuard(entity: Entity): EntityArchiveGuard {
  const at = useEntityArchiveT();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const policy = useGuardedActionPolicy('entity.archive');
  const archive = useArchiveEntity(entity.id);
  const unarchive = useUnarchiveEntity(entity.id);

  // `archived` is the server's derived boolean; `archived_at` is the timestamp behind it. Read the
  // flag, and fall back to the timestamp so a response that carried only the latter still resolves.
  const isArchived = entity.archived ?? entity.archived_at != null;

  async function runArchive() {
    await archive.mutateAsync();
    toast.success(at('archiveDone'));
  }

  function requestToggle() {
    if (isArchived) {
      // The unguarded direction keeps a toast for its failure, because it has no dialog to render
      // one into. The confirmed path deliberately does not toast its error here — the dialog
      // reports inline (403) or toasts once itself.
      unarchive
        .mutateAsync()
        .then(() => toast.success(at('unarchiveDone')))
        .catch((error: unknown) => toast.error(error));
      return;
    }
    if (!policy.gated) {
      void runArchive().catch((error: unknown) => toast.error(error));
      return;
    }
    setOpen(true);
  }

  const dialog = (
    <GuardedActionModal
      action="entity.archive"
      open={open}
      onClose={() => setOpen(false)}
      title={at('archiveTitle')}
      intro={
        <div className="stack--tight">
          <p>{at('archiveIntro')}</p>
          <p>{at('archiveKeeps')}</p>
          {/* The entity is named on its own labelled line rather than dropped into either sentence
              above: an interpolated noun inside an inflected clause breaks agreement in every
              locale that has any. */}
          <p className="mono">{at('archiveSubject', { name: entity.name })}</p>
        </div>
      }
      confirmLabel={at('archiveConfirm')}
      pendingLabel={at('archivePending')}
      pending={archive.isPending}
      // The gathered `ConfirmActionArgs` are ignored: the endpoint is a bodyless `204` POST that
      // accepts no `ConfirmationProof`, and at the registry's `confirm` floor there is none to
      // send. Matches `DeactivateUserGuard`, whose `user.disable` endpoint is the same shape.
      onConfirm={() => runArchive()}
    />
  );

  return { requestToggle, dialog, pending: archive.isPending || unarchive.isPending };
}
