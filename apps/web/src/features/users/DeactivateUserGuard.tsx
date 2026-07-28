/**
 * **The confirm step in front of deactivating an account (t68).**
 *
 * Both places that offer the toggle — the roster row and the edit screen's Estado card — fired
 * `PATCH /v1/users/{id}` on the first click. Deactivation is the product's *only* way to take an
 * account's access away (users are never deleted), so a misplaced click on a dense roster row
 * silently removed someone's ability to sign in with nothing between the pointer and the wire.
 *
 * # Why one module instead of a dialog in each screen
 *
 * The two screens must not be able to drift into two different verdicts about the same action.
 * They share the policy read, the "does this click need a dialog at all" branch, and the copy;
 * each screen supplies only its own mutation.
 *
 * # Deactivating is guarded, reactivating is not
 *
 * The server registry models `user.disable` and has no counterpart for re-enabling — granting
 * sign-in back is not the dangerous direction, and a prompt with no severity behind it devalues
 * the ones that have some. So the guard reads the *target* state and lets a reactivation through
 * untouched.
 *
 * How hard the dialog is to pass is the server's decision, not this module's: strictness and
 * framing come from `GET /v1/confirmation-policy` via {@link GuardedActionModal}. Today
 * `user.disable` is floored at a plain confirm and framed destructive; an operator who raises it
 * gets the stricter dialog here with no change to this file.
 */
import { useState, type ReactElement } from 'react';
import { useT } from '../../i18n';
import type { UserView } from '../../api/types';
import { GuardedActionModal, useGuardedActionPolicy, useToast } from '../../ui';

export interface DeactivateUserGuard {
  /**
   * Call in place of the toggle's old direct mutation. Runs `apply` immediately for a
   * reactivation or an unguarded policy; otherwise opens the dialog and runs nothing.
   */
  requestToggle: () => void;
  /** Render anywhere in the screen; renders nothing until the dialog is open. */
  dialog: ReactElement;
}

/**
 * @param user   The account the toggle acts on; its `active` decides which way the click goes.
 * @param apply  Performs the mutation. Must reject on failure so the dialog can surface the
 *               error inline (and keep itself open) rather than closing over a failed write.
 */
export function useDeactivateUserGuard(
  user: UserView,
  apply: (nextActive: boolean) => Promise<void>,
): DeactivateUserGuard {
  const t = useT();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const policy = useGuardedActionPolicy('user.disable');

  function requestToggle() {
    const nextActive = !user.active;
    if (nextActive || !policy.gated) {
      // The direct path has no dialog to render a failure into, so it keeps the toast the
      // pre-t68 `onError` gave it. The confirmed path deliberately does not toast here — the
      // dialog reports inline (403) or toasts once itself (anything else).
      void apply(nextActive).catch((error: unknown) => toast.error(error));
      return;
    }
    setOpen(true);
  }

  const dialog = (
    <GuardedActionModal
      action="user.disable"
      open={open}
      onClose={() => setOpen(false)}
      title={t('users.disable.confirm.title')}
      intro={
        <div className="stack--tight">
          <p>{t('users.disable.confirm.intro')}</p>
          {/* The account is named on its own labelled line rather than dropped into the sentence
              above: an interpolated name inside an inflected clause breaks agreement in every
              locale that has any. */}
          <p className="mono">{t('users.disable.confirm.subject', { username: user.username })}</p>
        </div>
      }
      confirmLabel={t('users.disable.confirm.action')}
      pendingLabel={t('users.edit.status.pending')}
      onConfirm={() => apply(false)}
    />
  );

  return { requestToggle, dialog };
}
