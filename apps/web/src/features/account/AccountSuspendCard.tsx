/**
 * Suspender a minha conta — the self-service lock-out, for when you believe your account is
 * compromised.
 *
 * ## Every part of this design follows from that one sentence
 *
 * - **It is one-way.** Suspending is self-service; lifting it needs `user.manage`. If a user could
 *   lift their own suspension it would not be one — whoever is holding the stolen session holds
 *   exactly the access needed to undo it. There is deliberately no un-suspend control anywhere on
 *   this surface, and no endpoint behind one.
 * - **It is step-up gated.** A session token alone must not suspend an account: locking the real
 *   owner out while you work is precisely what an attacker would do with a stolen session. The
 *   proof is gathered by the shared {@link ConfirmActionModal} with `requireReauth`, which already
 *   offers password / recovery phrase / passkey assertion and renders the server's uniform 403 as
 *   an honest inline re-auth error. No new proof UI, and no chance of this one drifting from the
 *   other step-up surfaces.
 * - **Every session dies, including this one.** The server ends all of them. Neither side can tell
 *   which live session is the attacker's — the request being served may itself be riding the
 *   stolen token — so a suspension that spared any session would achieve nothing. The consequence
 *   is spelled out BEFORE the button, not discovered after it: the operator is about to sign
 *   themselves out and will need an administrator to come back.
 * - **It can be refused.** A sole active Owner suspending themselves would leave nobody able to
 *   lift it, and a sole active user would brick the instance. The server refuses both with a `409`
 *   naming the reason, which surfaces here as the server's own sentence — this screen does not
 *   pre-guess the answer, because the roster it would need to guess from is exactly what an
 *   ordinary user cannot read.
 *
 * ## Why a dedicated card rather than a row in the sessions table
 *
 * "I do not recognise this sign-in" and "my account is compromised" are different judgements with
 * different costs. The first is a per-row revoke that costs nothing and is reversible by signing in
 * again; the second is irreversible without another person. Putting them side by side as peer
 * affordances would invite the second to be pressed for the first's reason.
 */
import { useState } from 'react';
import { useSuspendMyAccount } from '../../api/hooks';
import { useT } from '../../i18n';
import { Button, Card, ConfirmActionModal, Icon, InlineWarning, useToast } from '../../ui';

export function AccountSuspendCard() {
  const t = useT();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const suspend = useSuspendMyAccount();

  return (
    <Card title={t('account.suspend.card')}>
      <div className="stack">
        <p className="field__hint">{t('account.suspend.body')}</p>

        {/* The three consequences, before the control rather than inside the dialog that follows
            it. A confirmation dialog is where you re-state a decision; it is the wrong place to
            introduce one. */}
        <InlineWarning tone="warn" title={t('account.suspend.effect.title')}>
          <ul className="stack--tight">
            <li>{t('account.suspend.effect.sessions')}</li>
            <li>{t('account.suspend.effect.signin')}</li>
            <li>{t('account.suspend.effect.lift')}</li>
          </ul>
        </InlineWarning>

        <div className="form__actions">
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Power />}
            disabled={suspend.isPending}
            data-testid="account-suspend"
            onClick={() => setOpen(true)}
          >
            {suspend.isPending ? t('account.suspend.pending') : t('account.suspend.action')}
          </Button>
        </div>
      </div>

      <ConfirmActionModal
        open={open}
        onClose={() => setOpen(false)}
        danger
        // Step-up, and no type-to-confirm phrase. The phrase rail exists for operations whose blast
        // radius is the whole instance and which no credential could make safe to mistype; this one
        // affects one account, is refused outright when it would strand the instance, and already
        // demands a credential. A second ritual on top would be theatre.
        requireReauth
        title={t('account.suspend.confirm.title')}
        intro={t('account.suspend.confirm.intro')}
        confirmLabel={t('account.suspend.confirm.action')}
        pendingLabel={t('account.suspend.pending')}
        pending={suspend.isPending}
        onConfirm={async ({ reauth }) => {
          await suspend.mutateAsync({ reauth });
          // The session is already dead by the time this resolves — the toast is the last thing
          // this surface says before the auth wall replaces it.
          toast.success(t('account.suspend.done'));
        }}
      />
    </Card>
  );
}
