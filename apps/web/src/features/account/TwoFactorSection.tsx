/**
 * The two-factor (TOTP) block — **one component, two surfaces** (t103's design, extracted here).
 *
 * ## Why it lives in `features/account/` and not beside the admin screen
 *
 * It was written inside `features/users/EditUserPage.tsx`, the *administrative* user screen, and it
 * already forked on `isSelf` because the self and cross-user cases are genuinely different actions.
 * That fork is good and is unchanged. What was wrong was only its address: the self case is the
 * dominant one and the self-service `/account` area needs it, and a second implementation of
 * "enrol my authenticator" is how one of the two quietly stops matching the server. So the
 * component moved to the surface that owns the self case, and the admin screen imports it.
 *
 * `features/account/` is deliberately the home rather than a neutral `features/common/`: everything
 * here is a thing only the account holder may do, and the admin screen borrowing it is the special
 * case, not the other way round.
 *
 * ## The `isSelf` fork is the whole design
 *
 * - **Self** — enrol (`enrol` → show the QR from `provisioning_uri` and the manual `secret`,
 *   both shown once → `confirm` with a code → show the ten backup codes once), regenerate backup
 *   codes, and disable — the last only when the account is not `two_factor_required`, because the
 *   server refuses that with a `409` and offering a button that can only 409 is dishonest.
 * - **Another user (admin)** — read-only state (enrolled / confirmed) plus the **"require 2FA"
 *   toggle**, which IS a legitimate administrative action (`PATCH /v1/users/{id}`
 *   `{ two_factor_required }`, gated `user.manage`, enforced as enrol-on-next-sign-in). There is
 *   deliberately **no** enrol and **no** disable-their-secret cross-user: the secret has to reach
 *   the holder's authenticator, so an admin cannot stand it up, and per the plan there is no admin
 *   reset of another user's TOTP.
 *
 * ## What never persists
 *
 * The `secret`, the `provisioning_uri` and the backup codes are shown once and never cached — they
 * live in local component state for the life of the enrolment and are dropped on completion. No
 * secret material reaches a URL, a log or an error. A wrong confirmation code is a `401` the API
 * client classifies as a credential proof, so a mistyped code does not sign the operator out.
 */
import { useState } from 'react';
import {
  useConfirmTotp,
  useDisableTotp,
  useEnrolTotp,
  useRegenerateBackupCodes,
  useTwoFactor,
  useUpdateUser,
} from '../../api/hooks';
import { ApiError } from '../../api/client';
import type { ReAuth, UserView } from '../../api/types';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  ConfirmActionModal,
  Field,
  Icon,
  InlineWarning,
  Input,
  useToast,
} from '../../ui';
import { QrCode } from '../pairing/QrCode';
import { GateButton } from '../session/permissions';

/**
 * A refused TOTP confirmation code — the `401` the API client flags `credentialProof` (so it
 * leaves the session signed in). Mirrors `UserAccessManager.isRefusedProof`: a wrong code is a
 * proof failure to surface inline, never an expired session that should eject the operator.
 */
function isRefused(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 401 || e.credentialProof === true);
}

/**
 * Once-shown backup codes, in a warning box with a copy affordance (t103).
 *
 * The ten codes are returned by confirm and by regenerate and are shown EXACTLY ONCE — the server
 * keeps only their hashes, so a code that is not copied now is gone. The same shown-once discipline
 * the recovery phrase uses: a copy button, honest "cannot be retrieved later" copy, and the list is
 * dismissed by the operator (never auto-hidden while it may be unread).
 */
function BackupCodesNotice({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const t = useT();
  const toast = useToast();
  function copyAll() {
    if (!navigator.clipboard) return;
    void navigator.clipboard
      .writeText(codes.join('\n'))
      .then(() => toast.success(t('users.totp.backup.copied')))
      .catch(() => {
        /* clipboard denied — the codes are still visible to copy by hand */
      });
  }
  return (
    <InlineWarning tone="warn" title={t('users.totp.backup.title')}>
      <p>{t('users.totp.backup.body')}</p>
      <ul className="totp-backup-codes">
        {codes.map((code) => (
          <li key={code}>
            <code className="mono">{code}</code>
          </li>
        ))}
      </ul>
      <div className="form__actions">
        <Button type="button" variant="secondary" icon={<Icon.Copy />} onClick={copyAll}>
          {t('users.totp.backup.copy')}
        </Button>
        <Button type="button" variant="primary" onClick={onDone}>
          {t('users.recovery.done')}
        </Button>
      </div>
    </InlineWarning>
  );
}

export function TwoFactorSection({ user, isSelf }: { user: UserView; isSelf: boolean }) {
  const t = useT();
  const toast = useToast();
  const status = useTwoFactor(user.id);
  const enrol = useEnrolTotp(user.id);
  const confirm = useConfirmTotp(user.id);
  const disable = useDisableTotp(user.id);
  const regenerate = useRegenerateBackupCodes(user.id);
  const setRequired = useUpdateUser(user.id);

  // The once-shown enrolment material and backup codes live here for the flow's lifetime only.
  const [enrolment, setEnrolment] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  // Open-state for the two step-up dialogs. Both actions destroy a credential, so neither may fire
  // straight from its button.
  const [disabling, setDisabling] = useState(false);
  const [regenerating, setRegenerating] = useState(false);

  // The live two-factor read is the authority; the `UserView` booleans are the fallback for the
  // frame before it lands (and for a `403` on another account, where the read is refused).
  //
  // This matters most on the self-service `/account` surface: its `UserView` comes from
  // `GET /v1/session`, and the enrolment path deliberately does NOT invalidate the session — doing
  // so would lift the second-factor wall and destroy the once-shown backup codes. `keys.userTwoFactor`
  // IS invalidated on confirm/disable, so reading `confirmed` here is what makes the badge and the
  // controls correct on both surfaces without touching the session cache.
  const enrolled = status.data?.confirmed ?? user.has_totp;
  const required = status.data?.required ?? user.two_factor_required;
  const busy = enrol.isPending || confirm.isPending || disable.isPending || regenerate.isPending;

  function startEnrol() {
    setCodeError(null);
    enrol.mutate(undefined, {
      onSuccess: (res) => setEnrolment({ secret: res.secret, uri: res.provisioning_uri }),
      onError: (e) => toast.error(e),
    });
  }

  function submitCode(e: React.FormEvent) {
    e.preventDefault();
    setCodeError(null);
    confirm.mutate(
      { code: code.trim() },
      {
        onSuccess: (res) => {
          setEnrolment(null);
          setCode('');
          setBackupCodes(res.backup_codes);
          toast.success(t('users.totp.enrolled'));
        },
        onError: (err) => {
          // A wrong code is the 401 the client flags as a credential proof (no sign-out). Surface
          // it inline against the field and keep it editable to retry.
          if (isRefused(err)) setCodeError(t('users.totp.code.wrong'));
          else toast.error(err);
        },
      },
    );
  }

  function cancelEnrol() {
    setEnrolment(null);
    setCode('');
    setCodeError(null);
  }

  // Both of these destroy a credential — the second factor itself, or the printed backup codes —
  // so the server demands step-up and the UI has to collect it. They are driven through
  // `ConfirmActionModal` with `requireReauth`, the same way `PasskeySection` revokes a passkey.
  //
  // Errors are deliberately NOT caught here: the modal renders a rejection inline, which is where
  // a refused proof belongs — "that password was wrong" is an answer to the dialog's question, not
  // a toast that outlives the dialog.
  async function confirmDisable({ reauth }: { reauth: ReAuth }) {
    await disable.mutateAsync(reauth);
    toast.success(t('users.totp.disabled'));
    setDisabling(false);
  }

  async function confirmRegenerate({ reauth }: { reauth: ReAuth }) {
    const res = await regenerate.mutateAsync(reauth);
    setBackupCodes(res.backup_codes);
    toast.success(t('users.totp.backup.regenerated'));
    setRegenerating(false);
  }

  function toggleRequired(next: boolean) {
    setRequired.mutate(
      { two_factor_required: next },
      {
        onSuccess: () =>
          toast.success(next ? t('users.totp.required.on') : t('users.totp.required.off')),
        onError: (e) => toast.error(e),
      },
    );
  }

  const remaining = status.data?.backup_codes_remaining;

  return (
    <Card
      title={t('users.totp.title')}
      actions={
        enrolled ? (
          <Badge tone="ok">{t('users.totp.on')}</Badge>
        ) : (
          <Badge tone="neutral">{t('users.totp.off')}</Badge>
        )
      }
    >
      <div className="stack">
        <p className="field__hint">{t('users.totp.intro')}</p>

        {/* The backup codes take over the card while shown once, exactly like the recovery
            phrase — nothing else is actionable until the operator has saved them. */}
        {backupCodes ? (
          <BackupCodesNotice codes={backupCodes} onDone={() => setBackupCodes(null)} />
        ) : isSelf ? (
          enrolment ? (
            // Mid-enrolment: the QR + manual secret (shown once), then the confirmation code.
            <form className="form settings-rows" onSubmit={submitCode}>
              <div className="totp-enrol">
                <QrCode value={enrolment.uri} title={t('users.totp.qr.alt')} size={200} />
                <div className="stack--tight">
                  <p className="field__hint">{t('users.totp.qr.hint')}</p>
                  <p className="totp-enrol__secret">
                    <span className="field__hint">{t('users.totp.secret.label')}</span>{' '}
                    <code className="mono">{enrolment.secret}</code>
                  </p>
                </div>
              </div>
              <Field
                label={t('users.totp.code.label')}
                htmlFor={`totp-code-${user.id}`}
                hint={t('users.totp.code.hint')}
                error={codeError}
              >
                <Input
                  id={`totp-code-${user.id}`}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  spellCheck={false}
                />
              </Field>
              <div className="form__actions">
                <Button type="button" variant="ghost" disabled={busy} onClick={cancelEnrol}>
                  {t('common.cancel')}
                </Button>
                <Button type="submit" variant="primary" disabled={busy || code.trim() === ''}>
                  {confirm.isPending ? t('common.saving') : t('users.totp.confirm')}
                </Button>
              </div>
            </form>
          ) : enrolled ? (
            // Enrolled, self: show how many codes are left, regenerate, and disable (unless the
            // account is required to keep a factor).
            <div className="form settings-rows">
              <Field label={t('users.totp.backup.remainingLabel')}>
                <Badge tone={remaining != null && remaining <= 2 ? 'warn' : 'neutral'}>
                  {remaining ?? '—'}
                </Badge>
              </Field>
              <div className="form__actions">
                <Button
                  type="button"
                  variant="secondary"
                  disabled={busy}
                  onClick={() => setRegenerating(true)}
                >
                  {t('users.totp.backup.regenerate')}
                </Button>
                {required ? (
                  <p className="field__hint">{t('users.totp.required.locked')}</p>
                ) : (
                  <Button
                    type="button"
                    variant="ghost"
                    disabled={busy}
                    onClick={() => setDisabling(true)}
                  >
                    {t('users.totp.disable')}
                  </Button>
                )}
              </div>
            </div>
          ) : (
            // Not enrolled, self: the call to action.
            <div className="form__actions">
              <Button
                type="button"
                variant="primary"
                icon={<Icon.Shield />}
                disabled={busy}
                onClick={startEnrol}
              >
                {t('users.totp.enrol')}
              </Button>
            </div>
          )
        ) : (
          // Cross-user (admin): read-only state + the "require 2FA" toggle. No enrol, no disable.
          <div className="form settings-rows">
            <Field label={t('users.totp.stateLabel')}>
              {enrolled ? (
                <Badge tone="ok">{t('users.totp.on')}</Badge>
              ) : (
                <Badge tone="neutral">{t('users.totp.off')}</Badge>
              )}
            </Field>
            <Field label={t('users.totp.required.label')} help={t('users.totp.required.hint')}>
              <GateButton
                perm="user.manage"
                type="button"
                variant={required ? 'secondary' : 'primary'}
                disabled={setRequired.isPending}
                onClick={() => toggleRequired(!required)}
              >
                {required ? t('users.totp.required.remove') : t('users.totp.required.add')}
              </GateButton>
            </Field>
          </div>
        )}
      </div>
      {/* Step-up dialogs. `requireReauth` collects the proof the server demands; a refused proof
          renders inline in the dialog rather than as a toast that outlives it. */}
      <ConfirmActionModal
        open={disabling}
        onClose={() => setDisabling(false)}
        title={t('users.totp.disable.title')}
        intro={<p>{t('users.totp.disable.consequence')}</p>}
        confirmLabel={t('users.totp.disable.confirm')}
        pendingLabel={t('users.totp.disable.pending')}
        danger
        requireReauth
        pending={disable.isPending}
        onConfirm={confirmDisable}
      />
      <ConfirmActionModal
        open={regenerating}
        onClose={() => setRegenerating(false)}
        title={t('users.totp.backup.regenerate.title')}
        intro={<p>{t('users.totp.backup.regenerate.consequence')}</p>}
        confirmLabel={t('users.totp.backup.regenerate.confirm')}
        pendingLabel={t('users.totp.backup.regenerate.pending')}
        requireReauth
        pending={regenerate.isPending}
        onConfirm={confirmRegenerate}
      />
    </Card>
  );
}
