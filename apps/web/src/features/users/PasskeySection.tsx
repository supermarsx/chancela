/**
 * Chaves de acesso — the passkey block on the Segurança tab (t10).
 *
 * ## The `isSelf` fork is not cosmetic, it mirrors the server's authorization split
 *
 * `GET /v1/users/{id}/passkeys` is self-or-`user.manage`; **enrol, rename and revoke are
 * self-only** and refused in the handler. So an administrator sees the list — which is genuinely
 * useful, "does this colleague hold a passkey?" is an operational question — and is offered no
 * control at all. That is not an over-cautious UI choice: a passkey is created by touching an
 * authenticator that is physically present, so enrolling one for someone else is not a coherent
 * operation, and an administrator who could revoke one silently could lock a colleague out without
 * the account-lifecycle guard ever being consulted for their own account.
 *
 * ## What the list has to show, and why each column earns its place
 *
 * Name, created and last-used identify a credential. **Backup state** is the one an operator
 * deciding what to revoke actually needs and the one that is easiest to leave out: a synced
 * credential survives losing the device, a device-bound one does not, and "remove the one on the
 * laptop I dropped" has opposite answers depending on which it was.
 *
 * A credential enrolled under a previous RP ID comes back `usable: false`. It is still listed —
 * it is still enrolled and only its holder can remove it — with the current domain named, because
 * "my passkey is broken" and "the administrator moved this instance" send a person to two
 * different places and only the second is true.
 *
 * ## Two sentences that must be said before they are discovered
 *
 * 1. **A passkey never removes the password.** The attestation key keeps its password wrap
 *    always — the server refuses to remove it while a key exists — so "passwordless" here means no
 *    password *at sign-in*, never no password *wrap*. Implying otherwise would be an overclaim
 *    about key custody.
 * 2. **A non-PRF authenticator degrades**, and the sentence belongs at enrolment. Such a
 *    credential signs the user in but cannot unwrap their attestation key, so the first document
 *    they attest asks for their password. An operator who meets that mid-ceremony, at signing
 *    time, files a support ticket; one who was told at enrolment does not.
 *
 * ## Revocation
 *
 * Through {@link ConfirmActionModal} with `requireReauth`, because the server demands step-up — a
 * credential operation must not ride a session alone. The account-lifecycle refusal (revoking the
 * last thing that can start a session) is surfaced from the server's `409`, **never pre-empted
 * with a disabled button**: the predicate is over every credential kind the account holds, and
 * re-deriving it here would be a second implementation of the lockout rule, free to disagree with
 * the first.
 */
import { useState } from 'react';
import {
  useBeginPasskeyEnrolment,
  useFinishPasskeyEnrolment,
  usePasskeys,
  useRenamePasskey,
  useRevokePasskey,
} from '../../api/hooks';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n/types';
import {
  Badge,
  Button,
  Card,
  ColumnHead,
  DateTime,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  SkeletonTable,
  Table,
  useToast,
} from '../../ui';
import { ConfirmActionModal } from '../../ui/ConfirmActionModal';
import { isPermissionError, PermissionDeniedNote } from '../session/permissions';
import { api } from '../../api/client';
import {
  describeCeremonyFailure,
  passkeySupport,
  runAssertionCeremonyWithPrf,
  runEnrolmentCeremony,
  type CeremonyFailure,
} from '../session/webauthn';
import type { PasskeyView, UserView } from '../../api/types';

/** The refusal copy for each way a browser ceremony can end without a credential. */
const FAILURE_COPY: Record<CeremonyFailure, MessageKey> = {
  cancelled: 'users.passkeys.error.cancelled',
  already_enrolled: 'users.passkeys.error.alreadyEnrolled',
  rp_id_mismatch: 'users.passkeys.error.rpIdMismatch',
  unsupported: 'users.passkeys.error.unsupported',
  not_user_verified: 'users.passkeys.error.notUserVerified',
  failed: 'users.passkeys.error.failed',
};

/**
 * How a credential survives — or does not survive — losing the device it lives on.
 *
 * Three states rather than two, because "eligible but not yet backed up" is a real and temporary
 * condition (a platform authenticator whose sync has not run) and calling it either of the other
 * two would be wrong in the direction that matters: telling someone a credential is safe when it
 * is not yet.
 */
function backupLabel(passkey: PasskeyView): MessageKey {
  switch (passkey.backup) {
    case 'exists':
      return 'users.passkeys.backup.exists';
    case 'eligible':
      return 'users.passkeys.backup.eligible';
    default:
      return 'users.passkeys.backup.notEligible';
  }
}

/** Rename one credential in place. A blank label is refused here and by the server. */
function RenameForm({
  passkey,
  userId,
  onDone,
}: {
  passkey: PasskeyView;
  userId: string;
  onDone: () => void;
}) {
  const t = useT();
  const toast = useToast();
  const rename = useRenamePasskey(userId);
  const [name, setName] = useState(passkey.name);
  const trimmed = name.trim();

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (trimmed === '' || trimmed === passkey.name) return;
    rename.mutate(
      { credentialId: passkey.credential_id, name: trimmed },
      {
        onSuccess: () => {
          toast.success(t('users.passkeys.renamed'));
          onDone();
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <form className="passkey-rename" onSubmit={submit}>
      <Input
        value={name}
        onChange={(e) => setName(e.target.value)}
        // The column's own name, not the enrolment field's. Both controls edit the same thing, so
        // reusing `users.passkeys.name.label` would put two identically-named fields on one screen
        // — indistinguishable to anyone navigating by accessible name, which is the only way this
        // control is reachable at all (it has no visible label; the column header is its context).
        aria-label={t('users.passkeys.col.name')}
        autoComplete="off"
        autoFocus
      />
      <Button
        type="submit"
        variant="primary"
        icon={<Icon.Check />}
        disabled={rename.isPending || trimmed === '' || trimmed === passkey.name}
      >
        {rename.isPending ? t('common.saving') : t('common.save')}
      </Button>
      <Button type="button" variant="ghost" disabled={rename.isPending} onClick={onDone}>
        {t('common.cancel')}
      </Button>
    </form>
  );
}

export function PasskeySection({ user, isSelf }: { user: UserView; isSelf: boolean }) {
  const t = useT();
  const toast = useToast();
  const list = usePasskeys(user.id);
  const begin = useBeginPasskeyEnrolment(user.id);
  const finish = useFinishPasskeyEnrolment(user.id);
  const revoke = useRevokePasskey(user.id);

  const [name, setName] = useState('');
  const [renaming, setRenaming] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<PasskeyView | null>(null);
  // The credential that just enrolled, so the note can name it and say whether it ended up
  // passwordless. Held in state rather than derived from the list, because it is a notice about an
  // action just taken — showing it on every render would make it wallpaper.
  const [justEnrolled, setJustEnrolled] = useState<{ name: string; passwordless: boolean } | null>(
    null,
  );

  const unavailable = passkeySupport();
  const passkeys = list.data?.passkeys ?? [];
  const rpId = list.data?.rp_id;
  const configured = list.data?.enrolment_available ?? false;
  const busy = begin.isPending || finish.isPending;

  async function enrol() {
    setJustEnrolled(null);
    try {
      const options = await begin.mutateAsync();
      const credential = await runEnrolmentCeremony(options);
      const enrolled = await finish.mutateAsync({
        credential,
        ...(name.trim() === '' ? {} : { name: name.trim() }),
      });
      setName('');
      toast.success(t('users.passkeys.enrolled'));

      // **The PRF wrap — a second `get()` right after `create()`.** `webauthn_rp` cannot evaluate
      // PRF at creation, so a separate ceremony reads this credential's PRF output and seals a wrap
      // of the attestation key under it. Best-effort: a browser without PRF, a cancelled second
      // prompt, or a session whose key is not unlocked all degrade to the password fallback — the
      // credential is already enrolled and works either way. The copy below then follows the wrap
      // that actually exists (`unlocks_without_password`), never the capability that might have.
      let passwordless = enrolled.unlocks_without_password;
      try {
        const prfOptions = await api.beginPasskeyPrfWrap(user.id, enrolled.credential_id);
        const { credential: prfCredential, prfSecret } =
          await runAssertionCeremonyWithPrf(prfOptions);
        if (prfSecret) {
          const wrapped = await api.finishPasskeyPrfWrap(user.id, enrolled.credential_id, {
            credential: prfCredential,
            prf_secret: prfSecret,
          });
          passwordless = wrapped.unlocks_without_password;
        }
      } catch {
        // Degrade silently: enrolment succeeded; this credential simply asks for the password.
      }
      // The wrap changed the row after the enrolment hook's own invalidation, so refresh the list.
      void list.refetch();
      setJustEnrolled({ name: enrolled.name, passwordless });
    } catch (error) {
      // A ceremony that never reached the server (cancelled, wrong RP ID, an authenticator that
      // could not comply) is a DOM exception the server has no opinion about, so it is translated
      // here. Anything that did reach the server keeps the server's own message.
      if (error instanceof Error && !('status' in error)) {
        toast.error(t(FAILURE_COPY[describeCeremonyFailure(error)]));
      } else {
        toast.error(error);
      }
    }
  }

  return (
    <Card
      title={t('users.passkeys.title')}
      actions={
        passkeys.length > 0 ? (
          <Badge tone="ok">{t('users.passkeys.count', { count: passkeys.length })}</Badge>
        ) : (
          <Badge tone="neutral">{t('users.passkeys.none')}</Badge>
        )
      }
    >
      <div className="stack">
        <p className="field__hint">
          {isSelf ? t('users.passkeys.intro.self') : t('users.passkeys.intro.other')}
        </p>

        {/* The overclaim guard, stated wherever passkeys are: the attestation key keeps its
            password wrap always, so a passkey removes the password from SIGN-IN and from nothing
            else. Shown on both the holder's view and an administrator's, because both are places
            someone might conclude otherwise. */}
        <p className="field__hint">{t('users.passkeys.passwordNote')}</p>

        {list.isLoading ? (
          <SkeletonTable cols={4} />
        ) : list.error ? (
          isPermissionError(list.error) ? (
            <PermissionDeniedNote />
          ) : (
            <ErrorNote error={list.error} />
          )
        ) : passkeys.length === 0 ? (
          <EmptyState title={t('users.passkeys.empty')}>
            <p>{isSelf ? t('users.passkeys.emptyBody') : t('users.passkeys.emptyBody.other')}</p>
          </EmptyState>
        ) : (
          <Table
            caption={t('users.passkeys.caption')}
            head={
              <tr>
                <th>{t('users.passkeys.col.name')}</th>
                {/* `ColumnHead` renders its own `<th>`; wrapping it in another would nest one
                    header cell inside the next. */}
                <ColumnHead
                  label={t('users.passkeys.col.type')}
                  help={t('users.passkeys.col.type.help')}
                />
                <th>{t('users.passkeys.col.created')}</th>
                <th>{t('users.passkeys.col.lastUsed')}</th>
                {isSelf ? <th>{t('users.passkeys.col.action')}</th> : null}
              </tr>
            }
          >
            {passkeys.map((passkey) => (
              <tr key={passkey.credential_id}>
                <td>
                  {renaming === passkey.credential_id ? (
                    <RenameForm
                      passkey={passkey}
                      userId={user.id}
                      onDone={() => setRenaming(null)}
                    />
                  ) : (
                    <span className="stack--tight">
                      <span>{passkey.name}</span>
                      {/* An explicit space, never a CSS gap: a margin inserts no character, so
                          without it the label and the badge read fused to a screen reader and to
                          find-in-page. */}
                      {passkey.usable ? null : (
                        <span>
                          <Badge tone="warn" wrap>
                            {t('users.passkeys.unusable.badge')}
                          </Badge>{' '}
                          <span className="field__hint">
                            {t('users.passkeys.unusable.hint', {
                              enrolled: passkey.rp_id,
                              current: rpId ?? '—',
                            })}
                          </span>
                        </span>
                      )}
                      {/* The passwordless marker keys on `unlocks_without_password` — the wrap that
                          exists — never on `prf_capable`, the capability that might have. A capable
                          authenticator whose wrap ceremony never completed falls back like any
                          other, and a badge on it would promise a passwordless path it does not
                          have. An explicit space, never a CSS gap, for the same screen-reader
                          reason as the domain badge above. */}
                      {passkey.unlocks_without_password ? (
                        <span>
                          {' '}
                          <Badge tone="ok" wrap>
                            {t('users.passkeys.passwordless.badge')}
                          </Badge>
                        </span>
                      ) : null}
                    </span>
                  )}
                </td>
                <td>
                  <Badge tone={passkey.backup === 'exists' ? 'ok' : 'neutral'} wrap>
                    {t(backupLabel(passkey))}
                  </Badge>
                </td>
                <td>
                  <DateTime value={passkey.created_at} />
                </td>
                <td>
                  {passkey.last_used_at ? (
                    <DateTime value={passkey.last_used_at} />
                  ) : (
                    <span className="muted">{t('users.passkeys.neverUsed')}</span>
                  )}
                </td>
                {/* Cross-user the column is absent entirely rather than rendered empty: a header
                    over nothing invites the reading that the controls failed to load. */}
                {isSelf ? (
                  <td className="table-action-cell">
                    <span className="table-actions">
                      <Button
                        type="button"
                        variant="ghost"
                        icon={<Icon.Pencil />}
                        disabled={renaming === passkey.credential_id}
                        onClick={() => setRenaming(passkey.credential_id)}
                      >
                        {t('users.passkeys.rename')}
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        icon={<Icon.Trash />}
                        onClick={() => setRevoking(passkey)}
                      >
                        {t('users.passkeys.revoke')}
                      </Button>
                    </span>
                  </td>
                ) : null}
              </tr>
            ))}
          </Table>
        )}

        {justEnrolled ? (
          justEnrolled.passwordless ? (
            // The wrap sealed: this credential signs in and attests with no password. Said only now
            // it is genuinely true — «sem palavra-passe» is a claim about the wrap that exists, not
            // the capability that might have.
            <InlineWarning tone="info" title={t('users.passkeys.passwordlessNote.title')}>
              <p>{t('users.passkeys.passwordlessNote.body', { name: justEnrolled.name })}</p>
            </InlineWarning>
          ) : (
            // Said at enrolment, which is the entire point: meeting it mid-attestation, at signing
            // time, is a support incident. `info` rather than `warn` — nothing went wrong and the
            // credential does exactly what it was enrolled to do; the password is simply still the
            // thing that opens the audit key.
            <InlineWarning tone="info" title={t('users.passkeys.signingNote.title')}>
              <p>{t('users.passkeys.signingNote.body', { name: justEnrolled.name })}</p>
            </InlineWarning>
          )
        ) : null}

        {!isSelf ? (
          <p className="field__hint">{t('users.passkeys.crossUser.note')}</p>
        ) : unavailable === 'desktop_shell' ? (
          // One honest sentence, and no control. Passkeys cannot work in the desktop shell on any
          // platform — the custom protocol admits only `tauri.localhost` as an RP ID, and
          // WebKitGTK implements no WebAuthn at all — so an enrol button here could only throw.
          <InlineWarning tone="info">{t('users.passkeys.unavailable.desktop')}</InlineWarning>
        ) : unavailable === 'browser' ? (
          <InlineWarning tone="info">{t('users.passkeys.unavailable.browser')}</InlineWarning>
        ) : !configured ? (
          // An instance-configuration state, not a user error, and the copy says whose job it is.
          // The RP ID is a one-way operator choice: a credential is permanently bound to the domain
          // it was created under, so nothing can be defaulted on an administrator's behalf.
          <InlineWarning tone="info" title={t('users.passkeys.unconfigured.title')}>
            <p>{t('users.passkeys.unconfigured.body')}</p>
          </InlineWarning>
        ) : (
          <form
            className="form settings-rows"
            onSubmit={(e) => {
              e.preventDefault();
              void enrol();
            }}
          >
            <Field
              label={t('users.passkeys.name.label')}
              htmlFor={`passkey-name-${user.id}`}
              help={t('users.passkeys.name.hint')}
            >
              <Input
                id={`passkey-name-${user.id}`}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t('users.passkeys.name.placeholder')}
                autoComplete="off"
              />
            </Field>
            {/* One passkey is one lost phone away from a lockout, so the second one is pushed
                rather than merely permitted. */}
            {passkeys.length === 1 ? (
              <p className="field__hint">{t('users.passkeys.addSecond')}</p>
            ) : null}
            <div className="form__actions">
              <Button type="submit" variant="primary" icon={<Icon.Plus />} disabled={busy}>
                {busy ? t('users.passkeys.adding') : t('users.passkeys.add')}
              </Button>
            </div>
          </form>
        )}
      </div>

      <ConfirmActionModal
        open={revoking !== null}
        onClose={() => setRevoking(null)}
        title={t('users.passkeys.revoke.title')}
        intro={
          <>
            <p>{t('users.passkeys.revoke.intro', { name: revoking?.name ?? '' })}</p>
            {/* Revoking destroys this credential's PRF wrap. The attestation key survives as long
                as any wrap survives — and the password wrap always does — so this is a "you will
                type your password again", never a "you lose your signing identity". */}
            <p>{t('users.passkeys.revoke.consequence')}</p>
          </>
        }
        confirmLabel={t('users.passkeys.revoke.confirm')}
        pendingLabel={t('users.passkeys.revoke.pending')}
        danger
        requireReauth
        pending={revoke.isPending}
        onConfirm={async ({ reauth }) => {
          if (!revoking) return;
          // Deliberately NOT caught here: `ConfirmActionModal` renders a rejection inline, which is
          // where the account-lifecycle `409` has to land — "removing this would leave you no way
          // to sign in" is an answer to the dialog's question, not a toast that outlives it.
          await revoke.mutateAsync({ credentialId: revoking.credential_id, reauth });
          toast.success(t('users.passkeys.revoked'));
          setRevoking(null);
        }}
      />
    </Card>
  );
}
