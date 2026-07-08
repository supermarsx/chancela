/**
 * Per-user access + audit management (plan t44 §5, t29 §5.2) — the sign-in password and
 * PKI audit-attestation key controls for one user, shown inline on the Utilizadores page.
 *
 * ## Honest boundaries (t29 §0/§6, plan R3)
 * The password is a LOCAL tamper speed-bump, not at-rest encryption. There is no admin
 * reset: removing it destroys the attestation key with it (the key's KEK is derived from
 * the secret), and a lost password makes the key unrecoverable. The attestation key is an
 * attestation, "não uma assinatura qualificada".
 *
 * Changing/removing a password, and every key operation once a secret exists, require the
 * CURRENT password (verified server-side; a wrong one is a 401 whose PT message is
 * surfaced via toast).
 */
import { useState } from 'react';
import type { UserView } from '../../api/types';
import {
  useCreateAttestationKey,
  useRemoveAttestationKey,
  useRemoveUserSecret,
  useSetUserSecret,
} from '../../api/hooks';
import { useT } from '../../i18n';
import { Badge, Button, Field, Icon, InlineWarning, Input, useToast } from '../../ui';

type PwMode = null | 'set' | 'change' | 'remove';

export function UserAccessManager({ user }: { user: UserView }) {
  const t = useT();
  const toast = useToast();
  const setSecret = useSetUserSecret(user.id);
  const removeSecret = useRemoveUserSecret(user.id);
  const createKey = useCreateAttestationKey(user.id);
  const removeKey = useRemoveAttestationKey(user.id);

  const [pwMode, setPwMode] = useState<PwMode>(null);
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [current, setCurrent] = useState('');
  const [pwLocalError, setPwLocalError] = useState<string | null>(null);

  const [keyCurrent, setKeyCurrent] = useState('');

  const pwBusy = setSecret.isPending || removeSecret.isPending;
  const keyBusy = createKey.isPending || removeKey.isPending;

  function resetPw() {
    setPwMode(null);
    setNext('');
    setConfirm('');
    setCurrent('');
    setPwLocalError(null);
  }

  function submitSecret() {
    setPwLocalError(null);
    if (next.length < 8) {
      setPwLocalError(t('users.secret.hint'));
      return;
    }
    if (next !== confirm) {
      setPwLocalError(t('users.secret.mismatch'));
      return;
    }
    setSecret.mutate(
      { password: next, current_password: pwMode === 'change' ? current : undefined },
      {
        onSuccess: () => {
          toast.success(t('toast.secret.set'));
          resetPw();
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  function submitRemoveSecret() {
    removeSecret.mutate(
      { current_password: current || undefined },
      {
        onSuccess: () => {
          toast.success(t('toast.secret.removed'));
          resetPw();
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  function generateKey() {
    createKey.mutate(
      { current_password: keyCurrent || undefined },
      {
        onSuccess: () => {
          toast.success(t('toast.key.generated'));
          setKeyCurrent('');
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  function deleteKey() {
    removeKey.mutate(
      { current_password: keyCurrent || undefined },
      {
        onSuccess: () => {
          toast.success(t('toast.key.removed'));
          setKeyCurrent('');
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <div className="access-manager">
      {/* --- Password --------------------------------------------------------- */}
      <div className="access-manager__block">
        <div className="access-manager__head">
          <span className="access-manager__label">{t('users.secret.label')}</span>
          {user.has_secret ? (
            <Badge tone="ok">{t('users.secret.has')}</Badge>
          ) : (
            <Badge tone="neutral">{t('users.secret.none')}</Badge>
          )}
        </div>

        {pwMode === null ? (
          <div className="access-manager__actions">
            {user.has_secret ? (
              <>
                <Button variant="secondary" onClick={() => setPwMode('change')}>
                  {t('users.secret.change')}
                </Button>
                <Button variant="ghost" icon={<Icon.Trash />} onClick={() => setPwMode('remove')}>
                  {t('users.secret.remove')}
                </Button>
              </>
            ) : (
              <Button variant="secondary" icon={<Icon.Plus />} onClick={() => setPwMode('set')}>
                {t('users.secret.set')}
              </Button>
            )}
          </div>
        ) : pwMode === 'remove' ? (
          <form
            className="access-manager__form"
            onSubmit={(e) => {
              e.preventDefault();
              submitRemoveSecret();
            }}
          >
            <InlineWarning tone="warn">{t('users.access.cascadeWarning')}</InlineWarning>
            <Field
              label={t('users.secret.current')}
              htmlFor={`sec-cur-${user.id}`}
              hint={t('users.secret.currentHint')}
            >
              <Input
                id={`sec-cur-${user.id}`}
                type="password"
                value={current}
                onChange={(e) => setCurrent(e.target.value)}
                autoComplete="current-password"
              />
            </Field>
            <div className="access-manager__actions">
              <Button type="button" variant="ghost" disabled={pwBusy} onClick={resetPw}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" variant="primary" disabled={pwBusy}>
                {pwBusy ? t('common.saving') : t('users.secret.remove')}
              </Button>
            </div>
          </form>
        ) : (
          <form
            className="access-manager__form"
            onSubmit={(e) => {
              e.preventDefault();
              submitSecret();
            }}
          >
            {pwMode === 'change' ? (
              <Field
                label={t('users.secret.current')}
                htmlFor={`sec-cur-${user.id}`}
                hint={t('users.secret.currentHint')}
              >
                <Input
                  id={`sec-cur-${user.id}`}
                  type="password"
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                  autoComplete="current-password"
                />
              </Field>
            ) : null}
            <Field
              label={t('users.secret.new')}
              htmlFor={`sec-new-${user.id}`}
              hint={t('users.secret.hint')}
            >
              <Input
                id={`sec-new-${user.id}`}
                type="password"
                value={next}
                onChange={(e) => setNext(e.target.value)}
                autoComplete="new-password"
              />
            </Field>
            <Field
              label={t('users.secret.confirm')}
              htmlFor={`sec-cnf-${user.id}`}
              error={pwLocalError}
            >
              <Input
                id={`sec-cnf-${user.id}`}
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                autoComplete="new-password"
              />
            </Field>
            <div className="access-manager__actions">
              <Button type="button" variant="ghost" disabled={pwBusy} onClick={resetPw}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" variant="primary" disabled={pwBusy || next.length === 0}>
                {pwBusy ? t('common.saving') : t('common.save')}
              </Button>
            </div>
          </form>
        )}
      </div>

      {/* --- Attestation key -------------------------------------------------- */}
      <div className="access-manager__block">
        <div className="access-manager__head">
          <span className="access-manager__label">{t('users.key.label')}</span>
          {user.has_attestation_key ? (
            <Badge tone="ok">{t('users.key.has')}</Badge>
          ) : (
            <Badge tone="neutral">{t('users.key.none')}</Badge>
          )}
        </div>

        {user.has_attestation_key && user.attestation_key_fingerprint ? (
          <p className="access-manager__fingerprint">
            <span className="access-manager__fplabel">{t('users.key.fingerprint')}:</span>{' '}
            <code className="mono">{user.attestation_key_fingerprint}</code>
          </p>
        ) : null}

        {!user.has_secret ? (
          <InlineWarning tone="info">{t('users.key.requiresSecret')}</InlineWarning>
        ) : (
          <form
            className="access-manager__form"
            onSubmit={(e) => {
              e.preventDefault();
              generateKey();
            }}
          >
            <Field
              label={t('users.secret.current')}
              htmlFor={`key-cur-${user.id}`}
              hint={t('users.secret.currentHint')}
            >
              <Input
                id={`key-cur-${user.id}`}
                type="password"
                value={keyCurrent}
                onChange={(e) => setKeyCurrent(e.target.value)}
                autoComplete="current-password"
              />
            </Field>
            <div className="access-manager__actions">
              <Button type="submit" variant="secondary" icon={<Icon.Seal />} disabled={keyBusy}>
                {keyBusy
                  ? t('common.saving')
                  : user.has_attestation_key
                    ? t('users.key.rotate')
                    : t('users.key.generate')}
              </Button>
              {user.has_attestation_key ? (
                <Button
                  type="button"
                  variant="ghost"
                  icon={<Icon.Trash />}
                  disabled={keyBusy}
                  onClick={deleteKey}
                >
                  {t('users.key.remove')}
                </Button>
              ) : null}
            </div>
          </form>
        )}
      </div>

      <p className="access-manager__note">{t('users.access.note')}</p>
    </div>
  );
}
