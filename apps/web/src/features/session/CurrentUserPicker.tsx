/**
 * Current-user picker (plan t14 §2.8) — a compact control at the right of the fixed
 * tab bar. It shows the active user's display name, or the system actor "api" when no
 * one is signed in. Opening it lists the active users; picking one signs in
 * (`POST /v1/session`, token kept in memory), signing out clears the session
 * (`DELETE /v1/session`). While signed in, the API client sends `X-Chancela-Session`
 * on every request so the ledger attributes the actor to the chosen user.
 *
 * The token is deliberately never persisted (see `api/session`); a page reload returns
 * to the system actor until a user is picked again — `useSession` reflects that on load.
 */
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useCreateSession, useDeleteSession, useSession, useUsers } from '../../api/hooks';
import { ApiError } from '../../api/client';
import type { UserView } from '../../api/types';
import { useT } from '../../i18n';
import { useToast } from '../../ui';
import { SignOut } from '../../ui/icons';

export function CurrentUserPicker() {
  const t = useT();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  // The user being switched TO who carries a secret — reveals an inline password prompt.
  const [pending, setPending] = useState<UserView | null>(null);
  const [password, setPassword] = useState('');
  const [wrongPassword, setWrongPassword] = useState(false);
  const session = useSession();
  const users = useUsers();
  const signIn = useCreateSession();
  const signOut = useDeleteSession();

  const currentUser = session.data?.user ?? null;
  const label = currentUser ? currentUser.display_name : 'api';
  const initial = label.charAt(0).toUpperCase();
  const activeUsers = (users.data ?? []).filter((u) => u.active);
  const busy = signIn.isPending || signOut.isPending;
  const actionError = signOut.error;

  // Close on Escape while open.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open]);

  function reset() {
    setPending(null);
    setPassword('');
    setWrongPassword(false);
  }

  function attempt(user: UserView, secret?: string) {
    setWrongPassword(false);
    signIn.mutate(
      { userId: user.id, password: secret },
      {
        onSuccess: () => {
          toast.success(t('toast.signin.success'));
          reset();
          setOpen(false);
        },
        onError: (e) => {
          // 401 → wrong/missing password (inline); everything else (429 backoff…) → toast.
          if (e instanceof ApiError && e.status === 401) {
            setWrongPassword(true);
            setPending(user);
          } else {
            toast.error(e);
          }
        },
      },
    );
  }

  function pick(user: UserView) {
    if (user.id === currentUser?.id) {
      setOpen(false);
      return;
    }
    if (user.has_secret) {
      setPending(user);
      setPassword('');
      setWrongPassword(false);
    } else {
      attempt(user);
    }
  }

  function out() {
    signOut.mutate(undefined, {
      onSuccess: () => {
        reset();
        setOpen(false);
      },
    });
  }

  return (
    <div className="session-picker">
      <button
        type="button"
        data-testid="session-trigger"
        className={`session-picker__trigger${currentUser ? ' is-active' : ''}`}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        title={
          currentUser
            ? t('session.trigger.title.active', { username: currentUser.username })
            : t('session.trigger.title.none')
        }
      >
        <span className="session-picker__avatar" aria-hidden="true">
          {initial}
        </span>
        <span className="session-picker__name">{label}</span>
      </button>

      {open ? (
        <>
          <div
            className="session-picker__backdrop"
            onClick={() => {
              setOpen(false);
              reset();
            }}
            aria-hidden="true"
          />
          <div className="session-picker__menu" role="menu">
            <p className="session-picker__head">
              {currentUser ? (
                <>
                  {t('session.head.activePrefix')}
                  <strong>{currentUser.display_name}</strong>
                </>
              ) : (
                <>{t('session.head.none')}</>
              )}
            </p>

            {pending ? (
              <form
                className="session-picker__pwform"
                onSubmit={(e) => {
                  e.preventDefault();
                  attempt(pending, password);
                }}
              >
                <label className="session-picker__pwlabel" htmlFor="picker-pw">
                  {t('signin.requiresPassword')} — <strong>{pending.display_name}</strong>
                </label>
                <input
                  id="picker-pw"
                  className="control"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t('signin.password.placeholder')}
                  autoComplete="current-password"
                  autoFocus
                />
                {wrongPassword ? (
                  <p className="session-picker__error" role="alert">
                    {t('signin.wrongPassword')}
                  </p>
                ) : null}
                <div className="session-picker__pwactions">
                  <button
                    type="button"
                    className="session-picker__pwback"
                    disabled={busy}
                    onClick={reset}
                  >
                    {t('signin.back')}
                  </button>
                  <button
                    type="submit"
                    className="session-picker__pwsubmit"
                    disabled={busy || password.length === 0}
                  >
                    {busy ? t('signin.submitting') : t('signin.submit')}
                  </button>
                </div>
              </form>
            ) : (
              <div className="session-picker__list">
                {users.isLoading ? (
                  <p className="muted session-picker__empty">{t('common.loading')}</p>
                ) : activeUsers.length === 0 ? (
                  <p className="muted session-picker__empty">{t('session.empty')}</p>
                ) : (
                  activeUsers.map((u) => {
                    const isCurrent = currentUser?.id === u.id;
                    return (
                      <button
                        key={u.id}
                        type="button"
                        role="menuitemradio"
                        aria-checked={isCurrent}
                        className={`session-picker__item${isCurrent ? ' is-current' : ''}`}
                        disabled={busy}
                        onClick={() => pick(u)}
                      >
                        <span className="session-picker__item-name">{u.display_name}</span>
                        <code className="mono session-picker__item-user">{u.username}</code>
                      </button>
                    );
                  })
                )}
              </div>
            )}

            {actionError ? (
              <p className="session-picker__error" role="alert">
                {actionError instanceof Error ? actionError.message : t('session.error.generic')}
              </p>
            ) : null}

            <div className="session-picker__foot">
              {currentUser ? (
                <button
                  type="button"
                  className="session-picker__signout"
                  disabled={busy}
                  onClick={out}
                >
                  <span className="btn__icon">
                    <SignOut />
                  </span>
                  {t('session.signOut')}
                </button>
              ) : (
                <span />
              )}
              <Link
                to="/utilizadores"
                className="session-picker__manage"
                onClick={() => setOpen(false)}
              >
                {t('session.manage')}
              </Link>
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}
