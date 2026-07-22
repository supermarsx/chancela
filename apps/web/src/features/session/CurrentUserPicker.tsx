/**
 * Current-user picker (plan t14 §2.8) — a compact control at the right of the fixed
 * tab bar. It shows the active user's display name, or the system actor "api" when no
 * one is signed in. Opening it lists the accounts used on this device; picking one prompts
 * for a password and signs in (`POST /v1/session`), signing out clears the session
 * (`DELETE /v1/session`). While signed in, the API client sends `X-Chancela-Session` on every
 * request so the ledger attributes the actor to the chosen user.
 *
 * ## The list is DEVICE-LOCAL, never the instance roster (t94)
 * This menu used to render `GET /v1/users` — every account on the instance, to anyone signed
 * in who holds `user.read@Global`. That is the same enumeration the sign-in screen shed in
 * t33, just moved behind the login. It now reads the identical store the sign-in screen uses
 * ({@link recentAccounts}: identifiers that have SUCCESSFULLY signed in in this browser), so
 * the two surfaces cannot drift apart, plus the current user pinned at the top so a
 * just-signed-in operator never faces an empty menu.
 *
 * Consequences worth keeping straight:
 *  - Switching only ever targets an identifier already remembered here, so the picker adds no
 *    NEW username to storage — it only refreshes the `lastUsedAt` of one already present.
 *    The sign-in screen's "guardar neste dispositivo" opt-out therefore still means what it
 *    says: opting out there keeps the identifier out of localStorage for good.
 *  - The ✕ on a row is {@link forgetAccount} — a localStorage delete and nothing else. It
 *    never touches the server; the account is untouched and can sign in again by typing.
 *  - The current user's row has no ✕ (forgetting the identity you are using is nonsense) and
 *    it is display-only: pinning it does not write it to storage.
 *
 * The token is held in tab-scoped `sessionStorage` (see `api/session`), so a page reload keeps
 * the same user signed in rather than dropping to the system actor. Signing out clears it on
 * both sides; closing the tab clears it here.
 */
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useCreateSession, useDeleteSession, useSession } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { useT } from '../../i18n';
import { Icon, Tooltip, useToast } from '../../ui';
import { SignOut } from '../../ui/icons';
import { forgetAccount, readRecentAccounts, rememberAccount } from './recentAccounts';
import { useAuthWallT } from './authWallCopy';

/** One row of the menu: an identifier known on this device, or the pinned current user. */
interface PickerEntry {
  username: string;
  displayName: string;
  /** The signed-in identity — pinned, checked, and not removable. */
  isCurrent: boolean;
}

export function CurrentUserPicker() {
  const t = useT();
  const st = useAuthWallT();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  // The identity being switched TO — reveals an inline password prompt.
  const [pending, setPending] = useState<PickerEntry | null>(null);
  const [password, setPassword] = useState('');
  const [wrongPassword, setWrongPassword] = useState(false);
  const [recents, setRecents] = useState(() => readRecentAccounts());
  const session = useSession();
  const signIn = useCreateSession();
  const signOut = useDeleteSession();
  const menuRef = useRef<HTMLDivElement | null>(null);

  const currentUser = session.data?.user ?? null;
  const label = currentUser ? currentUser.display_name : 'api';
  const initial = label.charAt(0).toUpperCase();
  const busy = signIn.isPending || signOut.isPending;
  const actionError = signOut.error;

  // The current user first (pinned, display-only), then the identifiers this browser
  // remembers, most-recent first, minus a duplicate of the pinned one.
  const entries: PickerEntry[] = [
    ...(currentUser
      ? [
          {
            username: currentUser.username,
            displayName: currentUser.display_name,
            isCurrent: true,
          },
        ]
      : []),
    ...recents
      .filter((r) => r.username.toLowerCase() !== (currentUser?.username ?? '').toLowerCase())
      .map((r) => ({
        username: r.username,
        displayName: r.displayName ?? r.username,
        isCurrent: false,
      })),
  ];

  // Another tab (or the sign-in screen before this one mounted) may have changed the stored
  // list, so re-read it each time the menu opens rather than trusting mount-time state.
  useEffect(() => {
    if (open) setRecents(readRecentAccounts());
  }, [open]);

  // Close on Escape while open.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open]);

  /** The `role="menuitemradio"` buttons currently rendered in the open popup (list mode). */
  function menuItems(): HTMLElement[] {
    const root = menuRef.current;
    if (!root) return [];
    return Array.from(root.querySelectorAll<HTMLElement>('[role="menuitemradio"]'));
  }

  // On open (list mode), move focus to the currently-checked item, or the first — matching the
  // ARIA menu pattern's initial-focus intent. Re-runs when the row count changes (the session
  // read may still be in flight on open). In password mode the form's own `autoFocus` owns
  // focus, so we skip it there.
  useEffect(() => {
    if (!open || pending) return;
    const items = menuItems();
    if (items.length === 0) return;
    const checked = items.find((el) => el.getAttribute('aria-checked') === 'true');
    (checked ?? items[0]).focus();
  }, [open, pending, entries.length]);

  // Roving focus for the ARIA menu: Arrow keys step between menuitems (wrapping at the ends),
  // Home/End jump to the first/last. Native button tabbing (and the trap-free Tab flow) is left
  // untouched. A no-op in password mode, where `menuItems()` is empty.
  function onMenuKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    const { key } = e;
    if (key !== 'ArrowDown' && key !== 'ArrowUp' && key !== 'Home' && key !== 'End') return;
    const items = menuItems();
    if (items.length === 0) return;
    e.preventDefault();
    const active = document.activeElement as HTMLElement | null;
    const at = active ? items.indexOf(active) : -1;
    let next: number;
    if (key === 'Home') next = 0;
    else if (key === 'End') next = items.length - 1;
    else if (key === 'ArrowDown') next = at < 0 ? 0 : (at + 1) % items.length;
    else next = at < 0 ? items.length - 1 : (at - 1 + items.length) % items.length;
    items[next].focus();
  }

  function reset() {
    setPending(null);
    setPassword('');
    setWrongPassword(false);
  }

  function attempt(entry: PickerEntry, secret: string) {
    setWrongPassword(false);
    // By identifier, exactly as the sign-in screen does — the id is not stored on this device
    // and the server resolves the username itself (t33-e2).
    signIn.mutate(
      { username: entry.username, password: secret },
      {
        onSuccess: (result) => {
          // A target account with a confirmed second factor answers `POST /v1/session` with a
          // challenge, not a token (t95 P2). The in-session switcher has no second-factor step —
          // that lives only on the signed-out sign-in screen — so the switch cannot complete here.
          // Leave the current session untouched and point the user at the sign-in screen.
          if ('two_factor_challenge' in result) {
            toast.error(st('signin.challenge.switcherUnsupported'));
            reset();
            return;
          }
          // Only on success, and only for an identifier already remembered here: this
          // refreshes its ordering, it never introduces a new one.
          setRecents(
            rememberAccount({
              username: result.user.username,
              displayName: result.user.display_name,
            }),
          );
          toast.success(t('toast.signin.success'));
          reset();
          setOpen(false);
        },
        onError: (e) => {
          // 401 → wrong/missing password (inline); everything else (429 backoff…) → toast.
          if (e instanceof ApiError && e.status === 401) {
            setWrongPassword(true);
            setPending(entry);
          } else {
            toast.error(e);
          }
        },
      },
    );
  }

  function pick(entry: PickerEntry) {
    if (entry.isCurrent) {
      setOpen(false);
      return;
    }
    setPending(entry);
    setPassword('');
    setWrongPassword(false);
  }

  function out() {
    signOut.mutate(undefined, {
      onSuccess: () => {
        // Sign-in success is toasted in `attempt` (above); sign-out is toasted here — the
        // two never fire together (t44-retrofit-b partition). R7: the inline `actionError`
        // note below still renders on a sign-out failure.
        toast.success(t('toast.signout.success'));
        reset();
        setOpen(false);
      },
      onError: (e) => toast.error(e),
    });
  }

  return (
    <div className="session-picker">
      <Tooltip
        label={
          currentUser
            ? t('session.trigger.title.active', { username: currentUser.username })
            : t('session.trigger.title.none')
        }
        placement="bottom"
      >
        <button
          type="button"
          data-testid="session-trigger"
          className={`session-picker__trigger${currentUser ? ' is-active' : ''}`}
          aria-haspopup="menu"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
        >
          <span className="session-picker__avatar" aria-hidden="true">
            {initial}
          </span>
          <span className="session-picker__name">{label}</span>
        </button>
      </Tooltip>

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
          <div className="session-picker__menu" role="menu" ref={menuRef} onKeyDown={onMenuKeyDown}>
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
                  {t('signin.requiresPassword')} — <strong>{pending.displayName}</strong>
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
              // No fetch backs this list: it is the current identity plus what this browser
              // remembers, so there is nothing to wait for and no skeleton to show.
              <div className="session-picker__list">
                {entries.length === 0 ? (
                  <p className="muted session-picker__empty">{t('session.empty')}</p>
                ) : (
                  entries.map((entry) => (
                    <div key={entry.username} className="session-picker__row">
                      <button
                        type="button"
                        role="menuitemradio"
                        aria-checked={entry.isCurrent}
                        className={`session-picker__item${entry.isCurrent ? ' is-current' : ''}`}
                        disabled={busy}
                        onClick={() => pick(entry)}
                      >
                        <span className="session-picker__item-name">{entry.displayName}</span>
                        <code className="mono session-picker__item-user">{entry.username}</code>
                      </button>
                      {entry.isCurrent ? null : (
                        <button
                          type="button"
                          className="session-picker__forget"
                          aria-label={t('signin.recent.remove', { username: entry.username })}
                          disabled={busy}
                          onClick={() => setRecents(forgetAccount(entry.username))}
                        >
                          <Icon.Close />
                        </button>
                      )}
                    </div>
                  ))
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
                to="/settings/users"
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
