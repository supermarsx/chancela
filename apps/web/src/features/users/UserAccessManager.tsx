/**
 * Per-user access + audit management (plan t44 §5, t29 §5.2, t51) — the sign-in password,
 * the PKI audit-attestation key, and the one-time recovery phrase controls for one user,
 * shown on that user's edit screen.
 *
 * ## Honest boundaries (t29 §0/§6, plan R3)
 * The password is a LOCAL tamper speed-bump, not at-rest encryption. The attestation key is
 * an attestation, "não uma assinatura qualificada".
 *
 * ## Cross-user authorization (t51)
 * Editing your OWN account keeps the self-service flow: changing/replacing a password (and
 * every key op once a secret exists) proves your CURRENT password. Editing ANOTHER user
 * (cross-user — the session user id differs from the edited user id) requires a proof of
 * authority on every secret/key/recovery mutation: EITHER the target's current password OR a
 * valid one-time recovery phrase. The backend refuses a missing/wrong cross-user proof with
 * a **403** (distinct from the 401 session error) — we surface that as an inline refusal and
 * an error toast, and keep the fields editable so the operator can retry.
 *
 * The recovery phrase is generated server-side and returned exactly once; we show it once,
 * with a copy affordance and honest "cannot be retrieved later" copy, and never persist it.
 */
import { useEffect, useRef, useState } from 'react';
import type {
  AttestationKeyBody,
  IssueRecoveryBody,
  SetSecretBody,
  UserView,
} from '../../api/types';
import { ApiError } from '../../api/client';
import {
  useCreateAttestationKey,
  useIssueRecovery,
  useRemoveAttestationKey,
  useSession,
  useSetUserSecret,
} from '../../api/hooks';
import { useT } from '../../i18n';
import { Badge, Button, Field, Icon, InlineWarning, Input, Select, useToast } from '../../ui';

type PwMode = null | 'set' | 'change';
type ProofKind = 'password' | 'recovery';

/** How long the once-shown recovery phrase may sit on the clipboard before a best-effort wipe. */
const CLIPBOARD_CLEAR_MS = 60_000;

/**
 * Best-effort defense-in-depth: after {@link CLIPBOARD_CLEAR_MS}, wipe the clipboard IFF it still
 * holds exactly `secret`, so the once-shown recovery phrase does not linger indefinitely. Never
 * throws, never blocks, and never clears unrelated content — if clipboard read-back is unavailable
 * or denied it silently does nothing. The pending timer lives in `ref` so a re-copy or an unmount
 * can cancel it.
 */
function scheduleClipboardClear(
  ref: { current: ReturnType<typeof setTimeout> | null },
  secret: string,
): void {
  if (ref.current) clearTimeout(ref.current);
  ref.current = setTimeout(() => {
    ref.current = null;
    void (async () => {
      try {
        if (typeof navigator === 'undefined' || !navigator.clipboard?.readText) return;
        const current = await navigator.clipboard.readText();
        if (current === secret) await navigator.clipboard.writeText('');
      } catch {
        /* read-back unavailable or denied — leave the clipboard untouched */
      }
    })();
  }, CLIPBOARD_CLEAR_MS);
}

/**
 * The cross-user proof control: pick the proof kind (the target's current password or a
 * recovery phrase) and enter it. Rendered only when editing another user; the `forbidden`
 * flag attaches the 403 refusal inline against the value field (kept editable to retry).
 */
function ProofFields({
  idPrefix,
  kind,
  onKind,
  value,
  onValue,
  forbidden,
}: {
  idPrefix: string;
  kind: ProofKind;
  onKind: (k: ProofKind) => void;
  value: string;
  onValue: (v: string) => void;
  forbidden: boolean;
}) {
  const t = useT();
  return (
    <>
      <Field
        label={t('users.proof.label')}
        htmlFor={`${idPrefix}-kind`}
        hint={t('users.proof.hint')}
      >
        <Select
          id={`${idPrefix}-kind`}
          value={kind}
          onChange={(e) => onKind(e.target.value as ProofKind)}
          options={[
            { value: 'password', label: t('users.proof.password') },
            { value: 'recovery', label: t('users.proof.recovery') },
          ]}
        />
      </Field>
      <Field
        label={kind === 'password' ? t('users.proof.password') : t('users.proof.recovery')}
        htmlFor={`${idPrefix}-val`}
        error={forbidden ? t('users.secret.forbidden') : undefined}
      >
        <Input
          id={`${idPrefix}-val`}
          type={kind === 'password' ? 'password' : 'text'}
          value={value}
          onChange={(e) => onValue(e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
      </Field>
    </>
  );
}

export function UserAccessManager({ user }: { user: UserView }) {
  const t = useT();
  const toast = useToast();
  const session = useSession();
  const setSecret = useSetUserSecret(user.id);
  const createKey = useCreateAttestationKey(user.id);
  const removeKey = useRemoveAttestationKey(user.id);
  const issueRecovery = useIssueRecovery(user.id);

  // Cross-vs-self: cross-user only when we KNOW the session user and it differs from the
  // edited user. When the session is unknown (loading/signed out) we default to the
  // self-service flow — the backend remains the real gate and a wrong guess simply surfaces
  // its 403, which we handle inline.
  const isCrossUser = !!session.data?.user && session.data.user.id !== user.id;

  const [pwMode, setPwMode] = useState<PwMode>(null);
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [current, setCurrent] = useState('');
  const [pwLocalError, setPwLocalError] = useState<string | null>(null);
  // Cross-user proof for the password block.
  const [pwProofKind, setPwProofKind] = useState<ProofKind>('password');
  const [pwProofValue, setPwProofValue] = useState('');
  const [pwForbidden, setPwForbidden] = useState(false);

  const [keyCurrent, setKeyCurrent] = useState('');

  // Recovery-phrase block (t51).
  const [recOpen, setRecOpen] = useState(false);
  const [recProofKind, setRecProofKind] = useState<ProofKind>('password');
  const [recProofValue, setRecProofValue] = useState('');
  const [recForbidden, setRecForbidden] = useState(false);
  const [recPhrase, setRecPhrase] = useState<string | null>(null);
  const recClearTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Cancel any pending recovery-phrase clipboard wipe when this manager unmounts.
  useEffect(() => {
    return () => {
      if (recClearTimerRef.current) clearTimeout(recClearTimerRef.current);
    };
  }, []);

  const pwBusy = setSecret.isPending;
  const keyBusy = createKey.isPending || removeKey.isPending;

  function resetPw() {
    setPwMode(null);
    setNext('');
    setConfirm('');
    setCurrent('');
    setPwLocalError(null);
    setPwProofKind('password');
    setPwProofValue('');
    setPwForbidden(false);
  }

  /** 403 → inline refusal (retryable); every error still toasts the server's PT message. */
  function handleSecretError(e: unknown) {
    if (e instanceof ApiError && e.status === 403) setPwForbidden(true);
    toast.error(e);
  }

  /** The cross-user proof to attach to a secret/key body from the password-block selection. */
  function pwProof(): { current_password?: string; recovery_phrase?: string } {
    return pwProofKind === 'recovery'
      ? { recovery_phrase: pwProofValue || undefined }
      : { current_password: pwProofValue || undefined };
  }

  function submitSecret() {
    setPwLocalError(null);
    setPwForbidden(false);
    if (next.length < 8) {
      setPwLocalError(t('users.secret.hint'));
      return;
    }
    if (next !== confirm) {
      setPwLocalError(t('users.secret.mismatch'));
      return;
    }
    const body: SetSecretBody = { password: next };
    if (isCrossUser) Object.assign(body, pwProof());
    else if (pwMode === 'change') body.current_password = current;
    setSecret.mutate(body, {
      onSuccess: () => {
        toast.success(t('toast.secret.set'));
        resetPw();
      },
      onError: handleSecretError,
    });
  }

  // Key ops: a cross-user caller proves the target's current password via the same field
  // (recovery cannot GENERATE a key — backend 403s that path — so the key block offers the
  // password proof only, which authorizes both generate and remove).
  function keyBody(): AttestationKeyBody {
    return { current_password: keyCurrent || undefined };
  }

  function generateKey() {
    createKey.mutate(keyBody(), {
      onSuccess: () => {
        toast.success(t('toast.key.generated'));
        setKeyCurrent('');
      },
      onError: (e) => toast.error(e),
    });
  }

  function deleteKey() {
    removeKey.mutate(keyBody(), {
      onSuccess: () => {
        toast.success(t('toast.key.removed'));
        setKeyCurrent('');
      },
      onError: (e) => toast.error(e),
    });
  }

  function resetRec() {
    setRecOpen(false);
    setRecProofKind('password');
    setRecProofValue('');
    setRecForbidden(false);
  }

  function submitRecovery() {
    setRecForbidden(false);
    const body: IssueRecoveryBody = {};
    if (isCrossUser) {
      if (recProofKind === 'recovery') body.recovery_phrase = recProofValue || undefined;
      else body.current_password = recProofValue || undefined;
    } else if (user.has_secret) {
      // Self-service: prove the current password when one is set (legacy no-hash state has none).
      body.current_password = recProofValue || undefined;
    }
    issueRecovery.mutate(body, {
      onSuccess: (res) => {
        setRecPhrase(res.recovery_phrase);
        resetRec();
        toast.success(t('toast.recovery.issued'));
      },
      onError: (e) => {
        if (e instanceof ApiError && e.status === 403) setRecForbidden(true);
        toast.error(e);
      },
    });
  }

  function copyPhrase() {
    if (recPhrase && navigator.clipboard) {
      const phrase = recPhrase;
      void navigator.clipboard
        .writeText(phrase)
        .then(() => {
          toast.success(t('users.recovery.copied'));
          scheduleClipboardClear(recClearTimerRef, phrase);
        })
        .catch(() => {
          /* clipboard denied — the phrase is still visible to copy manually */
        });
    }
  }

  return (
    <div className="access-manager">
      {isCrossUser ? (
        <InlineWarning tone="info">{t('users.access.crossUserNote')}</InlineWarning>
      ) : null}

      {/* --- Password --------------------------------------------------------- */}
      {/* t51-e3: cross-user password-change proof — when editing another user the
          change/set controls collect the target's current password OR a recovery
          phrase (ProofFields) and send it on the secret mutation; a 403 refusal renders
          inline (retryable) and toasts. Self-service keeps the current-password flow. */}
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
              <Button variant="secondary" onClick={() => setPwMode('change')}>
                {t('users.secret.change')}
              </Button>
            ) : (
              <Button variant="secondary" icon={<Icon.Plus />} onClick={() => setPwMode('set')}>
                {t('users.secret.set')}
              </Button>
            )}
          </div>
        ) : (
          <form
            className="access-manager__form"
            onSubmit={(e) => {
              e.preventDefault();
              submitSecret();
            }}
          >
            {isCrossUser ? (
              <ProofFields
                idPrefix={`sec-proof-${user.id}`}
                kind={pwProofKind}
                onKind={setPwProofKind}
                value={pwProofValue}
                onValue={setPwProofValue}
                forbidden={pwForbidden}
              />
            ) : pwMode === 'change' ? (
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

      {/* --- Recovery phrase (t51) -------------------------------------------- */}
      <div className="access-manager__block">
        <div className="access-manager__head">
          <span className="access-manager__label">{t('users.recovery.label')}</span>
          {user.has_recovery_phrase ? (
            <Badge tone="accent">{t('users.recovery.has')}</Badge>
          ) : (
            <Badge tone="neutral">{t('users.recovery.none')}</Badge>
          )}
        </div>
        <p className="access-manager__note">{t('users.recovery.description')}</p>

        {recPhrase ? (
          <InlineWarning tone="warn" title={t('users.recovery.shownOnceTitle')}>
            <p>{t('users.recovery.shownOnceBody')}</p>
            <p className="access-manager__recovery-phrase">
              <code className="mono">{recPhrase}</code>
            </p>
            <div className="access-manager__actions">
              <Button type="button" variant="secondary" icon={<Icon.Copy />} onClick={copyPhrase}>
                {t('users.recovery.copy')}
              </Button>
              <Button type="button" variant="primary" onClick={() => setRecPhrase(null)}>
                {t('users.recovery.done')}
              </Button>
            </div>
          </InlineWarning>
        ) : recOpen ? (
          <form
            className="access-manager__form"
            onSubmit={(e) => {
              e.preventDefault();
              submitRecovery();
            }}
          >
            {isCrossUser ? (
              <ProofFields
                idPrefix={`rec-proof-${user.id}`}
                kind={recProofKind}
                onKind={setRecProofKind}
                value={recProofValue}
                onValue={setRecProofValue}
                forbidden={recForbidden}
              />
            ) : user.has_secret ? (
              <Field
                label={t('users.secret.current')}
                htmlFor={`rec-cur-${user.id}`}
                hint={t('users.recovery.selfHint')}
                error={recForbidden ? t('users.secret.forbidden') : undefined}
              >
                <Input
                  id={`rec-cur-${user.id}`}
                  type="password"
                  value={recProofValue}
                  onChange={(e) => setRecProofValue(e.target.value)}
                  autoComplete="current-password"
                />
              </Field>
            ) : null}
            <div className="access-manager__actions">
              <Button
                type="button"
                variant="ghost"
                disabled={issueRecovery.isPending}
                onClick={resetRec}
              >
                {t('common.cancel')}
              </Button>
              <Button type="submit" variant="primary" disabled={issueRecovery.isPending}>
                {issueRecovery.isPending ? t('common.saving') : t('users.recovery.issueSubmit')}
              </Button>
            </div>
          </form>
        ) : (
          <div className="access-manager__actions">
            <Button variant="secondary" icon={<Icon.Seal />} onClick={() => setRecOpen(true)}>
              {user.has_recovery_phrase ? t('users.recovery.rotate') : t('users.recovery.generate')}
            </Button>
          </div>
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
              label={isCrossUser ? t('users.proof.password') : t('users.secret.current')}
              htmlFor={`key-cur-${user.id}`}
              hint={isCrossUser ? t('users.proof.keyGenNote') : t('users.secret.currentHint')}
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
