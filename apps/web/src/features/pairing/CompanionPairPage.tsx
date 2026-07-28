/**
 * The **companion side** of device pairing (t70) — the page the phone loads from the QR.
 *
 * The desktop half of this flow has existed since wp27-e5 and looks finished: it mints a code,
 * renders a QR and a deep link, and polls for the enrolment. Nothing consumed that link. This is
 * the page that does.
 *
 * # It is deliberately outside `Layout`
 *
 * The whole point of the pairing handshake (`crates/chancela-api/src/pairing.rs`) is that the
 * operator obtains a session on the phone **without** typing their password into a remote WebView.
 * A phone arriving here therefore has no session, so this route sits beside
 * `/external-signature` outside the authenticated shell. Putting it inside would send every
 * visitor to the sign-in screen — which is the one screen this flow exists to avoid.
 *
 * # What it does NOT decide
 *
 * Which proofs are acceptable is the server's answer, not this page's. `?methods=` only chooses
 * which inputs to render, and is presentational for exactly that reason: it rides in a URL an
 * operator can edit, so a tampered value can add a field but can never make the server accept one.
 * `POST /v1/pairing/exchange` re-decides every time, and an unaccepted proof is a `403` whatever
 * this page drew. When the parameter is absent or unreadable the page offers **every** method
 * rather than guessing — an operator being shown one field too many is a smaller failure than
 * being shown none of the one they hold.
 *
 * # The code leaves the URL
 *
 * The pairing code is read once and then stripped from the address bar, mirroring
 * `ExternalSignerInvitePage`. A phone's history, and whatever sync it has turned on, is not a
 * place for a live credential — even a five-minute one.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../../api/client';
import type {
  PairingConfirmationMethod,
  PairingConfirmationProof,
  PairingExchanged,
} from '../../api/types';
import { useT } from '../../i18n';
import { Button, Card, ErrorNote, Field, Icon, InlineWarning, Input } from '../../ui';

/** Every method the client knows how to collect. The server still decides which it accepts. */
const ALL_METHODS: PairingConfirmationMethod[] = ['password', 'totp_code', 'emailed_code'];

/**
 * Read `?methods=` into a set of methods to offer.
 *
 * Unknown entries are dropped rather than rendered: a value this page cannot collect a proof for
 * would draw a field that goes nowhere. If nothing recognisable survives, every method is offered —
 * see the module header on why that direction, and not "offer nothing", is the safe one here. This
 * is a display choice with no security consequence, so being generous costs nothing.
 */
export function parseOfferedMethods(raw: string | null): PairingConfirmationMethod[] {
  if (!raw) return ALL_METHODS;
  const asked = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  const offered = ALL_METHODS.filter((method) => asked.includes(method));
  return offered.length > 0 ? offered : ALL_METHODS;
}

export function CompanionPairPage() {
  const t = useT();
  const [params, setParams] = useSearchParams();

  // Read the code once, then take it out of the address bar.
  const [code] = useState(() => params.get('code') ?? '');
  const offered = useMemo(() => parseOfferedMethods(params.get('methods')), [params]);

  const [method, setMethod] = useState<PairingConfirmationMethod>(() => offered[0]);
  const [secret, setSecret] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [paired, setPaired] = useState<PairingExchanged | null>(null);

  useEffect(() => {
    if (!params.get('code')) return;
    const next = new URLSearchParams(params);
    next.delete('code');
    setParams(next, { replace: true });
  }, [params, setParams]);

  const submit = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      setError(null);
      setPending(true);
      try {
        // Exactly one proof is sent — the one the operator chose. Sending every field with the
        // others blank would let a blank land in a slot the server then has to reason about.
        const confirmation: PairingConfirmationProof = { [method]: secret.trim() };
        setPaired(await api.exchangePairingCode({ code, confirmation }));
      } catch (e) {
        setError(e);
      } finally {
        setPending(false);
      }
    },
    [code, method, secret],
  );

  if (paired) {
    return (
      <main className="pairing-companion">
        {/* The card keeps the page's identity across every state; the panel inside it is what
            reports the outcome. Repeating the outcome as the card title too said the same thing
            twice in a row. */}
        <Card title={t('companionPair.title')}>
          <InlineWarning tone="info" title={t('companionPair.done.title')}>
            <div className="stack--tight">
              <p>{t('companionPair.done.body')}</p>
              {/* An appended labelled line, never a noun dropped into an inflected sentence. */}
              <p className="field__hint">
                {t('companionPair.done.confirmedBy')}{' '}
                <strong>{t(`companionPair.method.${paired.confirmed_by}`)}</strong>
              </p>
            </div>
          </InlineWarning>
        </Card>
      </main>
    );
  }

  if (!code) {
    return (
      <main className="pairing-companion">
        <Card title={t('companionPair.title')}>
          <InlineWarning tone="warn" title={t('companionPair.noCode.title')}>
            {t('companionPair.noCode.body')}
          </InlineWarning>
        </Card>
      </main>
    );
  }

  return (
    <main className="pairing-companion">
      <Card title={t('companionPair.title')}>
        <form className="form settings-rows" onSubmit={(e) => void submit(e)}>
          <p className="field__hint">{t('companionPair.lede')}</p>

          {offered.length > 1 ? (
            <Field label={t('companionPair.method.label')} htmlFor="companion-method">
              <select
                id="companion-method"
                className="input"
                value={method}
                onChange={(e) => {
                  setMethod(e.target.value as PairingConfirmationMethod);
                  // The previous proof is for a different method; carrying it over would submit
                  // one credential in another's slot.
                  setSecret('');
                }}
              >
                {offered.map((option) => (
                  <option key={option} value={option}>
                    {t(`companionPair.method.${option}`)}
                  </option>
                ))}
              </select>
            </Field>
          ) : null}

          <Field
            label={t(`companionPair.method.${method}`)}
            htmlFor="companion-secret"
            hint={t(`companionPair.hint.${method}`)}
          >
            <Input
              id="companion-secret"
              // Only the password is masked. A TOTP code and a mailed code are single-use and
              // short-lived, and masking a value being transcribed from another screen mostly
              // produces typos the operator cannot see to fix.
              type={method === 'password' ? 'password' : 'text'}
              value={secret}
              autoComplete={method === 'password' ? 'current-password' : 'one-time-code'}
              onChange={(e) => setSecret(e.target.value)}
            />
          </Field>

          {error ? <ErrorNote error={error} /> : null}

          <div className="form__actions">
            <Button
              type="submit"
              variant="primary"
              icon={<Icon.IdCard />}
              disabled={pending || secret.trim().length === 0}
            >
              {pending ? t('companionPair.pending') : t('companionPair.submit')}
            </Button>
          </div>
        </form>
      </Card>
    </main>
  );
}

export default CompanionPairPage;
