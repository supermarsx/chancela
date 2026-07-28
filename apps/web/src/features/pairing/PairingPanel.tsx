/**
 * "Connect a phone" — the desktop-side companion enrollment panel (wp27-e5).
 *
 * Wired to the wp27-e4 pairing backend. The operator mints a single-use, 5-minute pairing
 * code; the panel renders it as a hand-rolled zero-dependency QR **and** a copyable
 * deep-link and counts the TTL down. It polls the device list so the phone's exchange
 * surfaces as a success without a manual refresh, and lists every enrolled device with a
 * per-device revoke.
 *
 * The plaintext pairing code is held only in local component state (never cached), exactly
 * like the API-key secret panel it mirrors.
 *
 * # Minting is a guarded action (t70)
 *
 * `POST /v1/pairing/codes` is floored at `confirm_with_reauth` by the server's guarded-action
 * registry, because minting enrols a new device as this operator. So the mint goes through
 * {@link GuardedActionModal}, which reads the floor from `GET /v1/confirmation-policy` rather
 * than this panel deciding a strictness for itself, and threads the gathered proof into the
 * request body.
 *
 * **The automatic re-mint on expiry is deliberately gone.** It re-minted with zero clicks for
 * as long as the panel stayed open, which is exactly the thing the floor exists to stop — the
 * registry's reason for flooring this action is that "an unattended signed-in browser must not
 * be one click from it", and a silent re-mint loop is no clicks at all. Keeping it would have
 * required caching the operator's password in component state to replay the proof, which is a
 * worse thing to hold than the code this panel is already careful never to persist. An expired
 * code now asks for the confirmation again.
 */
import { useEffect, useMemo, useState } from 'react';
import type { PairingCodeMinted, PairingDeviceView, ReAuth } from '../../api/types';
import { GuardedActionModal } from '../../ui/GuardedActionModal';
import { useCreatePairingCode, usePairingDevices, useRevokePairingDevice } from '../../api/hooks';
import { resolveApiBaseUrl } from '../../api/baseUrl';
import { openExternal } from '../../desktop/openExternal';
import { useT } from '../../i18n';
import { usePairingShareT } from '../../i18n/pairingShareFallback';
import {
  Badge,
  Button,
  Card,
  DateTime,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Skeleton,
  SkeletonRegion,
  Toggle,
  SkeletonTable,
  Table,
  useToast,
} from '../../ui';
import { GateButton } from '../session/permissions';
import { QrCode } from './QrCode';
import './pairing.css';

/** How often to poll the device list while a pairing code is outstanding. */
const POLL_INTERVAL_MS = 4000;

/** The app origin the phone should load to complete pairing (absolute for a remote phone). */
function resolveAppOrigin(): string {
  const base = resolveApiBaseUrl();
  if (base) return base;
  if (typeof window !== 'undefined' && window.location?.origin) return window.location.origin;
  return '';
}

/**
 * The deep link the QR encodes: the companion origin, the `/pair` route, the pairing code, and
 * which proofs this deployment accepts.
 *
 * **It points at `/pair`, not `/`.** The original link put `?companion_pair=` on the root path,
 * which is inside the authenticated shell — a phone loading it met the sign-in screen, which is
 * the one screen this whole handshake exists to avoid. Nothing had ever consumed that link, so
 * moving it cost nothing.
 *
 * `methods` is **presentational only**. It rides in a URL the operator can edit, so it can add an
 * input but can never make the server accept a proof: `POST /v1/pairing/exchange` re-decides from
 * `auth.device_pairing.accepted` every time. It is here because the phone is unauthenticated and
 * cannot read `GET /v1/confirmation-policy` for itself, and rendering a field for a method the
 * deployment refuses would waste the operator's one attempt at the code.
 */
function buildDeepLink(minted: PairingCodeMinted): string {
  const query = new URLSearchParams({
    code: minted.code,
    methods: minted.accepted_confirmation_methods.join(','),
  });
  return `${resolveAppOrigin()}/pair?${query.toString()}`;
}

/** Format a remaining-seconds count as `m:ss` for the countdown. */
function formatCountdown(totalSeconds: number): string {
  const clamped = Math.max(0, totalSeconds);
  const minutes = Math.floor(clamped / 60);
  const seconds = clamped % 60;
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
}

interface PairingSession {
  label: string;
  /** Device ids that already existed when the session began — anything new is the enrollment. */
  baseline: Set<string>;
}

/** The live code panel: QR, deep-link, countdown, and the waiting/expired states. */
function ActiveCodePanel({
  minted,
  remaining,
  expired,
  shareEmailEnabled,
  shareWhatsappEnabled,
  onCancel,
  onRenew,
}: {
  minted: PairingCodeMinted;
  remaining: number;
  expired: boolean;
  shareEmailEnabled: boolean;
  shareWhatsappEnabled: boolean;
  onCancel: () => void;
  /** Ask for a fresh code. Re-opens the confirmation — there is no silent re-mint. */
  onRenew: () => void;
}) {
  const t = useT();
  const pt = usePairingShareT();
  const toast = useToast();
  const deepLink = useMemo(() => buildDeepLink(minted), [minted]);
  const shareMessage = pt('pairing.share.message', { link: deepLink });

  async function copy(value: string, message: string) {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(message);
    } catch (e) {
      toast.error(e);
    }
  }

  async function openShare(url: string, message: string) {
    try {
      await openExternal(url);
      toast.info(message);
    } catch {
      toast.error(pt('pairing.share.failed'));
    }
  }

  return (
    <Card title={t('pairing.code.title')}>
      <div className="pairing-code">
        <p className="field__hint">{t('pairing.code.instructions')}</p>
        <div className="pairing-code__qr">
          <QrCode value={deepLink} title={t('pairing.qr.alt')} />
        </div>

        <dl className="pairing-code__details">
          <div>
            <dt>{t('pairing.deepLink.label')}</dt>
            <dd>
              <code className="mono pairing-code__link">{deepLink}</code>
              <Button
                type="button"
                variant="secondary"
                icon={<Icon.Copy />}
                onClick={() => void copy(deepLink, t('pairing.deepLink.copied'))}
              >
                {t('pairing.deepLink.copy')}
              </Button>
            </dd>
          </div>
          <div>
            <dt>{t('pairing.code.label')}</dt>
            <dd>
              <code className="mono">{minted.code}</code>
              <Button
                type="button"
                variant="ghost"
                icon={<Icon.Copy />}
                onClick={() => void copy(minted.code, t('pairing.code.copied'))}
              >
                {t('pairing.code.copy')}
              </Button>
            </dd>
          </div>
        </dl>

        {shareEmailEnabled || shareWhatsappEnabled ? (
          <div
            className="pairing-code__share"
            role="group"
            aria-label={pt('pairing.share.actions')}
          >
            <div className="row-wrap">
              {shareEmailEnabled ? (
                <Button
                  type="button"
                  variant="secondary"
                  // The shared icon set has no mail/envelope glyph. Tray is already the
                  // established email-settings glyph in the admin navigation.
                  icon={<Icon.Tray />}
                  disabled={expired}
                  onClick={() =>
                    void openShare(
                      `mailto:?subject=${encodeURIComponent(
                        pt('pairing.share.subject'),
                      )}&body=${encodeURIComponent(shareMessage)}`,
                      pt('pairing.share.openingEmail'),
                    )
                  }
                >
                  {pt('pairing.share.email')}
                </Button>
              ) : null}
              {shareWhatsappEnabled ? (
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.ExternalLink />}
                  disabled={expired}
                  onClick={() =>
                    void openShare(
                      `https://wa.me/?text=${encodeURIComponent(shareMessage)}`,
                      pt('pairing.share.openingWhatsapp'),
                    )
                  }
                >
                  {pt('pairing.share.whatsapp')}
                </Button>
              ) : null}
            </div>
            <p className="field__hint">{pt('pairing.share.help')}</p>
          </div>
        ) : (
          <p className="field__hint">{pt('pairing.share.disabled')}</p>
        )}

        {expired ? (
          <InlineWarning tone="warn" title={t('pairing.expired.title')}>
            <div className="stack--tight">
              <p>{t('pairing.expired.body')}</p>
              <div className="form__actions">
                <Button type="button" variant="primary" icon={<Icon.IdCard />} onClick={onRenew}>
                  {t('pairing.expired.renew')}
                </Button>
              </div>
            </div>
          </InlineWarning>
        ) : (
          <div className="pairing-code__status" role="status" aria-live="polite">
            <Badge tone="accent">
              {t('pairing.expiresIn', { time: formatCountdown(remaining) })}
            </Badge>
            <span className="field__hint">{t('pairing.waiting')}</span>
          </div>
        )}

        <div className="form__actions">
          <Button type="button" variant="ghost" icon={<Icon.Close />} onClick={onCancel}>
            {t('pairing.cancel')}
          </Button>
        </div>
      </div>
    </Card>
  );
}

/** One row of the enrolled-device table, with the inline revoke confirm. */
function DeviceRow({ device }: { device: PairingDeviceView }) {
  const t = useT();
  const toast = useToast();
  const revoke = useRevokePairingDevice();
  const [confirming, setConfirming] = useState(false);

  function doRevoke() {
    revoke.mutate(device.device_id, {
      onSuccess: () => {
        toast.success(t('pairing.revokedToast'));
        setConfirming(false);
      },
      onError: (e) => {
        toast.error(e);
        setConfirming(false);
      },
    });
  }

  return (
    <tr>
      <td>{device.label}</td>
      {/* Enrolling a device is a credential event; the exact instant is what an operator
          checks against when a device is later disputed or revoked. */}
      <td>
        <DateTime value={device.created_at} evidentiary />
      </td>
      <td>
        {device.revoked ? (
          <Badge tone="warn">{t('pairing.status.revoked')}</Badge>
        ) : (
          <Badge tone="ok">{t('pairing.status.active')}</Badge>
        )}
      </td>
      <td className="users-actions">
        {device.revoked ? (
          <span className="muted">—</span>
        ) : confirming ? (
          <span className="row-wrap">
            <Button
              type="button"
              variant="ghost"
              disabled={revoke.isPending}
              onClick={() => setConfirming(false)}
            >
              {t('common.cancel')}
            </Button>
            <GateButton
              perm="user.manage"
              variant="primary"
              icon={<Icon.Trash />}
              disabled={revoke.isPending}
              onClick={doRevoke}
            >
              {revoke.isPending ? t('pairing.revoking') : t('pairing.revoke.confirm')}
            </GateButton>
          </span>
        ) : (
          <GateButton
            perm="user.manage"
            type="button"
            variant="ghost"
            icon={<Icon.Trash />}
            onClick={() => setConfirming(true)}
          >
            {t('pairing.revoke')}
          </GateButton>
        )}
      </td>
    </tr>
  );
}

export function PairingPanel({
  shareEmailEnabled = true,
  shareWhatsappEnabled = true,
}: {
  /** Instance-wide admin policy. Defaults preserve sharing against older settings payloads. */
  shareEmailEnabled?: boolean;
  /** Instance-wide admin policy. Defaults preserve sharing against older settings payloads. */
  shareWhatsappEnabled?: boolean;
} = {}) {
  const t = useT();
  const toast = useToast();

  const [session, setSession] = useState<PairingSession | null>(null);
  const [minted, setMinted] = useState<PairingCodeMinted | null>(null);
  const [mintedAt, setMintedAt] = useState<number>(0);
  const [now, setNow] = useState<number>(() => Date.now());
  const [enrolled, setEnrolled] = useState<PairingDeviceView | null>(null);
  const [label, setLabel] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [emailCode, setEmailCode] = useState(false);

  const mint = useCreatePairingCode();
  const devices = usePairingDevices({
    refetchInterval: session && !enrolled ? POLL_INTERVAL_MS : false,
  });

  const remaining = minted ? minted.expires_in_secs - Math.floor((now - mintedAt) / 1000) : 0;
  const expired = !!minted && remaining <= 0;

  // Tick the countdown once a second while a code is outstanding.
  useEffect(() => {
    if (!minted) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [minted]);

  // Detect the phone's enrollment: any device absent from the session baseline is the new one.
  useEffect(() => {
    if (!session || enrolled) return;
    const fresh = (devices.data?.devices ?? []).find(
      (d) => !d.revoked && !session.baseline.has(d.device_id),
    );
    if (fresh) {
      setEnrolled(fresh);
      setMinted(null);
      toast.success(t('pairing.enrolled.toast', { label: fresh.label }));
    }
  }, [devices.data, session, enrolled, toast, t]);

  // No automatic re-mint on expiry — see the module header. Minting is floored at
  // `confirm_with_reauth`, so a new code costs a fresh confirmation, every time.

  /**
   * Mint one code with the proof the dialog gathered.
   *
   * Returns a promise so {@link GuardedActionModal} can keep the dialog open and render the
   * server's `403` inline when the proof is wrong, instead of closing over a failure.
   */
  function runMint(reauth: ReAuth): Promise<void> {
    const trimmed = label.trim();
    const baseline = new Set((devices.data?.devices ?? []).map((d) => d.device_id));
    setEnrolled(null);
    setSession({ label: trimmed, baseline });
    return new Promise<void>((resolve, reject) => {
      mint.mutate(
        {
          label: trimmed || undefined,
          confirmation: { reauth },
          email_confirmation_code: emailCode,
        },
        {
          onSuccess: (res) => {
            setMinted(res);
            setMintedAt(Date.now());
            setNow(Date.now());
            resolve();
          },
          onError: (e) => {
            // The session baseline is dropped so a refused mint leaves the panel exactly where
            // it started, with nothing outstanding — matching the server, which minted no code.
            setSession(null);
            reject(e);
          },
        },
      );
    });
  }

  function endSession() {
    setSession(null);
    setMinted(null);
    setEnrolled(null);
  }

  const list = devices.data?.devices ?? [];

  return (
    <div className="stack">
      {enrolled ? (
        <InlineWarning tone="info" title={t('pairing.enrolled.title')}>
          <div className="stack--tight">
            <p>{t('pairing.enrolled.body', { label: enrolled.label })}</p>
            <div className="form__actions">
              <Button type="button" variant="primary" icon={<Icon.Check />} onClick={endSession}>
                {t('pairing.enrolled.done')}
              </Button>
            </div>
          </div>
        </InlineWarning>
      ) : null}

      {session && minted ? (
        <ActiveCodePanel
          minted={minted}
          remaining={remaining}
          expired={expired}
          shareEmailEnabled={shareEmailEnabled}
          shareWhatsappEnabled={shareWhatsappEnabled}
          onCancel={endSession}
          onRenew={() => setConfirmOpen(true)}
        />
      ) : session && mint.isPending ? (
        <Card title={t('pairing.code.title')}>
          {/* The minted panel is a fixed shape — an instruction line, a QR square, then the
              code and its countdown — so the mint wait reserves it rather than showing a
              bar. The label rides as visually-hidden text, not a caption. */}
          <SkeletonRegion className="pairing-code" label={t('pairing.minting')}>
            <Skeleton height="0.85rem" width="70%" />
            <Skeleton height="12rem" width="12rem" />
            <Skeleton height="1.8rem" width="9rem" />
            <Skeleton height="0.8rem" width="11rem" />
          </SkeletonRegion>
        </Card>
      ) : !enrolled ? (
        <Card title={t('pairing.connect.title')}>
          <div className="form settings-rows">
            <p className="field__hint">{t('pairing.lede')}</p>
            <Field
              label={t('pairing.label.label')}
              htmlFor="pairing-label"
              hint={t('pairing.label.hint')}
            >
              <Input
                id="pairing-label"
                value={label}
                placeholder={t('pairing.label.placeholder')}
                onChange={(e) => setLabel(e.target.value)}
                autoComplete="off"
              />
            </Field>
            {/* Offered unconditionally, and deliberately not gated on the accepted-method set.
                That set only arrives on a MINT RESPONSE, and this control has to be chosen before
                the mint — so hiding it until we know would hide it forever on the first pairing of
                a session. The server answers the question properly instead: asking for a mailed
                code on an instance that does not accept the method, or on an account with no
                address, is a specific 422 raised BEFORE any code is minted, so nothing is spent
                learning the answer. A guess here would either hide a working option or promise a
                broken one. */}
            <Toggle
              checked={emailCode}
              onChange={setEmailCode}
              label={t('pairing.emailCode.label')}
            />
            <p className="field__hint">{t('pairing.emailCode.hint')}</p>
            <div className="form__actions">
              <GateButton
                perm="user.manage"
                type="button"
                variant="primary"
                icon={<Icon.IdCard />}
                disabled={mint.isPending}
                onClick={() => setConfirmOpen(true)}
              >
                {t('pairing.connect')}
              </GateButton>
            </div>
          </div>
        </Card>
      ) : null}

      {mint.error && !session ? <ErrorNote error={mint.error} /> : null}

      {/* The strictness and framing come from the server policy for `device.pairing`, not from
          this panel. `onConfirm` threads the gathered proof into the request body; the dialog
          gathers it and never transmits it itself. */}
      <GuardedActionModal
        action="device.pairing"
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title={t('pairing.confirm.title')}
        intro={t('pairing.confirm.intro')}
        confirmLabel={t('pairing.confirm.action')}
        pendingLabel={t('pairing.minting')}
        pending={mint.isPending}
        onConfirm={({ reauth }) => runMint(reauth)}
      />

      <Card title={t('pairing.devices.title')}>
        {/* Four columns: device, enrolled, status, action. (The mint wait above keeps the
            indeterminate bar — that one is an action in flight, with no shape to reserve.) */}
        {devices.isLoading ? (
          <SkeletonRegion>
            <SkeletonTable cols={4} />
          </SkeletonRegion>
        ) : devices.error ? (
          <ErrorNote error={devices.error} />
        ) : list.length === 0 ? (
          <EmptyState title={t('pairing.devices.empty')}>
            <p>{t('pairing.devices.emptyBody')}</p>
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>{t('pairing.table.device')}</th>
                <th>{t('pairing.table.enrolled')}</th>
                <th>{t('pairing.table.status')}</th>
                <th>{t('pairing.table.action')}</th>
              </tr>
            }
          >
            {list.map((device) => (
              <DeviceRow key={device.device_id} device={device} />
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
