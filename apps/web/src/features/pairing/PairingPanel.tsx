/**
 * "Connect a phone" — the desktop-side companion enrollment panel (wp27-e5).
 *
 * Wired to the wp27-e4 pairing backend. The operator mints a single-use, 5-minute pairing
 * code; the panel renders it as a hand-rolled zero-dependency QR **and** a copyable
 * deep-link, counts the TTL down, and re-mints automatically when a code expires while the
 * panel is open. It polls the device list so the phone's exchange surfaces as a success
 * without a manual refresh, and lists every enrolled device with a per-device revoke.
 *
 * The plaintext pairing code is held only in local component state (never cached), exactly
 * like the API-key secret panel it mirrors.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import type { PairingCodeMinted, PairingDeviceView } from '../../api/types';
import { useCreatePairingCode, usePairingDevices, useRevokePairingDevice } from '../../api/hooks';
import { resolveApiBaseUrl } from '../../api/baseUrl';
import { useT } from '../../i18n';
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
  Loading,
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
 * The deep-link the QR encodes: the companion app origin plus the pairing code as a query
 * parameter. Loading it on the phone gives the companion both the server base (the URL
 * origin) and the code to POST to `/v1/pairing/exchange`.
 */
function buildDeepLink(code: string): string {
  return `${resolveAppOrigin()}/?companion_pair=${encodeURIComponent(code)}`;
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
  onCancel,
}: {
  minted: PairingCodeMinted;
  remaining: number;
  expired: boolean;
  onCancel: () => void;
}) {
  const t = useT();
  const toast = useToast();
  const deepLink = useMemo(() => buildDeepLink(minted.code), [minted.code]);

  async function copy(value: string, message: string) {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(message);
    } catch (e) {
      toast.error(e);
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

        {expired ? (
          <InlineWarning tone="warn" title={t('pairing.expired.title')}>
            {t('pairing.expired.body')}
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

export function PairingPanel() {
  const t = useT();
  const toast = useToast();

  const [session, setSession] = useState<PairingSession | null>(null);
  const [minted, setMinted] = useState<PairingCodeMinted | null>(null);
  const [mintedAt, setMintedAt] = useState<number>(0);
  const [now, setNow] = useState<number>(() => Date.now());
  const [enrolled, setEnrolled] = useState<PairingDeviceView | null>(null);
  const [label, setLabel] = useState('');

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

  // Re-mint automatically when the outstanding code expires while the panel is open.
  const remintGuard = useRef(false);
  useEffect(() => {
    if (!session || enrolled || !expired || mint.isPending || remintGuard.current) return;
    remintGuard.current = true;
    mint.mutate(
      { label: session.label || undefined },
      {
        onSuccess: (res) => {
          setMinted(res);
          setMintedAt(Date.now());
          setNow(Date.now());
          remintGuard.current = false;
        },
        onError: (e) => {
          toast.error(e);
          remintGuard.current = false;
        },
      },
    );
  }, [expired, session, enrolled, mint, toast]);

  function startConnect() {
    const trimmed = label.trim();
    const baseline = new Set((devices.data?.devices ?? []).map((d) => d.device_id));
    setEnrolled(null);
    setSession({ label: trimmed, baseline });
    mint.mutate(
      { label: trimmed || undefined },
      {
        onSuccess: (res) => {
          setMinted(res);
          setMintedAt(Date.now());
          setNow(Date.now());
        },
        onError: (e) => {
          toast.error(e);
          setSession(null);
        },
      },
    );
  }

  function endSession() {
    setSession(null);
    setMinted(null);
    setEnrolled(null);
    remintGuard.current = false;
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
          onCancel={endSession}
        />
      ) : session && mint.isPending ? (
        <Card title={t('pairing.code.title')}>
          <Loading label={t('pairing.minting')} />
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
            <div className="form__actions">
              <GateButton
                perm="user.manage"
                type="button"
                variant="primary"
                icon={<Icon.IdCard />}
                disabled={mint.isPending}
                onClick={startConnect}
              >
                {t('pairing.connect')}
              </GateButton>
            </div>
          </div>
        </Card>
      ) : null}

      {mint.error && !session ? <ErrorNote error={mint.error} /> : null}

      <Card title={t('pairing.devices.title')}>
        {devices.isLoading ? (
          <Loading />
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
