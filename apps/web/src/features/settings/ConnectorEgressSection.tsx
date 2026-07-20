/**
 * Connector outbound-egress allowlist (t21).
 *
 * This is the one Settings section that edits a containment boundary rather than a preference: it
 * decides which hosts a connector may ship minute-book bytes to. Two things therefore have to be
 * true of this UI, not just of the server:
 *
 * 1. The **precedence rule is stated here**, where the change is made. When the deployment sets
 *    `CHANCELA_CONNECTOR_ALLOWED_HOSTS` that list is a ceiling and this one can only narrow it;
 *    when it does not, this list is the only egress boundary that exists, and the operator is told
 *    so in as many words.
 * 2. The **validation is mirrored client-side** so a rejected entry is explained next to the field
 *    instead of arriving as a bare 422. The server re-validates identically and remains the
 *    authority — this mirror is for legibility, never for enforcement.
 */
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import type { ConnectorSettings } from '../../api/types';
import { Card, Field, InlineWarning, TextArea } from '../../ui';

/** Matches `MAX_RUNTIME_ALLOWLIST_ENTRIES` in `chancela-connectors`. */
const MAX_ENTRIES = 64;
/** Matches `MIN_ADMIN_V4_PREFIX` / `MIN_ADMIN_V6_PREFIX`. */
const MIN_V4_PREFIX = 16;
const MIN_V6_PREFIX = 32;

export type EntryProblem =
  /** Not a bare hostname or IP/CIDR: a scheme, port, path, credentials, or plain nonsense. */
  | 'format'
  | 'wildcard'
  /** The link-local range that carries the cloud instance-metadata endpoint. */
  | 'metadata'
  | 'loopback'
  /** Multicast or the unspecified address — never a legitimate connector target. */
  | 'forbiddenRange'
  | 'broadPrefix';

const problemKeys: Record<EntryProblem, MessageKey> = {
  format: 'settings.connectorEgress.reason.format',
  wildcard: 'settings.connectorEgress.reason.wildcard',
  metadata: 'settings.connectorEgress.reason.metadata',
  loopback: 'settings.connectorEgress.reason.loopback',
  forbiddenRange: 'settings.connectorEgress.reason.forbiddenRange',
  broadPrefix: 'settings.connectorEgress.reason.broadPrefix',
};

function parseIpv4(value: string): number[] | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => (/^\d{1,3}$/.test(part) ? Number(part) : NaN));
  return octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)
    ? octets
    : null;
}

/**
 * Why an entry is unacceptable, or `null` when it is fine.
 *
 * Deliberately conservative: anything this cannot confidently classify is reported as a format
 * problem rather than waved through, since the server decides and a false "looks fine" here would
 * be the misleading answer.
 */
export function entryProblem(raw: string): EntryProblem | null {
  const entry = raw.trim().toLowerCase();
  if (!entry) return 'format';
  if (entry.includes('*')) return 'wildcard';
  if (
    entry.includes('://') ||
    entry.includes('@') ||
    entry.includes('?') ||
    entry.includes('#') ||
    entry.includes(' ') ||
    entry.includes(',') ||
    entry.includes('[')
  )
    return 'format';

  const slash = entry.indexOf('/');
  const address = slash === -1 ? entry : entry.slice(0, slash);
  const prefixText = slash === -1 ? null : entry.slice(slash + 1);
  const octets = parseIpv4(address);
  const looksIpv6 = !octets && address.includes(':') && /^[0-9a-f:]+$/.test(address);

  if (prefixText !== null) {
    if (!octets && !looksIpv6) return 'format';
    if (!/^\d{1,3}$/.test(prefixText)) return 'format';
    const prefix = Number(prefixText);
    if (prefix > (octets ? 32 : 128)) return 'format';
    if (prefix < (octets ? MIN_V4_PREFIX : MIN_V6_PREFIX)) return 'broadPrefix';
  }

  if (octets) {
    if (octets[0] === 127) return 'loopback';
    if (octets[0] === 169 && octets[1] === 254) return 'metadata';
    if (octets[0] === 0 || octets[0] >= 224) return 'forbiddenRange';
    return null;
  }
  if (looksIpv6) {
    if (address === '::1') return 'loopback';
    if (/^fe[89ab]/.test(address)) return 'metadata';
    if (address === '::' || address.startsWith('ff')) return 'forbiddenRange';
    return null;
  }

  // Hostname territory: a stray ':' here is a port, a stray '/' a path.
  if (address.includes(':') || slash !== -1) return 'format';
  if (address === 'localhost' || address.endsWith('.localhost')) return 'loopback';
  if (address.length > 253 || !/^[a-z0-9.-]+$/.test(address)) return 'format';
  return null;
}

/** One entry per line, trimmed, lowercased, blank-free and duplicate-free. */
export function parseAllowedHosts(text: string): string[] {
  const seen = new Set<string>();
  const entries: string[] = [];
  for (const line of text.split('\n')) {
    const entry = line.trim().toLowerCase();
    if (!entry || seen.has(entry)) continue;
    seen.add(entry);
    entries.push(entry);
  }
  return entries;
}

export function ConnectorEgressSection({
  value,
  onChange,
}: {
  value: ConnectorSettings;
  onChange: (next: ConnectorSettings) => void;
}) {
  const t = useT();
  const entries = value.allowed_hosts;
  const ceiling = value.environment_ceiling ?? null;
  const hasCeiling = Array.isArray(ceiling) && ceiling.length > 0;
  const tooMany = entries.length > MAX_ENTRIES;
  const rejected = entries
    .map((entry) => ({ entry, problem: entryProblem(entry) }))
    .filter((item): item is { entry: string; problem: EntryProblem } => item.problem !== null);

  const error = tooMany
    ? t('settings.connectorEgress.tooMany', { max: MAX_ENTRIES })
    : rejected.length > 0
      ? rejected
          .map((item) =>
            t('settings.connectorEgress.rejected', {
              entry: item.entry,
              reason: t(problemKeys[item.problem]),
            }),
          )
          .join(' ')
      : undefined;

  return (
    <Card title={t('settings.connectorEgress.title')}>
      <p className="muted">{t('settings.connectorEgress.intro')}</p>

      <InlineWarning
        tone={hasCeiling ? 'info' : 'warn'}
        title={t('settings.connectorEgress.precedenceTitle')}
      >
        {hasCeiling
          ? t('settings.connectorEgress.precedenceCeiling', { hosts: ceiling.join(', ') })
          : t('settings.connectorEgress.precedenceNoCeiling')}
      </InlineWarning>

      <Field
        label={t('settings.connectorEgress.hostsLabel')}
        htmlFor="connector-allowed-hosts"
        hint={t('settings.connectorEgress.hostsHint')}
        error={error}
      >
        <TextArea
          id="connector-allowed-hosts"
          rows={6}
          spellCheck={false}
          value={entries.join('\n')}
          placeholder={t('settings.connectorEgress.placeholder')}
          onChange={(event) =>
            onChange({ ...value, allowed_hosts: parseAllowedHosts(event.target.value) })
          }
        />
      </Field>

      <p className="muted">{t('settings.connectorEgress.effect')}</p>
      <p className="muted">{t('settings.connectorEgress.audited')}</p>
    </Card>
  );
}
