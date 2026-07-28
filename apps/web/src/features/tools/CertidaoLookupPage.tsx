/**
 * Ferramentas → "Certidão de Registo Permanente" — a **lookup-only** consultation tool (t95).
 *
 * Enter a código de acesso, see what the registry returns, keep nothing. This is deliberately a
 * separate tool from the import flow (`RegistryImportPanel` / `EntityRegistryImportPage`), which
 * enriches or creates an entity: the two share the fetch, and nothing else.
 *
 * # This tool mutates nothing, and that is load-bearing
 *
 * It calls `POST /v1/registry/lookup`, whose handler consults and parses and then stops — no
 * entity is created, updated or matched, no aggregate row is written, and no domain-ledger event is
 * appended. There is no cache to warm either: the stored-extract map is written only by the import
 * handlers. Running this twice changes nothing, which is why the page can offer a plain "consultar"
 * with no confirmation gate.
 *
 * **There is deliberately no "import this" affordance here.** The point of the tool is that it does
 * not import; adding a one-click bridge would quietly restore the coupling the separation exists to
 * remove. The import flow keeps its own surface.
 *
 * # Failures stay distinct
 *
 * The API returns a stable `code` per failure (`registry.unreachable`, `registry.code_rejected`, …)
 * and {@link certidaoLookupErrorKey} maps it to one sentence each. The distinction that matters
 * most is between *we got no answer* and *the registry answered "no such certidão"*: collapsing
 * them would tell an operator a company has no registry record on the strength of a network
 * timeout. An unrecognised code falls through to the server's English detail rather than a guess.
 *
 * # The access code is a credential
 *
 * It is held in component state only, sent transiently, and cleared from the input the moment the
 * lookup resolves — so it is not left on screen after use and cannot be read back off the page. It
 * is never logged, never stored, and never echoed: the result carries only the masked
 * `****-****-NNNN` form the server derived.
 */
import { useEffect, useRef, useState } from 'react';
import { ApiError, api } from '../../api/client';
import type { CaeRefView, RegistryExtractView } from '../../api/types';
import {
  certidaoLookupErrorKey,
  useCertidaoLookupT,
  type CertidaoLookupCopyKey,
} from '../../i18n/certidaoLookupFallback';
import { useT } from '../../i18n';
import { Button, Card, InlineWarning, Table } from '../../ui';
import { AccessCodeField } from '../registry/AccessCodeField';

/**
 * One row of the result table.
 *
 * `value === null` means the certidão did not carry the field. It is rendered as an explicit
 * "não consta da certidão", never as a blank or a dash — an empty cell under *Sede* reads as a
 * claim that the company has no seat, which the certidão never made.
 */
interface ResultRow {
  key: string;
  label: string;
  value: string | null;
  mono?: boolean;
}

/** Join a certidão's CAE refs into one cell, keeping an uncatalogued code visible rather than dropped. */
function formatCae(cae: CaeRefView[]): string | null {
  if (cae.length === 0) return null;
  return cae
    .map((ref) => (ref.designation ? `${ref.code} — ${ref.designation}` : ref.code))
    .join('; ');
}

function ValueCell({ value, mono }: { value: string | null; mono?: boolean }) {
  const ct = useCertidaoLookupT();
  if (value === null) {
    return <span className="muted">{ct('certidaoLookup.absent')}</span>;
  }
  return <span className={mono ? 'mono registry-breakable' : 'registry-breakable'}>{value}</span>;
}

function ResultTable({
  caption,
  rows,
  ct,
}: {
  caption: string;
  rows: ResultRow[];
  ct: (key: CertidaoLookupCopyKey) => string;
}) {
  return (
    <Table
      caption={caption}
      head={
        <tr>
          <th scope="col">{ct('certidaoLookup.table.field')}</th>
          <th scope="col">{ct('certidaoLookup.table.value')}</th>
        </tr>
      }
    >
      {rows.map((row) => (
        <tr key={row.key}>
          <th scope="row">{row.label}</th>
          <td>
            <ValueCell value={row.value} mono={row.mono} />
          </td>
        </tr>
      ))}
    </Table>
  );
}

/**
 * Render a failed lookup with the one sentence that fits it.
 *
 * The server's English `error` detail is kept in a secondary line rather than discarded, so an
 * operator can quote it in a bug report — the same split `ApiError.code` was designed for.
 */
function LookupErrorNote({ error }: { error: unknown }) {
  const ct = useCertidaoLookupT();
  const code = error instanceof ApiError ? error.code : undefined;
  const key = certidaoLookupErrorKey(code);
  const detail = error instanceof Error ? error.message : String(error);

  return (
    <InlineWarning tone="error" title={ct('certidaoLookup.error.title')}>
      {/* An unrecognised code shows the server's own words — never a Portuguese sentence
          invented for a failure this build does not know about. */}
      <p>{key ? ct(key) : detail}</p>
      {key ? (
        <p className="muted">
          {ct('certidaoLookup.error.detail')}: {detail}
        </p>
      ) : null}
    </InlineWarning>
  );
}

export function CertidaoLookupPage() {
  const t = useT();
  const ct = useCertidaoLookupT();
  const [code, setCode] = useState('');
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<RegistryExtractView | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [emptyCode, setEmptyCode] = useState(false);
  // Guards a resolve that lands after the operator has navigated away.
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (pending) return;
    const trimmed = code.trim();
    if (trimmed === '') {
      setEmptyCode(true);
      return;
    }
    setEmptyCode(false);
    setPending(true);
    setError(null);
    setResult(null);
    try {
      const extract = await api.registryLookup({ code: trimmed });
      if (!alive.current) return;
      setResult(extract);
    } catch (e) {
      if (!alive.current) return;
      setError(e);
    } finally {
      if (alive.current) {
        setPending(false);
        // The código de acesso is a credential: drop it from the input as soon as it has been
        // used, so it is not left readable on screen.
        setCode('');
      }
    }
  }

  const identityRows: ResultRow[] = result
    ? [
        { key: 'firma', label: t('registry.field.firma'), value: result.firma },
        { key: 'nipc', label: t('registry.field.nipc'), value: result.nipc, mono: true },
        {
          key: 'forma',
          label: t('registry.field.legalForm'),
          value: result.forma_juridica ?? result.legal_form,
        },
        { key: 'matricula', label: t('registry.field.matricula'), value: result.matricula },
        { key: 'sede', label: t('registry.field.sede'), value: result.sede },
        { key: 'capital', label: t('registry.field.capital'), value: result.capital },
        { key: 'objeto', label: t('registry.field.objeto'), value: result.objeto },
        { key: 'cae', label: t('registry.field.cae'), value: formatCae(result.cae) },
        {
          key: 'constituicao',
          label: t('registry.field.dataConstituicao'),
          value: result.data_constituicao,
        },
      ]
    : [];

  const provenanceRows: ResultRow[] = result
    ? [
        {
          key: 'codigo',
          label: t('registry.provenance.accessCode'),
          value: result.provenance.access_code_masked,
          mono: true,
        },
        {
          key: 'retrieved',
          label: t('registry.provenance.retrievedAt'),
          value: result.provenance.retrieved_at,
          mono: true,
        },
        {
          key: 'conservatoria',
          label: t('registry.provenance.conservatoria'),
          value: result.provenance.conservatoria,
        },
        {
          key: 'oficial',
          label: t('registry.provenance.oficial'),
          value: result.provenance.oficial,
        },
        {
          key: 'subscribed',
          label: t('registry.provenance.subscribedOn'),
          value: result.provenance.subscribed_on,
        },
        {
          key: 'validUntil',
          label: t('registry.provenance.validUntil'),
          value: result.provenance.valid_until,
        },
      ]
    : [];

  return (
    <div className="stack">
      <Card title={ct('certidaoLookup.title')}>
        <div className="stack">
          <p>{ct('certidaoLookup.intro')}</p>

          {/* Stated BEFORE the lookup, so "nothing is saved" is a property the operator knows
              going in rather than a caption they may not read afterwards. */}
          <InlineWarning tone="info" title={ct('certidaoLookup.notice.title')}>
            <p>{ct('certidaoLookup.notice.body')}</p>
          </InlineWarning>

          <form onSubmit={submit} className="stack">
            <AccessCodeField
              id="certidao-lookup-code"
              value={code}
              onChange={(next) => {
                setCode(next);
                if (next.trim() !== '') setEmptyCode(false);
              }}
              hint={ct('certidaoLookup.quotaWarning')}
              error={emptyCode ? ct('certidaoLookup.codeRequired') : undefined}
            />
            <div className="row">
              <Button type="submit" variant="primary" disabled={pending}>
                {pending ? ct('certidaoLookup.submitting') : ct('certidaoLookup.submit')}
              </Button>
              {result || error ? (
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => {
                    setResult(null);
                    setError(null);
                  }}
                >
                  {ct('certidaoLookup.clear')}
                </Button>
              ) : null}
            </div>
          </form>

          {error ? <LookupErrorNote error={error} /> : null}
        </div>
      </Card>

      {result ? (
        <Card title={ct('certidaoLookup.result.nothingSaved')}>
          <div className="stack">
            <ResultTable caption={ct('certidaoLookup.table.caption')} rows={identityRows} ct={ct} />
            <h4>{ct('certidaoLookup.provenance.title')}</h4>
            <ResultTable
              caption={ct('certidaoLookup.provenance.caption')}
              rows={provenanceRows}
              ct={ct}
            />
          </div>
        </Card>
      ) : null}
    </div>
  );
}
