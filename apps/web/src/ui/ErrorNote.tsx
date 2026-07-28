/**
 * `ErrorNote` — the app-wide inline error surface.
 *
 * Every feature page renders a failed request through this component, so it is the single place
 * where the server's English operator detail is turned into something a person can read. It does
 * NOT translate that detail and it does not drop it: `apiErrorFallback.ts` resolves the stable
 * `code` to a reviewed pt-PT sentence that becomes the HEADLINE, and everything the server said —
 * the English detail, the code, the HTTP status, the request id and the path — is demoted into a
 * technical-details block underneath (memory: `reject-never-silently-transform`).
 *
 * Two paths, deliberately:
 *
 *  - **A 403 with no specific code** keeps the verbatim `perm.denied` copy it has always had. The
 *    server says nothing beyond "forbidden" (`ApiError::Forbidden` puts the Tier-1 default
 *    `http.forbidden` on the wire), so there is no detail worth a block and nothing to resolve.
 *  - **Everything else** goes through {@link resolveApiError}. A 403 that DOES carry a code is not
 *    special: `cross_user_proof_required` has its own reviewed sentence and must render it.
 *
 * The copy lives in `apiErrorFallback.ts`, not the shared `Catalog` — see that module's header for
 * why, and for the rule that a noun never enters a sentence through a placeholder.
 */
import { useState } from 'react';
import { useT } from '../i18n';
import { resolveApiError, useApiErrorT } from '../i18n/apiErrorFallback';
import { ApiError } from '../api/client';
import { Button, InlineWarning } from './index';

/** One label/value row of the technical-details block. Absent facts are not rendered at all. */
interface ErrorFact {
  label: string;
  value: string;
  /** Stable English field name for the clipboard payload, which is read by whoever debugs it. */
  field: string;
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function ErrorNote({ error }: { error: unknown }) {
  const t = useT();
  const et = useApiErrorT();
  const [copied, setCopied] = useState(false);

  const apiError = error instanceof ApiError ? error : undefined;
  const resolution = resolveApiError(apiError);

  // A bare permission denial: the resolver landed on the 403 tier with no code of its own to
  // refine it. Preserved verbatim rather than routed through the code table — `perm.denied` is
  // the sentence the whole app already uses for "sem permissão", and a details block here would
  // only restate the status.
  if (apiError?.status === 403 && resolution.key === 'apiError.tier.403' && !resolution.unmapped) {
    return (
      <InlineWarning tone="error" title={t('perm.denied.title')}>
        {t('perm.denied.body')}
      </InlineWarning>
    );
  }

  const detail = error instanceof Error ? error.message : String(error);
  const facts: ErrorFact[] = [];
  if (apiError?.code) {
    facts.push({ label: et('apiError.details.code'), value: apiError.code, field: 'code' });
  }
  if (apiError) {
    facts.push({
      label: et('apiError.details.status'),
      value: String(apiError.status),
      field: 'status',
    });
  }
  if (apiError?.requestId) {
    facts.push({
      label: et('apiError.details.requestId'),
      value: apiError.requestId,
      field: 'request_id',
    });
  }
  if (apiError?.path) {
    facts.push({ label: et('apiError.details.path'), value: apiError.path, field: 'path' });
  }
  if (detail) {
    facts.push({ label: et('apiError.details.detail'), value: detail, field: 'detail' });
  }

  // Force the block open when the operator would otherwise be left with a sentence that cannot
  // name the fault: an unmapped code, a scrubbed `internal`/`upstream`, or a thrown `Error` that
  // never reached the server and so carries no status or code to resolve at all.
  const forceOpen = resolution.forceDetails || apiError === undefined;

  return (
    <InlineWarning tone="error">
      <div className={`error-note${resolution.nonRoutine ? ' error-note--non-routine' : ''}`}>
        <p className="error-note__headline">{et(resolution.key)}</p>
        {facts.length > 0 ? (
          <>
            <details className="error-note__details" open={forceOpen}>
              <summary className="error-note__summary">{et('apiError.details.summary')}</summary>
              <dl className="error-note__facts">
                {facts.map((fact) => (
                  <div className="error-note__fact" key={fact.field}>
                    <dt>{fact.label}</dt>
                    <dd>{fact.value}</dd>
                  </div>
                ))}
              </dl>
              <p className="error-note__hint">{et('apiError.details.hint')}</p>
            </details>
            {/* Outside the `<details>` so the payload can be copied into a bug report without
                first expanding it — and so the button stays reachable when the block is closed. */}
            <p className="error-note__actions">
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  // English field names, matching the block's own hint: this payload is pasted
                  // into a bug report and must stay greppable whatever locale produced it.
                  const payload = facts.map((f) => `${f.field}: ${f.value}`).join('\n');
                  void copyText(payload).then(setCopied);
                }}
              >
                {copied ? et('apiError.details.copied') : et('apiError.details.copy')}
              </Button>
            </p>
          </>
        ) : null}
      </div>
    </InlineWarning>
  );
}
