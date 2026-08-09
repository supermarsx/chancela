/**
 * The trust-anchor assistant (t118) — proposals for `signing.tsl_trust_anchor_*`.
 *
 * Sits inside the existing "Trusted List trust anchors" card, immediately above the fields it
 * proposes values for, because the operator's question ("what do I paste here?") is asked at those
 * fields and nowhere else.
 *
 * ## The invariant this component exists to hold
 *
 * A proposal derived from the **authenticated EU LOTL** and a certificate scraped out of a list's
 * **own signature** are not the same kind of thing, and the second one proves nothing. So they are
 * never rendered alike:
 *
 * - the provenance badge is the first thing in the row, not a tooltip;
 * - a `list_self_asserted` candidate is preceded by a fail-closed `InlineWarning` — no `notice`
 *   key, so it can never acquire a dismiss control;
 * - it offers only its **fingerprint**, because the server withholds the PEM for exactly this
 *   reason: the operator's job is to compare that fingerprint against a published one first.
 *
 * ## The bootstrap case
 *
 * With no anchor at all the run refuses, and until now that was the end of the screen: the operator
 * was told to fetch a value from the Official Journal and given nothing to act on. A second,
 * separately-labelled control now asks for the certificate the EU LOTL document itself carries.
 * Three properties hold it in place:
 *
 * - it is rendered **only** under `lotl_anchor_not_configured`, and only after the first run has
 *   already reported that state — so it cannot be reached without having read the refusal;
 * - it is a separate request. The ordinary "Suggest anchors" button never asks for it, so no
 *   operator encounters this candidate without having asked for it by name; and
 * - what comes back is an ordinary `list_self_asserted` proposal, rendered by the very same
 *   `Proposal` component, with the same undismissable warning and the same withheld PEM. There is
 *   no bootstrap-specific rendering path that could quietly present it more softly.
 *
 * ## What this component cannot do
 *
 * Nothing here writes. Each button appends a value to the settings draft the operator is already
 * editing, and the existing save flow (PUT /v1/settings, `signing.configure`) is the only thing
 * that persists it. There is no pre-selection, and deliberately **no "add all"**: a bulk control
 * would be the one gesture capable of sweeping a self-asserted candidate in beside LOTL-derived
 * ones without the operator ever reading its warning.
 *
 * Adding a self-asserted candidate reports that fact to the caller, which records it in
 * `signing.tsl_trust_anchor_self_asserted_sha256`. Without that, the provenance this whole
 * component is built around would survive exactly until the operator pressed Save.
 */
import { useState } from 'react';
import type {
  TrustAnchorProposalView,
  TrustAnchorSourceSuggestionView,
  TrustAnchorSuggestionsView,
} from '../../api/types';
import { useTrustAnchorSuggestions } from '../../api/hooks';
import { useT, type TFunction } from '../../i18n';
import {
  LOTL_ANCHOR_NOT_CONFIGURED,
  trustAnchorSuggestionKey,
} from '../../i18n/trustAnchorSuggestions';
import { Badge, Button, ErrorNote, Icon, InlineWarning } from '../../ui';

interface Props {
  /** Append a PEM to `signing.tsl_trust_anchor_certs` in the draft. */
  onAddCertificate: (pem: string) => void;
  /**
   * Append a lowercase-hex SHA-256 to `signing.tsl_trust_anchor_sha256` in the draft.
   *
   * `selfAsserted` is not decoration: it is the proposal's provenance travelling with the value so
   * the caller can record it in `signing.tsl_trust_anchor_self_asserted_sha256`. A caller that
   * ignored it would store an unverified anchor as though it had come from the Official Journal.
   */
  onAddFingerprint: (sha256: string, selfAsserted: boolean) => void;
}

/**
 * Render an outcome code, or the raw identifier marked as untranslated.
 *
 * The server sends no English sentence for these, so there is nothing to fall back to and nothing
 * to paraphrase. Showing the identifier is the visible failure that gets the next backend-added
 * code a translation — a silent blank would hide it.
 */
function Outcome({ code, t }: { code: string; t: TFunction }) {
  const key = trustAnchorSuggestionKey(code);
  if (!key) return <span lang="en">{code}</span>;
  return <>{t(key)}</>;
}

/** The server's own error string, framed as such. Never translated — see the i18n module note. */
function Detail({ detail, t }: { detail: string | null; t: TFunction }) {
  if (!detail) return null;
  return (
    <p className="field__hint">
      {t('settings.signing.anchorSuggest.detail')} <span lang="en">{detail}</span>
    </p>
  );
}

function Proposal({
  proposal,
  t,
  onAddCertificate,
  onAddFingerprint,
}: { proposal: TrustAnchorProposalView; t: TFunction } & Props) {
  const lotlDerived = proposal.provenance === 'eu_lotl';
  return (
    <div className="settings-rows anchor-suggestion">
      <div className="section-head">
        <Badge tone={lotlDerived ? 'ok' : 'warn'} wrap>
          {t(
            lotlDerived
              ? 'settings.signing.anchorSuggest.provenance.lotl'
              : 'settings.signing.anchorSuggest.provenance.listSelfAsserted',
          )}
        </Badge>
        {proposal.already_configured ? (
          <Badge tone="info" wrap>
            {t('settings.signing.anchorSuggest.alreadyConfigured')}
          </Badge>
        ) : null}
      </div>

      {/* Fail-closed and therefore never dismissable: it is the only thing standing between a
          candidate that proves nothing and the trust root of every qualified signature. It is
          rendered BEFORE the certificate's details, so it cannot be scrolled past. */}
      {lotlDerived ? null : (
        <InlineWarning tone="warn" title={t('settings.signing.anchorSuggest.selfAsserted.title')}>
          {t('settings.signing.anchorSuggest.selfAsserted.body')}
        </InlineWarning>
      )}

      <dl className="kv">
        <dt>{t('settings.signing.anchorSuggest.subject')}</dt>
        <dd>{proposal.subject}</dd>
        <dt>{t('settings.signing.anchorSuggest.issuer')}</dt>
        <dd>{proposal.issuer}</dd>
        {proposal.not_before ? (
          <>
            <dt>{t('settings.signing.anchorSuggest.validFrom')}</dt>
            <dd>{proposal.not_before}</dd>
          </>
        ) : null}
        {proposal.not_after ? (
          <>
            <dt>{t('settings.signing.anchorSuggest.validUntil')}</dt>
            <dd>{proposal.not_after}</dd>
          </>
        ) : null}
        <dt>{t('settings.signing.anchorSuggest.fingerprint')}</dt>
        {/* Prominent and copyable: for a self-asserted candidate this value is the entire point —
            it is what the operator carries over to the scheme operator's published figure. */}
        <dd className="mono">{proposal.sha256}</dd>
      </dl>

      {proposal.already_configured ? null : (
        <div className="section-head">
          {proposal.certificate_pem ? (
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Plus />}
              onClick={() => onAddCertificate(proposal.certificate_pem ?? '')}
            >
              {t('settings.signing.anchorSuggest.addCertificate')}
            </Button>
          ) : null}
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Plus />}
            onClick={() => onAddFingerprint(proposal.sha256, !lotlDerived)}
          >
            {t('settings.signing.anchorSuggest.addFingerprint')}
          </Button>
        </div>
      )}
    </div>
  );
}

function Source({
  source,
  t,
  onAddCertificate,
  onAddFingerprint,
}: { source: TrustAnchorSourceSuggestionView; t: TFunction } & Props) {
  return (
    <div className="settings-rows">
      <p>
        <strong>{source.source_name}</strong>
      </p>
      {source.url ? <p className="field__hint mono">{source.url}</p> : null}
      <p className="field__hint">
        <Outcome code={source.code} t={t} />
      </p>
      <Detail detail={source.detail} t={t} />
      {source.proposals.length === 0 ? (
        <p className="field__hint">{t('settings.signing.anchorSuggest.noProposals')}</p>
      ) : (
        source.proposals.map((proposal) => (
          <Proposal
            key={`${source.source_id}-${proposal.sha256}`}
            proposal={proposal}
            t={t}
            onAddCertificate={onAddCertificate}
            onAddFingerprint={onAddFingerprint}
          />
        ))
      )}
    </div>
  );
}

export function TrustAnchorSuggestions({ onAddCertificate, onAddFingerprint }: Props) {
  const t = useT();
  const suggest = useTrustAnchorSuggestions();
  const [result, setResult] = useState<TrustAnchorSuggestionsView | null>(null);
  const [error, setError] = useState<unknown>(null);
  // Which of the two buttons is in flight. `isPending` alone cannot say, and a shared spinner would
  // put "Consulting the List of Trusted Lists…" on a button that is doing nothing.
  const [pendingBootstrap, setPendingBootstrap] = useState(false);

  const run = (bootstrapSelfAsserted: boolean) => {
    setError(null);
    setPendingBootstrap(bootstrapSelfAsserted);
    suggest.mutate(bootstrapSelfAsserted, {
      onSuccess: (view) => setResult(view),
      onError: (err) => {
        setResult(null);
        setError(err);
      },
    });
  };

  return (
    <div className="form settings-rows">
      <p className="field__hint">{t('settings.signing.anchorSuggest.hint')}</p>
      <div className="section-head">
        <p className="field__hint">{t('settings.signing.anchorSuggest.title')}</p>
        <Button
          type="button"
          variant="secondary"
          onClick={() => run(false)}
          disabled={suggest.isPending}
        >
          {t(
            suggest.isPending && !pendingBootstrap
              ? 'settings.signing.anchorSuggest.running'
              : 'settings.signing.anchorSuggest.run',
          )}
        </Button>
      </div>

      {error ? <ErrorNote error={error} /> : null}

      {result ? (
        <>
          <p className="field__hint">
            {t('settings.signing.anchorSuggest.checkedAt', {
              url: result.lotl_url,
              timestamp: result.checked_at,
            })}
          </p>
          {result.lotl_authenticated ? (
            result.sources.map((source) => (
              <Source
                key={source.source_id}
                source={source}
                t={t}
                onAddCertificate={onAddCertificate}
                onAddFingerprint={onAddFingerprint}
              />
            ))
          ) : (
            <>
              {/* The whole run refused. Every source is still listed by the server, but not one of
                  them carries a proposal — so rendering the reason alone is rendering the result. */}
              <InlineWarning tone="warn" title={t('settings.signing.anchorSuggest.refused.title')}>
                <Outcome code={result.lotl_code} t={t} />
                <Detail detail={result.lotl_detail} t={t} />
              </InlineWarning>

              {/* Offered ONLY for the unanchored case, and only after the refusal above has
                  already been rendered. Every other refusal — a failed fetch, a list that did not
                  authenticate — is a state where an anchor exists and the answer is to fix
                  something, not to trust a document that vouches for itself. */}
              {result.lotl_code === LOTL_ANCHOR_NOT_CONFIGURED ? (
                <>
                  <InlineWarning
                    tone="warn"
                    title={t('settings.signing.anchorSuggest.bootstrap.title')}
                  >
                    {t('settings.signing.anchorSuggest.bootstrap.body')}
                  </InlineWarning>
                  <div className="section-head">
                    <Button
                      type="button"
                      variant="secondary"
                      onClick={() => run(true)}
                      disabled={suggest.isPending}
                    >
                      {t(
                        suggest.isPending && pendingBootstrap
                          ? 'settings.signing.anchorSuggest.bootstrap.running'
                          : 'settings.signing.anchorSuggest.bootstrap.run',
                      )}
                    </Button>
                  </div>
                </>
              ) : null}

              {result.lotl_bootstrap_code ? (
                <p className="field__hint">
                  <Outcome code={result.lotl_bootstrap_code} t={t} />
                </p>
              ) : null}
              <Detail detail={result.lotl_bootstrap_detail ?? null} t={t} />

              {/* The same `Proposal` the member-state fallback uses, so the candidate cannot be
                  presented any more gently than the fallback it is. */}
              {(result.lotl_proposals ?? []).map((proposal) => (
                <Proposal
                  key={`lotl-bootstrap-${proposal.sha256}`}
                  proposal={proposal}
                  t={t}
                  onAddCertificate={onAddCertificate}
                  onAddFingerprint={onAddFingerprint}
                />
              ))}
            </>
          )}
        </>
      ) : null}
    </div>
  );
}
