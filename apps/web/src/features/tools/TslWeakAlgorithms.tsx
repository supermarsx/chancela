/**
 * The AT-USE-TIME weak-algorithm marker for a Trusted List verdict.
 *
 * ## Why this exists at all
 *
 * `signing.tsl_legacy_algorithms` lets an operator permit a cryptographically broken algorithm when
 * verifying a Trusted List's own signature. The whole point of the feature is that permitting one
 * is not a decision taken once on a settings screen and then forgotten: every verdict that
 * *depended* on it has to say so, wherever that verdict is read. "Signature valid" and "signature
 * valid because SHA-1 was allowed" are different facts, and a screen that renders them identically
 * is the failure this component removes.
 *
 * So it is deliberately additive to the existing signature badge rather than a replacement for it:
 * the verdict is still whatever the backend said, and this states what it rested on.
 *
 * ## One of three concerns, sharing one treatment
 *
 * This used to own both of its own pieces — a labelled status-line cell and a banner directly
 * under it. It now contributes a {@link TrustConcern} instead, and `trustConcerns.tsx` renders the
 * icon in the status line and the entry in the single banner below the lists. Nothing here was
 * dropped in the move: the label and badge that were the cell's whole content became the entry's
 * header, and the title and body are the entry's heading and prose.
 *
 * It returns **nothing at all** when the list is empty or absent. That is what makes the marker a
 * signal rather than decoration: on an untouched install, where no broken algorithm is permitted,
 * no icon and no entry appear, so their appearance always means something happened.
 *
 * ## Copy comes from the catalog, never from the wire
 *
 * The backend emits a stable `code` and a structured position, no prose — see
 * `i18n/tslWeakAlgorithms.ts` for why. A code this build does not recognise still produces an
 * entry, wording only what is certain (a broken algorithm was relied upon) rather than falling
 * silent, because a newer backend must never be able to turn this warning off.
 */
import { useT, type TFunction } from '../../i18n';
import { legacyAlgorithmLabelKey, weakAlgorithmSentenceKey } from '../../i18n/tslWeakAlgorithms';
import type { WeakAlgorithmUse } from '../../api/types';
import type { TrustConcern } from './trustConcerns';

/**
 * One reliance, worded. Kept separate from the list so the `site` discriminant is narrowed in one
 * place: `index`/`total`/`uri` exist on the `reference` arm alone, and the compiler is what proves
 * the other arm never reads them.
 */
function WeakAlgorithmItem({ use }: { use: WeakAlgorithmUse }) {
  const t = useT();
  const sentence = weakAlgorithmSentenceKey(use.code);
  const label = legacyAlgorithmLabelKey(use.algorithm);
  return (
    <li className="trust-weak-algorithm">
      <p>{t(sentence ?? 'trust.weakAlgorithms.unknown')}</p>
      {label ? <p>{t(label)}</p> : null}
      {/* The URI verbatim, in every locale: it is the exact string the settings document holds and
          the exact string a 422 names, so translating or abbreviating it would break the one use
          an operator has for it. */}
      <p className="mono trust-opaque">{use.algorithm}</p>
      {use.site === 'reference' ? (
        <p className="mono trust-opaque">
          {t('trust.weakAlgorithms.reference', {
            index: use.index,
            total: use.total,
            uri: use.uri,
          })}
        </p>
      ) : null}
    </li>
  );
}

/**
 * The concern, or `null` when this verdict rested on nothing broken.
 *
 * `severity: 'warn'` rather than an error tone on purpose. Nothing failed — the list validated,
 * and it validated under a rule the operator deliberately configured. Painting it as an error
 * would train operators to ignore it, and would also overstate the case: permitting one algorithm
 * widens exactly one gate and relaxes no other check.
 */
export function weakAlgorithmsConcern(
  t: TFunction,
  uses?: readonly WeakAlgorithmUse[],
): TrustConcern | null {
  if (!uses || uses.length === 0) return null;
  return {
    slug: 'weak-algorithms',
    severity: 'warn',
    label: t('trust.weakAlgorithms.label'),
    badge: t('trust.weakAlgorithms.badge'),
    heading: t('trust.weakAlgorithms.title'),
    body: (
      <>
        <p>{t('trust.weakAlgorithms.intro')}</p>
        <ul className="trust-weak-algorithms" data-weak-algorithms={uses.length}>
          {uses.map((use, index) => (
            <WeakAlgorithmItem key={`${use.code}-${use.algorithm}-${index}`} use={use} />
          ))}
        </ul>
      </>
    ),
  };
}
