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
 * ## Two pieces, because they answer two different questions at two different distances
 *
 * {@link WeakAlgorithmStatuslineItem} is a labelled cell in the status line an operator scans; it
 * answers "is there anything to look at here". {@link TslWeakAlgorithmsNotice} is the banner below
 * it that answers "what exactly", naming each reliance, its algorithm URI verbatim, and — for a
 * reference digest — which of the list's references it was.
 *
 * The status-line piece renders its own labelled cell rather than a bare badge, and that is not
 * cosmetic: two badges dropped side by side in one cell are separated only by a CSS `gap`, which
 * inserts no character, so a screen reader and find-in-page both read them fused into one word.
 *
 * Both render **nothing at all** when the list is empty or absent. That is what makes the marker a
 * signal rather than decoration: on an untouched install, where no broken algorithm is permitted,
 * neither appears, so their appearance always means something happened.
 *
 * ## Copy comes from the catalog, never from the wire
 *
 * The backend emits a stable `code` and a structured position, no prose — see
 * `i18n/tslWeakAlgorithms.ts` for why. A code this build does not recognise still produces a
 * banner, wording only what is certain (a broken algorithm was relied upon) rather than falling
 * silent, because a newer backend must never be able to turn this warning off.
 */
import { InlineWarning, Badge } from '../../ui';
import { useT } from '../../i18n';
import { legacyAlgorithmLabelKey, weakAlgorithmSentenceKey } from '../../i18n/tslWeakAlgorithms';
import type { WeakAlgorithmUse } from '../../api/types';

/**
 * A compact marker for a `.trust-statusline`: this verdict relied on a broken algorithm.
 *
 * Renders nothing when it did not — including when the field is absent, which is how the wire
 * spells "nothing weak was permitted".
 */
export function WeakAlgorithmStatuslineItem({ uses }: { uses?: readonly WeakAlgorithmUse[] }) {
  const t = useT();
  if (!uses || uses.length === 0) return null;
  return (
    <div className="trust-statusline__item" data-weak-algorithms={uses.length}>
      <span className="trust-statusline__label">{t('trust.weakAlgorithms.label')}</span>
      <Badge tone="warn">{t('trust.weakAlgorithms.badge')}</Badge>
    </div>
  );
}

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
 * The full banner: every broken algorithm this verdict rested on.
 *
 * `tone="warn"` rather than `"error"` on purpose. Nothing failed — the list validated, and it
 * validated under a rule the operator deliberately configured. Painting it as an error would train
 * operators to ignore it, and would also overstate the case: permitting one algorithm widens
 * exactly one gate and relaxes no other check.
 *
 * No `notice` key, so there is no dismiss control: this is a property of the verdict on screen, not
 * an announcement, and it must come back the next time the same thing happens.
 */
export function TslWeakAlgorithmsNotice({ uses }: { uses?: readonly WeakAlgorithmUse[] }) {
  const t = useT();
  if (!uses || uses.length === 0) return null;
  return (
    <InlineWarning tone="warn" title={t('trust.weakAlgorithms.title')}>
      <p>{t('trust.weakAlgorithms.intro')}</p>
      <ul className="trust-weak-algorithms" data-weak-algorithms={uses.length}>
        {uses.map((use, index) => (
          <WeakAlgorithmItem key={`${use.code}-${use.algorithm}-${index}`} use={use} />
        ))}
      </ul>
    </InlineWarning>
  );
}
