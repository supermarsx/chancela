/**
 * Preferências — durable per-user state that is neither identity nor credential.
 *
 * ## What is here: the notices you have hidden
 *
 * Dismissing an informational notice writes a durable entry in the self-scoped
 * `/v1/me/preferences` document, so it stays hidden across sessions and machines. Bringing one back
 * is offered by `InlineWarning` itself — but only *in place of the banner*, which means you have to
 * remember which page it was on and navigate there. This card is the index: the notices you have
 * hidden, in one list, each with its own restore control.
 *
 * ## Why only some hidden notices are listed, and why that is right
 *
 * A notice is restorable exactly when its copy provides the sentence that NAMES it
 * (`noticeDismissFallback`'s `restore`, which is optional by design — `external_signing` has never
 * offered a way back). Portuguese agreement is the reason that sentence cannot be assembled from a
 * template: "Repor aviso sobre **as** citações" versus "Repor aviso sobre **o** âmbito dos logs".
 *
 * So this card lists a hidden notice only when that sentence exists, and it uses that sentence as
 * the control's name rather than inventing a second one. A notice with no restore copy is not
 * listed, because there is no honest name to list it under and no action to offer beside it — and
 * inventing either would quietly opt a banner into restorability that its author deliberately did
 * not grant. The footnote says a hidden notice may not appear here, so the absence is stated rather
 * than left to be discovered.
 *
 * ## What is deliberately NOT here: per-table column choices
 *
 * They are per-user and durable, and they live in the same preferences document — but they already
 * have exactly one address each: the column picker on the table itself, which is where the choice
 * is made and where its effect is visible. A second surface listing "your column overrides" would
 * be a second address for an action that has one, which is the defect this codebase has removed
 * twice (t71, t89). Reported as a deliberate omission rather than a gap.
 */
import { useUserPreferences } from '../../api/hooks';
import type { NoticeKey, UserPreferences } from '../../api/types';
import { useT } from '../../i18n';
import { RESTORABLE_NOTICE_KEYS } from '../../i18n/noticeDismissFallback';
import {
  Button,
  Card,
  EmptyState,
  ErrorNote,
  informationalNoticeIsHidden,
  SkeletonList,
  useNoticeDismissal,
} from '../../ui';

/**
 * Every notice key the preferences API accepts, as runtime DATA.
 *
 * `Record<NoticeKey, true>` and not `readonly NoticeKey[]`, deliberately: the record is a TOTAL
 * type, so a key added to the union does not compile until it is added here, and an invented key
 * does not compile at all. An annotated array would have checked only membership — a new notice
 * would have been silently absent from this index, which is the one place a hidden notice can be
 * found without knowing which page it belonged to. Same discipline `noticeDismissFallback` uses for
 * the per-notice copy, and for the same reason.
 */
const NOTICE_KEYS: Record<NoticeKey, true> = {
  external_signing: true,
  platform_log_scope: true,
  leg_citations: true,
  termo_signing_legend: true,
  book_open_guidance: true,
};

export const ALL_NOTICE_KEYS = Object.keys(NOTICE_KEYS) as readonly NoticeKey[];

/**
 * One row of the index. A component per notice because `useNoticeDismissal` is a hook and must be
 * called unconditionally — the alternative (one hook call with a dynamic key) cannot read five
 * notices at once.
 *
 * Renders nothing unless the notice is BOTH hidden and restorable: `hidden` is the whole reason to
 * list it, and `restore` is the only honest name for it (see the module note).
 */
function HiddenNoticeRow({ notice }: { notice: NoticeKey }) {
  const dismissal = useNoticeDismissal(notice);
  const restore = dismissal.copy.restore;
  if (!dismissal.ready || !dismissal.hidden || !restore) return null;
  return (
    <li>
      <Button
        type="button"
        variant="secondary"
        disabled={dismissal.pending}
        data-notice={notice}
        onClick={dismissal.restore}
      >
        {restore.label}
      </Button>
    </li>
  );
}

/**
 * How many rows will actually render, computed from the same document and the same two predicates
 * the rows use.
 *
 * Deliberately NOT inferred from the rendered children: React gives no such count, so a parent that
 * guessed would show an empty state above a populated list — or an empty `<ul>` under a "you have
 * hidden notices" heading — the moment the predicates drifted. Both conditions are applied here:
 * currently hidden, AND restorable (a hidden notice with no restore sentence has no honest name to
 * be listed under, and the footnote says so).
 */
function hiddenRestorableCount(preferences: UserPreferences): number {
  const dismissals = preferences.notice_dismissals ?? {};
  const legacy = preferences.external_signature_notice_dismissal;
  return ALL_NOTICE_KEYS.filter((notice) => {
    if (!RESTORABLE_NOTICE_KEYS.has(notice)) return false;
    const dismissal =
      dismissals[notice] ?? (notice === 'external_signing' ? legacy : undefined) ?? null;
    return informationalNoticeIsHidden(dismissal);
  }).length;
}

function HiddenNoticesCard() {
  const t = useT();
  const preferences = useUserPreferences();
  const count = preferences.data ? hiddenRestorableCount(preferences.data) : undefined;

  return (
    <Card title={t('account.notices.card')}>
      <div className="stack">
        <p className="field__hint">{t('account.notices.body')}</p>
        {preferences.isLoading ? (
          <SkeletonList items={2} />
        ) : preferences.error ? (
          <ErrorNote error={preferences.error} />
        ) : count === 0 ? (
          <EmptyState title={t('account.notices.empty')} />
        ) : (
          <ul className="stack--tight">
            {ALL_NOTICE_KEYS.map((notice) => (
              <HiddenNoticeRow key={notice} notice={notice} />
            ))}
          </ul>
        )}
        <p className="field__hint">{t('account.notices.footnote')}</p>
      </div>
    </Card>
  );
}

export function AccountPreferencesSection() {
  const t = useT();
  return (
    <div className="stack">
      {/* A plain lede, not a Card: a panel whose whole body is one sentence is a frame around
          nothing, and the section's cards are what the frame is for. */}
      <p className="lede">{t('account.preferences.lede')}</p>
      <HiddenNoticesCard />
    </div>
  );
}
