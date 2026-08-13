/**
 * The shared treatment for every "this verdict depended on something you should know about"
 * marker on the trust screens.
 *
 * ## What this replaces, and why
 *
 * Three markers had accumulated — a permitted broken algorithm, a verdict served out of the
 * durable cache, and a Trusted List fetched over a transport this installation does not
 * authenticate. Each had grown the same two pieces independently: a labelled cell in the status
 * line, and a full `InlineWarning` rendered immediately below it. With all three present that is
 * three cells and three stacked banners of prose sitting between the status line and the fact
 * tables the operator came to read, which pushed the lists off the first screen — and the more
 * markers accrue, the worse it gets, because each one was paying its own full price in vertical
 * space at the top of the page.
 *
 * They share a shape, so they now share a treatment:
 *
 * - **In the status line**, {@link TrustConcernMarkers} — one small icon per concern and nothing
 *   else. It says *that* there is something to look at, in roughly a tenth of the width the three
 *   labelled cells took.
 * - **Below the lists**, {@link TrustConcernsBanner} — a single banner where the detail lives, one
 *   entry per concern.
 *
 * ## Nothing is behind a hover, and nothing was dropped
 *
 * Every sentence the three banners rendered is still rendered, in the banner entry, as plain
 * on-screen text. So are the two strings that used to live in the status-line cell — the label
 * ("Transport") and the badge ("Not authenticated") — which move into the entry's header rather
 * than being lost with the cell. The icon carries a tooltip, but it only repeats the entry's own
 * heading, which is also its accessible name; a mouse user gets the gist without scrolling, and
 * nobody has to hover to obtain information that exists nowhere else.
 *
 * ## How an icon and its entry are tied together
 *
 * Each marker is a real in-page link (`href="#trust-concern-…"`) whose accessible name is the
 * heading of the entry it points at, and each entry carries that id and `tabIndex={-1}` so
 * following the link lands focus on it. A link rather than an `aria-describedby` because the two
 * are now deliberately far apart: `aria-describedby` would read four paragraphs of prose out at a
 * status-line icon, which is precisely the crowding this change removes, and it would still leave
 * a screen-reader user with no way to *get* to the entry. The link's name matching its target's
 * heading is what lets someone tell which item is affected without sighted scanning.
 *
 * ## Severity is not flattened
 *
 * An unverified transport is informational; an expired cached list and a permitted broken
 * algorithm are warnings. That distinction is carried four ways: warnings sort ahead of
 * informational entries, each marker draws a different glyph, each entry keeps the badge tone its
 * status-line cell used, and the banner as a whole takes the highest severity present. It is never
 * a bare count of "concerns".
 *
 * ## Empty is empty
 *
 * With no concerns, {@link TrustConcernMarkers} and {@link TrustConcernsBanner} both render `null`
 * — no cell, no banner, no container and no "0 concerns" chrome. On an untouched install these
 * screens look exactly as they did before any of the three markers existed, which is what makes
 * the icon's presence a signal.
 */
import type { ReactNode } from 'react';
import { Badge, Icon, InlineWarning, Tooltip } from '../../ui';

/** How loudly a concern speaks. `warn` sorts first and colours the banner. */
export type TrustConcernSeverity = 'warn' | 'info';

/** The stable slug of each concern this build knows how to raise. */
export type TrustConcernSlug = 'weak-algorithms' | 'cache-fallback' | 'unverified-transport';

/**
 * One reason a verdict on screen is qualified.
 *
 * Built by the module that owns the copy — `TslWeakAlgorithms`, `TslCacheFallback`,
 * `TslUnverifiedTransport` — so the wording stays next to the reasoning that justifies it, and
 * this module never has to know what any of them mean.
 */
export interface TrustConcern {
  slug: TrustConcernSlug;
  severity: TrustConcernSeverity;
  /** The short field name the status-line cell used to show ("Transport"). */
  label: string;
  /** The short verdict the status-line cell used to show ("Not authenticated"). */
  badge: string;
  /** The marker's accessible name AND the entry's heading — deliberately the same string. */
  heading: string;
  /** Everything the concern's own banner used to render below its title. */
  body: ReactNode;
}

/**
 * Where a set of concerns is rendered. Part of the entry ids, so two groups on one page — the
 * current status and the last import, which carry independent verdicts — cannot collide.
 */
export type TrustConcernGroup = 'tsl-status' | 'tsl-import' | 'tsa-summary';

/** The DOM id of one concern's banner entry: what its marker links to. */
export function trustConcernEntryId(group: TrustConcernGroup, slug: TrustConcernSlug): string {
  return `trust-concern-${group}-${slug}`;
}

const SEVERITY_RANK: Record<TrustConcernSeverity, number> = { warn: 0, info: 1 };

/**
 * Drop the absent ones and order what is left: warnings first, source order within a severity.
 *
 * The sort is what stops a single banner reading as one undifferentiated pile — an operator
 * scanning from the top hits the expired cached list before the informational transport note,
 * every time, rather than in whatever order the fields happen to sit in the view type.
 */
export function orderTrustConcerns(
  concerns: readonly (TrustConcern | null)[],
): readonly TrustConcern[] {
  return concerns
    .filter((concern): concern is TrustConcern => concern !== null)
    .map((concern, index) => ({ concern, index }))
    .sort(
      (a, b) =>
        SEVERITY_RANK[a.concern.severity] - SEVERITY_RANK[b.concern.severity] || a.index - b.index,
    )
    .map(({ concern }) => concern);
}

/** The tone the collecting banner takes: the loudest severity it carries. */
function bannerTone(concerns: readonly TrustConcern[]): TrustConcernSeverity {
  return concerns.some((concern) => concern.severity === 'warn') ? 'warn' : 'info';
}

/**
 * The alert affordance itself: one icon per concern, beside the verdict it qualifies, and nothing
 * else — no label, no badge, no count.
 *
 * Renders nothing at all when there are none, rather than an empty box: in the status line's flex
 * row an empty cell reads as a missing value, not as "all clear".
 */
export function TrustConcernMarkers({
  concerns,
  group,
  className,
}: {
  concerns: readonly TrustConcern[];
  group: TrustConcernGroup;
  /**
   * Extra classes for the box the icons sit in. The status line passes its own cell classes so
   * the group is a cell of that flex row; a fact-table cell passes nothing, because a `<td>` that
   * is taken out of table layout makes the column's geometry a property of the row that happens
   * to carry a marker (`ui/tableActionCellGuards.test.ts` fails on it, by construction).
   */
  className?: string;
}) {
  if (concerns.length === 0) return null;
  return (
    <span
      className={`trust-concern-markers${className ? ` ${className}` : ''}`}
      data-trust-concerns={concerns.length}
    >
      {concerns.map((concern) => (
        // `describe={false}`: the bubble repeats the anchor's own accessible name verbatim, so
        // describing it would make a screen reader read the same sentence twice. It is here for
        // the sighted mouse user, who otherwise gets a glyph and no words at all.
        <Tooltip key={concern.slug} label={concern.heading} describe={false}>
          {/* A plain anchor, not a button: the target is a real element with a real id, so the
              browser's own fragment navigation moves focus there and the back button undoes it.
              Nothing here needs JavaScript to work. */}
          <a
            className={`trust-concern-marker trust-concern-marker--${concern.severity}`}
            href={`#${trustConcernEntryId(group, concern.slug)}`}
            aria-label={concern.heading}
            data-trust-concern={concern.slug}
            data-severity={concern.severity}
          >
            {concern.severity === 'warn' ? <Icon.Alert /> : <Icon.Info />}
          </a>
        </Tooltip>
      ))}
    </span>
  );
}

/** One entry: the status-line cell's two strings, the old banner's title, the old banner's body. */
function TrustConcernEntry({
  concern,
  group,
}: {
  concern: TrustConcern;
  group: TrustConcernGroup;
}) {
  return (
    <li
      id={trustConcernEntryId(group, concern.slug)}
      // Focusable only as a link target: following a marker lands the caret here rather than
      // leaving a screen-reader user at the top of a banner counting entries.
      tabIndex={-1}
      className={`trust-concern trust-concern--${concern.severity}`}
      data-trust-concern={concern.slug}
      data-severity={concern.severity}
    >
      <div className="trust-concern__meta">
        <span className="trust-statusline__label">{concern.label}</span>
        <Badge tone={concern.severity === 'warn' ? 'warn' : 'neutral'}>{concern.badge}</Badge>
      </div>
      <p className="trust-concern__heading">{concern.heading}</p>
      <div className="trust-concern__body">{concern.body}</div>
    </li>
  );
}

/**
 * The one banner, at the end of the lists it qualifies.
 *
 * No `notice` key, so there is no dismiss control — inherited deliberately from all three of the
 * banners this replaces. Each is a property of the verdict on screen, not an announcement, and
 * must come back the next time the same thing happens.
 */
export function TrustConcernsBanner({
  concerns,
  group,
}: {
  concerns: readonly TrustConcern[];
  group: TrustConcernGroup;
}) {
  if (concerns.length === 0) return null;
  return (
    <InlineWarning tone={bannerTone(concerns)}>
      <ul className="trust-concerns" data-trust-concerns={concerns.length}>
        {concerns.map((concern) => (
          <TrustConcernEntry key={concern.slug} concern={concern} group={group} />
        ))}
      </ul>
    </InlineWarning>
  );
}
