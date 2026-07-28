/**
 * `InlineWarning` — the app-wide inline banner, and the one place a banner may be made dismissable.
 *
 * ## The capability, and why it is safe by default
 *
 * A banner opts into per-user dismissal by naming the registry key it is stored under:
 *
 * ```tsx
 * <InlineWarning tone="info" notice="platform_log_scope" title={…}>…</InlineWarning>
 * ```
 *
 * There is deliberately **no boolean**. Dismissal is not a flag that can be flipped the wrong way
 * by a careless edit or a copied call site — it requires naming a key from the closed `NoticeKey`
 * enum, which the API mirrors and which does not compile until someone has also written the copy
 * that names the notice (`i18n/noticeDismissFallback.ts`). Omitting `notice` is the only default,
 * and it is the safe one.
 *
 * That matters because most of this component's ~460 call sites are **fail-closed**: they tell an
 * operator that an act cannot be signed, that a book is sealed, that a credential is missing. Those
 * must never acquire a dismiss control, and the shape of this module is what guarantees it —
 * {@link InlineWarningFrame}, the markup every banner renders, has no parameter for actions and no
 * access to the registry at all. A banner with no key cannot render a dismiss control and cannot
 * reach the mutation that would persist one; there is no path from "someone changed a prop" to
 * "a blocking warning was hidden".
 *
 * ## Why the registry work sits in a child component
 *
 * {@link DismissibleInlineWarning} is mounted only when a key was named, so the other call sites
 * subscribe to no queries and own no mutation — dismissal costs nothing to a banner that did not
 * ask for it.
 */
import type { ReactNode } from 'react';
import type { NoticeKey } from '../api/types';
import { useNoticeDismissal } from './noticeDismissal';
import { Button } from './index';

export interface InlineWarningProps {
  tone?: 'warn' | 'error' | 'info';
  title?: ReactNode;
  /**
   * Opt this banner into durable per-user dismissal, under this registry key.
   *
   * **Omit it for anything fail-closed.** An absent key is not "dismissal turned off" — it is a
   * banner that has no dismiss control to render and no registry entry to write.
   */
  notice?: NoticeKey;
  children: ReactNode;
}

/**
 * The banner markup, shared by both paths. It takes no actions and knows nothing about dismissal:
 * that absence is the guarantee described in this module's header, so keep it that way.
 */
function InlineWarningFrame({
  tone = 'warn',
  title,
  notice,
  children,
}: Omit<InlineWarningProps, 'notice'> & { notice?: NoticeKey }) {
  return (
    <div className={`inline-warning inline-warning--${tone}`} role="note" data-notice={notice}>
      {title ? <p className="inline-warning__title">{title}</p> : null}
      <div className="inline-warning__body">{children}</div>
    </div>
  );
}

export function InlineWarning({ notice, ...rest }: InlineWarningProps) {
  return notice === undefined ? (
    <InlineWarningFrame {...rest} />
  ) : (
    <DismissibleInlineWarning {...rest} notice={notice} />
  );
}

/**
 * A banner that named a registry key: it hides itself once the operator dismisses it, and — where
 * the notice's copy provides the sentence naming it — leaves a restore control in its place, so a
 * dismissal is never a one-way door.
 */
function DismissibleInlineWarning({
  notice,
  tone,
  title,
  children,
}: Omit<InlineWarningProps, 'notice'> & { notice: NoticeKey }) {
  const dismissal = useNoticeDismissal(notice);

  // Nothing at all until we know the operator's choice, and nothing once it is "hidden".
  if (dismissal.loading) return null;

  if (dismissal.hidden) {
    const restore = dismissal.copy.restore;
    // `ready` is required: without the loaded document there is no safe PUT to build, and a
    // notice that is not restorable simply leaves nothing behind.
    if (!dismissal.ready || !restore) return null;
    return (
      <div className="notice-restore">
        <Button
          type="button"
          variant="ghost"
          disabled={dismissal.pending}
          onClick={dismissal.restore}
        >
          {restore.label}
        </Button>
      </div>
    );
  }

  return (
    <InlineWarningFrame tone={tone} title={title} notice={notice}>
      {children}
      {dismissal.ready ? (
        <div
          className="informational-notice__actions"
          role="group"
          aria-label={dismissal.copy.dismissActions}
        >
          <Button
            type="button"
            variant="secondary"
            disabled={dismissal.pending}
            onClick={() => dismissal.hide('snoozed')}
          >
            {dismissal.copy.hideTemporary}
          </Button>
          <Button
            type="button"
            variant="ghost"
            disabled={dismissal.pending}
            onClick={() => dismissal.hide('permanent')}
          >
            {dismissal.copy.hidePermanent}
          </Button>
        </div>
      ) : null}
    </InlineWarningFrame>
  );
}
