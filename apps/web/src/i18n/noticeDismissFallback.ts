/**
 * Copy for the `InlineWarning` dismiss capability (`ui/InlineWarning.tsx`).
 *
 * Kept outside the shared locale catalogs for the reason the three modules it replaces gave —
 * `Catalog` is a TOTAL type, so a handful of control labels would otherwise cost a key in all 14
 * shipped catalogs. This is the established owned-fallback escape valve: pt-PT anchored, English
 * for every other locale.
 *
 * ## Why the copy is split in two
 *
 * The **shared** half ("Ocultar durante N dias", "Ocultar permanentemente" and their two
 * confirmations) says nothing about which notice is being hidden, so one copy serves every notice.
 *
 * The **self-naming** half — the dismiss group's accessible name, and the restore control — must
 * say WHAT is being hidden or brought back, and that sentence is inflected around the noun
 * ("Repor aviso sobre **as** citações" vs "Repor aviso sobre **o** âmbito dos logs"). Portuguese
 * agreement means such a sentence can never be assembled from a noun dropped into a template, so
 * each notice carries its own complete standalone strings. `Record<NoticeKey, …>` is total: a new
 * `NoticeKey` does not compile until someone has written them.
 *
 * ## Restore is opt-in the same way dismissal is
 *
 * `restore` is optional, and its ABSENCE is what makes a notice non-restorable — `external_signing`
 * has never offered a way back and keeps that behaviour. A notice becomes restorable exactly when
 * someone writes the sentence that names it, which is the same deliberate act as opting a banner
 * into dismissal in the first place.
 */
import { useMemo } from 'react';
import type { NoticeKey } from '../api/types';
import { interpolate } from './interpolate';
import { useActiveLocale } from './useT';

/** The label/confirmation pair for bringing one dismissed notice back. Present ⇔ restorable. */
interface NoticeRestoreCopy {
  /** Accessible name of the restore control. Names the notice; never assembled from a noun. */
  label: string;
  /** Toast shown once the restore has been persisted. */
  confirmation: string;
}

interface NoticeSelfCopy {
  /** Accessible name of the `role="group"` holding the dismiss buttons. */
  dismissActions: string;
  restore?: NoticeRestoreCopy;
}

const SHARED_PT_PT = {
  hideTemporary: 'Ocultar durante {days} dias',
  hidePermanent: 'Ocultar permanentemente',
  hiddenTemporary: 'Aviso ocultado durante {days} dias.',
  hiddenPermanent: 'Aviso ocultado permanentemente.',
} as const;

const SHARED_ENGLISH = {
  hideTemporary: 'Hide for {days} days',
  hidePermanent: 'Hide permanently',
  hiddenTemporary: 'Notice hidden for {days} days.',
  hiddenPermanent: 'Notice hidden permanently.',
} as const satisfies Record<keyof typeof SHARED_PT_PT, string>;

const SELF_PT_PT: Record<NoticeKey, NoticeSelfCopy> = {
  external_signing: {
    dismissActions: 'Opções para ocultar este aviso',
  },
  platform_log_scope: {
    dismissActions: 'Opções para ocultar o aviso sobre o âmbito dos logs',
    restore: {
      label: 'Repor aviso sobre o âmbito dos logs',
      confirmation: 'Aviso sobre o âmbito dos logs reposto.',
    },
  },
  leg_citations: {
    dismissActions: 'Opções para ocultar este aviso',
    restore: {
      label: 'Repor aviso sobre as citações',
      confirmation: 'Aviso sobre as citações reposto.',
    },
  },
  termo_signing_legend: {
    dismissActions: 'Opções para ocultar este aviso',
    restore: {
      label: 'Repor legenda das assinaturas do termo',
      confirmation: 'Legenda das assinaturas do termo reposta.',
    },
  },
  book_open_guidance: {
    dismissActions: 'Opções para ocultar este aviso',
    restore: {
      label: 'Repor orientação sobre a abertura de livros',
      confirmation: 'Orientação sobre a abertura de livros reposta.',
    },
  },
};

const SELF_ENGLISH: Record<NoticeKey, NoticeSelfCopy> = {
  external_signing: {
    dismissActions: 'Options for hiding this notice',
  },
  platform_log_scope: {
    dismissActions: 'Options for hiding the log-scope notice',
    restore: {
      label: 'Restore log-scope notice',
      confirmation: 'Log-scope notice restored.',
    },
  },
  leg_citations: {
    dismissActions: 'Options for hiding this notice',
    restore: {
      label: 'Restore citations notice',
      confirmation: 'Citations notice restored.',
    },
  },
  // "termo" is the legal instrument's own name and stays Portuguese in every locale.
  termo_signing_legend: {
    dismissActions: 'Options for hiding this notice',
    restore: {
      label: 'Restore termo signature legend',
      confirmation: 'Termo signature legend restored.',
    },
  },
  book_open_guidance: {
    dismissActions: 'Options for hiding this notice',
    restore: {
      label: 'Restore book-opening guidance',
      confirmation: 'Book-opening guidance restored.',
    },
  },
};

/**
 * The notices that can be brought back — a locale-independent FACT about the copy, not a policy.
 *
 * Restorability is "somebody wrote the sentence that names this notice", and the two catalogs above
 * agree on which notices those are (the parity is asserted in the tests, so a locale that gained or
 * lost a `restore` block fails rather than making a notice restorable in one language only). The
 * account area's hidden-notice index needs this outside a hook, to decide whether it has anything
 * to list before it renders a list.
 */
export const RESTORABLE_NOTICE_KEYS: ReadonlySet<NoticeKey> = new Set(
  (Object.entries(SELF_PT_PT) as [NoticeKey, NoticeSelfCopy][])
    .filter(([, copy]) => copy.restore !== undefined)
    .map(([notice]) => notice),
);

/** Every string one dismissable banner needs, already interpolated for its snooze length. */
export interface NoticeDismissCopy {
  dismissActions: string;
  hideTemporary: string;
  hidePermanent: string;
  hiddenTemporary: string;
  hiddenPermanent: string;
  restore?: NoticeRestoreCopy;
}

export function useNoticeDismissCopy(
  notice: NoticeKey,
  temporaryHideDays: number,
): NoticeDismissCopy {
  const locale = useActiveLocale();
  return useMemo(() => {
    const isPtPT = locale === 'pt-PT';
    const shared = isPtPT ? SHARED_PT_PT : SHARED_ENGLISH;
    const self = (isPtPT ? SELF_PT_PT : SELF_ENGLISH)[notice];
    const days = { days: temporaryHideDays };
    return {
      dismissActions: self.dismissActions,
      hideTemporary: interpolate(shared.hideTemporary, days),
      hidePermanent: shared.hidePermanent,
      hiddenTemporary: interpolate(shared.hiddenTemporary, days),
      hiddenPermanent: shared.hiddenPermanent,
      restore: self.restore,
    };
  }, [locale, notice, temporaryHideDays]);
}
