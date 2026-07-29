/**
 * Address builders for the five RGPD compliance registers (t55).
 *
 * Every register record has a real, pasteable address now — `/settings/privacy/dpias/<id>` is the
 * canonical reference to a DPIA, and `…/new` is the create screen. Before t55 the create/edit form
 * was a modal (processors, DPIAs) or an inline `<Card>` shoved above the list (breach playbooks,
 * transfer controls, retention policies); neither had an address and browser Back reached neither.
 *
 * ## Two things this module encodes, so no call site has to remember them
 *
 * 1. **Slugs are English and are the API resource name** (t97b — "a URL slug is an identifier, not
 *    copy"). `processors` stays `processors` even though the register is renamed in pt-PT, because
 *    the resource did not move. These addresses never had a Portuguese spelling, so there is no
 *    `legacySlugs` entry to add.
 * 2. **Every record address is FOUR segments.** The settings catch-all is `settings/:sec?/:sub?`,
 *    which matches at most three, so a record route can neither shadow nor be shadowed by it. That
 *    is also why `retention` (the sub-tab, 3 segments) and `retention-policies` (the register, 4)
 *    can sit at the same position without colliding.
 *
 * Ids are server-generated and always `encodeURIComponent`-ed here, so an id can never be read as
 * a path separator; and because React Router ranks static above dynamic, `…/new` always resolves to
 * the create screen rather than to a record whose id happens to be `new`.
 *
 * Mirrors `templateRoutes.ts` and `providerCredentialRoutes.ts`.
 */

/** The five register resources, spelled as they appear in the URL. */
export type PrivacyRegisterSlug =
  'processors' | 'dpias' | 'breach-playbooks' | 'transfer-controls' | 'retention-policies';

export const PRIVACY_REGISTER_SLUGS = [
  'processors',
  'dpias',
  'breach-playbooks',
  'transfer-controls',
  'retention-policies',
] as const satisfies readonly PrivacyRegisterSlug[];

/** The Privacidade tab itself — the return address for registers #1-#4 and the second crumb. */
export function privacyListPath(): string {
  return '/settings/privacy';
}

/**
 * The Retenção sub-tab — the return address for the retention-policy register.
 *
 * The privacy sub-tabs are component-local state today, so `/settings/privacy/retention` does not
 * resolve yet and this deliberately points at the tab's default (`/settings/privacy`, which opens
 * on Registos). t55-e5 makes the sub-tabs path segments and upgrades this ONE constant — which is
 * the whole reason the return address is a function and not a string literal at each call site.
 */
export function privacyRetentionListPath(): string {
  return '/settings/privacy';
}

/** The create screen for a register: `/settings/privacy/dpias/new`. */
export function privacyRecordNewPath(slug: PrivacyRegisterSlug): string {
  return `/settings/privacy/${slug}/new`;
}

/** One record's canonical address: `/settings/privacy/dpias/<id>`. */
export function privacyRecordPath(slug: PrivacyRegisterSlug, id: string): string {
  return `/settings/privacy/${slug}/${encodeURIComponent(id)}`;
}

/** The list a given register's pages return to (§4.6 — three explicit exits, one address). */
export function privacyRegisterListPath(slug: PrivacyRegisterSlug): string {
  return slug === 'retention-policies' ? privacyRetentionListPath() : privacyListPath();
}

/**
 * The DPIA guidance MODEL editor: `/settings/privacy/dpia-template/edit`.
 *
 * Not a register — a singleton document, so there is no id and no `…/new`. It still earns a page
 * of its own for the reason the five registers did: it is a multi-section authoring surface, and
 * an inline card inside a sub-tab has no address, no Back, and no unsaved-changes guard.
 *
 * `dpia-template` is the API resource name and the slug is English for the same reason the five
 * register slugs are (t97b — "a URL slug is an identifier, not copy"). Four segments, so it can
 * neither shadow nor be shadowed by the `settings/:sec?/:sub?` catch-all, exactly as the record
 * addresses above; the trailing `edit` is what makes the fourth segment, since a singleton has no
 * id to supply one.
 */
export function privacyDpiaTemplateEditPath(): string {
  return '/settings/privacy/dpia-template/edit';
}
