# `apps/web` UI conventions

The consistency checklist every feature surface follows. Written for plan **t44 §t44-consistency**
after the onboarding / autosave / toast slices landed, so it doubles as the audit these slices were
held against. Keep changes surgical: match the existing idiom, do not restyle.

The primitives referenced below all live in `src/ui` (barrel: `src/ui/index.tsx`).

## 1. Loading states — `Skeleton*`, not a bare `<Loading>`

- A surface that loads **content with a known shape** (a table, a list of cards, a definition list,
  a form, a metrics grid) renders a matching skeleton so the box model is reserved and the swap-in
  is jank-free: `SkeletonTable`, `SkeletonCards`, `SkeletonDeflist`, `SkeletonText`, or bare
  `Skeleton` bars arranged like the real layout.
- `<Loading>` (plain "A carregar…" text) is reserved for a **brief top-level boot** where there is no
  content shape yet: the app/auth-gate quiet boot and the sign-in / settings page boot. Do not use it
  in a card/panel/list body.
- Every skeleton block is `aria-hidden`; the screen reader hears the surrounding busy region's status,
  not the decorative bars. Skeletons already collapse their shimmer under `prefers-reduced-motion`.

## 2. Error states — inline **and** a toast (R7)

- A mutation error keeps its **inline** surface — an `ErrorNote` (or a `Field` `error=` with
  `role="alert"`, or a feature-specific note like `RegistryErrorNote`) — **and** additionally fires
  `toast.error(caughtValue)`. The toast is the consistency spine; it does not replace the inline copy.
  Passing the caught value straight through lets the toast unwrap an `ApiError`'s PT server message.
- Field-level validation conflicts (e.g. a 409 duplicate username, a 422 bad NIPC) surface inline
  against the field; they also toast (R7). The redundant text is intentional.
- A read (`useQuery`) error renders inline only (`ErrorNote`) — reads do not toast.
- 401 is never hand-rendered: the client clears the token and the `AuthGate` routes to sign-in (R2).

## 3. Success feedback — a toast (R6)

- A successful **mutation** fires `toast.success(t('toast.<domain>.<action>'))`. The message is already
  translated by the caller; the toast owns only its own chrome keys.
- The `ToastProvider` sits **above the router** (`app/providers.tsx`), so a success toast fired as the
  handler navigates away (entity/book/ata create, registry import) still renders. `test/utils.tsx`
  provides it too, so any mutation-component test renders with a live toast handle.
- Partition sign-in/secret/attestation-key/onboarding outcomes so each fires **once**: those are owned
  by the onboarding surfaces (`SignIn`, `CurrentUserPicker` sign-in, `UserAccessManager`,
  `OnboardingWizard`); the retrofit slices cover everything else (sign-out, users create/toggle,
  registry, CAE, law).

## 4. Empty states — `EmptyState`

- A list/collection that can be legitimately empty renders `<EmptyState title=…>` with a short body
  (and, where useful, a call to action linking to where the first item is created), not a blank area
  or a raw "nothing here" string. See Entidades, Livros, Utilizadores, the Legislação no-match state.

## 5. Mutating buttons — disabled + pending label

- Every button that triggers a mutation is `disabled={m.isPending}` (combine with any validity guard,
  e.g. `disabled={m.isPending || !isValid}`), and swaps its label to a pending form while in flight
  (`t('…creating')` / `t('common.saving')` / a "A …" gerund). This prevents double-submits and shows
  progress. A shared busy flag (`busy = a.isPending || b.isPending`) covers a surface with sibling
  mutations (the picker, the access manager).

## 6. Forms — `Field` + `role="alert"`

- Inputs are wrapped in `<Field label htmlFor hint error>`; the `error` slot renders with
  `role="alert"` so a validation message is announced. Label `htmlFor` matches the control `id`.
  Inputs that have no visible label carry an `aria-label`.

## 7. Focus / ARIA on menus, dialogs, the wizard, and toasts

- **Menus** (the `CurrentUserPicker`): trigger has `aria-haspopup="menu"` + `aria-expanded`; the popup
  is `role="menu"` with `role="menuitemradio"` + `aria-checked` items; Escape and a backdrop click
  close it; the password sub-prompt autofocuses.
- **The onboarding wizard**: a labelled `role="region"`, a `aria-live="polite"` step counter, autofocus
  on each step's first input, static motion (reduced-motion / safe-mode safe).
- **Toasts**: a persistent labelled `role="region"`; each toast is `role="status"`+`aria-live="polite"`
  (success/info) or `role="alert"`+`aria-live="assertive"` (error); the dismiss control has an
  `aria-label`; auto-dismiss pauses on hover/focus.
- Decorative glyphs are `aria-hidden`; an icon that carries meaning pairs with `sr-only` text or an
  `aria-label`/`title`.

## 8. Every user-facing string via `t()`

- No literal user-facing text in JSX (labels, headings, placeholders, `aria-label`, `title`, button
  copy). Add a key to `src/i18n/locales/pt-PT.ts` (the source union) **and all 13 other catalogs**,
  non-empty; the `i18n.test.ts` completeness matrix stays 14/14. Interpolate with `t('key', { param })`.
- The only sanctioned exceptions are the brand proper noun "Chancela" and the last-resort
  `CrashScreen` / `ErrorBoundary` fallbacks, which must render before/without the i18n store.
- Backend-authored legal/compliance messages are rendered **verbatim** as received — they are not
  catalog keys.
