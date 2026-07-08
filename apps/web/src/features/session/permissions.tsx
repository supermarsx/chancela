/**
 * The web permissions context (t64-E5) — a client-side `can(permission, scope)` derived
 * from the signed-in principal's effective grants, applied across the UI as
 * disable-with-explanation.
 *
 * The server is the REAL authorization gate (every sensitive endpoint is
 * `require_permission`-gated, t64-E3); THIS layer is UX only — it mirrors the backend
 * narrowing honestly so the UI can disable (never silently hide) the actions a user lacks
 * permission for, with an honest tooltip, instead of letting them click into a 403.
 *
 * Scope narrowing (mirrors `chancela-authz::scope_covers`, plan §2.4, t64-E1/E3):
 *   • a `global` grant covers ANY target scope;
 *   • an `entity(E)` grant covers `entity(E)` AND any `book` owned by E;
 *   • a `book(B)` grant covers `book(B)` only;
 *   • a scoped grant NEVER satisfies a `global` check (scope-escape upward is impossible).
 *
 * Fail-closed everywhere: no matching grant ⇒ false; an absent/empty permission set ⇒
 * false; used outside a provider ⇒ deny. The Owner (all permissions @ global) ⇒ every
 * check true. The book→entity relation the `book` narrowing needs is derived pragmatically
 * from whatever books are already in the query cache (the same books the UI has loaded).
 *
 * FROZEN API for t64-E6 (role/delegation management UI) and t62 (admin UI): they reuse
 * `useCan`/`usePermissions`, the `CanScope` shape, the `scope*` builders, the `Gate*`
 * controls, and the 403 helpers from here.
 */
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  type ButtonHTMLAttributes,
  type ReactNode,
} from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { BookView, PermissionGrant } from '../../api/types';
import { ApiError } from '../../api/client';
import { keys, useSession } from '../../api/hooks';
import { useT } from '../../i18n';
import {
  Button,
  ButtonLink,
  IconButton,
  InlineWarning,
  Tooltip,
  type TooltipPlacement,
} from '../../ui';

// --- Scope model ----------------------------------------------------------------

/** A permission target scope, mirroring the server's `ScopeView`/`PermissionScope`. */
export type CanScope =
  { kind: 'global' } | { kind: 'entity'; id: string } | { kind: 'book'; id: string };

/** The whole-instance scope — the default target when a caller passes no scope. */
export const scopeGlobal: CanScope = { kind: 'global' };
/** An entity-scoped target (covers the entity and its books). */
export const scopeEntity = (id: string): CanScope => ({ kind: 'entity', id });
/** A single-book-scoped target. */
export const scopeBook = (id: string): CanScope => ({ kind: 'book', id });

/** The book→entity relation the `book` narrowing consults (fail-closed: unknown ⇒ none). */
export type BookEntityResolver = (bookId: string) => string | undefined;

/**
 * Whether one effective grant covers a target scope — the client mirror of the server's
 * narrowing-only `scope_covers`. A `global` grant covers everything; an `entity` grant
 * covers that entity and its books; a `book` grant covers only itself; and a scoped grant
 * can never satisfy a `global` check (upward scope-escape is structurally impossible).
 */
export function grantCoversScope(
  grant: PermissionGrant,
  target: CanScope,
  bookEntity: BookEntityResolver,
): boolean {
  const g = grant.scope;
  if (g.kind === 'global') return true;
  // A scoped grant never satisfies a Global target.
  if (target.kind === 'global') return false;
  if (g.kind === 'entity') {
    if (target.kind === 'entity') return g.id === target.id;
    // book target: covered iff the book belongs to the granted entity.
    const owner = bookEntity(target.id);
    return owner !== undefined && owner === g.id;
  }
  // g.kind === 'book' — covers only the exact book.
  return target.kind === 'book' && g.id === target.id;
}

// --- Context --------------------------------------------------------------------

export interface PermissionsContextValue {
  /**
   * Whether the current principal effectively holds `permission` at `scope` (default
   * `global`). Mirrors the server's `has_permission`; fail-closed.
   */
  can: (permission: string, scope?: CanScope) => boolean;
  /**
   * Whether the principal holds `permission` at ANY scope — for list-level "create"
   * affordances where the concrete target scope is only chosen later in a form (e.g.
   * "Abrir livro" before the entity is picked). The server re-checks the real scope.
   */
  canAny: (permission: string) => boolean;
  /** The raw effective grant set (role ∪ delegation), for advanced consumers (E6/t62). */
  grants: PermissionGrant[];
  /** True once the session query has resolved (so a gate isn't decided mid-load). */
  ready: boolean;
}

/** Fail-closed default: deny everything when used outside a {@link PermissionsProvider}. */
const FAIL_CLOSED: PermissionsContextValue = {
  can: () => false,
  canAny: () => false,
  grants: [],
  ready: false,
};

const PermissionsContext = createContext<PermissionsContextValue | null>(null);

/**
 * Feeds the permissions context from the current session's embedded `permissions`
 * (`SessionView.permissions`, refreshed with the `['session']` query, t64-E3). Mounted
 * once in `app/providers` inside the QueryClient so `useCan` works app-wide.
 */
export function PermissionsProvider({ children }: { children: ReactNode }) {
  const session = useSession();
  const qc = useQueryClient();
  const grants = session.data?.permissions ?? EMPTY_GRANTS;
  const ready = !session.isLoading;

  // Resolve a book's owning entity from whatever book reads are cached (single-book or any
  // list). Fail-closed: an unknown book ⇒ undefined ⇒ an entity grant does not cover it.
  const bookEntity = useCallback<BookEntityResolver>(
    (bookId) => {
      const single = qc.getQueryData<BookView>(keys.book(bookId));
      if (single?.entity_id) return single.entity_id;
      const lists = qc.getQueriesData<BookView[]>({ queryKey: ['books'] });
      for (const [, list] of lists) {
        const found = Array.isArray(list) ? list.find((b) => b?.id === bookId) : undefined;
        if (found) return found.entity_id;
      }
      return undefined;
    },
    [qc],
  );

  const value = useMemo<PermissionsContextValue>(() => {
    const can = (permission: string, scope: CanScope = scopeGlobal) =>
      grants.some((gr) => gr.permission === permission && grantCoversScope(gr, scope, bookEntity));
    const canAny = (permission: string) => grants.some((gr) => gr.permission === permission);
    return { can, canAny, grants, ready };
  }, [grants, ready, bookEntity]);

  return <PermissionsContext.Provider value={value}>{children}</PermissionsContext.Provider>;
}

/** Stable empty grant list so an unauthenticated session keeps a stable identity. */
const EMPTY_GRANTS: PermissionGrant[] = [];

/**
 * A fixed-value provider — the seam tests (and E6/t62 stories) use it to inject an
 * explicit `can`/`canAny` without a live session. Also the app's own standard test
 * context (allow-all) is built from this.
 */
export function StaticPermissionsProvider({
  value,
  children,
}: {
  value: PermissionsContextValue;
  children: ReactNode;
}) {
  return <PermissionsContext.Provider value={value}>{children}</PermissionsContext.Provider>;
}

/** An allow-all context value (an Owner). The default test context uses this. */
export const ALLOW_ALL_PERMISSIONS: PermissionsContextValue = {
  can: () => true,
  canAny: () => true,
  grants: [],
  ready: true,
};

/** Build a static context value from an explicit `can` predicate (for scoped tests). */
export function permissionsValue(
  can: (permission: string, scope?: CanScope) => boolean,
): PermissionsContextValue {
  return { can, canAny: (p) => can(p), grants: [], ready: true };
}

/** The full permissions context (E6/t62 read `grants`/`ready` here). Fail-closed. */
export function usePermissions(): PermissionsContextValue {
  return useContext(PermissionsContext) ?? FAIL_CLOSED;
}

/** The scope-aware `can(permission, scope?)` predicate. */
export function useCan(): PermissionsContextValue['can'] {
  return usePermissions().can;
}

// --- 403 helpers ----------------------------------------------------------------

/** Whether an error is a server permission denial (403 — distinct from a 401 session). */
export function isPermissionError(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403;
}

/**
 * An honest inline "sem permissão" note for a 403. Rendered instead of a raw error so a
 * permission denial reads as a permission denial, not a technical failure. (401 is handled
 * separately — the client clears the stale token and the AuthGate routes to sign-in.)
 */
export function PermissionDeniedNote() {
  const t = useT();
  return (
    <InlineWarning tone="error" title={t('perm.denied.title')}>
      {t('perm.denied.body')}
    </InlineWarning>
  );
}

// --- Disable-with-explanation controls ------------------------------------------
//
// The consistent gating primitives (plan Flag-D): an action the current user lacks
// permission for renders DISABLED with an honest tooltip via the W1 Tooltip/IconButton,
// never silently hidden. A blocked control keeps a real (focusable, hoverable) button so
// the tooltip is reachable by hover AND keyboard; `aria-disabled` + a swallowed click make
// it inert, and `.btn[aria-disabled='true']` styles it like a native disabled button.

type ButtonVariant = 'primary' | 'secondary' | 'ghost';

interface GateProps {
  /** The dotted permission id required, e.g. `"act.seal"`. */
  perm: string;
  /** The target scope; defaults to `global`. */
  scope?: CanScope;
  /**
   * Gate on holding `perm` at ANY scope rather than the concrete `scope` — for list-level
   * "create" affordances whose real target scope is only chosen later in a form (e.g.
   * "Abrir livro" before the entity is picked). The server re-checks the real scope.
   */
  anyScope?: boolean;
  /** Override the disabled tooltip (defaults to the honest "Sem permissão para esta ação"). */
  reason?: string;
  placement?: TooltipPlacement;
}

function useGateReason(reason?: string): string {
  const t = useT();
  return reason ?? t('perm.denied.action');
}

/** Resolve whether a gated affordance is allowed (scoped, or at any scope). */
function useGateAllowed(perm: string, scope?: CanScope, anyScope?: boolean): boolean {
  const { can, canAny } = usePermissions();
  return anyScope ? canAny(perm) : can(perm, scope);
}

/** A no-op that fully inerts a blocked control's activation. */
function swallow(event: { preventDefault: () => void; stopPropagation: () => void }) {
  event.preventDefault();
  event.stopPropagation();
}

type GateButtonProps = ButtonHTMLAttributes<HTMLButtonElement> &
  GateProps & { variant?: ButtonVariant; icon?: ReactNode };

/**
 * A {@link Button} gated by `useCan(perm, scope)`. Allowed → a normal Button; blocked → the
 * same button rendered disabled-with-explanation (honest tooltip, inert). Drop-in for the
 * existing `<Button>` action controls.
 */
export function GateButton({
  perm,
  scope,
  anyScope,
  reason,
  placement,
  ...props
}: GateButtonProps) {
  const allowed = useGateAllowed(perm, scope, anyScope);
  const label = useGateReason(reason);
  if (allowed) return <Button {...props} />;
  // Blocked: spread first, then override `onClick` with the inert swallow (later wins).
  return (
    <Tooltip label={label} placement={placement}>
      <Button {...props} aria-disabled="true" data-gated="true" onClick={swallow} />
    </Tooltip>
  );
}

type GateButtonLinkProps = GateProps & {
  to: string;
  variant?: ButtonVariant;
  icon?: ReactNode;
  className?: string;
  children: ReactNode;
};

/**
 * A {@link ButtonLink} gated by `useCan`. Allowed → a navigating link; blocked → an inert,
 * disabled-styled button with the honest tooltip (you cannot navigate to an action you may
 * not perform).
 */
export function GateButtonLink({
  perm,
  scope,
  anyScope,
  reason,
  placement,
  to,
  variant = 'secondary',
  icon,
  className,
  children,
}: GateButtonLinkProps) {
  const allowed = useGateAllowed(perm, scope, anyScope);
  const label = useGateReason(reason);
  if (allowed) {
    return (
      <ButtonLink to={to} variant={variant} icon={icon} className={className}>
        {children}
      </ButtonLink>
    );
  }
  return (
    <Tooltip label={label} placement={placement}>
      <button
        type="button"
        className={`btn btn--${variant}${icon ? ' btn--icon' : ''} ${className ?? ''}`.trim()}
        aria-disabled="true"
        data-gated="true"
        onClick={swallow}
      >
        {icon ? <span className="btn__icon">{icon}</span> : null}
        {children}
      </button>
    </Tooltip>
  );
}

type GateIconButtonProps = ButtonHTMLAttributes<HTMLButtonElement> &
  GateProps & { icon: ReactNode; label: string; variant?: ButtonVariant };

/**
 * An {@link IconButton} gated by `useCan`. Allowed → the normal icon action (its tooltip is
 * the action name); blocked → an inert icon button whose tooltip explains the missing
 * permission, keeping the action name as the accessible label.
 */
export function GateIconButton({
  perm,
  scope,
  anyScope,
  reason,
  placement,
  icon,
  label,
  variant = 'ghost',
  ...props
}: GateIconButtonProps) {
  const allowed = useGateAllowed(perm, scope, anyScope);
  const blockedReason = useGateReason(reason);
  if (allowed) {
    return (
      <IconButton icon={icon} label={label} variant={variant} placement={placement} {...props} />
    );
  }
  return (
    <Tooltip label={blockedReason} placement={placement}>
      <button
        type="button"
        className={`btn btn--${variant} btn--icon btn--iconOnly`}
        aria-label={label}
        {...props}
        aria-disabled="true"
        data-gated="true"
        onClick={swallow}
      >
        <span className="btn__icon">{icon}</span>
      </button>
    </Tooltip>
  );
}
