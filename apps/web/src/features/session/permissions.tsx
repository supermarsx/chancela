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
 *   • a `global` grant covers ANY valid target scope;
 *   • a `tenant(T)` grant covers resources whose authoritative parent chain reaches T;
 *   • an `entity(E)` grant covers that entity and its contained books/acts/resources;
 *   • a `book(B)` grant covers that book and its contained acts/resources;
 *   • resource grants (`act`, `folder`, `template_library`, `archive`, `integration`,
 *     `repository`) cover themselves and only narrow through a resolved parent chain;
 *   • a scoped grant NEVER satisfies a `global` check (scope-escape upward is impossible).
 *
 * Fail-closed everywhere: no matching grant ⇒ false; an absent/empty permission set ⇒
 * false; used outside a provider ⇒ deny. The Owner (all permissions @ global) ⇒ every
 * check true. Parent relations are derived only from authoritative resource DTOs already in
 * the query cache; an unknown parent, malformed scope, or cycle denies the check.
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
import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import type { ActView, BookView, Entity, PermissionGrant, PermissionScope } from '../../api/types';
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

/** A permission target scope, mirroring the server's complete `ScopeView` union. */
export type CanScope = PermissionScope;

/** The whole-instance scope — the default target when a caller passes no scope. */
export const scopeGlobal: Extract<CanScope, { kind: 'global' }> = { kind: 'global' };
/** A tenant-isolation-boundary target. */
export const scopeTenant = (id: string): Extract<CanScope, { kind: 'tenant' }> => ({
  kind: 'tenant',
  id,
});
/** An entity-scoped target (covers the entity and its books). */
export const scopeEntity = (id: string): Extract<CanScope, { kind: 'entity' }> => ({
  kind: 'entity',
  id,
});
/** A single-book-scoped target. */
export const scopeBook = (id: string): Extract<CanScope, { kind: 'book' }> => ({
  kind: 'book',
  id,
});
/** A single act/minute target. */
export const scopeAct = (id: string): Extract<CanScope, { kind: 'act' }> => ({ kind: 'act', id });
/** A records-folder target. */
export const scopeFolder = (id: string): Extract<CanScope, { kind: 'folder' }> => ({
  kind: 'folder',
  id,
});
/** A shared template-library target. */
export const scopeTemplateLibrary = (
  id: string,
): Extract<CanScope, { kind: 'template_library' }> => ({ kind: 'template_library', id });
/** An archive/export-resource target. */
export const scopeArchive = (id: string): Extract<CanScope, { kind: 'archive' }> => ({
  kind: 'archive',
  id,
});
/** An integration/connector target. */
export const scopeIntegration = (id: string): Extract<CanScope, { kind: 'integration' }> => ({
  kind: 'integration',
  id,
});
/** A storage-repository target. */
export const scopeRepository = (id: string): Extract<CanScope, { kind: 'repository' }> => ({
  kind: 'repository',
  id,
});

/** The book→entity relation the `book` narrowing consults (fail-closed: unknown ⇒ none). */
export type BookEntityResolver = (bookId: string) => string | undefined;

/** One authoritative parent hop for a target scope (unknown ⇒ none/fail closed). */
export type ScopeParentResolver = (scope: CanScope) => CanScope | undefined;

const VALID_SCOPE_KINDS = new Set([
  'global',
  'tenant',
  'entity',
  'book',
  'act',
  'folder',
  'template_library',
  'archive',
  'integration',
  'repository',
]);

/** Reject malformed/unrecognised runtime DTOs before evaluating even a global grant. */
function isValidScope(scope: unknown): scope is CanScope {
  if (!scope || typeof scope !== 'object') return false;
  const candidate = scope as { kind?: unknown; id?: unknown };
  if (typeof candidate.kind !== 'string' || !VALID_SCOPE_KINDS.has(candidate.kind)) return false;
  if (candidate.kind === 'global') return !('id' in candidate);
  return typeof candidate.id === 'string' && candidate.id.trim().length > 0;
}

function scopeEquals(left: CanScope, right: CanScope): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === 'global' || right.kind === 'global') return true;
  return left.id === right.id;
}

function scopeKey(scope: CanScope): string {
  return scope.kind === 'global' ? 'global' : `${scope.kind}:${scope.id}`;
}

/**
 * Whether one effective grant covers a target scope — the client mirror of the server's
 * narrowing-only `scope_covers`. The target is walked toward its authoritative parents for
 * at most eight hops, matching the server bound. Unknown parents and cycles fail closed.
 * `bookEntity` keeps the original three-level caller API source-compatible; `parentScope`
 * supplies the additive tenant/act/resource hierarchy.
 */
export function grantCoversScope(
  grant: PermissionGrant,
  target: CanScope,
  bookEntity: BookEntityResolver,
  parentScope?: ScopeParentResolver,
): boolean {
  const g = grant.scope;
  if (!isValidScope(g) || !isValidScope(target)) return false;
  if (g.kind === 'global') return true;

  let current: CanScope | undefined = target;
  const seen = new Set<string>();
  for (let hop = 0; hop < 8 && current; hop += 1) {
    if (scopeEquals(g, current)) return true;
    const key = scopeKey(current);
    if (seen.has(key)) return false;
    seen.add(key);

    const resolved: CanScope | undefined = parentScope?.(current);
    if (resolved !== undefined) {
      if (!isValidScope(resolved)) return false;
      current = resolved;
      continue;
    }

    // Source-compatible fallback for the original Entity → Book relation.
    if (current.kind === 'book') {
      const owner = bookEntity(current.id);
      current = owner ? scopeEntity(owner) : undefined;
    } else {
      current = undefined;
    }
  }
  return false;
}

/**
 * Resolve one authoritative parent hop from live query-cache DTOs. Only relations explicitly
 * carried by Entity, Book, and Act responses are inferred; unsupported leaf resources return
 * undefined until their own DTO/query contract exposes a parent.
 */
export function cachedScopeParent(qc: QueryClient, scope: CanScope): CanScope | undefined {
  if (scope.kind === 'entity') {
    const single = qc.getQueryData<Entity>(keys.entity(scope.id));
    if (single?.tenant_id) return scopeTenant(single.tenant_id);
    const cached = qc.getQueriesData<unknown>({ queryKey: keys.entities });
    for (const [, value] of cached) {
      const found = Array.isArray(value)
        ? (value as Entity[]).find((entity) => entity?.id === scope.id)
        : undefined;
      if (found?.tenant_id) return scopeTenant(found.tenant_id);
    }
    return undefined;
  }

  if (scope.kind === 'book') {
    const single = qc.getQueryData<BookView>(keys.book(scope.id));
    if (single?.entity_id) return scopeEntity(single.entity_id);
    const cached = qc.getQueriesData<unknown>({ queryKey: ['books'] });
    for (const [, value] of cached) {
      const found = Array.isArray(value)
        ? (value as BookView[]).find((book) => book?.id === scope.id)
        : undefined;
      if (found?.entity_id) return scopeEntity(found.entity_id);
    }
    return undefined;
  }

  if (scope.kind === 'act') {
    const single = qc.getQueryData<ActView>(keys.act(scope.id));
    if (single?.book_id) return scopeBook(single.book_id);
    const cached = qc.getQueriesData<unknown>({ queryKey: ['books'] });
    for (const [, value] of cached) {
      const found = Array.isArray(value)
        ? (value as ActView[]).find((act) => act?.id === scope.id && act?.book_id)
        : undefined;
      if (found?.book_id) return scopeBook(found.book_id);
    }
  }

  return undefined;
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

  // Resolve only relations proven by cached API DTOs. Unknown resources and unsupported leaf
  // parents deliberately return undefined: a wider grant must never be guessed from an id.
  const parentScope = useCallback<ScopeParentResolver>(
    (scope) => cachedScopeParent(qc, scope),
    [qc],
  );

  /** Source-compatible book→entity adapter for callers of the original three-scope API. */
  const bookEntity = useCallback<BookEntityResolver>(
    (bookId) => {
      const parent = parentScope(scopeBook(bookId));
      return parent?.kind === 'entity' ? parent.id : undefined;
    },
    [parentScope],
  );

  const value = useMemo<PermissionsContextValue>(() => {
    const can = (permission: string, scope: CanScope = scopeGlobal) =>
      grants.some(
        (gr) =>
          gr.permission === permission && grantCoversScope(gr, scope, bookEntity, parentScope),
      );
    const canAny = (permission: string) => grants.some((gr) => gr.permission === permission);
    return { can, canAny, grants, ready };
  }, [grants, ready, bookEntity, parentScope]);

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
