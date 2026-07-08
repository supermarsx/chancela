/**
 * TanStack Query hooks over the typed `api` client (plan t5 §2).
 *
 * Query keys are structured so mutations can invalidate precisely: creating an
 * entity refetches the entity list; opening/closing a book refetches the book, its
 * entity's book list and the dashboard; every act mutation refetches that act, its
 * compliance and the dashboard; sealing additionally refetches the ledger. The
 * compliance-gated seal (§2.5) therefore keeps the CompliancePanel and dashboard
 * counts live without manual wiring.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import type {
  CaeRevision,
  CloseBookBody,
  CreateEntityBody,
  CreateUserBody,
  DraftActBody,
  ImportFromRegistryBody,
  LawEntryView,
  OpenBookBody,
  RegistryImportBody,
  SealActBody,
  Settings,
  SetSecretBody,
  RemoveSecretBody,
  AttestationKeyBody,
  UpdateActBody,
  UpdateEntityBody,
  UpdateUserBody,
  ActState,
} from './types';
import { api } from './client';
import { clearSessionToken, onSessionCleared, setSessionToken } from './session';

export const keys = {
  entities: ['entities'] as const,
  entity: (id: string) => ['entities', id] as const,
  entityRegistry: (id: string) => ['entities', id, 'registry'] as const,
  books: (entityId?: string) => ['books', { entityId: entityId ?? null }] as const,
  book: (id: string) => ['books', id] as const,
  bookActs: (id: string) => ['books', id, 'acts'] as const,
  act: (id: string) => ['acts', id] as const,
  compliance: (id: string) => ['acts', id, 'compliance'] as const,
  ledger: (params: { scope?: string; limit?: number }) => ['ledger', params] as const,
  ledgerVerify: ['ledger', 'verify'] as const,
  dashboard: ['dashboard'] as const,
  settings: ['settings'] as const,
  health: ['health'] as const,
  caeCatalog: ['cae', 'catalog'] as const,
  caeSearch: (search: string, revision?: CaeRevision) =>
    ['cae', 'search', search, revision] as const,
  caeEntry: (code: string, revision?: CaeRevision) => ['cae', 'entry', code, revision] as const,
  caeChildren: (code: string, revision: CaeRevision) =>
    ['cae', 'children', code, revision] as const,
  lawManifest: ['law', 'manifest'] as const,
  users: ['users'] as const,
  user: (id: string) => ['users', id] as const,
  session: ['session'] as const,
  roster: ['session', 'roster'] as const,
};

// --- Entities -------------------------------------------------------------------

export function useEntities() {
  return useQuery({ queryKey: keys.entities, queryFn: () => api.listEntities() });
}

export function useEntity(id: string) {
  return useQuery({ queryKey: keys.entity(id), queryFn: () => api.getEntity(id), enabled: !!id });
}

export function useCreateEntity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateEntityBody) => api.createEntity(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.entities });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

/**
 * Set/clear an entity's statute overlay (`PATCH /v1/entities/{id}`, ENT-03/t31). On
 * success the entity refetches (so the profile/statute panels reflect the change) and
 * the ledger refetches (the PATCH appends an `entity.statute_updated` event).
 */
export function useUpdateEntity(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdateEntityBody) => api.updateEntity(id, body),
    onSuccess: (entity) => {
      qc.setQueryData(keys.entity(id), entity);
      void qc.invalidateQueries({ queryKey: keys.entity(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

// --- Registry — certidão permanente (plan t11) ----------------------------------

/**
 * The stored registry extract for an entity (`GET /v1/entities/{id}/registry`). The
 * server returns `404` until something has been imported; we treat that as "no
 * extract" (the panel shows an empty state) rather than an error, and never retry it.
 * The response carries only the MASKED access code — the full código de acesso is
 * never cached here.
 */
export function useEntityRegistry(id: string) {
  return useQuery({
    queryKey: keys.entityRegistry(id),
    queryFn: () => api.getEntityRegistry(id),
    enabled: !!id,
    retry: false,
  });
}

/**
 * Create a new entity from a certidão (`POST /v1/entities/import-from-registry`). The
 * `code` lives only in the mutation variables for the duration of the request; on
 * success the entity list + dashboard refetch and the caller navigates to the new
 * entity.
 */
export function useImportFromRegistry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ImportFromRegistryBody) => api.importFromRegistry(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.entities });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

/**
 * Enrich an existing entity from a certidão (`POST /v1/entities/{id}/registry/import`).
 * Refetches the entity, its stored extract and the ledger (an import appends a
 * `registry.imported` event). The `code` is only ever a transient mutation variable.
 */
export function useImportEntityRegistry(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RegistryImportBody) => api.importEntityRegistry(id, body),
    onSuccess: (report) => {
      qc.setQueryData(keys.entity(id), report.entity);
      qc.setQueryData(keys.entityRegistry(id), report.extract);
      void qc.invalidateQueries({ queryKey: keys.entity(id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

// --- Books ----------------------------------------------------------------------

export function useBooks(entityId?: string) {
  return useQuery({ queryKey: keys.books(entityId), queryFn: () => api.listBooks(entityId) });
}

export function useBook(id: string) {
  return useQuery({ queryKey: keys.book(id), queryFn: () => api.getBook(id), enabled: !!id });
}

export function useBookActs(id: string) {
  return useQuery({
    queryKey: keys.bookActs(id),
    queryFn: () => api.listBookActs(id),
    enabled: !!id,
  });
}

export function useOpenBook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: OpenBookBody) => api.openBook(body),
    onSuccess: (book) => {
      void qc.invalidateQueries({ queryKey: ['books'] });
      void qc.invalidateQueries({ queryKey: keys.entity(book.entity_id) });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useCloseBook(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CloseBookBody) => api.closeBook(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['books'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

// --- Acts -----------------------------------------------------------------------

export function useAct(id: string) {
  return useQuery({ queryKey: keys.act(id), queryFn: () => api.getAct(id), enabled: !!id });
}

export function useCompliance(id: string) {
  return useQuery({
    queryKey: keys.compliance(id),
    queryFn: () => api.getCompliance(id),
    enabled: !!id,
  });
}

export function useDraftAct() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: DraftActBody) => api.draftAct(body),
    onSuccess: (act) => {
      void qc.invalidateQueries({ queryKey: keys.bookActs(act.book_id) });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useUpdateAct(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdateActBody) => api.updateAct(id, body),
    onSuccess: (act) => {
      qc.setQueryData(keys.act(id), act);
      void qc.invalidateQueries({ queryKey: keys.compliance(id) });
    },
  });
}

export function useAdvanceAct(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (to: ActState) => api.advanceAct(id, { to }),
    onSuccess: (act) => {
      qc.setQueryData(keys.act(id), act);
      void qc.invalidateQueries({ queryKey: keys.compliance(id) });
      void qc.invalidateQueries({ queryKey: keys.bookActs(act.book_id) });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useSealAct(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SealActBody) => api.sealAct(id, body),
    onSuccess: (result) => {
      qc.setQueryData(keys.act(id), result.act);
      void qc.invalidateQueries({ queryKey: keys.compliance(id) });
      void qc.invalidateQueries({ queryKey: keys.bookActs(result.act.book_id) });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useArchiveAct(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.archiveAct(id),
    onSuccess: (act) => {
      qc.setQueryData(keys.act(id), act);
      void qc.invalidateQueries({ queryKey: keys.bookActs(act.book_id) });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

// --- Ledger / Dashboard ---------------------------------------------------------

export function useLedger(params: { scope?: string; limit?: number } = {}) {
  return useQuery({ queryKey: keys.ledger(params), queryFn: () => api.listLedger(params) });
}

export function useLedgerVerify() {
  return useQuery({ queryKey: keys.ledgerVerify, queryFn: () => api.verifyLedger() });
}

export function useDashboard() {
  return useQuery({ queryKey: keys.dashboard, queryFn: () => api.dashboard() });
}

// --- CAE catalog + lookup (plan t14) --------------------------------------------

/**
 * The active CAE catalog metadata (`GET /v1/cae` without `search`): origin
 * (Embedded/Cache), generation stamp and per-revision node counts. Kept fresh for a
 * minute; a successful refresh invalidates it.
 */
export function useCaeCatalog() {
  return useQuery({
    queryKey: keys.caeCatalog,
    queryFn: () => api.getCaeCatalog(),
    staleTime: 60_000,
  });
}

/**
 * Search-as-you-type over the CAE catalog (`GET /v1/cae?search=`). Disabled for a
 * blank term (the server treats blank as "no search" and would return metadata, not an
 * array), and the previous results are kept visible while the next term loads.
 */
export function useCaeSearch(search: string, revision?: CaeRevision) {
  const term = search.trim();
  return useQuery({
    queryKey: keys.caeSearch(term, revision),
    queryFn: () => api.searchCae(term, { revision }),
    enabled: term.length > 0,
    placeholderData: (prev) => prev,
  });
}

/**
 * Resolve a single código (`GET /v1/cae/{code}?revision=`) to its designation, level,
 * revision and ancestor `hierarchy` (secção → … → self). Disabled for a blank code; a
 * `404` (unknown code) surfaces as an error the caller renders as "not found". Kept
 * fresh for a minute — a code's meaning only changes on a catalog refresh.
 */
export function useCae(code: string, revision?: CaeRevision) {
  const trimmed = code.trim();
  return useQuery({
    queryKey: keys.caeEntry(trimmed, revision),
    queryFn: () => api.getCae(trimmed, revision),
    enabled: trimmed.length > 0,
    staleTime: 60_000,
    retry: false,
  });
}

/** The largest child-search page the tree drill-down requests (the server caps at 500). */
export const CAE_CHILD_SEARCH_LIMIT = 500;

/**
 * Fetch the candidate pool for a node's direct children by searching its código
 * (`GET /v1/cae?search=<code>&revision=`), which the caller filters down to the exact
 * one-level-deeper prefix children. This backs the tree's downward drill for the
 * numeric levels (divisão→grupo→classe→subclasse), where children share the parent's
 * code prefix. Enumerating a secção's divisões (whose parent is a letter, not a code
 * prefix) is NOT prefix-derivable and needs a backend children endpoint — see the
 * explorer note; this hook is only enabled for the numeric levels.
 */
export function useCaeChildren(code: string, revision: CaeRevision, enabled: boolean) {
  const trimmed = code.trim();
  return useQuery({
    queryKey: keys.caeChildren(trimmed, revision),
    queryFn: () => api.searchCae(trimmed, { revision, limit: CAE_CHILD_SEARCH_LIMIT }),
    enabled: enabled && trimmed.length > 0,
    staleTime: 60_000,
    placeholderData: (prev) => prev,
  });
}

/**
 * Force a catalog refresh (`POST /v1/cae/refresh`). On a real update the catalog
 * metadata is invalidated so the counts/origin refresh; a same/older dataset is a
 * no-op (`updated:false`) and the page surfaces that distinctly.
 */
export function useRefreshCae() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.refreshCae(),
    onSuccess: (result) => {
      if (result.updated) {
        qc.setQueryData(keys.caeCatalog, result.metadata);
        void qc.invalidateQueries({ queryKey: ['cae'] });
        void qc.invalidateQueries({ queryKey: ['ledger'] });
      }
    },
  });
}

// --- Law archive (t27) — the local "mini law archive" ---------------------------

/**
 * The resolved state of the local law archive: either the feature is unavailable (the
 * running server predates t27) or it is available with a per-diploma-id lookup of the
 * manifest entries.
 */
export type LawArchiveState =
  { available: false } | { available: true; entries: Map<string, LawEntryView> };

/**
 * Load + normalize the `/v1/law` manifest into a {@link LawArchiveState}. A 404, a
 * non-JSON reply (an old server SPA-falls-back unknown routes to `index.html`), or any
 * transport error is swallowed to `{ available: false }` so the Legislação shelf degrades
 * gracefully to links-only rather than surfacing an error for an optional feature.
 */
async function loadLawArchive(): Promise<LawArchiveState> {
  try {
    const raw = await api.getLawManifest();
    const list = Array.isArray(raw) ? raw : (raw?.entries ?? []);
    return { available: true, entries: new Map(list.map((e) => [e.id, e])) };
  } catch {
    return { available: false };
  }
}

/** Feature-detected law-archive manifest; never errors (absent → `{ available:false }`). */
export function useLawArchive() {
  return useQuery({ queryKey: keys.lawManifest, queryFn: loadLawArchive, staleTime: 60_000 });
}

/**
 * Download + store a diploma's official PDF (`POST /v1/law/{id}/fetch`). On success the
 * manifest is invalidated so the card flips to its "stored" state (badge + local "Abrir
 * PDF").
 */
export function useFetchLawPdf() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.fetchLawPdf(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.lawManifest });
    },
  });
}

// --- Users + session (plan t14) -------------------------------------------------

export function useUsers() {
  return useQuery({ queryKey: keys.users, queryFn: () => api.listUsers() });
}

/**
 * A single user by id (`GET /v1/users/{id}`, t50 W2) — the edit screen's cold-deep-link
 * fallback: when a `/utilizadores/:id` URL is opened directly the list cache may be empty,
 * so the autonomous edit page resolves the user through this read. Sharing the `['users',
 * id]` key means a mutation that invalidates `keys.users` (create/toggle/secret/key) also
 * refetches an open detail view.
 */
export function useUser(id: string) {
  return useQuery({ queryKey: keys.user(id), queryFn: () => api.getUser(id), enabled: !!id });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateUserBody) => api.createUser(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      // The unauth roster gates onboarding-vs-sign-in; creating a user (the first-run
      // bootstrap especially) flips `onboarding_required`, so the guard must refetch it.
      void qc.invalidateQueries({ queryKey: keys.roster });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Set / change a user's sign-in secret (`POST /v1/users/{id}/secret`, t29). Changing an
 * existing secret requires `current_password` (verified server-side; 401 on mismatch)
 * and re-wraps any attestation key under the new secret. The updated `UserView`
 * (`has_secret:true`) primes the caches the sign-in roster and management panel read.
 */
export function useSetUserSecret(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SetSecretBody) => api.setUserSecret(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: keys.roster });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Remove a user's sign-in secret (`DELETE /v1/users/{id}/secret`, t29). Cascades: the
 * attestation key is destroyed with the secret (its KEK is gone). Requires the current
 * password when one is set (401 on mismatch).
 */
export function useRemoveUserSecret(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RemoveSecretBody) => api.removeUserSecret(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: keys.roster });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * Generate / rotate a user's PKI audit-attestation key (`POST /v1/users/{id}/attestation-key`,
 * t29). Requires a sign-in secret first (409 if none) and the current password (401 on
 * mismatch). Rotating replaces the key; prior attestations still verify (each carries its
 * own fingerprint).
 */
export function useCreateAttestationKey(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AttestationKeyBody) => api.createAttestationKey(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/** Remove a user's attestation key (`DELETE /v1/users/{id}/attestation-key`, t29). */
export function useRemoveAttestationKey(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AttestationKeyBody) => api.removeAttestationKey(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

export function useUpdateUser(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdateUserBody) => api.updateUser(id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: keys.session });
      void qc.invalidateQueries({ queryKey: ['ledger'] });
    },
  });
}

/**
 * The current session (`GET /v1/session`), read from the in-memory token. On a fresh
 * page load the token is gone (it is never persisted — see `./session`), so this
 * resolves to `{ user: null }` until a user is picked; that is the intended v1
 * behaviour. The picker keys its display off this query.
 *
 * This hook is always mounted at the app shell (via `CurrentUserPicker` in `layout`),
 * so it is the natural place to register the 401-clear listener: when the API client
 * drops a stale token on a 401, the session query is invalidated and refetches with
 * no token → `{ user: null }`, so the UI reflects the signed-out state immediately
 * instead of showing a stale signed-in user.
 */
export function useSession() {
  const qc = useQueryClient();
  useEffect(() => {
    return onSessionCleared(() => {
      qc.setQueryData(keys.session, { user: null });
      void qc.invalidateQueries({ queryKey: keys.session });
    });
  }, [qc]);
  return useQuery({ queryKey: keys.session, queryFn: () => api.getSession() });
}

/**
 * The UNAUTHENTICATED sign-in roster (`GET /v1/session/roster`, t45-e1). Readable while
 * signed out (no session header, never 401s), so the auth guard and the sign-in surface
 * use it — NOT the auth-gated `GET /v1/users`, which 401s signed-out (the chicken-and-egg
 * lockout the t43 audit flagged). Kept fresh briefly; `useCreateUser`/`useSetUserSecret`
 * invalidate it when the roster changes.
 */
export function useSessionRoster() {
  return useQuery({
    queryKey: keys.roster,
    queryFn: () => api.getSessionRoster(),
    staleTime: 15_000,
    retry: false,
  });
}

/** Arguments for {@link useCreateSession}: the user to sign in as and, for a
 *  password-protected user (`has_secret`), their sign-in secret. */
export interface SignInArgs {
  userId: string;
  password?: string;
}

/**
 * Sign in as a user (`POST /v1/session`, t29). The issued token is stored in memory so
 * every subsequent request carries it; the session query is primed with the returned
 * user so the shell updates immediately. A password is sent only for `has_secret` users;
 * a wrong/missing password is a **401** and too many attempts a **429** (backoff) — the
 * caller surfaces those distinctly.
 */
export function useCreateSession() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, password }: SignInArgs) =>
      api.createSession({ user_id: userId, password }),
    onSuccess: (result) => {
      setSessionToken(result.token);
      qc.setQueryData(keys.session, { user: result.user });
      void qc.invalidateQueries({ queryKey: keys.session });
      // Now signed in, the auth-gated user list becomes readable — refetch it so the
      // management page / picker have the full UserView set.
      void qc.invalidateQueries({ queryKey: keys.users });
    },
  });
}

/** Sign out (`DELETE /v1/session`); drops the token and clears the session query. */
export function useDeleteSession() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.deleteSession(),
    onSuccess: () => {
      clearSessionToken();
      qc.setQueryData(keys.session, { user: null });
      void qc.invalidateQueries({ queryKey: keys.session });
    },
  });
}

// --- Settings / Health ----------------------------------------------------------

/**
 * The application settings document (§2.8), loaded once at app start and shared by
 * every consumer (the appearance layer, the Configurações page, the actor/numbering
 * pre-fills). Settings rarely change, so the cache is kept fresh for a minute.
 */
export function useSettings() {
  return useQuery({
    queryKey: keys.settings,
    queryFn: () => api.getSettings(),
    staleTime: 60_000,
  });
}

/**
 * Persist the whole settings document. Optimistic: the cache is updated with the
 * outgoing document immediately (so the live appearance layer reacts without waiting
 * for the round-trip), rolled back on error, and reconciled with the server's echoed
 * document (which stamps `schema_version`) on settle.
 */
export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Settings) => api.putSettings(body),
    onMutate: async (next) => {
      await qc.cancelQueries({ queryKey: keys.settings });
      const previous = qc.getQueryData<Settings>(keys.settings);
      qc.setQueryData(keys.settings, next);
      return { previous };
    },
    onError: (_err, _next, context) => {
      if (context?.previous) qc.setQueryData(keys.settings, context.previous);
    },
    onSuccess: (stored) => {
      qc.setQueryData(keys.settings, stored);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.settings });
    },
  });
}

/** Liveness + running server version, for the Configurações “Sobre” section. */
export function useHealth() {
  return useQuery({ queryKey: keys.health, queryFn: () => api.health(), staleTime: 60_000 });
}
