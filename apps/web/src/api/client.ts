/**
 * Typed `fetch` wrappers for the Chancela API (plan t5 §2).
 *
 * Every path is relative (`/v1/...`, `/health`) so the same client works in three
 * origins unchanged: the Vite dev proxy (:5173 → :8080), the production server that
 * serves the built SPA same-origin, and the Tauri desktop WebView pointed at the
 * embedded loopback server. Errors are surfaced as `ApiError`, which carries the
 * HTTP status plus the optional `issues`/`warnings` arrays some endpoints add to the
 * base `{ "error": "..." }` body (compliance/seal per §2.5).
 */
import type {
  ActView,
  AdvanceActBody,
  CaeCatalogView,
  CaeEntryView,
  CaeNode,
  CaeRefreshResult,
  CaeRevision,
  CaeUpdates,
  CloseBookBody,
  ComplianceIssue,
  ComplianceReport,
  CreateEntityBody,
  CreateSessionBody,
  CreateUserBody,
  Dashboard,
  DocumentBundle,
  DocumentModel,
  DraftActBody,
  Entity,
  EntityFamily,
  LifecycleStage,
  TemplateSummary,
  ImportFromRegistryBody,
  LawEntryView,
  LedgerEventView,
  LedgerVerify,
  OpenBookBody,
  RegistryExtractView,
  RegistryImportBody,
  RegistryImportReport,
  RegistryLookupBody,
  SealActBody,
  SealResult,
  SignatureStatusView,
  CmdInitiateBody,
  CmdInitiateResult,
  CmdConfirmBody,
  CmdConfirmResult,
  UpdateEntityBody,
  SessionResult,
  SessionRoster,
  SessionView,
  SetSecretBody,
  RemoveSecretBody,
  AttestationKeyBody,
  IssueRecoveryBody,
  RecoveryIssued,
  Settings,
  UpdateActBody,
  UpdateUserBody,
  UserView,
  RoleView,
  PermissionCatalogView,
  CreateRoleBody,
  PatchRoleBody,
  RoleAssignmentInput,
  RoleAssignmentView,
  SessionPermissions,
  DelegationView,
  GrantDelegationBody,
  BookView,
  HealthResponse,
  IntegrityReportView,
  ReanchorBody,
  ReanchorResult,
  RestoreBody,
  RestoreOutcomeView,
  ImportOutcomeView,
  CollisionPolicy,
  StartOverBookBody,
  StartOverBookResult,
  ResetDataBody,
  ResetOutcomeView,
  StartOverInstanceBody,
  StartOverInstanceView,
} from './types';
import { clearSessionToken, getSessionToken } from './session';
import { t } from '../i18n';

/** The header that carries the current-user session token (plan t14 §2.8). */
export const SESSION_HEADER = 'X-Chancela-Session';

/** Shape of an error response body; `issues`/`warnings` are endpoint-specific. */
interface ApiErrorBody {
  error: string;
  issues?: ComplianceIssue[];
  warnings?: ComplianceIssue[];
}

export class ApiError extends Error {
  readonly status: number;
  readonly issues?: ComplianceIssue[];
  readonly warnings?: ComplianceIssue[];

  constructor(status: number, body: ApiErrorBody) {
    super(body.error || t('error.requestFailed', { status }));
    this.name = 'ApiError';
    this.status = status;
    this.issues = body.issues;
    this.warnings = body.warnings;
  }
}

/** The path a response came back on, for diagnostics; empty when the URL is unavailable. */
function responsePath(res: Response, path?: string): string {
  if (path) return path;
  try {
    return new URL(res.url).pathname;
  } catch {
    return res.url || '';
  }
}

/**
 * Parse a `Response` into JSON, throwing `ApiError` on non-2xx. Exposed for unit
 * testing the parse/error path against a mocked `fetch`. `204 No Content` and empty
 * bodies resolve to `undefined`. `path` (when known) is woven into diagnostics.
 *
 * Guards the `Content-Type` before parsing: a non-JSON body (typically the SPA's
 * `index.html`, served when a route the running server does not know falls through to the
 * app shell) becomes a clear typed error instead of an opaque `JSON.parse` "Unexpected
 * token '<'". That condition almost always means the server binary is older than this UI.
 */
export async function parseResponse<T>(res: Response, path?: string): Promise<T> {
  const text = await res.text();
  if (!text) {
    // Empty body (e.g. 204): nothing to parse. A non-2xx empty body still errors.
    if (!res.ok) {
      throw new ApiError(res.status, { error: t('error.requestFailed', { status: res.status }) });
    }
    return undefined as T;
  }

  const contentType = res.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    const looksHtml = contentType.includes('text/html') || text.trimStart().startsWith('<');
    const where = responsePath(res, path);
    const suffix = where ? t('error.pathSuffix', { path: where }) : '';
    const detail = looksHtml
      ? t('error.detail.html')
      : t('error.detail.type', { contentType: contentType || t('error.detail.unknownType') });
    throw new ApiError(res.status, {
      error: t('error.unexpectedResponse', { detail, suffix, status: res.status }),
    });
  }

  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    const where = responsePath(res, path);
    const suffix = where ? t('error.pathSuffix', { path: where }) : '';
    throw new ApiError(res.status, {
      error: t('error.invalidJson', { suffix, status: res.status }),
    });
  }

  if (!res.ok) {
    const body: ApiErrorBody =
      data && typeof data === 'object' && 'error' in data
        ? (data as ApiErrorBody)
        : { error: t('error.requestFailed', { status: res.status }) };
    throw new ApiError(res.status, body);
  }
  return data as T;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // Attach the current-user session token (when signed in) so the server attributes
  // the ledger actor. Absent when signed out → the system ("api") actor, unchanged.
  const token = getSessionToken();
  // Caller headers FIRST, then the security-critical ones LAST, so a caller cannot
  // overwrite the session token or content-type (L-4: header spread order).
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (token) headers[SESSION_HEADER] = token;
  if (init?.body) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, { ...init, headers });
  // A 401 means the server no longer recognises the token (e.g. it restarted and the
  // in-memory session was lost). Clear the stale token and notify listeners so the
  // session query refetches and the UI reflects the signed-out state (L-1).
  if (res.status === 401) {
    clearSessionToken();
  }
  return parseResponse<T>(res, path);
}

const get = <T>(path: string) => request<T>(path);
const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
const patch = <T>(path: string, body: unknown) =>
  request<T>(path, { method: 'PATCH', body: JSON.stringify(body) });
const put = <T>(path: string, body: unknown) =>
  request<T>(path, { method: 'PUT', body: JSON.stringify(body) });
const del = <T>(path: string, body?: unknown) =>
  request<T>(path, {
    method: 'DELETE',
    body: body === undefined ? undefined : JSON.stringify(body),
  });

/**
 * Fetch a binary body (e.g. a generated PDF) as a `Blob`, attaching the session token
 * exactly like {@link request} and clearing a stale token on 401. A non-2xx status is
 * surfaced as an `ApiError` (its friendly `{error}` body parsed when the server sent
 * JSON — e.g. the 404-until-sealed case), so callers get the same error idiom as the
 * JSON path. Used for the document download, which must not go through JSON parsing.
 */
export async function fetchBlob(path: string): Promise<Blob> {
  const token = getSessionToken();
  const headers: Record<string, string> = {};
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(path, { headers });
  if (res.status === 401) clearSessionToken();
  if (!res.ok) {
    let message = t('error.requestFailed', { status: res.status });
    try {
      const body = (await res.json()) as { error?: string };
      if (body?.error) message = body.error;
    } catch {
      // Non-JSON error body — keep the generic status message.
    }
    throw new ApiError(res.status, { error: message });
  }
  return res.blob();
}

/**
 * Fetch a binary body via a non-GET method (e.g. the book-export `.zip`, produced by a
 * `POST`). Mirrors {@link fetchBlob}: attaches the session token, clears a stale token on
 * 401, and surfaces a non-2xx as an `ApiError` (parsing the friendly `{error}` body when
 * the server sent JSON). Returns the `Blob` plus the response headers so a caller can read
 * the retained export path / bundle digest the server rides in `X-Chancela-*` headers.
 */
export async function fetchBlobVia(
  path: string,
  method: string,
): Promise<{ blob: Blob; headers: Headers }> {
  const token = getSessionToken();
  const headers: Record<string, string> = {};
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(path, { method, headers });
  if (res.status === 401) clearSessionToken();
  if (!res.ok) {
    let message = t('error.requestFailed', { status: res.status });
    try {
      const body = (await res.json()) as { error?: string };
      if (body?.error) message = body.error;
    } catch {
      // Non-JSON error body — keep the generic status message.
    }
    throw new ApiError(res.status, { error: message });
  }
  return { blob: await res.blob(), headers: res.headers };
}

/**
 * POST raw (non-JSON) bytes and parse a JSON response. The book-import endpoint takes the
 * bundle `.zip` bytes directly as the request body — NOT `application/json` — so it needs
 * its own path that does not stamp the JSON content-type `request` sets on a body.
 */
export async function postBytes<T>(path: string, bytes: ArrayBuffer | Blob): Promise<T> {
  const token = getSessionToken();
  const headers: Record<string, string> = { 'Content-Type': 'application/zip' };
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(path, { method: 'POST', headers, body: bytes });
  if (res.status === 401) clearSessionToken();
  return parseResponse<T>(res, path);
}

/** Build a query string from defined params only (skips `undefined`). */
function query(params: Record<string, string | number | undefined>): string {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) usp.set(k, String(v));
  }
  const s = usp.toString();
  return s ? `?${s}` : '';
}

export const api = {
  health: () => get<HealthResponse>('/health'),

  // Settings (§2.8) — whole-document GET/PUT.
  getSettings: () => get<Settings>('/v1/settings'),
  putSettings: (body: Settings) => put<Settings>('/v1/settings', body),

  // Entities (§2.3)
  listEntities: () => get<Entity[]>('/v1/entities'),
  getEntity: (id: string) => get<Entity>(`/v1/entities/${id}`),
  createEntity: (body: CreateEntityBody) => post<Entity>('/v1/entities', body),
  // Statute overlay (ENT-03, t31). Omit `statute` to leave it untouched, `null` to
  // clear it, or an object to set it; appends an `entity.statute_updated` ledger event.
  updateEntity: (id: string, body: UpdateEntityBody) => patch<Entity>(`/v1/entities/${id}`, body),

  // Books (§2.4)
  listBooks: (entityId?: string) => get<BookView[]>(`/v1/books${query({ entity_id: entityId })}`),
  getBook: (id: string) => get<BookView>(`/v1/books/${id}`),
  openBook: (body: OpenBookBody) => post<BookView>('/v1/books', body),
  closeBook: (id: string, body: CloseBookBody) => post<BookView>(`/v1/books/${id}/close`, body),
  listBookActs: (id: string) => get<ActView[]>(`/v1/books/${id}/acts`),

  // Acts (§2.5)
  getAct: (id: string) => get<ActView>(`/v1/acts/${id}`),
  draftAct: (body: DraftActBody) => post<ActView>('/v1/acts', body),
  updateAct: (id: string, body: UpdateActBody) => patch<ActView>(`/v1/acts/${id}`, body),
  advanceAct: (id: string, body: AdvanceActBody) => post<ActView>(`/v1/acts/${id}/advance`, body),
  getCompliance: (id: string) => get<ComplianceReport>(`/v1/acts/${id}/compliance`),
  sealAct: (id: string, body: SealActBody) => post<SealResult>(`/v1/acts/${id}/seal`, body),
  archiveAct: (id: string) => post<ActView>(`/v1/acts/${id}/archive`),

  // Generated documents (§3.3, plan t48). The preview renders the CURRENT record live
  // (works pre-seal); a `422`/`404` means the family has no template for the stage — the
  // caller renders that as an honest "sem modelo disponível" state, not an error. The
  // bundle is `404` until sealed (and for a sealed act whose family has no template).
  getActDocumentPreview: (id: string) => get<DocumentModel>(`/v1/acts/${id}/document/preview`),
  getActDocumentBundle: (id: string) => get<DocumentBundle>(`/v1/acts/${id}/document/bundle`),
  listTemplates: (params: { family?: EntityFamily; stage?: LifecycleStage } = {}) =>
    get<TemplateSummary[]>(`/v1/templates${query(params)}`),
  // The persisted PDF/A bytes (`GET /v1/acts/{id}/document`, `application/pdf`). Fetched
  // as a Blob (not JSON) so it can be triggered as a download with an honest filename;
  // carries the session token like every other request. 404 until sealed.
  fetchActDocumentPdf: (id: string) => fetchBlob(`/v1/acts/${id}/document`),

  // Qualified Chave Móvel Digital signing (§ t57). The two-phase flow: `initiate` (phone +
  // PIN → dispatches the SMS OTP) then `confirm` (session_id + OTP → the signed PDF). PIN/OTP
  // ride only in the request body and are never persisted client-side. The signature status
  // is `null`-free (unsigned/pending/signed); the signed PDF 404s until the act is signed.
  getActSignature: (id: string) => get<SignatureStatusView>(`/v1/acts/${id}/signature`),
  cmdInitiateSignature: (id: string, body: CmdInitiateBody) =>
    post<CmdInitiateResult>(`/v1/acts/${id}/signature/cmd/initiate`, body),
  cmdConfirmSignature: (id: string, body: CmdConfirmBody) =>
    post<CmdConfirmResult>(`/v1/acts/${id}/signature/cmd/confirm`, body),
  fetchSignedActDocumentPdf: (id: string) => fetchBlob(`/v1/acts/${id}/document/signed`),

  // Registry — certidão permanente (§2.7). The `code` in each body is a secret; it is
  // sent transiently in the request and never returned (provenance is masked).
  registryLookup: (body: RegistryLookupBody) =>
    post<RegistryExtractView>('/v1/registry/lookup', body),
  getEntityRegistry: (id: string) => get<RegistryExtractView>(`/v1/entities/${id}/registry`),
  importEntityRegistry: (id: string, body: RegistryImportBody) =>
    post<RegistryImportReport>(`/v1/entities/${id}/registry/import`, body),
  importFromRegistry: (body: ImportFromRegistryBody) =>
    post<RegistryImportReport>('/v1/entities/import-from-registry', body),

  // CAE — Classificação das Atividades Económicas (§2.7, plan t14).
  getCae: (code: string, revision?: CaeRevision) =>
    get<CaeEntryView>(`/v1/cae/${encodeURIComponent(code)}${query({ revision })}`),
  searchCae: (search: string, params: { revision?: CaeRevision; limit?: number } = {}) =>
    get<CaeNode[]>(`/v1/cae${query({ search, ...params })}`),
  getCaeCatalog: () => get<CaeCatalogView>('/v1/cae'),
  refreshCae: () => post<CaeRefreshResult>('/v1/cae/refresh'),
  // The INE SMI update-availability signal (t33-e2). Read-only; 502 when SMI is
  // unreachable. The "Verificar novas revisões" UI that consumes it is t23-e3's.
  getCaeUpdates: () => get<CaeUpdates>('/v1/cae/updates'),

  // Law archive (t27, FROZEN §law-v1) — the local "mini law archive". `GET /v1/law` is a
  // bare `[LawEntryView]`; the tolerant `{ entries }` alternative is kept only so the hook's
  // normalizer is robust. A 404 / non-JSON reply means the running server predates the
  // feature, which `useLawArchive` catches to fall back to links-only. `fetchLawPdf` may
  // fail with 404 / 409 (pdf_url null) / 422 (no data dir) / 502 — the friendly `{error}`
  // body is surfaced to the user via `ApiError.message`.
  getLawManifest: () => get<LawEntryView[] | { entries: LawEntryView[] }>('/v1/law'),
  fetchLawPdf: (id: string) => post<LawEntryView>(`/v1/law/${encodeURIComponent(id)}/fetch`),

  // Users + session (§2.8, plan t14). The session token is stored in memory (see
  // `./session`) and sent as `X-Chancela-Session` on every request by `request`.
  listUsers: () => get<UserView[]>('/v1/users'),
  getUser: (id: string) => get<UserView>(`/v1/users/${id}`),
  createUser: (body: CreateUserBody) => post<UserView>('/v1/users', body),
  updateUser: (id: string, body: UpdateUserBody) => patch<UserView>(`/v1/users/${id}`, body),
  // Sign-in secret + attestation-key management (t29 §4). All echo the updated UserView.
  // The `current_password` (when a secret already exists) rides in the body; a DELETE
  // carries it too (the `del` helper JSON-encodes an optional body).
  setUserSecret: (id: string, body: SetSecretBody) =>
    post<UserView>(`/v1/users/${id}/secret`, body),
  removeUserSecret: (id: string, body: RemoveSecretBody = {}) =>
    del<UserView>(`/v1/users/${id}/secret`, body),
  createAttestationKey: (id: string, body: AttestationKeyBody = {}) =>
    post<UserView>(`/v1/users/${id}/attestation-key`, body),
  removeAttestationKey: (id: string, body: AttestationKeyBody = {}) =>
    del<UserView>(`/v1/users/${id}/attestation-key`, body),
  // Issue/rotate a one-time recovery phrase (t51). The returned phrase is shown ONCE and
  // never crosses the wire again (stored only as a verifier) — callers must not persist it.
  issueRecovery: (id: string, body: IssueRecoveryBody = {}) =>
    post<RecoveryIssued>(`/v1/users/${id}/recovery`, body),
  getSession: () => get<SessionView>('/v1/session'),
  // The fuller permission view (identity + role assignments + effective grants) for the
  // signed-in principal (`GET /v1/session/permissions`, t64-E3). Used to seed the
  // role-assignment manager with the current user's OWN assignments (there is no read
  // endpoint for another user's assignments — the assign/unassign responses are the source
  // of truth for those).
  getSessionPermissions: () => get<SessionPermissions>('/v1/session/permissions'),

  // RBAC management (§ t64-E4, FROZEN DTOs). The server re-enforces the subset invariant,
  // protected-Owner, last-Owner and delegation hold-via-role rules on every write regardless
  // of what the UI offers — a rejected escalation comes back as an honest 403/409.
  listRoles: () => get<RoleView[]>('/v1/roles'),
  listPermissions: () => get<PermissionCatalogView>('/v1/permissions'),
  createRole: (body: CreateRoleBody) => post<RoleView>('/v1/roles', body),
  patchRole: (id: string, body: PatchRoleBody) => patch<RoleView>(`/v1/roles/${id}`, body),
  deleteRole: (id: string) => del<void>(`/v1/roles/${id}`),
  // Assign/unassign a `(role, scope)` to a user. Both echo the user's UPDATED assignment
  // list, so the caller keeps the shown assignments authoritative without a separate read.
  assignRole: (userId: string, body: RoleAssignmentInput) =>
    post<RoleAssignmentView[]>(`/v1/users/${userId}/roles`, body),
  unassignRole: (userId: string, body: RoleAssignmentInput) =>
    del<RoleAssignmentView[]>(`/v1/users/${userId}/roles`, body),
  // Scoped delegations. `GET` returns the delegations touching the caller (own) or all (for a
  // `delegation.revoke` holder); grant/revoke are gated + invariant-enforced server-side.
  listDelegations: () => get<DelegationView[]>('/v1/delegations'),
  grantDelegation: (body: GrantDelegationBody) => post<DelegationView>('/v1/delegations', body),
  revokeDelegation: (id: string) => del<void>(`/v1/delegations/${id}`),
  // The UNAUTHENTICATED sign-in roster (t45-e1): decides onboarding-vs-sign-in and lists
  // the signable users while signed out, without the auth-gated `GET /v1/users`.
  getSessionRoster: () => get<SessionRoster>('/v1/session/roster'),
  createSession: (body: CreateSessionBody) => post<SessionResult>('/v1/session', body),
  deleteSession: () => del<void>('/v1/session'),

  // Ledger (§2.6)
  listLedger: (params: { scope?: string; limit?: number } = {}) =>
    get<LedgerEventView[]>(`/v1/ledger/events${query(params)}`),
  verifyLedger: () => get<LedgerVerify>('/v1/ledger/verify'),

  // Chain integrity + recovery + per-book export/import/start-over + data management
  // (t54, frozen E3 DTOs). Every destructive op carries a step-up `reauth` proof.
  ledgerIntegrity: () => get<IntegrityReportView>('/v1/ledger/integrity'),
  reanchorLedger: (body: ReanchorBody) =>
    post<ReanchorResult>('/v1/ledger/recovery/reanchor', body),
  restoreLedger: (body: RestoreBody) =>
    post<RestoreOutcomeView>('/v1/ledger/recovery/restore', body),
  // Book bundle export: a `POST` that streams `application/zip`; the retained path +
  // digest ride in `X-Chancela-Export-Path` / `X-Chancela-Bundle-Digest` headers.
  exportBook: (id: string) => fetchBlobVia(`/v1/books/${id}/export`, 'POST'),
  // Book import: raw `.zip` bytes in the body; verify-before-trust → Verified|Quarantined.
  importBook: (bytes: ArrayBuffer | Blob, policy: CollisionPolicy = 'refuse') =>
    postBytes<ImportOutcomeView>(`/v1/books/import${query({ policy })}`, bytes),
  startOverBook: (id: string, body: StartOverBookBody) =>
    post<StartOverBookResult>(`/v1/books/${id}/start-over`, body),
  // Data management (§2.11). Frontend-reset is client-only — it has NO endpoint here.
  resetData: (body: ResetDataBody) => post<ResetOutcomeView>('/v1/data/reset', body),
  startOverInstance: (body: StartOverInstanceBody) =>
    post<StartOverInstanceView>('/v1/data/start-over', body),

  // Dashboard (§2.7)
  dashboard: () => get<Dashboard>('/v1/dashboard'),
};

/**
 * The same-origin path that serves a stored law PDF (`GET /v1/law/{id}/pdf`). Used as a
 * plain link target (not routed through `openExternal`) since it is an app-origin URL the
 * embedded server serves — in the browser it opens in a new tab, in the desktop WebView it
 * resolves against the in-process server.
 */
export function lawPdfPath(id: string): string {
  return `/v1/law/${encodeURIComponent(id)}/pdf`;
}
