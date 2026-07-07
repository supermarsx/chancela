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
  DraftActBody,
  Entity,
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
  UpdateEntityBody,
  SessionResult,
  SessionView,
  Settings,
  UpdateActBody,
  UpdateUserBody,
  UserView,
  BookView,
  HealthResponse,
} from './types';
import { getSessionToken } from './session';
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
  const res = await fetch(path, {
    ...init,
    headers: {
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { [SESSION_HEADER]: token } : {}),
      ...init?.headers,
    },
  });
  return parseResponse<T>(res, path);
}

const get = <T>(path: string) => request<T>(path);
const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
const patch = <T>(path: string, body: unknown) =>
  request<T>(path, { method: 'PATCH', body: JSON.stringify(body) });
const put = <T>(path: string, body: unknown) =>
  request<T>(path, { method: 'PUT', body: JSON.stringify(body) });
const del = <T>(path: string) => request<T>(path, { method: 'DELETE' });

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
  getSession: () => get<SessionView>('/v1/session'),
  createSession: (body: CreateSessionBody) => post<SessionResult>('/v1/session', body),
  deleteSession: () => del<void>('/v1/session'),

  // Ledger (§2.6)
  listLedger: (params: { scope?: string; limit?: number } = {}) =>
    get<LedgerEventView[]>(`/v1/ledger/events${query(params)}`),
  verifyLedger: () => get<LedgerVerify>('/v1/ledger/verify'),

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
