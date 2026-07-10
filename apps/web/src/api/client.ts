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
  TslCatalogView,
  TslCatalogSearchParams,
  TslProviderDetailView,
  TslRefreshRequest,
  TslRefreshStatusView,
  TslServiceDetailView,
  TslServiceSummaryView,
  TslSummaryView,
  TsaCatalogView,
  TsaCatalogSearchParams,
  TsaRecordView,
  CloseBookBody,
  ComplianceIssue,
  ComplianceReport,
  CompleteFollowUpBody,
  BreachPlaybookView,
  CreateBreachPlaybookBody,
  CreateDsrRequestBody,
  CreateDpiaRecordBody,
  CreateEntityBody,
  CreateFollowUpBody,
  CreateProcessorRecordBody,
  CreateRetentionPolicyBody,
  CreateSessionBody,
  CreateUserBody,
  Dashboard,
  DataCleanupBody,
  DataCleanupResult,
  DataStatusResponse,
  NotificationTriageResponse,
  NotificationTriageUpdateBody,
  NotificationTriageUpdateResponse,
  DocumentBundle,
  ImportedDocumentView,
  ImportedDocumentReviewBody,
  ImportDocumentBody,
  DocumentModel,
  DraftActBody,
  DpiaRecordView,
  DsrRequestView,
  Entity,
  EntityFamily,
  LifecycleStage,
  TemplateSummary,
  ImportFromRegistryBody,
  LawEntryView,
  LawCorpusView,
  LawDiplomaDetailView,
  LawArticleView,
  LawCitationRequest,
  LawCitationReport,
  LawSearchView,
  FollowUpView,
  LedgerArchiveDocumentParams,
  LedgerEventView,
  LedgerQueryParams,
  LedgerVerify,
  OpenBookBody,
  PaperBookImportReport,
  PaperBookImportPreservationReport,
  PaperBookImportPreserveBody,
  PaperBookImportView,
  PaperBookImportValidateBody,
  PaperBookOcrStatusUpdateBody,
  PaperBookOcrStatusView,
  PdfSignatureValidationBody,
  PdfSignatureValidationResponse,
  PlatformControllableServiceId,
  PlatformControlResponse,
  PlatformLogsQueryParams,
  PlatformLogsResponse,
  PlatformServiceAction,
  PlatformServicesResponse,
  RegistryExtractView,
  RegistryAutoUpdateAttemptBody,
  RegistryAutoUpdateAttemptView,
  RegistryAutoUpdateDuePlan,
  RegistryImportBody,
  RegistryImportReport,
  RegistryLookupBody,
  SealActBody,
  SealResult,
  PatchBreachPlaybookBody,
  PatchFollowUpBody,
  PatchDpiaRecordBody,
  PatchProcessorRecordBody,
  PatchRetentionPolicyBody,
  RetentionDryRunBody,
  RetentionDryRunReport,
  RetentionPolicyView,
  SignatureStatusView,
  CmdInitiateBody,
  CmdInitiateResult,
  CmdConfirmBody,
  CmdConfirmResult,
  CcSignBody,
  CcSignResult,
  CreateExternalSignerInviteBody,
  CreateExternalSignerInviteResult,
  ExternalSignerInviteDecision,
  ExternalSignerInvitePublicView,
  ExternalSignerInviteView,
  SignatureProviderView,
  RemoteInitiateBody,
  RemoteInitiateResult,
  RemoteConfirmBody,
  RemoteConfirmResult,
  UpdateEntityBody,
  SessionResult,
  SessionRoster,
  SessionView,
  PasswordPolicyView,
  ProcessorRecordView,
  CreateTransferControlBody,
  PatchTransferControlBody,
  TransferControlView,
  SetSecretBody,
  RemoveSecretBody,
  AttestationKeyBody,
  IssueRecoveryBody,
  RecoveryIssued,
  Settings,
  UpdateActBody,
  UpdateUserBody,
  UserView,
  VerifyAiHumanReviewBody,
  RoleView,
  PermissionCatalogView,
  CreateRoleBody,
  PatchRoleBody,
  RoleAssignmentInput,
  RoleAssignmentView,
  ApiKeyCreated,
  ApiKeyRotated,
  ApiKeyView,
  CreateApiKeyBody,
  SessionPermissions,
  DelegationView,
  GrantDelegationBody,
  BookView,
  BookLegalHoldView,
  ClearBookLegalHoldBody,
  HealthResponse,
  IntegrityReportView,
  ReanchorBody,
  ReanchorResult,
  RestoreBody,
  RestoreOutcomeView,
  BackupManifest,
  ImportOutcomeView,
  CollisionPolicy,
  StartOverBookBody,
  StartOverBookResult,
  ResetDataBody,
  ResetOutcomeView,
  StartOverInstanceBody,
  StartOverInstanceView,
  SetBookLegalHoldBody,
  UserDsrExport,
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

/** A non-JSON text export plus the original download metadata. */
export interface TextDownload {
  text: string;
  blob: Blob;
  contentType: string;
  headers: Headers;
}

export type ActDocumentWorkingCopyFormat = 'markdown' | 'txt' | 'html' | 'rtf' | 'odt';

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
 * Fetch a textual download without routing it through JSON parsing or PDF-specific
 * helpers. Returns both text and Blob forms, preserving
 * the response content type/header metadata for callers that save the file.
 */
export async function fetchTextDownload(path: string): Promise<TextDownload> {
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
  const contentType = res.headers.get('Content-Type') ?? '';
  const text = await res.clone().text();
  const blob = await res.blob();
  return { text, blob, contentType, headers: res.headers };
}

/**
 * Fetch a textual download via POST with a JSON body. Used by public token-gated downloads whose
 * token must stay in the request body rather than a path or query string.
 */
export async function postTextDownload(path: string, body: unknown): Promise<TextDownload> {
  const token = getSessionToken();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch(path, { method: 'POST', headers, body: JSON.stringify(body) });
  if (res.status === 401) clearSessionToken();
  if (!res.ok) {
    let message = t('error.requestFailed', { status: res.status });
    try {
      const parsed = (await res.json()) as { error?: string };
      if (parsed?.error) message = parsed.error;
    } catch {
      // Non-JSON error body — keep the generic status message.
    }
    throw new ApiError(res.status, { error: message });
  }
  const contentType = res.headers.get('Content-Type') ?? '';
  const text = await res.clone().text();
  const blob = await res.blob();
  return { text, blob, contentType, headers: res.headers };
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

function trustSearchQuery(
  params: TslCatalogSearchParams | string,
  limit?: number,
): Record<string, string | number | undefined> {
  if (typeof params === 'string') return { search: params, limit };
  return {
    search: params.search,
    service_type: params.service_type,
    status: params.status,
    history: params.history,
    supply_point: params.supply_point,
    limit: params.limit ?? limit,
  };
}

export const api = {
  health: () => get<HealthResponse>('/health'),

  // Settings (§2.8) — whole-document GET/PUT.
  getSettings: () => get<Settings>('/v1/settings'),
  putSettings: (body: Settings) => put<Settings>('/v1/settings', body),

  // Platform operations — desired-state controls plus honest runtime limitations.
  listPlatformServices: () => get<PlatformServicesResponse>('/v1/platform/services'),
  controlPlatformService: (id: PlatformControllableServiceId, action: PlatformServiceAction) =>
    post<PlatformControlResponse>(
      `/v1/platform/services/${encodeURIComponent(id)}/actions/${encodeURIComponent(action)}`,
    ),
  listPlatformLogs: (params: PlatformLogsQueryParams = {}) =>
    get<PlatformLogsResponse>(
      `/v1/platform/logs${query({
        service_id: params.service_id,
        level: params.level,
        tail: params.tail,
      })}`,
    ),

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
  getBookLegalHold: (id: string) => get<BookLegalHoldView>(`/v1/books/${id}/legal-hold`),
  setBookLegalHold: (id: string, body: SetBookLegalHoldBody) =>
    put<BookLegalHoldView>(`/v1/books/${id}/legal-hold`, body),
  clearBookLegalHold: (id: string, body?: ClearBookLegalHoldBody) =>
    del<BookLegalHoldView | void>(`/v1/books/${id}/legal-hold`, body),
  // Internal Chancela preservation package (`GET .../archive/package`, application/zip).
  // Read-only and not a DGLAB-specific export; offered as a direct browser download.
  fetchBookArchivePackage: (id: string) => fetchBlob(`/v1/books/${id}/archive/package`),

  // Acts (§2.5)
  getAct: (id: string) => get<ActView>(`/v1/acts/${id}`),
  draftAct: (body: DraftActBody) => post<ActView>('/v1/acts', body),
  updateAct: (id: string, body: UpdateActBody) => patch<ActView>(`/v1/acts/${id}`, body),
  advanceAct: (id: string, body: AdvanceActBody) => post<ActView>(`/v1/acts/${id}/advance`, body),
  verifyActHumanReview: (id: string, body: VerifyAiHumanReviewBody) =>
    post<ActView>(`/v1/acts/${id}/human-verification`, body),
  getCompliance: (id: string) => get<ComplianceReport>(`/v1/acts/${id}/compliance`),
  sealAct: (id: string, body: SealActBody) => post<SealResult>(`/v1/acts/${id}/seal`, body),
  archiveAct: (id: string) => post<ActView>(`/v1/acts/${id}/archive`),
  listActFollowUps: (id: string) => get<FollowUpView[]>(`/v1/acts/${id}/follow-ups`),
  createActFollowUp: (id: string, body: CreateFollowUpBody) =>
    post<FollowUpView>(`/v1/acts/${id}/follow-ups`, body),
  patchFollowUp: (id: string, body: PatchFollowUpBody) =>
    patch<FollowUpView>(`/v1/follow-ups/${encodeURIComponent(id)}`, body),
  completeFollowUp: (id: string, body: CompleteFollowUpBody = {}) =>
    post<FollowUpView>(`/v1/follow-ups/${encodeURIComponent(id)}/complete`, body),

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
  // Working-copy export (`GET .../document/working-copy`, text/markdown by default;
  // `?format=txt|html|rtf|odt` for other review formats). Non-evidentiary and intentionally
  // separate from the persisted/signed PDF downloads.
  fetchActDocumentWorkingCopy: (id: string, format: ActDocumentWorkingCopyFormat = 'markdown') =>
    fetchTextDownload(
      `/v1/acts/${id}/document/working-copy${format === 'markdown' ? '' : query({ format })}`,
    ),
  // Office-editable DOCX working-copy export (`GET .../document/office`). Read-only and
  // non-evidentiary; the persisted PDF/A or signed PDF remains the canonical record.
  fetchActDocumentOffice: (id: string) => fetchBlob(`/v1/acts/${id}/document/office`),
  // Non-canonical imported document evidence. Import re-runs server validation before
  // persistence; metadata JSON never carries raw bytes.
  importDocument: (body: ImportDocumentBody) =>
    post<ImportedDocumentView>('/v1/documents/import', body),
  listImportedDocuments: (params: { act_id?: string } = {}) =>
    get<ImportedDocumentView[]>(`/v1/documents/imported${query(params)}`),
  getImportedDocument: (id: string) =>
    get<ImportedDocumentView>(`/v1/documents/imported/${encodeURIComponent(id)}`),
  reviewImportedDocument: (id: string, body: ImportedDocumentReviewBody) =>
    patch<ImportedDocumentView>(`/v1/documents/imported/${encodeURIComponent(id)}/review`, body),
  fetchImportedDocumentBytes: (id: string) =>
    fetchBlob(`/v1/documents/imported/${encodeURIComponent(id)}/bytes`),

  // Qualified Chave Móvel Digital signing (§ t57). The two-phase flow: `initiate` (phone +
  // PIN → dispatches the SMS OTP) then `confirm` (session_id + OTP → the signed PDF). PIN/OTP
  // ride only in the request body and are never persisted client-side. The signature status
  // is `null`-free (unsigned/pending/signed); the signed PDF 404s until the act is signed.
  getActSignature: (id: string) => get<SignatureStatusView>(`/v1/acts/${id}/signature`),
  cmdInitiateSignature: (id: string, body: CmdInitiateBody) =>
    post<CmdInitiateResult>(`/v1/acts/${id}/signature/cmd/initiate`, body),
  cmdConfirmSignature: (id: string, body: CmdConfirmBody) =>
    post<CmdConfirmResult>(`/v1/acts/${id}/signature/cmd/confirm`, body),
  // Qualified Cartão de Cidadão signing (§ t58) — SYNCHRONOUS and desktop-only. A single
  // call signs the sealed PDF at the co-located card reader; NO PIN in the body (it is
  // entered at the reader / Autenticação.gov). Refused with 409 when the API is not
  // co-located with a reader (browser/remote server); a provider failure (no card / wrong
  // PIN / not activated / no reader) is an honest 422 whose PT message is surfaced verbatim.
  ccSignSignature: (id: string, body: CcSignBody = {}) =>
    post<CcSignResult>(`/v1/acts/${id}/signature/cc/sign`, body),
  fetchSignedActDocumentPdf: (id: string) => fetchBlob(`/v1/acts/${id}/document/signed`),

  // Generic remote qualified signing (§ t59) — the provider picker + the provider-agnostic
  // two-phase flow. `listSignatureProviders` enumerates CMD + every configured CSC QTSP (gated
  // `signing.perform`; a role without it → 403); the `remote/{provider}/initiate|confirm` pair
  // drives a CSC QTSP through the SAME two-phase activation as CMD. The credential/activation
  // ride only in the request body and are never persisted client-side.
  listSignatureProviders: () => get<SignatureProviderView[]>('/v1/signature/providers'),
  remoteInitiateSignature: (id: string, provider: string, body: RemoteInitiateBody) =>
    post<RemoteInitiateResult>(
      `/v1/acts/${id}/signature/remote/${encodeURIComponent(provider)}/initiate`,
      body,
    ),
  remoteConfirmSignature: (id: string, provider: string, body: RemoteConfirmBody) =>
    post<RemoteConfirmResult>(
      `/v1/acts/${id}/signature/remote/${encodeURIComponent(provider)}/confirm`,
      body,
    ),
  listExternalSignerInvites: (id: string) =>
    get<ExternalSignerInviteView[]>(`/v1/acts/${id}/signature/external-invites`),
  createExternalSignerInvite: (id: string, body: CreateExternalSignerInviteBody) =>
    post<CreateExternalSignerInviteResult>(`/v1/acts/${id}/signature/external-invites`, body),
  revokeExternalSignerInvite: (id: string, inviteId: string) =>
    post<ExternalSignerInviteView>(
      `/v1/acts/${id}/signature/external-invites/${encodeURIComponent(inviteId)}/revoke`,
    ),
  lookupExternalSignerInvite: (token: string) =>
    post<ExternalSignerInvitePublicView>('/v1/signature/external-invites/lookup', { token }),
  respondExternalSignerInvite: (token: string, decision: ExternalSignerInviteDecision) =>
    post<ExternalSignerInvitePublicView>('/v1/signature/external-invites/respond', {
      token,
      decision,
    }),
  fetchExternalSignerInviteWorkingCopy: (token: string) =>
    postTextDownload('/v1/signature/external-invites/document/working-copy', { token }),
  validatePdfSignature: (body: PdfSignatureValidationBody) =>
    post<PdfSignatureValidationResponse>('/v1/signature/pdf/validate', body),

  // Registry — certidão permanente (§2.7). The `code` in each body is a secret; it is
  // sent transiently in the request and never returned (provenance is masked).
  registryLookup: (body: RegistryLookupBody) =>
    post<RegistryExtractView>('/v1/registry/lookup', body),
  getRegistryAutoUpdateDuePlan: () => get<RegistryAutoUpdateDuePlan>('/v1/registry/lookup'),
  getEntityRegistry: (id: string) => get<RegistryExtractView>(`/v1/entities/${id}/registry`),
  requestRegistryAutoUpdate: (id: string, body: RegistryAutoUpdateAttemptBody = {}) =>
    post<RegistryAutoUpdateAttemptView>(`/v1/entities/${id}/registry`, body),
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

  // TSL trust catalog — read-only parsed Trusted List status/search/detail. No live fetch is
  // triggered by these endpoints; the server parses cached XML or its bundled fixture.
  getTrustStatus: () => get<TslSummaryView>('/v1/trust/status'),
  refreshTrustTsl: (body: TslRefreshRequest = {}) =>
    post<TslRefreshStatusView>('/v1/trust/refresh', body),
  getTrustCatalog: () => get<TslCatalogView>('/v1/trust/catalog'),
  searchTrustCatalog: (params: TslCatalogSearchParams | string, limit?: number) =>
    get<TslServiceSummaryView[]>(`/v1/trust/catalog${query(trustSearchQuery(params, limit))}`),
  getTrustProvider: (id: string) =>
    get<TslProviderDetailView>(`/v1/trust/providers/${encodeURIComponent(id)}`),
  getTrustService: (id: string) =>
    get<TslServiceDetailView>(`/v1/trust/services/${encodeURIComponent(id)}`),
  // TSA diagnostics/catalog — read-only configured RFC 3161 status plus offline fixture probe and
  // TSL timestamp-authority records. No live timestamp request is triggered.
  getTsaCatalog: () => get<TsaCatalogView>('/v1/trust/tsa'),
  searchTsaCatalog: (params: TsaCatalogSearchParams | string, limit?: number) =>
    get<TsaRecordView[]>(`/v1/trust/tsa${query(trustSearchQuery(params, limit))}`),

  // Law archive (t27, FROZEN §law-v1) — the local "mini law archive". `GET /v1/law` is a
  // bare `[LawEntryView]`; the tolerant `{ entries }` alternative is kept only so the hook's
  // normalizer is robust. A 404 / non-JSON reply means the running server predates the
  // feature, which `useLawArchive` catches to fall back to links-only. `fetchLawPdf` may
  // fail with 404 / 409 (pdf_url null) / 422 (no data dir) / 502 — the friendly `{error}`
  // body is surfaced to the user via `ApiError.message`.
  getLawManifest: () => get<LawEntryView[] | { entries: LawEntryView[] }>('/v1/law'),
  fetchLawPdf: (id: string) => post<LawEntryView>(`/v1/law/${encodeURIComponent(id)}/fetch`),

  // Law corpus reader (t55-E2, FROZEN corpus-v1) — read-only, full-text access to the embedded
  // statute corpus, gated `law.read@Global`. Distinct from the PDF archive above: this surfaces
  // the article-by-article verbatim text (or the loud unverified marker for a `Pending` article)
  // plus a per-article authenticity status, and an accent/case-insensitive full-text search.
  // `getLawDiploma`/`getLawArticle` 404 on an unknown diploma/article; a blank search `q` → an
  // empty result set (`limit` default 50, max 500 server-side).
  getLawCorpus: () => get<LawCorpusView>('/v1/law/corpus'),
  getLawDiploma: (diploma: string) =>
    get<LawDiplomaDetailView>(`/v1/law/corpus/${encodeURIComponent(diploma)}`),
  getLawArticle: (diploma: string, article: string) =>
    get<LawArticleView>(
      `/v1/law/corpus/${encodeURIComponent(diploma)}/${encodeURIComponent(article)}`,
    ),
  searchLawCorpus: (q: string, limit?: number) =>
    get<LawSearchView>(`/v1/law/corpus/search${query({ q, limit })}`),
  resolveLawCitations: (body: LawCitationRequest) =>
    post<LawCitationReport>('/v1/law/citations/resolve', body),

  // Users + session (§2.8, plan t14). The session token is stored in memory (see
  // `./session`) and sent as `X-Chancela-Session` on every request by `request`.
  listUsers: () => get<UserView[]>('/v1/users'),
  getUser: (id: string) => get<UserView>(`/v1/users/${id}`),
  createUser: (body: CreateUserBody) => post<UserView>('/v1/users', body),
  updateUser: (id: string, body: UpdateUserBody) => patch<UserView>(`/v1/users/${id}`, body),
  exportUserDsr: (id: string) => get<UserDsrExport>(`/v1/privacy/users/${id}/export`),
  listUserDsrRequests: (id: string) =>
    get<DsrRequestView[]>(`/v1/privacy/users/${id}/dsr-requests`),
  createUserDsrRequest: (id: string, body: CreateDsrRequestBody) =>
    post<DsrRequestView>(`/v1/privacy/users/${id}/dsr-requests`, body),
  completeUserDsrRequest: (userId: string, requestId: string) =>
    post<DsrRequestView>(`/v1/privacy/users/${userId}/dsr-requests/${requestId}/complete`),
  listProcessorRecords: () => get<ProcessorRecordView[]>('/v1/privacy/processors'),
  createProcessorRecord: (body: CreateProcessorRecordBody) =>
    post<ProcessorRecordView>('/v1/privacy/processors', body),
  patchProcessorRecord: (id: string, body: PatchProcessorRecordBody) =>
    patch<ProcessorRecordView>(`/v1/privacy/processors/${id}`, body),
  listDpiaRecords: () => get<DpiaRecordView[]>('/v1/privacy/dpias'),
  createDpiaRecord: (body: CreateDpiaRecordBody) => post<DpiaRecordView>('/v1/privacy/dpias', body),
  patchDpiaRecord: (id: string, body: PatchDpiaRecordBody) =>
    patch<DpiaRecordView>(`/v1/privacy/dpias/${id}`, body),
  listBreachPlaybooks: () => get<BreachPlaybookView[]>('/v1/privacy/breach-playbooks'),
  createBreachPlaybook: (body: CreateBreachPlaybookBody) =>
    post<BreachPlaybookView>('/v1/privacy/breach-playbooks', body),
  patchBreachPlaybook: (id: string, body: PatchBreachPlaybookBody) =>
    patch<BreachPlaybookView>(`/v1/privacy/breach-playbooks/${id}`, body),
  listTransferControls: () => get<TransferControlView[]>('/v1/privacy/transfer-controls'),
  createTransferControl: (body: CreateTransferControlBody) =>
    post<TransferControlView>('/v1/privacy/transfer-controls', body),
  patchTransferControl: (id: string, body: PatchTransferControlBody) =>
    patch<TransferControlView>(`/v1/privacy/transfer-controls/${id}`, body),
  listRetentionPolicies: () => get<RetentionPolicyView[]>('/v1/privacy/retention-policies'),
  createRetentionPolicy: (body: CreateRetentionPolicyBody) =>
    post<RetentionPolicyView>('/v1/privacy/retention-policies', body),
  patchRetentionPolicy: (id: string, body: PatchRetentionPolicyBody) =>
    patch<RetentionPolicyView>(`/v1/privacy/retention-policies/${id}`, body),
  dryRunRetentionPolicy: (body: RetentionDryRunBody) =>
    post<RetentionDryRunReport>('/v1/privacy/retention-policies/dry-run', body),
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
  // Active password-strength ruleset (t68). Exempt so onboarding can render the checklist
  // before a user/session exists; the server remains authoritative on submit.
  getPasswordPolicy: () => get<PasswordPolicyView>('/v1/session/password-policy'),
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

  // API keys — interactive-session-only management. Create/rotate return the plaintext secret once;
  // list/revoke return metadata only.
  listApiKeys: () => get<ApiKeyView[]>('/v1/api-keys'),
  createApiKey: (body: CreateApiKeyBody) => post<ApiKeyCreated>('/v1/api-keys', body),
  rotateApiKey: (id: string) => post<ApiKeyRotated>(`/v1/api-keys/${id}/rotate`),
  revokeApiKey: (id: string) => del<ApiKeyView>(`/v1/api-keys/${id}`),

  // The UNAUTHENTICATED sign-in roster (t45-e1): decides onboarding-vs-sign-in and lists
  // the signable users while signed out, without the auth-gated `GET /v1/users`.
  getSessionRoster: () => get<SessionRoster>('/v1/session/roster'),
  createSession: (body: CreateSessionBody) => post<SessionResult>('/v1/session', body),
  deleteSession: () => del<void>('/v1/session'),

  // Ledger (§2.6)
  listLedger: (params: LedgerQueryParams = {}) =>
    get<LedgerEventView[]>(
      `/v1/ledger/events${query({
        chain: params.chain,
        scope: params.scope,
        limit: params.limit,
      })}`,
    ),
  fetchLedgerArchiveDocumentPdf: (params: LedgerArchiveDocumentParams = {}) =>
    fetchBlob(
      `/v1/ledger/archive/document${query({
        chain: params.chain,
        scope: params.scope,
        kind: params.kind,
        actor: params.actor,
        from: params.from,
        to: params.to,
        limit: params.limit,
      })}`,
    ),
  verifyLedger: () => get<LedgerVerify>('/v1/ledger/verify'),

  // Chain integrity + recovery + per-book export/import/start-over + data management
  // (t54, frozen E3 DTOs). Every destructive op carries a step-up `reauth` proof.
  ledgerIntegrity: () => get<IntegrityReportView>('/v1/ledger/integrity'),
  reanchorLedger: (body: ReanchorBody) =>
    post<ReanchorResult>('/v1/ledger/recovery/reanchor', body),
  restoreLedger: (body: RestoreBody) =>
    post<RestoreOutcomeView>('/v1/ledger/recovery/restore', body),
  // Take a hot backup and return its manifest (`POST /v1/backup`, contract §3.2, t30). No
  // body; gated by `data.backup`@Global. 422 when the instance has no on-disk persistence
  // (in-memory mode). Server-response-modelled — no backup UI drives this yet.
  backup: () => post<BackupManifest>('/v1/backup'),
  // Book bundle export: a `POST` that streams `application/zip`; the retained path +
  // digest ride in `X-Chancela-Export-Path` / `X-Chancela-Bundle-Digest` headers.
  exportBook: (id: string) => fetchBlobVia(`/v1/books/${id}/export`, 'POST'),
  // Book import: raw `.zip` bytes in the body; verify-before-trust → Verified|Quarantined.
  importBook: (bytes: ArrayBuffer | Blob, policy: CollisionPolicy = 'refuse') =>
    postBytes<ImportOutcomeView>(`/v1/books/import${query({ policy })}`, bytes),
  validatePaperBookImport: (body: PaperBookImportValidateBody) =>
    post<PaperBookImportReport>('/v1/books/paper-import/validate', body),
  preservePaperBookImport: (body: PaperBookImportPreserveBody) =>
    post<PaperBookImportPreservationReport>('/v1/books/paper-import', body),
  listPaperBookImports: (params: { book_ref?: string } = {}) =>
    get<PaperBookImportView[]>(`/v1/books/paper-import${query(params)}`),
  getPaperBookImport: (id: string) =>
    get<PaperBookImportView>(`/v1/books/paper-import/${encodeURIComponent(id)}`),
  enqueuePaperBookImportOcr: (id: string) =>
    post<PaperBookOcrStatusView>(`/v1/books/paper-import/${encodeURIComponent(id)}/ocr/enqueue`),
  updatePaperBookImportOcrStatus: (id: string, body: PaperBookOcrStatusUpdateBody) =>
    patch<PaperBookOcrStatusView>(
      `/v1/books/paper-import/${encodeURIComponent(id)}/ocr-status`,
      body,
    ),
  fetchPaperBookImportBytes: (id: string) =>
    fetchBlob(`/v1/books/paper-import/${encodeURIComponent(id)}/bytes`),
  startOverBook: (id: string, body: StartOverBookBody) =>
    post<StartOverBookResult>(`/v1/books/${id}/start-over`, body),
  dataStatus: () => get<DataStatusResponse>('/v1/data/status'),
  cleanDataStorage: (body: DataCleanupBody) => post<DataCleanupResult>('/v1/data/cleanup', body),
  // Data management (§2.11). Frontend-reset is client-only — it has NO endpoint here.
  resetData: (body: ResetDataBody) => post<ResetOutcomeView>('/v1/data/reset', body),
  startOverInstance: (body: StartOverInstanceBody) =>
    post<StartOverInstanceView>('/v1/data/start-over', body),

  // Dashboard (§2.7)
  dashboard: () => get<Dashboard>('/v1/dashboard'),
  getNotificationTriage: () => get<NotificationTriageResponse>('/v1/notifications/triage'),
  patchNotificationTriage: (id: string, body: NotificationTriageUpdateBody) =>
    patch<NotificationTriageUpdateResponse>(
      `/v1/notifications/triage/${encodeURIComponent(id)}`,
      body,
    ),
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
