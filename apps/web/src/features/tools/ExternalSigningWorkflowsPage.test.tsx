import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import {
  DEFAULT_EXTERNAL_SIGNATURE_NOTICE_SNOOZE_DAYS,
  ExternalSigningWorkflowsPage,
  externalSignerInviteLink,
  informationalNoticeIsHidden,
} from './ExternalSigningWorkflowsPage';
import type {
  ActView,
  BookView,
  Entity,
  ExternalSignerInvitePublicView,
  ExternalSignerInviteStatus,
  ExternalSignerInviteView,
  UserPreferences,
} from '../../api/types';

const openExternalMock = vi.hoisted(() => vi.fn());

vi.mock('../../desktop/openExternal', () => ({
  openExternal: (url: string) => openExternalMock(url),
}));

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const ENTITY: Entity = {
  id: 'entity-1',
  tenant_id: 'tenant-1',
  group_id: null,
  name: 'Encosto Estratégico Lda',
  nipc: '500000000',
  nipc_validated: true,
  seat: 'Lisboa',
  family: 'CommercialCompany',
  kind: 'SociedadePorQuotas',
  fiscal_year_end: null,
  profile: {
    family: 'CommercialCompany',
    rule_pack_id: 'csc/v1',
    allowed_channels: ['Physical'],
    signature_policy: 'QualifiedOrHandwritten',
    template_family: 'commercial',
    calendar_presets: [],
    attendee_qualities: ['Member'],
  },
  statute: null,
};

const BOOK: BookView = {
  id: 'book-1',
  entity_id: ENTITY.id,
  kind: 'AssembleiaGeral',
  state: 'Open',
  purpose: null,
  numbering_scheme: 'Sequential',
  opening_date: null,
  closing_date: null,
  closing_reason: null,
  last_ata_number: 2,
  predecessor: null,
  required_signatories_abertura: null,
  required_signatories_encerramento: null,
};

function act(id: string, title: string, ataNumber: number): ActView {
  return {
    id,
    book_id: BOOK.id,
    title,
    channel: 'Physical',
    meeting_date: '2026-07-10',
    meeting_time: null,
    place: null,
    mesa: { presidente: null, secretarios: [] },
    agenda: [],
    attendance_reference: null,
    members_present: null,
    members_represented: null,
    referenced_documents: [],
    deliberations: '',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [],
    state: 'Sealed',
    ata_number: ataNumber,
    payload_digest: null,
    seal_event_seq: null,
    seal_metadata: null,
    retifies: null,
  };
}

const ACTS = [act('act-1', 'Ata de aprovação de contas', 1), act('act-2', 'Ata de eleição', 2)];

function invite(
  id: string,
  actId: string,
  name: string,
  status: ExternalSignerInviteStatus,
): ExternalSignerInviteView {
  return {
    id,
    act_id: actId,
    recipient_name: name,
    recipient_email: `${name.toLowerCase().replaceAll(' ', '.')}@example.test`,
    purpose: 'Acompanhar assinatura externa',
    status,
    workflow: 'tracking_only',
    token_hint: `cxi_${id.slice(-1)}…`,
    created_at: '2026-07-10T09:00:00Z',
    created_by: 'operator',
    expires_at: `2026-07-${11 + Number(id.slice(-1))}T12:00:00Z`,
    responded_at:
      status === 'accepted' || status === 'declined' ? '2026-07-10T10:00:00Z' : undefined,
  };
}

const INVITES: Record<string, ExternalSignerInviteView[]> = {
  'act-1': [
    invite('invite-1', 'act-1', 'Maria Pending', 'pending'),
    invite('invite-2', 'act-1', 'João Accepted', 'accepted'),
    invite('invite-3', 'act-1', 'Ana Declined', 'declined'),
  ],
  'act-2': [
    invite('invite-4', 'act-2', 'Rui Expired', 'expired'),
    { ...invite('invite-5', 'act-2', 'Sofia Revoked', 'revoked'), workflow: 'external_envelope' },
  ],
};

function envelopeFixture(
  status: ExternalSignerInviteStatus = 'pending',
): ExternalSignerInvitePublicView {
  return {
    invite_id: 'invite-token',
    act: {
      id: 'act-1',
      title: 'Ata de aprovação de contas',
      state: 'Sealed',
      meeting_date: '2026-07-10',
      ata_number: 1,
      entity_name: ENTITY.name,
      book_kind: BOOK.kind,
    },
    recipient_name: 'Maria Pending',
    purpose: 'Acompanhar assinatura externa',
    status,
    workflow: 'external_envelope',
    created_at: '2026-07-10T09:00:00Z',
    expires_at: '2026-07-12T12:00:00Z',
    notice: 'Tracking metadata only; no legal signing completion is claimed.',
  };
}

interface ExternalSigningFetchOptions {
  preferences?: UserPreferences;
  preferencesError?: boolean;
  temporaryHideDays?: number;
}

function externalSigningFetch(
  requests: { url: string; init?: RequestInit }[] = [],
  options: ExternalSigningFetchOptions = {},
): typeof fetch {
  let preferences = options.preferences ?? { table_columns: {} };
  return ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    requests.push({ url, init });
    const method = (init?.method ?? 'GET').toUpperCase();
    if (url.includes('/v1/me/preferences')) {
      if (method === 'GET' && options.preferencesError) {
        return Promise.resolve(jsonResponse({ error: 'preferences unavailable' }, 503));
      }
      if (method === 'PUT') preferences = JSON.parse(String(init?.body ?? '{}'));
      return Promise.resolve(jsonResponse(preferences));
    }
    if (url.includes('/v1/settings')) {
      return Promise.resolve(
        jsonResponse({
          ui: {
            registered_entity_columns: [],
            external_signature_notice_snooze_days:
              options.temporaryHideDays ?? DEFAULT_EXTERNAL_SIGNATURE_NOTICE_SNOOZE_DAYS,
            phone_pairing_share_email_enabled: true,
            phone_pairing_share_whatsapp_enabled: true,
          },
        }),
      );
    }
    if (url.includes('/v1/books/book-1/acts')) return Promise.resolve(jsonResponse(ACTS));
    if (url.includes('/v1/acts/act-1/signature/external-invites')) {
      return Promise.resolve(jsonResponse(INVITES['act-1']));
    }
    if (url.includes('/v1/acts/act-2/signature/external-invites')) {
      return Promise.resolve(jsonResponse(INVITES['act-2']));
    }
    if (url.includes('/v1/signature/external-invites/lookup')) {
      return Promise.resolve(jsonResponse(envelopeFixture()));
    }
    if (url.includes('/v1/entities')) return Promise.resolve(jsonResponse([ENTITY]));
    if (url.includes('/v1/books')) return Promise.resolve(jsonResponse([BOOK]));
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  openExternalMock.mockReset();
});

describe('ExternalSigningWorkflowsPage', () => {
  it('persists the configured temporary notice dismissal and keeps it hidden after remount', async () => {
    const requests: { url: string; init?: RequestInit }[] = [];
    const now = Date.parse('2026-07-25T12:00:00Z');
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const fetcher = externalSigningFetch(requests, {
      temporaryHideDays: 30,
      preferences: { table_columns: { books: ['Kind', 'Actions'] } },
    });
    vi.stubGlobal('fetch', fetcher);
    renderWithProviders(<ExternalSigningWorkflowsPage />, ['/tools/external-signing']);

    const actions = await screen.findByRole('group', {
      name: 'Opções para ocultar este aviso',
    });
    const temporary = within(actions).getByRole('button', {
      name: 'Ocultar durante 30 dias',
    });
    expect(within(actions).getByRole('button', { name: 'Ocultar permanentemente' })).toBeTruthy();
    fireEvent.click(temporary);

    await waitFor(() =>
      expect(
        requests.some(
          (request) =>
            request.url.includes('/v1/me/preferences') &&
            (request.init?.method ?? 'GET').toUpperCase() === 'PUT',
        ),
      ).toBe(true),
    );
    const put = requests.find(
      (request) =>
        request.url.includes('/v1/me/preferences') &&
        (request.init?.method ?? 'GET').toUpperCase() === 'PUT',
    );
    expect(JSON.parse(String(put?.init?.body))).toEqual({
      table_columns: { books: ['Kind', 'Actions'] },
      external_signature_notice_dismissal: {
        mode: 'snoozed',
        until: '2026-08-24T12:00:00.000Z',
      },
    });
    await waitFor(() =>
      expect(screen.queryByRole('group', { name: 'Opções para ocultar este aviso' })).toBeNull(),
    );

    cleanup();
    renderWithProviders(<ExternalSigningWorkflowsPage />, ['/tools/external-signing']);
    await screen.findByText('Maria Pending');
    expect(screen.queryByRole('group', { name: 'Opções para ocultar este aviso' })).toBeNull();
  });

  it('persists permanent notice dismissal as an explicit durable preference', async () => {
    const requests: { url: string; init?: RequestInit }[] = [];
    vi.stubGlobal('fetch', externalSigningFetch(requests));
    renderWithProviders(<ExternalSigningWorkflowsPage />, ['/tools/external-signing']);

    const actions = await screen.findByRole('group', {
      name: 'Opções para ocultar este aviso',
    });
    fireEvent.click(within(actions).getByRole('button', { name: 'Ocultar permanentemente' }));

    await waitFor(() => {
      const put = requests.find(
        (request) =>
          request.url.includes('/v1/me/preferences') &&
          (request.init?.method ?? 'GET').toUpperCase() === 'PUT',
      );
      expect(JSON.parse(String(put?.init?.body))).toEqual({
        table_columns: {},
        external_signature_notice_dismissal: { mode: 'permanent' },
      });
    });
  });

  it('keeps the notice visible but exposes no replacement PUT when preferences fail to load', async () => {
    const requests: { url: string; init?: RequestInit }[] = [];
    vi.stubGlobal('fetch', externalSigningFetch(requests, { preferencesError: true }));
    renderWithProviders(<ExternalSigningWorkflowsPage />, ['/tools/external-signing']);

    expect(await screen.findByText(/não conclui uma assinatura qualificada/i)).toBeTruthy();
    expect(screen.queryByRole('group', { name: 'Opções para ocultar este aviso' })).toBeNull();
    expect(screen.queryByRole('button', { name: /Ocultar durante/i })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Ocultar permanentemente' })).toBeNull();
    expect(
      requests.some(
        (request) =>
          request.url.includes('/v1/me/preferences') &&
          (request.init?.method ?? 'GET').toUpperCase() === 'PUT',
      ),
    ).toBe(false);
  });

  it('treats only future temporary and permanent dismissals as hidden', () => {
    const now = Date.parse('2026-07-25T12:00:00Z');
    expect(
      informationalNoticeIsHidden({ mode: 'snoozed', until: '2026-07-26T12:00:00Z' }, now),
    ).toBe(true);
    expect(
      informationalNoticeIsHidden({ mode: 'snoozed', until: '2026-07-24T12:00:00Z' }, now),
    ).toBe(false);
    expect(informationalNoticeIsHidden({ mode: 'permanent' }, now)).toBe(true);
  });

  it('normalizes the two External Signatures cards and notice action spacing in scoped CSS', async () => {
    const nodeFs = 'node:fs';
    const { readFileSync } = (await import(nodeFs)) as {
      readFileSync(path: string, encoding: 'utf8'): string;
    };
    const css = readFileSync('src/theme.css', 'utf8').replace(/\r\n/g, '\n');

    expect(css).toMatch(/\.external-signing-workflows\s*>\s*\.panel\s*\{[^}]*margin-block:\s*0;/s);
    expect(css).toMatch(
      /\.external-signing-workflows\s*>\s*\.panel\s*\+\s*\.panel\s*\{[^}]*margin-top:\s*1rem;/s,
    );
    expect(css).toMatch(
      /\.external-signing-notice__actions\s*\{[^}]*display:\s*flex;[^}]*gap:\s*0\.55rem;[^}]*margin-top:\s*0\.75rem;/s,
    );
  });

  it('lists external invite statuses with technical-only workflow limits', async () => {
    vi.stubGlobal('fetch', externalSigningFetch());
    renderWithProviders(<ExternalSigningWorkflowsPage />, ['/tools?tool=external-signing']);

    expect(await screen.findByText('Maria Pending')).toBeTruthy();
    expect(screen.getByText('João Accepted')).toBeTruthy();
    expect(screen.getByText('Ana Declined')).toBeTruthy();
    expect(screen.getByText('Rui Expired')).toBeTruthy();
    expect(screen.getByText('Sofia Revoked')).toBeTruthy();

    for (const status of ['Pendente', 'Aceite', 'Declinado', 'Expirado', 'Revogado']) {
      expect(screen.getByText(status)).toBeTruthy();
    }
    expect(screen.getAllByText('Acompanhamento apenas').length).toBeGreaterThanOrEqual(4);
    expect(screen.getByText('Fluxo com envelope')).toBeTruthy();
    expect(screen.queryByText('external_envelope')).toBeNull();
    expect(screen.getAllByText('Só acompanhamento técnico').length).toBeGreaterThanOrEqual(5);
    expect(screen.getAllByText('Token completo não guardado').length).toBeGreaterThanOrEqual(5);
    expect(screen.getByText(/não afirma validade legal/i)).toBeTruthy();
  });

  it('builds same-origin invite links safely and keeps lookup tokens out of the URL', async () => {
    const requests: { url: string; init?: RequestInit }[] = [];
    vi.stubGlobal('fetch', externalSigningFetch(requests));
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });

    renderWithProviders(<ExternalSigningWorkflowsPage />, ['/tools?tool=external-signing']);

    const unsafeLookingToken = 'javascript:alert(1)&next=https://evil.test';
    const expected = externalSignerInviteLink(unsafeLookingToken, window.location.origin);
    fireEvent.change(screen.getByLabelText('Token do convite'), {
      target: { value: ` ${unsafeLookingToken} ` },
    });

    expect(await screen.findByText(expected!)).toBeTruthy();
    expect(expected).toContain('/external-signature?token=javascript%3Aalert');
    expect(expected).not.toContain('token=javascript:alert');

    fireEvent.click(screen.getByRole('button', { name: 'Copiar ligação' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(expected));

    fireEvent.click(screen.getByRole('button', { name: 'Abrir ligação' }));
    expect(openExternalMock).toHaveBeenCalledWith(expected);

    fireEvent.click(screen.getByRole('button', { name: 'Consultar envelope' }));
    const envelopeTitle = await screen.findByText('Envelope público');
    const envelopeDetails = envelopeTitle.closest('.external-signing-envelope');
    expect(envelopeDetails).not.toBeNull();
    expect(within(envelopeDetails as HTMLElement).getByText('Fluxo com envelope')).toBeTruthy();
    expect(within(envelopeDetails as HTMLElement).queryByText('external_envelope')).toBeNull();
    const lookup = requests.find((request) =>
      request.url.includes('/v1/signature/external-invites/lookup'),
    );
    expect(lookup?.url).toBe('/v1/signature/external-invites/lookup');
    expect(JSON.parse(String(lookup?.init?.body))).toEqual({ token: unsafeLookingToken });
  });
});
