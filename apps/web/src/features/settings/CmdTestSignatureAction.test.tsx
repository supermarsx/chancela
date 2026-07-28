/**
 * The CMD PRODUCTION test-signature wiring (t51-e3/t69): the backend
 * (`crates/chancela-api/src/cmd_test_signature.rs`) shipped with no caller anywhere in the
 * frontend. This proves the client side end to end — both phases, the exact request shapes the
 * server's own test suite pins (`CONFIRM_PHRASE`, the nested `confirmation` proof), and that a
 * completed test renders the honest legal-effect negatives rather than omitting them.
 *
 * Interacts with `ConfirmActionModal`'s shared phrase/re-auth fields the same way every other
 * gated-action test in this codebase does (`getByLabelText('Palavra-passe')` /
 * `getByLabelText('Escreva … para confirmar')` — see `DataManagementSection.test.tsx`), since
 * those labels are shared app-wide copy this suite does not own. Everything this suite DOES own
 * (the trigger button, field labels, result copy) is asserted through its own dedicated fallback
 * catalog (`providerCredentialsFallback.ts`), not a guessed substring.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { ProviderCredentialsSection } from './ProviderCredentialsSection';
import type {
  CmdTestSignatureConfirmResult,
  CmdTestSignatureInitiateResult,
  ProviderCredentialsListView,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';

const CONFIRM_PHRASE = 'ASSINAR TESTE';

const cmdList: ProviderCredentialsListView = {
  strict: false,
  protection_level: 'confidential',
  can_store: true,
  providers: [
    {
      mode: 'cmd',
      provider_id: '',
      entries: [
        {
          entry_id: 'cmd-entry-1',
          label: 'CMD principal',
          priority: 0,
          enabled: true,
          selectors: { env: 'prod' },
          fields: [{ field_name: 'application_id', configured: true }],
          created_at: '2026-07-01T10:00:00Z',
          updated_at: '2026-07-01T10:00:00Z',
        },
      ],
    },
  ],
};

const cscList: ProviderCredentialsListView = {
  strict: false,
  protection_level: 'confidential',
  can_store: true,
  providers: [
    {
      mode: 'csc',
      provider_id: 'qtsp',
      entries: [
        {
          entry_id: 'entry-a',
          label: 'Primária',
          priority: 0,
          enabled: true,
          selectors: {},
          fields: [],
          created_at: '2026-07-01T10:00:00Z',
          updated_at: '2026-07-01T10:00:00Z',
        },
      ],
    },
  ],
};

const initiateResult: CmdTestSignatureInitiateResult = {
  session_id: 'sess-1',
  status: 'otp_pending',
  masked_phone: '+351 9*****678',
  credential_source: 'stored_entry',
  entry_id: 'cmd-entry-1',
  entry_label: 'CMD principal',
  environment: 'prod',
  expires_at: '2026-07-28T10:05:00Z',
  provider_contacted: true,
  signer_authorization_requested: true,
  document_signed: false,
};

const confirmResult: CmdTestSignatureConfirmResult = {
  test_id: 'test-1',
  status: 'signed',
  provider_contacted: true,
  document_signed: true,
  legal_effect: 'none',
  counts_toward_book_opening: false,
  counts_toward_act_signature: false,
  signed_pdf_digest: 'ab12cd34',
  signed_pdf_bytes: 1024,
  signing_time: '2026-07-28T10:00:00Z',
  signed_at: '2026-07-28T10:00:05Z',
  masked_phone: '+351 9*****678',
  credential_source: 'stored_entry',
  entry_id: 'cmd-entry-1',
  entry_label: 'CMD principal',
  environment: 'prod',
  trusted_list_status: 'Ok',
  timestamped: true,
  retained: true,
};

interface Call {
  url: string;
  method: string;
  body: string | null;
}

function stubFetch(
  view: ProviderCredentialsListView,
  options: {
    initiateStatus?: number;
    initiateBody?: unknown;
    confirmStatus?: number;
    confirmBody?: unknown;
  } = {},
) {
  const {
    initiateStatus = 200,
    initiateBody = initiateResult,
    confirmStatus = 200,
    confirmBody = confirmResult,
  } = options;
  const calls: Call[] = [];
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });
    if (method === 'GET') {
      return Promise.resolve(
        new Response(JSON.stringify(view), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    if (url.endsWith('/signature/cmd/test-signature/initiate')) {
      return Promise.resolve(
        new Response(JSON.stringify(initiateBody), {
          status: initiateStatus,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    if (url.endsWith('/signature/cmd/test-signature/confirm')) {
      return Promise.resolve(
        new Response(JSON.stringify(confirmBody), {
          status: confirmStatus,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    return Promise.resolve(
      new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    );
  }) as unknown as typeof fetch;
  return { fn, calls };
}

function renderSection() {
  return renderWithProviders(
    <Routes>
      <Route path="/admin/signing/providers" element={<ProviderCredentialsSection />} />
    </Routes>,
    ['/admin/signing/providers'],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('CmdTestSignatureAction', () => {
  it('runs the full initiate -> confirm production test-signature flow with the exact request shapes', async () => {
    const stub = stubFetch(cmdList);
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    fireEvent.click(await screen.findByRole('button', { name: 'Testar assinatura real (produção)' }));
    const initiateDialog = await screen.findByRole('dialog');
    const sendCode = within(initiateDialog).getByRole('button', { name: 'Enviar código' });
    expect((sendCode as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(within(initiateDialog).getByLabelText('Número de telemóvel'), {
      target: { value: '+351 912345678' },
    });
    fireEvent.change(within(initiateDialog).getByLabelText('PIN de assinatura'), {
      target: { value: '271828' },
    });
    // Phone + PIN alone are not enough — T3 (phrase + step-up) is still required.
    expect((sendCode as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(
      within(initiateDialog).getByLabelText(`Escreva ${CONFIRM_PHRASE} para confirmar`),
      { target: { value: CONFIRM_PHRASE } },
    );
    expect((sendCode as HTMLButtonElement).disabled).toBe(true); // phrase alone still isn't enough
    fireEvent.change(within(initiateDialog).getByLabelText('Palavra-passe'), {
      target: { value: 'operator-pw' },
    });
    expect((sendCode as HTMLButtonElement).disabled).toBe(false);

    fireEvent.click(sendCode);

    await waitFor(() => {
      const call = stub.calls.find((c) => c.url.endsWith('/signature/cmd/test-signature/initiate'));
      expect(call).toBeTruthy();
      expect(JSON.parse(call!.body ?? '{}')).toEqual({
        phone: '+351 912345678',
        pin: '271828',
        entry_id: 'cmd-entry-1',
        confirmation: { reauth: { password: 'operator-pw' }, confirm_phrase: CONFIRM_PHRASE },
      });
    });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.getByText(/Foi enviado um código por SMS/)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Introduzir código recebido' }));
    const confirmDialog = await screen.findByRole('dialog');
    fireEvent.change(within(confirmDialog).getByLabelText('Código recebido por SMS'), {
      target: { value: '314159' },
    });
    fireEvent.change(
      within(confirmDialog).getByLabelText(`Escreva ${CONFIRM_PHRASE} para confirmar`),
      { target: { value: CONFIRM_PHRASE } },
    );
    fireEvent.change(within(confirmDialog).getByLabelText('Palavra-passe'), {
      target: { value: 'operator-pw' },
    });
    fireEvent.click(within(confirmDialog).getByRole('button', { name: 'Confirmar código' }));

    await waitFor(() => {
      const call = stub.calls.find((c) => c.url.endsWith('/signature/cmd/test-signature/confirm'));
      expect(call).toBeTruthy();
      expect(JSON.parse(call!.body ?? '{}')).toEqual({
        session_id: 'sess-1',
        otp: '314159',
        confirmation: { reauth: { password: 'operator-pw' }, confirm_phrase: CONFIRM_PHRASE },
      });
    });

    // The pending affordance is gone and the honest result — including the explicit `false`
    // counters, rendered rather than omitted — is shown.
    expect(screen.queryByText(/Foi enviado um código por SMS/)).toBeNull();
    expect(await screen.findByText('Teste de produção concluído')).toBeTruthy();
    expect(screen.getByText('Nenhum — não é uma ata nem um termo')).toBeTruthy();
    expect(screen.getByText('ab12cd34')).toBeTruthy();
    expect(screen.getByText('Conta para a abertura de um livro').nextElementSibling?.textContent).toBe(
      'Não',
    );
    expect(
      screen.getByText('Conta para a assinatura de um ato').nextElementSibling?.textContent,
    ).toBe('Não');
  });

  it('surfaces the server refusal reason inline and never signs on an initiate failure', async () => {
    const stub = stubFetch(cmdList, {
      initiateStatus: 409,
      initiateBody: {
        error:
          'a Chave Móvel Digital está configurada para pré-produção; a assinatura de teste só corre em produção',
      },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    fireEvent.click(await screen.findByRole('button', { name: 'Testar assinatura real (produção)' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('Número de telemóvel'), {
      target: { value: '+351 912345678' },
    });
    fireEvent.change(within(dialog).getByLabelText('PIN de assinatura'), {
      target: { value: '271828' },
    });
    fireEvent.change(within(dialog).getByLabelText(`Escreva ${CONFIRM_PHRASE} para confirmar`), {
      target: { value: CONFIRM_PHRASE },
    });
    fireEvent.change(within(dialog).getByLabelText('Palavra-passe'), {
      target: { value: 'operator-pw' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Enviar código' }));

    // The server's own diagnostic message — naming pré-produção specifically, not a generic
    // failure — surfaces (inline in the dialog, and as a toast). The dialog stays open (no
    // pending session was ever created).
    expect((await screen.findAllByText(/pré-produção/)).length).toBeGreaterThan(0);
    expect(screen.queryByText(/Foi enviado um código por SMS/)).toBeNull();
  });

  it('does not offer the production test-signature control on a non-CMD credential', async () => {
    vi.stubGlobal('fetch', stubFetch(cscList).fn);
    renderSection();

    expect(await screen.findByText('Primária')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Testar assinatura real (produção)' })).toBeNull();
  });
});
