import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { CitizenCardBridgePage } from './CitizenCardBridgePage';
import { renderWithProviders } from '../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';
import type {
  CitizenCardBridgeProbe,
  CitizenCardBridgeStatus,
} from './CitizenCardBridgeDiagnostics';

const hookMocks = vi.hoisted(() => ({
  status: vi.fn(),
  probe: vi.fn(),
}));

vi.mock('../../api/hooks', () => ({
  useCitizenCardBridgeStatus: hookMocks.status,
  useTestCitizenCardBridge: hookMocks.probe,
  // The shared ConfirmActionModal's step-up gate now reads the acting user's held methods and
  // step-up preference from these two hooks (to offer TOTP only to a holder, per t10 follow-on).
  // This suite fully mocks the hooks module, so both must be present or every render of the
  // private-key confirmation throws. Benign defaults reproduce today's behaviour: no confirmed
  // TOTP factor (so no TOTP arm) and no preference (so the gate opens on the password arm).
  useSession: () => ({
    data: { user: { has_totp: false, has_secret: true }, permissions: [] },
    isLoading: false,
  }),
  useUserPreferences: () => ({ data: { table_columns: {} }, isLoading: false }),
}));

const readyStatus: CitizenCardBridgeStatus = {
  transport: 'embedded_loopback',
  checked_at: '2026-07-25T11:00:00Z',
  local_desktop: true,
  diagnostic_source: 'runtime',
  middleware: { status: 'ready', detail: 'Middleware disponível.' },
  pcsc: { status: 'ready', detail: 'PC/SC disponível.' },
  readers: { status: 'ready', detail: 'Leitor disponível.' },
  reader_count: 1,
  card: { status: 'ready', detail: 'Cartão disponível.' },
  signing_certificate: { status: 'ready', detail: 'Certificado disponível.' },
  issuer: { status: 'ready', detail: 'Emissor resolvido.' },
  ready: true,
  probe_supported: true,
  document_signed: false,
  persisted: false,
  ledger_event_written: false,
  qualified_status_claimed: false,
};

const passedProbe: CitizenCardBridgeProbe = {
  outcome: 'passed',
  signature_verified: true,
  algorithm: 'RSA-SHA256',
  signing_certificate_present: true,
  issuer_resolved: true,
  tested_at: '2026-07-25T11:01:00Z',
  document_signed: false,
  persisted: false,
  document_ledger_event_written: false,
  security_audit_intent_recorded: true,
  security_audit_outcome_recorded: true,
  qualified_status_claimed: false,
};

function statusResult(overrides: Record<string, unknown> = {}) {
  return {
    data: readyStatus,
    error: null,
    isLoading: false,
    isFetching: false,
    refetch: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

function probeResult(overrides: Record<string, unknown> = {}) {
  return {
    data: null,
    error: null,
    isPending: false,
    mutateAsync: vi.fn().mockResolvedValue(passedProbe),
    ...overrides,
  };
}

beforeEach(() => {
  hookMocks.status.mockReturnValue(statusResult());
  hookMocks.probe.mockReturnValue(probeResult());
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('CitizenCardBridgePage', () => {
  it('loads the sanitized bridge status and refreshes without collecting local identifiers', () => {
    const refetch = vi.fn().mockResolvedValue(undefined);
    hookMocks.status.mockReturnValue(statusResult({ refetch }));
    renderWithProviders(<CitizenCardBridgePage />);

    expect(hookMocks.status).toHaveBeenCalledWith(true);
    expect(screen.getByRole('heading', { name: 'Ponte do Cartão de Cidadão' })).toBeTruthy();
    expect(screen.getByText('Middleware disponível.')).toBeTruthy();
    expect(screen.queryByRole('textbox')).toBeNull();
    expect(screen.queryByLabelText(/pin|certificado|leitor/i)).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Atualizar diagnósticos' }));
    expect(refetch).toHaveBeenCalledOnce();
  });

  it('requires both signing permissions and never opens the private-key confirmation without them', () => {
    const mutateAsync = vi.fn();
    hookMocks.probe.mockReturnValue(probeResult({ mutateAsync }));
    const permissions = permissionsValue((permission) => permission === 'signing.configure');

    renderWithProviders(
      <StaticPermissionsProvider value={permissions}>
        <CitizenCardBridgePage />
      </StaticPermissionsProvider>,
    );

    expect(
      (
        screen.getByRole('button', {
          name: 'Testar chave de assinatura',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(
      screen.getByText(
        'Necessita das permissões para configurar a assinatura e utilizar uma chave de assinatura.',
      ),
    ).toBeTruthy();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(mutateAsync).not.toHaveBeenCalled();
  });

  it('runs the parameterless key probe only after confirmation and closes on success', async () => {
    const mutateAsync = vi.fn().mockResolvedValue(passedProbe);
    hookMocks.probe.mockReturnValue(probeResult({ mutateAsync }));
    renderWithProviders(<CitizenCardBridgePage />);

    fireEvent.click(screen.getByRole('button', { name: 'Testar chave de assinatura' }));
    expect(mutateAsync).not.toHaveBeenCalled();
    const dialog = screen.getByRole('dialog', {
      name: 'Testar a chave do Cartão de Cidadão?',
    });
    expect(dialog).toBeTruthy();
    expect(
      screen.getByText(/regista o pedido na auditoria de segurança.*regista o resultado/i),
    ).toBeTruthy();
    expect(screen.queryByRole('textbox')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Testar chave' }));

    await waitFor(() => expect(mutateAsync).toHaveBeenCalledWith());
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('replaces raw bridge and key errors before rendering or toasting them', async () => {
    const privateDetail =
      'reader ACS-123 at C:\\Windows\\System32\\pteidpkcs11.dll certificate 00:11';
    hookMocks.status.mockReturnValue(statusResult({ data: null, error: new Error(privateDetail) }));
    hookMocks.probe.mockReturnValue(
      probeResult({ mutateAsync: vi.fn().mockRejectedValue(new Error(privateDetail)) }),
    );
    renderWithProviders(<CitizenCardBridgePage />);

    expect(
      screen.getByText(
        'Não foi possível obter o diagnóstico seguro da ponte do Cartão de Cidadão.',
      ),
    ).toBeTruthy();
    expect(screen.queryByText(privateDetail)).toBeNull();

    // A status failure cannot establish probe support, so exercise the modal after a fresh
    // successful status response while retaining the rejecting mutation.
    hookMocks.status.mockReturnValue(statusResult());
    cleanup();
    renderWithProviders(<CitizenCardBridgePage />);
    fireEvent.click(screen.getByRole('button', { name: 'Testar chave de assinatura' }));
    fireEvent.click(screen.getByRole('button', { name: 'Testar chave' }));

    expect(
      await screen.findAllByText(
        'Não foi possível concluir o teste seguro da chave do Cartão de Cidadão.',
      ),
    ).toHaveLength(2);
    expect(screen.queryByText(privateDetail)).toBeNull();
  });

  it('fails closed without signing configuration permission and disables the query', () => {
    const permissions = permissionsValue(() => false);
    renderWithProviders(
      <StaticPermissionsProvider value={permissions}>
        <CitizenCardBridgePage />
      </StaticPermissionsProvider>,
    );

    expect(hookMocks.status).toHaveBeenCalledWith(false);
    expect(screen.getByText(/sem permissão/i)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Atualizar diagnósticos' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Testar chave de assinatura' })).toBeNull();
  });
});
