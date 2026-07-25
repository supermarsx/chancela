import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { i18nStore } from '../../i18n/store';
import {
  CitizenCardBridgeDiagnostics,
  type CitizenCardBridgeProbe,
  type CitizenCardBridgeStatus,
} from './CitizenCardBridgeDiagnostics';

function readyStatus(overrides: Partial<CitizenCardBridgeStatus> = {}): CitizenCardBridgeStatus {
  return {
    transport: 'embedded_loopback',
    checked_at: '2026-07-25T10:00:00Z',
    local_desktop: true,
    diagnostic_source: 'real',
    middleware: { status: 'ready' },
    pcsc: { status: 'ready' },
    readers: { status: 'ready' },
    reader_count: 1,
    card: { status: 'ready' },
    signing_certificate: { status: 'ready' },
    issuer: { status: 'ready' },
    ready: true,
    probe_supported: true,
    document_signed: false,
    persisted: false,
    ledger_event_written: false,
    qualified_status_claimed: false,
    ...overrides,
  };
}

function passedProbe(overrides: Partial<CitizenCardBridgeProbe> = {}): CitizenCardBridgeProbe {
  return {
    outcome: 'passed',
    signature_verified: true,
    algorithm: 'RSA-SHA256',
    signing_certificate_present: true,
    issuer_resolved: true,
    tested_at: '2026-07-25T10:00:00Z',
    error: null,
    document_signed: false,
    persisted: false,
    document_ledger_event_written: false,
    security_audit_intent_recorded: true,
    security_audit_outcome_recorded: true,
    qualified_status_claimed: false,
    ...overrides,
  };
}

function renderPanel(props: Partial<ComponentProps<typeof CitizenCardBridgeDiagnostics>> = {}) {
  const onRefresh = vi.fn();
  const onTest = vi.fn();
  render(
    <CitizenCardBridgeDiagnostics
      status={readyStatus()}
      onRefresh={onRefresh}
      onTest={onTest}
      {...props}
    />,
  );
  return { onRefresh, onTest };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  i18nStore.setActiveLocale('pt-PT');
});

describe('CitizenCardBridgeDiagnostics', () => {
  it('uses the English fallback outside pt-PT without relying on shared catalog changes', () => {
    i18nStore.setActiveLocale('en-GB');
    renderPanel();

    expect(screen.getByRole('heading', { name: 'Citizen Card' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Test signing key' })).toBeTruthy();
    expect(screen.getByText(/creates no document/i)).toBeTruthy();
  });

  it('presents all desktop bridge prerequisites in a compact diagnostics table', () => {
    renderPanel();

    expect(
      screen.getByRole('table', { name: 'Diagnóstico da ponte local do Cartão de Cidadão' }),
    ).toBeTruthy();
    expect(screen.getByRole('rowheader', { name: 'Aplicação de secretária local' })).toBeTruthy();
    expect(screen.getByRole('rowheader', { name: 'Middleware do Cartão de Cidadão' })).toBeTruthy();
    expect(screen.getByRole('rowheader', { name: 'PC/SC' })).toBeTruthy();
    expect(screen.getByRole('rowheader', { name: 'Leitores' })).toBeTruthy();
    expect(screen.getByRole('rowheader', { name: 'Cartão inserido' })).toBeTruthy();
    expect(
      screen.getByRole('rowheader', { name: 'Certificado de assinatura selecionado' }),
    ).toBeTruthy();
    expect(screen.getByRole('rowheader', { name: 'Emissor e cadeia de confiança' })).toBeTruthy();
    expect(screen.getByRole('rowheader', { name: 'Prontidão para assinatura' })).toBeTruthy();
    expect(screen.getByText('1 detetado(s)')).toBeTruthy();
    expect(screen.getByRole('rowheader', { name: 'Verificado em' })).toBeTruthy();
  });

  it('is explicit when it is not running in the desktop bridge', () => {
    renderPanel({
      status: readyStatus({
        local_desktop: false,
        ready: false,
        probe_supported: false,
        middleware: { status: 'not_checked' },
        pcsc: { status: 'not_checked' },
      }),
    });

    expect(screen.getByText(/requer a aplicação de secretária/i)).toBeTruthy();
    expect(
      screen.getByText(/teste fica disponível quando a ponte local estiver disponível/i),
    ).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Testar chave de assinatura' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it('shows partial diagnostic failures without treating the bridge as ready, while still allowing a key probe', () => {
    renderPanel({
      status: readyStatus({
        ready: false,
        issuer: {
          status: 'unavailable',
          code: 'issuer_not_resolved',
          detail: 'O emissor ainda não foi encontrado na lista de confiança.',
        },
      }),
    });

    expect(screen.getByText('issuer_not_resolved')).toBeTruthy();
    expect(screen.getByText(/a ponte ainda não está pronta para assinar/i)).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Testar chave de assinatura' }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
  });

  it('calls only the supplied parameterless refresh and test actions', () => {
    const { onRefresh, onTest } = renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Atualizar diagnósticos' }));
    fireEvent.click(screen.getByRole('button', { name: 'Testar chave de assinatura' }));

    expect(onRefresh).toHaveBeenCalledTimes(1);
    expect(onRefresh).toHaveBeenCalledWith();
    expect(onTest).toHaveBeenCalledTimes(1);
    expect(onTest).toHaveBeenCalledWith();
  });

  it('renders a successful challenge probe without claiming a document signature', () => {
    renderPanel({ probe: passedProbe() });

    expect(screen.getByTestId('cc-bridge-probe-result').textContent).toContain('Teste concluído');
    expect(screen.getByText('RSA-SHA256')).toBeTruthy();
    expect(screen.getByText(/assina apenas um desafio efémero/i)).toBeTruthy();
    expect(screen.getByText(/não cria documento/i)).toBeTruthy();
    expect(screen.getByText(/não cria documento nem grava evento num livro de atas/i)).toBeTruthy();
    expect(screen.getByText('Pedido e resultado registados')).toBeTruthy();
    expect(screen.getByText('Nenhum evento gravado')).toBeTruthy();
    expect(
      screen.getByText(
        /não faz qualquer declaração de validade legal ou de assinatura qualificada/i,
      ),
    ).toBeTruthy();
  });

  it('renders a failed challenge probe with its sanitized diagnostic', () => {
    renderPanel({
      probe: passedProbe({
        outcome: 'failed',
        signature_verified: false,
        algorithm: null,
        error: { code: 'card_removed', detail: 'O cartão deixou de estar disponível.' },
      }),
    });

    expect(screen.getByTestId('cc-bridge-probe-result').textContent).toContain('Teste falhou');
    expect(screen.getByText('card_removed')).toBeTruthy();
    expect(screen.getByText('O cartão deixou de estar disponível.')).toBeTruthy();
  });

  it('does not render a credential field', () => {
    renderPanel();

    expect(document.querySelectorAll('input, textarea, select')).toHaveLength(0);
    expect(screen.queryByLabelText(/pin/i)).toBeNull();
    expect(screen.queryByPlaceholderText(/pin/i)).toBeNull();
  });
});
