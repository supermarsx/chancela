import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './client';
import { useCitizenCardBridgeStatus, useTestCitizenCardBridge } from './hooks';
import type { CitizenCardBridgeProbe, CitizenCardBridgeStatus } from './types';

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

const status: CitizenCardBridgeStatus = {
  transport: 'embedded_loopback',
  local_desktop: true,
  checked_at: '2026-07-25T12:00:00Z',
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
};

const probe: CitizenCardBridgeProbe = {
  outcome: 'passed',
  signature_verified: true,
  algorithm: 'rsa_sha256',
  signing_certificate_present: true,
  issuer_resolved: true,
  tested_at: '2026-07-25T12:01:00Z',
  document_signed: false,
  persisted: false,
  document_ledger_event_written: false,
  security_audit_intent_recorded: true,
  security_audit_outcome_recorded: true,
  qualified_status_claimed: false,
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('Citizen Card bridge API', () => {
  it('sends the private-key probe with no request body', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(probe), {
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(api.testCitizenCardBridge()).resolves.toEqual(probe);
    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/signature/cc/bridge/test',
      expect.objectContaining({
        method: 'POST',
        body: undefined,
      }),
    );
  });

  it('gates the status query and exposes the parameterless test mutation', async () => {
    const read = vi.spyOn(api, 'getCitizenCardBridgeStatus').mockResolvedValue(status);
    const test = vi.spyOn(api, 'testCitizenCardBridge').mockResolvedValue(probe);
    const disabled = renderHook(() => useCitizenCardBridgeStatus(false), { wrapper });
    expect(read).not.toHaveBeenCalled();
    disabled.unmount();

    const enabled = renderHook(() => useCitizenCardBridgeStatus(true), { wrapper });
    await waitFor(() => expect(enabled.result.current.data).toBe(status));
    expect(read).toHaveBeenCalledOnce();

    const mutation = renderHook(() => useTestCitizenCardBridge(), { wrapper });
    await act(async () => {
      await mutation.result.current.mutateAsync();
    });
    expect(test).toHaveBeenCalledWith();
    await waitFor(() => expect(mutation.result.current.data).toBe(probe));
  });
});
