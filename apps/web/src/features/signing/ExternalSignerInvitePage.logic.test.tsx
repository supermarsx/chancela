import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { ApiError } from '../../api/client';
import type { ExternalSignerInvitePublicView } from '../../api/types';
import type { TFunction } from '../../i18n';
import {
  EXTERNAL_INVITE_SIGNED_PDF_RAW_MAX_BYTES,
  canUploadExternalInviteSignedPdf,
  externalInviteFileToBase64,
  externalInviteSignedPdfSizeError,
  externalInviteSlotStatusBadge,
  externalInviteSlotStatusLabel,
  externalInviteStatusBadge,
  externalInviteUnavailableMessage,
  formatExternalInviteBytes,
} from './ExternalSignerInvitePage';

const t = ((key: string, params?: Record<string, unknown>) =>
  params?.max ? `${key}:${String(params.max)}` : key) as TFunction;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('external signer invite presentation and file helpers', () => {
  // Dates are no longer formatted here: the page renders them through the shared
  // <DateTime>/<DateOnly> components (t66), which own the null/invalid behaviour.
  it('formats byte sizes defensively', () => {
    expect(formatExternalInviteBytes(-1)).toBe('unknown');
    expect(formatExternalInviteBytes(Number.NaN)).toBe('unknown');
    expect(formatExternalInviteBytes(512)).toBe('512 bytes');
    expect(formatExternalInviteBytes(1536)).toBe('1.5 KB');
    expect(formatExternalInviteBytes(10 * 1024)).toBe('10 KB');
    expect(formatExternalInviteBytes(2 * 1024 * 1024)).toBe('2 MB');
    expect(formatExternalInviteBytes(3 * 1024 * 1024 * 1024)).toBe('3 GB');
  });

  it('renders every invite and envelope-slot status with an honest tone', () => {
    const inviteStatuses = ['pending', 'accepted', 'declined', 'expired', 'revoked'] as const;
    const inviteView = render(
      <>{inviteStatuses.map((status) => externalInviteStatusBadge(status, t))}</>,
    );
    for (const status of inviteStatuses) {
      expect(inviteView.getByText(`externalInvite.status.${status}`).className).toContain(
        'badge--',
      );
    }
    inviteView.unmount();

    const slotStatuses = [
      'pending',
      'initiated',
      'signed',
      'declined',
      'revoked',
      'expired',
    ] as const;
    render(<>{slotStatuses.map((status) => externalInviteSlotStatusBadge(status, t))}</>);
    for (const status of slotStatuses) {
      expect(externalInviteSlotStatusLabel(status, t)).toBe(
        `signing.envelopes.slot.status.${status}`,
      );
      expect(screen.getByText(`signing.envelopes.slot.status.${status}`)).toBeTruthy();
    }
  });

  it('distinguishes unavailable tokens from ordinary request failures', () => {
    const unavailable = render(
      <>{externalInviteUnavailableMessage(new ApiError(404, { error: 'missing' }), t)}</>,
    );
    expect(unavailable.getByText('externalInvite.unavailable.title')).toBeTruthy();
    expect(unavailable.getByText('externalInvite.unavailable.body')).toBeTruthy();
    unavailable.unmount();

    render(<>{externalInviteUnavailableMessage(new Error('offline'), t)}</>);
    expect(screen.getByText('offline')).toBeTruthy();
  });

  it('encodes native file bytes and FileReader fallback bytes', async () => {
    await expect(
      externalInviteFileToBase64({
        arrayBuffer: async () => new Uint8Array([0, 1, 254, 255]).buffer,
      } as File),
    ).resolves.toBe('AAH+/w==');

    class Reader {
      result: ArrayBuffer | string | null = null;
      error: Error | null = null;
      onload: null | (() => void) = null;
      onerror: null | (() => void) = null;
      readAsArrayBuffer(file: File) {
        this.result = file.name === 'wrong.pdf' ? 'wrong' : new Uint8Array([9]).buffer;
        this.onload?.();
      }
    }
    vi.stubGlobal('FileReader', Reader);
    await expect(externalInviteFileToBase64({ name: 'ok.pdf' } as File)).resolves.toBe('CQ==');
    await expect(externalInviteFileToBase64({ name: 'wrong.pdf' } as File)).rejects.toThrow(
      'Could not read the selected PDF.',
    );

    Reader.prototype.readAsArrayBuffer = function () {
      this.error = new Error('reader failed');
      this.onerror?.();
    };
    await expect(externalInviteFileToBase64({ name: 'bad.pdf' } as File)).rejects.toThrow(
      'reader failed',
    );
  });

  it('enforces upload size and workflow eligibility', () => {
    expect(
      externalInviteSignedPdfSizeError(
        { size: EXTERNAL_INVITE_SIGNED_PDF_RAW_MAX_BYTES } as File,
        t,
      ),
    ).toBeNull();
    expect(
      externalInviteSignedPdfSizeError(
        { size: EXTERNAL_INVITE_SIGNED_PDF_RAW_MAX_BYTES + 1 } as File,
        t,
      )?.message,
    ).toContain('externalInvite.upload.file.tooLarge:16 MB');

    expect(
      canUploadExternalInviteSignedPdf({
        workflow: 'external_envelope',
        external_envelope: { id: 'envelope-1' },
      } as ExternalSignerInvitePublicView),
    ).toBe(true);
    expect(
      canUploadExternalInviteSignedPdf({
        workflow: 'external_envelope',
        external_envelope: null,
      } as unknown as ExternalSignerInvitePublicView),
    ).toBe(false);
    expect(
      canUploadExternalInviteSignedPdf({
        workflow: 'tracking_only',
        external_envelope: { id: 'envelope-1' },
      } as ExternalSignerInvitePublicView),
    ).toBe(false);
  });
});
