/**
 * The AMA certificate field's «carregar de ficheiro» affordance, on both routes.
 *
 * `ProviderCredentialPage.test.tsx` covers the browser `<input type="file">` change event and the
 * clipboard. This file covers the BUTTON that reaches it, which is where the desktop/browser fork
 * lives: under Tauri it opens a native dialog, and it must degrade to the browser input rather
 * than leaving the operator with a control that silently does nothing. Every refusal the picker
 * can return has to arrive as a distinguishable visible notice — a cancelled dialog is not a
 * failure, an unreadable file is.
 *
 * The field must end up holding certificate TEXT and never a path: `ama_cert_pem` stores the
 * certificate itself, while `CHANCELA_CMD_AMA_CERT_PEM` is the variable that names a file, and
 * conflating the two is the mistake this control exists to make hard.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { ProviderCredentialPage } from './ProviderCredentialPage';
import { renderWithProviders } from '../../test/utils';
import { ptPT } from '../../i18n/locales/pt-PT';
import type { OpenTextFileOptions, OpenTextFileResult } from '../../desktop/openTextFile';
import type { ProviderCredentialsListView } from '../../api/types';

// Typed WITH its parameter, not as `() => …`: one case below reads
// `mock.calls[0][0]` to prove the native dialog is offered the same extensions and size
// ceiling as the browser input. A nullary mock type makes `calls` a `[]`, so that read is a
// compile error rather than an assertion — and dropping the read to satisfy the compiler
// would quietly retire the guarantee it exists to hold.
const openTextFileNative = vi.hoisted(() =>
  vi.fn<(options: OpenTextFileOptions) => Promise<OpenTextFileResult>>(),
);
vi.mock('../../desktop/openTextFile', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../desktop/openTextFile')>()),
  openTextFileNative,
}));

const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';

const list: ProviderCredentialsListView = {
  strict: false,
  protection_level: 'confidential',
  can_store: true,
  providers: [],
};

function stubFetch() {
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify(list), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    ) as unknown as typeof fetch,
  );
}

/** The CMD create page, where the AMA certificate field lives, with its field resolved. */
async function openCmdCreatePage() {
  stubFetch();
  renderWithProviders(
    <Routes>
      <Route path="/admin/signing/providers/new" element={<ProviderCredentialPage />} />
      <Route path="/admin/signing/providers" element={<span />} />
    </Routes>,
    ['/admin/signing/providers/new?mode=cmd'],
  );
  const field = (await screen.findByLabelText(
    ptPT['settings.providerCredentials.field.amaCertPem'],
  )) as HTMLTextAreaElement;
  const input = screen.getByTestId('ama-cert-file-input') as HTMLInputElement;
  // The browser fallback is a real, keyboard-reachable input; spying on `click` is how we observe
  // the button delegating to it without opening a picker jsdom cannot render.
  const browserPicker = vi.spyOn(input, 'click').mockImplementation(() => {});
  return { field, input, browserPicker };
}

function chooseFile() {
  fireEvent.click(screen.getByTestId('ama-cert-from-file'));
}

function inTauri() {
  (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
}

afterEach(() => {
  cleanup();
  delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
  openTextFileNative.mockReset();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('AMA certificate field — choosing a file', () => {
  it('uses the browser input outside the desktop shell, and never the native dialog', async () => {
    const { browserPicker } = await openCmdCreatePage();

    chooseFile();

    await waitFor(() => expect(browserPicker).toHaveBeenCalledTimes(1));
    expect(openTextFileNative).not.toHaveBeenCalled();
  });

  it('reads the native dialog result as TEXT under the desktop shell', async () => {
    inTauri();
    openTextFileNative.mockResolvedValue({ kind: 'opened', name: 'ama.pem', text: PEM });
    const { field, browserPicker } = await openCmdCreatePage();

    chooseFile();

    await waitFor(() => expect(field.value).toBe(PEM));
    // The name is feedback only; the path never becomes the field's value.
    expect(field.value).not.toContain('ama.pem');
    expect(browserPicker).not.toHaveBeenCalled();
  });

  it('offers the native dialog the same extensions and ceiling as the browser route', async () => {
    inTauri();
    openTextFileNative.mockResolvedValue({ kind: 'opened', name: 'ok.pem', text: PEM });
    const { input } = await openCmdCreatePage();

    chooseFile();

    await waitFor(() => expect(openTextFileNative).toHaveBeenCalledTimes(1));
    // No cast: the mock's own parameter type carries the shape, so a change to
    // `OpenTextFileOptions` fails HERE rather than being absorbed by a hand-written duplicate of
    // it. (A `Options | undefined` assertion would also make the two `?.` reads below vacuous —
    // an absent call would pass every one of them.)
    const options = openTextFileNative.mock.calls[0][0];
    // Derived from the input's own `accept`, so the two routes cannot drift into accepting
    // different files depending on whether the operator is on the desktop or in a browser.
    expect(options.extensions.map((extension) => `.${extension}`).join(',')).toBe(
      input.getAttribute('accept'),
    );
    expect(options.maxBytes).toBe(64 * 1024);
  });

  it('falls back to the browser input when the native plugins are unavailable', async () => {
    inTauri();
    openTextFileNative.mockResolvedValue({ kind: 'unavailable' });
    const { browserPicker } = await openCmdCreatePage();

    chooseFile();

    // A desktop build whose dialog plugin did not load must still be able to load a certificate.
    await waitFor(() => expect(browserPicker).toHaveBeenCalledTimes(1));
  });

  it('says nothing at all when the operator cancels the dialog', async () => {
    inTauri();
    openTextFileNative.mockResolvedValue({ kind: 'cancelled' });
    const { field } = await openCmdCreatePage();

    chooseFile();

    await waitFor(() => expect(openTextFileNative).toHaveBeenCalled());
    // Cancelling is a decision, not a failure: no alert, and the field is untouched.
    expect(screen.queryByRole('alert')).toBeNull();
    expect(field.value).toBe('');
  });

  it('reports an unreadable file rather than leaving the field silently empty', async () => {
    inTauri();
    openTextFileNative.mockResolvedValue({ kind: 'unreadable', name: 'locked.pem' });
    const { field } = await openCmdCreatePage();

    chooseFile();

    expect((await screen.findByRole('alert')).textContent?.trim()).toBeTruthy();
    expect(field.value).toBe('');
  });

  it('reports an oversized native pick without ever holding its bytes', async () => {
    inTauri();
    openTextFileNative.mockResolvedValue({
      kind: 'too-large',
      name: 'huge.pem',
      bytes: 900_000_000,
    });
    const { field } = await openCmdCreatePage();

    chooseFile();

    expect((await screen.findByRole('alert')).textContent?.trim()).toBeTruthy();
    expect(field.value).toBe('');
  });
});

describe('AMA certificate field — the browser input', () => {
  it('does nothing when the change event carries no file', async () => {
    const { field, input } = await openCmdCreatePage();

    Object.defineProperty(input, 'files', { value: [], configurable: true });
    fireEvent.change(input);

    expect(screen.queryByRole('alert')).toBeNull();
    expect(field.value).toBe('');
  });

  it('clears its own value so the SAME file can be chosen twice', async () => {
    const { field, input } = await openCmdCreatePage();
    const file = {
      name: 'ama.pem',
      size: PEM.length,
      text: () => Promise.resolve(PEM),
    } as unknown as File;

    Object.defineProperty(input, 'files', { value: [file], configurable: true });
    fireEvent.change(input);

    await waitFor(() => expect(field.value).toBe(PEM));
    // Left populated, the second `change` for an identical path would never fire and the button
    // would appear dead on the retry after an edit.
    expect(input.value).toBe('');
  });
});
