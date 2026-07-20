/**
 * The guard's three exits (t52): browser unload, in-app navigation, desktop window close.
 *
 * The desktop path is exercised through a mocked `@tauri-apps/api/window` plus the
 * `__TAURI_INTERNALS__` global that {@link ../desktop/tauri isTauri} keys on, so the real
 * shell contract (veto → confirm → destroy) is asserted without a WebView.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Link, RouterProvider, createMemoryRouter } from 'react-router-dom';
import { useState, type ReactNode } from 'react';
import { UnsavedChangesGuard } from './UnsavedChangesGuard';
import { useUnsavedChanges } from '../hooks/useUnsavedChanges';

const destroy = vi.fn(async () => {});
const close = vi.fn(async () => {});
let closeRequestedHandler: ((event: { preventDefault: () => void }) => void) | null = null;
const unlisten = vi.fn();

vi.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({
    destroy,
    close,
    onCloseRequested: (handler: (event: { preventDefault: () => void }) => void) => {
      closeRequestedHandler = handler;
      return Promise.resolve(unlisten);
    },
  }),
}));

/** A surface whose dirtiness is toggled by a button, exactly like a real editor's derived flag. */
function Editor({ initiallyDirty = false }: { initiallyDirty?: boolean }) {
  const [dirty, setDirty] = useState(initiallyDirty);
  useUnsavedChanges(dirty);
  return (
    <div>
      <button type="button" onClick={() => setDirty(true)}>
        edit
      </button>
      <button type="button" onClick={() => setDirty(false)}>
        save
      </button>
      <Link to="/outra">sair</Link>
      <Link to="/editor#ancora">ancora</Link>
    </div>
  );
}

function renderApp(ui: ReactNode, initialEntry = '/editor') {
  const router = createMemoryRouter(
    [
      {
        path: '/editor',
        element: (
          <>
            <UnsavedChangesGuard />
            {ui}
          </>
        ),
      },
      {
        path: '/outra',
        element: (
          <>
            <UnsavedChangesGuard />
            <h1>outra pagina</h1>
          </>
        ),
      },
    ],
    { initialEntries: [initialEntry] },
  );
  return render(<RouterProvider router={router} />);
}

/** Dispatch a cancelable `beforeunload` and report whether anything vetoed it. */
function fireBeforeUnload(): boolean {
  const event = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(event);
  return event.defaultPrevented;
}

afterEach(() => {
  cleanup();
  closeRequestedHandler = null;
  destroy.mockClear();
  close.mockClear();
  unlisten.mockClear();
  delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
});

describe('browser unload', () => {
  it('a clean surface registers no beforeunload listener at all', async () => {
    renderApp(<Editor />);

    expect(fireBeforeUnload()).toBe(false);

    // …and it appears only once there is something to lose.
    fireEvent.click(screen.getByRole('button', { name: 'edit' }));
    expect(fireBeforeUnload()).toBe(true);
  });

  it('saving removes the listener again', async () => {
    renderApp(<Editor initiallyDirty />);
    expect(fireBeforeUnload()).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: 'save' }));
    expect(fireBeforeUnload()).toBe(false);
  });

  it('unmounting the dirty surface removes the listener', () => {
    const view = renderApp(<Editor initiallyDirty />);
    expect(fireBeforeUnload()).toBe(true);

    view.unmount();
    expect(fireBeforeUnload()).toBe(false);
  });
});

describe('in-app navigation', () => {
  it('lets a clean surface navigate without a dialog', async () => {
    renderApp(<Editor />);

    fireEvent.click(screen.getByRole('link', { name: 'sair' }));
    expect(await screen.findByRole('heading', { name: 'outra pagina' })).toBeTruthy();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('shows the real, translated dialog for a dirty surface and can be cancelled', async () => {
    renderApp(<Editor initiallyDirty />);

    fireEvent.click(screen.getByRole('link', { name: 'sair' }));

    const dialog = await screen.findByRole('dialog');
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(screen.getByText('Sair sem guardar?')).toBeTruthy();
    // Cancel is the safe answer, so it holds focus when the dialog opens.
    const stay = screen.getByRole('button', { name: 'Continuar a editar' });
    await waitFor(() => expect(document.activeElement).toBe(stay));

    fireEvent.click(stay);
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    // Still on the editor, still dirty.
    expect(screen.getByRole('button', { name: 'edit' })).toBeTruthy();
    expect(fireBeforeUnload()).toBe(true);
  });

  it('Escape cancels the dialog', async () => {
    renderApp(<Editor initiallyDirty />);

    fireEvent.click(screen.getByRole('link', { name: 'sair' }));
    await screen.findByRole('dialog');

    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(screen.getByRole('button', { name: 'edit' })).toBeTruthy();
  });

  it('confirming discards the work and completes the navigation', async () => {
    renderApp(<Editor initiallyDirty />);

    fireEvent.click(screen.getByRole('link', { name: 'sair' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Sair sem guardar' }));

    expect(await screen.findByRole('heading', { name: 'outra pagina' })).toBeTruthy();
    // The surface unmounted, so nothing is registered any more.
    expect(fireBeforeUnload()).toBe(false);
  });

  it('never prompts for a same-page hash navigation', async () => {
    renderApp(<Editor initiallyDirty />);

    fireEvent.click(screen.getByRole('link', { name: 'ancora' }));
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});

describe('desktop window close', () => {
  beforeEach(() => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
  });

  it('closes straight away when there is nothing to lose', async () => {
    renderApp(<Editor />);
    await waitFor(() => expect(closeRequestedHandler).not.toBeNull());

    const preventDefault = vi.fn();
    act(() => closeRequestedHandler!({ preventDefault }));

    // The veto is unconditional — the guard, not Tauri's shim, decides when to close.
    expect(preventDefault).toHaveBeenCalled();
    await waitFor(() => expect(destroy).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('asks first when work would be lost, and cancelling keeps the window open', async () => {
    renderApp(<Editor initiallyDirty />);
    await waitFor(() => expect(closeRequestedHandler).not.toBeNull());

    act(() => closeRequestedHandler!({ preventDefault: vi.fn() }));

    expect(await screen.findByText('Fechar a aplicação?')).toBeTruthy();
    expect(destroy).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'Continuar a editar' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(destroy).not.toHaveBeenCalled();
  });

  it('destroys the window once the operator confirms', async () => {
    renderApp(<Editor initiallyDirty />);
    await waitFor(() => expect(closeRequestedHandler).not.toBeNull());

    act(() => closeRequestedHandler!({ preventDefault: vi.fn() }));
    fireEvent.click(await screen.findByRole('button', { name: 'Fechar sem guardar' }));

    await waitFor(() => expect(destroy).toHaveBeenCalledTimes(1));
  });

  it('removes its close listener on unmount so the window is never held hostage', async () => {
    const view = renderApp(<Editor />);
    await waitFor(() => expect(closeRequestedHandler).not.toBeNull());

    view.unmount();
    expect(unlisten).toHaveBeenCalled();
  });
});
