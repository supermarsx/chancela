/**
 * Entity archiving, from the list row to the wire (t84).
 *
 * # What these tests are actually guarding
 *
 * The load-bearing assertion is **"no mutation is issued until the operator confirms"** — not
 * "a dialog appears". A dialog that renders while the POST has already gone out is worse than no
 * dialog, because it *looks* like a guard. So every confirmation test asserts the ABSENT write:
 * it enumerates the recorded fetch calls and requires zero archive requests among them.
 *
 * # Why nothing here matches rendered Portuguese
 *
 * Controls are addressed through `[data-archive-direction]` and the dialog's `button[type=submit]`,
 * never through their pt-PT accessible names. Matching copy is how a test passes for the wrong
 * reason: a sibling lane shipped an assertion on "âncora" that only ever passed because the
 * singular happened to fire, and it would have stayed green through a real regression in the plural
 * branch. The copy lives in `i18n/entityArchiveFallback.ts` and is reviewed by reading it, not by
 * substring-matching it here.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { makeClient } from '../../test/utils';
import { collectionPageFixture } from '../../test/utils';
import { ToastProvider } from '../../ui/toast';
import {
  ALLOW_ALL_PERMISSIONS,
  StaticPermissionsProvider,
  permissionsValue,
  type PermissionsContextValue,
} from '../session/permissions';
import { api } from '../../api/client';
import { DEFAULT_SETTINGS, type ConfirmationPolicyView, type Entity } from '../../api/types';
import { EntitiesPage } from './EntitiesPage';

const ACTIVE: Entity = {
  id: 'ent-active',
  tenant_id: 'tenant-1',
  group_id: null,
  name: 'Encosto Estratégico, Lda.',
  nipc: '503004642',
  nipc_validated: true,
  seat: 'Lisboa',
  family: 'CommercialCompany',
  kind: 'SociedadePorQuotas',
  fiscal_year_end: null,
  profile: {
    family: 'CommercialCompany',
    rule_pack_id: 'csc-art63/v2',
    allowed_channels: ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'],
    signature_policy: 'QualifiedPreferred',
    template_family: 'csc-commercial',
    calendar_presets: [],
    attendee_qualities: ['Member'],
  },
  statute: null,
  archived_at: null,
  archived: false,
};

const ARCHIVED: Entity = {
  ...ACTIVE,
  id: 'ent-archived',
  name: 'Fomento Interior, S.A.',
  archived_at: '2026-03-04T10:15:00Z',
  archived: true,
};

/** The server's real verdict for this action: a plain confirm, and NOT destructive framing. */
const POLICY: ConfirmationPolicyView = {
  actions: [
    {
      action: 'entity.archive',
      floor: 'confirm',
      effective: 'confirm',
      consequence: 'consequential',
      wired: true,
    },
  ],
};

interface Harness {
  calls: { url: string; method: string }[];
  /** Every archive/unarchive request issued so far — the thing the guard must keep empty. */
  mutations: () => { url: string; method: string }[];
}

/**
 * A fetch stub that RECORDS every call, so a test can assert on what was never sent.
 * `POST …/archive` and `…/unarchive` answer `204` with an empty body, as the server does.
 */
function harness(entities: Entity[], policy: ConfirmationPolicyView = POLICY): Harness {
  const calls: { url: string; method: string }[] = [];
  const stub = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method });

    const json = (body: unknown, status = 200) =>
      Promise.resolve(
        new Response(JSON.stringify(body), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      );

    if (/\/v1\/entities\/[^/]+\/(un)?archive$/.test(url) && method === 'POST') {
      // 204 No Content, exactly like `archive_entity`/`unarchive_entity`.
      return Promise.resolve(new Response(null, { status: 204 }));
    }
    if (url.includes('/v1/confirmation-policy')) return json(policy);
    if (url.includes('/v1/settings')) return json(DEFAULT_SETTINGS);
    if (/\/v1\/entities\/page(\?|$)/.test(url)) return json(collectionPageFixture(url, entities));
    if (url.includes('/v1/entities')) return json(entities);
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  vi.stubGlobal('fetch', stub);

  return {
    calls,
    mutations: () =>
      calls.filter((c) => c.method === 'POST' && /\/(un)?archive$/.test(new URL(c.url, 'http://t').pathname)),
  };
}

function renderPage(permissions: PermissionsContextValue = ALLOW_ALL_PERMISSIONS) {
  return render(
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <StaticPermissionsProvider value={permissions}>
          <MemoryRouter initialEntries={['/entities']}>
            <EntitiesPage />
          </MemoryRouter>
        </StaticPermissionsProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

/** The row control for one direction, found without touching a single translated string. */
function control(direction: 'archive' | 'unarchive'): HTMLButtonElement {
  const found = document.querySelectorAll(`[data-archive-direction="${direction}"]`);
  expect(found, `exactly one ${direction} control`).toHaveLength(1);
  return found[0] as HTMLButtonElement;
}

/** The dialog's confirm button is its only submit; cancel is a `type="button"`. */
function confirmButton(): HTMLButtonElement {
  const dialog = screen.getByRole('dialog');
  const submit = dialog.querySelector('button[type="submit"]');
  expect(submit, 'the dialog has a submit button').toBeTruthy();
  return submit as HTMLButtonElement;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('archiving an entity from the list', () => {
  it('issues NO archive request until the operator confirms', async () => {
    const h = harness([ACTIVE]);
    renderPage();
    await screen.findByText(ACTIVE.name);

    fireEvent.click(control('archive'));

    // The dialog is open …
    await screen.findByRole('dialog');
    // … and this is the assertion that matters: nothing has been written.
    expect(h.mutations()).toHaveLength(0);

    // Give any un-awaited mutation a chance to land before declaring the absence real.
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(h.mutations()).toHaveLength(0);
  });

  it('issues exactly one POST …/archive once the dialog is confirmed', async () => {
    const h = harness([ACTIVE]);
    renderPage();
    await screen.findByText(ACTIVE.name);

    fireEvent.click(control('archive'));
    await screen.findByRole('dialog');
    await waitFor(() => expect(confirmButton().disabled).toBe(false));
    fireEvent.click(confirmButton());

    await waitFor(() => expect(h.mutations()).toHaveLength(1));
    expect(h.mutations()[0].method).toBe('POST');
    expect(h.mutations()[0].url).toContain(`/v1/entities/${ACTIVE.id}/archive`);
  });

  it('abandons the write when the dialog is dismissed', async () => {
    const h = harness([ACTIVE]);
    renderPage();
    await screen.findByText(ACTIVE.name);

    fireEvent.click(control('archive'));
    const dialog = await screen.findByRole('dialog');
    const cancel = within(dialog).getAllByRole('button').find((b) => b.getAttribute('type') === 'button');
    fireEvent.click(cancel as HTMLElement);

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(h.mutations()).toHaveLength(0);
  });

  it('unarchives with no dialog — the server marks that direction NotGuarded', async () => {
    const h = harness([ARCHIVED]);
    renderPage();
    await screen.findByText(ARCHIVED.name);

    fireEvent.click(control('unarchive'));

    await waitFor(() => expect(h.mutations()).toHaveLength(1));
    expect(h.mutations()[0].url).toContain(`/v1/entities/${ARCHIVED.id}/unarchive`);
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('writes nothing when the principal lacks entity.archive', async () => {
    const h = harness([ACTIVE]);
    // Holds entity.update but NOT entity.archive — the server's own test draws the same line.
    renderPage(permissionsValue((perm) => perm !== 'entity.archive'));
    await screen.findByText(ACTIVE.name);

    const button = control('archive');
    expect(button.getAttribute('aria-disabled')).toBe('true');
    expect(button.getAttribute('data-gated')).toBe('true');

    fireEvent.click(button);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(h.mutations()).toHaveLength(0);
  });
});

describe('archived state in the list', () => {
  it('badges an archived row and leaves an active one unbadged', async () => {
    harness([ACTIVE, ARCHIVED]);
    renderPage();
    await screen.findByText(ARCHIVED.name);

    const cellOf = (name: string) =>
      (screen.getByText(name).closest('td') ?? screen.getByText(name)) as HTMLElement;

    expect(cellOf(ARCHIVED.name).querySelectorAll('.badge').length).toBeGreaterThan(0);
    expect(cellOf(ACTIVE.name).querySelectorAll('.badge')).toHaveLength(0);
  });

  it('offers the direction matching each row rather than one control for both', async () => {
    harness([ACTIVE, ARCHIVED]);
    renderPage();
    await screen.findByText(ARCHIVED.name);

    expect(document.querySelectorAll('[data-archive-direction="archive"]')).toHaveLength(1);
    expect(document.querySelectorAll('[data-archive-direction="unarchive"]')).toHaveLength(1);
  });
});

describe('the tri-state archived filter', () => {
  /** The `archived=` value on the last entities page request, or `null` when it was absent. */
  function lastArchivedParam(h: Harness): string | null {
    const pages = h.calls.filter((c) => c.url.includes('/v1/entities/page'));
    expect(pages.length).toBeGreaterThan(0);
    return new URL(pages[pages.length - 1].url, 'http://t').searchParams.get('archived');
  }

  it('sends no archived= at the default, so the listing is the server default (include)', async () => {
    const h = harness([ACTIVE, ARCHIVED]);
    renderPage();
    await screen.findByText(ARCHIVED.name);

    expect(lastArchivedParam(h)).toBeNull();
    // The default really does show both — that is the whole point of the server's `include`.
    expect(screen.getByText(ACTIVE.name)).toBeTruthy();
    expect(screen.getByText(ARCHIVED.name)).toBeTruthy();
  });

  it('narrows to active rows on exclude, and to archived rows on only', async () => {
    const h = harness([ACTIVE, ARCHIVED]);
    renderPage();
    await screen.findByText(ARCHIVED.name);

    const select = document.getElementById('entities-archived-filter') as HTMLSelectElement;
    expect(select, 'the filter is rendered').toBeTruthy();
    expect(select.value).toBe('include');

    fireEvent.change(select, { target: { value: 'exclude' } });
    await waitFor(() => expect(lastArchivedParam(h)).toBe('exclude'));
    await waitFor(() => expect(screen.queryByText(ARCHIVED.name)).toBeNull());
    expect(screen.getByText(ACTIVE.name)).toBeTruthy();

    fireEvent.change(select, { target: { value: 'only' } });
    await waitFor(() => expect(lastArchivedParam(h)).toBe('only'));
    await waitFor(() => expect(screen.queryByText(ACTIVE.name)).toBeNull());
    expect(screen.getByText(ARCHIVED.name)).toBeTruthy();
  });
});

describe('the client carries archiving on the wire', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('keeps archived_at and archived instead of dropping them', async () => {
    vi.stubGlobal(
      'fetch',
      (() =>
        Promise.resolve(
          new Response(JSON.stringify(ARCHIVED), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        )) as typeof fetch,
    );

    const entity = await api.getEntity(ARCHIVED.id);
    // Typed reads: these do not compile if the interface loses the fields again.
    expect(entity.archived_at).toBe('2026-03-04T10:15:00Z');
    expect(entity.archived).toBe(true);
  });

  it('threads the archived filter onto both list endpoints and omits it when unset', async () => {
    const urls: string[] = [];
    vi.stubGlobal(
      'fetch',
      ((input: RequestInfo | URL) => {
        urls.push(typeof input === 'string' ? input : input.toString());
        return Promise.resolve(
          new Response(JSON.stringify([]), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        );
      }) as typeof fetch,
    );

    await api.listEntities();
    expect(urls[0]).not.toContain('archived=');

    await api.listEntities({ archived: 'only' });
    expect(urls[1]).toContain('archived=only');
  });

  it('posts to the archive and unarchive routes and tolerates a bodyless 204', async () => {
    const seen: { url: string; method: string }[] = [];
    vi.stubGlobal(
      'fetch',
      ((input: RequestInfo | URL, init?: RequestInit) => {
        seen.push({
          url: typeof input === 'string' ? input : input.toString(),
          method: init?.method ?? 'GET',
        });
        return Promise.resolve(new Response(null, { status: 204 }));
      }) as typeof fetch,
    );

    await expect(api.archiveEntity('ent-1')).resolves.toBeUndefined();
    await expect(api.unarchiveEntity('ent-1')).resolves.toBeUndefined();

    expect(seen).toEqual([
      { url: expect.stringContaining('/v1/entities/ent-1/archive'), method: 'POST' },
      { url: expect.stringContaining('/v1/entities/ent-1/unarchive'), method: 'POST' },
    ]);
  });
});
