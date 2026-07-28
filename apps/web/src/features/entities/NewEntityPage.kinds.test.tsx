/**
 * The create form honours the instance's registrable-entity-type allowlist (t54 §6.2/§6.3).
 *
 * This is a **courtesy, not the control** — `ensure_entity_kind_enabled` refuses a disabled kind on
 * `POST /v1/entities` (and on the certidão-permanente import) whatever the form offers. What these
 * tests pin is the half a narrowed form can still get wrong: leaving the product-default selection
 * (`SociedadePorQuotas`) in state while showing a list that no longer contains it, which would
 * submit a type the operator was never offered and earn a 422 they could not have predicted.
 *
 * Kept in its own file rather than added to `entities.test.tsx`, which several lanes are editing.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { NewEntityPage } from './NewEntityPage';
import { ENTITY_KINDS, type EntityKind } from '../../api/types';
import { renderWithProviders } from '../../test/utils';

const CREATED = {
  id: 'ent-1',
  name: 'Encosto Estratégico Lda',
  nipc: '500000000',
  seat: 'Lisboa',
  kind: 'Condominio',
  family: 'Condominium',
  created_at: '2026-07-01T10:00:00Z',
};

/** Stubs `GET /v1/settings` with the given allowlist plus the create POST. */
function stub(enabledKinds: EntityKind[] | undefined) {
  const posts: unknown[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    if (url.includes('/v1/settings')) {
      // `entities` is skip-serialised at its default, so `undefined` here is the real shape of a
      // document from an instance that has never narrowed anything — not a contrivance.
      const body = enabledKinds === undefined ? {} : { entities: { enabled_kinds: enabledKinds } };
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    if (url.includes('/v1/entities') && method === 'POST') {
      posts.push(init?.body ? JSON.parse(init.body as string) : null);
      return Promise.resolve(
        new Response(JSON.stringify(CREATED), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  vi.stubGlobal('fetch', fn);
  return posts;
}

function legalForm(): HTMLSelectElement {
  return screen.getByLabelText('Forma jurídica') as HTMLSelectElement;
}

function offered(): string[] {
  return Array.from(legalForm().options).map((option) => option.value);
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('NewEntityPage — the legal-form select follows the allowlist', () => {
  it('offers all ten types when the settings document carries no narrowing', async () => {
    stub(undefined);
    renderWithProviders(<NewEntityPage />, ['/entities/new']);

    await waitFor(() => expect(offered()).toEqual([...ENTITY_KINDS]));
    expect(legalForm().value).toBe('SociedadePorQuotas');
  });

  it('offers all ten types for an explicitly empty list — [] means every kind', async () => {
    stub([]);
    renderWithProviders(<NewEntityPage />, ['/entities/new']);

    await waitFor(() => expect(offered()).toEqual([...ENTITY_KINDS]));
  });

  it('offers only the permitted types, in the contract order rather than the stored order', async () => {
    stub(['Cooperativa', 'Condominio']);
    renderWithProviders(<NewEntityPage />, ['/entities/new']);

    await waitFor(() => expect(offered()).toEqual(['Condominio', 'Cooperativa']));
  });

  it('moves the selection off a product default the instance no longer registers', async () => {
    stub(['Condominio', 'Associacao']);
    renderWithProviders(<NewEntityPage />, ['/entities/new']);

    // Before settings resolve the form shows the product default; once the narrowing arrives the
    // selection must follow the list, not linger on a value that is no longer among the options.
    await waitFor(() => expect(legalForm().value).toBe('Condominio'));
    expect(offered()).not.toContain('SociedadePorQuotas');
  });

  it('submits a kind the operator was actually offered', async () => {
    const posts = stub(['Condominio', 'Associacao']);
    renderWithProviders(<NewEntityPage />, ['/entities/new']);
    await waitFor(() => expect(legalForm().value).toBe('Condominio'));

    fireEvent.change(screen.getByLabelText('Denominação'), {
      target: { value: 'Encosto Estratégico Lda' },
    });
    fireEvent.change(screen.getByLabelText('NIPC'), { target: { value: '500000000' } });
    fireEvent.change(screen.getByLabelText('Sede'), { target: { value: 'Lisboa' } });
    fireEvent.click(screen.getByRole('button', { name: 'Criar entidade' }));

    await waitFor(() => expect(posts).toHaveLength(1));
    expect((posts[0] as { kind: string }).kind).toBe('Condominio');
  });

  it('leaves an operator choice alone once made', async () => {
    stub(['Condominio', 'Associacao']);
    renderWithProviders(<NewEntityPage />, ['/entities/new']);
    await waitFor(() => expect(legalForm().value).toBe('Condominio'));

    fireEvent.change(legalForm(), { target: { value: 'Associacao' } });

    // The correction effect fires on every settings render; it must only ever rescue a selection
    // that fell outside the list, never overwrite a permitted one the operator picked.
    await waitFor(() => expect(legalForm().value).toBe('Associacao'));
    expect(legalForm().value).toBe('Associacao');
  });
});
