/**
 * EntityStatuteEditor tests (t31, ENT-03): the read-only profile surfaces the rule pack,
 * and the statute overlay PATCHes `/v1/entities/{id}` — a reinforced majority is assembled
 * from its numerator/denominator, and "Repor" clears the overlay back to null.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { EntityStatuteEditor } from './EntityStatuteEditor';
import { entityFieldHelp } from './fieldHelp';
import { makeClient } from '../../test/utils';
import { ToastProvider } from '../../ui/toast';
import { ALLOW_ALL_PERMISSIONS, StaticPermissionsProvider } from '../session/permissions';
import type { Entity } from '../../api/types';

const entity: Entity = {
  id: 'ent-1',
  tenant_id: 'tenant-1',
  group_id: null,
  name: 'Encosto Estratégico, S.A.',
  nipc: '503004642',
  nipc_validated: true,
  seat: 'Lisboa',
  family: 'CommercialCompany',
  kind: 'SociedadeAnonima',
  profile: {
    family: 'CommercialCompany',
    rule_pack_id: 'csc-art63/v2',
    allowed_channels: ['Physical', 'Telematic'],
    signature_policy: 'QualifiedPreferred',
    template_family: 'csc',
    calendar_presets: [],
  },
  statute: null,
};

/** Captures PATCH bodies and echoes back the merged entity. */
function stateful(initial: Entity) {
  let ent = initial;
  const patches: { statute?: unknown }[] = [];
  const json = (body: unknown) =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  const fetchImpl = ((_input: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method ?? 'GET';
    if (method === 'PATCH') {
      const body = JSON.parse(init!.body as string) as { statute?: Entity['statute'] };
      patches.push(body);
      ent = { ...ent, statute: body.statute ?? null };
      return json(ent);
    }
    return json(ent);
  }) as typeof fetch;
  return { fetchImpl, patches };
}

function renderEditor(ent: Entity) {
  return render(
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <StaticPermissionsProvider value={ALLOW_ALL_PERMISSIONS}>
          <MemoryRouter>
            <EntityStatuteEditor entity={ent} />
          </MemoryRouter>
        </StaticPermissionsProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('EntityStatuteEditor', () => {
  it('shows the read-only rule pack from the profile', () => {
    renderEditor(entity);
    expect(screen.getByText('csc-art63/v2')).toBeTruthy();
  });

  it('adds inline help to statute override fields', () => {
    renderEditor(entity);

    expect(screen.getAllByRole('button', { name: 'Ajuda' })).toHaveLength(3);
    expect(document.body.textContent).toContain(entityFieldHelp.statuteQuorum);
    expect(document.body.textContent).toContain(entityFieldHelp.statuteMajority);
    expect(document.body.textContent).toContain(entityFieldHelp.statuteNotice);
  });

  it('PATCHes a quorum + reinforced majority overlay', async () => {
    const shared = stateful(entity);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor(entity);

    fireEvent.change(screen.getByLabelText('Quórum mínimo (presentes)'), {
      target: { value: '5' },
    });
    fireEvent.change(screen.getByLabelText('Numerador'), { target: { value: '2' } });
    fireEvent.change(screen.getByLabelText('Denominador'), { target: { value: '3' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar estatutos' }));

    await waitFor(() =>
      expect(shared.patches.at(-1)).toEqual({
        statute: {
          quorum: { min_present: 5 },
          majority: { numerator: 2, denominator: 3 },
          convocation_notice_days: null,
        },
      }),
    );
    // A success toast fires on save (t44 retrofit-a).
    expect(await screen.findByText('Estatuto atualizado.')).toBeTruthy();
  });

  it('clears the overlay via Repor when a statute exists', async () => {
    const withStatute: Entity = {
      ...entity,
      statute: { quorum: { min_present: 3 }, majority: null, convocation_notice_days: null },
    };
    const shared = stateful(withStatute);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor(withStatute);

    fireEvent.click(screen.getByRole('button', { name: 'Repor por omissão' }));
    await waitFor(() => expect(shared.patches.at(-1)).toEqual({ statute: null }));
  });
});
