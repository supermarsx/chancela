/**
 * The registrable-entity-types card (t54 §6.5).
 *
 * The behaviour under test is the one the plan calls binding: on the wire `[]` means EVERY kind,
 * so an empty grid and "reset to all" are the same document — and an administrator who unticked
 * everything expecting *nothing* would get *everything*. These tests pin both halves of the fix:
 * "todos os tipos" is a state with a name that submits `[]` deliberately, and no interaction with
 * the grid can ever produce `[]`.
 *
 * They also pin the record-count acknowledgement: switching off a type that already has entities is
 * consequential, not destructive, so it must gate — and must NOT wear destructive styling.
 *
 * Assertions are plain DOM (this project registers no `jest-dom` matchers).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { EntityKindsSection } from './EntityKindsSection';
import { ENTITY_KINDS, type EntitiesSettings, type EntityKind } from '../../api/types';
import { renderWithProviders } from '../../test/utils';

const PT_KIND_LABELS: Record<EntityKind, string> = {
  SociedadeEmNomeColetivo: 'Sociedade em Nome Coletivo',
  SociedadePorQuotas: 'Sociedade por Quotas',
  SociedadeUnipessoalPorQuotas: 'Sociedade Unipessoal por Quotas',
  SociedadeAnonima: 'Sociedade Anónima',
  SociedadeEmComanditaSimples: 'Sociedade em Comandita Simples',
  SociedadeEmComanditaPorAcoes: 'Sociedade em Comandita por Ações',
  Condominio: 'Condomínio',
  Associacao: 'Associação',
  Fundacao: 'Fundação',
  Cooperativa: 'Cooperativa',
};

function entityRow(id: string, kind: EntityKind) {
  return {
    id,
    name: 'Encosto Estratégico Lda',
    nipc: '500000000',
    seat: 'Lisboa',
    kind,
    family: 'CommercialCompany',
    created_at: '2026-07-01T10:00:00Z',
  };
}

/** Stubs the one query the card makes: the entities list it counts records from. */
function stubEntities(rows: unknown[], status = 200) {
  const fn = ((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/v1/entities')) {
      return Promise.resolve(
        new Response(JSON.stringify(status === 200 ? rows : { error: 'forbidden' }), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  vi.stubGlobal('fetch', fn);
}

/**
 * The card is controlled, and every assertion here is about a SEQUENCE of edits, so the tests
 * drive it through a real owner that holds the value — asserting against a spy alone would let a
 * second interaction read a stale selection and still pass.
 */
function Harness({
  initial,
  onChange,
}: {
  initial: EntitiesSettings;
  onChange: (next: EntitiesSettings) => void;
}) {
  const [value, setValue] = useState(initial);
  return (
    <EntityKindsSection
      value={value}
      onChange={(next) => {
        setValue(next);
        onChange(next);
      }}
    />
  );
}

function renderCard(initial: EntitiesSettings) {
  const onChange = vi.fn<(next: EntitiesSettings) => void>();
  renderWithProviders(<Harness initial={initial} onChange={onChange} />);
  return onChange;
}

/** The checkbox for a legal type, found by its label — the count aside does not change identity. */
function kindBox(kind: EntityKind): HTMLInputElement {
  return screen.getByRole('checkbox', {
    name: new RegExp(PT_KIND_LABELS[kind]),
  }) as HTMLInputElement;
}

function radio(name: string): HTMLInputElement {
  return screen.getByRole('radio', { name }) as HTMLInputElement;
}

/** Everything the row for `kind` reads as, including any record-count aside. */
function rowText(kind: EntityKind): string {
  const box = kindBox(kind);
  const label = document.querySelector(`label[for="${box.id}"]`);
  return label?.textContent ?? '';
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('EntityKindsSection — "todos os tipos" is a named state', () => {
  it('reads an empty list as the every-kind state, shows every type ticked, and inerts the grid', () => {
    stubEntities([]);
    renderCard({ enabled_kinds: [] });

    expect(radio('Todos os tipos').checked).toBe(true);
    expect(radio('Apenas os tipos selecionados').checked).toBe(false);
    // Every kind reads as available, and none can be unticked from here: "all" is not expressed by
    // the state of ten checkboxes, so the checkboxes do not get to contradict it.
    for (const kind of ENTITY_KINDS) {
      expect(kindBox(kind).checked, kind).toBe(true);
      expect(kindBox(kind).disabled, kind).toBe(true);
    }
  });

  it('narrows to an explicit ten-item list — never [] — when "apenas os selecionados" is chosen', () => {
    stubEntities([]);
    const onChange = renderCard({ enabled_kinds: [] });

    fireEvent.click(radio('Apenas os tipos selecionados'));

    expect(onChange).toHaveBeenCalledTimes(1);
    const next = onChange.mock.calls[0][0];
    // Seeded complete: the operator narrows DOWN from every type, so a zero-tick draft never
    // exists to be autosaved as the every-kind default in disguise.
    expect(next.enabled_kinds).toEqual([...ENTITY_KINDS]);
    expect(next.enabled_kinds).not.toEqual([]);
    expect(kindBox('Condominio').disabled).toBe(false);
  });

  it('submits [] deliberately when "todos os tipos" is chosen back', () => {
    stubEntities([]);
    const onChange = renderCard({ enabled_kinds: ['Condominio'] });

    expect(radio('Apenas os tipos selecionados').checked).toBe(true);
    fireEvent.click(radio('Todos os tipos'));

    expect(onChange).toHaveBeenCalledWith({ enabled_kinds: [] });
  });
});

describe('EntityKindsSection — an empty selection is never submitted as a narrowing', () => {
  it('refuses to untick the last remaining type and points at the state that means "all"', () => {
    stubEntities([]);
    const onChange = renderCard({ enabled_kinds: ['Condominio'] });

    fireEvent.click(kindBox('Condominio'));

    expect(onChange).not.toHaveBeenCalled();
    expect(kindBox('Condominio').checked).toBe(true);
    expect(screen.getByRole('alert').textContent).toBe(
      'Selecione pelo menos um tipo. Para permitir todos, escolha «Todos os tipos» em cima.',
    );
  });

  it('clears the refusal once a real change lands', () => {
    stubEntities([]);
    const onChange = renderCard({ enabled_kinds: ['Condominio'] });

    fireEvent.click(kindBox('Condominio'));
    expect(screen.queryByRole('alert')).not.toBeNull();

    fireEvent.click(kindBox('Associacao'));

    expect(onChange).toHaveBeenCalledWith({ enabled_kinds: ['Condominio', 'Associacao'] });
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('keeps the canonical order regardless of the order types were ticked in', () => {
    stubEntities([]);
    const onChange = renderCard({ enabled_kinds: ['Cooperativa'] });

    fireEvent.click(kindBox('SociedadePorQuotas'));

    // `SociedadePorQuotas` precedes `Cooperativa` in ENTITY_KINDS; the stored list follows the
    // contract's order, not the click order, so two administrators who enable the same set store
    // the same document.
    expect(onChange).toHaveBeenCalledWith({
      enabled_kinds: ['SociedadePorQuotas', 'Cooperativa'],
    });
  });
});

describe('EntityKindsSection — switching off a type that already has records', () => {
  const twoCondominios = [entityRow('e1', 'Condominio'), entityRow('e2', 'Condominio')];

  it('shows the record count beside the type', async () => {
    stubEntities(twoCondominios);
    renderCard({ enabled_kinds: ['Condominio', 'Associacao'] });

    await waitFor(() => expect(rowText('Condominio')).toContain('2 entidades registadas'));
    // A type with no records says nothing rather than "0" — an absence is not a quantity worth
    // announcing on nine rows out of ten.
    expect(rowText('Associacao')).toBe('Associação');
  });

  it('gates on an acknowledgement that states the count and the reassurance, and applies only on confirm', async () => {
    stubEntities(twoCondominios);
    const onChange = renderCard({ enabled_kinds: ['Condominio', 'Associacao'] });
    await waitFor(() => expect(rowText('Condominio')).toContain('2 entidades registadas'));

    fireEvent.click(kindBox('Condominio'));

    const dialog = screen.getByRole('dialog');
    expect(dialog.textContent).toContain(
      '2 entidades registadas têm este tipo. Deixará de ser possível registar novas entidades com ele.',
    );
    expect(dialog.textContent).toContain('Nada é apagado.');
    expect(onChange).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'Deixar de oferecer este tipo' }));

    await waitFor(() => expect(onChange).toHaveBeenCalledWith({ enabled_kinds: ['Associacao'] }));
  });

  it('leaves the type enabled when the acknowledgement is dismissed', async () => {
    stubEntities(twoCondominios);
    const onChange = renderCard({ enabled_kinds: ['Condominio', 'Associacao'] });
    await waitFor(() => expect(rowText('Condominio')).toContain('2 entidades registadas'));

    fireEvent.click(kindBox('Condominio'));
    fireEvent.click(screen.getByRole('button', { name: 'Cancelar' }));

    expect(onChange).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(kindBox('Condominio').checked).toBe(true);
  });

  it('is consequential, not destructive — no danger styling and no typed phrase', async () => {
    stubEntities(twoCondominios);
    renderCard({ enabled_kinds: ['Condominio', 'Associacao'] });
    await waitFor(() => expect(rowText('Condominio')).toContain('2 entidades registadas'));

    fireEvent.click(kindBox('Condominio'));

    // t56 separated strictness (T1: a single confirm) from severity (`danger`, which paints the
    // dialog red). Misclassifying an admissions-policy edit as destruction is what trains an
    // operator to click through the guards that do matter.
    expect(screen.getByRole('dialog').className).not.toContain('modal--danger');
    expect(screen.queryByRole('textbox')).toBeNull();
  });

  it('says one entity in the singular, never "1 entidades"', async () => {
    stubEntities([entityRow('e1', 'Fundacao')]);
    renderCard({ enabled_kinds: ['Fundacao', 'Associacao'] });
    await waitFor(() => expect(rowText('Fundacao')).toContain('1 entidade registada'));

    fireEvent.click(kindBox('Fundacao'));

    expect(screen.getByRole('dialog').textContent).toContain(
      'Uma entidade registada tem este tipo. Deixará de ser possível registar novas entidades com ele.',
    );
  });

  it('switches off a type with no records without a gate', async () => {
    stubEntities(twoCondominios);
    const onChange = renderCard({ enabled_kinds: ['Condominio', 'Associacao'] });
    await waitFor(() => expect(rowText('Condominio')).toContain('2 entidades registadas'));

    fireEvent.click(kindBox('Associacao'));

    expect(screen.queryByRole('dialog')).toBeNull();
    expect(onChange).toHaveBeenCalledWith({ enabled_kinds: ['Condominio'] });
  });

  it('shows no counts and no gate when the entities list is not readable', async () => {
    stubEntities([], 403);
    const onChange = renderCard({ enabled_kinds: ['Condominio', 'Associacao'] });

    // "We do not know" is stated by saying nothing, never guessed at as "there are none" — and the
    // server refuses a disabled kind by name either way, so nothing here is the control.
    fireEvent.click(kindBox('Condominio'));
    await waitFor(() => expect(onChange).toHaveBeenCalledWith({ enabled_kinds: ['Associacao'] }));
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});
