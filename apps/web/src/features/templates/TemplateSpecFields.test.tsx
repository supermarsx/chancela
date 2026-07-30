/**
 * `TemplateSpecFields` — the shared metadata table behind both template authoring surfaces.
 *
 * It exists so the create page and the edit page cannot drift apart, which means a defect here
 * lands on both at once. The component owns no state: every control hands the caller a *reducer*
 * over the current spec, and the assertions below are on the spec that reducer produces. That is
 * the contract that matters — two of these controls are not simple assignments (the channel list
 * toggles, and clearing the layout override must DELETE the key rather than set it to undefined),
 * and both would look correct in a render-only test.
 *
 * The id is immutable once a template exists: a new id is a different template, not a rename.
 */
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { TemplateSpecFields } from './TemplateSpecFields';
import { DEFAULT_SETTINGS, type TemplateSpec } from '../../api/types';
import { ptPT } from '../../i18n/locales/pt-PT';

function spec(overrides: Partial<TemplateSpec> = {}): TemplateSpec {
  return {
    id: 'ata-ag-ordinaria',
    family: 'CommercialCompany',
    stage: 'Ata',
    channels: ['Physical'],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: 'pt-csc',
    blocks: [],
    locale: 'pt-PT',
    ...overrides,
  };
}

/**
 * Render the fields and return the spec each interaction produces. `onSpecChange` receives a
 * reducer, so the harness applies it to the CURRENT spec exactly as a page would.
 */
function renderFields(initial: TemplateSpec = spec(), idLocked = false) {
  vi.stubGlobal('fetch', (() =>
    Promise.resolve(
      new Response(JSON.stringify(DEFAULT_SETTINGS), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )) as typeof fetch);
  let current = initial;

  // A stateful host, the way both real pages hold the spec: the component re-renders from the
  // reduced value, so a control that read a stale spec would show it.
  function Host() {
    const [value, setValue] = useState(initial);
    current = value;
    return (
      <TemplateSpecFields
        spec={value}
        onSpecChange={(next) => setValue((previous) => next(previous))}
        idLocked={idLocked}
      />
    );
  }

  renderWithProviders(<Host />);
  return { latest: () => current };
}

function control(id: string): HTMLInputElement | HTMLSelectElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`no control #${id}`);
  return el as HTMLInputElement | HTMLSelectElement;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('TemplateSpecFields', () => {
  it('produces a reducer per scalar field, leaving the rest of the spec untouched', () => {
    const { latest } = renderFields();

    fireEvent.change(control('tpl-id'), { target: { value: 'ata-ag-extraordinaria' } });
    expect(latest().id).toBe('ata-ag-extraordinaria');

    fireEvent.change(control('tpl-family'), { target: { value: 'Condominium' } });
    fireEvent.change(control('tpl-stage'), { target: { value: 'Certidao' } });
    fireEvent.change(control('tpl-signature'), { target: { value: 'ManualAttested' } });
    fireEvent.change(control('tpl-rule-pack'), { target: { value: 'pt-ph' } });

    expect(latest()).toMatchObject({
      id: 'ata-ag-extraordinaria',
      family: 'Condominium',
      stage: 'Certidao',
      signature_policy: 'ManualAttested',
      rule_pack_id: 'pt-ph',
    });
    // The blocks are edited elsewhere; this table must never rewrite them.
    expect(latest().blocks).toEqual([]);
  });

  it('locks the identifier for an existing template, because a new id is a new template', () => {
    renderFields(spec(), true);
    expect((control('tpl-id') as HTMLInputElement).disabled).toBe(true);
  });

  it('offers only the locale template authoring actually accepts', () => {
    renderFields();
    const locale = control('tpl-locale') as HTMLSelectElement;

    // The wider LOCALES catalog belongs to user and document settings; offering one of those here
    // guarantees a 422 from the write API rather than a template in another language.
    expect([...locale.options].map((option) => option.value)).toEqual(['pt-PT']);
  });

  it('adds and removes a meeting channel rather than replacing the list', () => {
    const { latest } = renderFields(spec({ channels: ['Physical'] }));
    const boxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
    expect(boxes.length).toBeGreaterThan(1);

    // The second channel is unchecked: ticking it must ADD to the list.
    const unchecked = boxes.find((box) => !box.checked);
    expect(unchecked).toBeTruthy();
    fireEvent.click(unchecked!);
    expect(latest().channels).toHaveLength(2);
    expect(latest().channels).toContain('Physical');

    // Unticking the one that was already on must remove only it.
    const checked = boxes.find((box) => box.checked);
    fireEvent.click(checked!);
    expect(latest().channels).not.toContain('Physical');
  });

  it('leaves a template with no channel at all rather than silently keeping the last one', () => {
    const { latest } = renderFields(spec({ channels: ['Physical'] }));

    fireEvent.click(
      screen.getAllByRole('checkbox').find((box) => (box as HTMLInputElement).checked)!,
    );

    // An empty channel list is the operator's statement; the server decides whether to accept it.
    expect(latest().channels).toEqual([]);
  });

  it('DELETES the layout-override key when it is reset, never leaves it present-and-undefined', () => {
    const { latest } = renderFields(
      spec({ document_layout_override: { page: { orientation: 'Landscape' } } }),
    );

    const reset = screen.getByRole('button', {
      name: ptPT['documentLayout.action.resetInherited'],
    }) as HTMLButtonElement;
    expect(reset.disabled).toBe(false);
    fireEvent.click(reset);

    // The key must be ABSENT. A spec carrying `document_layout_override: undefined` serialises
    // differently from one that omits it, and "inherit from the instance" is the omission.
    expect('document_layout_override' in latest()).toBe(false);
    expect(latest().id).toBe('ata-ag-ordinaria');
  });

  it('has nothing to reset on a template that inherits every layout property', () => {
    renderFields();

    expect(
      (
        screen.getByRole('button', {
          name: ptPT['documentLayout.action.resetInherited'],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });
});
