import { cleanup, fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_SETTINGS } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import {
  applyDocumentLayoutOverrides,
  DocumentLayoutDefaultsEditor,
  DocumentLayoutOverridesEditor,
} from './DocumentLayoutEditor';

const PRODUCT = DEFAULT_SETTINGS.documents.layout_defaults;

afterEach(cleanup);

describe('DocumentLayoutEditor', () => {
  it('resolves visible levels without mutating the concrete inherited policy', () => {
    const inherited = structuredClone(PRODUCT);
    const resolved = applyDocumentLayoutOverrides(inherited, {
      page: { size: 'A5' },
      typography: { body_font_family: 'NotoSans' },
    });

    expect(resolved.page.size).toBe('A5');
    expect(resolved.typography.body_font_family).toBe('NotoSans');
    expect(inherited).toEqual(PRODUCT);
  });

  it('defaults every lower-level property to inherit and materializes only the chosen leaf', () => {
    const onChange = vi.fn();
    renderWithProviders(
      <DocumentLayoutOverridesEditor
        inherited={PRODUCT}
        inheritanceLabel="da instância"
        onChange={onChange}
      />,
    );

    const modes = screen.getAllByRole('combobox', { name: /^Modo de / });
    expect(modes).toHaveLength(17);
    for (const mode of modes) expect((mode as HTMLSelectElement).value).toBe('inherit');

    fireEvent.change(screen.getByRole('combobox', { name: 'Modo de Formato da página' }), {
      target: { value: 'override' },
    });
    expect(onChange).toHaveBeenLastCalledWith({ page: { size: 'A4' } });
  });

  it('removes an inherited leaf instead of storing its effective value', () => {
    const onChange = vi.fn();
    renderWithProviders(
      <DocumentLayoutOverridesEditor
        value={{ typography: { body_font_family: 'NotoSans' } }}
        inherited={PRODUCT}
        inheritanceLabel="da instância"
        onChange={onChange}
      />,
    );

    fireEvent.change(screen.getByRole('combobox', { name: 'Modo de Tipo de letra do corpo' }), {
      target: { value: 'inherit' },
    });
    expect(onChange).toHaveBeenLastCalledWith(undefined);
  });

  it('edits concrete instance defaults and offers an explicit product reset', () => {
    const onChange = vi.fn();
    const onReset = vi.fn();
    renderWithProviders(
      <DocumentLayoutDefaultsEditor value={PRODUCT} onChange={onChange} onRequestReset={onReset} />,
    );

    fireEvent.change(screen.getByLabelText('Orientação'), { target: { value: 'Landscape' } });
    expect(onChange).toHaveBeenLastCalledWith({
      ...PRODUCT,
      page: { ...PRODUCT.page, orientation: 'Landscape' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Repor predefinições do produto' }));
    expect(onReset).toHaveBeenCalledOnce();
  });
});
