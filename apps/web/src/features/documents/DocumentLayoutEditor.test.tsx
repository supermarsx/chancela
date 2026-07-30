import { cleanup, fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_SETTINGS, PRODUCT_DOCUMENT_FURNITURE } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import {
  applyDocumentLayoutOverrides,
  DocumentLayoutDefaultsEditor,
  DocumentLayoutOverridesEditor,
} from './DocumentLayoutEditor';
import { FURNITURE_PLACEHOLDERS, FURNITURE_SAMPLE_FACTS } from './furnitureTemplate';

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

    // One per leaf of the server's layout contract (`DocumentLayoutField::ALL`): 17 page /
    // typography / region leaves plus the 11 page-furniture leaves.
    const modes = screen.getAllByRole('combobox', { name: /^Modo de / });
    expect(modes).toHaveLength(28);
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
    expect(PRODUCT.typography.body_font_size_pt).toBe(10);
    renderWithProviders(
      <DocumentLayoutDefaultsEditor value={PRODUCT} onChange={onChange} onRequestReset={onReset} />,
    );

    fireEvent.change(screen.getByLabelText('Orientação'), { target: { value: 'Landscape' } });
    expect(onChange).toHaveBeenLastCalledWith({
      ...PRODUCT,
      // The wire omits `furniture` at its all-disabled default, so the first edit is also what
      // makes it concrete. It must go up as the product default, never as anything else.
      furniture: PRODUCT_DOCUMENT_FURNITURE,
      page: { ...PRODUCT.page, orientation: 'Landscape' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Repor predefinições do produto' }));
    expect(onReset).toHaveBeenCalledOnce();
  });
});

/** A policy whose furniture is concrete, for the cases that need a value in a template field. */
function withFurniture(text: { header?: string; footer?: string }) {
  return {
    ...PRODUCT,
    furniture: {
      ...PRODUCT_DOCUMENT_FURNITURE,
      header: { ...PRODUCT_DOCUMENT_FURNITURE.header, text: text.header ?? '' },
      footer: { ...PRODUCT_DOCUMENT_FURNITURE.footer, text: text.footer ?? '' },
    },
  };
}

describe('DocumentLayoutEditor page furniture', () => {
  it('renders the furniture leaves off when the wire omitted the whole object', () => {
    // The product default IS the omitted shape: this is what arrives from a server whose
    // instance has never enabled a piece.
    expect(PRODUCT.furniture).toBeUndefined();
    const { container } = renderWithProviders(
      <DocumentLayoutDefaultsEditor value={PRODUCT} onChange={vi.fn()} idPrefix="dl" />,
    );

    for (const key of ['header', 'footer', 'side-text']) {
      const toggle = container.querySelector<HTMLInputElement>(`#dl-furniture-${key}-enabled`);
      expect(toggle, key).not.toBeNull();
      expect(toggle?.checked, key).toBe(false);
    }
  });

  it('writes a furniture edit to the NESTED policy path', () => {
    const onChange = vi.fn();
    const { container } = renderWithProviders(
      <DocumentLayoutDefaultsEditor value={PRODUCT} onChange={onChange} idPrefix="dl" />,
    );

    const input = container.querySelector('#dl-furniture-footer-text');
    fireEvent.change(input!, { target: { value: 'Página {{ page }} de {{ page_capacity }}' } });
    expect(onChange.mock.calls.at(-1)?.[0].furniture.footer.text).toBe(
      'Página {{ page }} de {{ page_capacity }}',
    );
  });

  it('writes a furniture override to the FLAT override path the server keys provenance on', () => {
    const onChange = vi.fn();
    const { container } = renderWithProviders(
      <DocumentLayoutOverridesEditor
        inherited={PRODUCT}
        inheritanceLabel="da instância"
        idPrefix="ov"
        onChange={onChange}
      />,
    );

    fireEvent.change(container.querySelector('#ov-furniture-footer-enabled-mode')!, {
      target: { value: 'override' },
    });
    // Flat `footer_enabled`, NOT nested `footer.enabled` — the shape `deny_unknown_fields` accepts.
    expect(onChange).toHaveBeenLastCalledWith({ furniture: { footer_enabled: false } });
  });

  it('reads a stored flat furniture override back into the resolved policy', () => {
    const resolved = applyDocumentLayoutOverrides(PRODUCT, {
      furniture: {
        footer_enabled: true,
        footer_text: '{{ entity_name }}',
        side_text_edge: 'Right',
      },
    });

    expect(resolved.furniture?.footer.enabled).toBe(true);
    expect(resolved.furniture?.footer.text).toBe('{{ entity_name }}');
    expect(resolved.furniture?.side_text.edge).toBe('Right');
    // Untouched leaves stay at the inherited product value rather than being materialised.
    expect(resolved.furniture?.header.enabled).toBe(false);
  });

  it('names an unknown token rather than accepting a line that would print blank', () => {
    const { container } = renderWithProviders(
      <DocumentLayoutDefaultsEditor
        value={withFurniture({ header: '{{ pagina }}' })}
        onChange={vi.fn()}
        idPrefix="dl"
      />,
    );

    const alerts = screen.getAllByRole('alert');
    expect(alerts.some((node) => node.textContent?.includes('pagina'))).toBe(true);
    // One message, not two: the echo stays silent while the template cannot be parsed.
    expect(container.querySelector('[data-furniture-echo="furniture-header-text"]')).toBeNull();
  });

  it('echoes what a valid template prints, resolved against the sample document', () => {
    const { container } = renderWithProviders(
      <DocumentLayoutDefaultsEditor
        value={withFurniture({ footer: 'Página {{ page }} de {{ page_capacity }}' })}
        onChange={vi.fn()}
        idPrefix="dl"
      />,
    );

    const echo = container.querySelector('[data-furniture-echo="furniture-footer-text"]');
    expect(echo?.textContent).toContain(
      `Página ${FURNITURE_SAMPLE_FACTS.page} de ${FURNITURE_SAMPLE_FACTS.page_capacity}`,
    );
  });

  it('lists every token of the closed vocabulary, so none has to be found in the source', () => {
    renderWithProviders(<DocumentLayoutDefaultsEditor value={PRODUCT} onChange={vi.fn()} />);

    for (const placeholder of FURNITURE_PLACEHOLDERS) {
      expect(screen.getAllByText(`{{ ${placeholder} }}`).length).toBeGreaterThan(0);
    }
  });
});
