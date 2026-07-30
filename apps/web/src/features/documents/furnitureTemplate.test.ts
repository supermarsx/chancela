/**
 * The client parser has to agree with `chancela-core::document_layout::parse_furniture_template`.
 * Where it is laxer, the operator gets a 422 on save with no warning in the field; where it is
 * stricter, a template the server would accept becomes unauthorable in the UI. These pin the
 * cases the two implementations can most easily drift on.
 */
import { describe, expect, it } from 'vitest';
import {
  FURNITURE_PLACEHOLDERS,
  FURNITURE_SAMPLE_FACTS,
  MAX_FURNITURE_TEXT_CHARS,
  parseFurnitureTemplate,
  previewFurnitureTemplate,
  resolveFurnitureSegments,
} from './furnitureTemplate';

describe('parseFurnitureTemplate', () => {
  it('splits literals from placeholders in reading order', () => {
    const parsed = parseFurnitureTemplate('Página {{ page }} de {{ page_capacity }}');
    expect(parsed).toEqual({
      ok: true,
      segments: [
        { kind: 'literal', text: 'Página ' },
        { kind: 'placeholder', placeholder: 'page' },
        { kind: 'literal', text: ' de ' },
        { kind: 'placeholder', placeholder: 'page_capacity' },
      ],
    });
  });

  it('recognises every advertised token, and only those', () => {
    for (const placeholder of FURNITURE_PLACEHOLDERS) {
      expect(parseFurnitureTemplate(`{{ ${placeholder} }}`).ok, placeholder).toBe(true);
    }
    expect(parseFurnitureTemplate('{{ pagina }}')).toEqual({
      ok: false,
      error: { code: 'unknown_placeholder', name: 'pagina' },
    });
  });

  it('tolerates the whitespace the server trims inside the braces', () => {
    expect(parseFurnitureTemplate('{{page}}').ok).toBe(true);
    expect(parseFurnitureTemplate('{{    page    }}').ok).toBe(true);
  });

  it('rejects an unclosed placeholder and a line break', () => {
    expect(parseFurnitureTemplate('{{ page')).toEqual({
      ok: false,
      error: { code: 'unclosed_placeholder' },
    });
    expect(parseFurnitureTemplate('cabeçalho\nrodapé')).toEqual({
      ok: false,
      error: { code: 'line_break' },
    });
    expect(parseFurnitureTemplate('cabeçalho\rrodapé')).toEqual({
      ok: false,
      error: { code: 'line_break' },
    });
  });

  it('counts the length in Unicode scalar values, exactly as the server does', () => {
    // 'ã' is one scalar value but two UTF-16 code units in NFD; an emoji is one scalar value and
    // a surrogate pair. Counting `String.length` would reject a template the server accepts.
    const atLimit = '😀'.repeat(MAX_FURNITURE_TEXT_CHARS);
    expect([...atLimit].length).toBe(MAX_FURNITURE_TEXT_CHARS);
    expect(atLimit.length).toBeGreaterThan(MAX_FURNITURE_TEXT_CHARS);
    expect(parseFurnitureTemplate(atLimit).ok).toBe(true);

    expect(parseFurnitureTemplate('a'.repeat(MAX_FURNITURE_TEXT_CHARS + 1))).toEqual({
      ok: false,
      error: {
        code: 'too_long',
        maximum: MAX_FURNITURE_TEXT_CHARS,
        actual: MAX_FURNITURE_TEXT_CHARS + 1,
      },
    });
  });

  it('accepts an empty template, which draws nothing', () => {
    expect(parseFurnitureTemplate('')).toEqual({ ok: true, segments: [] });
  });
});

describe('resolveFurnitureSegments', () => {
  it('withholds the whole line when the document lacks a fact it asks for', () => {
    const parsed = parseFurnitureTemplate('Página {{ page }} de {{ page_capacity }}');
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    expect(resolveFurnitureSegments(parsed.segments, { page: '3', page_capacity: '100' })).toBe(
      'Página 3 de 100',
    );
    // A book that declared no capacity: 'Página 3 de ' on a signed instrument states something
    // false, so the renderer prints nothing at all.
    expect(resolveFurnitureSegments(parsed.segments, { page: '3' })).toBeNull();
  });
});

describe('previewFurnitureTemplate', () => {
  it('resolves against a sample that carries every fact, so a valid template always echoes', () => {
    for (const placeholder of FURNITURE_PLACEHOLDERS) {
      expect(previewFurnitureTemplate(`{{ ${placeholder} }}`), placeholder).toBe(
        FURNITURE_SAMPLE_FACTS[placeholder],
      );
    }
  });

  it('returns nothing for a template that is not authorable', () => {
    expect(previewFurnitureTemplate('{{ pagina }}')).toBeNull();
  });
});
