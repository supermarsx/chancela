/**
 * DocumentPreviewSkeleton tests: the preview's loading state reserves the *document's* shape
 * (the `.doc-preview` paper box, a head, body blocks and signature slots) rather than a flat
 * bar, uses the one shared `.skeleton` pulsing primitive instead of a second system, stays
 * silent to assistive tech behind a busy region, and never reaches paper.
 *
 * Assertions are structural (classes, roles, counts) — never on rendered copy.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { DocumentPreviewSkeleton } from './DocumentPreviewSkeleton';

async function readCss(path: string): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(path, 'utf8');
}

afterEach(cleanup);

describe('DocumentPreviewSkeleton', () => {
  it('announces the wait through a busy status region', () => {
    render(<DocumentPreviewSkeleton />);

    const region = screen.getByRole('status');
    expect(region.getAttribute('aria-busy')).toBe('true');
  });

  it('reserves the real document box so the swap is not a jolt', () => {
    const { container } = render(<DocumentPreviewSkeleton />);

    const paper = container.querySelector('.doc-preview');
    expect(paper).toBeTruthy();
    // The modifier is what the print rule and any future loading-only styling key on.
    expect(paper?.classList.contains('doc-preview--loading')).toBe(true);
    // Same head/body split `DocumentPreview` renders, so the column height is reserved.
    expect(paper?.querySelector('.doc-preview__head')).toBeTruthy();
    expect(paper?.querySelector('.doc-preview__body')).toBeTruthy();
    expect(paper?.querySelector('.doc-kv')).toBeTruthy();
    expect(paper?.querySelector('.doc-signatures')).toBeTruthy();
  });

  it('draws every placeholder with the one shared pulsing primitive', () => {
    const { container } = render(<DocumentPreviewSkeleton />);

    const blocks = container.querySelectorAll('.skeleton');
    expect(blocks.length).toBeGreaterThanOrEqual(12);
    // A document shape, not a single bar.
    expect(container.querySelectorAll('.doc-skeleton__paragraph').length).toBeGreaterThanOrEqual(2);
  });

  it('keeps the placeholder subtree out of the accessibility tree', () => {
    const { container } = render(<DocumentPreviewSkeleton />);

    expect(container.querySelector('.doc-preview')?.getAttribute('aria-hidden')).toBe('true');
  });

  it('defines no second shimmer: the sweep stays in the shared theme layer', async () => {
    const css = await readCss('src/features/documents/documents.css');

    expect(css).not.toMatch(/@keyframes/u);
    expect(css).toMatch(/\.doc-skeleton__paragraph\s*\{/u);
  });

  it('never prints the loading shape', async () => {
    const css = await readCss('src/features/documents/documents.css');

    expect(css).toMatch(/body\.printing-doc \.doc-preview--loading\s*\{[^}]*display:\s*none;/su);
  });
});
