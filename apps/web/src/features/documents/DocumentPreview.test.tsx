/**
 * DocumentPreview tests (t48-e6): the renderer faithfully draws EVERY DocumentModel block
 * variant — Heading (by level), Paragraph (bold/italic runs), KeyValue, VoteTable
 * (favor/against/abstain), SignatureBlock, Rule, PageBreak — and the document metadata
 * header. It renders only server-supplied content (no client-side fabrication).
 */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { DocumentPreview } from './DocumentPreview';
import type { DocumentModel } from '../../api/types';

const doc: DocumentModel = {
  title: 'Ata número um',
  entity_name: 'Encosto Estratégico Lda',
  entity_nipc: '500600700',
  subject: 'Assembleia Geral Ordinária',
  language: 'pt-PT',
  created_at: '2026-06-30',
  blocks: [
    { type: 'Heading', level: 1, text: 'Abertura' },
    {
      type: 'Paragraph',
      runs: [
        { text: 'Presente o ', bold: false, italic: false },
        { text: 'presidente', bold: true, italic: false },
        { text: ' da mesa', bold: false, italic: true },
      ],
    },
    {
      type: 'KeyValue',
      rows: [
        { key: 'Data', value: '30-06-2026' },
        { key: 'Local', value: 'Lisboa' },
      ],
    },
    {
      type: 'VoteTable',
      rows: [{ label: 'Aprovação de contas', favor: 8, against: 2, abstain: 1 }],
    },
    { type: 'SignatureBlock', slots: [{ role: 'Presidente', name: 'Amélia Marques' }] },
    { type: 'Rule' },
    { type: 'PageBreak' },
  ],
};

afterEach(cleanup);

describe('DocumentPreview', () => {
  it('renders the document metadata header', () => {
    const { container } = render(<DocumentPreview doc={doc} />);
    expect(screen.getByText('Ata número um')).toBeTruthy();
    expect(screen.getByText('Encosto Estratégico Lda')).toBeTruthy();
    expect(screen.getByText('NIPC 500600700')).toBeTruthy();
    expect(screen.getByText('Assembleia Geral Ordinária')).toBeTruthy();
    expect(container.querySelector('.doc-preview')?.getAttribute('lang')).toBe('pt-PT');
  });

  it('renders a Heading at the right level', () => {
    render(<DocumentPreview doc={doc} />);
    const h = screen.getByText('Abertura');
    expect(h.tagName).toBe('H1');
    expect(h.className).toContain('doc-heading--1');
  });

  it('renders Paragraph runs with bold/italic styling', () => {
    render(<DocumentPreview doc={doc} />);
    const bold = screen.getByText('presidente');
    expect(bold.tagName).toBe('STRONG');
    const italic = screen.getByText('da mesa');
    expect(italic.tagName).toBe('EM');
  });

  it('renders a KeyValue definition list', () => {
    render(<DocumentPreview doc={doc} />);
    expect(screen.getByText('Data')).toBeTruthy();
    expect(screen.getByText('30-06-2026')).toBeTruthy();
    expect(screen.getByText('Local')).toBeTruthy();
    expect(screen.getByText('Lisboa')).toBeTruthy();
  });

  it('renders a VoteTable with favor/against/abstain columns and counts', () => {
    render(<DocumentPreview doc={doc} />);
    const table = document.querySelector('.doc-votetable') as HTMLElement;
    expect(within(table).getByText('A favor')).toBeTruthy();
    expect(within(table).getByText('Contra')).toBeTruthy();
    expect(within(table).getByText('Abstenções')).toBeTruthy();
    expect(within(table).getByText('Aprovação de contas')).toBeTruthy();
    expect(within(table).getByText('8')).toBeTruthy();
    expect(within(table).getByText('2')).toBeTruthy();
    expect(within(table).getByText('1')).toBeTruthy();
  });

  it('renders a SignatureBlock slot with role and name', () => {
    render(<DocumentPreview doc={doc} />);
    expect(screen.getByText('Presidente')).toBeTruthy();
    expect(screen.getByText('Amélia Marques')).toBeTruthy();
  });

  it('renders a Rule and a PageBreak', () => {
    const { container } = render(<DocumentPreview doc={doc} />);
    expect(container.querySelector('hr.doc-rule')).toBeTruthy();
    expect(container.querySelector('.doc-pagebreak')).toBeTruthy();
    expect(screen.getByText('Quebra de página')).toBeTruthy();
  });

  it('shows an honest empty state when there are no blocks', () => {
    render(<DocumentPreview doc={{ ...doc, blocks: [] }} />);
    expect(screen.getByText('O documento não tem conteúdo.')).toBeTruthy();
  });
});
