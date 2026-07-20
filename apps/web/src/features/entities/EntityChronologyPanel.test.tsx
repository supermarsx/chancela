import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, screen } from '@testing-library/react';
import { fetchTable, renderWithProviders } from '../../test/utils';
import type { EntityChronologyView } from '../../api/types';
import { EntityChronologyPanel } from './EntityChronologyPanel';

const ENTITY_ID = '9c8f6a8d-62e4-42ea-bf20-chronology01';

const chronologyEvents = [
  {
    date: '2020-01-15',
    kind: 'Constitution',
    description: 'Constituição por pacto social',
    source_inscription: '1',
    actors: ['Amélia Marques'],
  },
];

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function renderPanel(body: unknown) {
  vi.stubGlobal('fetch', fetchTable([{ match: `/v1/entities/${ENTITY_ID}/chronology`, body }]));
  renderWithProviders(<EntityChronologyPanel entityId={ENTITY_ID} />);
}

describe('EntityChronologyPanel', () => {
  it('renders the timeline when the response omits the derived analytics block', async () => {
    renderPanel({
      events: chronologyEvents,
      mermaid: {
        shareholders: 'graph LR\n  entity["Encosto Estratégico Lda"] --> s0["Amélia Marques"]',
        organs: '',
        relationships: '',
      },
    } as unknown as EntityChronologyView);

    // The events still render, and the analytics section is dropped rather than the panel.
    // The description shows twice: once on the visual rail, once in the table.
    expect((await screen.findAllByText('Constituição por pacto social')).length).toBe(2);
    expect(screen.queryByText('Resumo analítico local')).toBeNull();
  });

  it('renders the analytics section when only the per-graph counts are absent', async () => {
    renderPanel({
      events: chronologyEvents,
      mermaid: { shareholders: '', organs: '', relationships: '' },
      analytics: {
        total_events: 1,
        dated_events: 1,
        undated_events: 0,
        event_kinds: [{ kind: 'Constitution', count: 1 }],
        source_inscription_count: 1,
        source_inscriptions: ['1'],
      },
    } as unknown as EntityChronologyView);

    expect(await screen.findByText('Resumo analítico local')).toBeTruthy();
    expect(screen.getAllByText(/Sem código Mermaid para este grafo\./).length).toBeGreaterThan(0);
  });

  it('renders when the response omits the Mermaid sources entirely', async () => {
    renderPanel({ events: chronologyEvents } as unknown as EntityChronologyView);

    // The description shows twice: once on the visual rail, once in the table.
    expect((await screen.findAllByText('Constituição por pacto social')).length).toBe(2);
    expect(screen.getAllByText('Sem código Mermaid para este grafo.').length).toBeGreaterThan(0);
  });
});
