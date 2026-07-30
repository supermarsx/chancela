/**
 * How the integrity report NAMES the chain it is reporting on.
 *
 * `BookIntegritySection.test.tsx` covers the report's verdicts and every recovery flow. What it
 * never varies is the chain id: every fixture there is the global chain. The label is not
 * decoration — an operator reading a broken-chain report acts on the chain it names, and a
 * `company:` chain rendered as a book (or a book rendered under another book's purpose) sends
 * them to re-anchor the wrong ledger.
 *
 * Two of the paths are refusals rather than lookups, and they matter most:
 *   - a chain whose book or entity is NOT in the loaded lists falls back to the truncated id
 *     rather than borrowing a neighbour's name;
 *   - a chain of a kind this build does not recognise renders verbatim, so a future chain kind is
 *     shown honestly instead of being filed under an existing one.
 *
 * Assertions are on the DATA carried into the label — the purpose, the name, the id — never on the
 * sentence around it.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';

vi.mock('../../desktop/saveFile', () => ({
  saveBlobAs: vi.fn(),
  saveBlobResultMessage: () => 'guardado',
}));

import { BookIntegritySection } from './BookIntegritySection';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const KNOWN_BOOK_ID = '11111111-2222-3333-4444-555555555555';
const KNOWN_ENTITY_ID = '99999999-8888-7777-6666-555555555555';
const UNKNOWN_BOOK_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const UNKNOWN_ENTITY_ID = 'ffffffff-0000-1111-2222-333333333333';

const BOOK = {
  id: KNOWN_BOOK_ID,
  entity_id: KNOWN_ENTITY_ID,
  kind: 'Atas',
  purpose: 'Atas da assembleia geral',
  state: 'Open',
  last_ata_number: 3,
};

const ENTITY = { id: KNOWN_ENTITY_ID, name: 'Encosto Estratégico Lda' };

function chain(id: string) {
  return {
    chain: id,
    genesis_kind: null,
    length: 2,
    head: 'aa'.repeat(32),
    verified: true,
    first_break: null,
  };
}

/** One report carrying every chain-id shape the label function has to distinguish. */
const REPORT = {
  healthy: true,
  degraded: false,
  global: chain('global'),
  chains: [
    chain('application'),
    chain(`book:${KNOWN_BOOK_ID}`),
    chain(`book:${UNKNOWN_BOOK_ID}`),
    chain(`company:${KNOWN_ENTITY_ID}`),
    chain(`company:${UNKNOWN_ENTITY_ID}`),
    // A kind this build has never seen. It must survive as itself.
    chain('archive:2026-Q1'),
  ],
  reanchored_segments: [],
};

/** The label of every chain row the report rendered, in order. */
function chainLabels(): string[] {
  return [...document.querySelectorAll('.chainrow__label')].map(
    (el) => el.textContent?.trim() ?? '',
  );
}

async function labelsAfterLoad(): Promise<string[]> {
  await waitFor(() => expect(chainLabels().length).toBeGreaterThan(6));
  return chainLabels();
}

function renderSection() {
  vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/v1/ledger/integrity')) return Promise.resolve(jsonResponse(REPORT));
    if (url.includes('/v1/books')) return Promise.resolve(jsonResponse([BOOK]));
    if (url.includes('/v1/entities')) return Promise.resolve(jsonResponse([ENTITY]));
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch);
  return renderWithProviders(<BookIntegritySection />);
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('BookIntegritySection chain labels', () => {
  it('names a known book by its purpose and a known entity by its name', async () => {
    renderSection();
    const labels = await labelsAfterLoad();

    // The operator recognises "Atas da assembleia geral", not a UUID.
    expect(labels.some((label) => label.includes('Atas da assembleia geral'))).toBe(true);
    expect(labels.some((label) => label.includes('Encosto Estratégico Lda'))).toBe(true);
    // And a named chain does not also carry the id it resolved from.
    expect(labels.some((label) => label.includes(KNOWN_BOOK_ID.slice(0, 8)))).toBe(false);
  });

  it('falls back to a truncated id when the book or entity is not loaded', async () => {
    renderSection();
    const labels = await labelsAfterLoad();

    // Eight characters of the id — enough to correlate with a log line, and unmistakably an id
    // rather than a name borrowed from another row.
    expect(labels.some((label) => label.includes(UNKNOWN_BOOK_ID.slice(0, 8)))).toBe(true);
    expect(labels.some((label) => label.includes(UNKNOWN_ENTITY_ID.slice(0, 8)))).toBe(true);
    // Never the full id, and never another row's name in its place.
    expect(labels.some((label) => label.includes(UNKNOWN_BOOK_ID))).toBe(false);
  });

  it('renders an unrecognised chain kind verbatim rather than filing it under a known one', async () => {
    renderSection();
    const labels = await labelsAfterLoad();

    // The canonical id itself, untranslated: a future chain kind must not be described as a book.
    expect(labels).toContain('archive:2026-Q1');
  });

  it('gives the global and application ledgers distinct labels of their own', async () => {
    renderSection();
    const labels = await labelsAfterLoad();

    // Two different ledgers with different meanings; a shared label would make a report about
    // one read as a report about the other. Neither is left as its bare canonical id.
    expect(labels).not.toContain('global');
    expect(labels).not.toContain('application');
    expect(new Set(labels).size).toBe(labels.length);
  });
});
