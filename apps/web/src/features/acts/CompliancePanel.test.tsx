import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AtaEditorPage } from './AtaEditorPage';
import { makeClient, fetchTable } from '../../test/utils';
import type { ActView, BookView, ComplianceReport } from '../../api/types';

const baseAct: ActView = {
  id: 'act-1',
  book_id: 'book-1',
  title: 'Assembleia Geral Ordinária',
  channel: 'Physical',
  meeting_date: '2026-06-30',
  meeting_time: null,
  place: 'Lisboa',
  mesa: { presidente: null, secretarios: [] },
  agenda: [],
  attendance_reference: null,
  members_present: null,
  members_represented: null,
  referenced_documents: [],
  deliberations: 'Ponto único.',
  deliberation_items: [],
  telematic_evidence: null,
  attachments: [],
  signatories: [{ name: 'Ana', capacity: 'Chair', signed: true }],
  state: 'Signing',
  ata_number: null,
  payload_digest: null,
  seal_event_seq: null,
  retifies: null,
};

const book: BookView = {
  id: 'book-1',
  entity_id: 'ent-1',
  kind: 'AssembleiaGeral',
  state: 'Open',
  purpose: 'Atas AG',
  numbering_scheme: 'Sequential',
  opening_date: '2026-01-01',
  closing_date: null,
  closing_reason: null,
  last_ata_number: 0,
  predecessor: null,
  required_signatories_abertura: ['Presidente'],
  required_signatories_encerramento: null,
};

function renderEditor(act: ActView, compliance: ComplianceReport) {
  vi.stubGlobal(
    'fetch',
    fetchTable([
      { match: 'compliance', body: compliance },
      { match: '/v1/acts/', body: act },
      { match: '/v1/books/', body: book },
    ]),
  );
  return render(
    <QueryClientProvider client={makeClient()}>
      <MemoryRouter initialEntries={['/atas/act-1']}>
        <Routes>
          <Route path="/atas/:id" element={<AtaEditorPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('AtaEditorPage seal gating', () => {
  it('disables the seal action and lists issues when compliance has errors', async () => {
    const report: ComplianceReport = {
      rule_pack: 'csc-art63/v2',
      family: 'CommercialCompany',
      statute_overlay: false,
      issues: [
        {
          rule_id: 'csc-art63-deliberations',
          severity: 'Error',
          message: 'A ata tem de registar as deliberações (CSC art. 63.º n.º 2).',
        },
      ],
      errors: 1,
      warnings: 0,
      seal_allowed: false,
    };
    renderEditor({ ...baseAct, deliberations: '' }, report);

    const sealButton = await screen.findByRole<HTMLButtonElement>('button', { name: /selar ata/i });
    expect(sealButton.disabled).toBe(true);
    // The blocking issue message is rendered (scoped tight: several field hints also cite
    // "CSC art. 63", so match the issue's own wording).
    expect(screen.getByText(/tem de registar as deliberações/i)).toBeTruthy();
  });

  it('enables the seal action when compliance is clean and the act is Signing', async () => {
    const report: ComplianceReport = {
      rule_pack: 'csc-art63/v2',
      family: 'CommercialCompany',
      statute_overlay: false,
      issues: [],
      errors: 0,
      warnings: 0,
      seal_allowed: true,
    };
    renderEditor(baseAct, report);

    const sealButton = await screen.findByRole<HTMLButtonElement>('button', { name: /selar ata/i });
    expect(sealButton.disabled).toBe(false);
    // SIG-03 manual-signature banner shows during the signing phase.
    expect(screen.getByText(/Assinatura manual \(SIG-03\)/i)).toBeTruthy();
  });
});
