import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AtaEditorPage } from './AtaEditorPage';
import { CompliancePanel } from './CompliancePanel';
import { makeClient, fetchTable } from '../../test/utils';
import { ToastProvider } from '../../ui/toast';
import { ALLOW_ALL_PERMISSIONS, StaticPermissionsProvider } from '../session/permissions';
import type { ActView, BookView, ComplianceReport } from '../../api/types';

type IssueWithSourceMetadata = ComplianceReport['issues'][number] & Record<string, unknown>;
type AdvisoryWithSourceMetadata = NonNullable<ComplianceReport['convening_advisories']>[number] &
  Record<string, unknown>;

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
  seal_metadata: null,
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

function complianceReport(overrides: Partial<ComplianceReport> = {}): ComplianceReport {
  return {
    rule_pack: 'csc-art63/v2',
    family: 'CommercialCompany',
    statute_overlay: false,
    issues: [],
    errors: 0,
    warnings: 0,
    seal_allowed: true,
    ...overrides,
  };
}

function renderEditor(act: ActView, compliance: ComplianceReport) {
  vi.stubGlobal(
    'fetch',
    fetchTable([
      { match: 'compliance', body: compliance },
      { match: '/v1/acts/act-1/follow-ups', body: [] },
      { match: '/v1/acts/', body: act },
      { match: '/v1/books/', body: book },
    ]),
  );
  return render(
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <StaticPermissionsProvider value={ALLOW_ALL_PERMISSIONS}>
          <MemoryRouter initialEntries={['/atas/act-1']}>
            <Routes>
              <Route path="/atas/:id" element={<AtaEditorPage />} />
            </Routes>
          </MemoryRouter>
        </StaticPermissionsProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('CompliancePanel legal-source references', () => {
  it('keeps findings without source metadata unchanged', () => {
    const report = complianceReport({
      issues: [
        {
          rule_id: 'csc-art63-deliberations',
          severity: 'Error',
          message: 'A ata tem de registar as deliberações (CSC art. 63.º n.º 2).',
        },
      ],
      errors: 1,
      seal_allowed: false,
    });

    render(<CompliancePanel report={report} />);

    expect(screen.getByText(/tem de registar as deliberações/i)).toBeTruthy();
    expect(screen.queryByLabelText('Fonte')).toBeNull();
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('renders multiple legal references as links and inert source text', () => {
    const report = complianceReport({
      issues: [
        {
          rule_id: 'csc-art63-presencas',
          severity: 'Warning',
          message: 'A lista de presenças deve estar referida na ata.',
          references: [
            {
              authority: 'Código das Sociedades Comerciais',
              article: 'Artigo 63.º, n.º 2',
              url: 'https://dre.pt/dre/legislacao-consolidada/decreto-lei/1986-34443975-43518275',
            },
            { authority: 'Estatutos', article: 'Cláusula 8.ª' },
            'Regulamento interno, ponto 4',
          ],
        } as IssueWithSourceMetadata,
      ],
      warnings: 1,
    });

    render(<CompliancePanel report={report} />);

    const link = screen.getByRole('link', {
      name: /Código das Sociedades Comerciais, Artigo 63.º/i,
    });
    expect(link.getAttribute('href')).toBe(
      'https://dre.pt/dre/legislacao-consolidada/decreto-lei/1986-34443975-43518275',
    );
    expect(screen.getByText('Estatutos, Cláusula 8.ª')).toBeTruthy();
    expect(screen.getByText('Regulamento interno, ponto 4')).toBeTruthy();
  });

  it('renders structured legal_basis metadata as pending source references', () => {
    const report = complianceReport({
      issues: [
        {
          rule_id: 'CSC-63/mesa-presidente',
          severity: 'Error',
          message: 'A ata tem de identificar o presidente da mesa.',
          legal_basis: [
            {
              source_id: 'csc',
              source_label: 'Código das Sociedades Comerciais',
              article: '63',
              article_label: 'Artigo 63.º',
              citation: 'Código das Sociedades Comerciais, Artigo 63.º',
              verification: 'Pending',
              source_url: null,
              source_complete: false,
            },
          ],
        },
      ],
      errors: 1,
      seal_allowed: false,
    });

    render(<CompliancePanel report={report} />);

    expect(
      screen.getByText('Código das Sociedades Comerciais, Artigo 63.º · fonte pendente'),
    ).toBeTruthy();
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('renders unsafe and non-http URL metadata as inert text', () => {
    const report = complianceReport({
      issues: [
        {
          rule_id: 'csc-art377-telematica',
          severity: 'Warning',
          message: 'A reunião telemática precisa de evidência técnica.',
          legal_source: { label: 'Fonte suspeita', url: 'javascript:alert(1)' },
          references: [{ url: 'ftp://example.invalid/csc-art377' }, 'data:text/html,CSC'],
        } as IssueWithSourceMetadata,
      ],
      warnings: 1,
    });

    render(<CompliancePanel report={report} />);

    expect(screen.getByText('Fonte suspeita (javascript:alert(1))')).toBeTruthy();
    expect(screen.getByText('ftp://example.invalid/csc-art377')).toBeTruthy();
    expect(screen.getByText('data:text/html,CSC')).toBeTruthy();
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('keeps long article labels readable without claiming verification', () => {
    const longLabel =
      'Código das Sociedades Comerciais, Artigo 377.º, n.º 5, meios telemáticos e autenticidade das declarações dos participantes';
    const report = complianceReport({
      issues: [
        {
          rule_id: 'csc-art377-channel',
          severity: 'Warning',
          message: 'O canal telemático deve identificar a forma de autenticação.',
          source: { label: longLabel, url: 'https://dre.pt/dre/legislacao-consolidada/artigo/377' },
        } as IssueWithSourceMetadata,
      ],
      warnings: 1,
    });

    render(<CompliancePanel report={report} />);

    const link = screen.getByText(longLabel);
    expect(link.tagName).toBe('A');
    expect(link.className).toContain('truncate');
    expect(link.getAttribute('title')).toBe(longLabel);
  });

  it('leaves the clean no-finding state unchanged', () => {
    const { container } = render(<CompliancePanel report={complianceReport()} />);

    expect(screen.getByText('Sem questões de conformidade')).toBeTruthy();
    expect(container.querySelector('.empty')).toBeTruthy();
    expect(screen.queryByLabelText('Fonte')).toBeNull();
    expect(screen.queryByRole('link')).toBeNull();
  });
});

describe('AtaEditorPage seal gating', () => {
  it('renders convening advisories returned by the compliance endpoint', () => {
    const report: ComplianceReport = {
      rule_pack: 'csc-art63/v2',
      family: 'CommercialCompany',
      statute_overlay: true,
      issues: [],
      errors: 0,
      warnings: 0,
      seal_allowed: true,
      convening_advisories: [
        {
          code: 'convening.statute_notice.below_minimum',
          severity: 'Warning',
          message:
            'Os estatutos registados exigem convocatória com pelo menos 8 dias de antecedência; a ata regista 5 dias. Aviso não bloqueante.',
          threshold_id: 'entity.statute.convocation_notice_days',
          actual_days: 5,
          minimum_days: 8,
          references: [{ authority: 'Estatutos', article: 'Cláusula 12.ª' }],
        } as AdvisoryWithSourceMetadata,
      ],
    };

    const { container } = render(<CompliancePanel report={report} />);

    expect(screen.getByText('convening.statute_notice.below_minimum')).toBeTruthy();
    expect(screen.getByText('entity.statute.convocation_notice_days')).toBeTruthy();
    expect(screen.getByText(/a ata regista 5 dias/i)).toBeTruthy();
    expect(screen.getByText('Estatutos, Cláusula 12.ª')).toBeTruthy();
    expect(container.querySelector('.empty')).toBeNull();
  });

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

  it('keeps the seal action disabled until the act reaches Signing even when compliance is clean', async () => {
    renderEditor({ ...baseAct, state: 'Draft' }, complianceReport());

    const sealButton = await screen.findByRole<HTMLButtonElement>('button', { name: /selar ata/i });
    expect(sealButton.disabled).toBe(true);
    expect(screen.getByText(/só fica disponível no estado «Em assinatura»/i)).toBeTruthy();
    expect(screen.queryByText(/está conforme e em assinatura/i)).toBeNull();
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
