import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AtaEditorPage } from './AtaEditorPage';
import { CompliancePanel } from './CompliancePanel';
import { makeClient, fetchTable } from '../../test/utils';
import { ToastProvider } from '../../ui/toast';
import { ALLOW_ALL_PERMISSIONS, StaticPermissionsProvider } from '../session/permissions';
import type { ActView, BookView, ComplianceReport } from '../../api/types';

const openExternalMock = vi.hoisted(() => vi.fn());
vi.mock('../../desktop/openExternal', () => ({
  openExternal: (url: string) => openExternalMock(url),
}));
vi.mock('../signing/SigningPanel', () => ({ SigningPanel: () => null }));

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
      { match: '/v1/acts/act-1/documents/generated', body: [] },
      { match: '/v1/acts/act-1/document/bundle', status: 404, body: { error: 'not found' } },
      { match: '/v1/acts/', body: act },
      { match: '/v1/books/', body: book },
    ]),
  );
  return render(
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <StaticPermissionsProvider value={ALLOW_ALL_PERMISSIONS}>
          <MemoryRouter initialEntries={['/acts/act-1']}>
            <Routes>
              <Route path="/acts/:id" element={<AtaEditorPage />} />
            </Routes>
          </MemoryRouter>
        </StaticPermissionsProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

function renderPanel(report: ComplianceReport) {
  return render(
    <MemoryRouter>
      <CompliancePanel report={report} />
    </MemoryRouter>,
  );
}

afterEach(() => {
  cleanup();
  openExternalMock.mockReset();
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

    renderPanel(report);

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

    renderPanel(report);

    const link = screen.getByRole('link', {
      name: /Código das Sociedades Comerciais, Artigo 63.º/i,
    });
    expect(link.getAttribute('href')).toBe(
      'https://dre.pt/dre/legislacao-consolidada/decreto-lei/1986-34443975-43518275',
    );
    expect(screen.getByText('Estatutos, Cláusula 8.ª')).toBeTruthy();
    expect(screen.getByText('Regulamento interno, ponto 4')).toBeTruthy();
  });

  it('links structured legal_basis metadata with source and article to the corpus tool', () => {
    const report = complianceReport({
      issues: [
        {
          rule_id: 'CSC-63/mesa-presidente',
          severity: 'Error',
          message: 'A ata tem de identificar o presidente da mesa.',
          legal_basis: [
            {
              source_id: 'csc consolidado',
              source_label: 'Código das Sociedades Comerciais',
              article: '63.º n.º 2',
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

    renderPanel(report);

    const link = screen.getByRole('link', {
      name: /Código das Sociedades Comerciais, Artigo 63.º/i,
    });
    expect(link.getAttribute('href')).toBe(
      '/tools?tool=legislacao&diploma=csc+consolidado&artigo=63.%C2%BA+n.%C2%BA+2',
    );
    expect(link.getAttribute('target')).toBeNull();
    expect(link.getAttribute('rel')).toBeNull();
    expect(screen.getByText('Por verificar')).toBeTruthy();
    fireEvent.click(link);
    expect(openExternalMock).not.toHaveBeenCalled();
  });

  it('links structured legal_basis metadata with source only to the corpus tool', () => {
    const report = complianceReport({
      issues: [
        {
          rule_id: 'CSC-63/mesa-presidente',
          severity: 'Warning',
          message: 'A ata tem de identificar o presidente da mesa.',
          legal_basis: [
            {
              source_id: 'csc',
              source_label: 'Código das Sociedades Comerciais',
              article: '   ',
              article_label: null,
              citation: 'Código das Sociedades Comerciais',
              verification: 'Verified',
              source_url: null,
              source_complete: true,
            },
          ],
        },
      ],
      warnings: 1,
    });

    renderPanel(report);

    const link = screen.getByRole('link', { name: /Código das Sociedades Comerciais/i });
    expect(link.getAttribute('href')).toBe('/tools?tool=legislacao&diploma=csc');
    expect(screen.getByText('Verificado')).toBeTruthy();
    expect(screen.queryByText(/fonte pendente/)).toBeNull();
  });

  it('keeps external source_url references on external URL behavior', () => {
    const report = complianceReport({
      issues: [
        {
          rule_id: 'eidas-art25',
          severity: 'Warning',
          message: 'A assinatura qualificada deve manter a equivalência legal.',
          legal_basis: [
            {
              source_label: 'Regulamento eIDAS',
              article: '25',
              article_label: 'Artigo 25.º',
              citation: 'Regulamento eIDAS, Artigo 25.º',
              verification: 'Verified',
              source_url: 'https://eur-lex.europa.eu/eli/reg/2014/910/oj',
              source_complete: true,
            },
          ],
        } as IssueWithSourceMetadata,
      ],
      warnings: 1,
    });

    renderPanel(report);

    const link = screen.getByRole('link', { name: /Regulamento eIDAS, Artigo 25.º/ });
    expect(link.getAttribute('href')).toBe('https://eur-lex.europa.eu/eli/reg/2014/910/oj');
    expect(link.getAttribute('target')).toBe('_blank');
    fireEvent.click(link);
    expect(openExternalMock).toHaveBeenCalledWith('https://eur-lex.europa.eu/eli/reg/2014/910/oj');
    expect(screen.getByText('Verificado')).toBeTruthy();
    expect(screen.queryByText(/fonte pendente/)).toBeNull();
  });

  it('keeps free-text and statute references without source_id non-linked', () => {
    const report = complianceReport({
      issues: [
        {
          rule_id: 'statute-convening',
          severity: 'Warning',
          message: 'A convocatória deve respeitar o prazo estatutário.',
          legal_basis: [
            {
              source_label: 'Estatutos',
              article: 'Cláusula 12.ª',
              citation: 'Estatutos, Cláusula 12.ª',
              verification: 'Pending',
              source_complete: false,
            },
            'Código das Sociedades Comerciais, artigo 377.º',
          ],
        } as IssueWithSourceMetadata,
      ],
      warnings: 1,
    });

    renderPanel(report);

    expect(screen.getByText('Estatutos, Cláusula 12.ª · fonte pendente')).toBeTruthy();
    expect(screen.getByText('Código das Sociedades Comerciais, artigo 377.º')).toBeTruthy();
    expect(screen.getByText('Por verificar')).toBeTruthy();
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

    renderPanel(report);

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

    renderPanel(report);

    const link = screen.getByText(longLabel);
    expect(link.tagName).toBe('A');
    expect(link.className).toContain('truncate');
    expect(link.getAttribute('title')).toBe(longLabel);
  });

  it('leaves the clean no-finding state unchanged', () => {
    const { container } = renderPanel(complianceReport());

    expect(screen.getByText('Sem questões de conformidade')).toBeTruthy();
    expect(container.querySelector('.empty')).toBeTruthy();
    expect(screen.queryByLabelText('Fonte')).toBeNull();
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('renders written-resolution local evidence review depth without proof claims', () => {
    render(
      <MemoryRouter>
        <CompliancePanel
          report={complianceReport({
            written_resolution_evidence_status: {
              status: 'bound_present',
              boundary: 'workflow_evidence_status_only',
              signed_signatory_slots: 0,
              digested_attachments: 0,
              checklist_items: 1,
              digested_checklist_items: 1,
              referenced_checklist_items: 0,
              bound_count: 1,
              referenced_only_count: 0,
              review_receipts: 1,
              latest_review_status: 'reviewed',
              reviewed_evidence_locators: 2,
              reviewed_evidence_digests: 1,
            },
          })}
        />
      </MemoryRouter>,
    );

    expect(
      screen.getByLabelText('Revisão local da evidência da deliberação por escrito'),
    ).toBeTruthy();
    expect(screen.getByText('Comprovativo registado')).toBeTruthy();
    expect(screen.getByText('Evidência vinculada presente')).toBeTruthy();
    expect(screen.getAllByText('Revista').length).toBeGreaterThan(0);
    expect(screen.getByText('Comprovativos de revisão')).toBeTruthy();
    expect(screen.getByText('Localizadores revistos')).toBeTruthy();
    expect(screen.getByText('Digests revistos')).toBeTruthy();
    expect(screen.getByText(/Apenas metadados locais/i)).toBeTruthy();
    expect(
      screen.getByText(/Não se afirma consentimento, quórum, identidade, suficiência jurídica/i),
    ).toBeTruthy();
    expect(screen.queryByText(/aceitação legal/i)).toBeNull();
    expect(screen.queryByText(/certificação por autoridade afirmada/i)).toBeNull();
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

    const { container } = renderPanel(report);

    expect(screen.getByText('convening.statute_notice.below_minimum')).toBeTruthy();
    expect(screen.getByText('entity.statute.convocation_notice_days')).toBeTruthy();
    expect(screen.getByText(/a ata regista 5 dias/i)).toBeTruthy();
    expect(screen.getByText('Estatutos, Cláusula 12.ª')).toBeTruthy();
    expect(container.querySelector('.empty')).toBeNull();
  });

  it('adds next-record guidance for missing convocation notice metadata without legal claims', () => {
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
          code: 'convening.statute_notice.missing_actual',
          severity: 'Warning',
          message:
            'Os estatutos registados exigem convocatória com pelo menos 8 dias de antecedência; a ata não regista antecedência verificável. Aviso não bloqueante.',
          threshold_id: 'entity.statute.convocation_notice_days',
          actual_days: null,
          minimum_days: 8,
        },
      ],
    };

    renderPanel(report);

    expect(screen.getByLabelText('Orientação local da convocatória')).toBeTruthy();
    expect(screen.getByText('Próximo registo local')).toBeTruthy();
    expect(
      screen.getByText(
        'Confirme a data da reunião e registe data/meio de expedição, antecedência efetiva e prova conservada.',
      ),
    ).toBeTruthy();
    expect(
      screen.getByText(
        'Aviso consultivo local sobre metadados registados; não afirma suficiência jurídica, entrega externa válida nem conclusão do workflow.',
      ),
    ).toBeTruthy();
    const pageText = document.body.textContent ?? '';
    expect(pageText).not.toMatch(/suficiência jurídica confirmada/i);
    expect(pageText).not.toMatch(/entrega externa válida confirmada/i);
    expect(pageText).not.toMatch(/workflow concluído/i);
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

    expect(await screen.findByText(/só fica disponível no estado «Em assinatura»/i)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /selar ata/i })).toBeNull();
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
    // SIG-03 is shown as an explicit alternative while signed-PDF evidence is absent.
    expect(
      screen.getByText(/Via alternativa: original assinado manualmente \(SIG-03\)/i),
    ).toBeTruthy();
  });
});
