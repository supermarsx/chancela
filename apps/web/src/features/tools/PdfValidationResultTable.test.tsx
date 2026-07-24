/**
 * The validation report renders as a real table whose verdicts read without colour, and
 * which still carries every field the previous key/value cards showed — for a validator,
 * the reason a check failed is the payload, so nothing may be dropped for tightness.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import type { PdfSignatureValidationResponse } from '../../api/types';
import { PdfValidationResultTable } from './PdfValidationResultTable';
import { PdfSignatureValidatorPanel } from './PdfSignatureValidatorPanel';
import { renderWithProviders } from '../../test/utils';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function plan(overrides: Record<string, unknown> = {}) {
  return {
    status: 'available',
    scope: 'local_technical_evidence_only',
    notice: 'Local embedded evidence planning only; not a B-LT/B-LTA or legal LTV claim.',
    signature_timestamp_present: true,
    dss_revocation_evidence_present: true,
    dss_validation_time_present: false,
    doc_timestamp_present: true,
    doc_timestamp_imprints_valid: true,
    missing_inputs: ['dss_validation_time'],
    next_action: 'record_dss_validation_time',
    has_local_evidence_gap: true,
    all_local_planning_inputs_present: false,
    production_long_term_profile_claimed: false,
    legal_ltv_claimed: false,
    ...overrides,
  };
}

/** A two-signature report whose byte-range coverage check fails, with a stated reason. */
const MULTI_SIGNATURE_REPORT: PdfSignatureValidationResponse = {
  report_kind: 'pdf_signature_validation',
  scope: 'local_technical_pdf_pades_evidence',
  legal_notice: 'Local technical PDF/PAdES evidence validation only.',
  status: 'indeterminate',
  filename: 'duas-assinaturas.pdf',
  sha256: 'a'.repeat(64),
  size_bytes: 2048,
  declared_sha256: 'a'.repeat(64),
  declared_size_bytes: 2048,
  structure: {
    is_pdf: true,
    header_offset: 0,
    version: '1.7',
    has_eof_marker: true,
    has_startxref: true,
  },
  signature: {
    status: 'indeterminate',
    validation_performed: true,
    validation_error: 'signature 2 could not be parsed to a CMS SignedData',
    signed_pdf_signal: true,
    signature_marker_count: 2,
    byte_range_marker_count: 2,
    has_contents_marker: true,
    pades_profile: 'PAdES-B-T',
    byte_range: {
      byte_range: [0, 10, 20, 30],
      covered_len: 40,
      total_len: 42,
      signed_revision_len: 42,
      excluded_len: 2,
      covers_whole_file_except_contents: false,
      covers_signed_revision_except_contents: true,
      has_later_incremental_updates: true,
      digest_sha256: 'b'.repeat(64),
    },
    cades: {
      status: 'valid',
      attrs_ok: true,
      signing_certificate_v2_present: true,
      signer_cert_sha256: 'c'.repeat(64),
      signer_cert_subject: 'CN=Amélia Marques',
      signing_time: '2026-07-10T10:00:00Z',
    },
    timestamp: { signature_timestamp_present: true, status_scope: 'technical_evidence_only' },
    dss: {
      present: true,
      vri_count: 2,
      vri_tu_count: 1,
      vri_tu_keys: ['DSS-VRI-TU-1'],
      vri_has_tu: true,
      certificate_count: 2,
      ocsp_count: 1,
      crl_count: 0,
      revocation_evidence_present: true,
      certificate_sha256: ['d'.repeat(64)],
      ocsp_sha256: ['e'.repeat(64)],
      crl_sha256: [],
      status_scope: 'technical_evidence_only',
    },
    doc_timestamp: {
      present: true,
      count: 1,
      token_count: 1,
      token_sha256: ['f'.repeat(64)],
      all_imprints_valid: false,
      validations: [
        {
          index: 0,
          object_id: '12 0 R',
          byte_range: [0, 10, 20, 30],
          document_digest_sha256: '1'.repeat(64),
          token_imprint_sha256: '2'.repeat(64),
          token_hash_algorithm: 'sha256',
          status: 'invalid',
          failure_reason: 'token imprint does not match the document digest',
        },
      ],
      status_scope: 'technical_evidence_only',
    },
    local_technical_renewal_plan: plan(),
    multi_signature_local_renewal_plan: {
      status: 'available',
      scope: 'local_technical_evidence_only',
      notice: 'Local embedded evidence planning only; not a B-LT/B-LTA or legal LTV claim.',
      signature_count: 2,
      signatures: [
        {
          index: 0,
          object_id: '8 0 R',
          signed_revision_len: 42,
          vri_key_sha256: '3'.repeat(64),
          dss_vri_present: true,
          dss_vri_validation_time_present: false,
          local_technical_renewal_plan: plan({
            missing_inputs: ['signature_one_dss_validation_time'],
            next_action: 'record_signature_one_dss_validation_time',
          }),
        },
        {
          index: 1,
          object_id: '9 0 R',
          signed_revision_len: 84,
          vri_key_sha256: '4'.repeat(64),
          dss_vri_present: false,
          dss_vri_validation_time_present: false,
          local_technical_renewal_plan: plan({
            status: 'unavailable',
            missing_inputs: ['signature_two_dss_vri'],
            next_action: 'record_signature_two_dss_vri',
          }),
        },
      ],
      signatures_with_local_evidence_gaps: [0, 1],
      next_action: 'record_multi_signature_dss_validation_time',
      has_local_evidence_gap: true,
      all_local_planning_inputs_present: false,
      production_long_term_profile_claimed: false,
      legal_ltv_claimed: false,
    },
  },
  trust: {
    status: 'not_performed',
    performed: false,
    live_trusted_list_validation_performed: false,
    ama_integration_performed: false,
    message: 'trust validation not performed',
  },
  revocation: {
    status: 'not_performed',
    live_fetch_performed: false,
    freshness_validation_performed: false,
    embedded_evidence_inspected: true,
    embedded_revocation_evidence_present: true,
    message: 'revocation freshness not performed',
  },
  qualification: {
    status: 'not_performed',
    qualified_status_claimed: false,
    legal_validity_claimed: false,
    legal_effect_assessed: false,
    message: 'qualification not assessed',
  },
  findings: [
    {
      severity: 'error',
      code: 'byte_range_does_not_cover_file',
      message: 'the signature ByteRange leaves bytes outside the signed revision',
    },
    {
      severity: 'warning',
      code: 'doc_timestamp_imprint_mismatch',
      message: 'a DocTimeStamp imprint could not be confirmed',
    },
  ],
};

function renderTable() {
  return renderWithProviders(<PdfValidationResultTable report={MULTI_SIGNATURE_REPORT} />);
}

function row(key: string): HTMLTableRowElement {
  const found = document.querySelector<HTMLTableRowElement>(`tr[data-validator-row="${key}"]`);
  if (!found) throw new Error(`no row rendered for ${key}`);
  return found;
}

function verdictOf(key: string): string {
  return row(key).querySelector('.pdf-validator-verdict')?.getAttribute('data-verdict') ?? '';
}

function verdictTextOf(key: string): string {
  return row(key).querySelector('.pdf-validator-verdict__label')?.textContent ?? '';
}

describe('PDF validation result table', () => {
  it('renders one accessible table with column headers and a caption', () => {
    renderTable();
    // Queried through the DOM rather than by role: accessible-name computation over a
    // hundred-row table is slow enough in jsdom to trip the suite timeout.
    const table = document.querySelector('table.table');
    expect(table).toBeTruthy();
    // The caption is the table's accessible name.
    expect(table?.querySelector('caption')?.textContent).toBe(
      'Verificações técnicas de validação PDF/PAdES',
    );

    const columnHeaders = Array.from(table?.querySelectorAll('thead th') ?? []).map(
      (th) => th.textContent,
    );
    expect(columnHeaders).toEqual(['Verificação', 'Resultado', 'Evidência']);
    for (const th of table?.querySelectorAll('thead th') ?? []) {
      expect(th.getAttribute('scope')).toBe('col');
    }
    // Group headers span the row and are scoped to the group they introduce.
    for (const th of table?.querySelectorAll('.pdf-validator-table__group th') ?? []) {
      expect(th.getAttribute('scope')).toBe('colgroup');
      expect(th.getAttribute('colspan')).toBe('3');
    }
    // Each check names itself through a row header, so a screen reader reading the
    // verdict cell announces which check it belongs to.
    const rowHeaders = table?.querySelectorAll('tbody th[scope="row"]') ?? [];
    expect(rowHeaders.length).toBeGreaterThan(20);
  });

  it('groups a multi-signature report so every signature keeps its own labelled rows', () => {
    renderTable();
    expect(screen.getByText('Assinatura 0 · 8 0 R')).toBeTruthy();
    expect(screen.getByText('Assinatura 1 · 9 0 R')).toBeTruthy();
    // The per-signature evidence stays attributable rather than merging into one list.
    expect(row('signature-0-8 0 R-dss-vri').textContent).toContain('Sim');
    expect(row('signature-1-9 0 R-dss-vri').textContent).toContain('Não');
    expect(screen.getByText('signature_one_dss_validation_time')).toBeTruthy();
    expect(screen.getByText('signature_two_dss_vri')).toBeTruthy();
  });

  it('distinguishes pass, fail and inconclusive by text, not only by colour', () => {
    renderTable();
    expect(verdictOf('structure-is-pdf')).toBe('pass');
    expect(verdictTextOf('structure-is-pdf')).toBe('Conforme');

    expect(verdictOf('byte-range-covers-file')).toBe('fail');
    expect(verdictTextOf('byte-range-covers-file')).toBe('Falha');

    expect(verdictOf('trust-performed')).toBe('inconclusive');
    expect(verdictTextOf('trust-performed')).toBe('Inconclusivo');

    // A measured fact is not a verdict: a version string must not read as a pass.
    expect(verdictOf('structure-version')).toBe('info');
    expect(verdictTextOf('structure-version')).toBe('Informativo');

    // The distinguishing text lives in the DOM, not in a class or a colour.
    expect(verdictTextOf('structure-is-pdf')).not.toBe(verdictTextOf('byte-range-covers-file'));
  });

  it('never treats an unclaimed legal conclusion as a failed check', () => {
    renderTable();
    expect(verdictOf('qualification-legal-validity')).toBe('info');
    expect(verdictOf('multi-plan-ltv')).toBe('info');
    expect(verdictOf('trust-live-tsl')).toBe('info');
  });

  it('keeps the reason a check failed next to the check', () => {
    renderTable();
    expect(row('signature-performed').textContent).toContain(
      'signature 2 could not be parsed to a CMS SignedData',
    );
    expect(row('docts-0-12 0 R-status').textContent).toContain(
      'token imprint does not match the document digest',
    );
    expect(row('trust-status').textContent).toContain('trust validation not performed');
    expect(row('revocation-status').textContent).toContain('revocation freshness not performed');
    expect(row('qualification-status').textContent).toContain('qualification not assessed');
  });

  it('renders findings as rows whose severity maps to a verdict', () => {
    renderTable();
    expect(verdictOf('finding-0-byte_range_does_not_cover_file')).toBe('fail');
    expect(verdictOf('finding-1-doc_timestamp_imprint_mismatch')).toBe('inconclusive');
    expect(
      screen.getByText('the signature ByteRange leaves bytes outside the signed revision'),
    ).toBeTruthy();
  });

  it('still reaches every field the key/value cards used to show', () => {
    renderTable();
    const text = document.body.textContent ?? '';
    for (const expected of [
      // File
      '2.0 KB',
      // Structure
      '1.7',
      // Signature / PAdES
      'PAdES-B-T',
      // Byte range
      '0, 10, 20, 30',
      '40 de 42 bytes',
      // CAdES
      'CN=Amélia Marques',
      '2026-07-10T10:00:00Z',
      // DSS
      'DSS-VRI-TU-1',
      'technical_evidence_only',
      // DocTimeStamp validation
      'sha256',
      // Renewal plans
      'dss_validation_time',
      'record_multi_signature_dss_validation_time',
      'Local embedded evidence planning only; not a B-LT/B-LTA or legal LTV claim.',
      // Trust / revocation / qualification
      'not_performed',
    ]) {
      expect(text, `${expected} should still reach the reader`).toContain(expected);
    }
    // Digests are shown through the shared `Digest` control, which elides the middle.
    expect(document.querySelectorAll('.digest').length).toBeGreaterThan(5);
  });

  it('bounds a wide table with horizontal scroll instead of clipping it', () => {
    renderTable();
    // `.table-wrap` is the app's shared `overflow-x: auto` container.
    expect(document.querySelector('.pdf-validator-table .table-wrap')).toBeTruthy();
  });

  it('renders the shared table skeleton while a validation is in flight', async () => {
    // A request that never settles keeps the mutation pending, which is the branch under
    // test. The skeleton is the shared `SkeletonTable`, not a bespoke placeholder.
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(() => {})) as unknown as typeof fetch);
    renderWithProviders(<PdfSignatureValidatorPanel />);
    expect(document.querySelector('.skeleton-table')).toBeNull();

    const file = new File(['%PDF-1.7\n%%EOF'], 'signed.pdf', { type: 'application/pdf' });
    fireEvent.change(screen.getByLabelText('PDF assinado'), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: /validar pdf/i }));

    await waitFor(() => expect(document.querySelector('.skeleton-table')).toBeTruthy());
    // The busy region is announced: the skeleton bars themselves are aria-hidden.
    expect(screen.getByRole('status').textContent).toContain('A validar');
  });
});

// Matches the convention in Skeleton.test.tsx / LedgerPage.test.tsx: an indirect dynamic
// import, since the web tsconfig carries no @types/node.
async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8');
}

describe('PDF validator table styling', () => {
  it('styles verdicts from theme tokens only, never literal colours', async () => {
    const css = await themeCss();
    const start = css.indexOf('.pdf-validator-table .table {');
    const end = css.indexOf(
      '}',
      css.indexOf(".pdf-validator-verdict[data-verdict='inconclusive']"),
    );
    expect(start).toBeGreaterThan(-1);
    const block = css.slice(start, end + 1);
    expect(block).toContain('var(--ok)');
    expect(block).toContain('var(--error)');
    expect(block).toContain('var(--warn)');
    expect(block).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(block).not.toMatch(/\brgba?\(/);
    expect(block).not.toMatch(/\bhsla?\(/);
  });
});
