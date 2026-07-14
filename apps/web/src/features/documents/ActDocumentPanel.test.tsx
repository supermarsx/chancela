/**
 * ActDocumentPanel tests (t48-e6): the download action only appears once the act is sealed
 * AND a document exists (the DOC-03 bundle resolves), and the live preview degrades to an
 * honest "sem modelo disponível" state when the family has no template (the endpoint 422s)
 * rather than surfacing an error.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { useQueryClient } from '@tanstack/react-query';
import { ActDocumentPanel } from './ActDocumentPanel';
import { keys } from '../../api/hooks';
import { renderWithProviders } from '../../test/utils';
import { StaticPermissionsProvider, permissionsValue } from '../session/permissions';
import type {
  ActView,
  DocumentBundle,
  DocumentCanonicalConversionPreflightReport,
  DocumentImportValidationReport,
  GeneratedDocumentDispatchEvidenceList,
  GeneratedDocumentView,
  ImportedDocumentView,
  TemplateSummary,
} from '../../api/types';

const baseAct: ActView = {
  id: 'act-1',
  book_id: 'book-1',
  title: 'Assembleia Geral Anual',
  channel: 'Physical',
  meeting_date: '2026-06-30',
  meeting_time: null,
  place: 'Lisboa',
  mesa: { presidente: 'Amélia Marques', secretarios: [] },
  agenda: [],
  attendance_reference: null,
  members_present: null,
  members_represented: null,
  referenced_documents: [],
  deliberations: '',
  deliberation_items: [],
  telematic_evidence: null,
  attachments: [],
  signatories: [],
  state: 'Draft',
  ata_number: null,
  payload_digest: null,
  seal_event_seq: null,
  seal_metadata: null,
  retifies: null,
};

const bundle: DocumentBundle = {
  act_id: 'act-1',
  document: {
    id: 'doc-1',
    template_id: 'csc-ata-ag/v1',
    pdf_digest: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    profile: 'application/pdf; profile=PDF/A-2u',
    created_at: '2026-06-30T10:00:00Z',
  },
  pdf: { media_type: 'application/pdf', byte_length: 12345, download: '/v1/acts/act-1/document' },
  attachments_manifest: [],
  validation_report: {
    report_kind: 'document_bundle_validation',
    scope: 'generated_document_bundle',
    status: 'technical_consistent',
    evidence_index: {
      index_kind: 'document_bundle_evidence_index',
      status_scope: 'technical_metadata_only',
      document_id: 'doc-1',
      act_id: 'act-1',
      bundle_paths: {
        canonical_pdf_download: '/v1/acts/act-1/document',
        signed_pdf_download: null,
        attachments_manifest_json_pointer: '/attachments_manifest',
        validation_report_json_pointer: '/validation_report',
      },
      pdf_accessibility: {
        evidence_kind: 'pdf_accessibility_report',
        metadata_schema: 'chancela-pdf-accessibility-evidence/v1',
        bundle_report_json_pointer: '/validation_report/pdf_accessibility',
        archive_path_pattern: 'evidence/pdf-accessibility/{document_id}.json',
        evidence_status: 'pdf_accessibility_report_attached',
        status_scope: 'technical_metadata_only',
        pdf_ua_claimed: false,
        dglab_certification_claimed: false,
        legal_validity_claimed: false,
        pdf_ua_blockers: ['limited_tagged_structure', 'missing_role_map'],
      },
      external_validator_reports: {
        evidence_kind: 'external_validator_report_metadata',
        status_scope: 'technical_metadata_only',
        attachments: [],
      },
    },
    legal_notice:
      'Local technical evidence only; no legal validity, PDF/A conformance, qualified signature, or trust-provider validation is certified.',
    bundle_document_consistency: {
      route_act_id: 'act-1',
      stored_document_act_id: 'act-1',
      act_id_matches_document: true,
      document_id_present: true,
      template_id_present: true,
      created_at_present: true,
      profile_matches_expected: true,
      attachments_manifest_count: 0,
    },
    canonical_pdf: {
      present: true,
      media_type: 'application/pdf',
      byte_length: 12345,
      download: '/v1/acts/act-1/document',
      pdf_header_present: true,
      version: '1.7',
      eof_marker_present: true,
      startxref_present: true,
      pdfa_identification_markers_present: false,
    },
    pdf_accessibility: {
      evidence_kind: 'pdf_accessibility_report',
      metadata_schema: 'chancela-pdf-accessibility-evidence/v1',
      status_scope: 'technical_metadata_only',
      evidence_status: 'pdf_accessibility_report_attached',
      document_id: 'doc-1',
      act_id: 'act-1',
      template_id: 'csc-ata-ag/v1',
      report_source: 'chancela_doc_pdfa_accessibility_report',
      pdf_ua_claimed: false,
      dglab_certification_claimed: false,
      legal_validity_claimed: false,
      report_version: 9,
      pdf_ua_blockers: ['limited_tagged_structure', 'missing_role_map'],
      accessibility_report_json: {
        version: 9,
        pdf_ua_claimed: false,
        pdf_ua_blockers: ['limited_tagged_structure', 'missing_role_map'],
      },
    },
    fixity: {
      canonical_pdf_sha256: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
      stored_pdf_digest: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
      canonical_pdf_digest_matches_metadata: true,
      attachment_count: 0,
      attachments_with_digest: 0,
      attachments_without_digest: 0,
      signed_pdf_sha256: null,
      stored_signed_pdf_digest: null,
      signed_pdf_digest_matches_metadata: null,
    },
    signed_document: {
      present: false,
      status: 'missing_signed_pdf',
      document_id: null,
      document_id_matches_canonical: null,
      byte_length: null,
      signed_pdf_digest: null,
      signed_pdf_digest_matches_metadata: null,
      download: null,
      signing_time: null,
      signed_at: null,
      stored_signature_family: null,
      stored_evidentiary_level: null,
      trusted_list_status: null,
      signer_cert_subject_present: null,
      timestamp_token_present: null,
      structural_validation: null,
    },
    non_certification: {
      legal_validity_claimed: false,
      pdfa_conformance_certified: false,
      pdfua_conformance_claimed: false,
      qualified_signature_claimed: false,
      dglab_certification_claimed: false,
      production_ltv_claimed: false,
      trust_provider_validation_performed: false,
    },
    findings: [],
  },
};

const importedDocumentReviewNotice =
  'Operator review records a preservation workflow decision only; it does not run OCR, convert bytes, replace the canonical PDF/A, or claim legal acceptance.';

const importedDocumentReviewGuardrailChecklist = [
  'preserved_original_bytes_remain_non_canonical_evidence',
  'canonical_pdfa_record_is_not_replaced',
  'signed_pdf_artifact_is_not_created_or_validated',
  'ocr_or_conversion_output_is_not_promoted_to_canonical_records',
];

const importedDocumentPreservationPolicy = {
  review_state: 'operator_review_required',
  requires_operator_review: true,
  requires_ocr_review: false,
  canonical_record_status: 'not_canonical_record',
  signed_artifact_status: 'not_signed_artifact',
  review_guardrail_checklist: importedDocumentReviewGuardrailChecklist,
  canonical_conversion_status: 'not_performed_non_canonical_original_only',
  original_bytes_preservation_status: 'preserved_original_bytes',
  preservation_action: 'preserve_original_bytes_as_non_canonical_evidence_if_needed',
  canonical_conversion_performed: false,
  canonical_pdfa_generated: false,
  legal_acceptance_claimed: false,
};

const nonLegacyCanonicalConversionPreflight = {
  report_kind: 'legacy_imported_document_canonical_conversion_preflight',
  scope: 'local_metadata_only',
  status: 'not_attempted',
  source_format: 'not_legacy_doc_or_ole',
  review_state: 'operator_review_required',
  bounded_evidence_status: 'not_applicable_to_import_format',
  evidence_basis: [],
  blockers: ['not_legacy_doc_or_ole_import'],
  next_step: 'no_legacy_doc_canonical_conversion_preflight_action',
  local_metadata_only: true,
  original_bytes_preserved: true,
  canonical_conversion_performed: false,
  canonical_pdfa_generated: false,
  signature_validation_performed: false,
  ocr_performed: false,
  legal_acceptance_claimed: false,
  external_provider_contacted: false,
  canonical_record_replaced: false,
} satisfies DocumentCanonicalConversionPreflightReport;

const legacyDocCanonicalConversionPreflight = {
  ...nonLegacyCanonicalConversionPreflight,
  status: 'blocked',
  source_format: 'legacy_word_doc',
  review_state: 'canonical_conversion_review_required',
  bounded_evidence_status: 'metadata_only_legacy_doc_preflight',
  evidence_basis: [
    'ole_cfb_magic_detected',
    'legacy_word_doc_metadata_or_extension_detected',
    'original_bytes_preserved',
  ],
  blockers: [
    'non_canonical_import_only',
    'operator_conversion_review_required',
    'no_canonical_conversion_workflow_executed',
  ],
  next_step: 'separate_operator_review_required_before_any_canonical_conversion_workflow',
} satisfies DocumentCanonicalConversionPreflightReport;

const importedDocument: ImportedDocumentView = {
  id: 'import-1',
  act_id: 'act-1',
  filename: 'supporting-evidence.pdf',
  size_bytes: 52,
  sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  declared_content_type: 'application/pdf',
  detected_content_type: 'application/pdf',
  evidence_family: 'pdf',
  classification: 'imported_pdf_non_canonical_evidence',
  imported_at: '2026-07-09T10:15:30Z',
  imported_by: 'amelia.marques',
  operator_review_status: 'reviewed_non_canonical_original_only',
  operator_reviewed_at: '2026-07-10T09:30:00Z',
  operator_reviewed_by: 'amelia.operator',
  operator_review_note: 'Checked as non-canonical technical evidence only.',
  acknowledged_guardrail_ids: importedDocumentReviewGuardrailChecklist,
  review_history: [
    {
      decision_index: 1,
      review_status: 'reviewed_non_canonical_original_only',
      reviewed_at: '2026-07-10T09:30:00Z',
      reviewed_by: 'amelia.operator',
      review_note: 'Checked as non-canonical technical evidence only.',
      acknowledged_guardrail_ids: importedDocumentReviewGuardrailChecklist,
      bytes_in_payload: false,
      ocr_performed: false,
      canonical_conversion_performed: false,
      canonical_pdfa_generated: false,
      signed_artifact_created_or_validated: false,
      legal_acceptance_claimed: false,
      certification_claimed: false,
    },
  ],
  operator_review_notice: importedDocumentReviewNotice,
  non_canonical: true,
  requires_ocr_review: false,
  canonical_record_status: 'not_canonical_record',
  signed_artifact_status: 'not_signed_artifact',
  review_guardrail_checklist: importedDocumentReviewGuardrailChecklist,
  canonical_conversion_status: 'not_performed_non_canonical_original_only',
  canonical_conversion_performed: false,
  canonical_conversion_preflight: nonLegacyCanonicalConversionPreflight,
  legal_acceptance_claimed: false,
  preservation_policy: {
    ...importedDocumentPreservationPolicy,
    review_state: 'reviewed_non_canonical_original_only',
    requires_operator_review: false,
  },
  legal_notice:
    'Imported document preserved as non-canonical evidence only; it does not replace the generated PDF/A or signed PDF, and no legal validity, PDF/A conformance, or signature validity is claimed.',
  bytes_download: '/v1/documents/imported/import-1/bytes',
};

const absentOwnerCommunication: GeneratedDocumentView = {
  id: 'generated-absent-1',
  act_id: 'act-1',
  template_id: 'condominio-comunicacao-ausentes/v1',
  pdf_digest: 'f'.repeat(64),
  profile: 'application/pdf; profile=PDF/A-2u',
  created_at: '2026-07-11T09:15:00Z',
  download: '/v1/documents/generated/generated-absent-1',
  dispatch_evidence_status: {
    status: 'operator_evidence_partial',
    required: true,
    evidence_attached: true,
    dispatch_completed: false,
    completion_basis: 'none',
    required_recipients: ['Fração B', 'Fração C'],
    recorded_recipients: ['Fração B'],
    missing_recipients: ['Fração C'],
    note: 'operator-recorded evidence only',
  },
};

const certidaoTemplate: TemplateSummary = {
  id: 'condominio-certidao-deliberacoes/v1',
  family: 'Condominium',
  stage: 'Certidao',
  channels: ['Physical'],
  signature_policy: 'QualifiedPreferred',
  rule_pack_id: 'condominio',
  law_references: [],
  locale: 'pt-PT',
};

const extratoTemplate: TemplateSummary = {
  id: 'condominio-extrato-deliberacoes/v1',
  family: 'Condominium',
  stage: 'Extrato',
  channels: ['Physical'],
  signature_policy: 'QualifiedPreferred',
  rule_pack_id: 'condominio',
  law_references: [],
  locale: 'pt-PT',
};

const generatedCertidao: GeneratedDocumentView = {
  id: 'generated-certidao-1',
  act_id: 'act-1',
  template_id: 'condominio-certidao-deliberacoes/v1',
  pdf_digest: 'c'.repeat(64),
  profile: 'application/pdf; profile=PDF/A-2u',
  created_at: '2026-07-12T09:15:00Z',
  download: '/v1/documents/generated/generated-certidao-1',
  dispatch_evidence_status: null,
};

const generatedExtrato: GeneratedDocumentView = {
  id: 'generated-extrato-1',
  act_id: 'act-1',
  template_id: 'condominio-extrato-deliberacoes/v1',
  pdf_digest: 'd'.repeat(64),
  profile: 'application/pdf; profile=PDF/A-2u',
  created_at: '2026-07-12T09:20:00Z',
  download: '/v1/documents/generated/generated-extrato-1',
  dispatch_evidence_status: null,
};

const absentOwnerEvidence: GeneratedDocumentDispatchEvidenceList = {
  document_id: 'generated-absent-1',
  act_id: 'act-1',
  template_id: 'condominio-comunicacao-ausentes/v1',
  dispatch_evidence_status: absentOwnerCommunication.dispatch_evidence_status!,
  evidence: [
    {
      document_id: 'generated-absent-1',
      idempotency_key: 'idem-1',
      act_id: 'act-1',
      template_id: 'condominio-comunicacao-ausentes/v1',
      actor: 'amelia.marques',
      dispatched_at: '2026-07-11T10:00:00Z',
      channel: 'RegisteredLetter',
      reference: 'RL-123',
      evidence_reference: 'scan-page-4',
      imported_document_id: 'import-1',
      recipients: ['Fração B'],
      operator_note: 'Envelope handed to postal desk.',
      recorded_at: '2026-07-11T10:05:00Z',
      sending_performed_by_chancela: false,
      delivery_confirmed: false,
      legal_sufficiency_claimed: false,
      legal_notice_completion_claimed: false,
      bytes_in_payload: false,
    },
  ],
};

const importedDocumentPendingReview: ImportedDocumentView = {
  ...importedDocument,
  operator_review_status: 'operator_review_required',
  operator_reviewed_at: null,
  operator_reviewed_by: null,
  operator_review_note: null,
  operator_review_notice: importedDocumentReviewNotice,
  review_history: [],
  requires_ocr_review: false,
  canonical_record_status: 'not_canonical_record',
  signed_artifact_status: 'not_signed_artifact',
  review_guardrail_checklist: importedDocumentReviewGuardrailChecklist,
  canonical_conversion_status: 'not_performed_non_canonical_original_only',
  canonical_conversion_performed: false,
  legal_acceptance_claimed: false,
  preservation_policy: importedDocumentPreservationPolicy,
};

const unsignedImportSignature = {
  validation_status: 'unsigned',
  signed_pdf_signal: false,
  has_signature_dictionary_marker: false,
  signature_marker_count: 0,
  has_byte_range: false,
  byte_range_marker_count: 0,
  byte_range: null,
  byte_range_complete: null,
  byte_range_digest_sha256: null,
  signed_revision_bytes: null,
  covered_bytes: null,
  excluded_bytes: null,
  has_contents_marker: false,
  cryptographic_validation_performed: false,
  pades_profile: null,
  validation_error: null,
};

const baseImportValidationReport: DocumentImportValidationReport = {
  report_kind: 'document_import_validation',
  scope: 'non_canonical_import_candidate',
  legal_notice:
    'Imported document validation is local technical evidence only; no legal validity, PDF/A conformance, qualified signature, or trust-provider validation is certified.',
  filename: 'supporting-evidence.pdf',
  size_bytes: 52,
  sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  fixity: {
    size_bytes: 52,
    sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    declared_size_bytes: null,
    declared_sha256: null,
    size_matches_declared: null,
    sha256_matches_declared: null,
  },
  content_type: {
    declared: 'application/pdf',
    detected: 'application/pdf',
    declared_matches_detected: true,
  },
  classification: {
    family: 'pdf',
    classification: 'imported_pdf_non_canonical_evidence',
    non_canonical: true,
    warning:
      'Imported bytes are preserved only as non-canonical evidence; no legal conversion, PDF/A conformance, signature validity, or canonical record replacement is claimed.',
    canonical_conversion_performed: false,
    canonical_pdfa_generated: false,
    legal_validity_claimed: false,
  },
  canonical_conversion_preflight: {
    ...nonLegacyCanonicalConversionPreflight,
    original_bytes_preserved: false,
  },
  pdf: {
    is_pdf: true,
    header_offset: 0,
    version: '1.7',
    has_eof_marker: true,
    has_startxref: true,
    pdfa: {
      is_pdfa_ish: false,
      part: null,
      conformance: null,
      part_values: [],
      conformance_values: [],
      duplicate_metadata: false,
      odd_metadata: false,
    },
  },
  legacy_word: {
    is_ole_cfb: false,
    is_legacy_word_doc: false,
    filename_extension_doc: false,
    declared_content_type_msword: false,
    declared_content_type_generic: false,
    filename_extension_conflict: false,
    declared_content_type_conflict: false,
    macro_execution_performed: false,
    conversion_performed: false,
    canonical_pdfa_generated: false,
  },
  image: {
    is_image: false,
    format: null,
    width: null,
    height: null,
    declared_content_type_image: false,
    filename_extension_image: false,
    conversion_performed: false,
    canonical_pdfa_generated: false,
  },
  text: {
    is_supported_text: false,
    kind: null,
    utf8_valid: false,
    has_nul: false,
    declared_content_type_text: false,
    filename_extension_text: false,
    structure_validation_performed: false,
    conversion_performed: false,
    canonical_pdfa_generated: false,
  },
  zip_bundle: {
    is_zip: false,
    readable: false,
    entry_count: 0,
    unsafe_entry_count: 0,
    unsafe_entry_names: [],
    total_uncompressed_size: null,
    extraction_performed: false,
    canonical_pdfa_generated: false,
    validation_error: null,
  },
  signature: unsignedImportSignature,
  can_accept_non_canonical_import: true,
  findings: [],
};

const legacyWordImportValidationReport: DocumentImportValidationReport = {
  ...baseImportValidationReport,
  filename: 'board-minutes.doc',
  size_bytes: 32,
  sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  fixity: {
    ...baseImportValidationReport.fixity,
    size_bytes: 32,
    sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  },
  content_type: {
    declared: 'application/msword',
    detected: 'application/msword',
    declared_matches_detected: true,
  },
  classification: {
    ...baseImportValidationReport.classification,
    family: 'legacy_word_doc',
    classification: 'legacy_word_doc_non_canonical_evidence',
  },
  canonical_conversion_preflight: {
    ...legacyDocCanonicalConversionPreflight,
    original_bytes_preserved: false,
    evidence_basis: [
      'ole_cfb_magic_detected',
      'legacy_word_doc_metadata_or_extension_detected',
      'validation_candidate_bytes_not_persisted',
    ],
  },
  pdf: {
    ...baseImportValidationReport.pdf,
    is_pdf: false,
    header_offset: null,
    version: null,
    has_eof_marker: false,
    has_startxref: false,
  },
  legacy_word: {
    is_ole_cfb: true,
    is_legacy_word_doc: true,
    filename_extension_doc: true,
    declared_content_type_msword: true,
    declared_content_type_generic: false,
    filename_extension_conflict: false,
    declared_content_type_conflict: false,
    macro_execution_performed: false,
    conversion_performed: false,
    canonical_pdfa_generated: false,
  },
  findings: [
    {
      severity: 'info',
      code: 'legacy_word_doc_detected',
      message:
        'legacy Microsoft Word .doc/OLE CFB detected; it can be preserved only as non-canonical evidence',
    },
    {
      severity: 'info',
      code: 'legacy_word_no_macro_execution',
      message:
        'OLE CFB bytes were inspected by magic bytes and metadata only; macros and embedded objects were not executed',
    },
    {
      severity: 'info',
      code: 'legacy_word_no_pdfa_conversion',
      message:
        'no DOC-to-PDF/A conversion was performed; this import does not become the canonical PDF/A record',
    },
  ],
};

const ambiguousOlePdfValidationReport: DocumentImportValidationReport = {
  ...legacyWordImportValidationReport,
  filename: 'board-minutes.pdf',
  sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  fixity: {
    ...legacyWordImportValidationReport.fixity,
    sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  },
  content_type: {
    declared: 'application/pdf',
    detected: 'application/vnd.ms-office',
    declared_matches_detected: false,
  },
  classification: {
    ...baseImportValidationReport.classification,
    family: 'ole_compound_file',
    classification: 'ole_cfb_non_canonical_evidence',
  },
  canonical_conversion_preflight: {
    ...legacyWordImportValidationReport.canonical_conversion_preflight,
    source_format: 'ole_compound_file',
    bounded_evidence_status: 'metadata_only_ole_preflight',
    evidence_basis: ['ole_cfb_magic_detected', 'validation_candidate_bytes_not_persisted'],
    blockers: [
      'ambiguous_ole_compound_file',
      'non_canonical_import_only',
      'no_canonical_conversion_workflow_executed',
    ],
    next_step: 'resolve_ole_identity_before_any_separate_canonical_conversion_workflow',
  },
  pdf: {
    ...baseImportValidationReport.pdf,
    is_pdf: true,
  },
  legacy_word: {
    ...legacyWordImportValidationReport.legacy_word,
    is_legacy_word_doc: false,
    filename_extension_doc: false,
    declared_content_type_msword: false,
    filename_extension_conflict: true,
    declared_content_type_conflict: true,
  },
  can_accept_non_canonical_import: false,
  findings: [
    {
      severity: 'error',
      code: 'legacy_word_ambiguous_pdf',
      message:
        'candidate starts as an OLE compound file but also contains a PDF header in the first 1024 bytes',
    },
    {
      severity: 'error',
      code: 'legacy_word_filename_conflict',
      message: 'OLE compound file bytes were supplied with a non-.doc filename extension',
    },
    {
      severity: 'error',
      code: 'legacy_word_content_type_conflict',
      message:
        'OLE compound file bytes were supplied with a declared content type that is not compatible with legacy Word DOC',
    },
  ],
};

function json(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

function blobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}

function emptyImports(url: string) {
  if (url.includes('/v1/acts/') && url.includes('/documents/generated')) return json([]);
  if (url.includes('/v1/documents/imported')) return json([]);
  return null;
}

function isImportCreate(url: string) {
  return url.endsWith('/v1/documents/import');
}

function isImportValidate(url: string) {
  return url.endsWith('/v1/documents/import/validate');
}

function isBlockedReviewReceiptEndpoint(url: string) {
  const lower = url.toLowerCase();
  return (
    lower.includes('/bytes') ||
    lower.includes('/archive') ||
    lower.includes('/signed-document') ||
    lower.includes('/external-validator') ||
    lower.includes('/trust') ||
    lower.includes('/mcp')
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('ActDocumentPanel — download only post-seal', () => {
  it('hides the download while the act is a draft', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/templates')) {
        return json([
          { id: 'csc-ata-ag/v1', family: 'CommercialCompany', stage: 'Ata', locale: 'pt-PT' },
        ]);
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} family="CommercialCompany" />);

    // The template picker surfaces which model applies…
    expect(await screen.findByText('csc-ata-ag/v1')).toBeTruthy();
    // …but no download button while unsealed.
    expect(screen.queryByRole('button', { name: 'Descarregar PDF' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Descarregar Markdown' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Descarregar TXT' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Descarregar HTML' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Descarregar RTF' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Descarregar ODT' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Descarregar DOCX' })).toBeNull();
  });

  it('shows the PDF and working-copy downloads + digest once sealed and a document exists', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(
      <ActDocumentPanel
        act={sealed}
        entityName="Encosto Estratégico Lda"
        family="CommercialCompany"
      />,
    );

    expect(await screen.findByRole('button', { name: 'Descarregar PDF' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Descarregar Markdown' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Descarregar TXT' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Descarregar HTML' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Descarregar RTF' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Descarregar ODT' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Descarregar DOCX' })).toBeTruthy();
    expect(
      screen.getByText(
        'Markdown, TXT, HTML, RTF, ODT e DOCX são cópias de trabalho não probatórias para revisão; o PDF/A preservado é o documento oficial.',
      ),
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Descarregar RTF' }).getAttribute('title')).toBe(
      'Markdown, TXT, HTML, RTF, ODT e DOCX são cópias de trabalho não probatórias para revisão; o PDF/A preservado é o documento oficial.',
    );
    expect(screen.getByText('Impressão do PDF:')).toBeTruthy();
  });

  it('surfaces PDF/A metadata and unresolved legal source/threshold caveats without fake links', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(<ActDocumentPanel act={sealed} family="CommercialCompany" />);

    const metadata = await screen.findByRole('group', {
      name: 'Metadados e proveniência do documento',
    });
    expect(within(metadata).getByText('Metadados do PDF/A')).toBeTruthy();
    expect(within(metadata).getByText('csc-ata-ag/v1')).toBeTruthy();
    expect(within(metadata).getByText('application/pdf; profile=PDF/A-2u')).toBeTruthy();
    expect(
      within(metadata).getByText(
        'Não fornecida pelo bundle do documento; nenhuma ligação foi criada.',
      ),
    ).toBeTruthy();
    expect(within(metadata).getByText('Não fornecido pelo bundle do documento.')).toBeTruthy();
    expect(within(metadata).queryByRole('link')).toBeNull();
  });

  it('shows attached PDF accessibility evidence as technical no-claim metadata', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(<ActDocumentPanel act={sealed} family="CommercialCompany" />);

    const evidence = await screen.findByRole('group', {
      name: 'Evidência técnica de acessibilidade PDF',
    });
    expect(within(evidence).getByText('Evidência anexada')).toBeTruthy();
    expect(within(evidence).getByText('chancela_doc_pdfa_accessibility_report')).toBeTruthy();
    expect(within(evidence).getByText('9')).toBeTruthy();
    expect(within(evidence).getByText('2 bloqueio(s)')).toBeTruthy();
    expect(within(evidence).getByText('limited_tagged_structure')).toBeTruthy();
    expect(within(evidence).getByText('missing_role_map')).toBeTruthy();
    expect(within(evidence).getByText('pdf_ua_claimed=false')).toBeTruthy();
    expect(within(evidence).getByText('dglab_certification_claimed=false')).toBeTruthy();
    expect(within(evidence).getByText('legal_validity_claimed=false')).toBeTruthy();
    expect(
      within(evidence).getByText(
        'Metadados técnicos locais; não declaram PDF/UA, certificação DGLAB, validade legal nem conformidade de acessibilidade do PDF assinado.',
      ),
    ).toBeTruthy();
    expect(within(evidence).queryByText(/PDF\/UA conforme/i)).toBeNull();
    expect(within(evidence).queryByText(/Certificação DGLAB confirmada/i)).toBeNull();
    expect(within(evidence).queryByText(/Validade legal confirmada/i)).toBeNull();
    expect(within(evidence).queryByRole('link')).toBeNull();
  });

  it('shows unavailable PDF accessibility evidence without sidecar links or conformance claims', async () => {
    const unavailableBundle: DocumentBundle = {
      ...bundle,
      validation_report: {
        ...bundle.validation_report,
        evidence_index: {
          ...bundle.validation_report.evidence_index!,
          pdf_accessibility: {
            ...bundle.validation_report.evidence_index!.pdf_accessibility!,
            evidence_status: 'pdf_accessibility_report_unavailable',
            pdf_ua_blockers: [],
          },
        },
        pdf_accessibility: {
          evidence_kind: 'pdf_accessibility_report',
          metadata_schema: 'chancela-pdf-accessibility-evidence/v1',
          status_scope: 'technical_metadata_only',
          evidence_status: 'pdf_accessibility_report_unavailable',
          document_id: 'doc-1',
          act_id: 'act-1',
          template_id: 'csc-ata-ag/v1',
          report_source: 'unavailable',
          pdf_ua_claimed: false,
          dglab_certification_claimed: false,
          legal_validity_claimed: false,
          report_version: null,
          pdf_ua_blockers: [],
          unavailable_reason: 'document_model_unavailable_for_accessibility_report',
        },
      },
    };
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(unavailableBundle);
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(<ActDocumentPanel act={sealed} family="CommercialCompany" />);

    const evidence = await screen.findByRole('group', {
      name: 'Evidência técnica de acessibilidade PDF',
    });
    expect(within(evidence).getByText('Evidência indisponível')).toBeTruthy();
    expect(within(evidence).getByText('unavailable')).toBeTruthy();
    expect(within(evidence).getAllByText('Não indicado').length).toBeGreaterThanOrEqual(1);
    expect(within(evidence).getByText('Sem bloqueios indicados')).toBeTruthy();
    expect(
      within(evidence).getByText('document_model_unavailable_for_accessibility_report'),
    ).toBeTruthy();
    expect(within(evidence).getByText('pdf_ua_claimed=false')).toBeTruthy();
    expect(within(evidence).getByText('dglab_certification_claimed=false')).toBeTruthy();
    expect(within(evidence).getByText('legal_validity_claimed=false')).toBeTruthy();
    expect(within(evidence).queryByText(/PDF\/UA conforme/i)).toBeNull();
    expect(within(evidence).queryByText(/Certificação DGLAB confirmada/i)).toBeNull();
    expect(within(evidence).queryByText(/Validade legal confirmada/i)).toBeNull();
    expect(
      within(evidence).queryByText('evidence/pdf-accessibility/{document_id}.json'),
    ).toBeNull();
    expect(within(evidence).queryByRole('link')).toBeNull();
  });

  it('renders missing template id and profile honestly instead of blank metadata', async () => {
    const incompleteBundle: DocumentBundle = {
      ...bundle,
      document: {
        id: 'doc-1',
        pdf_digest: bundle.document.pdf_digest,
        created_at: bundle.document.created_at,
      } as DocumentBundle['document'],
    };
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(incompleteBundle);
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(<ActDocumentPanel act={sealed} family="CommercialCompany" />);

    const metadata = await screen.findByRole('group', {
      name: 'Metadados e proveniência do documento',
    });
    expect(within(metadata).getAllByText('Não indicado no bundle')).toHaveLength(2);
    expect(within(metadata).getByText('doc-1')).toBeTruthy();
  });

  it('keeps a long template id visible as metadata and does not turn it into a source link', async () => {
    const longTemplateId =
      'csc-ata-ag/sociedade-por-quotas/assembleia-geral-ordinaria-com-convocatoria-especial/v2026.07.09';
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) {
        return json({
          ...bundle,
          document: { ...bundle.document, template_id: longTemplateId },
        });
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(<ActDocumentPanel act={sealed} family="CommercialCompany" />);

    const metadata = await screen.findByRole('group', {
      name: 'Metadados e proveniência do documento',
    });
    expect(within(metadata).getByText(longTemplateId)).toBeTruthy();
    expect(within(metadata).getByTitle(longTemplateId)).toBeTruthy();
    expect(within(metadata).queryByRole('link', { name: longTemplateId })).toBeNull();
    expect(
      screen.getByText(
        'Markdown, TXT, HTML, RTF, ODT e DOCX são cópias de trabalho não probatórias para revisão; o PDF/A preservado é o documento oficial.',
      ),
    ).toBeTruthy();
  });

  it('downloads the Markdown working copy as a text/markdown .md file without replacing the PDF action', async () => {
    const calls: string[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      calls.push(url);
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/document/working-copy')) {
        return Promise.resolve(
          new Response('# Ata\n\nCópia de trabalho', {
            status: 200,
            headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
          }),
        );
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const createUrl = vi.fn((object: Blob | MediaSource) => {
      void object;
      return 'blob:working-copy';
    });
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(
      <ActDocumentPanel
        act={sealed}
        entityName="Encosto Estratégico Lda"
        family="CommercialCompany"
      />,
    );

    expect(await screen.findByRole('button', { name: 'Descarregar PDF' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Descarregar Markdown' }));

    await waitFor(() =>
      expect(calls.some((url) => url.includes('/v1/acts/act-1/document/working-copy'))).toBe(true),
    );
    await waitFor(() => expect(createUrl).toHaveBeenCalled());
    const blob = createUrl.mock.calls[0]?.[0];
    expect(blob).toBeInstanceOf(Blob);
    const markdownBlob = blob as Blob;
    expect(markdownBlob.type).toBe('text/markdown;charset=utf-8');
    expect(await blobText(markdownBlob)).toBe('# Ata\n\nCópia de trabalho');
    expect(clickedDownloads).toEqual(['encosto-estrategico-lda-ata-1-working-copy.md']);
    expect(revokeUrl).toHaveBeenCalledWith('blob:working-copy');
    expect(clickSpy).toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Descarregar PDF' })).toBeTruthy();
  });

  it('downloads TXT and HTML working copies with explicit format queries and filenames', async () => {
    const calls: string[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      calls.push(url);
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/document/working-copy?format=txt')) {
        return Promise.resolve(
          new Response('WORKING COPY - NON-EVIDENTIARY\n\nTXT copy', {
            status: 200,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
          }),
        );
      }
      if (url.includes('/document/working-copy?format=html')) {
        return Promise.resolve(
          new Response('<!doctype html><h1>WORKING COPY - NON-EVIDENTIARY</h1>', {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=utf-8' },
          }),
        );
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const objectUrls = ['blob:txt-working-copy', 'blob:html-working-copy'];
    let objectUrlIndex = 0;
    const createUrl = vi.fn((object: Blob | MediaSource) => {
      void object;
      return objectUrls[objectUrlIndex++] ?? 'blob:working-copy';
    });
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(
      <ActDocumentPanel
        act={sealed}
        entityName="Encosto Estratégico Lda"
        family="CommercialCompany"
      />,
    );

    expect(await screen.findByRole('button', { name: 'Descarregar TXT' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Descarregar TXT' }));
    await waitFor(() =>
      expect(
        calls.some((url) => url.includes('/v1/acts/act-1/document/working-copy?format=txt')),
      ).toBe(true),
    );
    await waitFor(() => expect(createUrl).toHaveBeenCalledTimes(1));
    const txtBlob = createUrl.mock.calls[0]?.[0] as Blob;
    expect(txtBlob.type).toBe('text/plain;charset=utf-8');
    expect(await blobText(txtBlob)).toContain('TXT copy');

    fireEvent.click(screen.getByRole('button', { name: 'Descarregar HTML' }));
    await waitFor(() =>
      expect(
        calls.some((url) => url.includes('/v1/acts/act-1/document/working-copy?format=html')),
      ).toBe(true),
    );
    await waitFor(() => expect(createUrl).toHaveBeenCalledTimes(2));
    const htmlBlob = createUrl.mock.calls[1]?.[0] as Blob;
    expect(htmlBlob.type).toBe('text/html;charset=utf-8');
    expect(await blobText(htmlBlob)).toContain('<!doctype html>');

    expect(clickedDownloads).toEqual([
      'encosto-estrategico-lda-ata-1-working-copy.txt',
      'encosto-estrategico-lda-ata-1-working-copy.html',
    ]);
    expect(revokeUrl).toHaveBeenCalledWith('blob:txt-working-copy');
    expect(revokeUrl).toHaveBeenCalledWith('blob:html-working-copy');
  });

  it('downloads RTF and ODT working copies with explicit format queries and filenames', async () => {
    const calls: string[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      calls.push(url);
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/document/working-copy?format=rtf')) {
        return Promise.resolve(
          new Response('{\\rtf1 WORKING COPY - NON-EVIDENTIARY}', {
            status: 200,
            headers: { 'Content-Type': 'application/rtf' },
          }),
        );
      }
      if (url.includes('/document/working-copy?format=odt')) {
        return Promise.resolve(
          new Response(new Blob(['PK\u0003\u0004odt']), {
            status: 200,
            headers: { 'Content-Type': 'application/vnd.oasis.opendocument.text' },
          }),
        );
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const objectUrls = ['blob:rtf-working-copy', 'blob:odt-working-copy'];
    let objectUrlIndex = 0;
    const createUrl = vi.fn((object: Blob | MediaSource) => {
      void object;
      return objectUrls[objectUrlIndex++] ?? 'blob:working-copy';
    });
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(
      <ActDocumentPanel
        act={sealed}
        entityName="Encosto Estratégico Lda"
        family="CommercialCompany"
      />,
    );

    expect(await screen.findByRole('button', { name: 'Descarregar RTF' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Descarregar RTF' }));
    await waitFor(() =>
      expect(
        calls.some((url) => url.includes('/v1/acts/act-1/document/working-copy?format=rtf')),
      ).toBe(true),
    );
    await waitFor(() => expect(createUrl).toHaveBeenCalledTimes(1));
    const rtfBlob = createUrl.mock.calls[0]?.[0] as Blob;
    expect(rtfBlob.type).toBe('application/rtf');
    expect(await blobText(rtfBlob)).toContain('WORKING COPY - NON-EVIDENTIARY');

    fireEvent.click(screen.getByRole('button', { name: 'Descarregar ODT' }));
    await waitFor(() =>
      expect(
        calls.some((url) => url.includes('/v1/acts/act-1/document/working-copy?format=odt')),
      ).toBe(true),
    );
    await waitFor(() => expect(createUrl).toHaveBeenCalledTimes(2));
    const odtBlob = createUrl.mock.calls[1]?.[0] as Blob;
    expect(odtBlob.type).toBe('application/vnd.oasis.opendocument.text');

    expect(clickedDownloads).toEqual([
      'encosto-estrategico-lda-ata-1-working-copy.rtf',
      'encosto-estrategico-lda-ata-1-working-copy.odt',
    ]);
    expect(revokeUrl).toHaveBeenCalledWith('blob:rtf-working-copy');
    expect(revokeUrl).toHaveBeenCalledWith('blob:odt-working-copy');
  });

  it('downloads the DOCX office working copy as a non-evidentiary .docx file', async () => {
    const calls: string[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      calls.push(url);
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/document/office')) {
        return Promise.resolve(
          new Response(new Blob(['PK\u0003\u0004docx']), {
            status: 200,
            headers: {
              'Content-Type':
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            },
          }),
        );
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const createUrl = vi.fn((object: Blob | MediaSource) => {
      void object;
      return 'blob:office';
    });
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(
      <ActDocumentPanel
        act={sealed}
        entityName="Encosto Estratégico Lda"
        family="CommercialCompany"
      />,
    );

    expect(await screen.findByRole('button', { name: 'Descarregar DOCX' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Descarregar DOCX' }));

    await waitFor(() =>
      expect(calls.some((url) => url.includes('/v1/acts/act-1/document/office'))).toBe(true),
    );
    await waitFor(() => expect(createUrl).toHaveBeenCalled());
    const blob = createUrl.mock.calls[0]?.[0];
    expect(blob).toBeInstanceOf(Blob);
    expect((blob as Blob).type).toBe(
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    );
    expect(clickedDownloads).toEqual(['encosto-estrategico-lda-ata-1-office-working-copy.docx']);
    expect(revokeUrl).toHaveBeenCalledWith('blob:office');
    expect(clickSpy).toHaveBeenCalled();
  });

  it('shows an honest "not generated" note when a sealed act has no document', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json({ error: 'sem documento' }, 404);
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(<ActDocumentPanel act={sealed} family="Condominium" />);

    expect(await screen.findByText('Documento não gerado')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Descarregar PDF' })).toBeNull();
  });
});

describe('ActDocumentPanel — generated absent-owner communications', () => {
  const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };

  it('renders generated communications, evidence rows, and no-claim copy', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/v1/acts/act-1/documents/generated')) {
        return json([absentOwnerCommunication]);
      }
      if (
        url.includes('/v1/documents/generated/generated-absent-1/dispatch-evidence') &&
        init?.method !== 'POST'
      ) {
        return json(absentOwnerEvidence);
      }
      if (url.includes('/v1/documents/imported')) return json([importedDocument]);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={sealed} family="Condominium" />);

    const list = await screen.findByRole('list', { name: 'Comunicações geradas' });
    expect(within(list).getAllByText('condominio-comunicacao-ausentes/v1')).toHaveLength(2);
    expect(within(list).getByText('operator_evidence_partial')).toBeTruthy();
    expect(within(list).getByTitle('/v1/documents/generated/generated-absent-1')).toBeTruthy();

    const status = await screen.findByRole('group', {
      name: 'Estado da evidência de comunicação gerada',
    });
    expect(within(status).getByText('1/2 destinatários')).toBeTruthy();
    expect(within(status).getByText('dispatch_completed')).toBeTruthy();
    expect(within(status).getByText('false')).toBeTruthy();
    expect(within(status).getByText('none')).toBeTruthy();
    expect(
      within(status).getByText(
        'A Chancela não enviou, não confirmou entrega e não completou aviso legal; mostra apenas evidência registada pelo operador e cobertura de destinatários.',
      ),
    ).toBeTruthy();

    const evidenceRows = await screen.findByRole('list', {
      name: 'Linhas de evidência registadas',
    });
    expect(within(evidenceRows).getByText('amelia.marques')).toBeTruthy();
    expect(within(evidenceRows).getByText('2026-07-11T10:05:00Z')).toBeTruthy();
    expect(within(evidenceRows).getByText('2026-07-11T10:00:00Z')).toBeTruthy();
    expect(within(evidenceRows).getByText('Carta registada')).toBeTruthy();
    expect(within(evidenceRows).getByText('RL-123')).toBeTruthy();
    expect(within(evidenceRows).getByText('scan-page-4')).toBeTruthy();
    expect(
      within(evidenceRows).getByRole('button', { name: 'supporting-evidence.pdf' }),
    ).toBeTruthy();
    expect(within(evidenceRows).getByText('Fração B')).toBeTruthy();
    expect(within(evidenceRows).getByText('Envelope handed to postal desk.')).toBeTruthy();
    expect(
      within(evidenceRows).getByText(
        'Envio pela Chancela=false; confirmação de entrega=false; suficiência legal=false; reivindicação de conclusão=false; bytes no payload=false.',
      ),
    ).toBeTruthy();
    expect(screen.queryByText('Aviso legal válido')).toBeNull();
  });

  it('shows post-act templates, generates an extract, downloads it, and keeps dispatch evidence scoped', async () => {
    const calls: { url: string; method?: string }[] = [];
    let generatedDocs = [absentOwnerCommunication, generatedCertidao];

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      calls.push({ url, method: init?.method });
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/v1/templates') && url.includes('stage=Certidao')) {
        return json([certidaoTemplate]);
      }
      if (url.includes('/v1/templates') && url.includes('stage=Extrato')) {
        return json([extratoTemplate]);
      }
      if (url.includes('/v1/acts/act-1/document/generate')) {
        generatedDocs = [absentOwnerCommunication, generatedCertidao, generatedExtrato];
        return json(generatedExtrato, 201);
      }
      if (url.includes('/v1/acts/act-1/documents/generated')) return json(generatedDocs);
      if (url.includes('/v1/documents/generated/generated-extrato-1')) {
        return Promise.resolve(
          new Response(new Blob(['%PDF-extrato'], { type: 'application/pdf' }), {
            status: 200,
            headers: { 'Content-Type': 'application/pdf' },
          }),
        );
      }
      if (
        url.includes('/v1/documents/generated/generated-absent-1/dispatch-evidence') &&
        init?.method !== 'POST'
      ) {
        return json(absentOwnerEvidence);
      }
      if (url.includes('/v1/documents/imported')) return json([]);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const createUrl = vi.fn((object: Blob | MediaSource) => {
      void object;
      return 'blob:generated-extrato';
    });
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    renderWithProviders(<ActDocumentPanel act={sealed} family="Condominium" />);

    expect(await screen.findByText('Minutas pós-ato')).toBeTruthy();
    expect(
      await screen.findByRole('option', { name: /Certidão - condominio-certidao/ }),
    ).toBeTruthy();
    expect(screen.getByRole('option', { name: /Extrato - condominio-extrato/ })).toBeTruthy();

    const list = await screen.findByRole('list', { name: 'Comunicações geradas' });
    const certidaoItem = within(list)
      .getAllByRole('listitem')
      .find((item) => item.textContent?.includes('condominio-certidao-deliberacoes/v1'));
    expect(certidaoItem).toBeTruthy();
    fireEvent.click(
      within(certidaoItem as HTMLElement).getByRole('button', { name: 'Ver evidência' }),
    );
    await waitFor(() =>
      expect(screen.queryByRole('form', { name: 'Registar evidência da comunicação gerada' }))
        .toBeNull(),
    );
    expect(
      calls.some((call) => call.url.includes('generated-certidao-1/dispatch-evidence')),
    ).toBe(false);

    fireEvent.change(screen.getByLabelText('Modelo'), {
      target: { value: 'condominio-extrato-deliberacoes/v1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Gerar documento' }));

    await waitFor(() =>
      expect(
        calls.some(
          (call) =>
            call.method === 'POST' &&
            call.url ===
              '/v1/acts/act-1/document/generate?template_id=condominio-extrato-deliberacoes%2Fv1',
        ),
      ).toBe(true),
    );
    const extratoItem = await waitFor(() =>
      within(list)
        .getAllByRole('listitem')
        .find((item) => item.textContent?.includes('condominio-extrato-deliberacoes/v1')),
    );
    expect(extratoItem).toBeTruthy();
    await waitFor(() => expect(extratoItem?.getAttribute('aria-current')).toBe('true'));
    expect(screen.queryByRole('form', { name: 'Registar evidência da comunicação gerada' })).toBe(
      null,
    );

    fireEvent.click(
      within(extratoItem as HTMLElement).getByRole('button', { name: 'Descarregar comunicação' }),
    );
    await waitFor(() =>
      expect(calls.some((call) => call.url === '/v1/documents/generated/generated-extrato-1')).toBe(
        true,
      ),
    );
    expect(createUrl).toHaveBeenCalled();
    expect(clickedDownloads).toEqual([
      'ata-1-generated-condominio-extrato-deliberacoes-v1-generated-extrato-1.pdf',
    ]);
    expect(revokeUrl).toHaveBeenCalledWith('blob:generated-extrato');
    expect(
      calls.some((call) => call.url.includes('generated-extrato-1/dispatch-evidence')),
    ).toBe(false);
  });

  it('selects and focuses dispatch evidence from the generated-document navigation target once', async () => {
    const scrollIntoView = vi.fn();
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
      configurable: true,
      value: scrollIntoView,
    });
    const otherCommunication: GeneratedDocumentView = {
      ...absentOwnerCommunication,
      id: 'generated-absent-2',
      download: '/v1/documents/generated/generated-absent-2',
      created_at: '2026-07-11T09:30:00Z',
      pdf_digest: 'e'.repeat(64),
    };

    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/v1/acts/act-1/documents/generated')) {
        return json([absentOwnerCommunication, otherCommunication]);
      }
      if (url.includes('/v1/documents/imported')) return json([importedDocument]);
      if (url.includes('/v1/documents/generated/') && url.includes('/dispatch-evidence')) {
        const documentId = url.includes('generated-absent-2')
          ? 'generated-absent-2'
          : 'generated-absent-1';
        return json({ ...absentOwnerEvidence, document_id: documentId });
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(
      <ActDocumentPanel
        act={sealed}
        family="Condominium"
        target={{ generatedDocumentId: 'generated-absent-2', focus: 'dispatch-evidence' }}
      />,
    );

    const list = await screen.findByRole('list', { name: 'Comunicações geradas' });
    const items = within(list).getAllByRole('listitem');
    const firstItem = items.find((item) => item.textContent?.includes('generated-absent-1'));
    const targetedItem = items.find((item) => item.textContent?.includes('generated-absent-2'));
    expect(firstItem).toBeTruthy();
    expect(targetedItem?.getAttribute('aria-current')).toBe('true');

    const form = await screen.findByRole('form', {
      name: 'Registar evidência da comunicação gerada',
    });
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalled());
    await waitFor(() => expect(document.activeElement).toBe(form));

    fireEvent.click(
      within(firstItem as HTMLElement).getByRole('button', { name: 'Ver evidência' }),
    );
    await waitFor(() => expect(firstItem?.getAttribute('aria-current')).toBe('true'));
    expect(targetedItem?.getAttribute('aria-current')).toBeNull();
  });

  it('selects and focuses imported-document review from the navigation target once', async () => {
    const scrollIntoView = vi.fn();
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
      configurable: true,
      value: scrollIntoView,
    });

    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/v1/acts/act-1/documents/generated')) {
        return json([absentOwnerCommunication]);
      }
      if (url.includes('/v1/documents/imported/import-1')) {
        return json(importedDocumentPendingReview);
      }
      if (url.includes('/v1/documents/imported')) return json([importedDocumentPendingReview]);
      if (url.includes('/v1/documents/generated/') && url.includes('/dispatch-evidence')) {
        return json(absentOwnerEvidence);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(
      <ActDocumentPanel
        act={sealed}
        family="Condominium"
        target={{ importedDocumentId: 'import-1', focus: 'import-review' }}
      />,
    );

    const list = await screen.findByRole('list', { name: 'Documentos importados' });
    const importedItem = within(list)
      .getAllByRole('listitem')
      .find((item) => item.textContent?.includes('supporting-evidence.pdf'));
    expect(importedItem).toBeTruthy();
    await waitFor(() => expect(importedItem?.getAttribute('aria-current')).toBe('true'));

    const status = await screen.findByLabelText('Estado de revisão');
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(document.activeElement).toBe(status));

    fireEvent.click(
      within(importedItem as HTMLElement).getByRole('button', { name: 'Ver metadados' }),
    );
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledTimes(1));
  });

  it('selects and focuses a generated-document navigation target that appears after refetch', async () => {
    const scrollIntoView = vi.fn();
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
      configurable: true,
      value: scrollIntoView,
    });
    const targetCommunication: GeneratedDocumentView = {
      ...absentOwnerCommunication,
      id: 'generated-absent-2',
      download: '/v1/documents/generated/generated-absent-2',
      created_at: '2026-07-11T09:30:00Z',
      pdf_digest: 'e'.repeat(64),
    };
    let includeTarget = false;

    function RefetchHarness() {
      const queryClient = useQueryClient();
      return (
        <>
          <button
            type="button"
            onClick={() => {
              void queryClient.invalidateQueries({ queryKey: keys.generatedDocuments(sealed.id) });
            }}
          >
            Refetch generated documents
          </button>
          <ActDocumentPanel
            act={sealed}
            family="Condominium"
            target={{ generatedDocumentId: 'generated-absent-2', focus: 'dispatch-evidence' }}
          />
        </>
      );
    }

    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/v1/acts/act-1/documents/generated')) {
        return json(
          includeTarget
            ? [absentOwnerCommunication, targetCommunication]
            : [absentOwnerCommunication],
        );
      }
      if (url.includes('/v1/documents/imported')) return json([importedDocument]);
      if (url.includes('/v1/documents/generated/') && url.includes('/dispatch-evidence')) {
        const documentId = url.includes('generated-absent-2')
          ? 'generated-absent-2'
          : 'generated-absent-1';
        return json({ ...absentOwnerEvidence, document_id: documentId });
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<RefetchHarness />);

    const initialList = await screen.findByRole('list', { name: 'Comunicações geradas' });
    const initialSelectedItem = within(initialList)
      .getAllByRole('listitem')
      .find((item) => item.getAttribute('aria-current') === 'true');
    expect(initialSelectedItem?.textContent).toContain('generated-absent-1');
    expect(scrollIntoView).not.toHaveBeenCalled();

    includeTarget = true;
    fireEvent.click(screen.getByRole('button', { name: 'Refetch generated documents' }));

    await waitFor(() => {
      const items = within(initialList).getAllByRole('listitem');
      const targetedItem = items.find((item) => item.textContent?.includes('generated-absent-2'));
      expect(targetedItem?.getAttribute('aria-current')).toBe('true');
    });

    const form = await screen.findByRole('form', {
      name: 'Registar evidência da comunicação gerada',
    });
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(document.activeElement).toBe(form));

    includeTarget = true;
    fireEvent.click(screen.getByRole('button', { name: 'Refetch generated documents' }));
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledTimes(1));
  });

  it('keeps the default generated document when the query target is missing', async () => {
    const scrollIntoView = vi.fn();
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
      configurable: true,
      value: scrollIntoView,
    });
    const otherCommunication: GeneratedDocumentView = {
      ...absentOwnerCommunication,
      id: 'generated-absent-2',
      download: '/v1/documents/generated/generated-absent-2',
      created_at: '2026-07-11T09:30:00Z',
      pdf_digest: 'e'.repeat(64),
    };

    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/v1/acts/act-1/documents/generated')) {
        return json([absentOwnerCommunication, otherCommunication]);
      }
      if (url.includes('/v1/documents/imported')) return json([importedDocument]);
      if (url.includes('/v1/documents/generated/generated-absent-1/dispatch-evidence')) {
        return json(absentOwnerEvidence);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(
      <ActDocumentPanel
        act={sealed}
        family="Condominium"
        target={{ generatedDocumentId: 'missing-generated', focus: 'dispatch-evidence' }}
      />,
    );

    const list = await screen.findByRole('list', { name: 'Comunicações geradas' });
    const selectedItem = within(list)
      .getAllByRole('listitem')
      .find((item) => item.getAttribute('aria-current') === 'true');
    expect(selectedItem?.textContent).toContain('generated-absent-1');
    expect(scrollIntoView).not.toHaveBeenCalled();
  });

  it('posts metadata-only evidence with selected recipients and a locator', async () => {
    const pendingCommunication: GeneratedDocumentView = {
      ...absentOwnerCommunication,
      dispatch_evidence_status: {
        ...absentOwnerCommunication.dispatch_evidence_status!,
        status: 'required_pending',
        evidence_attached: false,
        recorded_recipients: [],
        missing_recipients: ['Fração B', 'Fração C'],
      },
    };
    const pendingEvidence: GeneratedDocumentDispatchEvidenceList = {
      ...absentOwnerEvidence,
      dispatch_evidence_status: pendingCommunication.dispatch_evidence_status!,
      evidence: [],
    };
    const recordedBodies: unknown[] = [];

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/v1/acts/act-1/documents/generated')) return json([pendingCommunication]);
      if (url.includes('/v1/documents/imported')) return json([importedDocument]);
      if (url.includes('/v1/documents/generated/generated-absent-1/dispatch-evidence')) {
        if (init?.method === 'POST') {
          recordedBodies.push(JSON.parse(String(init.body)));
          return json(
            {
              evidence: absentOwnerEvidence.evidence[0],
              dispatch_evidence_status: absentOwnerCommunication.dispatch_evidence_status,
            },
            201,
          );
        }
        return json(pendingEvidence);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={sealed} family="Condominium" />);

    const form = await screen.findByRole('form', {
      name: 'Registar evidência da comunicação gerada',
    });
    const submit = within(form).getByRole('button', { name: 'Registar evidência' });
    expect((submit as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(within(form).getByLabelText('Data/hora registada'), {
      target: { value: '2026-01-11T11:30' },
    });
    fireEvent.change(within(form).getByLabelText('Canal'), { target: { value: 'Email' } });
    fireEvent.change(within(form).getByLabelText('Referência'), {
      target: { value: 'email-outbox-77' },
    });
    fireEvent.change(within(form).getByLabelText('Documento importado'), {
      target: { value: 'import-1' },
    });
    fireEvent.click(within(form).getByLabelText('Fração C'));
    fireEvent.change(within(form).getByLabelText('Nota do operador'), {
      target: { value: 'Operator-recorded evidence only.' },
    });
    expect((submit as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(submit);

    await waitFor(() => expect(recordedBodies).toHaveLength(1));
    expect(recordedBodies[0]).toEqual({
      actor: 'web-operator',
      dispatched_at: '2026-01-11T11:30:00.000Z',
      channel: 'Email',
      reference: 'email-outbox-77',
      recipients: ['Fração B'],
      evidence_reference: null,
      imported_document_id: 'import-1',
      operator_note: 'Operator-recorded evidence only.',
    });
  });

  it('keeps evidence submit permission-gated', async () => {
    let postCount = 0;
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/v1/acts/act-1/documents/generated')) {
        return json([absentOwnerCommunication]);
      }
      if (url.includes('/v1/documents/imported')) return json([importedDocument]);
      if (url.includes('/v1/documents/generated/generated-absent-1/dispatch-evidence')) {
        if (init?.method === 'POST') {
          postCount += 1;
          return json(absentOwnerEvidence, 201);
        }
        return json(absentOwnerEvidence);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'document.generate')}
      >
        <ActDocumentPanel act={sealed} family="Condominium" />
      </StaticPermissionsProvider>,
    );

    const form = await screen.findByRole('form', {
      name: 'Registar evidência da comunicação gerada',
    });
    fireEvent.change(within(form).getByLabelText('Referência'), {
      target: { value: 'RL-456' },
    });
    const submit = within(form).getByRole('button', { name: 'Registar evidência' });
    expect(submit.getAttribute('data-gated')).toBe('true');
    expect(submit.getAttribute('aria-disabled')).toBe('true');
    fireEvent.click(submit);
    await waitFor(() => expect(postCount).toBe(0));
  });
});

describe('ActDocumentPanel — imported evidence documents', () => {
  it('shows an evidence-only import affordance and an empty state without validity claims', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} />);

    expect(await screen.findByText('Nenhum documento importado')).toBeTruthy();
    expect(screen.getByLabelText('Importar evidência')).toBeTruthy();
    expect(screen.getByText('Evidência não canónica')).toBeTruthy();
    expect(
      screen.getByText(
        'Documentos importados ficam guardados como evidência ou referência não canónica. Não substituem o PDF/A preservado nem qualquer PDF assinado; a importação não declara validade legal, conformidade PDF/A ou validade de assinatura.',
      ),
    ).toBeTruthy();
    expect(screen.queryByText('Assinatura válida')).toBeNull();
    expect(screen.queryByText('PDF/A válido')).toBeNull();
  });

  it('lists imported documents and reads metadata with missing filenames and long values intact', async () => {
    const longId =
      'import-long-id-0000000000000000000000000000000000000000000000000000000000000000';
    const longFilename =
      'assembleia-geral-extraordinaria-anexos-de-suporte-com-nome-muito-longo-2026-07-09.pdf';
    const missingName: ImportedDocumentView = {
      ...importedDocument,
      id: longId,
      filename: null,
      declared_content_type: null,
      detected_content_type: 'application/octet-stream',
      evidence_family: 'unknown',
      classification: 'unsupported_document_evidence',
      sha256: 'a'.repeat(64),
      bytes_download: `/v1/documents/imported/${longId}/bytes`,
    };
    const longNamed: ImportedDocumentView = {
      ...importedDocument,
      id: 'import-2',
      filename: longFilename,
      sha256: 'b'.repeat(64),
      bytes_download: '/v1/documents/imported/import-2/bytes',
    };
    const calls: string[] = [];

    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      calls.push(url);
      if (url.includes(`/v1/documents/imported/${encodeURIComponent(longId)}/bytes`)) {
        return Promise.resolve(
          new Response(new Blob(['import bytes'], { type: 'application/octet-stream' }), {
            status: 200,
          }),
        );
      }
      if (url.includes(`/v1/documents/imported/${encodeURIComponent(longId)}`)) {
        return json(missingName);
      }
      if (url.includes('/v1/documents/imported')) return json([missingName, longNamed]);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const createUrl = vi.fn((object: Blob | MediaSource) => {
      void object;
      return 'blob:imported';
    });
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    renderWithProviders(<ActDocumentPanel act={baseAct} />);

    const list = await screen.findByRole('list', { name: 'Documentos importados' });
    expect(within(list).getByText('Documento importado sem nome')).toBeTruthy();
    expect(within(list).getByText(longFilename)).toBeTruthy();
    expect(within(list).getByTitle(longFilename)).toBeTruthy();

    const firstItem = within(list).getAllByRole('listitem')[0];
    fireEvent.click(within(firstItem).getByRole('button', { name: 'Ver metadados' }));

    const metadata = await screen.findByRole('group', {
      name: 'Metadados do documento importado',
    });
    const summary = await screen.findByRole('group', {
      name: 'Resumo de profundidade da revisão importada',
    });
    expect(within(metadata).getByText('Nome não fornecido pelo importador')).toBeTruthy();
    expect(within(metadata).getByTitle(longId)).toBeTruthy();
    expect(within(metadata).getByText('Não declarado')).toBeTruthy();
    expect(within(metadata).getByText('application/octet-stream')).toBeTruthy();
    expect(within(metadata).getByText('Não canónico')).toBeTruthy();
    expect(within(summary).getByText(/Bytes preservados/)).toBeTruthy();
    expect(within(summary).getByText(/digest SHA-256/i)).toBeTruthy();
    expect(within(summary).getByText(/aceitação legal: não/i)).toBeTruthy();
    expect(calls.some((url) => url.includes(`/v1/documents/imported/${longId}`))).toBe(true);

    fireEvent.click(within(firstItem).getByRole('button', { name: 'Descarregar importado' }));

    await waitFor(() =>
      expect(calls.some((url) => url.includes(`/v1/documents/imported/${longId}/bytes`))).toBe(
        true,
      ),
    );
    expect(clickedDownloads).toEqual([`documento-importado-${longId}.bin`]);
    expect(revokeUrl).toHaveBeenCalledWith('blob:imported');
    expect(screen.queryByText('Assinatura válida')).toBeNull();
  });

  it('keeps terminal imported-document review disabled until guardrails are acknowledged', async () => {
    let reviewAttempts = 0;

    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/v1/documents/imported/import-1/review')) {
        reviewAttempts += 1;
        return json(importedDocumentPendingReview);
      }
      if (url.includes('/v1/documents/imported/import-1'))
        return json(importedDocumentPendingReview);
      if (url.includes('/v1/documents/imported')) return json([importedDocumentPendingReview]);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} />);

    const list = await screen.findByRole('list', { name: 'Documentos importados' });
    fireEvent.click(within(list).getByRole('button', { name: 'Ver metadados' }));
    const receipt = await screen.findByRole('group', { name: 'Recibo de revisão' });
    const history = await screen.findByRole('group', { name: 'Histórico técnico de revisão' });
    const summary = await screen.findByRole('group', {
      name: 'Resumo de profundidade da revisão importada',
    });
    const save = await screen.findByRole('button', { name: 'Guardar revisão' });
    const acknowledgement = screen.getByLabelText(
      /Confirmo que revi estes limites/,
    ) as HTMLInputElement;

    expect(within(summary).getByText('Resumo de profundidade da revisão')).toBeTruthy();
    expect(within(summary).getByText(/Bytes preservados/)).toBeTruthy();
    expect(within(summary).getByText(/digest SHA-256/i)).toBeTruthy();
    expect(within(summary).getByText(/Revisão do operador necessária/i)).toBeTruthy();
    expect(within(summary).getByText(/nota do operador\s+não indicada/i)).toBeTruthy();
    expect(within(summary).getByText(/Histórico técnico: sem decisões/i)).toBeTruthy();
    expect(within(summary).getByText(/OCR, conversão, substituição de PDF\/A/i)).toBeTruthy();
    expect(within(summary).getByText(/PDF assinado, validação de assinatura, selo/i)).toBeTruthy();
    expect(within(summary).getByText(/PDF\/UA e aceitação legal/i)).toBeTruthy();
    expect(within(summary).getByText(/OCR: não · conversão: não/i)).toBeTruthy();
    expect(within(summary).queryByText(/Assinatura válida/i)).toBeNull();
    expect(within(summary).queryByText(/Conversão concluída/i)).toBeNull();
    expect(within(summary).queryByText(/PDF\/A certificado/i)).toBeNull();
    expect(within(receipt).getByText('Estado do recibo')).toBeTruthy();
    expect(within(receipt).getByText('Revisão do operador necessária')).toBeTruthy();
    expect(within(receipt).getByText('Revisto em')).toBeTruthy();
    expect(within(receipt).getByText('Revisto por')).toBeTruthy();
    expect(within(receipt).getByText('Nota registada')).toBeTruthy();
    expect(within(receipt).getAllByText('Não indicado no recibo')).toHaveLength(2);
    expect(within(receipt).getByText('Sem nota registada')).toBeTruthy();
    expect(within(receipt).getByText('OCR')).toBeTruthy();
    expect(within(receipt).getByText('Não efetuado por esta revisão.')).toBeTruthy();
    expect(within(receipt).getByText('Conversão')).toBeTruthy();
    expect(within(receipt).getByText('Não efetuada por esta revisão.')).toBeTruthy();
    expect(within(receipt).getByText('Substituição do PDF/A canónico')).toBeTruthy();
    expect(within(receipt).getByText('Não substituído por este documento.')).toBeTruthy();
    expect(within(receipt).getByText('PDF assinado')).toBeTruthy();
    expect(within(receipt).getByText('Não criado nem validado por esta revisão.')).toBeTruthy();
    expect(within(receipt).getByText('Aceitação legal')).toBeTruthy();
    expect(within(receipt).getByText('Não declarada por esta revisão.')).toBeTruthy();
    expect(within(history).getByText('Histórico técnico de revisão')).toBeTruthy();
    expect(
      within(history).getByText(
        'Sem histórico técnico registado para além dos metadados atuais da revisão.',
      ),
    ).toBeTruthy();
    expect((save as HTMLButtonElement).disabled).toBe(true);
    expect(acknowledgement.checked).toBe(false);
    fireEvent.click(save);
    expect(reviewAttempts).toBe(0);

    fireEvent.click(acknowledgement);

    expect(acknowledgement.checked).toBe(true);
    expect((save as HTMLButtonElement).disabled).toBe(false);
  });

  it('shows operator review metadata and patches a conservative review status after guardrail acknowledgement', async () => {
    const reviewBodies: unknown[] = [];
    const calls: { url: string; method: string }[] = [];
    let current: ImportedDocumentView = importedDocumentPendingReview;

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method });
      if (url.includes('/v1/documents/imported/import-1/review')) {
        const body = JSON.parse(String(init?.body));
        reviewBodies.push(body);
        current = {
          ...importedDocumentPendingReview,
          operator_review_status: body.review_status,
          operator_reviewed_at: '2026-07-10T09:30:00Z',
          operator_reviewed_by: 'amelia.operator',
          operator_review_note: body.review_note,
          acknowledged_guardrail_ids: body.acknowledged_guardrail_ids,
          review_history: [
            {
              decision_index: 1,
              review_status: 'operator_review_required',
              reviewed_at: '2026-07-09T10:20:00Z',
              reviewed_by: 'ana.reviewer',
              review_note: 'Triagem inicial mantida como evidência não canónica.',
              acknowledged_guardrail_ids: body.acknowledged_guardrail_ids,
              bytes_in_payload: false,
              ocr_performed: false,
              canonical_conversion_performed: false,
              canonical_pdfa_generated: false,
              signed_artifact_created_or_validated: false,
              legal_acceptance_claimed: false,
              certification_claimed: false,
            },
            {
              decision_index: 2,
              review_status: body.review_status,
              reviewed_at: '2026-07-10T09:30:00Z',
              reviewed_by: 'amelia.operator',
              review_note: body.review_note,
              acknowledged_guardrail_ids: body.acknowledged_guardrail_ids,
              bytes_in_payload: false,
              ocr_performed: false,
              canonical_conversion_performed: false,
              canonical_pdfa_generated: false,
              signed_artifact_created_or_validated: false,
              legal_acceptance_claimed: false,
              certification_claimed: false,
            },
          ],
        };
        return json(current);
      }
      if (url.includes('/v1/documents/imported/import-1')) return json(current);
      if (url.includes('/v1/documents/imported')) return json([current]);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} />);

    const list = await screen.findByRole('list', { name: 'Documentos importados' });
    expect(within(list).getByText('Revisão do operador necessária')).toBeTruthy();
    fireEvent.click(within(list).getByRole('button', { name: 'Ver metadados' }));

    const metadata = await screen.findByRole('group', {
      name: 'Metadados do documento importado',
    });
    const receipt = await screen.findByRole('group', { name: 'Recibo de revisão' });
    const history = await screen.findByRole('group', { name: 'Histórico técnico de revisão' });
    const summary = await screen.findByRole('group', {
      name: 'Resumo de profundidade da revisão importada',
    });
    expect(within(metadata).getByText('Revisão do operador necessária')).toBeTruthy();
    expect(within(metadata).getByText(importedDocumentReviewNotice)).toBeTruthy();
    expect(within(summary).getByText(/Resumo de profundidade da revisão/)).toBeTruthy();
    expect(within(summary).getByText(/Bytes preservados/)).toBeTruthy();
    expect(within(summary).getByText(/aceitação legal: não/i)).toBeTruthy();
    expect(within(summary).getByText(/Histórico técnico: sem decisões/i)).toBeTruthy();
    expect(within(receipt).getByText('Estado do recibo')).toBeTruthy();
    expect(within(receipt).getByText('Revisão do operador necessária')).toBeTruthy();
    expect(within(receipt).getByText('Limites exigidos')).toBeTruthy();
    expect(within(receipt).getByText('Limites reconhecidos')).toBeTruthy();
    expect(within(receipt).getAllByText('Não indicado no recibo')).toHaveLength(2);
    expect(within(receipt).getByText('Sem nota registada')).toBeTruthy();
    expect(within(metadata).getByText('Limites de preservação')).toBeTruthy();
    expect(within(metadata).getByText('Registo canónico')).toBeTruthy();
    expect(within(metadata).getByText('Não substitui o PDF/A canónico preservado.')).toBeTruthy();
    expect(within(metadata).getByText('Artefacto assinado')).toBeTruthy();
    expect(within(metadata).getByText('Não cria nem valida PDF assinado.')).toBeTruthy();
    expect(
      within(metadata).getByText(
        'Bytes originais permanecem preservados apenas como evidência não canónica.',
      ),
    ).toBeTruthy();
    expect(
      within(metadata).getByText(
        'Nenhum artefacto assinado é criado ou validado por esta importação.',
      ),
    ).toBeTruthy();
    expect(within(metadata).getAllByText('Não indicado').length).toBeGreaterThanOrEqual(2);

    const status = screen.getByLabelText('Estado de revisão') as HTMLSelectElement;
    expect(Array.from(status.options).map((option) => option.value)).toEqual([
      'reviewed_non_canonical_original_only',
      'rejected_non_canonical_evidence',
    ]);
    fireEvent.change(status, { target: { value: 'rejected_non_canonical_evidence' } });
    fireEvent.change(screen.getByLabelText('Nota da revisão'), {
      target: { value: 'Conferido contra o original preservado.' },
    });
    const save = screen.getByRole('button', { name: 'Guardar revisão' }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/Confirmo que revi estes limites/));
    expect(save.disabled).toBe(false);
    const callsBeforeReview = calls.length;
    fireEvent.click(save);

    await waitFor(() => expect(reviewBodies).toHaveLength(1));
    expect(reviewBodies[0]).toEqual({
      review_status: 'rejected_non_canonical_evidence',
      acknowledged_guardrail_ids: importedDocumentReviewGuardrailChecklist,
      review_note: 'Conferido contra o original preservado.',
    });
    expect(
      calls.some(
        (call) =>
          call.method === 'PATCH' && call.url.includes('/v1/documents/imported/import-1/review'),
      ),
    ).toBe(true);
    const reviewCalls = calls.slice(callsBeforeReview);
    expect(reviewCalls.some((call) => call.method === 'PATCH')).toBe(true);
    expect(reviewCalls.filter((call) => isBlockedReviewReceiptEndpoint(call.url))).toEqual([]);
    await waitFor(() =>
      expect(within(metadata).getByText('Rejeitado como evidência não canónica')).toBeTruthy(),
    );
    await waitFor(() =>
      expect(within(receipt).getByText('Rejeitado como evidência não canónica')).toBeTruthy(),
    );
    expect(within(receipt).getByText('Revisto em')).toBeTruthy();
    expect(within(receipt).getByText('2026-07-10T09:30:00Z')).toBeTruthy();
    expect(within(receipt).getByText('Revisto por')).toBeTruthy();
    expect(within(receipt).getByText('amelia.operator')).toBeTruthy();
    expect(within(receipt).getByText('Nota registada')).toBeTruthy();
    expect(within(receipt).getByText('Conferido contra o original preservado.')).toBeTruthy();
    expect(within(receipt).getByText('Limites exigidos')).toBeTruthy();
    expect(within(receipt).getByText('Limites reconhecidos')).toBeTruthy();
    expect(
      within(receipt).getAllByText(
        'Bytes originais permanecem preservados apenas como evidência não canónica.',
      ),
    ).toHaveLength(2);
    expect(
      within(receipt).getAllByText('OCR ou conversão não são promovidos a registos canónicos.'),
    ).toHaveLength(2);
    expect(within(receipt).getByText('Não efetuado por esta revisão.')).toBeTruthy();
    expect(within(receipt).getByText('Não efetuada por esta revisão.')).toBeTruthy();
    expect(within(receipt).getByText('Não substituído por este documento.')).toBeTruthy();
    expect(within(receipt).getByText('Não criado nem validado por esta revisão.')).toBeTruthy();
    expect(within(receipt).getByText('Não declarada por esta revisão.')).toBeTruthy();
    expect(await screen.findAllByText('2026-07-10T09:30:00Z')).toHaveLength(3);
    expect(await screen.findAllByText('amelia.operator')).toHaveLength(3);
    expect(within(history).getByText('Histórico técnico de revisão')).toBeTruthy();
    expect(
      within(history).getByText('Triagem inicial mantida como evidência não canónica.'),
    ).toBeTruthy();
    expect(within(history).getByText('Conferido contra o original preservado.')).toBeTruthy();
    expect(within(history).getAllByText(/Histórico de revisão metadata-only/i)).toHaveLength(2);
    expect(
      within(history).getAllByText(/sem OCR, conversão, substituição de PDF\/A/i),
    ).toHaveLength(2);
    expect(within(history).getAllByText(/certificação ou aceitação legal/i)).toHaveLength(2);
    expect(within(history).queryByText(/certificado/i)).toBeNull();
    await waitFor(() =>
      expect(within(metadata).getByText('Conferido contra o original preservado.')).toBeTruthy(),
    );
    expect(screen.queryByText('OCR concluído')).toBeNull();
    expect(screen.queryByText('Conversão concluída')).toBeNull();
  });

  it('keeps imported-document review disabled when the operator lacks document.generate', async () => {
    let reviewAttempts = 0;

    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/v1/documents/imported/import-1/review')) {
        reviewAttempts += 1;
        return json(importedDocumentPendingReview);
      }
      if (url.includes('/v1/documents/imported/import-1'))
        return json(importedDocumentPendingReview);
      if (url.includes('/v1/documents/imported')) return json([importedDocumentPendingReview]);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'document.generate')}
      >
        <ActDocumentPanel act={baseAct} />
      </StaticPermissionsProvider>,
    );

    const list = await screen.findByRole('list', { name: 'Documentos importados' });
    fireEvent.click(within(list).getByRole('button', { name: 'Ver metadados' }));
    const save = await screen.findByRole('button', { name: 'Guardar revisão' });

    expect(save.getAttribute('aria-disabled')).toBe('true');
    fireEvent.click(save);
    expect(reviewAttempts).toBe(0);
  });

  it('imports an uploaded file for the current act after server-side validation', async () => {
    const bodies: unknown[] = [];
    const validationBodies: unknown[] = [];
    let stored = false;

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (isImportValidate(url)) {
        validationBodies.push(JSON.parse(String(init?.body)));
        return json(baseImportValidationReport);
      }
      if (isImportCreate(url)) {
        bodies.push(JSON.parse(String(init?.body)));
        stored = true;
        return json(importedDocument);
      }
      if (url.includes('/v1/documents/imported/import-1')) return json(importedDocument);
      if (url.includes('/v1/documents/imported')) return json(stored ? [importedDocument] : []);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} />);
    expect(await screen.findByText('Nenhum documento importado')).toBeTruthy();

    const input = screen.getByLabelText('Importar evidência') as HTMLInputElement;
    const file = new File(['evidence'], 'evidence.pdf', { type: 'application/pdf' });
    fireEvent.change(input, { target: { files: [file] } });

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(validationBodies).toHaveLength(1);
    expect(bodies[0]).toEqual({
      content_base64: 'ZXZpZGVuY2U=',
      content_type: 'application/pdf',
      filename: 'evidence.pdf',
      act_id: 'act-1',
    });
    expect(validationBodies[0]).toEqual(bodies[0]);
    expect(await screen.findAllByText('supporting-evidence.pdf')).toHaveLength(2);
    expect(
      await screen.findByRole('group', { name: 'Metadados do documento importado' }),
    ).toBeTruthy();
  });

  it('surfaces invalid imported content from the API and does not add a fake success state', async () => {
    const bodies: unknown[] = [];

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (isImportValidate(url)) return json(baseImportValidationReport);
      if (isImportCreate(url)) {
        bodies.push(JSON.parse(String(init?.body)));
        return json({ error: 'Conteúdo inválido: tipo não suportado' }, 422);
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} />);
    expect(await screen.findByText('Nenhum documento importado')).toBeTruthy();

    const input = screen.getByLabelText('Importar evidência') as HTMLInputElement;
    const file = new File(['bad'], 'bad.bin', { type: 'application/octet-stream' });
    fireEvent.change(input, { target: { files: [file] } });

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(await screen.findAllByText('Conteúdo inválido: tipo não suportado')).toHaveLength(2);
    expect(screen.queryByRole('group', { name: 'Metadados do documento importado' })).toBeNull();
    expect(screen.queryByText('Assinatura válida')).toBeNull();
  });

  it('surfaces legacy Word .doc OLE evidence before preserving it as non-canonical import', async () => {
    const bodies: unknown[] = [];
    const validationBodies: unknown[] = [];
    let stored = false;
    const legacyImportedDocument: ImportedDocumentView = {
      ...importedDocument,
      filename: 'board-minutes.doc',
      declared_content_type: 'application/msword',
      detected_content_type: 'application/msword',
      evidence_family: 'legacy_word_doc',
      classification: 'legacy_word_doc_non_canonical_evidence',
      operator_review_status: 'canonical_conversion_review_required',
      canonical_conversion_preflight: legacyDocCanonicalConversionPreflight,
      preservation_policy: {
        ...importedDocumentPreservationPolicy,
        review_state: 'canonical_conversion_review_required',
        preservation_action: 'preserve_original_bytes_then_operator_review_conversion_if_needed',
      },
    };

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (isImportValidate(url)) {
        validationBodies.push(JSON.parse(String(init?.body)));
        return json(legacyWordImportValidationReport);
      }
      if (isImportCreate(url)) {
        bodies.push(JSON.parse(String(init?.body)));
        stored = true;
        return json(legacyImportedDocument);
      }
      if (url.includes('/v1/documents/imported/import-1')) return json(legacyImportedDocument);
      if (url.includes('/v1/documents/imported')) {
        return json(stored ? [legacyImportedDocument] : []);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} />);
    expect(await screen.findByText('Nenhum documento importado')).toBeTruthy();

    const input = screen.getByLabelText('Importar evidência') as HTMLInputElement;
    const file = new File(
      [new Uint8Array([0xd0, 0xcf, 0x11, 0xe0]), 'legacy'],
      'board-minutes.doc',
      {
        type: 'application/msword',
      },
    );
    fireEvent.change(input, { target: { files: [file] } });

    await waitFor(() => expect(validationBodies).toHaveLength(1));
    await waitFor(() => expect(bodies).toHaveLength(1));
    const validation = await screen.findByRole('group', {
      name: 'Relatório de validação do documento importado',
    });
    expect(within(validation).getByText('Microsoft Word .doc/OLE CFB legado')).toBeTruthy();
    expect(
      within(validation).getByText(/preservado apenas como evidência não canónica/),
    ).toBeTruthy();
    expect(within(validation).getByText('application/msword')).toBeTruthy();
    expect(within(validation).getByText('legacy_word_doc_detected')).toBeTruthy();
    expect(within(validation).getByText('legacy_word_no_macro_execution')).toBeTruthy();
    expect(within(validation).getByText('legacy_word_no_pdfa_conversion')).toBeTruthy();
    expect(within(validation).getByText('Conversão DOC-to-PDF/A')).toBeTruthy();
    expect(within(validation).getByText('PDF/A canónico gerado')).toBeTruthy();
    expect(within(validation).getByText('Pré-flight local de conversão canónica')).toBeTruthy();
    expect(within(validation).getByText('metadata_only_legacy_doc_preflight')).toBeTruthy();
    expect(within(validation).getByText('operator_conversion_review_required')).toBeTruthy();
    expect(within(validation).getByText('no_canonical_conversion_workflow_executed')).toBeTruthy();
    expect(within(validation).getByText('validation_candidate_bytes_not_persisted')).toBeTruthy();
    expect(within(validation).getByText('Validação de assinatura')).toBeTruthy();
    expect(within(validation).getByText('Fornecedor externo contactado')).toBeTruthy();
    expect(within(validation).getByText('Registo canónico substituído')).toBeTruthy();
    expect(await screen.findAllByText('board-minutes.doc')).toHaveLength(2);
    expect(await screen.findByText('original_bytes_preserved')).toBeTruthy();
    expect(screen.queryByText('Assinatura válida')).toBeNull();
  });

  it('shows ambiguous OLE/PDF validation findings and does not import the candidate', async () => {
    let importAttempts = 0;

    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (isImportValidate(url)) return json(ambiguousOlePdfValidationReport);
      if (isImportCreate(url)) {
        importAttempts += 1;
        return json(importedDocument);
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} />);
    expect(await screen.findByText('Nenhum documento importado')).toBeTruthy();

    const input = screen.getByLabelText('Importar evidência') as HTMLInputElement;
    const file = new File(
      [new Uint8Array([0xd0, 0xcf, 0x11, 0xe0]), '%PDF-1.7'],
      'board-minutes.pdf',
      {
        type: 'application/pdf',
      },
    );
    fireEvent.change(input, { target: { files: [file] } });

    const validation = await screen.findByRole('group', {
      name: 'Relatório de validação do documento importado',
    });
    expect(within(validation).getByText('Importação recusada pela validação')).toBeTruthy();
    expect(
      within(validation).getByText(
        'O ficheiro não foi gravado; reveja os erros técnicos reportados abaixo.',
      ),
    ).toBeTruthy();
    expect(within(validation).getByText('legacy_word_ambiguous_pdf')).toBeTruthy();
    expect(within(validation).getByText('legacy_word_filename_conflict')).toBeTruthy();
    expect(within(validation).getByText('legacy_word_content_type_conflict')).toBeTruthy();
    expect(within(validation).getByText('application/vnd.ms-office')).toBeTruthy();
    expect(within(validation).queryByText(/preservado apenas como evidência/)).toBeNull();
    expect(importAttempts).toBe(0);
    expect(screen.queryByText('board-minutes.pdf')).toBeNull();
    expect(screen.queryByText('Assinatura válida')).toBeNull();
  });
});

describe('ActDocumentPanel — honest no-template preview', () => {
  it('renders "sem modelo disponível" when the preview endpoint 422s', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/preview')) return json({ error: 'sem modelo' }, 422);
      if (url.includes('/templates')) return json([]);
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} family="Condominium" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Pré-visualizar documento' }));

    await waitFor(() => expect(screen.getByText('Sem modelo disponível')).toBeTruthy());
  });
});
