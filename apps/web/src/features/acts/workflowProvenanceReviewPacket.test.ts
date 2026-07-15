import { describe, expect, it } from 'vitest';
import type { ActView, ComplianceReport } from '../../api/types';
import {
  buildWorkflowProvenanceReviewCopyPayload,
  buildWorkflowProvenanceReviewEvidence,
  formatWorkflowProvenanceReviewCopyPayload,
  workflowHumanReviewBucket,
  workflowLifecycleBucket,
} from './workflowProvenanceReviewPacket';

function sensitiveAct(overrides: Partial<ActView> = {}): ActView {
  return {
    id: 'SECRET_ACT_ID',
    book_id: 'SECRET_BOOK_ID',
    title: 'SECRET_TITLE',
    channel: 'WrittenResolution',
    meeting_date: '2026-07-15',
    meeting_time: '09:30',
    place: 'SECRET_PLACE',
    mesa: { presidente: 'SECRET_CHAIR_NAME', secretarios: ['SECRET_SECRETARY_NAME'] },
    agenda: [{ number: 1, text: 'SECRET_AGENDA_TEXT' }],
    attendance_reference: 'SECRET_ATTENDANCE_REF',
    members_present: 4,
    members_represented: 2,
    referenced_documents: [{ label: 'SECRET_DOC_LABEL', reference: 'SECRET_ACCESS_CODE' }],
    written_resolution_evidence: {
      status: {
        status: 'bound_present',
        boundary: 'SECRET_BOUNDARY_NOTE',
        signed_signatory_slots: 1,
        digested_attachments: 1,
        checklist_items: 1,
        digested_checklist_items: 1,
        referenced_checklist_items: 0,
        bound_count: 1,
        referenced_only_count: 0,
        review_receipts: 1,
        latest_review_status: 'reviewed',
        reviewed_evidence_locators: 1,
        reviewed_evidence_digests: 1,
      },
      checklist: [
        {
          label: 'SECRET_CHECKLIST_LABEL',
          reference: 'SECRET_CHECKLIST_REF',
          digest: 'SECRET_CHECKLIST_DIGEST',
          note: 'SECRET_CHECKLIST_NOTE',
        },
      ],
      review_receipts: [
        {
          reviewer: 'SECRET_REVIEWER_NAME',
          reviewed_at: '2026-07-15T09:30:00Z',
          status: 'reviewed',
          guardrail_acknowledgements: ['SECRET_GUARDRAIL_ID'],
          evidence: [
            {
              label: 'SECRET_LOCATOR_LABEL',
              locator: 'SECRET_LOCATOR',
              digest: 'SECRET_LOCATOR_DIGEST',
            },
          ],
          note: 'SECRET_RECEIPT_NOTE',
          consent_proof_claimed: false,
          quorum_proof_claimed: false,
          identity_proof_claimed: false,
          legal_acceptance_claimed: false,
          legal_sufficiency_claimed: false,
          external_validation_claimed: false,
          automatic_approval_claimed: false,
          authority_certified_claimed: false,
        },
      ],
      note: 'SECRET_WRITTEN_NOTE',
    },
    deliberations: 'SECRET_DELIBERATIONS',
    deliberation_items: [
      {
        agenda_number: 1,
        text: 'SECRET_ITEM_TEXT',
        vote: { type: 'Recorded', em_favor: 4, contra: 0, abstencoes: 0 },
        statements: [{ member: 'SECRET_MEMBER_NAME', text: 'SECRET_STATEMENT_TEXT' }],
      },
    ],
    telematic_evidence: 'SECRET_TELEMATIC_REF',
    attachments: [{ label: 'SECRET_ATTACHMENT_LABEL', kind: 'Other', digest: 'SECRET_DIGEST' }],
    signatories: [
      {
        name: 'SECRET_SIGNATORY_NAME',
        email: 'secret.signatory@example.pt',
        capacity: 'Chair',
        signed: true,
      },
    ],
    state: 'TextApproved',
    ata_number: 9,
    payload_digest: 'SECRET_PAYLOAD_DIGEST',
    seal_event_seq: 11,
    seal_metadata: {
      rule_pack_id: 'SECRET_RULE_PACK',
      version: 'SECRET_VERSION',
      family: 'CommercialCompany',
      profile: 'SociedadeAnonima',
      manual_signature_original_reference: {
        storage_reference: 'SECRET_STORAGE_REF',
        custodian: 'SECRET_CUSTODIAN',
        note: 'SECRET_MANUAL_NOTE',
      },
    },
    retifies: 'SECRET_RETIFIED_ACT_ID',
    convening: {
      convener: 'SECRET_CONVENER',
      convener_capacity: 'Chair',
      dispatch_date: '2026-07-01',
      antecedence_days: 14,
      channel: 'Email',
      evidence_reference: 'SECRET_CONVENING_EVIDENCE',
      recipients: [
        {
          name: 'SECRET_RECIPIENT',
          contact: 'secret.recipient@example.pt',
          channel: 'Email',
          reference: 'SECRET_DISPATCH_REF',
          dispatched_at: '2026-07-01T10:00:00Z',
        },
      ],
      second_call: null,
    },
    ai_provenance: {
      source: 'SECRET_AI_SOURCE',
      tool: 'SECRET_AI_TOOL',
      statement_source: 'SECRET_OPERATOR_PROMPT',
      statement_sources: [
        {
          path: 'SECRET_SOURCE_PATH',
          source_type: 'SECRET_SOURCE_TYPE',
          source_label: 'SECRET_SOURCE_LABEL',
          human_verified: true,
          human_verification_status: 'accepted_by_human',
          authoritative_source_claimed: true,
          legal_validity_claimed: true,
        },
        {
          path: '',
          source_type: 'ai_suggestion',
          source_label: 'SECRET_MISSING_SOURCE_LABEL',
          human_verified: false,
          human_verification_status: 'pending_human_verification',
          authoritative_source_claimed: false,
          legal_validity_claimed: false,
        },
      ],
      human_verification: {
        status: 'accepted_by_human',
        actor: 'secret.reviewer@example.pt',
        reviewed_at: '2026-07-15T10:00:00Z',
        note: 'SECRET_AI_REVIEW_NOTE',
      },
    },
    ...overrides,
  };
}

function complianceReport(): ComplianceReport {
  return {
    rule_pack: 'SECRET_RULE_PACK',
    family: 'CommercialCompany',
    statute_overlay: false,
    issues: [
      {
        rule_id: 'SECRET_RULE_ID',
        severity: 'Warning',
        message: 'SECRET_COMPLIANCE_MESSAGE',
      },
    ],
    errors: 0,
    warnings: 1,
    seal_allowed: true,
    convening_advisories: [
      {
        code: 'SECRET_ADVISORY_CODE',
        severity: 'Warning',
        message: 'SECRET_ADVISORY_MESSAGE',
        threshold_id: 'SECRET_THRESHOLD',
        actual_days: 5,
        minimum_days: 8,
      },
    ],
  };
}

describe('workflowProvenanceReviewPacket', () => {
  it('builds deterministic aggregate workflow evidence without raw values', () => {
    const act = sensitiveAct();
    const report = complianceReport();

    const evidence = buildWorkflowProvenanceReviewEvidence(act, report);

    expect(evidence).toEqual({
      schema_version: 'workflow-provenance-review-packet/v1',
      generated_from: 'act.workflow.aggregate',
      aggregate_counts_only: true,
      raw_values_echoed: false,
      workflows: [
        {
          workflow_state: 'approved',
          human_review: {
            status: 'accepted',
            present: true,
          },
          evidence_present: {
            ledger_ref: true,
            archive_ref: false,
            signature_ref: true,
            digest: true,
            generated_document_ref: true,
          },
        },
      ],
      workflow_summary: {
        record_count: 1,
        lifecycle_buckets: { approved: 1 },
        ai_human_review_buckets: { accepted: 1 },
        marker_counts: {
          ledger: 1,
          archive: 0,
          signature: 1,
          fingerprint: 1,
          docs: 2,
          ai_statement_sources: 2,
          convening_dispatch: 1,
          written_resolution_reviews: 1,
          compliance_findings: 1,
        },
        missing_unknown_counts: {
          lifecycle: 0,
          ai_human_review: 0,
          ai_statement_source_fields: 1,
          compliance_report: 0,
          fingerprint: 0,
          seal_event: 0,
          convening_dispatch: 0,
          written_resolution_review: 0,
          total: 1,
        },
        compliance_buckets: {
          errors: 0,
          warnings: 2,
          seal_allowed: true,
          report_present: true,
        },
        raw_values_echoed: false,
      },
      no_claim_flags: {
        ai_01_complete: false,
        ai_02_complete: false,
        full_ai_mcp_completion: false,
        legal_validity: false,
        workflow_completion: false,
        source_certification: false,
        extraction_accuracy: false,
        signature_validation: false,
        qualified_signature: false,
        trust_validation: false,
        provider_assurance: false,
        registry_validation: false,
        ownership_validation: false,
        live_ai_provider: false,
        api_from_mcp: false,
        non_stdio_transport: false,
      },
    });

    const serialized = JSON.stringify(evidence);
    for (const rawValue of [
      'SECRET_ACT_ID',
      'SECRET_BOOK_ID',
      'SECRET_TITLE',
      'SECRET_DELIBERATIONS',
      'SECRET_AI_SOURCE',
      'SECRET_AI_TOOL',
      'SECRET_OPERATOR_PROMPT',
      'SECRET_SOURCE_PATH',
      'SECRET_SOURCE_TYPE',
      'SECRET_SOURCE_LABEL',
      'secret.reviewer@example.pt',
      'SECRET_AI_REVIEW_NOTE',
      'SECRET_DOC_LABEL',
      'SECRET_ACCESS_CODE',
      'SECRET_PAYLOAD_DIGEST',
      'SECRET_COMPLIANCE_MESSAGE',
      'SECRET_CONVENER',
      'secret.recipient@example.pt',
    ]) {
      expect(serialized).not.toContain(rawValue);
    }
  });

  it('normalizes lifecycle and human-review states into stable buckets', () => {
    expect(workflowLifecycleBucket('TextApproved')).toBe('approved');
    expect(workflowLifecycleBucket('Signing')).toBe('pending');
    expect(workflowLifecycleBucket('Sealed')).toBe('sealed');
    expect(workflowLifecycleBucket('unexpected-private-state')).toBe('other');
    expect(workflowLifecycleBucket('unknown')).toBe('unknown');
    expect(workflowHumanReviewBucket('pending_human_verification')).toBe('pending');
    expect(workflowHumanReviewBucket('accepted_by_human')).toBe('accepted');
    expect(workflowHumanReviewBucket('rejected_by_human')).toBe('rejected');
    expect(workflowHumanReviewBucket('custom-private-review-state')).toBe('other');
    expect(workflowHumanReviewBucket(null)).toBe('missing');
  });

  it('formats the MCP resources/read payload without caller values', () => {
    const act = sensitiveAct({
      state: 'Archived',
      ai_provenance: null,
      payload_digest: null,
      seal_event_seq: null,
      convening: {
        ...sensitiveAct().convening!,
        recipients: [
          {
            name: 'SECRET_UNDISPATCHED',
            contact: 'undispatched@example.pt',
            channel: null,
            reference: null,
            dispatched_at: null,
          },
        ],
      },
    });

    const payload = buildWorkflowProvenanceReviewCopyPayload(act, null);
    const serialized = formatWorkflowProvenanceReviewCopyPayload(act, null);

    expect(payload.uri).toBe('chancela://mcp/workflow-provenance-review');
    expect(payload.arguments.workflow_evidence.workflows[0]).toMatchObject({
      workflow_state: 'archived',
      human_review: { status: 'missing', present: false },
      evidence_present: {
        ledger_ref: false,
        archive_ref: true,
        signature_ref: true,
        digest: false,
        generated_document_ref: true,
      },
    });
    expect(serialized).toBe(`${JSON.stringify(payload, null, 2)}\n`);
    expect(serialized).toContain('"workflow_evidence"');
    expect(serialized).toContain('"api_from_mcp": false');
    expect(serialized).not.toContain('SECRET_UNDISPATCHED');
    expect(serialized).not.toContain('undispatched@example.pt');
    expect(serialized).not.toContain('SECRET_TITLE');
    expect(serialized).not.toContain('SECRET_PAYLOAD_DIGEST');
  });
});
