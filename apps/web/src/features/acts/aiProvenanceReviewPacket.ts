import type { AiProvenanceView } from '../../api/types';

const MISSING_BUCKET = 'missing';

export const AI_PROVENANCE_REVIEW_PACKET_SCHEMA_VERSION = 'ai-provenance-review-packet/v1';

export const AI_PROVENANCE_REVIEW_PACKET_NO_CLAIM_FLAGS = {
  legal_validity: false,
  source_certification: false,
  provider_assurance: false,
  trust_validation: false,
  external_validation: false,
  signature_qualification: false,
  mcp_completion: false,
  ai_quality: false,
} as const;

export interface AiProvenanceReviewPacket {
  schema_version: typeof AI_PROVENANCE_REVIEW_PACKET_SCHEMA_VERSION;
  generated_from: 'act.ai_provenance';
  source: string;
  tool: string | null;
  statement_source_present: boolean;
  human_review: {
    status: string;
    actor_present: boolean;
    reviewed_at_present: boolean;
    note_present: boolean;
  };
  statement_sources: {
    total: number;
    counts_by_source_type: Record<string, number>;
    counts_by_review_status: Record<string, number>;
    missing: {
      row_count: number;
      rows: Array<{
        index: number;
        path: string | null;
      }>;
    };
    pending_or_unverified_row_count: number;
    claim_flagged_row_count: number;
  };
  no_claim_flags: typeof AI_PROVENANCE_REVIEW_PACKET_NO_CLAIM_FLAGS;
}

function normalizedString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function hasText(value: unknown): boolean {
  return normalizedString(value) !== null;
}

function countByStableKey<T>(
  values: T[],
  keyFor: (value: T) => string | null,
): Record<string, number> {
  const counts = new Map<string, number>();
  for (const value of values) {
    const key = keyFor(value) ?? MISSING_BUCKET;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  return Object.fromEntries(
    Array.from(counts.entries()).sort(([left], [right]) => left.localeCompare(right)),
  );
}

function statementSourceHasMissingField(
  source: Partial<NonNullable<AiProvenanceView['statement_sources']>[number]>,
): boolean {
  return (
    !hasText(source.path) ||
    !hasText(source.source_type) ||
    !hasText(source.source_label) ||
    !hasText(source.human_verification_status)
  );
}

export function buildAiProvenanceReviewPacket(
  provenance: AiProvenanceView,
): AiProvenanceReviewPacket {
  const statementSources = provenance.statement_sources ?? [];
  const missingRows = statementSources
    .map((source, index) => ({ source, index }))
    .filter(({ source }) => statementSourceHasMissingField(source))
    .map(({ source, index }) => ({
      index,
      path: normalizedString(source.path),
    }));

  return {
    schema_version: AI_PROVENANCE_REVIEW_PACKET_SCHEMA_VERSION,
    generated_from: 'act.ai_provenance',
    source: normalizedString(provenance.source) ?? MISSING_BUCKET,
    tool: normalizedString(provenance.tool),
    statement_source_present: hasText(provenance.statement_source),
    human_review: {
      status: normalizedString(provenance.human_verification.status) ?? MISSING_BUCKET,
      actor_present: hasText(provenance.human_verification.actor),
      reviewed_at_present: hasText(provenance.human_verification.reviewed_at),
      note_present: hasText(provenance.human_verification.note),
    },
    statement_sources: {
      total: statementSources.length,
      counts_by_source_type: countByStableKey(statementSources, (source) =>
        normalizedString(source.source_type),
      ),
      counts_by_review_status: countByStableKey(statementSources, (source) =>
        normalizedString(source.human_verification_status),
      ),
      missing: {
        row_count: missingRows.length,
        rows: missingRows,
      },
      pending_or_unverified_row_count: statementSources.filter(
        (source) =>
          source.human_verified !== true ||
          source.human_verification_status !== 'accepted_by_human',
      ).length,
      claim_flagged_row_count: statementSources.filter(
        (source) =>
          source.authoritative_source_claimed === true || source.legal_validity_claimed === true,
      ).length,
    },
    no_claim_flags: AI_PROVENANCE_REVIEW_PACKET_NO_CLAIM_FLAGS,
  };
}

export function formatAiProvenanceReviewPacket(provenance: AiProvenanceView): string {
  return `${JSON.stringify(buildAiProvenanceReviewPacket(provenance), null, 2)}\n`;
}
