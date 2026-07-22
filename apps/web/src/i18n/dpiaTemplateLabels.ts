/**
 * Client-side id → catalog-key map for the local DPIA guidance template.
 *
 * The template (`GET /v1/privacy/dpia-template`, built in `chancela-api` `dpia_template_view()`
 * and mirrored by `contracts/privacy.dpia-template.json`) keeps ENGLISH as its structural/wire
 * source of truth: `section.title`, `section.description`, `section.prompts[]`,
 * `checklist[].label`, and `template.operator_actions[]` arrive in English. Rendering that verbatim
 * showed English copy to readers of every locale, so the client resolves the backend's STABLE ids
 * to translated catalog keys here — the same pattern as `STATUS_LABEL_KEYS` / `RISK_LABEL_KEYS` in
 * `PrivacyComplianceSection.tsx`. No backend change: the wire stays English, the UI is localized.
 *
 * Each mapped value is a real `MessageKey` literal, so `tsc` rejects a typo or a key the catalog is
 * missing — the compiler is the first completeness guard. The second is `dpiaTemplateLabels.test.ts`,
 * which drives these maps off the contract fixture so a section/prompt/checklist id added to the
 * backend later fails loudly here instead of silently rendering English again.
 *
 * NOT mapped (deliberately, and they must stay so): the 28 `no_claims` flag identifiers (each names
 * a legal claim the product does not make — see the note in `PrivacyComplianceSection.tsx`) and the
 * six `field_type` wire identifiers. Both render verbatim in `mono`; translating them would invent
 * copy this boundary must not invent.
 *
 * Prompts and operator actions have no stable id — they are positional — so they map by array index.
 * Adding, removing, or reordering a prompt on the backend is therefore a breaking change the
 * completeness test is designed to catch.
 */
import type { MessageKey } from './types';

/** Section `id` → its title catalog key. */
export const DPIA_SECTION_TITLE_KEYS: Record<string, MessageKey> = {
  processing_description: 'settings.privacy.dpiaTemplate.section.processing_description.title',
  necessity_proportionality:
    'settings.privacy.dpiaTemplate.section.necessity_proportionality.title',
  risk_prompts: 'settings.privacy.dpiaTemplate.section.risk_prompts.title',
  safeguards: 'settings.privacy.dpiaTemplate.section.safeguards.title',
  consultation_escalation: 'settings.privacy.dpiaTemplate.section.consultation_escalation.title',
  evidence_boundaries: 'settings.privacy.dpiaTemplate.section.evidence_boundaries.title',
};

/** Section `id` → its description catalog key. */
export const DPIA_SECTION_DESC_KEYS: Record<string, MessageKey> = {
  processing_description: 'settings.privacy.dpiaTemplate.section.processing_description.desc',
  necessity_proportionality: 'settings.privacy.dpiaTemplate.section.necessity_proportionality.desc',
  risk_prompts: 'settings.privacy.dpiaTemplate.section.risk_prompts.desc',
  safeguards: 'settings.privacy.dpiaTemplate.section.safeguards.desc',
  consultation_escalation: 'settings.privacy.dpiaTemplate.section.consultation_escalation.desc',
  evidence_boundaries: 'settings.privacy.dpiaTemplate.section.evidence_boundaries.desc',
};

/** Section `id` → its prompt catalog keys, positional (prompt index → key). */
export const DPIA_SECTION_PROMPT_KEYS: Record<string, readonly MessageKey[]> = {
  processing_description: [
    'settings.privacy.dpiaTemplate.section.processing_description.prompt.0',
    'settings.privacy.dpiaTemplate.section.processing_description.prompt.1',
    'settings.privacy.dpiaTemplate.section.processing_description.prompt.2',
    'settings.privacy.dpiaTemplate.section.processing_description.prompt.3',
  ],
  necessity_proportionality: [
    'settings.privacy.dpiaTemplate.section.necessity_proportionality.prompt.0',
    'settings.privacy.dpiaTemplate.section.necessity_proportionality.prompt.1',
    'settings.privacy.dpiaTemplate.section.necessity_proportionality.prompt.2',
    'settings.privacy.dpiaTemplate.section.necessity_proportionality.prompt.3',
  ],
  risk_prompts: [
    'settings.privacy.dpiaTemplate.section.risk_prompts.prompt.0',
    'settings.privacy.dpiaTemplate.section.risk_prompts.prompt.1',
    'settings.privacy.dpiaTemplate.section.risk_prompts.prompt.2',
    'settings.privacy.dpiaTemplate.section.risk_prompts.prompt.3',
  ],
  safeguards: [
    'settings.privacy.dpiaTemplate.section.safeguards.prompt.0',
    'settings.privacy.dpiaTemplate.section.safeguards.prompt.1',
    'settings.privacy.dpiaTemplate.section.safeguards.prompt.2',
  ],
  consultation_escalation: [
    'settings.privacy.dpiaTemplate.section.consultation_escalation.prompt.0',
    'settings.privacy.dpiaTemplate.section.consultation_escalation.prompt.1',
    'settings.privacy.dpiaTemplate.section.consultation_escalation.prompt.2',
    'settings.privacy.dpiaTemplate.section.consultation_escalation.prompt.3',
  ],
  evidence_boundaries: [
    'settings.privacy.dpiaTemplate.section.evidence_boundaries.prompt.0',
    'settings.privacy.dpiaTemplate.section.evidence_boundaries.prompt.1',
    'settings.privacy.dpiaTemplate.section.evidence_boundaries.prompt.2',
  ],
};

/** Checklist item `id` → its label catalog key. */
export const DPIA_CHECKLIST_LABEL_KEYS: Record<string, MessageKey> = {
  activity_label: 'settings.privacy.dpiaTemplate.checklist.activity_label.label',
  purpose_placeholder: 'settings.privacy.dpiaTemplate.checklist.purpose_placeholder.label',
  lawful_basis_prompt: 'settings.privacy.dpiaTemplate.checklist.lawful_basis_prompt.label',
  data_category_placeholders:
    'settings.privacy.dpiaTemplate.checklist.data_category_placeholders.label',
  system_boundary: 'settings.privacy.dpiaTemplate.checklist.system_boundary.label',
  necessity_rationale: 'settings.privacy.dpiaTemplate.checklist.necessity_rationale.label',
  less_intrusive_alternatives:
    'settings.privacy.dpiaTemplate.checklist.less_intrusive_alternatives.label',
  minimization_controls: 'settings.privacy.dpiaTemplate.checklist.minimization_controls.label',
  retention_prompt: 'settings.privacy.dpiaTemplate.checklist.retention_prompt.label',
  transparency_prompt: 'settings.privacy.dpiaTemplate.checklist.transparency_prompt.label',
  rights_impacts: 'settings.privacy.dpiaTemplate.checklist.rights_impacts.label',
  misuse_scenarios: 'settings.privacy.dpiaTemplate.checklist.misuse_scenarios.label',
  scale_context: 'settings.privacy.dpiaTemplate.checklist.scale_context.label',
  unresolved_questions: 'settings.privacy.dpiaTemplate.checklist.unresolved_questions.label',
  risk_review_note: 'settings.privacy.dpiaTemplate.checklist.risk_review_note.label',
  technical_safeguards: 'settings.privacy.dpiaTemplate.checklist.technical_safeguards.label',
  organizational_safeguards:
    'settings.privacy.dpiaTemplate.checklist.organizational_safeguards.label',
  access_logging_controls: 'settings.privacy.dpiaTemplate.checklist.access_logging_controls.label',
  evidence_references: 'settings.privacy.dpiaTemplate.checklist.evidence_references.label',
  residual_follow_up: 'settings.privacy.dpiaTemplate.checklist.residual_follow_up.label',
  reviewer_roles: 'settings.privacy.dpiaTemplate.checklist.reviewer_roles.label',
  consultation_questions: 'settings.privacy.dpiaTemplate.checklist.consultation_questions.label',
  escalation_blockers: 'settings.privacy.dpiaTemplate.checklist.escalation_blockers.label',
  target_review_date: 'settings.privacy.dpiaTemplate.checklist.target_review_date.label',
  next_operator_action: 'settings.privacy.dpiaTemplate.checklist.next_operator_action.label',
  local_evidence_index: 'settings.privacy.dpiaTemplate.checklist.local_evidence_index.label',
  false_no_claim_flags: 'settings.privacy.dpiaTemplate.checklist.false_no_claim_flags.label',
  no_sensitive_echo_check: 'settings.privacy.dpiaTemplate.checklist.no_sensitive_echo_check.label',
  separate_record_update_prompt:
    'settings.privacy.dpiaTemplate.checklist.separate_record_update_prompt.label',
};

/** Operator actions, positional (action index → key). */
export const DPIA_OPERATOR_ACTION_KEYS: readonly MessageKey[] = [
  'settings.privacy.dpiaTemplate.operatorAction.0',
  'settings.privacy.dpiaTemplate.operatorAction.1',
  'settings.privacy.dpiaTemplate.operatorAction.2',
  'settings.privacy.dpiaTemplate.operatorAction.3',
];

/**
 * Resolve a section title key. Returns `undefined` for an unknown id so the caller can fall back
 * to the raw backend English (visible degradation) rather than crash; the completeness test keeps
 * `undefined` from ever happening for a shipped backend payload.
 */
export function dpiaSectionTitleKey(sectionId: string): MessageKey | undefined {
  return DPIA_SECTION_TITLE_KEYS[sectionId];
}

/** Resolve a section description key. `undefined` for an unknown id (see `dpiaSectionTitleKey`). */
export function dpiaSectionDescKey(sectionId: string): MessageKey | undefined {
  return DPIA_SECTION_DESC_KEYS[sectionId];
}

/** Resolve a positional prompt key for a section. `undefined` for an unknown id/index. */
export function dpiaSectionPromptKey(sectionId: string, index: number): MessageKey | undefined {
  return DPIA_SECTION_PROMPT_KEYS[sectionId]?.[index];
}

/** Resolve a checklist-item label key. `undefined` for an unknown id (see `dpiaSectionTitleKey`). */
export function dpiaChecklistLabelKey(checklistId: string): MessageKey | undefined {
  return DPIA_CHECKLIST_LABEL_KEYS[checklistId];
}

/** Resolve a positional operator-action key. `undefined` for an out-of-range index. */
export function dpiaOperatorActionKey(index: number): MessageKey | undefined {
  return DPIA_OPERATOR_ACTION_KEYS[index];
}
