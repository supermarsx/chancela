/**
 * Completeness and restraint gate for `dpiaTemplateEditorFallback.ts`.
 *
 * The module carries the DPIA guidance-model editor's chrome in every shipped locale, outside the
 * catalogs (its header explains why). Living outside the catalogs means it also lives outside the
 * catalogs' own completeness checks, so this file supplies them:
 *
 *  - every shipped locale is present, with EXACTLY the English key set — no missing key silently
 *    falling through to English, and no stale key nobody renders;
 *  - `{actor}` and `{timestamp}` survive translation in every locale, because a dropped placeholder
 *    turns an attribution into a sentence with a hole in it;
 *  - pt-BR is not a copy of pt-PT (Brazil is under the LGPD, and `secção`/`registo`/`guardar` are
 *    European forms);
 *  - 🔒 no locale renders a `no_claims` identifier as copy. The 28 flags name legal claims this
 *    product does not make; the whole reason they stay in English is that translating one would be
 *    writing it. A translated flag name appearing in this module is that failure.
 *  - no locale asserts that an edited model is compliant, approved, certified or accepted — the
 *    copy describes a mechanism and stops.
 */
import { describe, expect, it } from 'vitest';
import { LOCALES } from '../api/types';
import {
  DPIA_TEMPLATE_EDITOR_COPY_BY_LOCALE,
  dpiaTemplateEditorEnglish,
  dpiaTemplateEditorPtPT,
  type DpiaTemplateEditorCopyKey,
} from './dpiaTemplateEditorFallback';

const KEYS = Object.keys(dpiaTemplateEditorEnglish) as DpiaTemplateEditorCopyKey[];

/** The 28 flags, spelled as they arrive on the wire. Kept here rather than imported: this test's
 *  job is to notice if one ever reappears as prose, so it must not depend on the same source. */
const NO_CLAIMS_FLAGS = [
  'authority_filing_completed',
  'authority_approval_obtained',
  'cnpd_filing_completed',
  'edpb_filing_completed',
  'cnpd_or_edpb_approval_obtained',
  'legal_review_accepted',
  'legal_validation_completed',
  'external_validation_completed',
  'external_legal_validation_completed',
  'external_delivery_completed',
  'dpia_completed',
  'dpia_completion_certified',
  'compliance_certification_completed',
  'transfer_approval_claimed',
  'transfer_execution_claimed',
  'authority_notification_claimed',
  'subject_notification_claimed',
  'automated_risk_scoring_performed',
  'risk_score_authority_claimed',
  'automated_legal_decision_made',
  'register_mutation_performed',
  'external_call_performed',
  'raw_register_contents_included',
  'processor_names_included',
  'data_subjects_included',
  'recipients_included',
  'personal_data_included',
  'secrets_included',
] as const;

describe('the DPIA model editor copy is complete in every shipped locale', () => {
  it('is non-vacuous and covers the whole key set', () => {
    expect(KEYS.length).toBeGreaterThanOrEqual(30);
  });

  it('ships every locale the application ships', () => {
    for (const locale of LOCALES) {
      expect(
        DPIA_TEMPLATE_EDITOR_COPY_BY_LOCALE[locale],
        `no DPIA model editor copy for ${locale}`,
      ).toBeDefined();
    }
    // Both directions: a locale here that the app does not ship is dead weight.
    for (const locale of Object.keys(DPIA_TEMPLATE_EDITOR_COPY_BY_LOCALE)) {
      expect(LOCALES as readonly string[]).toContain(locale);
    }
  });

  it('gives every locale exactly the English key set, with no empty string', () => {
    for (const locale of LOCALES) {
      const copy = DPIA_TEMPLATE_EDITOR_COPY_BY_LOCALE[locale];
      expect(copy, locale).toBeDefined();
      expect(Object.keys(copy ?? {}).sort(), `${locale} key set`).toEqual([...KEYS].sort());
      for (const key of KEYS) {
        const value = (copy as Record<string, string>)[key];
        expect(typeof value, `${locale}.${key}`).toBe('string');
        expect(value.trim().length, `${locale}.${key} is blank`).toBeGreaterThan(0);
        expect(value, `${locale}.${key} is its own key`).not.toBe(key);
      }
    }
  });

  it('keeps {actor} and {timestamp} through translation, and only where they belong', () => {
    for (const locale of LOCALES) {
      const copy = DPIA_TEMPLATE_EDITOR_COPY_BY_LOCALE[locale] as Record<string, string>;
      for (const key of KEYS) {
        const expected = key.endsWith('note.savedBy');
        expect(copy[key].includes('{actor}'), `${locale}.${key} {actor}`).toBe(expected);
        expect(copy[key].includes('{timestamp}'), `${locale}.${key} {timestamp}`).toBe(expected);
      }
    }
  });

  it('keeps pt-BR distinct from pt-PT rather than copying European forms', () => {
    const ptBR = DPIA_TEMPLATE_EDITOR_COPY_BY_LOCALE['pt-BR'] as Record<string, string>;
    const differing = KEYS.filter(
      (key) => ptBR[key] !== (dpiaTemplateEditorPtPT as Record<string, string>)[key],
    );
    expect(differing.length, 'pt-BR reads as a copy of pt-PT').toBeGreaterThan(10);
    // Spot-check the European spellings that must not have travelled.
    const brazilian = KEYS.map((key) => ptBR[key]).join(' ');
    expect(brazilian).not.toMatch(/secção|Secção/u);
    expect(brazilian).not.toMatch(/\bregisto\b/u);
  });

  it('renders no no_claims identifier as copy, in any locale', () => {
    for (const locale of LOCALES) {
      const copy = DPIA_TEMPLATE_EDITOR_COPY_BY_LOCALE[locale] as Record<string, string>;
      const text = KEYS.map((key) => copy[key]).join(' ');
      for (const flag of NO_CLAIMS_FLAGS) {
        expect(text.includes(flag), `${locale} renders the flag ${flag} as copy`).toBe(false);
      }
    }
  });

  it('asserts nothing about compliance, approval or evidentiary weight', () => {
    const forbidden = [
      // House rule: this phrase never appears in user-visible copy.
      'valor probatório',
      'valor probatorio',
      // An edited model is not certified, approved or accepted by anyone.
      'em conformidade com o RGPD',
      'aprovado pela CNPD',
      'GDPR compliant',
      'legally valid',
      'juridicamente válido',
    ];
    for (const locale of LOCALES) {
      const copy = DPIA_TEMPLATE_EDITOR_COPY_BY_LOCALE[locale] as Record<string, string>;
      const text = KEYS.map((key) => copy[key])
        .join(' ')
        .toLowerCase();
      for (const phrase of forbidden) {
        expect(text.includes(phrase.toLowerCase()), `${locale} claims: ${phrase}`).toBe(false);
      }
    }
  });
});
