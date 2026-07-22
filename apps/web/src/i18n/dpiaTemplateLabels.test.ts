/**
 * Completeness contract for the DPIA guidance-template label maps.
 *
 * The maps in `dpiaTemplateLabels.ts` resolve the backend's stable ids (and positional prompt /
 * operator-action indexes) to translated catalog keys. `tsc` already proves every mapped value is a
 * real `MessageKey`; this test proves the OTHER direction — that the maps cover exactly what the
 * live template emits — by driving off `contracts/privacy.dpia-template.json`, the fixture asserted
 * against real wire bytes by the e2e contract suite. So a section, prompt, checklist item, or
 * operator action added, removed, or reordered on the backend fails HERE, loudly, instead of
 * silently rendering English in the UI again (memory: reject, never silently transform).
 *
 * It also pins the deliberate exclusions: the 28 `no_claims` flag identifiers and the six
 * `field_type` wire identifiers are NOT mapped and must stay unmapped — they render verbatim.
 */
import { describe, it, expect } from 'vitest';
import {
  DPIA_SECTION_TITLE_KEYS,
  DPIA_SECTION_DESC_KEYS,
  DPIA_SECTION_PROMPT_KEYS,
  DPIA_CHECKLIST_LABEL_KEYS,
  DPIA_OPERATOR_ACTION_KEYS,
  dpiaSectionTitleKey,
  dpiaSectionDescKey,
  dpiaSectionPromptKey,
  dpiaChecklistLabelKey,
  dpiaOperatorActionKey,
} from './dpiaTemplateLabels';

interface ChecklistItem {
  id: string;
  label: string;
  field_type: string;
  required: boolean;
}
interface Section {
  id: string;
  title: string;
  description: string;
  prompts: string[];
  checklist: ChecklistItem[];
}
interface TemplateFixture {
  sections: Section[];
  operator_actions: string[];
  no_claims: Record<string, boolean>;
}

async function loadTemplate(): Promise<TemplateFixture> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  // Tests run with cwd = apps/web; the repo root is two levels up.
  return JSON.parse(
    readFileSync('../../contracts/privacy.dpia-template.json', 'utf8'),
  ) as TemplateFixture;
}

describe('DPIA template label maps cover the backend template', () => {
  it('maps a title and description key for every section id', async () => {
    const { sections } = await loadTemplate();
    expect(sections.length).toBeGreaterThan(0);
    for (const section of sections) {
      expect(dpiaSectionTitleKey(section.id), `title for ${section.id}`).toBeDefined();
      expect(dpiaSectionDescKey(section.id), `desc for ${section.id}`).toBeDefined();
    }
  });

  it('maps a prompt key for every prompt index of every section', async () => {
    const { sections } = await loadTemplate();
    for (const section of sections) {
      expect(section.prompts.length, `prompts for ${section.id}`).toBeGreaterThan(0);
      section.prompts.forEach((_prompt, index) => {
        expect(
          dpiaSectionPromptKey(section.id, index),
          `prompt ${index} for ${section.id}`,
        ).toBeDefined();
      });
      // No stale surplus: the map has exactly as many prompts as the section emits.
      expect(DPIA_SECTION_PROMPT_KEYS[section.id]?.length, `prompt count for ${section.id}`).toBe(
        section.prompts.length,
      );
    }
  });

  it('maps a label key for every checklist item id', async () => {
    const { sections } = await loadTemplate();
    for (const section of sections) {
      for (const item of section.checklist) {
        expect(dpiaChecklistLabelKey(item.id), `label for ${item.id}`).toBeDefined();
      }
    }
  });

  it('maps an operator-action key for every operator action', async () => {
    const { operator_actions } = await loadTemplate();
    expect(operator_actions.length).toBeGreaterThan(0);
    operator_actions.forEach((_action, index) => {
      expect(dpiaOperatorActionKey(index), `operator action ${index}`).toBeDefined();
    });
    expect(DPIA_OPERATOR_ACTION_KEYS.length).toBe(operator_actions.length);
  });

  it('has no stale section/checklist map entries beyond what the backend emits', async () => {
    const { sections } = await loadTemplate();
    const sectionIds = new Set(sections.map((s) => s.id));
    const checklistIds = new Set(sections.flatMap((s) => s.checklist.map((c) => c.id)));

    for (const id of Object.keys(DPIA_SECTION_TITLE_KEYS)) {
      expect(sectionIds.has(id), `stale title map entry: ${id}`).toBe(true);
    }
    for (const id of Object.keys(DPIA_SECTION_DESC_KEYS)) {
      expect(sectionIds.has(id), `stale desc map entry: ${id}`).toBe(true);
    }
    for (const id of Object.keys(DPIA_SECTION_PROMPT_KEYS)) {
      expect(sectionIds.has(id), `stale prompt map entry: ${id}`).toBe(true);
    }
    for (const id of Object.keys(DPIA_CHECKLIST_LABEL_KEYS)) {
      expect(checklistIds.has(id), `stale checklist map entry: ${id}`).toBe(true);
    }
  });

  it('does NOT map the no_claims flags or the field_type identifiers (they stay verbatim)', async () => {
    const { sections, no_claims } = await loadTemplate();
    for (const flag of Object.keys(no_claims)) {
      expect(DPIA_CHECKLIST_LABEL_KEYS[flag], `no_claims flag must stay unmapped: ${flag}`).toBe(
        undefined,
      );
      expect(DPIA_SECTION_TITLE_KEYS[flag]).toBe(undefined);
    }
    const fieldTypes = new Set(sections.flatMap((s) => s.checklist.map((c) => c.field_type)));
    for (const fieldType of fieldTypes) {
      expect(
        DPIA_CHECKLIST_LABEL_KEYS[fieldType],
        `field_type must stay unmapped: ${fieldType}`,
      ).toBe(undefined);
    }
  });

  it('returns undefined for unknown ids and out-of-range indexes', () => {
    expect(dpiaSectionTitleKey('nope')).toBe(undefined);
    expect(dpiaSectionDescKey('nope')).toBe(undefined);
    expect(dpiaSectionPromptKey('processing_description', 99)).toBe(undefined);
    expect(dpiaSectionPromptKey('nope', 0)).toBe(undefined);
    expect(dpiaChecklistLabelKey('nope')).toBe(undefined);
    expect(dpiaOperatorActionKey(99)).toBe(undefined);
  });
});
