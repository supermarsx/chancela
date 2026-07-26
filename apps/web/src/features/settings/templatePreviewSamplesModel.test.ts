import { describe, expect, it } from 'vitest';
import {
  DEFAULT_TEMPLATE_PREVIEW_SAMPLES,
  TEMPLATE_PREVIEW_FAMILY_PROFILE_KEYS,
} from '../../api/types';
import {
  TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
  TEMPLATE_PREVIEW_SAMPLE_MAX_BYTES,
  TEMPLATE_PREVIEW_SECRETARIES_MAX,
  TEMPLATE_PREVIEW_STATEMENTS_MAX,
  hydrateTemplatePreviewSamples,
  normalizeTemplatePreviewSamples,
  templatePreviewSamplesByteSize,
  validateTemplatePreviewSamples,
} from './templatePreviewSamplesModel';

describe('templatePreviewSamplesModel', () => {
  it('hydrates omitted stale-client fields while preserving explicitly empty authored lists', () => {
    const hydrated = hydrateTemplatePreviewSamples({
      entity: { nipc: '999999990' },
      family_profiles: {
        association: { name: 'Associação de Teste' },
      },
      meeting: {
        mesa: { president: 'Presidente de Teste', secretaries: [] },
        attendees: [],
      },
      agenda: [],
    });

    expect(hydrated.general).toEqual(DEFAULT_TEMPLATE_PREVIEW_SAMPLES.general);
    expect(hydrated.entity).toEqual({
      ...DEFAULT_TEMPLATE_PREVIEW_SAMPLES.entity,
      nipc: '999999990',
    });
    expect(hydrated.family_profiles.association).toEqual({
      ...DEFAULT_TEMPLATE_PREVIEW_SAMPLES.family_profiles.association,
      name: 'Associação de Teste',
    });
    expect(hydrated.family_profiles.commercial_company).toEqual(
      DEFAULT_TEMPLATE_PREVIEW_SAMPLES.family_profiles.commercial_company,
    );
    expect(hydrated.meeting.mesa).toEqual({
      president: 'Presidente de Teste',
      secretaries: [],
    });
    expect(hydrated.meeting.attendees).toEqual([]);
    expect(hydrated.agenda).toEqual([]);
  });

  it('normalizes bounded numbers and authored collection limits without mutating the input', () => {
    const input = structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
    input.act.number = 2_000_000;
    input.meeting.members_present = -2;
    input.meeting.mesa.secretaries = Array.from({ length: 15 }, (_, index) => `S${index}`);
    input.agenda = Array.from({ length: 55 }, (_, index) => ({
      number: index === 0 ? 0 : index,
      text: `Ponto ${index}`,
    }));
    input.deliberations.items[0].statements = Array.from({ length: 25 }, (_, index) => ({
      agenda_number: index + 1,
      member: `Membro ${index}`,
      text: `Declaração ${index}`,
    }));
    input.meeting.attendees[0].weight.permilage = 2_000;

    const normalized = normalizeTemplatePreviewSamples(input);

    expect(normalized.act.number).toBe(999_999);
    expect(normalized.meeting.members_present).toBe(0);
    expect(normalized.meeting.mesa.secretaries).toHaveLength(TEMPLATE_PREVIEW_SECRETARIES_MAX);
    expect(normalized.agenda).toHaveLength(TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX);
    expect(normalized.agenda[0].number).toBe(1);
    expect(normalized.deliberations.items[0].statements).toHaveLength(
      TEMPLATE_PREVIEW_STATEMENTS_MAX,
    );
    expect(normalized.meeting.attendees[0].weight.permilage).toBe(1_000);
    expect(input.act.number).toBe(2_000_000);
    expect(input.meeting.mesa.secretaries).toHaveLength(15);
  });

  it('reports every data-losing normalization boundary before autosave', () => {
    const input = structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
    input.act.number = 0;
    input.meeting.mesa.secretaries = Array.from({ length: 11 }, (_, index) => `S${index}`);
    input.agenda = Array.from({ length: 51 }, (_, index) => ({
      number: index + 1,
      text: `Ponto ${index + 1}`,
    }));
    input.deliberations.items[0].statements = Array.from({ length: 21 }, (_, index) => ({
      agenda_number: index + 1,
      member: `Membro ${index}`,
      text: `Declaração ${index}`,
    }));

    expect(validateTemplatePreviewSamples(input)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'number', path: 'act.number', min: 1, max: 999_999 }),
        expect.objectContaining({
          kind: 'collection',
          path: 'meeting.mesa.secretaries',
          value: 11,
          max: 10,
        }),
        expect.objectContaining({
          kind: 'collection',
          path: 'agenda',
          value: 51,
          max: 50,
        }),
        expect.objectContaining({
          kind: 'collection',
          path: 'deliberations.items.statements',
          value: 21,
          max: 20,
        }),
      ]),
    );
  });

  it('mirrors required text, length, format, digest and unique-agenda validation', () => {
    expect(validateTemplatePreviewSamples(DEFAULT_TEMPLATE_PREVIEW_SAMPLES)).toEqual([]);
    const input = structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
    input.general.title = '   ';
    input.general.subject = 's'.repeat(241);
    input.general.created_at = '2026-02-30';
    input.entity.nipc = '123ABC';
    input.entity.address = 'a'.repeat(501);
    input.act.meeting_time = '25:00';
    input.agenda[1].number = input.agenda[0].number;
    input.agenda[0].text = 'p'.repeat(2_001);
    input.evidence.attachments[0].digest = 'A'.repeat(64);

    expect(validateTemplatePreviewSamples(input)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'required', path: 'general.title' }),
        expect.objectContaining({
          kind: 'length',
          path: 'general.subject',
          value: 241,
          max: 240,
        }),
        expect.objectContaining({ kind: 'format', path: 'general.created_at', format: 'date' }),
        expect.objectContaining({ kind: 'format', path: 'entity.nipc', format: 'nipc' }),
        expect.objectContaining({
          kind: 'length',
          path: 'entity.address',
          value: 501,
          max: 500,
        }),
        expect.objectContaining({ kind: 'format', path: 'act.meeting_time', format: 'time' }),
        expect.objectContaining({ kind: 'duplicate', path: 'agenda.number', value: 1 }),
        expect.objectContaining({
          kind: 'length',
          path: 'agenda.text',
          value: 2_001,
          max: 2_000,
        }),
        expect.objectContaining({
          kind: 'format',
          path: 'evidence.attachments.digest',
          format: 'digest',
        }),
      ]),
    );
  });

  it('mirrors server character counting, control-character rules, and contact-sized places', () => {
    const padded = structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
    padded.general.subject = ` ${'s'.repeat(239)} `;
    expect(validateTemplatePreviewSamples(padded)).toContainEqual({
      kind: 'length',
      path: 'general.subject',
      value: 241,
      max: 240,
    });

    const unicodeScalars = structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
    unicodeScalars.general.subject = '😀'.repeat(240);
    expect(validateTemplatePreviewSamples(unicodeScalars)).toEqual([]);
    unicodeScalars.general.subject += '😀';
    expect(validateTemplatePreviewSamples(unicodeScalars)).toContainEqual({
      kind: 'length',
      path: 'general.subject',
      value: 241,
      max: 240,
    });

    const controls = structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
    controls.general.title = 'Ata\u0007fictícia';
    controls.entity.address = 'Rua\u0085Exemplo';
    controls.agenda[0].text = 'Linha 1\r\n\tLinha 2';
    controls.agenda[1].text = 'Texto\u0000inválido';
    expect(validateTemplatePreviewSamples(controls)).toEqual(
      expect.arrayContaining([
        { kind: 'characters', path: 'general.title' },
        { kind: 'characters', path: 'entity.address' },
        { kind: 'characters', path: 'agenda.text' },
      ]),
    );
    expect(
      validateTemplatePreviewSamples(controls).filter(
        (issue) => issue.kind === 'characters' && issue.path === 'agenda.text',
      ),
    ).toHaveLength(1);

    const places = structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
    places.act.place = 'A'.repeat(500);
    places.meeting.place = 'M'.repeat(500);
    expect(validateTemplatePreviewSamples(places)).toEqual([]);
    places.act.place += 'A';
    places.meeting.place += 'M';
    expect(validateTemplatePreviewSamples(places)).toEqual(
      expect.arrayContaining([
        { kind: 'length', path: 'act.place', value: 501, max: 500 },
        { kind: 'length', path: 'meeting.place', value: 501, max: 500 },
      ]),
    );
  });

  it('ships five fictitious family profiles, strict digests, and no editable law references', () => {
    expect(Object.keys(DEFAULT_TEMPLATE_PREVIEW_SAMPLES.family_profiles)).toEqual(
      TEMPLATE_PREVIEW_FAMILY_PROFILE_KEYS,
    );
    expect(
      Object.values(DEFAULT_TEMPLATE_PREVIEW_SAMPLES.family_profiles).every(
        (profile) => profile.name.length > 0 && profile.legal_form.length > 0,
      ),
    ).toBe(true);
    for (const attachment of DEFAULT_TEMPLATE_PREVIEW_SAMPLES.evidence.attachments) {
      expect(attachment.digest).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(DEFAULT_TEMPLATE_PREVIEW_SAMPLES.book_instruments.payload_digest).toMatch(
      /^[0-9a-f]{64}$/,
    );
    expect(DEFAULT_TEMPLATE_PREVIEW_SAMPLES.book_instruments.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(DEFAULT_TEMPLATE_PREVIEW_SAMPLES.book_instruments.rectifies).toContain('Ata');
    expect(JSON.stringify(DEFAULT_TEMPLATE_PREVIEW_SAMPLES)).not.toContain('law_references');
  });

  it('measures the UTF-8 wire payload against the 256 KiB budget', () => {
    const sample = structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
    sample.general.title = 'Pré-visualização fictícia';
    const serialized = JSON.stringify(sample);

    expect(templatePreviewSamplesByteSize(sample)).toBe(
      new TextEncoder().encode(serialized).length,
    );
    expect(templatePreviewSamplesByteSize(sample)).toBeGreaterThan(serialized.length);
    expect(templatePreviewSamplesByteSize(sample)).toBeLessThan(TEMPLATE_PREVIEW_SAMPLE_MAX_BYTES);
  });
});
