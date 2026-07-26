import {
  DEFAULT_TEMPLATE_PREVIEW_SAMPLES,
  TEMPLATE_PREVIEW_FAMILY_PROFILE_KEYS,
  type TemplatePreviewSampleSettings,
} from '../../api/types';

export const TEMPLATE_PREVIEW_SAMPLE_MAX_BYTES = 256 * 1024;
export const TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX = 50;
export const TEMPLATE_PREVIEW_STATEMENTS_MAX = 20;
export const TEMPLATE_PREVIEW_SECRETARIES_MAX = 10;

const CONTROL_CHARACTER = /\p{Cc}/u;

export function templatePreviewScalarLength(value: string): number {
  return [...value].length;
}

function hasUnsupportedTemplatePreviewControl(
  value: string,
  allowProseWhitespace: boolean,
): boolean {
  return [...value].some(
    (character) =>
      CONTROL_CHARACTER.test(character) &&
      !(allowProseWhitespace && ['\r', '\n', '\t'].includes(character)),
  );
}

function isTemplatePreviewText(
  value: string,
  max: number,
  required: boolean,
  allowProseWhitespace: boolean,
): boolean {
  return (
    (!required || value.trim().length > 0) &&
    templatePreviewScalarLength(value) <= max &&
    !hasUnsupportedTemplatePreviewControl(value, allowProseWhitespace)
  );
}

export const isTemplatePreviewShortText = (value: string): boolean =>
  isTemplatePreviewText(value, 240, true, false);

export const isTemplatePreviewContactText = (value: string): boolean =>
  isTemplatePreviewText(value, 500, true, false);

export const isTemplatePreviewProse = (value: string): boolean =>
  isTemplatePreviewText(value, 2_000, true, true);

export function isTemplatePreviewIsoDate(candidate: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(candidate);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  return (
    parsed.getUTCFullYear() === year &&
    parsed.getUTCMonth() === month - 1 &&
    parsed.getUTCDate() === day
  );
}

export const isTemplatePreviewDigest = (value: string): boolean => /^[0-9a-f]{64}$/.test(value);

export const isTemplatePreviewDocumentNumber = (value: number): boolean =>
  Number.isInteger(value) && value >= 1 && value <= 999_999;

export const isTemplatePreviewCount = (value: number): boolean =>
  Number.isInteger(value) && value >= 0 && value <= 1_000_000;

export const isTemplatePreviewPermilage = (value: number): boolean =>
  Number.isInteger(value) && value >= 0 && value <= 1_000;

export type TemplatePreviewSampleValidationIssue =
  | {
      kind: 'collection';
      path: string;
      value: number;
      min: number;
      max: number;
    }
  | {
      kind: 'number';
      path: string;
      value: number;
      min: number;
      max: number;
    }
  | {
      kind: 'required';
      path: string;
    }
  | {
      kind: 'length';
      path: string;
      value: number;
      max: number;
    }
  | {
      kind: 'characters';
      path: string;
    }
  | {
      kind: 'format';
      path: string;
      format: 'date' | 'time' | 'nipc' | 'digest';
    }
  | {
      kind: 'duplicate';
      path: string;
      value: number;
    }
  | {
      kind: 'size';
      path: 'root';
      value: number;
      max: number;
    };

export type DeepPartial<T> = T extends readonly (infer Item)[]
  ? DeepPartial<Item>[]
  : T extends object
    ? { [Key in keyof T]?: DeepPartial<T[Key]> }
    : T;

function cloneDefaults(): TemplatePreviewSampleSettings {
  return structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
}

/**
 * Hydrate stale settings clients field-by-field. Arrays are atomic authored collections: an
 * explicit empty list stays empty, while an omitted list receives the product sample.
 */
export function hydrateTemplatePreviewSamples(
  value?: DeepPartial<TemplatePreviewSampleSettings> | null,
): TemplatePreviewSampleSettings {
  const defaults = cloneDefaults();
  if (!value) return defaults;
  const familyProfiles = Object.fromEntries(
    TEMPLATE_PREVIEW_FAMILY_PROFILE_KEYS.map((key) => [
      key,
      { ...defaults.family_profiles[key], ...(value.family_profiles?.[key] ?? {}) },
    ]),
  ) as TemplatePreviewSampleSettings['family_profiles'];

  return {
    general: { ...defaults.general, ...(value.general ?? {}) },
    entity: { ...defaults.entity, ...(value.entity ?? {}) },
    family_profiles: familyProfiles,
    book: { ...defaults.book, ...(value.book ?? {}) },
    act: { ...defaults.act, ...(value.act ?? {}) },
    meeting: {
      ...defaults.meeting,
      ...(value.meeting ?? {}),
      mesa: {
        ...defaults.meeting.mesa,
        ...(value.meeting?.mesa ?? {}),
        secretaries:
          (value.meeting?.mesa?.secretaries as string[] | undefined) ??
          defaults.meeting.mesa.secretaries,
      },
      attendees:
        (value.meeting?.attendees as TemplatePreviewSampleSettings['meeting']['attendees']) ??
        defaults.meeting.attendees,
    },
    agenda:
      (value.agenda as TemplatePreviewSampleSettings['agenda'] | undefined) ?? defaults.agenda,
    deliberations: {
      ...defaults.deliberations,
      ...(value.deliberations ?? {}),
      items:
        (value.deliberations?.items as TemplatePreviewSampleSettings['deliberations']['items']) ??
        defaults.deliberations.items,
    },
    evidence: {
      ...defaults.evidence,
      ...(value.evidence ?? {}),
      referenced_documents:
        (value.evidence
          ?.referenced_documents as TemplatePreviewSampleSettings['evidence']['referenced_documents']) ??
        defaults.evidence.referenced_documents,
      attachments:
        (value.evidence?.attachments as TemplatePreviewSampleSettings['evidence']['attachments']) ??
        defaults.evidence.attachments,
      signatories:
        (value.evidence?.signatories as TemplatePreviewSampleSettings['evidence']['signatories']) ??
        defaults.evidence.signatories,
      required_signatories:
        (value.evidence
          ?.required_signatories as TemplatePreviewSampleSettings['evidence']['required_signatories']) ??
        defaults.evidence.required_signatories,
    },
    convening: {
      ...defaults.convening,
      ...(value.convening ?? {}),
      second_call: {
        ...defaults.convening.second_call,
        ...(value.convening?.second_call ?? {}),
      },
      recipients:
        (value.convening?.recipients as TemplatePreviewSampleSettings['convening']['recipients']) ??
        defaults.convening.recipients,
    },
    convening_waiver: {
      ...defaults.convening_waiver,
      ...(value.convening_waiver ?? {}),
    },
    representation: {
      ...defaults.representation,
      ...(value.representation ?? {}),
      representative: {
        ...defaults.representation.representative,
        ...(value.representation?.representative ?? {}),
      },
      represented: {
        ...defaults.representation.represented,
        ...(value.representation?.represented ?? {}),
      },
    },
    telematic_evidence: {
      ...defaults.telematic_evidence,
      ...(value.telematic_evidence ?? {}),
    },
    book_instruments: {
      ...defaults.book_instruments,
      ...(value.book_instruments ?? {}),
    },
    fallbacks: {
      ...defaults.fallbacks,
      ...(value.fallbacks ?? {}),
      statement: {
        ...defaults.fallbacks.statement,
        ...(value.fallbacks?.statement ?? {}),
      },
      weight: { ...defaults.fallbacks.weight, ...(value.fallbacks?.weight ?? {}) },
    },
  };
}

const boundedInteger = (value: number, min: number, max: number): number => {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.trunc(value)));
};

/**
 * Validate authored values before autosave. The editor constrains new input, while this catches a
 * stale or externally-authored settings document so normalization never silently drops rows.
 */
export function validateTemplatePreviewSamples(
  value: TemplatePreviewSampleSettings,
): TemplatePreviewSampleValidationIssue[] {
  const issues: TemplatePreviewSampleValidationIssue[] = [];
  const number = (path: string, candidate: number, min: number, max: number) => {
    if (!Number.isInteger(candidate) || candidate < min || candidate > max) {
      issues.push({ kind: 'number', path, value: candidate, min, max });
    }
  };
  const collection = (path: string, length: number, min: number, max: number) => {
    if (length < min || length > max) {
      issues.push({ kind: 'collection', path, value: length, min, max });
    }
  };
  const text = (
    path: string,
    candidate: string,
    max = 240,
    required = true,
    allowProseWhitespace = false,
  ) => {
    const length = templatePreviewScalarLength(candidate);
    if (required && candidate.trim().length === 0) {
      issues.push({ kind: 'required', path });
    } else if (length > max) {
      issues.push({ kind: 'length', path, value: length, max });
    } else if (hasUnsupportedTemplatePreviewControl(candidate, allowProseWhitespace)) {
      issues.push({ kind: 'characters', path });
    }
  };
  const prose = (path: string, candidate: string) => text(path, candidate, 2_000, true, true);
  const formatted = (
    path: string,
    _candidate: string,
    format: 'date' | 'time' | 'nipc' | 'digest',
    valid: boolean,
  ) => {
    if (!valid) issues.push({ kind: 'format', path, format });
  };
  const date = (path: string, candidate: string) => {
    formatted(path, candidate, 'date', isTemplatePreviewIsoDate(candidate));
  };
  const time = (path: string, candidate: string) =>
    formatted(path, candidate, 'time', /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(candidate));
  const uniqueNumbers = (path: string, values: number[]) => {
    const seen = new Set<number>();
    const repeated = new Set<number>();
    values.forEach((candidate) => {
      if (seen.has(candidate)) repeated.add(candidate);
      seen.add(candidate);
    });
    repeated.forEach((candidate) => issues.push({ kind: 'duplicate', path, value: candidate }));
  };

  text('general.title', value.general.title);
  text('general.subject', value.general.subject, 240, false);
  date('general.created_at', value.general.created_at);
  formatted('entity.nipc', value.entity.nipc, 'nipc', /^\d{9}$/.test(value.entity.nipc));
  text('entity.seat', value.entity.seat, 500);
  text('entity.address', value.entity.address, 500);
  text('entity.share_capital', value.entity.share_capital);
  text('entity.capital', value.entity.capital);
  TEMPLATE_PREVIEW_FAMILY_PROFILE_KEYS.forEach((key) => {
    text('family_profiles.name', value.family_profiles[key].name);
    text('family_profiles.legal_form', value.family_profiles[key].legal_form);
  });
  text('book.kind', value.book.kind);
  text('book.reference', value.book.reference);
  text('book.predecessor_reference', value.book.predecessor_reference);

  number('act.number', value.act.number, 1, 999_999);
  text('act.title', value.act.title);
  date('act.meeting_date', value.act.meeting_date);
  time('act.meeting_time', value.act.meeting_time);
  text('act.place', value.act.place, 500);
  number('meeting.ata_number', value.meeting.ata_number, 1, 999_999);
  number('meeting.agenda_number', value.meeting.agenda_number, 1, 999_999);
  date('meeting.meeting_date', value.meeting.meeting_date);
  time('meeting.meeting_time', value.meeting.meeting_time);
  text('meeting.place', value.meeting.place, 500);
  number('meeting.members_present', value.meeting.members_present, 0, 1_000_000);
  number('meeting.members_represented', value.meeting.members_represented, 0, 1_000_000);
  text('meeting.attendance_reference', value.meeting.attendance_reference);
  text('meeting.mesa.president', value.meeting.mesa.president);
  collection(
    'meeting.mesa.secretaries',
    value.meeting.mesa.secretaries.length,
    1,
    TEMPLATE_PREVIEW_SECRETARIES_MAX,
  );
  value.meeting.mesa.secretaries.forEach((secretary) =>
    text('meeting.mesa.secretaries.value', secretary),
  );
  collection(
    'meeting.attendees',
    value.meeting.attendees.length,
    1,
    TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
  );
  value.meeting.attendees.forEach((attendee) => {
    text('meeting.attendees.name', attendee.name);
    text('meeting.attendees.quality_note', attendee.quality_note);
    if (attendee.weight.capital !== null) {
      text('meeting.attendees.weight.capital', attendee.weight.capital);
    }
    if (attendee.represented_by !== null) {
      text('meeting.attendees.represented_by', attendee.represented_by);
    }
    if (attendee.weight.permilage !== null) {
      number('meeting.attendees.weight.permilage', attendee.weight.permilage, 0, 1_000);
    }
  });

  collection('agenda', value.agenda.length, 1, TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX);
  value.agenda.forEach((item) => {
    number('agenda.number', item.number, 1, 999_999);
    prose('agenda.text', item.text);
  });
  uniqueNumbers(
    'agenda.number',
    value.agenda.map((item) => item.number),
  );
  collection(
    'deliberations.items',
    value.deliberations.items.length,
    1,
    TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
  );
  prose('deliberations.summary', value.deliberations.summary);
  value.deliberations.items.forEach((item) => {
    number('deliberations.items.agenda_number', item.agenda_number, 1, 999_999);
    prose('deliberations.items.text', item.text);
    collection(
      'deliberations.items.statements',
      item.statements.length,
      0,
      TEMPLATE_PREVIEW_STATEMENTS_MAX,
    );
    item.statements.forEach((statement) => {
      number('deliberations.items.statements.agenda_number', statement.agenda_number, 1, 999_999);
      text('deliberations.items.statements.member', statement.member);
      prose('deliberations.items.statements.text', statement.text);
    });
    if (item.vote !== 'Unanimous') {
      number('deliberations.items.vote.em_favor', item.vote.Recorded.em_favor, 0, 1_000_000);
      number('deliberations.items.vote.contra', item.vote.Recorded.contra, 0, 1_000_000);
      number('deliberations.items.vote.abstencoes', item.vote.Recorded.abstencoes, 0, 1_000_000);
    }
  });
  uniqueNumbers(
    'deliberations.items.agenda_number',
    value.deliberations.items.map((item) => item.agenda_number),
  );

  collection(
    'evidence.referenced_documents',
    value.evidence.referenced_documents.length,
    1,
    TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
  );
  value.evidence.referenced_documents.forEach((document) => {
    text('evidence.referenced_documents.label', document.label);
    text('evidence.referenced_documents.reference', document.reference);
  });
  collection(
    'evidence.attachments',
    value.evidence.attachments.length,
    1,
    TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
  );
  value.evidence.attachments.forEach((attachment) => {
    text('evidence.attachments.kind', attachment.kind);
    formatted(
      'evidence.attachments.digest',
      attachment.digest,
      'digest',
      /^[0-9a-f]{64}$/.test(attachment.digest),
    );
  });
  collection(
    'evidence.signatories',
    value.evidence.signatories.length,
    1,
    TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
  );
  collection(
    'evidence.required_signatories',
    value.evidence.required_signatories.length,
    1,
    TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
  );
  [...value.evidence.signatories, ...value.evidence.required_signatories].forEach((signatory) => {
    text('evidence.signatories.role', signatory.role);
    text('evidence.signatories.name', signatory.name);
  });
  text('convening.convener', value.convening.convener);
  date('convening.dispatch_date', value.convening.dispatch_date);
  number('convening.antecedence_days', value.convening.antecedence_days, 0, 3_650);
  date('convening.second_call.date', value.convening.second_call.date);
  time('convening.second_call.time', value.convening.second_call.time);
  collection(
    'convening.recipients',
    value.convening.recipients.length,
    1,
    TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
  );
  value.convening.recipients.forEach((recipient) => {
    text('convening.recipients.name', recipient.name);
    text('convening.recipients.contact', recipient.contact, 500);
    text('convening.recipients.reference', recipient.reference);
    date('convening.recipients.dispatched_at', recipient.dispatched_at);
  });
  text('convening_waiver.basis', value.convening_waiver.basis);
  prose('convening_waiver.grounds', value.convening_waiver.grounds);
  text('convening_waiver.evidence_reference', value.convening_waiver.evidence_reference);
  prose('representation.scope', value.representation.scope);
  prose('representation.instructions', value.representation.instructions);
  text('representation.evidence_reference', value.representation.evidence_reference);
  text('representation.representative.name', value.representation.representative.name);
  text('representation.representative.document', value.representation.representative.document);
  text('representation.represented.name', value.representation.represented.name);
  text('representation.represented.unit', value.representation.represented.unit);
  prose('telematic_evidence.authenticity', value.telematic_evidence.authenticity);
  prose('telematic_evidence.recording', value.telematic_evidence.recording);
  prose('telematic_evidence.security', value.telematic_evidence.security);
  date('book_instruments.opening_date', value.book_instruments.opening_date);
  date('book_instruments.closing_date', value.book_instruments.closing_date);
  text('book_instruments.numbering_label', value.book_instruments.numbering_label);
  prose('book_instruments.purpose', value.book_instruments.purpose);
  number('book_instruments.ata_count', value.book_instruments.ata_count, 0, 1_000_000);
  text('book_instruments.rectifies', value.book_instruments.rectifies);
  number('book_instruments.seal_event_seq', value.book_instruments.seal_event_seq, 0, 1_000_000);
  formatted(
    'book_instruments.payload_digest',
    value.book_instruments.payload_digest,
    'digest',
    /^[0-9a-f]{64}$/.test(value.book_instruments.payload_digest),
  );
  formatted(
    'book_instruments.digest',
    value.book_instruments.digest,
    'digest',
    /^[0-9a-f]{64}$/.test(value.book_instruments.digest),
  );
  text('fallbacks.contact', value.fallbacks.contact, 500);
  date('fallbacks.dispatched_at', value.fallbacks.dispatched_at);
  text('fallbacks.kind', value.fallbacks.kind);
  text('fallbacks.label', value.fallbacks.label);
  text('fallbacks.name', value.fallbacks.name);
  number('fallbacks.number', value.fallbacks.number, 1, 999_999);
  text('fallbacks.quality_note', value.fallbacks.quality_note);
  text('fallbacks.reference', value.fallbacks.reference);
  text('fallbacks.represented_by', value.fallbacks.represented_by);
  text('fallbacks.role', value.fallbacks.role);
  number('fallbacks.statement.agenda_number', value.fallbacks.statement.agenda_number, 1, 999_999);
  text('fallbacks.statement.member', value.fallbacks.statement.member);
  prose('fallbacks.statement.text', value.fallbacks.statement.text);
  prose('fallbacks.text', value.fallbacks.text);
  text('fallbacks.weight.capital', value.fallbacks.weight.capital);
  number('fallbacks.weight.permilage', value.fallbacks.weight.permilage, 0, 1_000);

  const bytes = templatePreviewSamplesByteSize(value);
  if (bytes > TEMPLATE_PREVIEW_SAMPLE_MAX_BYTES) {
    issues.push({
      kind: 'size',
      path: 'root',
      value: bytes,
      max: TEMPLATE_PREVIEW_SAMPLE_MAX_BYTES,
    });
  }
  return issues;
}

/** Client-side mirror of numeric/collection bounds. The server remains authoritative. */
export function normalizeTemplatePreviewSamples(
  input: TemplatePreviewSampleSettings,
): TemplatePreviewSampleSettings {
  const value = hydrateTemplatePreviewSamples(input);
  return {
    ...value,
    act: { ...value.act, number: boundedInteger(value.act.number, 1, 999_999) },
    meeting: {
      ...value.meeting,
      ata_number: boundedInteger(value.meeting.ata_number, 1, 999_999),
      agenda_number: boundedInteger(value.meeting.agenda_number, 1, 999_999),
      members_present: boundedInteger(value.meeting.members_present, 0, 1_000_000),
      members_represented: boundedInteger(value.meeting.members_represented, 0, 1_000_000),
      mesa: {
        ...value.meeting.mesa,
        secretaries: value.meeting.mesa.secretaries.slice(0, TEMPLATE_PREVIEW_SECRETARIES_MAX),
      },
      attendees: value.meeting.attendees
        .slice(0, TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX)
        .map((attendee) => ({
          ...attendee,
          weight: {
            ...attendee.weight,
            permilage:
              attendee.weight.permilage === null
                ? null
                : boundedInteger(attendee.weight.permilage, 0, 1_000),
          },
        })),
    },
    agenda: value.agenda.slice(0, TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX).map((item) => ({
      ...item,
      number: boundedInteger(item.number, 1, 999_999),
    })),
    deliberations: {
      ...value.deliberations,
      items: value.deliberations.items
        .slice(0, TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX)
        .map((item) => ({
          ...item,
          agenda_number: boundedInteger(item.agenda_number, 1, 999_999),
          vote:
            item.vote === 'Unanimous'
              ? item.vote
              : {
                  Recorded: {
                    em_favor: boundedInteger(item.vote.Recorded.em_favor, 0, 1_000_000),
                    contra: boundedInteger(item.vote.Recorded.contra, 0, 1_000_000),
                    abstencoes: boundedInteger(item.vote.Recorded.abstencoes, 0, 1_000_000),
                  },
                },
          statements: item.statements.slice(0, TEMPLATE_PREVIEW_STATEMENTS_MAX),
        })),
    },
    evidence: {
      referenced_documents: value.evidence.referenced_documents.slice(
        0,
        TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
      ),
      attachments: value.evidence.attachments.slice(0, TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX),
      signatories: value.evidence.signatories.slice(0, TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX),
      required_signatories: value.evidence.required_signatories.slice(
        0,
        TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX,
      ),
    },
    convening: {
      ...value.convening,
      antecedence_days: boundedInteger(value.convening.antecedence_days, 0, 3_650),
      recipients: value.convening.recipients.slice(0, TEMPLATE_PREVIEW_PRIMARY_COLLECTION_MAX),
    },
    book_instruments: {
      ...value.book_instruments,
      ata_count: boundedInteger(value.book_instruments.ata_count, 0, 1_000_000),
      seal_event_seq: boundedInteger(value.book_instruments.seal_event_seq, 0, 1_000_000),
    },
    fallbacks: {
      ...value.fallbacks,
      number: boundedInteger(value.fallbacks.number, 1, 999_999),
      statement: {
        ...value.fallbacks.statement,
        agenda_number: boundedInteger(value.fallbacks.statement.agenda_number, 1, 999_999),
      },
      weight: {
        ...value.fallbacks.weight,
        permilage: boundedInteger(value.fallbacks.weight.permilage, 0, 1_000),
      },
    },
  };
}

export function templatePreviewSamplesByteSize(value: TemplatePreviewSampleSettings): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}
