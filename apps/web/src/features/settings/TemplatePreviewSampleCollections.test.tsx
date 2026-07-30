/**
 * The repeatable-row editors inside the template-preview sample sections.
 *
 * `TemplatePreviewSampleSections.test.tsx` covers the inline controls and the `canEdit` lock.
 * What it cannot reach is everything behind the add button: `SampleCollectionTable` renders its
 * row editor, its per-row validity gate and its column cells only once a row is being edited, so
 * the whole modal half of these sections — every `renderEditor`, every `validateRow` — was never
 * executed.
 *
 * The property under test is the same for every collection and is a refusal: a row that does not
 * validate cannot be saved. These samples are what the template preview renders as a document, so
 * a half-filled row is a preview with a blank where a member's name or an agenda line belongs.
 *
 * The book and fallbacks sections are absent below because they hold no repeatable collection at
 * all — they are scalar editors, already covered by `TemplatePreviewSampleSections.test.tsx`.
 *
 * Everything is addressed structurally — the dialog, its submit control, its inputs — never by
 * translated prose.
 */
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, within } from '@testing-library/react';
import {
  DEFAULT_TEMPLATE_PREVIEW_SAMPLES,
  type TemplatePreviewSampleSettings,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import type { TemplatePreviewSampleUpdate } from './templatePreviewSampleSectionTypes';
import { TemplatePreviewSampleMeetingSection } from './TemplatePreviewSampleMeetingSection';
import { TemplatePreviewSampleAgendaSection } from './TemplatePreviewSampleAgendaSection';
import { TemplatePreviewSampleConveningSection } from './TemplatePreviewSampleConveningSection';
import { TemplatePreviewSampleEvidenceSection } from './TemplatePreviewSampleEvidenceBookSections';

type Section = (props: {
  value: TemplatePreviewSampleSettings;
  canEdit: boolean;
  update: TemplatePreviewSampleUpdate;
}) => React.ReactElement;

/** A stateful host: these editors are controlled, so `value` must advance between interactions. */
function Host({
  Section: S,
  onUpdate,
}: {
  Section: Section;
  onUpdate: TemplatePreviewSampleUpdate;
}) {
  const [value, setValue] = useState(() => structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES));
  return (
    <S
      value={value}
      canEdit
      update={(key, next) => {
        onUpdate(key, next);
        setValue((current) => ({ ...current, [key]: next }));
      }}
    />
  );
}

/**
 * Every enabled add control the section renders — one per collection it owns.
 *
 * Located structurally: `SampleCollectionTable` puts its add button either in the card's action
 * slot or in the nested collection's header, and never inside a row's action group. Matching on
 * position rather than on the label's words keeps this independent of the copy, which
 * interpolates the collection title.
 */
function addButtons(container: HTMLElement): HTMLButtonElement[] {
  return [
    ...container.querySelectorAll<HTMLButtonElement>(
      '.panel__actions button, .template-preview-nested-head button',
    ),
  ].filter((button) => !button.disabled);
}

function dialog(): HTMLElement {
  return screen.getByRole('dialog');
}

function saveButton(): HTMLButtonElement {
  const submit = dialog().querySelector<HTMLButtonElement>('button[type=submit]');
  if (!submit) throw new Error('the row editor has no submit control');
  return submit;
}

/** A lower-case 64-hex digest, the only shape `isTemplatePreviewDigest` accepts. */
const DIGEST = 'a'.repeat(64);

/**
 * Fill every field of the open row editor with a value its own input type accepts.
 *
 * The digest box is the one field with a FORMAT rather than merely a length, so it gets a real
 * digest — a filler that ignored the format would make "the save button enables" untestable for
 * the attachments collection, which is precisely where the format matters.
 */
function fillEditor(): number {
  const fields = [
    ...dialog().querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(
      'input, textarea, select',
    ),
  ];
  for (const [index, field] of fields.entries()) {
    if (field instanceof HTMLSelectElement) continue;
    if (field.type === 'checkbox') continue;
    const next = field.id.includes('digest')
      ? DIGEST
      : field.type === 'date'
        ? '2026-03-04'
        : field.type === 'time'
          ? '10:30'
          : field.type === 'number'
            ? String(index + 1)
            : `Amostra ${index + 1}`;
    fireEvent.change(field, { target: { value: next } });
  }
  return fields.length;
}

function tableRowCount(container: HTMLElement): number {
  return [...container.querySelectorAll('table tbody tr')].length;
}

const COLLECTION_SECTIONS: [string, Section][] = [
  ['meeting', TemplatePreviewSampleMeetingSection],
  ['agenda', TemplatePreviewSampleAgendaSection],
  ['convening', TemplatePreviewSampleConveningSection],
  ['evidence', TemplatePreviewSampleEvidenceSection],
];

afterEach(cleanup);

describe('template-preview sample collections', () => {
  it.each(COLLECTION_SECTIONS)(
    'refuses to save an empty row in every %s collection, and accepts a filled one',
    (name, Section) => {
      const onUpdate = vi.fn();
      const { container } = renderWithProviders(<Host Section={Section} onUpdate={onUpdate} />);
      const adds = addButtons(container);
      expect(adds.length, `${name} exposes no add control`).toBeGreaterThan(0);

      for (const add of adds) {
        fireEvent.click(add);
        const before = onUpdate.mock.calls.length;

        // A freshly created row is blank, and a blank row is not a sample.
        expect(saveButton().disabled).toBe(true);
        fireEvent.click(saveButton());
        expect(onUpdate.mock.calls.length).toBe(before);

        const filled = fillEditor();
        expect(filled).toBeGreaterThan(0);
        expect(saveButton().disabled).toBe(false);
        fireEvent.click(saveButton());

        // Saved: the dialog closes and the group is written through `update`.
        expect(screen.queryByRole('dialog')).toBeNull();
        expect(onUpdate.mock.calls.length).toBeGreaterThan(before);
        expect(Object.keys(DEFAULT_TEMPLATE_PREVIEW_SAMPLES)).toContain(
          onUpdate.mock.calls[onUpdate.mock.calls.length - 1][0] as string,
        );
      }
    },
  );

  it('cancels a row editor without writing anything', () => {
    const onUpdate = vi.fn();
    const { container } = renderWithProviders(
      <Host Section={TemplatePreviewSampleAgendaSection} onUpdate={onUpdate} />,
    );

    fireEvent.click(addButtons(container)[0]);
    fillEditor();
    const cancel = within(dialog())
      .getAllByRole('button')
      .find((button) => (button as HTMLButtonElement).type === 'button');
    fireEvent.click(cancel!);

    expect(screen.queryByRole('dialog')).toBeNull();
    // A row abandoned is a row never added — not a half-written sample left behind.
    expect(onUpdate).not.toHaveBeenCalled();
  });

  it('closes a row editor on Escape, which must also discard it', () => {
    const onUpdate = vi.fn();
    const { container } = renderWithProviders(
      <Host Section={TemplatePreviewSampleAgendaSection} onUpdate={onUpdate} />,
    );

    fireEvent.click(addButtons(container)[0]);
    fillEditor();
    fireEvent.keyDown(document, { key: 'Escape' });

    expect(screen.queryByRole('dialog')).toBeNull();
    expect(onUpdate).not.toHaveBeenCalled();
  });

  it('reorders and removes rows through the per-row controls', () => {
    const onUpdate = vi.fn();
    const { container } = renderWithProviders(
      <Host Section={TemplatePreviewSampleAgendaSection} onUpdate={onUpdate} />,
    );

    const rowsAtStart = tableRowCount(container);
    expect(rowsAtStart).toBeGreaterThan(1);

    const rowActions = (index: number) => [
      ...container
        .querySelectorAll('table tbody tr')
        [index].querySelectorAll<HTMLButtonElement>('.template-preview-sample-actions button'),
    ];

    // Four controls per row: up, down, edit, remove. The first row cannot move up and the last
    // cannot move down — the ends of a list are not silently wrapped.
    const first = rowActions(0);
    expect(first).toHaveLength(4);
    expect(first[0].disabled).toBe(true);
    expect(rowActions(rowsAtStart - 1)[1].disabled).toBe(true);

    fireEvent.click(rowActions(0)[1]);
    expect(onUpdate).toHaveBeenCalledTimes(1);

    fireEvent.click(rowActions(0)[3]);
    expect(tableRowCount(container)).toBe(rowsAtStart - 1);
  });

  it('opens an existing row for editing with its current values, not a blank one', () => {
    const onUpdate = vi.fn();
    const { container } = renderWithProviders(
      <Host Section={TemplatePreviewSampleAgendaSection} onUpdate={onUpdate} />,
    );

    const edit = [
      ...container
        .querySelectorAll('table tbody tr')[0]
        .querySelectorAll<HTMLButtonElement>('.template-preview-sample-actions button'),
    ][2];
    fireEvent.click(edit);

    const fields = [...dialog().querySelectorAll<HTMLInputElement>('input, textarea')];
    expect(fields.length).toBeGreaterThan(0);
    // Seeded from the row: an editor that opened blank would silently blank the row on save.
    expect(fields.some((field) => field.value.trim().length > 0)).toBe(true);
    // And it is already valid, because the row it came from was.
    expect(saveButton().disabled).toBe(false);
  });
});
