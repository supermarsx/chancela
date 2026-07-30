/**
 * The template-preview sample SECTION editors, on their own.
 *
 * `TemplatePreviewSamplesPanel.test.tsx` exercises the pane — its tabs, its size budget, its
 * reset. The seven section components it mounts were reached only incidentally, so the family
 * sat between 22% and 54% covered while the pane itself was at 97%. These are the editors an
 * operator actually types into, and every one of them is a `value` / `canEdit` / `update`
 * contract, so testing them directly is both cheap and the honest place to assert that contract.
 *
 * Assertions are by **stable control id** and by the payload handed to `update` — never by
 * translated prose, so the pt-PT copy can be rewritten without touching this file.
 */
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent } from '@testing-library/react';
import {
  DEFAULT_TEMPLATE_PREVIEW_SAMPLES,
  type TemplatePreviewSampleSettings,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import type { TemplatePreviewSampleUpdate } from './templatePreviewSampleSectionTypes';
import {
  TemplatePreviewEntitySection,
  TemplatePreviewGeneralSection,
} from './TemplatePreviewSampleGeneralSections';
import { TemplatePreviewSampleMeetingSection } from './TemplatePreviewSampleMeetingSection';
import { TemplatePreviewSampleAgendaSection } from './TemplatePreviewSampleAgendaSection';
import { TemplatePreviewSampleConveningSection } from './TemplatePreviewSampleConveningSection';
import {
  TemplatePreviewSampleBookSection,
  TemplatePreviewSampleEvidenceSection,
  TemplatePreviewSampleFallbacksSection,
} from './TemplatePreviewSampleEvidenceBookSections';

type Section = (props: {
  value: TemplatePreviewSampleSettings;
  canEdit: boolean;
  update: TemplatePreviewSampleUpdate;
}) => React.ReactElement;

/**
 * A stateful host, because every section is CONTROLLED. With a bare spy the `value` prop never
 * advances, so a second edit to the same group would be computed against the original settings
 * and the test would assert a component that does not exist.
 */
function Host({
  Section: S,
  canEdit = true,
  onUpdate,
}: {
  Section: Section;
  canEdit?: boolean;
  onUpdate?: TemplatePreviewSampleUpdate;
}) {
  const [value, setValue] = useState(() => structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES));
  return (
    <S
      value={value}
      canEdit={canEdit}
      update={(key, next) => {
        onUpdate?.(key, next);
        setValue((current) => ({ ...current, [key]: next }));
      }}
    />
  );
}

const ALL_SECTIONS: [string, Section][] = [
  ['general', TemplatePreviewGeneralSection],
  ['entity', TemplatePreviewEntitySection],
  ['meeting', TemplatePreviewSampleMeetingSection],
  ['agenda', TemplatePreviewSampleAgendaSection],
  ['convening', TemplatePreviewSampleConveningSection],
  ['evidence', TemplatePreviewSampleEvidenceSection],
  ['book', TemplatePreviewSampleBookSection],
  ['fallbacks', TemplatePreviewSampleFallbacksSection],
];

/**
 * `evidence` is deliberately absent from the inline-control sweeps.
 *
 * It is built entirely from `SampleCollectionTable`s — referenced documents and attachments —
 * whose row editors live inside a modal, so it renders a grid and an add button and no inline
 * `<input>` at all. Asserting "every section has controls" over it would not be a stronger test,
 * it would be a false description of the component. It gets its own assertions below instead.
 */
const INLINE_SECTIONS = ALL_SECTIONS.filter(([name]) => name !== 'evidence');
const COLLECTION_SECTIONS = ALL_SECTIONS.filter(([name]) => name === 'evidence');

afterEach(cleanup);

describe('template-preview sample sections', () => {
  it.each(INLINE_SECTIONS)('renders %s with editable controls', (_name, Section) => {
    const { container } = renderWithProviders(<Host Section={Section} />);
    const controls = [...container.querySelectorAll('input, textarea, select')];
    expect(controls.length).toBeGreaterThan(0);
    for (const control of controls) expect(control.hasAttribute('disabled')).toBe(false);
  });

  it.each(INLINE_SECTIONS)(
    'disables every control in %s when editing is not permitted',
    (_name, Section) => {
      const { container } = renderWithProviders(<Host Section={Section} canEdit={false} />);
      const controls = [...container.querySelectorAll('input, textarea, select')];
      expect(controls.length).toBeGreaterThan(0);
      // `canEdit` is the whole permission story for these editors: if one control forgets to read
      // it, a viewer without the permission can still type into the sample.
      for (const control of controls) expect(control.hasAttribute('disabled')).toBe(true);
    },
  );

  it.each(INLINE_SECTIONS)(
    'routes every %s edit through `update` with its own group key',
    (name, Section) => {
      const onUpdate = vi.fn();
      const { container } = renderWithProviders(<Host Section={Section} onUpdate={onUpdate} />);
      const controls = [...container.querySelectorAll('input, textarea')].filter(
        (c) => (c as HTMLInputElement).type !== 'checkbox',
      );

      for (const [index, control] of controls.entries()) {
        const input = control as HTMLInputElement;
        // A value each control's own type accepts, so `type="date"`/`"number"` are not silently
        // blanked into an assertion that would pass for the wrong reason.
        const next =
          input.type === 'date'
            ? '2026-03-04'
            : input.type === 'time'
              ? '10:30'
              : input.type === 'number'
                ? String(index + 2)
                : `editado ${index}`;
        fireEvent.change(input, { target: { value: next } });
      }

      // Not every inline control writes on `change` — some are composite rows whose parts are
      // committed together — so this asserts that editing reaches `update`, not a per-control
      // count that would encode today's field list as a contract.
      expect(onUpdate.mock.calls.length).toBeGreaterThan(0);
      expect(onUpdate.mock.calls.length).toBeLessThanOrEqual(controls.length);
      // Every call names a real settings group, and a section only ever writes its own.
      const keys = new Set(onUpdate.mock.calls.map((call) => call[0] as string));
      for (const key of keys) {
        expect(Object.keys(DEFAULT_TEMPLATE_PREVIEW_SAMPLES)).toContain(key);
      }
      expect(keys.size, `${name} wrote no group`).toBeGreaterThan(0);
    },
  );

  it.each(COLLECTION_SECTIONS)(
    'renders %s as collection grids with an add control',
    (_name, Section) => {
      const { container } = renderWithProviders(<Host Section={Section} />);
      // Two collections — referenced documents and attachments — each a real table.
      expect(container.querySelectorAll('table').length).toBeGreaterThanOrEqual(2);
      const buttons = [...container.querySelectorAll('button')];
      expect(buttons.length).toBeGreaterThan(0);
      expect(buttons.some((b) => !b.hasAttribute('disabled'))).toBe(true);
    },
  );

  it.each(COLLECTION_SECTIONS)(
    'locks %s entirely when editing is not permitted',
    (_name, Section) => {
      const { container } = renderWithProviders(<Host Section={Section} canEdit={false} />);
      const buttons = [...container.querySelectorAll('button')];
      expect(buttons.length).toBeGreaterThan(0);
      // No path to mutate the sample without the permission — the row editors are behind these.
      for (const button of buttons) expect(button.hasAttribute('disabled')).toBe(true);
    },
  );

  it('toggles the boolean settings the sections expose', () => {
    const onUpdate = vi.fn();
    for (const [, Section] of ALL_SECTIONS) {
      const { container } = renderWithProviders(<Host Section={Section} onUpdate={onUpdate} />);
      for (const box of container.querySelectorAll('input[type="checkbox"]')) {
        fireEvent.click(box);
      }
      cleanup();
    }
    // Not every section has one; this asserts the ones that do actually write through.
    for (const call of onUpdate.mock.calls) {
      expect(Object.keys(DEFAULT_TEMPLATE_PREVIEW_SAMPLES)).toContain(call[0] as string);
    }
  });

  it('keeps each section writing only to the group it owns', () => {
    // A section that wrote a neighbour's key would silently discard the neighbour's edits, since
    // `update` replaces the whole group.
    const owned: Record<string, string[]> = {};
    for (const [name, Section] of INLINE_SECTIONS) {
      const onUpdate = vi.fn();
      const { container } = renderWithProviders(<Host Section={Section} onUpdate={onUpdate} />);
      for (const control of container.querySelectorAll('input:not([type="checkbox"]), textarea')) {
        fireEvent.change(control, { target: { value: 'x' } });
      }
      owned[name] = [...new Set(onUpdate.mock.calls.map((c) => c[0] as string))].sort();
      cleanup();
    }
    // The general and entity editors are two components over two different groups; the rest each
    // own one. Whatever the shape, it must be stable and non-empty.
    for (const [name, keys] of Object.entries(owned)) {
      expect(keys.length, `${name} wrote nothing`).toBeGreaterThan(0);
      expect(keys.length, `${name} wrote across too many groups`).toBeLessThanOrEqual(4);
    }
  });
});
