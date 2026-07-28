/**
 * The two states of the Sobre build-provenance rows (t100).
 *
 * The absent-git state is the reason this component exists separately from `SettingsPage.tsx`:
 * inside the page it depends on a build-time global that no test can vary, and a Docker or
 * source-tarball build is exactly the case that would otherwise ship unexercised.
 *
 * Copy is asserted through the fallback module's own objects, never as a pt-PT literal typed into
 * the test — a test that repeated the sentence would pass just as happily if the sentence rendered
 * from the wrong locale tier.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { Wrapper } from '../../test/utils';
import { buildProvenancePtPT } from '../../i18n/buildProvenanceFallback';
import { BuildProvenanceRows } from './BuildProvenanceRows';
import { describeBuildCommit } from './buildProvenance';

afterEach(cleanup);

const HASH = '744f82f2c0161eab7b13f4b0d9a1e5c6a7b8c9d0';
const COMMITTED_AT = '2026-07-27T18:03:11+01:00';
const COMMIT = describeBuildCommit({ hash: HASH, committedAt: COMMITTED_AT });

/** `<tr>` is only valid inside a table, and jsdom warns loudly (rightly) if it is not. */
function renderRows(commit: Parameters<typeof BuildProvenanceRows>[0]['commit']) {
  return render(
    <Wrapper>
      <table>
        <tbody>
          <BuildProvenanceRows commit={commit} />
        </tbody>
      </table>
    </Wrapper>,
  );
}

/** The `<td>` of the row whose header cell reads `label`. */
function valueCell(label: string): HTMLElement {
  const row = screen.getByRole('rowheader', { name: label }).closest('tr') as HTMLElement;
  return within(row).getByRole('cell');
}

describe('BuildProvenanceRows with a commit', () => {
  it('shows the short hash and keeps the full one on screen beside it', () => {
    renderRows(COMMIT);
    const cell = valueCell(buildProvenancePtPT['settings.about.build.commit']);
    expect(within(cell).getByText(HASH.slice(0, 12))).toBeTruthy();
    // The unambiguous form is present as real, selectable text — not a title attribute an
    // operator cannot copy out of.
    expect(within(cell).getByText(HASH)).toBeTruthy();
  });

  it('renders both hash forms monospaced, as identifiers rather than prose', () => {
    renderRows(COMMIT);
    const cell = valueCell(buildProvenancePtPT['settings.about.build.commit']);
    expect(within(cell).getByText(HASH.slice(0, 12)).className).toContain('mono');
    expect(within(cell).getByText(HASH).className).toContain('mono');
  });

  it('shows the committer date verbatim, offset included', () => {
    renderRows(COMMIT);
    const cell = valueCell(buildProvenancePtPT['settings.about.build.committedAt']);
    expect(cell.textContent).toBe(COMMITTED_AT);
  });

  it('shows the derived codename with the note saying it is an internal reference', () => {
    renderRows(COMMIT);
    const cell = valueCell(buildProvenancePtPT['settings.about.build.codename']);
    expect(within(cell).getByText(COMMIT?.codename ?? '')).toBeTruthy();
    // The note is the whole reason a codename is safe to show; it must travel with it.
    expect(
      within(cell).getByText(buildProvenancePtPT['settings.about.build.codenameNote']),
    ).toBeTruthy();
  });

  it('does not show the provenance-unavailable row', () => {
    renderRows(COMMIT);
    expect(screen.queryByText(buildProvenancePtPT['settings.about.build.unavailable'])).toBeNull();
  });
});

describe('BuildProvenanceRows without a commit', () => {
  it('says in words that the build records no commit', () => {
    // The absent-git path: Docker (`.dockerignore` drops `.git`), a source tarball, no git on PATH.
    renderRows(null);
    const cell = valueCell(buildProvenancePtPT['settings.about.build.provenance']);
    expect(cell.textContent).toBe(buildProvenancePtPT['settings.about.build.unavailable']);
  });

  it('leaves no empty row and no dash that would read as data', () => {
    renderRows(null);
    expect(screen.getAllByRole('row')).toHaveLength(1);
    expect(screen.queryByText('—')).toBeNull();
    expect(screen.getByRole('cell').textContent?.trim()).not.toBe('');
  });

  it('shows no hash, no date and no codename rows at all', () => {
    renderRows(null);
    expect(
      screen.queryByRole('rowheader', { name: buildProvenancePtPT['settings.about.build.commit'] }),
    ).toBeNull();
    expect(
      screen.queryByRole('rowheader', {
        name: buildProvenancePtPT['settings.about.build.committedAt'],
      }),
    ).toBeNull();
    expect(
      screen.queryByRole('rowheader', {
        name: buildProvenancePtPT['settings.about.build.codename'],
      }),
    ).toBeNull();
  });
});
