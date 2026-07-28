/**
 * The build-provenance rows of Settings → «Sobre» (t100): which commit this bundle was built from,
 * when that commit was made, and the codename derived from it.
 *
 * A separate component for one reason: the absent-git case is the path most likely to be wrong and
 * least likely to be exercised, and it is only reachable here by passing `commit={null}`. Inside
 * `SettingsPage.tsx` it would depend on a build-time global, which a test cannot vary. Both states
 * are rendered directly by `BuildProvenanceRows.test.tsx`.
 *
 * This is the ONLY surface that shows these values. They are not in the shell footer, not in crash
 * diagnostics, not in the version-skew banner and not on any API payload — build provenance is an
 * internal reference an operator quotes from the Sobre screen, not a fact the product asserts
 * anywhere else.
 */
import type { BuildProvenance } from './buildProvenance';
import { useBuildProvenanceT } from '../../i18n/buildProvenanceFallback';

export function BuildProvenanceRows({ commit }: { commit: BuildProvenance | null }) {
  const bt = useBuildProvenanceT();

  // No repository behind the build (Docker, a source tarball, a machine without git). One labelled
  // row that says so in words — never an em dash, which on a table of facts reads as data.
  if (commit === null) {
    return (
      <tr>
        <th scope="row">{bt('settings.about.build.provenance')}</th>
        <td>{bt('settings.about.build.unavailable')}</td>
      </tr>
    );
  }

  return (
    <>
      {/* Both forms, both selectable: the short hash is what anyone reads aloud, the full one is
          what an operator pastes into a support thread when the short form could be ambiguous.
          Monospace and verbatim in every locale — this is an identifier, not copy. */}
      <tr>
        <th scope="row">{bt('settings.about.build.commit')}</th>
        <td>
          <div className="mono">{commit.shortHash}</div>
          <div className="mono muted">{commit.hash}</div>
        </td>
      </tr>
      {/* The committer date exactly as git emitted it: ISO 8601 with an explicit offset. Rendered
          raw rather than localised, because the point of this row is that two people comparing two
          builds read the same characters. */}
      <tr>
        <th scope="row">{bt('settings.about.build.committedAt')}</th>
        <td className="mono">{commit.committedAt}</td>
      </tr>
      {/* The codename never stands alone: the note beneath it says what it is, so it cannot be
          mistaken for a product name or a release designation. */}
      <tr>
        <th scope="row">{bt('settings.about.build.codename')}</th>
        <td>
          <div>{commit.codename}</div>
          <div className="muted">{bt('settings.about.build.codenameNote')}</div>
        </td>
      </tr>
    </>
  );
}
