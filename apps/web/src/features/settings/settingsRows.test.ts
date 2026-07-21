/**
 * The settings-row layout gate (t69).
 *
 * NOTE THE FILE NAME: this is settingsRows, and the class is `.settings-rows`. An earlier draft
 * called it `.settings-grid` — which already exists in `theme.css` and tiles whole CARDS into
 * 22rem columns. Anything opted into that name instead of this one gets card tiling and looks
 * broken. The rule's own comment block in `theme.css` carries the same warning.
 *
 * `.settings-rows` is THE shared layout rule for configuration forms: a settings form opts in by
 * adding it beside `form` on a container it already has, and every `Field` inside becomes an
 * aligned label-column / control-column row. It is defined once, in `theme.css`.
 *
 * This gate exists because the failure mode is silent and ugly: the next agent adds a settings
 * tab, writes `className="form"` like every example around it, and ships one tab that does not
 * line up with the others. A half-converted settings area reads as a bug rather than as a style,
 * so "did you opt in" is asserted rather than left to review.
 *
 * It deliberately does NOT assert that the rule is a `<table>`. These are form controls; aligned
 * CSS columns give the neatness without misreporting them to a screen reader as tabular data.
 * Genuinely tabular settings content (TSL sources, TSA providers, API keys) uses the `Table`
 * primitive with its visually-hidden caption instead.
 *
 * ## What this gate can and cannot see
 *
 * It asserts **adoption and non-duplication**, both visible in the TSX. It does **not** assert the
 * contents of `theme.css`, and that is a limitation rather than a choice: Vite owns `.css`, so both
 * `import THEME from '…/theme.css?raw'` and the `import.meta.glob` equivalent resolve to an **empty
 * string** under vitest — which would make every CSS assertion pass vacuously, the worst possible
 * outcome for a gate. Reading the file with `node:fs` works at runtime but does not type-check:
 * this package ships no `@types/node`. So the stylesheet's own invariants — the token, the
 * `subgrid` sizing, the narrow-width collapse — are documented in the rule's comment block instead,
 * and only the parts that live in components are enforced here.
 */
import { describe, expect, it } from 'vitest';

const SOURCES = import.meta.glob('../**/*.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>;

/**
 * Every source file that renders inside a Configurações tab. Files in this folder are keyed
 * `./Name.tsx` by the glob; the others are sections mounted by `SettingsPage` from their own
 * feature folders.
 *
 * `NewUserPage` is the one that is not a tab: user creation lives on its own route
 * (`/utilizadores/novo`). It is listed anyway because it is still the create form *for* the
 * Utilizadores tab, and a creation screen that does not match the tab it belongs to is exactly
 * the inconsistency this gate exists to prevent.
 */
function isSettingsSurface(path: string): boolean {
  return (
    path.startsWith('./') ||
    path.endsWith('/pairing/PairingPanel.tsx') ||
    path.endsWith('/rbac/FuncoesSection.tsx') ||
    path.endsWith('/rbac/DelegacoesSection.tsx') ||
    path.endsWith('/recovery/GestaoDadosSection.tsx') ||
    path.endsWith('/recovery/LivrosIntegridadeSection.tsx') ||
    path.endsWith('/users/NewUserPage.tsx')
  );
}

/**
 * The one reviewed exception. The platform log tail's `.form` is a filter toolbar, not a list of
 * settings rows: its `Field`s sit inside `.platform-log-controls` rather than as direct children,
 * so the row grid would not reach them anyway and the hairline banding would be noise.
 */
const REVIEWED_PLAIN_FORMS = new Map([['SettingsPage.tsx', 1]]);

function basename(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

function settingsSources(): [string, string][] {
  return Object.entries(SOURCES).filter(([path]) => isSettingsSurface(path));
}

describe('settings row grid', () => {
  it('has every configuration form opted in, so no tab is left un-aligned', () => {
    const offenders: string[] = [];
    for (const [path, source] of settingsSources()) {
      const plain = source.match(/className="form"/gu)?.length ?? 0;
      const allowed = REVIEWED_PLAIN_FORMS.get(basename(path)) ?? 0;
      if (plain > allowed) {
        offenders.push(
          `${basename(path)}: ${plain} plain className="form" (allowed ${allowed}) — ` +
            'add settings-rows beside it, or document the exception in REVIEWED_PLAIN_FORMS',
        );
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  it('applies the rule across the configuration surface, not in one tab only', () => {
    // Guards against the sweep being quietly reverted to a single file: a shared rule is only
    // worth having if it is what every tab uses. A floor, not a fixed number, so adding a tab
    // does not break it.
    const adopters = settingsSources().filter(([, source]) =>
      source.includes('form settings-rows'),
    );
    expect(adopters.length).toBeGreaterThanOrEqual(8);
  });

  it('keeps the layout in the stylesheet — no tab re-implements it inline', () => {
    // The whole point is one place to change. An inline `style={{ gridTemplateColumns … }}` or a
    // per-tab label-column class would fork the layout silently: it would look right on the tab
    // that added it and drift from every other tab at the next adjustment.
    const offenders: string[] = [];
    for (const [path, source] of settingsSources()) {
      if (/style=\{\{[^}]*grid(?:Template)?(?:Columns)?\s*:/u.test(source)) {
        offenders.push(`${basename(path)}: inline grid style — use the settings-rows rule`);
      }
      if (/--[\w-]*label-col/u.test(source)) {
        offenders.push(`${basename(path)}: defines its own label-column token`);
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});
