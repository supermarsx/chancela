/**
 * CLASS GUARD: internal identifiers rendered where operator copy belongs (t87).
 *
 * The user reported the same defect twice in two minutes — `no_external_validator_report_metadata_attached`
 * under «Estado», then `data_dir` under «Armazenamento». Both were one surface rendering a raw
 * server token as its whole visible value. Fixing the two sightings would have left the rest of the
 * class for the user to find a third time, so this enumerates the class and pins it.
 *
 * ─── WHY THE TYPE CHECKER, NOT A TEXT SEARCH ───────────────────────────────────────────────────
 *
 * The rendered value is runtime data. `{data.persistence.sidecar_storage_mode}` contains no
 * snake_case text anywhere in the source — the token only exists in the field's TYPE. A grep over
 * `.tsx` cannot see it, and the sibling AST guards (`ui/noticeDismissGuards.test.ts`,
 * `ui/bannerMarginGuards.test.ts`) parse without a checker, which is enough for their containment
 * questions but blind to this one. So this builds a real program and asks the checker for the type
 * of every JSX text child, flagging those whose type is (or includes) a snake_case string literal.
 *
 * That costs ~14s. It is the only way to see the class, and it is the same order as the other
 * suites in this package.
 *
 * ─── ENUMERATE, THEN CLASSIFY ──────────────────────────────────────────────────────────────────
 *
 * A recogniser used as a filter silently drops whatever it cannot parse, so this does not try to
 * decide which sites are wrong. It enumerates ALL of them and asserts the population equals
 * {@link EXPECTED} exactly. A new site is RED whether it is a defect or not — it forces a
 * classification rather than letting one appear unnoticed.
 *
 * `mono` is the second half of the rule and the part with teeth. An identifier that is deliberately
 * NOT translated must still be *presented* as an identifier — monospace, verbatim — never folded
 * into prose. Recording it here means that taking a no-claims flag out of its `mono` cell and
 * dropping it into a sentence goes red, which is precisely the mistake a sibling lane made today.
 *
 * ─── THE NO-CLAIMS FAMILY ──────────────────────────────────────────────────────────────────────
 *
 * Two entries below are `no-claims`: identifiers naming legal claims the product explicitly does
 * NOT make. Translating them would assert the claim. They stay verbatim in `mono` forever, and
 * `unresolved: false` records that they are correct as they are, not pending work.
 *
 * ─── KNOWN LIMIT ───────────────────────────────────────────────────────────────────────────────
 *
 * Only MULTI-WORD snake_case is detected. Single-word identifier unions — `DataDurableBackendFamily`
 * is `'sqlite' | 'postgres'`, `DataSidecarStorageMode` is `'file' | 'database' | 'in_memory'` — are
 * invisible except for the member that happens to carry an underscore. Widening the pattern to any
 * lowercase literal would flag every `'ok'`/`'warn'` tone union in the app, which is the noisy-guard
 * failure mode. The limit is recorded rather than papered over.
 *
 * `active_backend_family` was the worked example: it rendered raw in the SAME CARD as
 * `sidecar_storage_mode`, and this guard could see only the cardmate. t98 fixed both together
 * through `dataRecoveryStatusFallback.ts`, whose own divergence test derives that population from
 * the `DurableBackendFamily` enum in Rust — which is where a single-word union can be checked
 * without guessing at render sites. The general limit stands: this scan will not enumerate the next
 * one, so a single-word union has to be noticed by whoever touches its card.
 */
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

/** Building a checked program over the whole app costs ~14s; the default 5s timeout is not enough.
 *  Only the first test pays it — {@link scan} memoises. */
const SCAN_TIMEOUT = 180_000;

/** Multi-word snake_case. See KNOWN LIMIT above for what this deliberately cannot see. */
const SNAKE = /^[a-z][a-z0-9]*(_[a-z0-9]+)+$/u;

type Classification = 'no-claims' | 'operational';

interface ExpectedSite {
  /** `<path under src/>::<expression text>`. Never a line number — those drift on a shared tree. */
  site: string;
  /** Rendered inside an element whose className contains `mono`. */
  mono: boolean;
  classification: Classification;
  /** True where the token still needs operator copy (mapped for a second pass). */
  unresolved: boolean;
}

/**
 * Every site in the app that renders a snake_case token as visible text.
 *
 * `features/tools/ExternalValidatorReportsPanel.tsx` is deliberately ABSENT: its three token fields
 * were the original report and now resolve through `externalValidatorStatusFallback.ts`, so the
 * token reaches JSX as a component prop rather than a text child. That absence is what a fixed
 * site looks like.
 *
 * The fourteen sites t98 resolved are absent for the same reason — through
 * `paperBookPreservationFallback.ts`, `dataRecoveryStatusFallback.ts` and
 * `retentionExecutionStatusFallback.ts`, each reaching JSX as a `token: string` prop. Note that a
 * resolved site does NOT stop rendering its identifier: it still shows it in `mono` beside the copy.
 * What changes is that the identifier is no longer the whole visible value, and the widened prop
 * type is what takes it out of this scan.
 *
 * So the population shrinking is the expected direction of travel, and it must shrink only via a
 * label module. A site that vanishes because someone deleted the render, or widened a type without
 * adding copy, looks identical here — which is why each of those three modules carries its own
 * both-direction gate against the Rust emitter. This scan says WHICH tokens reach the screen raw;
 * those tests say whether every token that can reach the screen has a sentence.
 */
const EXPECTED: readonly ExpectedSite[] = [
  // --- Correct as they stand: identifier presented as an identifier -----------------------------
  {
    // Paper-book OCR rehearsal `no_claims` flags, incl. `legal_compliance_claimed`.
    site: 'features/books/BookDetailPage.tsx::flag',
    mono: true,
    classification: 'no-claims',
    unresolved: false,
  },
  {
    // The 28 DPIA `no_claims` flag identifiers, the documented case (`dpiaTemplateLabels.ts`).
    site: 'features/settings/PrivacyComplianceSection.tsx::key',
    mono: true,
    classification: 'no-claims',
    unresolved: false,
  },
  {
    site: 'features/recovery/BookIntegritySection.tsx::report.policy',
    mono: true,
    classification: 'operational',
    unresolved: false,
  },
  {
    site: 'features/settings/PrivacyComplianceSection.tsx::item.field_type',
    mono: true,
    classification: 'operational',
    unresolved: false,
  },
  {
    site: 'features/settings/SettingsPage.tsx::logs.data.retention.source',
    mono: true,
    classification: 'operational',
    unresolved: false,
  },

  // --- Nothing is pending -----------------------------------------------------------------------
  // This list once carried 14 entries with `unresolved: true`, mapped for a second pass. t98 closed
  // all of them across three commits — paper-book import, data recovery, retention execution — each
  // with its own label module and its own divergence guard against Rust. Every remaining entry above
  // is correct as it stands.
  //
  // A NEW entry here should be `unresolved: true` only long enough to be classified. If it is
  // operational, it wants a label module and a Rust-derived divergence guard, and then it leaves
  // this list entirely, because the resolved shape passes the token as a prop. If it names a legal
  // claim the product does not make, it stays, in `mono`, with `unresolved: false` — forever.
];

interface FoundSite {
  site: string;
  mono: boolean;
}

let cached: FoundSite[] | null = null;

/** Build the program once; every test below reuses it. */
function scan(): FoundSite[] {
  if (cached) return cached;

  const cfg = ts.readConfigFile('tsconfig.app.json', ts.sys.readFile);
  expect(cfg.error, 'tsconfig.app.json did not parse').toBeUndefined();
  const parsed = ts.parseJsonConfigFileContent(cfg.config, ts.sys, '.');
  const program = ts.createProgram(parsed.fileNames, parsed.options);
  const checker = program.getTypeChecker();

  const found = new Map<string, boolean>();

  for (const sf of program.getSourceFiles()) {
    if (sf.isDeclarationFile) continue;
    if (!sf.fileName.includes('/src/')) continue;
    if (/\.test\.tsx?$/u.test(sf.fileName)) continue;

    const relative = sf.fileName.slice(sf.fileName.indexOf('/src/') + '/src/'.length);

    const visit = (node: ts.Node): void => {
      // A JSX expression whose parent is an element or fragment is rendered as visible text; one in
      // an attribute position is a prop, which is how a resolved site looks.
      if (
        ts.isJsxExpression(node) &&
        node.expression &&
        node.parent &&
        (ts.isJsxElement(node.parent) || ts.isJsxFragment(node.parent))
      ) {
        const type = checker.getTypeAtLocation(node.expression);
        const parts = type.isUnion() ? type.types : [type];
        const tokens = parts
          .filter((t): t is ts.StringLiteralType => Boolean(t.isStringLiteral?.()))
          .map((t) => t.value)
          .filter((v) => SNAKE.test(v));

        if (tokens.length > 0) {
          const site = `${relative}::${node.expression.getText()}`;
          found.set(site, found.get(site) === true || monoAncestor(node));
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }

  cached = [...found.entries()]
    .map(([site, mono]) => ({ site, mono }))
    .sort((a, b) => a.site.localeCompare(b.site));
  return cached;
}

/** Does any enclosing JSX element carry a className containing `mono`? */
function monoAncestor(node: ts.Node): boolean {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isJsxElement(current)) {
      for (const attr of current.openingElement.attributes.properties) {
        if (
          ts.isJsxAttribute(attr) &&
          attr.name.getText() === 'className' &&
          attr.initializer &&
          /mono/u.test(attr.initializer.getText())
        ) {
          return true;
        }
      }
    }
    current = current.parent;
  }
  return false;
}

describe('the raw-identifier scan actually sees the codebase', () => {
  it(
    'resolves types and finds a plausible population',
    () => {
      const found = scan().map((f) => f.site);
      // Non-vacuity: a program that failed to resolve, or a walk that matched nothing, would make the
      // set comparison below pass against an empty population.
      //
      // This used to be a floor of `> 10`, which held while 14 sites were awaiting copy. t98 resolved
      // all 14 and the population is now 5, so a size floor no longer distinguishes "the scan worked
      // and most sites are fixed" from "the scan resolved nothing" — and it will keep shrinking. Named
      // ANCHORS do the job at any size: both are `no_claims` families that must stay raw forever, so
      // neither can legitimately leave this list, and a checker that failed to resolve types would
      // find neither.
      expect(
        found,
        'the DPIA no-claims flags are not being seen — did the program resolve?',
      ).toContain('features/settings/PrivacyComplianceSection.tsx::key');
      expect(
        found,
        'the paper-book OCR no-claims flags are not being seen — did the program resolve?',
      ).toContain('features/books/BookDetailPage.tsx::flag');
      expect(found.length).toBeGreaterThanOrEqual(2);
    },
    SCAN_TIMEOUT,
  );

  it(
    'does not flag a site that resolves its token through a label module',
    () => {
      // The panel this lane fixed renders `token={…}` as a prop, so it must NOT appear.
      const files = scan().map((f) => f.site);
      expect(
        files.filter((s) => s.startsWith('features/tools/ExternalValidatorReportsPanel')),
      ).toEqual([]);
    },
    SCAN_TIMEOUT,
  );
});

describe('every raw-identifier render site is classified', () => {
  it(
    'matches the expected population exactly, in both directions',
    () => {
      const found = scan().map((f) => f.site);
      const expected = EXPECTED.map((e) => e.site).sort((a, b) => a.localeCompare(b));
      expect(found).toEqual(expected);
    },
    SCAN_TIMEOUT,
  );

  it(
    'presents every deliberately-untranslated identifier as an identifier',
    () => {
      const byName = new Map(scan().map((f) => [f.site, f.mono]));
      for (const entry of EXPECTED) {
        // A site recorded as correct-as-is must really be in a `mono` context: an identifier kept
        // verbatim because translating it would assert a claim must never be folded into prose.
        expect(byName.get(entry.site), `${entry.site} mono context`).toBe(entry.mono);
        if (!entry.unresolved) {
          expect(
            entry.mono,
            `${entry.site} is recorded as done but is not an identifier context`,
          ).toBe(true);
        }
      }
    },
    SCAN_TIMEOUT,
  );

  it(
    'keeps every no-claims identifier verbatim and never marks one as pending copy',
    () => {
      for (const entry of EXPECTED.filter((e) => e.classification === 'no-claims')) {
        expect(entry.mono, `${entry.site} must stay monospace`).toBe(true);
        expect(entry.unresolved, `${entry.site} must never be scheduled for translation`).toBe(
          false,
        );
      }
    },
    SCAN_TIMEOUT,
  );
});
