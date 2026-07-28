/**
 * DIVERGENCE GATE for `permissionDescriptionsFallback.ts` (t74).
 *
 * The descriptions live client-side while the authoritative verb catalog lives in Rust. That split
 * is only safe if drift is loud, so this file derives the truth from the Rust source itself rather
 * than from a hand-copied list:
 *
 *  - the catalog population, from `Permission`'s `#[serde(rename = "…")]` declarations in
 *    `crates/chancela-authz/src/permission.rs` (the same technique `permission.rs`'s own
 *    `all_holds_every_declared_variant_not_just_the_listed_ones` test uses);
 *  - the variant → dotted id mapping, from that file's `as_str()` match;
 *  - the set of verbs that gate nothing, from the `enforcement()` match in
 *    `crates/chancela-authz/src/permission_description.rs`.
 *
 * Set equality is asserted in BOTH directions: a verb added to Rust with no sentence here is red,
 * and a sentence here for a verb Rust no longer has is red.
 *
 * **These assertions are structural on purpose.** Nothing here matches Portuguese text. A test that
 * pins a substring of reviewed copy turns a correct translation fix red, so the copy is checked for
 * shape (non-empty, a real sentence, not a restatement of its own identifier) and never for wording.
 */
import { describe, expect, it } from 'vitest';

import {
  PERMISSIONS_THAT_GRANT_NOTHING,
  describePermission,
  permissionDescriptionsEnglish,
  permissionDescriptionsPtPT,
} from './permissionDescriptionsFallback';

async function readCrateSource(relative: string): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(`../../${relative}`, 'utf8');
}

/**
 * Everything above the `#[cfg(test)]` module, so fixtures and test-only lists never become
 * obligations.
 *
 * Split on the attribute at the START OF A LINE, not on the bare substring: both audited files
 * *mention* `#[cfg(test)]` inside a doc comment, and splitting on the substring truncated
 * `permission_description.rs` to 844 of its 25,324 characters — every arm silently vanished from
 * the search space. The length floor keeps that class of failure loud rather than vacuous.
 */
function productionSection(source: string): string {
  const section = source.split(/^#\[cfg\(test\)\]/mu)[0] as string;
  expect(section.length, 'the pre-test section is implausibly short — check the split').
    toBeGreaterThan(source.length / 2);
  return section;
}

/** The catalog's dotted ids, from the serde renames each variant carries exactly one of. */
async function catalogPermissionIds(): Promise<string[]> {
  const source = productionSection(await readCrateSource('crates/chancela-authz/src/permission.rs'));
  return [...source.matchAll(/#\[serde\(rename = "([^"]+)"\)\]/gu)].map((match) => match[1] as string);
}

/** `Permission::Variant => "dotted.id"` from `as_str()`, used to resolve enforcement arms. */
async function variantToId(): Promise<Map<string, string>> {
  const source = productionSection(await readCrateSource('crates/chancela-authz/src/permission.rs'));
  const pairs = [...source.matchAll(/Permission::(\w+) => "([^"]+)",/gu)];
  return new Map(pairs.map((match) => [match[1] as string, match[2] as string]));
}

/** The verbs the enforcement audit records as gating nothing. */
async function featureNotBuiltIds(): Promise<string[]> {
  const source = productionSection(
    await readCrateSource('crates/chancela-authz/src/permission_description.rs'),
  );
  const names = [...source.matchAll(/Permission::(\w+) => FeatureNotBuilt,/gu)].map(
    (match) => match[1] as string,
  );
  const map = await variantToId();
  return names.map((name) => {
    const id = map.get(name);
    expect(id, `${name} has no as_str() arm in permission.rs`).toBeDefined();
    return id as string;
  });
}

describe('the permission catalog is parsed, not assumed', () => {
  it('finds a catalog of unique dotted ids', async () => {
    const ids = await catalogPermissionIds();
    // Non-vacuity: a parse that silently matched nothing would make every set comparison below
    // trivially pass against an empty catalog.
    expect(ids.length).toBeGreaterThan(40);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$/u);
  });

  it('resolves every catalog id through the as_str() match', async () => {
    const ids = await catalogPermissionIds();
    const mapped = new Set((await variantToId()).values());
    expect([...ids].filter((id) => !mapped.has(id)).sort()).toEqual([]);
  });
});

describe('descriptions do not diverge from the Rust catalog', () => {
  it('describes every catalog verb, and describes nothing else', async () => {
    const catalog = (await catalogPermissionIds()).sort();
    const described = Object.keys(permissionDescriptionsPtPT).sort();

    const undescribed = catalog.filter((id) => !described.includes(id));
    const orphaned = described.filter((id) => !catalog.includes(id));

    expect(
      undescribed,
      'these verbs are in the Rust catalog but have no description: an administrator would see a ' +
        'bare identifier with nothing explaining what ticking it grants. Add a sentence to ' +
        'permissionDescriptionsFallback.ts, written from the verb\'s real handler evidence.',
    ).toEqual([]);
    expect(
      orphaned,
      'these descriptions name verbs the Rust catalog no longer has: remove them, or restore the ' +
        'verb. A description for a verb nobody can hold is copy nobody can act on.',
    ).toEqual([]);
    expect(described).toEqual(catalog);
  });

  it('keeps the English tier on exactly the same key set as the pt-PT source', () => {
    expect(Object.keys(permissionDescriptionsEnglish).sort()).toEqual(
      Object.keys(permissionDescriptionsPtPT).sort(),
    );
  });

  it('states that a verb grants nothing exactly when the enforcement audit says so', async () => {
    const audited = (await featureNotBuiltIds()).sort();
    // Non-vacuity: the audit currently records two phantoms; an empty parse must not pass.
    expect(audited.length).toBeGreaterThan(0);
    expect(
      [...PERMISSIONS_THAT_GRANT_NOTHING].sort(),
      'the set of verbs that gate nothing changed in Rust. A verb that became enforced still ' +
        'carries a sentence saying it grants nothing — a false statement about a live, gated ' +
        'route. Rewrite that sentence and move the id.',
    ).toEqual(audited);
  });
});

describe('description copy has a usable shape', () => {
  const entries = [
    ...Object.entries(permissionDescriptionsPtPT),
    ...Object.entries(permissionDescriptionsEnglish),
  ];

  it('renders no blank space for any described verb', () => {
    for (const [id, text] of entries) {
      expect(text.trim(), id).not.toBe('');
      expect(text, id).toBe(text.trim());
    }
  });

  it('writes complete sentences rather than fragments', () => {
    for (const [id, text] of entries) {
      expect(text, id).toMatch(/[.!?]$/u);
      expect(text.length, id).toBeGreaterThan(30);
    }
  });

  it('never merely restates the identifier it describes', () => {
    for (const [id, text] of entries) {
      expect(text.toLowerCase(), id).not.toContain(id.toLowerCase());
    }
  });

  it('interpolates nothing, so no noun can break agreement at runtime', () => {
    for (const [id, text] of entries) {
      expect(text, id).not.toMatch(/\{[^}]*\}/u);
    }
  });
});

describe('an undescribed verb never renders as empty space', () => {
  it('resolves an unknown verb to an explicit notice, not a blank string', () => {
    const resolved = describePermission('something.invented');
    expect(resolved.known).toBe(false);
    expect(resolved.text.trim().length).toBeGreaterThan(0);
  });

  it('reports a described verb as known', async () => {
    const [first] = await catalogPermissionIds();
    const resolved = describePermission(first as string);
    expect(resolved.known).toBe(true);
    expect(resolved.text.trim().length).toBeGreaterThan(0);
  });
});
