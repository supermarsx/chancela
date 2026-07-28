/**
 * DIVERGENCE GATE for `platformServiceFallback.ts` (t92).
 *
 * The operator-facing copy lives client-side while the authoritative English lives in Rust. That
 * split is only safe if drift is loud, so this file derives the truth from the emitting source
 * itself rather than from a hand-copied list. Four sites in
 * `crates/chancela-api/src/platform_ops.rs`, plus the two id constants in `settings.rs`:
 *
 *  - `api_action_capabilities()`  — three `(action, limitation)` pairs for the API process;
 *  - `mcp_action_capabilities()`  — one limitation fanned across three actions for the MCP process;
 *  - `outcome_message()`          — six `(service, action)` match arms plus the `_` fallback arm;
 *  - `limitations_for()`          — the standing caveats, grouped by service.
 *
 * Equality is asserted in BOTH directions per population, and on the **string values** as well as
 * the keys: a state the emitter gains with no entry here is red, an entry for a state the emitter
 * can no longer produce is red, and — because {@link platformServiceEnglish} is pinned to be the
 * Rust literal verbatim — so is a reworded sentence in Rust. The last one matters most: rewording
 * is the change most likely to happen without anyone thinking about translation, and it is what
 * silently breaks the text-matched `limitations[]` population.
 *
 * The service ids and the action tokens are parsed too, not assumed. `PlatformServiceAction`
 * reaches the wire through `#[serde(rename_all = "lowercase")]`; if that attribute is ever changed
 * the keys in the fallback module stop matching what the client receives, and nothing else in the
 * suite would notice.
 *
 * **These assertions are structural on purpose.** Nothing here matches Portuguese text. A test that
 * pins a substring of reviewed copy turns a correct translation fix red — and a singular/plural
 * slip makes it pass for the wrong reason — so the pt-PT tier is checked for shape (non-empty, a
 * real sentence, no interpolation slot, actually different from the English) and never for wording.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  SERVICE_LIMITATION_OWNER,
  type PlatformServiceCopy,
  type PlatformServiceLimitationCode,
  platformServiceEnglish,
  platformServicePtPT,
  resolveCapabilityLimitation,
  resolveControlMessage,
  resolveServiceLimitation,
} from './platformServiceFallback';

const EMITTER = 'crates/chancela-api/src/platform_ops.rs';
const SETTINGS = 'crates/chancela-api/src/settings.rs';

async function readCrateSource(relative: string): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(`../../${relative}`, 'utf8');
}

/**
 * Everything above the `#[cfg(test)]` module, so fixtures never become obligations. The emitter has
 * no test module today; this is prophylactic, and the length floor keeps it from silently
 * truncating the search space if one is added (memory: `grep-the-symbol-not-the-line`).
 */
function productionSection(source: string): string {
  const section = source.split(/^#\[cfg\(test\)\]/mu)[0] as string;
  expect(
    section.length,
    'the pre-test section is implausibly short — check the split',
  ).toBeGreaterThan(source.length / 2);
  return section;
}

/** Body of the first fn whose header matches, by brace matching rather than a line count. */
function fnBody(source: string, header: RegExp): string {
  const match = header.exec(source);
  expect(match, `no fn matching ${String(header)} in ${EMITTER}`).not.toBeNull();
  const open = source.indexOf('{', (match as RegExpExecArray).index);
  expect(open, 'matched fn header has no opening brace').toBeGreaterThan(-1);
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, i);
    }
  }
  throw new Error(`unbalanced braces after ${String(header)} in ${EMITTER}`);
}

const STRING_LITERAL = /"((?:[^"\\]|\\.)*)"/gu;

/** Every string literal in a fragment, in source order. */
function stringLiterals(fragment: string): string[] {
  return [...fragment.matchAll(STRING_LITERAL)].map((m) => m[1] as string);
}

const sorted = (values: readonly string[]): string[] => [...values].sort();

// ═══ WHAT RUST ACTUALLY EMITS ══════════════════════════════════════════════════════════════════

/** The two controllable service ids, read from their `const` definitions rather than assumed. */
async function serviceIds(): Promise<{ api: string; mcp: string }> {
  const source = await readCrateSource(SETTINGS);
  const read = (name: string): string => {
    const match = new RegExp(`pub const ${name}: &str = "([a-z0-9_]+)";`, 'u').exec(source);
    expect(match, `${name} is no longer a plain &str const in ${SETTINGS}`).not.toBeNull();
    return (match as RegExpExecArray)[1] as string;
  };
  return {
    api: read('PLATFORM_API_SERVICE_ID'),
    mcp: read('PLATFORM_MCP_STDIO_SERVICE_ID'),
  };
}

/** The action tokens as they reach the wire, including the serde rename that produces them. */
async function actionTokens(): Promise<string[]> {
  const source = await readCrateSource(SETTINGS);
  const block =
    /#\[serde\(rename_all = "(?<style>[a-z_]+)"\)\]\s*pub enum PlatformServiceAction \{(?<body>[^}]*)\}/u.exec(
      source,
    );
  expect(block, `PlatformServiceAction lost its serde rename in ${SETTINGS}`).not.toBeNull();
  const groups = (block as RegExpExecArray).groups as { style: string; body: string };
  // The fallback keys are built by lowercasing the variant; any other rename style would silently
  // change what the client receives and must be reflected here deliberately.
  expect(groups.style, 'PlatformServiceAction serde rename style changed').toBe('lowercase');
  const variants = [...groups.body.matchAll(/^\s*(\w+),/gmu)].map((m) =>
    (m[1] as string).toLowerCase(),
  );
  expect(variants.length, `parsed no PlatformServiceAction variants from ${SETTINGS}`).toBe(3);
  return variants;
}

/** `capabilityLimitation`: `${service}.${action}` → the English the endpoint sends. */
async function emittedCapabilityLimitations(): Promise<Record<string, string>> {
  const source = productionSection(await readCrateSource(EMITTER));
  const ids = await serviceIds();

  const apiBody = fnBody(
    source,
    /fn api_action_capabilities\(\) -> Vec<PlatformActionCapability>/u,
  );
  const apiPairs = [
    ...apiBody.matchAll(
      /action: PlatformServiceAction::(\w+),[\s\S]*?limitation:\s*"((?:[^"\\]|\\.)*)"/gu,
    ),
  ];
  expect(apiPairs.length, `api_action_capabilities parsed no (action, limitation) pairs`).toBe(3);

  const mcpBody = fnBody(
    source,
    /fn mcp_action_capabilities\(\) -> Vec<PlatformActionCapability>/u,
  );
  const mcpActions = [...mcpBody.matchAll(/PlatformServiceAction::(\w+)/gu)].map((m) =>
    (m[1] as string).toLowerCase(),
  );
  expect(mcpActions.length, 'mcp_action_capabilities parsed no actions').toBe(3);
  const mcpLimitations = [...new Set(stringLiterals(mcpBody))];
  // One shared sentence fanned across all three actions. If that ever becomes per-action, this
  // fails rather than quietly attributing the first literal to all three.
  expect(
    mcpLimitations.length,
    'mcp_action_capabilities no longer uses one shared limitation',
  ).toBe(1);

  const emitted: Record<string, string> = {};
  for (const pair of apiPairs) {
    emitted[`${ids.api}.${(pair[1] as string).toLowerCase()}`] = pair[2] as string;
  }
  for (const action of mcpActions) {
    emitted[`${ids.mcp}.${action}`] = mcpLimitations[0] as string;
  }
  return emitted;
}

/** `controlMessage`: `${service}.${action}` → English, plus `fallback` for the `_` arm. */
async function emittedControlMessages(): Promise<Record<string, string>> {
  const source = productionSection(await readCrateSource(EMITTER));
  const ids = await serviceIds();
  const body = fnBody(source, /fn outcome_message\(/u);

  const constToId: Record<string, string> = {
    PLATFORM_API_SERVICE_ID: ids.api,
    PLATFORM_MCP_STDIO_SERVICE_ID: ids.mcp,
  };

  const arms = [
    ...body.matchAll(
      /\(\s*(PLATFORM_\w+)\s*,\s*PlatformServiceAction::(\w+)\s*,\s*_\s*\)\s*=>\s*\{\s*"((?:[^"\\]|\\.)*)"\s*\}/gu,
    ),
  ];
  expect(arms.length, 'outcome_message parsed no (service, action) arms').toBe(6);

  const emitted: Record<string, string> = {};
  for (const arm of arms) {
    const id = constToId[arm[1] as string];
    expect(
      id,
      `outcome_message matches on an unknown service const ${String(arm[1])}`,
    ).toBeDefined();
    emitted[`${String(id)}.${(arm[2] as string).toLowerCase()}`] = arm[3] as string;
  }

  const wildcard = /^\s*_ => "((?:[^"\\]|\\.)*)",/mu.exec(body);
  expect(wildcard, 'outcome_message lost its `_` fallback arm').not.toBeNull();
  emitted.fallback = (wildcard as RegExpExecArray)[1] as string;
  return emitted;
}

/** `serviceLimitation`, grouped by the service whose match arm produces it. */
async function emittedServiceLimitations(): Promise<Record<string, string[]>> {
  const source = productionSection(await readCrateSource(EMITTER));
  const ids = await serviceIds();
  const body = fnBody(source, /fn limitations_for\(/u);

  const apiStart = body.indexOf('PLATFORM_API_SERVICE_ID =>');
  const mcpStart = body.indexOf('PLATFORM_MCP_STDIO_SERVICE_ID =>');
  expect(apiStart, `limitations_for has no ${ids.api} arm`).toBeGreaterThan(-1);
  expect(mcpStart, `limitations_for has no ${ids.mcp} arm`).toBeGreaterThan(apiStart);

  const emitted: Record<string, string[]> = {
    [ids.api]: stringLiterals(body.slice(apiStart, mcpStart)),
    [ids.mcp]: stringLiterals(body.slice(mcpStart)),
  };
  // Non-vacuity: an arm that parsed nothing would make the set comparison trivially pass.
  expect(emitted[ids.api]?.length, `limitations_for parsed no ${ids.api} caveats`).toBe(2);
  expect(emitted[ids.mcp]?.length, `limitations_for parsed no ${ids.mcp} caveats`).toBe(3);
  return emitted;
}

/** The English tier regrouped the way `limitations_for` groups it. */
function englishLimitationsByService(): Record<string, string[]> {
  const grouped: Record<string, string[]> = {};
  for (const [code, owner] of Object.entries(SERVICE_LIMITATION_OWNER)) {
    const english = platformServiceEnglish.serviceLimitation[code as PlatformServiceLimitationCode];
    (grouped[owner] ??= []).push(english);
  }
  return grouped;
}

// ═══ THE GATE ══════════════════════════════════════════════════════════════════════════════════

describe('the emitted copy is parsed from Rust, not assumed', () => {
  it('reads both controllable service ids from their consts', async () => {
    const ids = await serviceIds();
    expect(ids.api).toBe('api');
    expect(ids.mcp).toBe('mcp_stdio');
  });

  it('reads the three action tokens through the serde rename that produces them', async () => {
    expect(sorted(await actionTokens())).toEqual(['restart', 'start', 'stop']);
  });

  it('parses a distinct, non-empty population from each of the four sites', async () => {
    const capabilities = await emittedCapabilityLimitations();
    const messages = await emittedControlMessages();
    const limitations = await emittedServiceLimitations();
    expect(Object.keys(capabilities).length, 'capability population').toBe(6);
    expect(Object.keys(messages).length, 'control message population').toBe(7);
    expect(Object.values(limitations).flat().length, 'service limitation population').toBe(5);
    for (const value of [
      ...Object.values(capabilities),
      ...Object.values(messages),
      ...Object.values(limitations).flat(),
    ]) {
      expect(value.trim(), 'parsed an empty string literal out of the emitter').not.toBe('');
    }
  });
});

describe('every emitted string has copy, and every copy entry is emitted', () => {
  it('matches the action capabilities in both directions, keys and text', async () => {
    expect(platformServiceEnglish.capabilityLimitation).toEqual(
      await emittedCapabilityLimitations(),
    );
  });

  it('matches the control messages in both directions, keys and text', async () => {
    expect(platformServiceEnglish.controlMessage).toEqual(await emittedControlMessages());
  });

  it('matches the service limitations in both directions, per service', async () => {
    const emitted = await emittedServiceLimitations();
    const ours = englishLimitationsByService();
    expect(sorted(Object.keys(ours))).toEqual(sorted(Object.keys(emitted)));
    for (const service of Object.keys(emitted)) {
      expect(sorted(ours[service] ?? []), `${service} caveats`).toEqual(
        sorted(emitted[service] as string[]),
      );
    }
  });

  it('keeps the pt-PT tier on exactly the English key set', () => {
    const groups: (keyof PlatformServiceCopy)[] = [
      'capabilityLimitation',
      'controlMessage',
      'serviceLimitation',
    ];
    for (const group of groups) {
      expect(sorted(Object.keys(platformServicePtPT[group])), group).toEqual(
        sorted(Object.keys(platformServiceEnglish[group])),
      );
    }
  });
});

describe('the pt-PT copy has the right shape, whatever its wording', () => {
  const groups: (keyof PlatformServiceCopy)[] = [
    'capabilityLimitation',
    'controlMessage',
    'serviceLimitation',
  ];

  it('is a real sentence in both tiers', () => {
    for (const group of groups) {
      for (const [key, pt] of Object.entries(platformServicePtPT[group])) {
        const en = (platformServiceEnglish[group] as Record<string, string>)[key] as string;
        for (const text of [pt as string, en]) {
          expect(text.trim().length, `${group}/${key}`).toBeGreaterThan(40);
          expect(text.trim().endsWith('.'), `${group}/${key} is not a complete sentence`).toBe(
            true,
          );
        }
      }
    }
  });

  it('is actually translated, not the English copied across', () => {
    for (const group of groups) {
      for (const [key, pt] of Object.entries(platformServicePtPT[group])) {
        const en = (platformServiceEnglish[group] as Record<string, string>)[key] as string;
        expect(pt as string, `${group}/${key} was never translated`).not.toBe(en);
      }
    }
  });

  it('never interpolates a noun and never restates its own key', () => {
    for (const group of groups) {
      for (const [key, pt] of Object.entries(platformServicePtPT[group])) {
        // A noun dropped into an inflected sentence breaks agreement, so no entry carries a slot
        // (memory: `i18n-interpolated-nouns-break-agreement`).
        expect(pt as string, `${group}/${key} carries an interpolation slot`).not.toMatch(
          /\{[a-z]/iu,
        );
        expect((pt as string).toLowerCase(), `${group}/${key} restates its key`).not.toContain(
          key.toLowerCase(),
        );
      }
    }
  });

  it('leaves the one configuration identifier it cites in English', () => {
    // `settings.ai.enabled` is an identifier an operator greps for, not copy: it must survive
    // translation verbatim in both tiers (memory: `english-codebase-pt-ui`).
    expect(platformServicePtPT.serviceLimitation['mcp.ai_gate_disabled']).toContain(
      'settings.ai.enabled',
    );
    expect(platformServiceEnglish.serviceLimitation['mcp.ai_gate_disabled']).toContain(
      'settings.ai.enabled',
    );
  });
});

describe('resolution', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('resolves every emitted capability and message pair as known', async () => {
    for (const key of Object.keys(await emittedCapabilityLimitations())) {
      const [service, action] = key.split('.') as [string, string];
      const resolved = resolveCapabilityLimitation(
        platformServicePtPT,
        service,
        action,
        'server text',
      );
      expect(resolved.known, key).toBe(true);
      expect(resolved.text, key).not.toBe('server text');
    }
    for (const key of Object.keys(await emittedControlMessages())) {
      if (key === 'fallback') continue;
      const [service, action] = key.split('.') as [string, string];
      const resolved = resolveControlMessage(platformServicePtPT, service, action, 'server text');
      expect(resolved.known, key).toBe(true);
    }
  });

  it('resolves every emitted service limitation from its English text', async () => {
    const emitted = await emittedServiceLimitations();
    for (const text of Object.values(emitted).flat()) {
      const resolved = resolveServiceLimitation(platformServicePtPT, text);
      expect(resolved.known, text).toBe(true);
      expect(resolved.text, text).not.toBe(text);
    }
  });

  it('renders the server text verbatim and warns when a state is unknown', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    // `app` is in `PlatformServiceId` but is not controllable, so an audit row naming it must fall
    // through to what the server said rather than be forced into a key that does not describe it.
    const audit = resolveControlMessage(platformServicePtPT, 'app', 'start', 'Server said this.');
    expect(audit).toEqual({ text: 'Server said this.', known: false });

    const future = resolveCapabilityLimitation(
      platformServicePtPT,
      'api',
      'hibernate',
      'A future action.',
    );
    expect(future).toEqual({ text: 'A future action.', known: false });

    const caveat = resolveServiceLimitation(platformServicePtPT, 'A caveat from the future.');
    expect(caveat).toEqual({ text: 'A caveat from the future.', known: false });

    expect(warn).toHaveBeenCalledTimes(3);
  });
});
