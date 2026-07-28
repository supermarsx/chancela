/**
 * The API-error copy gate (t58-e5, plan §5.3).
 *
 * `apiErrorFallback.ts` sits off the shared catalog chain, so `catalogLeakGate.test.ts` never sees
 * it. This file is its equivalent, with the checks tightened where the shared gate had to be lenient:
 *
 * 1. **Agreement.** Every placeholder must be on the integer-only allowlist. A noun-shaped
 *    placeholder is what breaks pt-PT agreement (`i18n-interpolated-nouns-break-agreement`), and it
 *    is invisible in the source — a template reads fine and renders wrong. Making it unmergeable is
 *    the point of this file.
 * 2. **Placeholder-set equality** between pt-PT and the English fallback, mirroring the shared gate,
 *    so a translation cannot drop or invent a slot.
 * 3. **Divergence, with NO reviewed-identical escape hatch.** In the shared catalogs
 *    `REVIEWED_IDENTICAL_VALUES` exists because genuinely shared tokens (`NIPC`, `PDF/A`) must pass.
 *    Error copy has no such tokens, so the exemption list simply does not exist here — and cannot,
 *    because that ledger is precisely how `error.requestFailed` shipped untranslated for months.
 * 4. **The must-not-soften set** keeps its own copy and its refusal register. A future "let's make
 *    errors more consistent" pass that folds one of these into a generic tier headline fails here.
 * 5. **The cross-user 403 stays uniform.** Adding a finer key for wrong-password vs unknown-user
 *    would reintroduce user enumeration through the copy channel; the gate names those keys and
 *    refuses them.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  apiErrorPtPT,
  apiErrorEnglish,
  ALLOWED_PLACEHOLDERS,
  FORBIDDEN_PLACEHOLDERS,
  NON_ROUTINE_CODES,
  TIER_STATUSES,
  resolveApiError,
  tierKey,
  apiErrorCopy,
  type ApiErrorCopyKey,
} from './apiErrorFallback';

const ptPT: Record<string, string> = apiErrorPtPT;
const english: Record<string, string> = apiErrorEnglish;

function placeholders(value: string): string[] {
  return [...value.matchAll(/\{([^}]+)\}/gu)].map((match) => match[1]).sort();
}

const allowed = new Set<string>(ALLOWED_PLACEHOLDERS);

describe('agreement gate — no noun ever arrives through a placeholder', () => {
  it.each([
    ['pt-PT', ptPT],
    ['English', english],
  ])('%s uses only allowlisted, agreement-inert placeholders', (_label, catalog) => {
    const offenders = Object.entries(catalog).flatMap(([key, value]) =>
      placeholders(value)
        .filter((name) => !allowed.has(name))
        .map((name) => `${key}: {${name}}`),
    );
    expect(
      offenders,
      `A placeholder outside the integer-only allowlist. If it resolves to a noun, pt-PT agreement ` +
        `breaks at runtime — split the copy into one key per noun instead.\n${offenders.join('\n')}`,
    ).toEqual([]);
  });

  it.each([
    ['pt-PT', ptPT],
    ['English', english],
  ])('%s contains none of the categorically forbidden placeholder names', (_label, catalog) => {
    const forbidden = new Set<string>(FORBIDDEN_PLACEHOLDERS);
    const offenders = Object.entries(catalog).flatMap(([key, value]) =>
      placeholders(value)
        .filter((name) => forbidden.has(name))
        .map((name) => `${key}: {${name}}`),
    );
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  it('the allowlist itself admits no noun-shaped name', () => {
    // The gate is only worth as much as its allowlist. Every allowed name must resolve to an
    // integer; none may be one of the forbidden noun slots.
    for (const name of ALLOWED_PLACEHOLDERS) {
      expect(FORBIDDEN_PLACEHOLDERS as readonly string[]).not.toContain(name);
    }
  });

  it('detects a noun-shaped placeholder if one is ever introduced', () => {
    // Proves the checker actually fires, rather than passing because it matches nothing.
    const sabotaged = { 'apiError.example': 'Não foi possível eliminar o {entity}.' };
    const offenders = Object.entries(sabotaged).flatMap(([key, value]) =>
      placeholders(value)
        .filter((name) => !allowed.has(name))
        .map((name) => `${key}: {${name}}`),
    );
    expect(offenders).toEqual(['apiError.example: {entity}']);
  });
});

describe('pt-PT ↔ English parity', () => {
  it('covers exactly the same key set', () => {
    expect(Object.keys(english).sort()).toEqual(Object.keys(ptPT).sort());
  });

  it('preserves every interpolation placeholder', () => {
    const mismatches = Object.entries(ptPT).flatMap(([key, source]) => {
      const expected = placeholders(source);
      const actual = placeholders(english[key] ?? '');
      return JSON.stringify(actual) === JSON.stringify(expected)
        ? []
        : [`${key}: expected ${expected.join(', ') || 'none'}; got ${actual.join(', ') || 'none'}`];
    });
    expect(mismatches, mismatches.join('\n')).toEqual([]);
  });

  it('has no key whose pt-PT value equals its English fallback', () => {
    // No reviewed-identical ledger exists here, by design: an untranslated English error string
    // cannot be admitted by any route.
    const identical = Object.keys(ptPT).filter((key) => ptPT[key] === english[key]);
    expect(identical, `untranslated pt-PT copy:\n${identical.join('\n')}`).toEqual([]);
  });

  it('leaves no pt-PT value empty or whitespace-only', () => {
    const blank = Object.entries(ptPT)
      .filter(([, value]) => value.trim() === '')
      .map(([key]) => key);
    expect(blank).toEqual([]);
  });
});

describe('naming and copy conventions', () => {
  it('namespaces every key under apiError.', () => {
    const stray = Object.keys(ptPT).filter((key) => !key.startsWith('apiError.'));
    expect(stray).toEqual([]);
  });

  it('keeps every code an ASCII English identifier — codes are not copy', () => {
    const bad = Object.keys(ptPT).filter((key) => !/^apiError\.[a-z0-9_.]+$/i.test(key));
    expect(bad, `keys must stay snake_case ASCII:\n${bad.join('\n')}`).toEqual([]);
  });

  it('makes no evidentiary claim in user-visible copy', () => {
    const offenders = Object.entries({ ...ptPT, ...english })
      .filter(([, value]) => /valor probat/i.test(value))
      .map(([key]) => key);
    expect(offenders).toEqual([]);
  });

  it('names no real person or company — examples are fictional only', () => {
    const offenders = Object.entries({ ...ptPT, ...english })
      .filter(([, value]) => /vogue\s*homes|mariana/i.test(value))
      .map(([key]) => key);
    expect(offenders).toEqual([]);
  });
});

describe('status tiers are total', () => {
  it.each(TIER_STATUSES)('has a headline for %i', (status) => {
    expect(ptPT[`apiError.tier.${String(status)}`]).toBeTruthy();
    expect(tierKey(status)).toBe(`apiError.tier.${String(status)}`);
  });

  it('falls back to the unknown tier for a status it does not know', () => {
    expect(tierKey(418)).toBe('apiError.tier.unknown');
    expect(tierKey(undefined)).toBe('apiError.tier.unknown');
    expect(ptPT['apiError.tier.unknown']).toBeTruthy();
  });
});

describe('the must-not-soften set stays loud', () => {
  it.each(NON_ROUTINE_CODES)('%s has its own copy, not a generic tier headline', (code) => {
    const key = `apiError.${code}`;
    expect(ptPT[key], `${code} lost its dedicated key`).toBeTruthy();
    const tierValues = TIER_STATUSES.map((status) => ptPT[`apiError.tier.${String(status)}`]);
    expect(tierValues, `${code} collapsed into a status tier`).not.toContain(ptPT[key]);
  });

  it.each(NON_ROUTINE_CODES)('%s resolves as non-routine', (code) => {
    const resolved = resolveApiError({ status: 409, code });
    expect(resolved.nonRoutine, `${code} would render as an ordinary error`).toBe(true);
    expect(resolved.unmapped).toBe(false);
  });

  it('states plainly that the fail-closed termo refusals are not worth retrying', () => {
    for (const key of [
      'apiError.termo_abertura_not_signed',
      'apiError.termo_encerramento_not_signed',
    ] satisfies ApiErrorCopyKey[]) {
      expect(ptPT[key], key).toMatch(/recusa/i);
      expect(ptPT[key], `${key} must say retrying does not help`).toMatch(/não a resolve/i);
    }
  });

  it('does not blame the ata count when only the rendering moved', () => {
    // The refusal is correct; naming a cause that was not established is its own defect. The
    // render-drift copy must say the figures are still right, and must not claim a new ata.
    expect(ptPT['apiError.termo_snapshot_render_drift']).toMatch(/números declarados continuem/i);
    expect(ptPT['apiError.termo_snapshot_render_drift']).not.toMatch(/nova ata/i);
    // And where the cause cannot be narrowed, the copy names no cause at all.
    expect(ptPT['apiError.termo_snapshot_mismatch']).toMatch(/não foi possível apurar/i);
  });

  it('keeps a blocked Cartão de Cidadão terminal, and the final try urgent', () => {
    expect(ptPT['apiError.cc_pin_blocked']).toMatch(/PUK/);
    expect(ptPT['apiError.cc_pin_blocked']).toMatch(/não volta a assinar/i);
    expect(ptPT['apiError.cc_pin_wrong.final_try']).toMatch(/uma única tentativa/i);
    expect(ptPT['apiError.cc_pin_wrong.final_try']).toMatch(/bloqueado/i);
  });

  it('keeps the 429 copy honest about the real wait, in seconds', () => {
    expect(placeholders(ptPT['apiError.signin_throttled'])).toEqual(['seconds']);
    // Rendered against the symbol `s`, so `1` never has to agree with «segundo/segundos».
    expect(ptPT['apiError.signin_throttled']).toContain('{seconds} s');
  });

  it('keeps the 503 not-leader copy explicit that a retry will work', () => {
    expect(ptPT['apiError.cluster_not_leader']).toMatch(/volte a tentar/i);
    expect(ptPT['apiError.cluster_not_leader']).toMatch(/não foi realizada/i);
  });

  it('keeps compliance and warnings citing their own items rather than a summary', () => {
    expect(ptPT['apiError.compliance_blocked']).toMatch(/abaixo/i);
    expect(ptPT['apiError.warnings_not_acknowledged']).toMatch(/confirme/i);
    // Not dismissable: closing the notice must not read as acknowledgement.
    expect(ptPT['apiError.warnings_not_acknowledged']).toMatch(/não os dá por confirmados/i);
  });

  it('says nothing was written when a rejected ata body is refused', () => {
    expect(ptPT['apiError.invalid_act_body']).toMatch(/nada foi guardado/i);
    expect(ptPT['apiError.unsupported_markdown']).toMatch(/nada foi convertido nem removido/i);
  });

  it('keeps the three trust-anchor causes apart, and blames the provider only for its own', () => {
    // Key names mirror `SigningError`'s variants; the server emits exactly these three. A code the
    // server sends with no key here falls to the status tier, which is how the catalog silently
    // drifted behind the emitter once already.
    const anchorFaults = [
      'apiError.trust_anchor_not_configured',
      'apiError.trusted_list_not_anchored',
    ];
    const provider = 'apiError.signer_service_not_active';
    const all = [...anchorFaults, provider];

    for (const key of all) expect(ptPT[key], `${key} has no copy`).toBeTruthy();
    // Three distinct sentences. Two sharing one is the collapse that made an operator diagnose a
    // third party for their own configuration.
    expect(new Set(all.map((key) => ptPT[key])).size).toBe(all.length);

    // Only the signer's own service points at the provider. Both anchor faults are the operator's
    // configuration and must say so — pointing outward is the original defect, not a wording choice.
    expect(ptPT[provider]).toMatch(/lado do prestador/i);
    for (const key of anchorFaults) {
      expect(ptPT[key], `${key} blames the provider for a local fault`).not.toMatch(
        /lado do prestador/i,
      );
      expect(ptPT[key], `${key} must point at the anchor configuration`).toMatch(/âncora/i);
    }
    // A configured-but-wrong anchor must never read as nothing-configured: telling an operator who
    // did configure an anchor that they configured none is the narrower version of the same lie.
    expect(ptPT['apiError.trusted_list_not_anchored']).not.toMatch(/ainda não tem/i);
  });
});

describe('the cross-user 403 does not enumerate users', () => {
  it('has exactly one no-valid-proof code', () => {
    expect(ptPT['apiError.cross_user_proof_required']).toBeTruthy();
  });

  it('admits no key that would distinguish the uniform cases', () => {
    // The server answers wrong password, absent proof and non-existent target identically. A finer
    // key here would leak the distinction through the copy instead of the status.
    const banned = [
      'apiError.wrong_password',
      'apiError.cross_user_wrong_password',
      'apiError.user_not_found',
      'apiError.cross_user_user_not_found',
      'apiError.cross_user_proof_missing',
      'apiError.cross_user_target_unknown',
    ];
    const present = banned.filter((key) => key in ptPT);
    expect(present, `these reintroduce user enumeration:\n${present.join('\n')}`).toEqual([]);
  });

  it('says in the copy itself that the answer is uniform', () => {
    const copy = ptPT['apiError.cross_user_proof_required'];
    expect(copy).toMatch(/a resposta é a mesma/i);
    expect(copy).toMatch(/não confirma nem desmente/i);
  });
});

describe('resolution never drops the server detail and never shows raw English as the headline', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('maps a known code to its own copy', () => {
    const resolved = resolveApiError({ status: 409, code: 'book_not_open' });
    expect(resolved).toEqual({
      key: 'apiError.book_not_open',
      unmapped: false,
      forceDetails: false,
      nonRoutine: false,
    });
  });

  it('demotes an unmapped code to the status tier AND forces the detail open', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const resolved = resolveApiError({ status: 422, code: 'a_code_no_one_has_written_copy_for' });
    expect(resolved.key).toBe('apiError.tier.422');
    expect(resolved.unmapped).toBe(true);
    // The English detail is demoted, never discarded: the surface must show it unprompted.
    expect(resolved.forceDetails).toBe(true);
  });

  it('treats a Tier-1 variant default as mapped, not as a gap — but force-opens the detail', () => {
    // `http.not_found` carries nothing beyond the status, so this catalog has no gap to fill: the
    // headline is the tier sentence and `unmapped` stays false. The code is the `http.`-prefixed
    // form the server actually emits: asserting on the bare name would pass while covering nothing.
    //
    // What the code does not say, the DETAIL does. A tier headline names the status and nothing
    // about the fault, so the server's English message is the only thing on screen that does — and
    // it must not start collapsed. (`with_code` is opt-in per site, so this is the common path.)
    const resolved = resolveApiError({ status: 404, code: 'http.not_found' });
    expect(resolved.key).toBe('apiError.tier.404');
    expect(resolved.unmapped).toBe(false);
    expect(resolved.forceDetails).toBe(true);
  });

  /**
   * The complete Tier-1 set `ApiError::code()` can emit, transcribed from `error.rs`. Pinned here
   * because the previous list held the *plan's* bare names while the server shipped `http.`-prefixed
   * ones: every routine 404/409/422 in the app silently took the unmapped branch, force-opening the
   * technical-details block and warning in DEV. Nothing went red, because no test named a code the
   * server actually sends. If the server's vocabulary moves again, this fails.
   */
  it.each([
    ['http.not_found', 404],
    ['http.conflict', 409],
    ['http.unprocessable', 422],
    ['http.unauthorized', 401],
    ['http.forbidden', 403],
    ['http.gone', 410],
    ['http.too_many_requests', 429],
    ['http.unavailable', 503],
  ])('%s resolves to its status tier without being treated as a gap', (code, status) => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const resolved = resolveApiError({ status, code });
    expect(resolved.key, `${code} did not reach its tier headline`).toBe(
      `apiError.tier.${String(status)}`,
    );
    expect(resolved.unmapped, `${code} was treated as an unwritten-copy gap`).toBe(false);
    // A tier headline names no fault, so the server detail is shown unprompted — the same rule the
    // unmapped branch follows, reached for a different reason (no code to map, not a missing entry).
    expect(resolved.forceDetails, `${code} left the operator's only fault detail collapsed`).toBe(
      true,
    );
    expect(warn, `${code} warned about missing copy that is not missing`).not.toHaveBeenCalled();
  });

  it('forces the detail open for the scrubbed 5xx, because the copy is generic on purpose', () => {
    // The wire form is `http.`-prefixed; it must reach the dedicated copy, not the status tier.
    const internal = resolveApiError({ status: 500, code: 'http.internal' });
    expect(internal.forceDetails).toBe(true);
    expect(internal.key).toBe('apiError.internal');
    expect(internal.unmapped).toBe(false);

    const upstream = resolveApiError({ status: 502, code: 'http.upstream' });
    expect(upstream.forceDetails).toBe(true);
    expect(upstream.key).toBe('apiError.upstream');
    expect(upstream.unmapped).toBe(false);
  });

  it('resolves the structured PIN status ahead of the code', () => {
    expect(resolveApiError({ status: 422, code: 'pin_rejected', pinStatus: 'blocked' })).toEqual({
      key: 'apiError.cc_pin_blocked',
      unmapped: false,
      forceDetails: false,
      nonRoutine: true,
    });
    expect(
      resolveApiError({ status: 422, pinStatus: 'wrong_pin', triesLeft: 'final_try' }).key,
    ).toBe('apiError.cc_pin_wrong.final_try');
    expect(resolveApiError({ status: 422, pinStatus: 'wrong_pin', triesLeft: 'low' }).key).toBe(
      'apiError.cc_pin_wrong.low',
    );
    // An unrecognised hint degrades to the plain wrong-PIN sentence, never to a raw token.
    expect(resolveApiError({ status: 422, pinStatus: 'wrong_pin', triesLeft: 'unknown' }).key).toBe(
      'apiError.cc_pin_wrong',
    );
  });

  it('still produces a sentence for a null error and an unknown status', () => {
    expect(resolveApiError(null).key).toBe('apiError.tier.unknown');
    expect(resolveApiError({ status: 418 }).key).toBe('apiError.tier.unknown');
  });

  it('serves pt-PT to pt-PT and the English fallback to every other locale', () => {
    const error = { status: 409, code: 'book_not_open' };
    expect(apiErrorCopy(error, 'pt-PT')).toBe(ptPT['apiError.book_not_open']);
    expect(apiErrorCopy(error, 'fr-FR')).toBe(english['apiError.book_not_open']);
  });

  it('interpolates an integer param without leaving the placeholder behind', () => {
    const rendered = apiErrorCopy({ status: 429, code: 'signin_throttled' }, 'pt-PT', {
      seconds: 1,
    });
    expect(rendered).toContain('1 s');
    expect(rendered).not.toContain('{seconds}');
  });
});
