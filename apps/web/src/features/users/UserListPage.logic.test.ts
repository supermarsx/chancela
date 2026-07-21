/**
 * Pure-predicate tests for the roster filters (t103), in the idiom
 * `EntitiesPage.logic.test.ts` established: the matchers are exported and exercised directly,
 * so the cases that are awkward or unstable to drive through a render — a clock, an unparseable
 * timestamp, the exact degradation of a bad URL value — are pinned without a DOM.
 *
 * The render-level behaviour (which rows appear, what the address says, when the advanced
 * disclosure opens) is asserted in `users.test.tsx`. These two are complements: this file says
 * the predicate is right, that one says it is wired up.
 */
import { describe, expect, it } from 'vitest';
import {
  matchesCreated,
  matchesEmail,
  matchesRole,
  matchesScope,
  readRoleFilter,
} from './UserListPage';
import type { UserView } from '../../api/types';

const OWNER = '6f776e65-7200-0000-0000-000000000001';
const OTHER = '11111111-2222-4333-8444-555555555555';

function user(overrides: Partial<UserView> = {}): UserView {
  return {
    id: 'u1',
    username: 'amelia.marques',
    display_name: 'Amélia Marques',
    created_at: '2026-07-07T12:00:00Z',
    active: true,
    has_secret: true,
    has_attestation_key: false,
    has_recovery_phrase: false,
    has_totp: false,
    two_factor_required: false,
    language: 'auto',
    role_assignments: [],
    ...overrides,
  };
}

describe('readRoleFilter — what a URL is allowed to mean', () => {
  it('passes a UUID through, case-folded so a link is not case-sensitive', () => {
    expect(readRoleFilter(OWNER.toUpperCase())).toBe(OWNER);
  });

  it('keeps the explicit "no role" value', () => {
    expect(readRoleFilter('none')).toBe('none');
  });

  it('degrades anything that is not a UUID to "no filter"', () => {
    // Notably the client-side slug (`owner`) and a display name: both are plausible things for a
    // person to type into the address bar, and neither is the stable identifier (t87).
    for (const bad of ['owner', 'Proprietário', '', '  ', 'null', '123']) {
      expect(readRoleFilter(bad), bad).toBe('all');
    }
    expect(readRoleFilter(null)).toBe('all');
  });

  it('does NOT degrade a well-formed id that names no live role', () => {
    // This is the whole basis of the merged-role empty state: the value survives so the screen
    // can say the role was merged, instead of silently showing everyone.
    expect(readRoleFilter('99999999-8888-4777-8666-555555555555')).toBe(
      '99999999-8888-4777-8666-555555555555',
    );
  });
});

describe('matchesRole', () => {
  const owner = user({ role_assignments: [{ role_id: OWNER, scope: { kind: 'global' } }] });
  const roleless = user();

  it('matches on the id, and ignores an account holding a different role', () => {
    expect(matchesRole(owner, OWNER)).toBe(true);
    expect(matchesRole(owner, OTHER)).toBe(false);
  });

  it('is case-insensitive on the stored id', () => {
    const shouty = user({
      role_assignments: [{ role_id: OWNER.toUpperCase(), scope: { kind: 'global' } }],
    });
    expect(matchesRole(shouty, OWNER)).toBe(true);
  });

  it('finds roleless accounts, which no role id ever matches', () => {
    expect(matchesRole(roleless, 'none')).toBe(true);
    expect(matchesRole(owner, 'none')).toBe(false);
    expect(matchesRole(roleless, OWNER)).toBe(false);
  });

  it('matches an account holding the role at any scope, not only globally', () => {
    const scoped = user({
      role_assignments: [{ role_id: OWNER, scope: { kind: 'book', id: 'b1' } }],
    });
    expect(matchesRole(scoped, OWNER)).toBe(true);
  });
});

describe('matchesScope — reach, not role', () => {
  const global = user({ role_assignments: [{ role_id: OWNER, scope: { kind: 'global' } }] });
  const confined = user({
    role_assignments: [{ role_id: OTHER, scope: { kind: 'entity', id: 'e1' } }],
  });
  const roleless = user();

  it('separates instance-wide authority from confined authority', () => {
    expect(matchesScope(global, 'global')).toBe(true);
    expect(matchesScope(confined, 'global')).toBe(false);
    expect(matchesScope(confined, 'scoped')).toBe(true);
  });

  it('excludes an account that ALSO holds a global role from "scoped"', () => {
    // "Confined" has to mean confined. An Owner who additionally holds a book-scoped role is not
    // an answer to "who cannot act instance-wide" — the question the filter exists to ask.
    const both = user({
      role_assignments: [
        { role_id: OWNER, scope: { kind: 'global' } },
        { role_id: OTHER, scope: { kind: 'book', id: 'b1' } },
      ],
    });
    expect(matchesScope(both, 'global')).toBe(true);
    expect(matchesScope(both, 'scoped')).toBe(false);
  });

  it('excludes a roleless account from both buckets rather than letting it fall into "scoped"', () => {
    expect(matchesScope(roleless, 'global')).toBe(false);
    expect(matchesScope(roleless, 'scoped')).toBe(false);
    expect(matchesScope(roleless, 'all')).toBe(true);
  });
});

describe('matchesEmail', () => {
  it('treats a blank address as no address', () => {
    expect(matchesEmail(user({ email: '   ' }), 'without')).toBe(true);
    expect(matchesEmail(user({ email: '   ' }), 'with')).toBe(false);
    expect(matchesEmail(user({ email: 'bruno@example.pt' }), 'with')).toBe(true);
    expect(matchesEmail(user({}), 'without')).toBe(true);
  });
});

describe('matchesCreated — against an injected clock', () => {
  const NOW = Date.parse('2026-07-10T00:00:00Z');
  const recent = user({ created_at: '2026-07-07T12:00:00Z' }); // ~2.5 days before NOW
  const old = user({ created_at: '2026-01-01T00:00:00Z' });

  it('keeps accounts inside the window and drops those outside it', () => {
    expect(matchesCreated(recent, '7', NOW)).toBe(true);
    expect(matchesCreated(old, '7', NOW)).toBe(false);
    expect(matchesCreated(old, '90', NOW)).toBe(false);
    expect(matchesCreated(old, 'all', NOW)).toBe(true);
  });

  it('excludes an unparseable timestamp instead of treating it as new', () => {
    // Guessing recency from a broken timestamp would put a mystery account at the top of an
    // access review — the wrong way to be wrong.
    expect(matchesCreated(user({ created_at: 'not a date' }), '7', NOW)).toBe(false);
    // …but it is not hidden from an unfiltered roster.
    expect(matchesCreated(user({ created_at: 'not a date' }), 'all', NOW)).toBe(true);
  });
});
