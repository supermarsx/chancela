import { describe, expect, it } from 'vitest';
import {
  PRIVACY_REGISTER_SLUGS,
  privacyListPath,
  privacyRecordNewPath,
  privacyRecordPath,
  privacyRegisterListPath,
  privacyRetentionListPath,
  type PrivacyRegisterSlug,
} from './privacyRoutes';

describe('privacy register addresses', () => {
  it('builds a create address per register', () => {
    expect(privacyRecordNewPath('processors')).toBe('/settings/privacy/processors/new');
    expect(privacyRecordNewPath('dpias')).toBe('/settings/privacy/dpias/new');
    expect(privacyRecordNewPath('breach-playbooks')).toBe('/settings/privacy/breach-playbooks/new');
    expect(privacyRecordNewPath('transfer-controls')).toBe(
      '/settings/privacy/transfer-controls/new',
    );
    expect(privacyRecordNewPath('retention-policies')).toBe(
      '/settings/privacy/retention-policies/new',
    );
  });

  it('builds a record address per register', () => {
    expect(privacyRecordPath('dpias', 'dpia-7')).toBe('/settings/privacy/dpias/dpia-7');
    expect(privacyRecordPath('retention-policies', 'ret-1')).toBe(
      '/settings/privacy/retention-policies/ret-1',
    );
  });

  it('encodes ids so one can never be read as a path separator', () => {
    // A slash or a space in a server id must not silently split the address into more segments —
    // that would change which route matches, turning an edit into a 404 or into another record.
    expect(privacyRecordPath('processors', 'group/one')).toBe(
      '/settings/privacy/processors/group%2Fone',
    );
    expect(privacyRecordPath('processors', 'a b')).toBe('/settings/privacy/processors/a%20b');
    expect(privacyRecordPath('dpias', '?q=1#x')).toBe('/settings/privacy/dpias/%3Fq%3D1%23x');
  });

  it('keeps every record address at four segments, so the settings catch-all cannot shadow it', () => {
    // `settings/:sec?/:sub?` matches at most three segments. This is the whole ordering argument.
    for (const slug of PRIVACY_REGISTER_SLUGS) {
      for (const path of [privacyRecordNewPath(slug), privacyRecordPath(slug, 'id-1')]) {
        expect(path.split('/').filter(Boolean)).toHaveLength(4);
      }
    }
  });

  it('sends every register back to its own list', () => {
    expect(privacyListPath()).toBe('/settings/privacy');
    for (const slug of PRIVACY_REGISTER_SLUGS) {
      expect(privacyRegisterListPath(slug)).toBe(
        slug === 'retention-policies' ? privacyRetentionListPath() : privacyListPath(),
      );
    }
  });

  it('spells slugs in English, as identifiers rather than copy', () => {
    // t97b: a URL slug is an identifier. The pt-PT terminology rename (t55-e6) renames the
    // REGISTER, not its resource — `processors` stays `processors` because the API did not move.
    const expected: readonly PrivacyRegisterSlug[] = [
      'processors',
      'dpias',
      'breach-playbooks',
      'transfer-controls',
      'retention-policies',
    ];
    expect([...PRIVACY_REGISTER_SLUGS]).toEqual([...expected]);
  });
});
