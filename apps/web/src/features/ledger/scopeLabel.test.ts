import { describe, expect, it } from 'vitest';
import { abbreviateId, parseScope, scopeTypeKey, type ScopeNameLookup } from './scopeLabel';

const ENTITY = '0a20de34-e096-4121-9d55-e5f76214be3c';
const BOOK = '7c1f9a02-1111-4222-8333-444455556666';

const names: ScopeNameLookup = {
  entity: (id) => (id === ENTITY ? 'Encosto Estratégico Lda' : null),
  book: (id) => (id === BOOK ? 'Assembleia Geral' : null),
};

describe('parseScope', () => {
  it('names the bare-UUID scope the user reported, without needing a discriminator', () => {
    // `entity.statute_updated` and `registry.imported` append `entity.id.to_string()` with no
    // prefix at all — the exact value that shipped as a naked id in the Âmbito column.
    expect(parseScope(ENTITY, names)).toEqual([
      { token: 'entity', id: ENTITY, name: 'Encosto Estratégico Lda' },
    ]);
  });

  it('refuses to call an unmatched bare UUID an entity', () => {
    // Every current emit site happens to mean "entity", but that is a convention, not a
    // contract. Claiming the type on an id we could not confirm would be a fabricated fact
    // about an evidentiary record, so the segment stays generically labelled.
    const other = '11111111-2222-4333-8444-555555555555';
    expect(parseScope(other, names)).toEqual([{ token: null, id: other, name: null }]);
    expect(scopeTypeKey(null)).toBe('enum.ledgerScopeType.unknown');
  });

  it('resolves each discriminated segment of a nested path independently', () => {
    const segments = parseScope(`entity:${ENTITY}/book:${BOOK}`, names);
    expect(segments).toEqual([
      { token: 'entity', id: ENTITY, name: 'Encosto Estratégico Lda' },
      { token: 'book', id: BOOK, name: 'Assembleia Geral' },
    ]);
  });

  it('keeps the declared type of a segment whose record cannot be resolved', () => {
    // A deleted book, or one this viewer may not read: the id survives and so does the type, so
    // the cell can still say WHAT was scoped even when it cannot say which one.
    const segments = parseScope('book:deadbeef-0000-4000-8000-000000000000', names);
    expect(segments[0].token).toBe('book');
    expect(segments[0].name).toBeNull();
    expect(scopeTypeKey(segments[0].token)).toBe('enum.ledgerScopeType.book');
  });

  it('separates the keyword `user` scope from one specific user', () => {
    // `users.rs` appends against the literal "user" (the administration surface); `privacy.rs`
    // appends `user:{uuid}` (one data subject). Same token, two meanings.
    expect(scopeTypeKey(parseScope('user', names)[0].token)).toBe(
      'enum.ledgerScopeType.user_accounts',
    );
    expect(scopeTypeKey(parseScope('user:abc', names)[0].token)).toBe('enum.ledgerScopeType.user');
  });

  it('labels the keyword scopes that carry no id at all', () => {
    for (const [scope, key] of [
      ['settings', 'enum.ledgerScopeType.settings'],
      ['law', 'enum.ledgerScopeType.law'],
      ['api-key', 'enum.ledgerScopeType.api-key'],
      ['provider_credentials', 'enum.ledgerScopeType.provider_credentials'],
      ['global', 'enum.ledgerScopeType.global'],
    ] as const) {
      const segments = parseScope(scope, names);
      expect(segments[0].id).toBeNull();
      expect(scopeTypeKey(segments[0].token)).toBe(key);
    }
  });

  it('never yields an empty segment list, so the cell always has something honest to draw', () => {
    expect(parseScope('', names)).toEqual([{ token: null, id: '', name: null }]);
  });
});

describe('abbreviateId', () => {
  it('marks an abbreviation so it can never be mistaken for a name', () => {
    expect(abbreviateId(ENTITY)).toBe('0a20de34…');
    expect(abbreviateId('b1')).toBe('b1');
  });
});
