/**
 * The device-local recents store (t33). These pin the two properties the store exists to
 * guarantee: it holds NOTHING secret, and a removal is durable (it survives a reload —
 * modelled here by re-reading from localStorage through a fresh call).
 */
import { beforeEach, describe, expect, it } from 'vitest';
import {
  forgetAccount,
  MAX_RECENT_ACCOUNTS,
  readRecentAccounts,
  rememberAccount,
} from './recentAccounts';

const KEY = 'chancela.signin.recentAccounts';

beforeEach(() => {
  window.localStorage.clear();
});

describe('recentAccounts', () => {
  it('starts empty and round-trips a remembered identifier', () => {
    expect(readRecentAccounts()).toEqual([]);
    rememberAccount({ username: 'amelia.marques', displayName: 'Amélia Marques' }, 1000);
    expect(readRecentAccounts()).toEqual([
      { username: 'amelia.marques', displayName: 'Amélia Marques', lastUsedAt: 1000 },
    ]);
  });

  it('persists ONLY the identifier, display name and timestamp — never anything secret', () => {
    rememberAccount({ username: 'amelia.marques', displayName: 'Amélia Marques' }, 1000);
    const raw = window.localStorage.getItem(KEY) ?? '';
    const stored = JSON.parse(raw) as Record<string, unknown>[];
    expect(Object.keys(stored[0]).sort()).toEqual(['displayName', 'lastUsedAt', 'username']);
    // No password, token or user id may ever reach storage.
    expect(raw).not.toMatch(/password|token|secret|user_?id/iu);
  });

  it('drops unknown keys from a tampered payload rather than carrying them through', () => {
    window.localStorage.setItem(
      KEY,
      JSON.stringify([{ username: 'amelia.marques', token: 'tok-1', lastUsedAt: 5 }]),
    );
    const [entry] = readRecentAccounts();
    expect(entry).toEqual({ username: 'amelia.marques', lastUsedAt: 5 });
    expect('token' in entry).toBe(false);
  });

  it('orders most-recent-first, de-duplicates case-insensitively and caps the list', () => {
    rememberAccount({ username: 'amelia.marques' }, 1000);
    rememberAccount({ username: 'bruno.dias' }, 2000);
    rememberAccount({ username: 'Amelia.Marques' }, 3000);
    expect(readRecentAccounts().map((r) => r.username)).toEqual(['Amelia.Marques', 'bruno.dias']);

    for (let i = 0; i < MAX_RECENT_ACCOUNTS + 3; i += 1) {
      rememberAccount({ username: `user${i}` }, 4000 + i);
    }
    expect(readRecentAccounts()).toHaveLength(MAX_RECENT_ACCOUNTS);
  });

  it('forgetAccount removes an entry durably', () => {
    rememberAccount({ username: 'amelia.marques' }, 1000);
    rememberAccount({ username: 'bruno.dias' }, 2000);
    expect(forgetAccount('amelia.marques').map((r) => r.username)).toEqual(['bruno.dias']);
    // A fresh read (what a reload does) still does not see it.
    expect(readRecentAccounts().map((r) => r.username)).toEqual(['bruno.dias']);
  });

  it('degrades to an empty list on malformed storage instead of throwing', () => {
    window.localStorage.setItem(KEY, 'not json');
    expect(readRecentAccounts()).toEqual([]);
    window.localStorage.setItem(KEY, JSON.stringify({ username: 'x' }));
    expect(readRecentAccounts()).toEqual([]);
  });
});
