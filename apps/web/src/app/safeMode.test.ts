import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  CRASH_THRESHOLD,
  CRASH_WINDOW_MS,
  clearCrashLog,
  enterSafeMode,
  exitSafeMode,
  hasSafeModeQueryParam,
  isSafeMode,
  recordCrash,
} from './safeMode';

function setSearch(search: string): void {
  window.history.pushState({}, '', `/${search}`);
}

beforeEach(() => {
  window.localStorage.clear();
  setSearch('');
});

afterEach(() => {
  window.localStorage.clear();
  setSearch('');
});

describe('safeMode store', () => {
  it('detects the manual ?safe=1 query flag', () => {
    expect(hasSafeModeQueryParam()).toBe(false);
    expect(isSafeMode()).toBe(false);

    setSearch('?safe=1');
    expect(hasSafeModeQueryParam()).toBe(true);
    expect(isSafeMode()).toBe(true);
  });

  it('treats ?safe (bare) and ?safe=true as on, ?safe=0 as off', () => {
    setSearch('?safe');
    expect(hasSafeModeQueryParam()).toBe(true);
    setSearch('?safe=true');
    expect(hasSafeModeQueryParam()).toBe(true);
    setSearch('?safe=0');
    expect(hasSafeModeQueryParam()).toBe(false);
  });

  it('persists the safe-mode flag across a (simulated) reload', () => {
    expect(isSafeMode()).toBe(false);
    enterSafeMode();
    // No query flag, but the persisted flag alone is enough.
    expect(isSafeMode()).toBe(true);
  });

  it('exit clears both the flag and the crash counter', () => {
    enterSafeMode();
    recordCrash();
    expect(isSafeMode()).toBe(true);

    exitSafeMode();
    expect(isSafeMode()).toBe(false);
    // A fresh crash after exit starts the count from one, not from the old total.
    expect(recordCrash()).toBe(false);
  });

  it('trips only once the threshold is reached within the window', () => {
    const t0 = 1_000_000;
    for (let i = 0; i < CRASH_THRESHOLD - 1; i += 1) {
      expect(recordCrash(t0 + i)).toBe(false);
    }
    // The threshold-th crash trips.
    expect(recordCrash(t0 + CRASH_THRESHOLD)).toBe(true);
  });

  it('prunes crashes older than the window so a slow trickle never trips', () => {
    const t0 = 1_000_000;
    expect(recordCrash(t0)).toBe(false);
    expect(recordCrash(t0 + 1)).toBe(false);
    // A crash well beyond the window drops the two old ones — count is 1, no trip.
    expect(recordCrash(t0 + CRASH_WINDOW_MS + 1)).toBe(false);
  });

  it('clearCrashLog resets the counter without touching the flag', () => {
    enterSafeMode();
    recordCrash();
    recordCrash();
    clearCrashLog();
    expect(isSafeMode()).toBe(true);
    expect(recordCrash()).toBe(false);
  });
});
