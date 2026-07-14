import { afterEach, describe, expect, it, vi } from 'vitest';
import { colorStore } from './colorStore';

afterEach(() => {
  colorStore.reset();
});

describe('colorStore', () => {
  it('starts empty (theme defaults) and reports no overrides', () => {
    colorStore.reset();
    expect(colorStore.get()).toEqual({});
    expect(colorStore.hasOverrides()).toBe(false);
  });

  it('sets and clears a single valid field, persisting to localStorage', () => {
    colorStore.setField('primary', '#123456');
    expect(colorStore.get()).toEqual({ primary: '#123456' });
    expect(colorStore.hasOverrides()).toBe(true);
    expect(window.localStorage.getItem('chancela.appearance.colors')).toContain('#123456');

    // clearing via a non-hex value drops the field
    colorStore.setField('primary', undefined);
    expect(colorStore.get()).toEqual({});
    // an empty store clears the persisted key entirely
    expect(window.localStorage.getItem('chancela.appearance.colors')).toBeNull();
  });

  it('rejects malformed hex on set', () => {
    colorStore.setField('secondary', 'not-a-color');
    expect(colorStore.get()).toEqual({});
  });

  it('sanitizes a whole set, dropping invalid fields', () => {
    colorStore.set({ primary: '#abc', secondary: 'bad', background: '#00ff00' });
    expect(colorStore.get()).toEqual({ primary: '#abc', background: '#00ff00' });
  });

  it('notifies subscribers on change', () => {
    const listener = vi.fn();
    const unsub = colorStore.subscribe(listener);
    colorStore.setField('surface', '#ffffff');
    expect(listener).toHaveBeenCalledTimes(1);
    unsub();
    colorStore.setField('surface', '#000000');
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('reset clears everything', () => {
    colorStore.set({ primary: '#111111', surface: '#222222' });
    colorStore.reset();
    expect(colorStore.get()).toEqual({});
    expect(colorStore.hasOverrides()).toBe(false);
  });
});
