/**
 * The registration mechanism (t52). The failure mode under test is the one that ruins the
 * feature: a registration that outlives its surface and makes the whole app prompt forever.
 */
import { describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import {
  allowNextNavigation,
  consumeNavigationBypass,
  hasUnsavedChanges,
  resetNavigationBypass,
  subscribeUnsavedChanges,
  useUnsavedChanges,
} from './useUnsavedChanges';

describe('useUnsavedChanges', () => {
  it('reports clean when nothing is registered', () => {
    expect(hasUnsavedChanges()).toBe(false);
  });

  it('a clean surface does not arm the guard', () => {
    renderHook(() => useUnsavedChanges(false));
    expect(hasUnsavedChanges()).toBe(false);
  });

  it('a dirty surface arms the guard, and going clean again disarms it', () => {
    const view = renderHook(({ dirty }) => useUnsavedChanges(dirty), {
      initialProps: { dirty: false },
    });
    expect(hasUnsavedChanges()).toBe(false);

    view.rerender({ dirty: true });
    expect(hasUnsavedChanges()).toBe(true);

    // Saving (or reverting the edit) flips the derived flag back.
    view.rerender({ dirty: false });
    expect(hasUnsavedChanges()).toBe(false);
  });

  it('unmounting a dirty surface clears its registration', () => {
    const view = renderHook(() => useUnsavedChanges(true));
    expect(hasUnsavedChanges()).toBe(true);

    view.unmount();
    expect(hasUnsavedChanges()).toBe(false);
  });

  it('keeps the guard armed while ANY registered surface is still dirty', () => {
    const first = renderHook(() => useUnsavedChanges(true));
    const second = renderHook(() => useUnsavedChanges(true));

    first.unmount();
    expect(hasUnsavedChanges()).toBe(true);

    second.unmount();
    expect(hasUnsavedChanges()).toBe(false);
  });

  it('gives each instance its own registration (two mounts are not one entry)', () => {
    const first = renderHook(({ dirty }) => useUnsavedChanges(dirty), {
      initialProps: { dirty: true },
    });
    const second = renderHook(({ dirty }) => useUnsavedChanges(dirty), {
      initialProps: { dirty: true },
    });

    first.rerender({ dirty: false });
    expect(hasUnsavedChanges()).toBe(true);

    second.rerender({ dirty: false });
    expect(hasUnsavedChanges()).toBe(false);

    first.unmount();
    second.unmount();
  });

  it('notifies subscribers only on real transitions', () => {
    const listener = vi.fn();
    const unsubscribe = subscribeUnsavedChanges(listener);

    const view = renderHook(({ dirty }) => useUnsavedChanges(dirty), {
      initialProps: { dirty: false },
    });
    expect(listener).not.toHaveBeenCalled();

    act(() => view.rerender({ dirty: true }));
    expect(listener).toHaveBeenCalledTimes(1);

    // Re-rendering with the same flag is not a transition.
    act(() => view.rerender({ dirty: true }));
    expect(listener).toHaveBeenCalledTimes(1);

    act(() => view.unmount());
    expect(listener).toHaveBeenCalledTimes(2);
    unsubscribe();
  });

  it('unsubscribing stops notifications', () => {
    const listener = vi.fn();
    subscribeUnsavedChanges(listener)();

    const view = renderHook(() => useUnsavedChanges(true));
    expect(listener).not.toHaveBeenCalled();
    view.unmount();
  });
});

describe('navigation bypass', () => {
  it('is one-shot', () => {
    resetNavigationBypass();
    expect(consumeNavigationBypass()).toBe(false);

    allowNextNavigation();
    expect(consumeNavigationBypass()).toBe(true);
    expect(consumeNavigationBypass()).toBe(false);
  });

  it('can be dropped unconsumed so it never leaks into a later navigation', () => {
    allowNextNavigation();
    resetNavigationBypass();
    expect(consumeNavigationBypass()).toBe(false);
  });
});
