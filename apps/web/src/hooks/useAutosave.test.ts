/**
 * Tests for {@link useAutosave}: it debounces a burst of edits into a single trailing
 * save (coalescing), never overlaps an in-flight save (queues the newest for after it
 * settles), and surfaces a retryable error status when the save rejects.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { useAutosave } from './useAutosave';

/** A promise whose resolution/rejection is driven manually, to hold a save "in flight". */
function deferred<T = void>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe('useAutosave', () => {
  it('does not save on mount when the value is unchanged', () => {
    const onSave = vi.fn(() => Promise.resolve());
    const { result } = renderHook(() => useAutosave({ value: 'a', onSave, delay: 700 }));

    act(() => vi.advanceTimersByTime(2000));
    expect(onSave).not.toHaveBeenCalled();
    expect(result.current.status).toBe('idle');
  });

  it('debounces a burst of edits into a single trailing save with the latest value', async () => {
    const onSave = vi.fn(() => Promise.resolve());
    const { result, rerender } = renderHook(
      ({ value }) => useAutosave({ value, onSave, delay: 700 }),
      {
        initialProps: { value: 'a' },
      },
    );

    // Three quick edits within the window — none should fire until it settles.
    rerender({ value: 'ab' });
    act(() => vi.advanceTimersByTime(300));
    rerender({ value: 'abc' });
    act(() => vi.advanceTimersByTime(300));
    rerender({ value: 'abcd' });
    expect(result.current.status).toBe('dirty');
    expect(onSave).not.toHaveBeenCalled();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(700);
    });

    expect(onSave).toHaveBeenCalledTimes(1);
    expect(onSave).toHaveBeenCalledWith('abcd');
    expect(result.current.status).toBe('saved');
    expect(result.current.isDirty).toBe(false);
  });

  it('never overlaps an in-flight save and persists the newest value once it settles', async () => {
    const first = deferred();
    const calls: string[] = [];
    const onSave = vi.fn((v: string) => {
      calls.push(v);
      return calls.length === 1 ? first.promise : Promise.resolve();
    });
    const { result, rerender } = renderHook(
      ({ value }) => useAutosave({ value, onSave, delay: 700 }),
      {
        initialProps: { value: 'a' },
      },
    );

    rerender({ value: 'b' });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(700);
    });
    // First save is in flight (unresolved).
    expect(onSave).toHaveBeenCalledTimes(1);
    expect(result.current.status).toBe('saving');

    // Edit again while it is still in flight — must NOT start a second overlapping save.
    rerender({ value: 'c' });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(700);
    });
    expect(onSave).toHaveBeenCalledTimes(1);
    expect(result.current.status).toBe('saving');

    // Let the first save settle: the queued newest value is saved exactly once.
    await act(async () => {
      first.resolve();
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(onSave).toHaveBeenCalledTimes(2);
    expect(calls).toEqual(['b', 'c']);
    expect(result.current.status).toBe('saved');
  });

  it('surfaces a retryable error status and calls onError when the save rejects', async () => {
    const onError = vi.fn();
    let attempt = 0;
    const onSave = vi.fn(() => {
      attempt += 1;
      return attempt === 1 ? Promise.reject(new Error('boom')) : Promise.resolve();
    });
    const { result, rerender } = renderHook(
      ({ value }) => useAutosave({ value, onSave, delay: 700, onError }),
      { initialProps: { value: 'a' } },
    );

    rerender({ value: 'b' });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(700);
    });

    expect(result.current.status).toBe('error');
    expect(result.current.isDirty).toBe(true);
    expect(result.current.error).toBeInstanceOf(Error);
    expect(onError).toHaveBeenCalledTimes(1);

    // flush() retries the same (still-dirty) value and succeeds.
    await act(async () => {
      result.current.flush();
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(onSave).toHaveBeenCalledTimes(2);
    expect(result.current.status).toBe('saved');
  });
});
