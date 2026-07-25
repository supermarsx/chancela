import { useEffect, useState } from 'react';
import { useCollectionPagerT } from '../../i18n/collectionPagerFallback';
import { Badge, Button, Icon } from '../../ui';
import './CollectionPager.css';

export interface PagePosition {
  offset?: number;
  cursor?: string;
  displayOffset: number;
}

export function useCollectionNavigation(resetKey: string) {
  const [state, setState] = useState<{ key: string; history: PagePosition[] }>({
    key: resetKey,
    history: [{ offset: 0, displayOffset: 0 }],
  });
  const history = state.key === resetKey ? state.history : [{ offset: 0, displayOffset: 0 }];
  const position = history[history.length - 1];

  // The derived reset makes the first render for a new filter correct. Persisting it is equally
  // important: otherwise an A → B → A sequence can resurrect A's old cursor.
  useEffect(() => {
    setState((current) =>
      current.key === resetKey
        ? current
        : { key: resetKey, history: [{ offset: 0, displayOffset: 0 }] },
    );
  }, [resetKey]);

  function previous() {
    setState({ key: resetKey, history: history.length > 1 ? history.slice(0, -1) : history });
  }

  function next(
    nextOffset: number | null,
    nextCursor: string | null | undefined,
    displayOffset: number,
  ) {
    if (nextOffset === null && !nextCursor) return;
    const nextPosition: PagePosition = nextCursor
      ? { cursor: nextCursor, displayOffset }
      : { offset: nextOffset ?? displayOffset, displayOffset };
    setState({
      key: resetKey,
      history: [...history, nextPosition],
    });
  }

  return {
    position: { offset: position.offset, cursor: position.cursor },
    displayOffset: position.displayOffset,
    hasPrevious: history.length > 1,
    previous,
    next,
  };
}

export function useDebouncedValue<T>(value: T, delay = 250): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(timer);
  }, [delay, value]);
  return debounced;
}

/** A compact count whose accessible name makes clear that it is not a collection total. */
export function CollectionPageCount({ count }: { count: number }) {
  const paginationT = useCollectionPagerT();
  if (count === 0) return null;
  return (
    <span aria-label={paginationT('pageCount', { count })}>
      <Badge>{count}</Badge>
    </span>
  );
}

export function CollectionPager({
  offset,
  count,
  hasPrevious,
  hasNext,
  disabled = false,
  onPrevious,
  onNext,
}: {
  offset: number;
  count: number;
  hasPrevious: boolean;
  hasNext: boolean;
  disabled?: boolean;
  onPrevious: () => void;
  onNext: () => void;
}) {
  const paginationT = useCollectionPagerT();
  if (!hasPrevious && !hasNext) return null;
  const from = count === 0 ? offset : offset + 1;
  const to = offset + count;
  return (
    <nav className="collection-pagination" aria-label={paginationT('aria')}>
      <span className="mono" aria-live="polite">
        {paginationT('range', { from, to })}
      </span>
      <span className="collection-pagination__actions">
        <Button
          type="button"
          variant="ghost"
          icon={<Icon.ArrowLeft />}
          disabled={disabled || !hasPrevious}
          onClick={onPrevious}
        >
          {paginationT('previous')}
        </Button>
        <Button
          type="button"
          variant="ghost"
          icon={<Icon.ArrowRight />}
          disabled={disabled || !hasNext}
          onClick={onNext}
        >
          {paginationT('next')}
        </Button>
      </span>
    </nav>
  );
}
