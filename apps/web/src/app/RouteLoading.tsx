import { Loading } from '../ui';

export function RouteLoading() {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <Loading />
    </div>
  );
}
