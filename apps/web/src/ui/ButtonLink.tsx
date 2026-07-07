/**
 * A router `<Link>` styled as a button — the "neat button" that opens a dedicated
 * create/import page while participating in normal client-side navigation (so it plays
 * with the route-enter transition like any other route change). Mirrors `Button`'s
 * variants so a link and a button read identically side by side.
 */
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

type Variant = 'primary' | 'secondary' | 'ghost';

export function ButtonLink({
  to,
  variant = 'secondary',
  className,
  icon,
  children,
}: {
  to: string;
  variant?: Variant;
  className?: string;
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <Link
      className={`btn btn--${variant}${icon ? ' btn--icon' : ''} ${className ?? ''}`.trim()}
      to={to}
    >
      {icon ? <span className="btn__icon">{icon}</span> : null}
      {children}
    </Link>
  );
}
