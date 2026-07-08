/**
 * Themed UI primitives reused across features. Purely presentational: they carry no
 * data-fetching and lean entirely on the `theme.css` token layer (editorial
 * dark-green, light/dark via `prefers-color-scheme`). Kept deliberately small so the
 * feature pages stay readable.
 */
import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from 'react';
import { useT } from '../i18n';

// Presentational primitives kept in their own files (they carry a little local state or
// a router dependency) but surfaced through this barrel so features import from one place.
export { Digest, abbreviateDigest } from './Digest';
export { Truncate } from './Truncate';
export { ButtonLink } from './ButtonLink';
export { PageHeader } from './PageHeader';
export { SubNav, type SubNavItem } from './SubNav';
export * as Icon from './icons';
export { Skeleton, SkeletonText, SkeletonTable, SkeletonCards, SkeletonDeflist } from './Skeleton';
export { ToastProvider, useToast, type ToastHandle, type ToastVariant } from './toast';

// --- Button ---------------------------------------------------------------------

type ButtonVariant = 'primary' | 'secondary' | 'ghost';

/**
 * A themed button. Pass an `icon` (one of the {@link ./icons} glyphs) to prefix the
 * label with a semantically-correct, decorative inline SVG; the icon is `aria-hidden`
 * so the accessible name still comes from the text label alone.
 */
export function Button({
  variant = 'secondary',
  className,
  icon,
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; icon?: ReactNode }) {
  return (
    <button
      className={`btn btn--${variant}${icon ? ' btn--icon' : ''} ${className ?? ''}`}
      {...props}
    >
      {icon ? <span className="btn__icon">{icon}</span> : null}
      {children}
    </button>
  );
}

// --- Form fields ----------------------------------------------------------------

interface FieldProps {
  label: string;
  htmlFor?: string;
  hint?: ReactNode;
  error?: ReactNode;
  children: ReactNode;
}

export function Field({ label, htmlFor, hint, error, children }: FieldProps) {
  return (
    <div className="field">
      <label className="field__label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {hint && !error ? <p className="field__hint">{hint}</p> : null}
      {error ? (
        <p className="field__error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input className="control" {...props} />;
}

export function TextArea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className="control control--textarea" {...props} />;
}

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  options: readonly { value: string; label: string }[];
}

export function Select({ options, className, ...props }: SelectProps) {
  return (
    <select className={`control control--select ${className ?? ''}`.trim()} {...props}>
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

/**
 * A themed on/off switch (t19-e2 item b) — a gold-on-leather track with a sliding thumb,
 * driven by a visually-hidden native checkbox so it stays fully keyboard/screen-reader
 * accessible (the `<label>` associates the control with its text). Use it for the boolean
 * settings toggles in place of a bare checkbox.
 */
export function Toggle({
  checked,
  onChange,
  label,
  disabled,
  id,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: ReactNode;
  disabled?: boolean;
  id?: string;
}) {
  return (
    <label className={`toggle${disabled ? ' toggle--disabled' : ''}`}>
      <input
        id={id}
        type="checkbox"
        className="toggle__input"
        role="switch"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="toggle__track" aria-hidden="true">
        <span className="toggle__thumb" />
      </span>
      <span className="toggle__label">{label}</span>
    </label>
  );
}

// --- Layout / surfaces ----------------------------------------------------------

export function Card({
  title,
  actions,
  children,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      {(title || actions) && (
        <header className="panel__head">
          {title ? <h3 className="panel__title">{title}</h3> : <span />}
          {actions}
        </header>
      )}
      <div className="panel__body">{children}</div>
    </section>
  );
}

export function Panel({ children }: { children: ReactNode }) {
  return <div className="panel">{children}</div>;
}

// --- Table ----------------------------------------------------------------------

export function Table({ head, children }: { head: ReactNode; children: ReactNode }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>{head}</thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

// --- Badge ----------------------------------------------------------------------

type BadgeTone = 'neutral' | 'accent' | 'warn' | 'error' | 'ok';

export function Badge({ tone = 'neutral', children }: { tone?: BadgeTone; children: ReactNode }) {
  return <span className={`badge badge--${tone}`}>{children}</span>;
}

// --- Empty state ----------------------------------------------------------------

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <p className="empty__title">{title}</p>
      {children ? <div className="empty__body">{children}</div> : null}
    </div>
  );
}

// --- Inline warning -------------------------------------------------------------

export function InlineWarning({
  tone = 'warn',
  title,
  children,
}: {
  tone?: 'warn' | 'error' | 'info';
  title?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className={`inline-warning inline-warning--${tone}`} role="note">
      {title ? <p className="inline-warning__title">{title}</p> : null}
      <div className="inline-warning__body">{children}</div>
    </div>
  );
}

// --- Query state helpers --------------------------------------------------------

export function Loading({ label }: { label?: string }) {
  const t = useT();
  return <p className="muted">{label ?? t('common.loading')}</p>;
}

export function ErrorNote({ error }: { error: unknown }) {
  const t = useT();
  const message = error instanceof Error ? error.message : String(error);
  return (
    <InlineWarning tone="error" title={t('common.error')}>
      {message}
    </InlineWarning>
  );
}
