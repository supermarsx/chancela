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
import { ApiError } from '../api/client';
import { FieldHelp } from './FieldHelp';

// Presentational primitives kept in their own files (they carry a little local state or
// a router dependency) but surfaced through this barrel so features import from one place.
export { Digest, abbreviateDigest } from './Digest';
export { DateOnly, DateTime, RelativeDateTime } from './DateTime';
export { Truncate } from './Truncate';
export { ButtonLink } from './ButtonLink';
export { PageHeader } from './PageHeader';
export { SubNav, type SubNavItem } from './SubNav';
export { Stepper, type StepperStep } from './Stepper';
export {
  Tooltip,
  IconButton,
  TooltipText,
  useIsClipped,
  type TooltipPlacement,
} from './Tooltip';
export { FieldHelp } from './FieldHelp';
export * as Icon from './icons';
export {
  Skeleton,
  SkeletonText,
  SkeletonTable,
  SkeletonCards,
  SkeletonDeflist,
  SkeletonList,
  SkeletonRegion,
} from './Skeleton';
export { ToastProvider, useToast, type ToastHandle, type ToastVariant } from './toast';
export {
  ConfirmActionModal,
  type ConfirmActionModalProps,
  type ConfirmActionArgs,
  type ExportFirstMode,
} from './ConfirmActionModal';

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
  /** Optional plain-language explanation → a {@link FieldHelp} glyph after the label. */
  help?: string;
  children: ReactNode;
}

export function Field({ label, htmlFor, hint, error, help, children }: FieldProps) {
  const labelEl = (
    <label className="field__label" htmlFor={htmlFor}>
      {label}
    </label>
  );
  return (
    <div className="field">
      {help ? (
        <span className="field__labelrow">
          {labelEl}
          <FieldHelp text={help} />
        </span>
      ) : (
        labelEl
      )}
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
  /**
   * `disabled` keeps an option **visible but unselectable** (t71). Prefer it to filtering the
   * option out whenever the operator needs to learn that the choice exists and why it is
   * unavailable — a silently absent option teaches nothing.
   */
  options: readonly { value: string; label: string; disabled?: boolean }[];
}

export function Select({ options, className, ...props }: SelectProps) {
  return (
    <select className={`control control--select ${className ?? ''}`.trim()} {...props}>
      {options.map((o) => (
        <option key={o.value} value={o.value} disabled={o.disabled}>
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

export function Table({
  head,
  caption,
  children,
}: {
  head: ReactNode;
  /**
   * The table's accessible name. Rendered as a visually hidden `<caption>`, so a screen
   * reader announces what the grid is without the page repeating the heading visually.
   */
  caption?: string;
  children: ReactNode;
}) {
  return (
    <div className="table-wrap">
      <table className="table">
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        <thead>{head}</thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

// --- Badge ----------------------------------------------------------------------

type BadgeTone = 'neutral' | 'accent' | 'warn' | 'error' | 'ok' | 'info';

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

/**
 * The shared indeterminate wait: a themed sweeping bar over its label.
 *
 * Use this only where the shape of what is coming is UNKNOWN (an unresolved route, a
 * search whose result count is not yet known). Where the shape IS known, a
 * {@link ./Skeleton} composite is the better instrument — it reserves the final layout
 * so the content swaps in without shifting, which a centred bar cannot do.
 *
 * The bar is deliberately **indeterminate**: it sweeps, it does not fill. This product
 * makes people wait on signing, sealing and validation, so a bar that crept to 90% on a
 * timer would be lying about progress we do not have — and would teach operators to
 * distrust the determinate bars that report real numerators.
 *
 * Accessibility: the region is a polite `role="status"` and the label stays as real text,
 * so the wait is announced rather than being a purely visual event. The track itself is
 * `aria-hidden` — it is decoration over the label, not a second announcement. Pass
 * `region={false}` when the CALLER is already a live region (the auth gate's boot panel
 * is): nesting two `role="status"` elements announces the same wait twice.
 *
 * Timing and motion live in `theme.css`: the whole region holds at opacity 0 for ~180ms
 * before fading in, so a fast response never flashes a bar in and out, and under
 * `prefers-reduced-motion` the sweep is replaced by a static filled track.
 */
export function Loading({ label, region = true }: { label?: string; region?: boolean }) {
  const t = useT();
  return (
    <div className="loading" role={region ? 'status' : undefined} aria-busy={region || undefined}>
      <span className="loading__track" aria-hidden="true">
        <span className="loading__indicator" />
      </span>
      <span className="loading__label muted">{label ?? t('common.loading')}</span>
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  const t = useT();
  // Honest 403 handling (t64-E5): a server permission denial (distinct from a 401 session,
  // which the client resolves by clearing the token → sign-in) reads as "sem permissão",
  // never a raw error. Applies app-wide since every inline error renders through here.
  if (error instanceof ApiError && error.status === 403) {
    return (
      <InlineWarning tone="error" title={t('perm.denied.title')}>
        {t('perm.denied.body')}
      </InlineWarning>
    );
  }
  const message = error instanceof Error ? error.message : String(error);
  return (
    <InlineWarning tone="error" title={t('common.error')}>
      {message}
    </InlineWarning>
  );
}
