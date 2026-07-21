/**
 * Themed UI primitives reused across features. Purely presentational: they carry no
 * data-fetching and lean entirely on the `theme.css` token layer (editorial
 * dark-green, light/dark via `prefers-color-scheme`). Kept deliberately small so the
 * feature pages stay readable.
 */
import { createContext, useContext, useId } from 'react';
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
export { Tooltip, IconButton, TooltipText, useIsClipped, type TooltipPlacement } from './Tooltip';
export { FieldHelp } from './FieldHelp';
export { ColumnHead } from './ColumnHead';
export * as Icon from './icons';
export {
  Skeleton,
  SkeletonText,
  SkeletonTable,
  SkeletonCards,
  SkeletonChips,
  SkeletonDeflist,
  SkeletonForm,
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

/**
 * The id of the help sentence a surrounding {@link Field} is showing, for its control to describe
 * itself with (t101, reported by t102-privacyux).
 *
 * ## The defect
 *
 * `Field` renders the explanation through a `FieldHelp` glyph beside the label, and `FieldHelp`
 * puts `aria-describedby` on *its own button*. That button is a separate tab stop. So a
 * screen-reader user who tabs into the input — the overwhelmingly common way to reach a form
 * control — heard the label and nothing else: the sentence existed, was announced to nobody who
 * needed it, and the tooltip was decoration for everyone not using a mouse.
 *
 * ## Why context rather than cloning the child
 *
 * The obvious fix is to `cloneElement(children, { 'aria-describedby': id })`. It is wrong here:
 * `Field`'s child is frequently NOT the control — it is a `<div className="row">` holding the
 * input plus a reset button, or a fragment — so the description would land on a wrapper and
 * describe nothing. Poking the DOM via `htmlFor` was the other option and loses to React on the
 * next render.
 *
 * Context reaches the control at any depth, and the control merges the id into whatever
 * `aria-describedby` the call site already passes rather than replacing it. A control that is
 * not one of these primitives simply does not opt in, which is honest: nothing silently claims
 * an association it does not have.
 *
 * The id is the BUBBLE's id, threaded through `FieldHelp` into the shared `Tooltip`, so the glyph
 * and the control point at the same node — the sentence is not duplicated in the accessibility
 * tree, and the bubble is always mounted, so the reference never dangles.
 */
const FieldHelpId = createContext<string | null>(null);

/** Merge the surrounding `Field`'s help id into a control's own `aria-describedby`. */
function useDescribedBy(own: string | undefined): string | undefined {
  const helpId = useContext(FieldHelpId);
  return [own, helpId].filter(Boolean).join(' ') || undefined;
}

export function Field({ label, htmlFor, hint, error, help, children }: FieldProps) {
  const helpId = useId();
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
          <FieldHelp text={help} describedById={helpId} />
        </span>
      ) : (
        labelEl
      )}
      {/* Only provided when there IS a help sentence: an empty provider would make every control
          in the app carry a describedby pointing at nothing. */}
      {help ? <FieldHelpId.Provider value={helpId}>{children}</FieldHelpId.Provider> : children}
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
  const describedBy = useDescribedBy(props['aria-describedby']);
  return <input className="control" {...props} aria-describedby={describedBy} />;
}

export function TextArea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const describedBy = useDescribedBy(props['aria-describedby']);
  return (
    <textarea className="control control--textarea" {...props} aria-describedby={describedBy} />
  );
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
  const describedBy = useDescribedBy(props['aria-describedby']);
  return (
    <select
      className={`control control--select ${className ?? ''}`.trim()}
      {...props}
      aria-describedby={describedBy}
    >
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
  'aria-describedby': ariaDescribedBy,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: ReactNode;
  disabled?: boolean;
  id?: string;
  'aria-describedby'?: string;
}) {
  const describedBy = useDescribedBy(ariaDescribedBy);
  return (
    <label className={`toggle${disabled ? ' toggle--disabled' : ''}`}>
      <input
        id={id}
        type="checkbox"
        className="toggle__input"
        role="switch"
        aria-describedby={describedBy}
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
  className,
  children,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  /**
   * Extra class on the panel, for a caller that needs to address its own instance — the same
   * affordance {@link Table} already carries, and used for the same reason. It does NOT change
   * how a card looks: `.panel` still supplies the whole treatment.
   */
  className?: string;
  children: ReactNode;
}) {
  return (
    <section className={className ? `panel ${className}` : 'panel'}>
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
  className,
  rowCount,
  children,
}: {
  head: ReactNode;
  /**
   * The table's accessible name. Rendered as a visually hidden `<caption>`, so a screen
   * reader announces what the grid is without the page repeating the heading visually.
   */
  caption?: string;
  /** Extra class on the wrapper, for a caller that restyles its own instance of the table. */
  className?: string;
  /**
   * Total rows the table stands for, header included — `aria-rowcount`. Only meaningful for a
   * table that grows lazily: pass `-1` (the ARIA value for "total not known") while more rows
   * remain on the server, and the real total once they do not. Omitting it leaves the table
   * plain, which is right when every row is already rendered.
   */
  rowCount?: number;
  children: ReactNode;
}) {
  return (
    <div className={className ? `table-wrap ${className}` : 'table-wrap'}>
      <table className="table" aria-rowcount={rowCount}>
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
