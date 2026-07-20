/**
 * A horizontal, full-width progress stepper — the shape of a form progress indicator:
 * numbered markers left to right, joined by a connector that fills up to the current step.
 *
 * It is a STATUS indicator, not a set of controls: an ordered list, the active step carrying
 * `aria-current="step"`, and per-step state exposed as visually-hidden text so "done" is never
 * conveyed by colour alone (the done marker also swaps its number for a check glyph, and the
 * current marker carries a ring).
 *
 * Responsive strategy — no horizontal scroll, no truncation. Every marker stays on screen at
 * every width (eight markers still fit a 320px viewport), and below 780px the labels of
 * the non-current steps become visually hidden rather than `display:none`, so the
 * bar degrades into "marker rail + current label" without losing anything from the
 * accessibility tree. The `Passo n de N · <label>` summary above the rail is always rendered,
 * so the current position is readable at any width and by any assistive technology.
 */
import type { ReactNode } from 'react';
import { useT } from '../i18n';
import { Check } from './icons';
import { TooltipText } from './Tooltip';

export interface StepperStep<T extends string> {
  id: T;
  label: string;
}

interface StepperProps<T extends string> {
  steps: readonly StepperStep<T>[];
  /** The step currently reached. An id outside `steps` renders every step as upcoming. */
  current: T;
  /** Accessible name for the list (e.g. the card title it sits under). */
  ariaLabel: string;
}

type StepState = 'done' | 'current' | 'upcoming';

export function Stepper<T extends string>({ steps, current, ariaLabel }: StepperProps<T>) {
  const t = useT();
  const currentIdx = steps.findIndex((step) => step.id === current);
  const currentLabel = currentIdx >= 0 ? steps[currentIdx].label : null;

  const stateOf = (i: number): StepState =>
    currentIdx >= 0 && i < currentIdx ? 'done' : i === currentIdx ? 'current' : 'upcoming';

  const statusText = (state: StepState): ReactNode => {
    if (state === 'done') return t('stepper.status.done');
    if (state === 'current') return t('stepper.status.current');
    return null;
  };

  return (
    <div className="stepper">
      {currentLabel ? (
        <p className="stepper__summary">
          <span className="stepper__summary-count">
            {t('stepper.progress', { current: currentIdx + 1, total: steps.length })}
          </span>
          <span className="stepper__summary-label">{currentLabel}</span>
        </p>
      ) : null}
      <ol className="stepper__track" aria-label={ariaLabel}>
        {steps.map((step, i) => {
          const state = stateOf(i);
          const status = statusText(state);
          return (
            <li
              key={step.id}
              className="stepper__step"
              data-state={state}
              aria-current={state === 'current' ? 'step' : undefined}
            >
              <span className="stepper__marker" aria-hidden="true">
                {state === 'done' ? <Check /> : i + 1}
              </span>
              {/* The label is normally shown in full, so the reveal is attached only if a
                  narrow rail actually ellipsises it (t31, replacing a native `title` that
                  duplicated the visible text on every step). Not a tab stop: the full label
                  is in the DOM either way, so assistive tech already reads it. */}
              <TooltipText className="stepper__label" label={step.label} onlyWhenClipped>
                {step.label}
              </TooltipText>
              {status ? <span className="sr-only">{status}</span> : null}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
