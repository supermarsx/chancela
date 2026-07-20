import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { Stepper, type StepperStep } from './Stepper';

afterEach(cleanup);

// The real act lifecycle shape: eight steps, which is what makes the responsive
// behaviour load-bearing rather than theoretical.
const STEPS: StepperStep<string>[] = [
  { id: 'Draft', label: 'Rascunho' },
  { id: 'Review', label: 'Em revisão' },
  { id: 'Convened', label: 'Convocada' },
  { id: 'Deliberated', label: 'Deliberada' },
  { id: 'TextApproved', label: 'Texto aprovado' },
  { id: 'Signing', label: 'Em assinatura' },
  { id: 'Sealed', label: 'Selada' },
  { id: 'Archived', label: 'Arquivada' },
];

function items(): HTMLElement[] {
  return within(screen.getByRole('list', { name: 'Ciclo de vida' })).getAllByRole('listitem');
}

// Same indirect dynamic import as Skeleton.test.tsx / books.test.tsx: the web tsconfig
// carries no @types/node.
async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  // Normalized to LF: the checked-out file may carry CRLF on Windows.
  return readFileSync('src/theme.css', 'utf8').replace(/\r\n/g, '\n');
}

describe('Stepper', () => {
  it('renders one horizontal list item per step, in order', () => {
    render(<Stepper steps={STEPS} current="Convened" ariaLabel="Ciclo de vida" />);
    expect(items().map((li) => li.querySelector('.stepper__label')?.textContent)).toEqual(
      STEPS.map((s) => s.label),
    );
  });

  it('marks the current step and distinguishes completed from upcoming steps', () => {
    render(<Stepper steps={STEPS} current="Deliberated" ariaLabel="Ciclo de vida" />);
    const lis = items();

    expect(lis.map((li) => li.dataset.state)).toEqual([
      'done',
      'done',
      'done',
      'current',
      'upcoming',
      'upcoming',
      'upcoming',
      'upcoming',
    ]);

    // Only the current step carries aria-current, and it is the one the eye lands on.
    expect(lis.filter((li) => li.getAttribute('aria-current') === 'step')).toHaveLength(1);
    expect(lis[3].getAttribute('aria-current')).toBe('step');

    // State is never colour-only: done steps swap the number for a check glyph, and both
    // done and current carry visually-hidden status text.
    expect(lis[0].querySelector('.stepper__marker svg')).toBeTruthy();
    expect(lis[0].querySelector('.sr-only')?.textContent).toBe('concluído');
    expect(lis[3].querySelector('.sr-only')?.textContent).toBe('passo atual');
    // Upcoming steps show their position number and claim no status.
    expect(lis[4].querySelector('.stepper__marker')?.textContent).toBe('5');
    expect(lis[4].querySelector('.sr-only')).toBeNull();
  });

  it('summarises the position in text so it is readable without the labels', () => {
    render(<Stepper steps={STEPS} current="TextApproved" ariaLabel="Ciclo de vida" />);
    expect(screen.getByText('Passo 5 de 8')).toBeTruthy();
    expect(document.querySelector('.stepper__summary-label')?.textContent).toBe('Texto aprovado');
  });

  it('treats an unknown current id as "nothing reached yet" rather than crashing', () => {
    render(<Stepper steps={STEPS} current="Nonsense" ariaLabel="Ciclo de vida" />);
    expect(items().every((li) => li.dataset.state === 'upcoming')).toBe(true);
    expect(document.querySelector('.stepper__summary')).toBeNull();
  });

  // --- Responsive contract -------------------------------------------------------
  // The chosen strategy is "always show every marker; hide only the non-current LABELS
  // below 780px" — no horizontal scroll, no truncation. jsdom has no cascade, so the two
  // halves are asserted separately: the DOM keeps every label at every width, and the
  // stylesheet hides them visually without removing them from the accessibility tree.

  it('keeps every step label in the DOM, so the compact rail loses no information', () => {
    render(<Stepper steps={STEPS} current="Signing" ariaLabel="Ciclo de vida" />);
    for (const step of STEPS) {
      const label = screen.getByText(step.label, { selector: '.stepper__label' });
      expect(label.textContent).toBe(step.label);
      // t31: no native `title` duplicating the visible label; the reveal is attached only
      // when the rail is narrow enough to actually ellipsise it.
      expect(label.getAttribute('title')).toBeNull();
    }
  });

  it('hides narrow-width labels visually, never with display:none', async () => {
    const css = await themeCss();
    const compact = css.slice(css.indexOf('/* Compact rail:'));
    const block = compact.slice(0, compact.indexOf('\n  }\n}') + 6);
    expect(block.length).toBeGreaterThan(0);

    expect(block).toContain('@media (max-width: 780px)');
    expect(block).toContain(".stepper__step:not([data-state='current']) .stepper__label");
    // Visually-hidden (clip), not display:none — a screen reader still reads every step.
    expect(block).toContain('clip: rect(0, 0, 0, 0)');
    expect(block).not.toContain('display: none');
    // The markers themselves are never hidden, so the progress rail survives at any width.
    expect(block).not.toContain('.stepper__marker');
  });

  it('lays the track out horizontally at full width with equal-width steps', async () => {
    const css = await themeCss();
    const track = css.slice(css.indexOf('.stepper__track {'));
    expect(track.slice(0, track.indexOf('}'))).toContain('display: flex');
    expect(track.slice(0, track.indexOf('}'))).toContain('width: 100%');

    const step = css.slice(css.indexOf('.stepper__step {'));
    expect(step.slice(0, step.indexOf('}'))).toContain('flex: 1 1 0');
    // `min-width: 0` is what stops eight steps from overflowing their container.
    expect(step.slice(0, step.indexOf('}'))).toContain('min-width: 0');
  });

  it('fills the connector up to the current step only', async () => {
    const css = await themeCss();
    const connector = css.slice(css.indexOf(".stepper__step[data-state='done']::before"));
    const block = connector.slice(0, connector.indexOf('}') + 1);
    expect(block).toContain("[data-state='current']::before");
    expect(block).toContain('background: var(--accent-strong)');
    // No hard-coded colours anywhere in the stepper block.
    const stepper = css.slice(css.indexOf('.stepper {'), css.indexOf('.ai-review__meta'));
    expect(stepper).not.toMatch(/:\s*#[0-9a-f]{3,8}/i);
    expect(stepper).not.toMatch(/\b(rgb|hsl)a?\(/i);
  });
});
