import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { Wrapper } from '../test/utils';
import { FieldHelp } from './FieldHelp';

afterEach(cleanup);

describe('FieldHelp', () => {
  it('renders a borderless Info trigger whose accessible name defaults to "Ajuda"', () => {
    render(
      <Wrapper>
        <FieldHelp text="Explicação do campo." />
      </Wrapper>,
    );
    // The trigger is a real button; its accessible name is the generic "Ajuda" (the
    // explanation rides on aria-describedby, not the name).
    const trigger = screen.getByRole('button', { name: 'Ajuda' });
    expect(trigger).toBeTruthy();
    expect(trigger.className).toContain('field-help');
  });

  it('carries the explanation in the tooltip bubble and links it via aria-describedby', () => {
    render(
      <Wrapper>
        <FieldHelp text="Explicação do campo." />
      </Wrapper>,
    );
    const trigger = screen.getByRole('button', { name: 'Ajuda' });
    // The bubble is always mounted (role="tooltip") so the description never dangles.
    const bubble = screen.getByRole('tooltip');
    expect(bubble.textContent).toBe('Explicação do campo.');
    // The trigger's aria-describedby resolves to the bubble carrying the sentence.
    const describedBy = trigger.getAttribute('aria-describedby');
    expect(describedBy).toBeTruthy();
    expect(describedBy).toBe(bubble.id);
  });

  it('accepts a custom accessible name for the trigger', () => {
    render(
      <Wrapper>
        <FieldHelp text="Explicação." label="Sobre o tema" />
      </Wrapper>,
    );
    expect(screen.getByRole('button', { name: 'Sobre o tema' })).toBeTruthy();
  });
});
