import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { Wrapper } from '../test/utils';
import { FieldHelp } from './FieldHelp';
import { Field, Input, Select, Toggle } from './index';

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

  it('describes the CONTROL, not only the glyph, when it sits in a Field', () => {
    // The defect t102-privacyux reported: `Field` put the explanation on the help button's own
    // `aria-describedby`, and that button is a separate tab stop. A screen-reader user tabbing
    // into the input — the normal way to reach a form control — heard the label and nothing else,
    // so every field tooltip in the app was decoration for anyone not using a mouse.
    render(
      <Wrapper>
        <Field label="Território" help="Marcador de território da lista, como PT ou EU.">
          {/* Deliberately NOT a bare child: the real call sites wrap the control in a row with a
              reset button, which is exactly why this cannot be fixed by cloning `children`. */}
          <div className="row">
            <Input aria-label="Território" />
            <button type="button">Repor</button>
          </div>
        </Field>
      </Wrapper>,
    );

    const bubble = screen.getByRole('tooltip');
    expect(bubble.textContent).toBe('Marcador de território da lista, como PT ou EU.');

    // The control is described by the sentence…
    const input = screen.getByLabelText('Território');
    expect(input.getAttribute('aria-describedby')?.split(' ')).toContain(bubble.id);
    // …and so is the glyph, pointing at the SAME node — the sentence is not duplicated in the
    // accessibility tree.
    expect(screen.getByRole('button', { name: 'Ajuda' }).getAttribute('aria-describedby')).toBe(
      bubble.id,
    );
  });

  it('reaches Select and Toggle too, and never replaces a describedby the caller set', () => {
    render(
      <Wrapper>
        <Field label="Nível" help="O nível mínimo que o servidor regista.">
          <Select
            aria-label="Nível"
            aria-describedby="caller-note"
            options={[{ value: 'info', label: 'info' }]}
          />
        </Field>
        <Field label="Ativa" help="Uma fonte desligada fica guardada mas é ignorada.">
          <Toggle checked label="Ativa" onChange={() => {}} />
        </Field>
      </Wrapper>,
    );

    const [levelBubble, toggleBubble] = screen.getAllByRole('tooltip');
    const select = screen.getByLabelText('Nível');
    // Merged, not overwritten: the call site's own description survives.
    expect(select.getAttribute('aria-describedby')?.split(' ')).toEqual([
      'caller-note',
      levelBubble.id,
    ]);
    expect(screen.getByRole('switch').getAttribute('aria-describedby')).toBe(toggleBubble.id);
  });

  it('leaves a control undescribed when its Field has no help sentence', () => {
    // An always-on provider would point every control in the app at a non-existent node.
    render(
      <Wrapper>
        <Field label="Nome">
          <Input aria-label="Nome" />
        </Field>
      </Wrapper>,
    );
    expect(screen.getByLabelText('Nome').getAttribute('aria-describedby')).toBeNull();
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
