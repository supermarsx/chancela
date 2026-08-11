import { cleanup, fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderWithProviders } from '../../test/utils';
import { ptPT } from '../../i18n/locales/pt-PT';
import { pairingSharePtPT } from '../../i18n/pairingShareFallback';
import { PairingShareSettingsCard } from './PairingShareSettingsCard';

afterEach(cleanup);

function renderCard() {
  return renderWithProviders(
    <PairingShareSettingsCard
      emailEnabled
      whatsappEnabled={false}
      externalSignatureNoticeSnoozeDays={90}
      onEmailEnabledChange={vi.fn()}
      onWhatsappEnabledChange={vi.fn()}
      onExternalSignatureNoticeSnoozeDaysChange={vi.fn()}
    />,
  );
}

describe('PairingShareSettingsCard', () => {
  it('renders established settings rows and emits bounded policy changes', () => {
    const onEmailEnabledChange = vi.fn();
    const onWhatsappEnabledChange = vi.fn();
    const onExternalSignatureNoticeSnoozeDaysChange = vi.fn();

    renderWithProviders(
      <PairingShareSettingsCard
        emailEnabled
        whatsappEnabled={false}
        externalSignatureNoticeSnoozeDays={90}
        onEmailEnabledChange={onEmailEnabledChange}
        onWhatsappEnabledChange={onWhatsappEnabledChange}
        onExternalSignatureNoticeSnoozeDaysChange={onExternalSignatureNoticeSnoozeDaysChange}
      />,
    );

    fireEvent.click(screen.getByRole('switch', { name: 'Partilha de emparelhamento por email' }));
    fireEvent.click(
      screen.getByRole('switch', { name: 'Partilha de emparelhamento por WhatsApp' }),
    );
    fireEvent.change(
      screen.getByLabelText('Ocultar temporariamente avisos de assinatura externa'),
      { target: { value: '5000' } },
    );

    expect(onEmailEnabledChange).toHaveBeenCalledWith(false);
    expect(onWhatsappEnabledChange).toHaveBeenCalledWith(true);
    expect(onExternalSignatureNoticeSnoozeDaysChange).toHaveBeenCalledWith(3650);
  });

  /**
   * The two switch explanations moved off the card face and behind a help glyph. The risk that
   * move carries is not visual — it is that the sentence stops being announced with the control
   * and becomes a mouse-only affordance, so these assert the association and the tab stop rather
   * than the absence of the paragraph alone.
   */
  describe('the switch explanations ride a help glyph, not a caption line', () => {
    it('gives each switch a real, named button as the route to its explanation', () => {
      renderCard();
      const triggers = screen.getAllByRole('button', { name: ptPT['common.help'] });
      expect(triggers.length).toBe(2);
      for (const trigger of triggers) {
        // A real button: keyboard-reachable by construction, and not a `div` with a click handler.
        expect(trigger.tagName).toBe('BUTTON');
        // `type="button"`, or the glyph would submit the settings form it sits in.
        expect(trigger.getAttribute('type')).toBe('button');
        trigger.focus();
        expect(document.activeElement).toBe(trigger);
      }
    });

    it('announces each explanation WITH its switch, not only with the glyph', () => {
      const { container } = renderCard();
      const rows = [
        {
          label: pairingSharePtPT['settings.pairingShare.email.label'],
          copy: pairingSharePtPT['settings.pairingShare.email.hint'],
        },
        {
          label: pairingSharePtPT['settings.pairingShare.whatsapp.label'],
          copy: pairingSharePtPT['settings.pairingShare.whatsapp.hint'],
        },
      ];
      for (const row of rows) {
        const control = screen.getByRole('switch', { name: row.label });
        const describedBy = control.getAttribute('aria-describedby');
        expect(describedBy).toBeTruthy();
        // The reference resolves to a mounted node — an orphaned id announces nothing.
        const bubble = container.ownerDocument.getElementById(describedBy as string);
        expect(bubble?.getAttribute('role')).toBe('tooltip');
        expect(bubble?.textContent).toBe(row.copy);
      }
    });

    it('leaves the switch rows without a caption paragraph', () => {
      const { container } = renderCard();
      // The snooze `Field` keeps its inline hint — it states the accepted range, which is needed
      // to fill the field — so the count is one, not zero.
      const hints = [...container.querySelectorAll('.field__hint')].map((n) => n.textContent);
      expect(hints).toEqual([pairingSharePtPT['settings.pairingShare.snooze.hint']]);
    });
  });
});
