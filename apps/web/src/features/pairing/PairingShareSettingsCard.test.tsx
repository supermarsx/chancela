import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { renderWithProviders } from '../../test/utils';
import { PairingShareSettingsCard } from './PairingShareSettingsCard';

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
});
