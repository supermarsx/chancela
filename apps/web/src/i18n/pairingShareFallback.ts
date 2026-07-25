/**
 * Additive copy for pairing invitation share actions and their instance-wide admin policy.
 * Kept outside the shared locale catalogs so this focused settings change does not require
 * touching every locale file; pt-PT is the reviewed source and other locales receive English.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const pairingSharePtPT = {
  'pairing.share.actions': 'Enviar convite de emparelhamento',
  'pairing.share.email': 'Enviar por email',
  'pairing.share.whatsapp': 'Enviar por WhatsApp',
  'pairing.share.help':
    'Abre um rascunho noutra aplicação. Nada é enviado até escolher o destinatário e confirmar o envio. Se nada abrir, use Copiar ligação.',
  'pairing.share.disabled':
    'A partilha de convites foi desativada pelo administrador. Ainda pode digitalizar o código QR ou copiar a ligação.',
  'pairing.share.subject': 'Convite para emparelhar um telemóvel com o Chancela',
  'pairing.share.message':
    'Abra esta ligação de utilização única para emparelhar o telemóvel com o Chancela:\n\n{link}\n\nA ligação expira brevemente. Envie-a apenas à pessoa que deve emparelhar este dispositivo.',
  'pairing.share.openingEmail':
    'A abrir um rascunho de email. Se nada abrir, copie a ligação de emparelhamento.',
  'pairing.share.openingWhatsapp':
    'A abrir o WhatsApp. Escolha o destinatário e confirme o envio; se nada abrir, copie a ligação.',
  'pairing.share.failed':
    'Não foi possível abrir a aplicação de partilha. Copie a ligação de emparelhamento e envie-a manualmente.',
  'settings.pairingShare.cardTitle': 'Convites e avisos',
  'settings.pairingShare.email.label': 'Partilha de emparelhamento por email',
  'settings.pairingShare.email.hint':
    'Mostra uma ação que abre um rascunho no cliente de email. O utilizador continua a escolher o destinatário e a enviar.',
  'settings.pairingShare.whatsapp.label': 'Partilha de emparelhamento por WhatsApp',
  'settings.pairingShare.whatsapp.hint':
    'Mostra uma ação que abre o WhatsApp com a ligação preenchida. O utilizador continua a escolher o destinatário e a enviar.',
  'settings.pairingShare.snooze.label': 'Ocultar temporariamente avisos de assinatura externa',
  'settings.pairingShare.snooze.hint':
    'Número de dias usado pela ação temporária de ocultar. O intervalo permitido é de 1 a 3650 dias.',
} as const;

export type PairingShareCopyKey = keyof typeof pairingSharePtPT;

export const pairingShareEnglish = {
  'pairing.share.actions': 'Send pairing invitation',
  'pairing.share.email': 'Send by email',
  'pairing.share.whatsapp': 'Send by WhatsApp',
  'pairing.share.help':
    'Opens a draft in another app. Nothing is sent until you choose the recipient and confirm sending. If nothing opens, use Copy link.',
  'pairing.share.disabled':
    'Invitation sharing was disabled by an administrator. You can still scan the QR code or copy the link.',
  'pairing.share.subject': 'Invitation to pair a phone with Chancela',
  'pairing.share.message':
    'Open this single-use link to pair the phone with Chancela:\n\n{link}\n\nThe link expires shortly. Send it only to the person who should pair this device.',
  'pairing.share.openingEmail': 'Opening an email draft. If nothing opens, copy the pairing link.',
  'pairing.share.openingWhatsapp':
    'Opening WhatsApp. Choose the recipient and confirm sending; if nothing opens, copy the link.',
  'pairing.share.failed':
    'The sharing app could not be opened. Copy the pairing link and send it manually.',
  'settings.pairingShare.cardTitle': 'Invitations and notices',
  'settings.pairingShare.email.label': 'Share pairing invitations by email',
  'settings.pairingShare.email.hint':
    'Shows an action that opens a draft in the email client. The user still chooses the recipient and sends it.',
  'settings.pairingShare.whatsapp.label': 'Share pairing invitations by WhatsApp',
  'settings.pairingShare.whatsapp.hint':
    'Shows an action that opens WhatsApp with the link filled in. The user still chooses the recipient and sends it.',
  'settings.pairingShare.snooze.label': 'Temporarily hide external-signing notices',
  'settings.pairingShare.snooze.hint':
    'Number of days used by the temporary hide action. The allowed range is 1 to 3650 days.',
} as const satisfies Record<PairingShareCopyKey, string>;

export function usePairingShareT(): (key: PairingShareCopyKey, params?: TParams) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? pairingSharePtPT : pairingShareEnglish;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
