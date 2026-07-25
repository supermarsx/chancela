/**
 * Copy used only by the Citizen Card bridge host page.
 *
 * Keeping this small fallback beside the page lets the isolated route land without changing the
 * shared locale catalogues. Portuguese is the product locale; every other active locale receives
 * the complete English fallback.
 */
import { useMemo } from 'react';
import { interpolate, type TParams } from '../../i18n/interpolate';
import { useActiveLocale } from '../../i18n/useT';

const citizenCardBridgePagePtPT = {
  'ccBridge.page.title': 'Ponte do Cartão de Cidadão',
  'ccBridge.page.back': 'Fornecedores de assinatura',
  'ccBridge.page.confirm.title': 'Testar a chave do Cartão de Cidadão?',
  'ccBridge.page.confirm.intro':
    'O Cartão de Cidadão poderá pedir confirmação no leitor. A aplicação regista o pedido na auditoria de segurança, assina apenas um desafio efémero em memória, verifica-o localmente e regista o resultado; não assina nem guarda qualquer documento.',
  'ccBridge.page.confirm.action': 'Testar chave',
  'ccBridge.page.confirm.pending': 'A testar chave…',
  'ccBridge.page.statusError':
    'Não foi possível obter o diagnóstico seguro da ponte do Cartão de Cidadão.',
  'ccBridge.page.probeError':
    'Não foi possível concluir o teste seguro da chave do Cartão de Cidadão.',
} as const;

type CitizenCardBridgePageCopyKey = keyof typeof citizenCardBridgePagePtPT;

const citizenCardBridgePageEnglish = {
  'ccBridge.page.title': 'Citizen Card bridge',
  'ccBridge.page.back': 'Signing providers',
  'ccBridge.page.confirm.title': 'Test the Citizen Card key?',
  'ccBridge.page.confirm.intro':
    'The Citizen Card may request confirmation on the reader. The application records the request in the security audit, signs only an ephemeral in-memory challenge, verifies it locally, and records the outcome; it does not sign or store a document.',
  'ccBridge.page.confirm.action': 'Test key',
  'ccBridge.page.confirm.pending': 'Testing key…',
  'ccBridge.page.statusError': 'The secure Citizen Card bridge diagnostics could not be loaded.',
  'ccBridge.page.probeError': 'The secure Citizen Card key test could not be completed.',
} as const satisfies Record<CitizenCardBridgePageCopyKey, string>;

export function useCitizenCardBridgePageT(): (
  key: CitizenCardBridgePageCopyKey,
  params?: TParams,
) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? citizenCardBridgePagePtPT : citizenCardBridgePageEnglish;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
