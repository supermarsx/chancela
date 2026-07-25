/**
 * Dedicated provider-management page and safe-probe copy.
 *
 * Kept in the established locale-aware fallback shape while the large shared catalogs are under
 * parallel ownership: reviewed pt-PT source copy, English everywhere else.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const providerCredentialsPtPT = {
  'providerCredentials.page.createTitle': 'Nova credencial de assinatura',
  'providerCredentials.page.editTitle': 'Editar credencial de assinatura',
  'providerCredentials.page.back': 'Fornecedores de assinatura',
  'providerCredentials.page.savedConfiguration': 'O teste usa a configuração já guardada.',
  'providerCredentials.action.test': 'Testar',
  'providerCredentials.action.testing': 'A testar…',
  'providerCredentials.probe.pkcs12.permission':
    'A operação de teste PKCS#12 requer a permissão signing.perform.',
  'providerCredentials.probe.pkcs12.confirmTitle': 'Testar a chave privada PKCS#12?',
  'providerCredentials.probe.pkcs12.confirmIntro':
    'Este teste não assina um documento, mas usa realmente a chave privada guardada para assinar um desafio aleatório e separado por domínio.',
  'providerCredentials.probe.pkcs12.confirm': 'Executar operação de chave',
  'providerCredentials.probe.pkcs12.pending': 'A executar…',
  'providerCredentials.probe.title': 'Resultado do teste',
  'providerCredentials.probe.ok': 'Operacional',
  'providerCredentials.probe.failed': 'Falhou',
  'providerCredentials.probe.interactive': 'Requer interação',
  'providerCredentials.probe.contacted': 'Fornecedor contactado',
  'providerCredentials.probe.keyOperation': 'Operação de chave privada',
  'providerCredentials.probe.signerAuthorization': 'Autorização do signatário pedida',
  'providerCredentials.probe.documentSigned': 'Documento assinado',
  'providerCredentials.probe.legalValidity': 'Validade jurídica alegada',
  'providerCredentials.probe.qualifiedStatus': 'Estatuto qualificado determinado',
  'providerCredentials.probe.yes': 'Sim',
  'providerCredentials.probe.no': 'Não',
  'providerCredentials.probe.disclaimer':
    'Este teste não assina documentos, não determina o estatuto qualificado e não faz qualquer alegação de validade jurídica.',
  'providerCredentials.probe.duration': '{duration} ms · {timestamp}',
  'providerCredentials.probe.check.passed': 'Passou',
  'providerCredentials.probe.check.failed': 'Falhou',
  'providerCredentials.probe.check.skipped': 'Não executado',
  'providerCredentials.error.invalidRoute': 'O endereço desta credencial não é válido.',
  'providerCredentials.error.notFound': 'A credencial pedida não existe.',
} as const;

export type ProviderCredentialsCopyKey = keyof typeof providerCredentialsPtPT;

export const providerCredentialsEnglish = {
  'providerCredentials.page.createTitle': 'New signing credential',
  'providerCredentials.page.editTitle': 'Edit signing credential',
  'providerCredentials.page.back': 'Signing providers',
  'providerCredentials.page.savedConfiguration': 'The test uses the configuration already saved.',
  'providerCredentials.action.test': 'Test',
  'providerCredentials.action.testing': 'Testing…',
  'providerCredentials.probe.pkcs12.permission':
    'The PKCS#12 test operation requires the signing.perform permission.',
  'providerCredentials.probe.pkcs12.confirmTitle': 'Test the PKCS#12 private key?',
  'providerCredentials.probe.pkcs12.confirmIntro':
    'This test does not sign a document, but it really uses the stored private key to sign a random, domain-separated challenge.',
  'providerCredentials.probe.pkcs12.confirm': 'Run key operation',
  'providerCredentials.probe.pkcs12.pending': 'Running…',
  'providerCredentials.probe.title': 'Test result',
  'providerCredentials.probe.ok': 'Operational',
  'providerCredentials.probe.failed': 'Failed',
  'providerCredentials.probe.interactive': 'Interaction required',
  'providerCredentials.probe.contacted': 'Provider contacted',
  'providerCredentials.probe.keyOperation': 'Private-key operation',
  'providerCredentials.probe.signerAuthorization': 'Signer authorisation requested',
  'providerCredentials.probe.documentSigned': 'Document signed',
  'providerCredentials.probe.legalValidity': 'Legal validity claimed',
  'providerCredentials.probe.qualifiedStatus': 'Qualified status determined',
  'providerCredentials.probe.yes': 'Yes',
  'providerCredentials.probe.no': 'No',
  'providerCredentials.probe.disclaimer':
    'This test does not sign a document, determine qualified status, or make any claim of legal validity.',
  'providerCredentials.probe.duration': '{duration} ms · {timestamp}',
  'providerCredentials.probe.check.passed': 'Passed',
  'providerCredentials.probe.check.failed': 'Failed',
  'providerCredentials.probe.check.skipped': 'Not run',
  'providerCredentials.error.invalidRoute': 'This credential address is invalid.',
  'providerCredentials.error.notFound': 'The requested credential does not exist.',
} as const satisfies Record<ProviderCredentialsCopyKey, string>;

export function useProviderCredentialsT(): (
  key: ProviderCredentialsCopyKey,
  params?: TParams,
) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? providerCredentialsPtPT : providerCredentialsEnglish;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
