/**
 * Copy owned by the Cartão de Cidadão desktop-bridge surface.
 *
 * This avoids editing shared locale catalogues while still resolving reviewed Portuguese copy for
 * pt-PT and English for every other active locale. It follows the small fallback-resolver pattern
 * used by other isolated feature lanes.
 */
import { useMemo } from 'react';
import { interpolate, type TParams } from '../../i18n/interpolate';
import { useActiveLocale } from '../../i18n/useT';

export const citizenCardBridgePtPT = {
  'ccBridge.title': 'Cartão de Cidadão',
  'ccBridge.refresh': 'Atualizar diagnósticos',
  'ccBridge.refreshPending': 'A atualizar…',
  'ccBridge.test': 'Testar chave de assinatura',
  'ccBridge.testPending': 'A testar chave…',
  'ccBridge.open': 'Verificar ponte local',
  'ccBridge.intro':
    'Verifica a ponte local entre a aplicação de secretária, o middleware e o leitor do Cartão de Cidadão. Nenhum leitor, certificado ou caminho do sistema é exposto nesta página.',
  'ccBridge.boundary.title': 'Limite do teste',
  'ccBridge.boundary.body':
    'O teste assina apenas um desafio efémero e verifica-o localmente. Não cria documento nem grava evento num livro de atas. O pedido e o resultado ficam registados no razão de segurança, sem identificadores do cartão, leitor ou certificado. Não faz qualquer declaração de validade legal ou de assinatura qualificada.',
  'ccBridge.permissions':
    'Necessita das permissões para configurar a assinatura e utilizar uma chave de assinatura.',
  'ccBridge.testUnavailable': 'O teste fica disponível quando a ponte local estiver disponível.',
  'ccBridge.empty': 'Atualize os diagnósticos para verificar a ponte local.',
  'ccBridge.table.caption': 'Diagnóstico da ponte local do Cartão de Cidadão',
  'ccBridge.table.component': 'Componente',
  'ccBridge.table.status': 'Estado',
  'ccBridge.desktop': 'Aplicação de secretária local',
  'ccBridge.middleware': 'Middleware do Cartão de Cidadão',
  'ccBridge.pcsc': 'PC/SC',
  'ccBridge.readers': 'Leitores',
  'ccBridge.card': 'Cartão inserido',
  'ccBridge.certificate': 'Certificado de assinatura selecionado',
  'ccBridge.issuer': 'Emissor e cadeia de confiança',
  'ccBridge.readiness': 'Prontidão para assinatura',
  'ccBridge.checkedAt': 'Verificado em',
  'ccBridge.readerCount': '{count} detetado(s)',
  'ccBridge.transport.local': 'Aplicação de secretária local',
  'ccBridge.status.ready': 'Pronto',
  'ccBridge.status.unavailable': 'Indisponível',
  'ccBridge.status.error': 'Erro',
  'ccBridge.status.notChecked': 'Por verificar',
  'ccBridge.status.injected': 'Ambiente de teste',
  'ccBridge.desktop.ready': 'A API está a executar-se na aplicação de secretária deste computador.',
  'ccBridge.desktop.unavailable':
    'Esta funcionalidade requer a aplicação de secretária no computador com o leitor.',
  'ccBridge.ready.ready': 'Todos os pré-requisitos técnicos e de confiança foram observados.',
  'ccBridge.ready.unavailable':
    'A ponte ainda não está pronta para assinar; reveja as verificações indicadas acima.',
  'ccBridge.probe.caption': 'Resultado do teste da ponte do Cartão de Cidadão',
  'ccBridge.probe.passed': 'Teste concluído',
  'ccBridge.probe.failed': 'Teste falhou',
  'ccBridge.probe.passedBody':
    'A chave de assinatura assinou e a aplicação verificou localmente um desafio efémero.',
  'ccBridge.probe.failedBody': 'Não foi possível assinar e verificar localmente o desafio efémero.',
  'ccBridge.probe.check': 'Verificação',
  'ccBridge.probe.result': 'Resultado',
  'ccBridge.probe.signatureVerified': 'Assinatura verificada',
  'ccBridge.probe.certificate': 'Certificado de assinatura',
  'ccBridge.probe.issuer': 'Emissor resolvido',
  'ccBridge.probe.securityAudit': 'Auditoria de segurança',
  'ccBridge.probe.securityAuditRecorded': 'Pedido e resultado registados',
  'ccBridge.probe.securityAuditMissing': 'Registo não confirmado',
  'ccBridge.probe.documentLedger': 'Livro do documento',
  'ccBridge.probe.documentLedgerWritten': 'Evento gravado',
  'ccBridge.probe.documentLedgerNotWritten': 'Nenhum evento gravado',
  'ccBridge.probe.algorithm': 'Algoritmo',
  'ccBridge.probe.diagnostic': 'Diagnóstico',
  'ccBridge.yes': 'Sim',
  'ccBridge.no': 'Não',
  'ccBridge.available': 'Disponível',
  'ccBridge.unavailable': 'Indisponível',
} as const;

export type CitizenCardBridgeCopyKey = keyof typeof citizenCardBridgePtPT;

export const citizenCardBridgeEnglish = {
  'ccBridge.title': 'Citizen Card',
  'ccBridge.refresh': 'Refresh diagnostics',
  'ccBridge.refreshPending': 'Refreshing…',
  'ccBridge.test': 'Test signing key',
  'ccBridge.testPending': 'Testing key…',
  'ccBridge.open': 'Check local bridge',
  'ccBridge.intro':
    'Checks the local bridge between the desktop app, middleware, and Citizen Card reader. No reader, certificate, or system path is exposed on this page.',
  'ccBridge.boundary.title': 'Test boundary',
  'ccBridge.boundary.body':
    'The test signs only an ephemeral challenge and verifies it locally. It creates no document and writes no event to a minute book. The request and outcome are recorded in the security ledger without card, reader, or certificate identifiers. It makes no legal-validity or qualified-signature claim.',
  'ccBridge.permissions': 'You need permission to configure signing and to use a signing key.',
  'ccBridge.testUnavailable': 'The test is available when the local bridge is available.',
  'ccBridge.empty': 'Refresh diagnostics to check the local bridge.',
  'ccBridge.table.caption': 'Citizen Card local bridge diagnostics',
  'ccBridge.table.component': 'Component',
  'ccBridge.table.status': 'Status',
  'ccBridge.desktop': 'Local desktop application',
  'ccBridge.middleware': 'Citizen Card middleware',
  'ccBridge.pcsc': 'PC/SC',
  'ccBridge.readers': 'Readers',
  'ccBridge.card': 'Card inserted',
  'ccBridge.certificate': 'Selected signing certificate',
  'ccBridge.issuer': 'Issuer and trust chain',
  'ccBridge.readiness': 'Signing readiness',
  'ccBridge.checkedAt': 'Checked at',
  'ccBridge.readerCount': '{count} detected',
  'ccBridge.transport.local': 'Local desktop application',
  'ccBridge.status.ready': 'Ready',
  'ccBridge.status.unavailable': 'Unavailable',
  'ccBridge.status.error': 'Error',
  'ccBridge.status.notChecked': 'Not checked',
  'ccBridge.status.injected': 'Test environment',
  'ccBridge.desktop.ready': 'The API is running in the desktop application on this computer.',
  'ccBridge.desktop.unavailable':
    'This feature requires the desktop application on the computer with the reader.',
  'ccBridge.ready.ready': 'All technical and trust prerequisites have been observed.',
  'ccBridge.ready.unavailable':
    'The bridge is not ready to sign yet; review the checks shown above.',
  'ccBridge.probe.caption': 'Citizen Card bridge test result',
  'ccBridge.probe.passed': 'Test completed',
  'ccBridge.probe.failed': 'Test failed',
  'ccBridge.probe.passedBody':
    'The signing key signed and the application locally verified an ephemeral challenge.',
  'ccBridge.probe.failedBody':
    'The application could not sign and locally verify the ephemeral challenge.',
  'ccBridge.probe.check': 'Check',
  'ccBridge.probe.result': 'Result',
  'ccBridge.probe.signatureVerified': 'Signature verified',
  'ccBridge.probe.certificate': 'Signing certificate',
  'ccBridge.probe.issuer': 'Issuer resolved',
  'ccBridge.probe.securityAudit': 'Security audit',
  'ccBridge.probe.securityAuditRecorded': 'Request and outcome recorded',
  'ccBridge.probe.securityAuditMissing': 'Record not confirmed',
  'ccBridge.probe.documentLedger': 'Document book',
  'ccBridge.probe.documentLedgerWritten': 'Event written',
  'ccBridge.probe.documentLedgerNotWritten': 'No event written',
  'ccBridge.probe.algorithm': 'Algorithm',
  'ccBridge.probe.diagnostic': 'Diagnostic',
  'ccBridge.yes': 'Yes',
  'ccBridge.no': 'No',
  'ccBridge.available': 'Available',
  'ccBridge.unavailable': 'Unavailable',
} as const satisfies Record<CitizenCardBridgeCopyKey, string>;

export function useCitizenCardBridgeT(): (
  key: CitizenCardBridgeCopyKey,
  params?: TParams,
) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? citizenCardBridgePtPT : citizenCardBridgeEnglish;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
