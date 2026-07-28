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

  // --- CMD production test signature (t51-e3/t69) ---------------------------------
  // A DIAGNOSTIC, but not a safe probe: a completed test costs one real, legally binding
  // qualified signature against AMA's live production service. Kept apart from the
  // `providerCredentials.probe.*` copy above on purpose, so the two never read as the same test.
  'providerCredentials.cmdTest.button': 'Testar assinatura real (produção)',
  'providerCredentials.cmdTest.permission':
    'Requer as permissões signing.configure e signing.perform.',
  'providerCredentials.cmdTest.pending': 'Código enviado',
  'providerCredentials.cmdTest.pendingBody':
    'Foi enviado um código por SMS para «{phone}». Introduza-o para concluir o teste.',
  'providerCredentials.cmdTest.confirmButton': 'Introduzir código recebido',
  'providerCredentials.cmdTest.initiateTitle': 'Testar a Chave Móvel Digital em produção?',
  'providerCredentials.cmdTest.initiateIntro1':
    'Este teste produz uma assinatura eletrónica qualificada real, contra o serviço de produção da AMA, com o telemóvel e o PIN indicados abaixo. Não existe modo de simulação: o que aqui se assina é apenas uma folha gerada pela aplicação que descreve o próprio teste, e a assinatura não conta para a abertura de qualquer livro nem para a assinatura de qualquer ato.',
  'providerCredentials.cmdTest.initiateIntro2': 'Credencial a testar: «{label}».',
  'providerCredentials.cmdTest.initiateConfirm': 'Enviar código',
  'providerCredentials.cmdTest.initiatePending': 'A enviar código…',
  'providerCredentials.cmdTest.otpSentToast': 'Código enviado por SMS.',
  'providerCredentials.cmdTest.phoneLabel': 'Número de telemóvel',
  'providerCredentials.cmdTest.phoneHint': 'Formato +351 XXXXXXXXX.',
  'providerCredentials.cmdTest.pinLabel': 'PIN de assinatura',
  'providerCredentials.cmdTest.confirmTitle': 'Confirmar a assinatura de teste',
  'providerCredentials.cmdTest.confirmIntro':
    'Introduza o código recebido por SMS em «{phone}». Ao confirmar, é produzida a assinatura eletrónica qualificada real.',
  'providerCredentials.cmdTest.confirmConfirm': 'Confirmar código',
  'providerCredentials.cmdTest.confirmPending': 'A confirmar…',
  'providerCredentials.cmdTest.otpLabel': 'Código recebido por SMS',
  'providerCredentials.cmdTest.signedToast': 'Assinatura de teste concluída.',
  'providerCredentials.cmdTest.resultSigned': 'Teste de produção concluído',
  'providerCredentials.cmdTest.legalEffect': 'Efeito jurídico',
  'providerCredentials.cmdTest.legalEffectNone': 'Nenhum — não é uma ata nem um termo',
  'providerCredentials.cmdTest.countsBookOpening': 'Conta para a abertura de um livro',
  'providerCredentials.cmdTest.countsActSignature': 'Conta para a assinatura de um ato',
  'providerCredentials.cmdTest.digest': 'Digesto do PDF assinado',
  'providerCredentials.cmdTest.signedAt': 'Assinado em',
  'providerCredentials.cmdTest.credentialSource': 'Origem da credencial',
  'providerCredentials.cmdTest.credentialSourceStored': 'Credencial guardada no painel',
  'providerCredentials.cmdTest.credentialSourceEnv': 'Variáveis de ambiente do servidor',
  'providerCredentials.cmdTest.trustedList': 'Estado na lista de confiança',
  'providerCredentials.cmdTest.timestamped': 'Com carimbo temporal',
  'providerCredentials.cmdTest.disclaimer':
    'Esta assinatura é real e qualificada, mas cobre apenas a folha de teste gerada pela aplicação. Não abre nem encerra livros, não assina atos e não é um registo da atividade da organização.',
  'providerCredentials.cmdTest.download': 'Transferir PDF assinado',
  'providerCredentials.cmdTest.downloadPending': 'A transferir…',
  'providerCredentials.cmdTest.newTest': 'Testar novamente',

  // --- Self-validation: what the application's own validator says about what it produced -------
  // Each coverage verdict is its OWN sentence rather than a token dropped into a shared one:
  // pt-PT inflects, and the verdicts differ in gender and number.
  'providerCredentials.cmdTest.selfValidation': 'Verificação pela própria aplicação',
  'providerCredentials.cmdTest.selfValidationHint':
    'A aplicação voltou a ler o PDF que acabou de produzir e verificou a assinatura com o mesmo validador que usa para validar documentos.',
  'providerCredentials.cmdTest.selfValidationVerifies': 'Assinatura verificada',
  'providerCredentials.cmdTest.selfValidationCovers': 'Cobre o documento apresentado',
  'providerCredentials.cmdTest.selfValidationCoverage': 'Âmbito da assinatura',
  'providerCredentials.cmdTest.selfValidationTimestamp': 'Carimbo temporal encontrado no ficheiro',
  'providerCredentials.cmdTest.selfValidationError': 'Motivo',
  'providerCredentials.cmdTest.selfValidationOk': 'A aplicação verificou a assinatura que produziu.',
  'providerCredentials.cmdTest.selfValidationBad':
    'A assinatura qualificada foi produzida e está conservada, mas a aplicação não a conseguiu verificar. O ficheiro está disponível para transferir e analisar.',
  'providerCredentials.cmdTest.coverage.whole_document': 'Todo o ficheiro',
  'providerCredentials.cmdTest.coverage.ltv_augmented_signed_revision':
    'A revisão assinada, com material de validação a longo prazo acrescentado depois',
  'providerCredentials.cmdTest.coverage.altered_after_signing':
    'Apenas a revisão assinada; o ficheiro foi alterado depois',
  'providerCredentials.cmdTest.coverage.malformed': 'Intervalo de bytes malformado',
  'providerCredentials.cmdTest.coverage.unrecognised':
    'Âmbito não reconhecido por esta versão da aplicação',
  'providerCredentials.cmdTest.coverage.unavailable': 'Não foi possível determinar',

  // --- The route from the safe probe to the real end-to-end test -------------------------------
  // An operator who ran the probe reads «live_provider_operation — Não executado» and has no way of
  // knowing where the real test lives. This section sits directly under that panel and says so.
  'providerCredentials.cmdTest.sectionTitle': 'Teste de ponta a ponta em produção',
  'providerCredentials.cmdTest.sectionIntro':
    'O teste acima verifica a configuração guardada e não contacta a Chave Móvel Digital: não existe operação de diagnóstico que não seja já uma assinatura. Para experimentar a integração de ponta a ponta, use o teste abaixo.',
  'providerCredentials.cmdTest.sectionWhatItDoes':
    'A aplicação gera um documento de exemplo em PDF/A cujo texto declara que é um teste, envia-lhe um código por SMS e, se o confirmar, produz sobre esse documento uma assinatura eletrónica qualificada real. No fim pode transferir o PDF assinado e ver o que o validador da própria aplicação diz sobre ele.',
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

  // --- CMD production test signature (t51-e3/t69) ---------------------------------
  'providerCredentials.cmdTest.button': 'Test real signature (production)',
  'providerCredentials.cmdTest.permission': 'Requires the signing.configure and signing.perform permissions.',
  'providerCredentials.cmdTest.pending': 'Code sent',
  'providerCredentials.cmdTest.pendingBody':
    'An SMS code was sent to "{phone}". Enter it to complete the test.',
  'providerCredentials.cmdTest.confirmButton': 'Enter received code',
  'providerCredentials.cmdTest.initiateTitle': 'Test Chave Móvel Digital in production?',
  'providerCredentials.cmdTest.initiateIntro1':
    'This test produces a real qualified electronic signature, against AMA\'s live production service, with the phone and PIN below. There is no simulation mode: what is signed is only a sheet generated by the application describing the test itself, and the signature does not count toward opening any book or signing any act.',
  'providerCredentials.cmdTest.initiateIntro2': 'Credential under test: "{label}".',
  'providerCredentials.cmdTest.initiateConfirm': 'Send code',
  'providerCredentials.cmdTest.initiatePending': 'Sending code…',
  'providerCredentials.cmdTest.otpSentToast': 'Code sent by SMS.',
  'providerCredentials.cmdTest.phoneLabel': 'Phone number',
  'providerCredentials.cmdTest.phoneHint': 'Format +351 XXXXXXXXX.',
  'providerCredentials.cmdTest.pinLabel': 'Signature PIN',
  'providerCredentials.cmdTest.confirmTitle': 'Confirm the test signature',
  'providerCredentials.cmdTest.confirmIntro':
    'Enter the SMS code received at "{phone}". Confirming produces the real qualified electronic signature.',
  'providerCredentials.cmdTest.confirmConfirm': 'Confirm code',
  'providerCredentials.cmdTest.confirmPending': 'Confirming…',
  'providerCredentials.cmdTest.otpLabel': 'SMS code received',
  'providerCredentials.cmdTest.signedToast': 'Test signature completed.',
  'providerCredentials.cmdTest.resultSigned': 'Production test completed',
  'providerCredentials.cmdTest.legalEffect': 'Legal effect',
  'providerCredentials.cmdTest.legalEffectNone': 'None — not an ata nor a termo',
  'providerCredentials.cmdTest.countsBookOpening': 'Counts toward opening a book',
  'providerCredentials.cmdTest.countsActSignature': 'Counts toward signing an act',
  'providerCredentials.cmdTest.digest': 'Signed PDF digest',
  'providerCredentials.cmdTest.signedAt': 'Signed at',
  'providerCredentials.cmdTest.credentialSource': 'Credential source',
  'providerCredentials.cmdTest.credentialSourceStored': 'Credential stored in the admin panel',
  'providerCredentials.cmdTest.credentialSourceEnv': 'Server environment variables',
  'providerCredentials.cmdTest.trustedList': 'Trusted-list status',
  'providerCredentials.cmdTest.timestamped': 'Timestamped',
  'providerCredentials.cmdTest.disclaimer':
    'This signature is real and qualified, but covers only the test sheet generated by the application. It does not open or close any book, does not sign any act, and is not a record of the organisation\'s activity.',
  'providerCredentials.cmdTest.download': 'Download signed PDF',
  'providerCredentials.cmdTest.downloadPending': 'Downloading…',
  'providerCredentials.cmdTest.newTest': 'Test again',
  'providerCredentials.cmdTest.selfValidation': "Checked by the application itself",
  'providerCredentials.cmdTest.selfValidationHint':
    'The application read back the PDF it just produced and verified the signature with the same validator it uses to validate documents.',
  'providerCredentials.cmdTest.selfValidationVerifies': 'Signature verified',
  'providerCredentials.cmdTest.selfValidationCovers': 'Covers the document as displayed',
  'providerCredentials.cmdTest.selfValidationCoverage': 'Signature scope',
  'providerCredentials.cmdTest.selfValidationTimestamp': 'Timestamp found in the file',
  'providerCredentials.cmdTest.selfValidationError': 'Reason',
  'providerCredentials.cmdTest.selfValidationOk':
    'The application verified the signature it produced.',
  'providerCredentials.cmdTest.selfValidationBad':
    'The qualified signature was produced and is retained, but the application could not verify it. The file is available to download and inspect.',
  'providerCredentials.cmdTest.coverage.whole_document': 'The whole file',
  'providerCredentials.cmdTest.coverage.ltv_augmented_signed_revision':
    'The signed revision, with long-term validation material appended afterwards',
  'providerCredentials.cmdTest.coverage.altered_after_signing':
    'Only the signed revision; the file was altered afterwards',
  'providerCredentials.cmdTest.coverage.malformed': 'Malformed byte range',
  'providerCredentials.cmdTest.coverage.unrecognised':
    'A scope this version of the application does not recognise',
  'providerCredentials.cmdTest.coverage.unavailable': 'Could not be determined',
  'providerCredentials.cmdTest.sectionTitle': 'End-to-end production test',
  'providerCredentials.cmdTest.sectionIntro':
    'The test above checks the stored configuration and does not contact Chave Móvel Digital: there is no diagnostic operation that is not already a signature. To exercise the integration end to end, use the test below.',
  'providerCredentials.cmdTest.sectionWhatItDoes':
    'The application generates a sample PDF/A document whose own text states that it is a test, sends you a code by SMS and, if you confirm it, produces a real qualified electronic signature over that document. At the end you can download the signed PDF and see what the application\'s own validator makes of it.',
} as const satisfies Record<ProviderCredentialsCopyKey, string>;

export function useProviderCredentialsT(): (
  key: ProviderCredentialsCopyKey,
  params?: TParams,
) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? providerCredentialsPtPT : providerCredentialsEnglish;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
