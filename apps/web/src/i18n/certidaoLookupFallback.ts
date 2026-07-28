/**
 * Ferramentas → "Certidão de Registo Permanente" copy — the lookup-only consultation tool (t95).
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are held under a single-writer serial lock for the
 * duration of the running i18n batch, so this change may not add the usual "one import + one spread
 * line per locale" wiring. The module owns its keys end to end and exposes its own locale-aware
 * resolver ({@link useCertidaoLookupT}), exactly as `trustSectionsFallback.ts` /
 * `notificationsRetentionFallback.ts` do. Folding these in later is a mechanical spread.
 *
 * **"Certidão de Registo Permanente" is a legal instrument name and is written out in full**, never
 * abbreviated into an invented short form and never translated in the non-pt locales — the English
 * fallback keeps the Portuguese instrument name and explains it, rather than coining "Permanent
 * Registry Certificate", which names no real document.
 *
 * **The failure copy is the point of this file.** Each `error.*` key is keyed by the API's stable
 * `code`, and the sentences are deliberately NOT interchangeable:
 *
 *  - `unreachable` must never read as a statement about the company. Not getting an answer and
 *    getting a negative answer are different facts, and only `certidaoNotFound` is the latter.
 *  - `codeRejected` carries the registry's own disjunction ("inválido **ou** expirado"). The
 *    service refuses to say which, so the copy does not pick one on its behalf.
 *  - `config` says the fault is local, so an operator does not go and report an outage to a
 *    government service that is working fine.
 *
 * No noun is interpolated into an inflected sentence anywhere in this file (memory
 * `i18n-interpolated-nouns-break-agreement`): where copy varies by field, it varies by *key*.
 *
 * pt-PT is the source. No invented anglicisms (memory `pt-pt-no-invented-anglicisms`).
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const certidaoLookupPtPT = {
  // --- Shell -------------------------------------------------------------------------------
  'tools.section.certidao': 'Certidão de Registo Permanente',
  'certidaoLookup.title': 'Consultar uma Certidão de Registo Permanente',
  'certidaoLookup.intro':
    'Introduza o código de acesso para consultar a certidão no registo. Esta ferramenta apenas consulta.',

  // --- The lookup-only promise, stated before and after ------------------------------------
  // The user's whole reason for asking for a separate tool: it does not import. Said up front so
  // it is not a surprise, and repeated over the result so it is not forgotten while reading.
  'certidaoLookup.notice.title': 'Consulta apenas',
  'certidaoLookup.notice.body':
    'Nada é guardado. Esta consulta não cria nem altera qualquer entidade, não importa dados e não fica registada no livro de registos. Pode repeti-la as vezes que quiser sem alterar nada.',
  'certidaoLookup.result.nothingSaved': 'Resultado da consulta. Nada foi guardado.',

  // --- Form --------------------------------------------------------------------------------
  'certidaoLookup.submit': 'Consultar',
  'certidaoLookup.submitting': 'A consultar…',
  'certidaoLookup.clear': 'Limpar',
  'certidaoLookup.codeRequired': 'Introduza o código de acesso.',
  'certidaoLookup.quotaWarning':
    'Cada consulta contacta o serviço do registo. Consulte apenas o que precisa.',

  // --- Result table ------------------------------------------------------------------------
  'certidaoLookup.table.caption': 'Dados da certidão consultada',
  'certidaoLookup.table.field': 'Campo',
  'certidaoLookup.table.value': 'Valor',
  'certidaoLookup.provenance.caption': 'Proveniência da consulta',
  'certidaoLookup.provenance.title': 'Proveniência',

  // A field the certidão did not carry. NOT rendered as a blank or a dash: an empty cell under
  // "Sede" reads as "esta empresa não tem sede", which is a claim the certidão never made.
  'certidaoLookup.absent': 'Não consta da certidão',
  // A field the certidão carried but that this instance cannot represent faithfully.
  'certidaoLookup.unrepresentable': 'Presente na certidão, mas não foi possível apresentar',

  // --- Failures, one per API `code` --------------------------------------------------------
  'certidaoLookup.error.invalidCode': 'O código de acesso tem de ter 12 dígitos.',
  'certidaoLookup.error.codeRejected':
    'O registo não aceitou este código de acesso: pode estar incorreto ou a certidão pode já ter expirado. O serviço do registo não distingue os dois casos, por isso não é possível dizer qual deles se aplica.',
  'certidaoLookup.error.certidaoNotFound':
    'O registo respondeu que não existe nenhuma certidão com este número.',
  'certidaoLookup.error.unreachable':
    'Não foi possível contactar o serviço do registo. Não chegámos a obter resposta, pelo que isto nada indica sobre a empresa nem sobre a validade do código.',
  'certidaoLookup.error.credentialsRejected':
    'O serviço do registo recusou as credenciais desta instalação. O código de acesso não está em causa.',
  'certidaoLookup.error.quotaExceeded':
    'O serviço do registo recusou mais consultas por agora, por limite de utilização. Aguarde e tente novamente.',
  'certidaoLookup.error.upstream': 'O serviço do registo respondeu com um erro.',
  'certidaoLookup.error.unrecognized':
    'O serviço do registo respondeu, mas a resposta não é uma certidão que seja possível interpretar.',
  'certidaoLookup.error.config':
    'A integração com o registo está mal configurada nesta instalação. A falha é local: o serviço do registo não está em causa.',
  'certidaoLookup.error.title': 'A consulta não foi concluída',
  'certidaoLookup.error.detail': 'Detalhe técnico',
} as const;

/** The key set the Certidão de Registo Permanente lookup copy resolves. */
export type CertidaoLookupCopyKey = keyof typeof certidaoLookupPtPT;

export const certidaoLookupEnglish = {
  'tools.section.certidao': 'Certidão de Registo Permanente',
  'certidaoLookup.title': 'Look up a Certidão de Registo Permanente',
  'certidaoLookup.intro':
    'Enter the access code to consult the certidão at the registry. This tool only consults.',

  'certidaoLookup.notice.title': 'Lookup only',
  'certidaoLookup.notice.body':
    'Nothing is saved. This lookup creates and changes no entity, imports no data, and is not recorded in the ledger. You can repeat it as often as you like without changing anything.',
  'certidaoLookup.result.nothingSaved': 'Lookup result. Nothing was saved.',

  'certidaoLookup.submit': 'Look up',
  'certidaoLookup.submitting': 'Looking up…',
  'certidaoLookup.clear': 'Clear',
  'certidaoLookup.codeRequired': 'Enter the access code.',
  'certidaoLookup.quotaWarning':
    'Each lookup contacts the registry service. Only look up what you need.',

  'certidaoLookup.table.caption': 'Data from the certidão consulted',
  'certidaoLookup.table.field': 'Field',
  'certidaoLookup.table.value': 'Value',
  'certidaoLookup.provenance.caption': 'Provenance of the lookup',
  'certidaoLookup.provenance.title': 'Provenance',

  'certidaoLookup.absent': 'Not stated in the certidão',
  'certidaoLookup.unrepresentable': 'Present in the certidão, but could not be displayed',

  'certidaoLookup.error.invalidCode': 'The access code must be 12 digits.',
  'certidaoLookup.error.codeRejected':
    'The registry did not accept this access code: it may be wrong, or the certidão may have expired. The registry service does not distinguish the two, so which one applies cannot be determined.',
  'certidaoLookup.error.certidaoNotFound':
    'The registry answered that no certidão exists with this number.',
  'certidaoLookup.error.unreachable':
    'The registry service could not be reached. No answer was received, so this says nothing about the company or about whether the code is valid.',
  'certidaoLookup.error.credentialsRejected':
    "The registry service refused this installation's credentials. The access code is not at fault.",
  'certidaoLookup.error.quotaExceeded':
    'The registry service is refusing further lookups for now, due to a usage limit. Wait and try again.',
  'certidaoLookup.error.upstream': 'The registry service answered with an error.',
  'certidaoLookup.error.unrecognized':
    'The registry service answered, but the response is not a certidão that can be interpreted.',
  'certidaoLookup.error.config':
    'The registry integration is misconfigured in this installation. The fault is local: the registry service is not at fault.',
  'certidaoLookup.error.title': 'The lookup did not complete',
  'certidaoLookup.error.detail': 'Technical detail',
} as const satisfies Record<CertidaoLookupCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split `trustSectionsFallback` uses while the catalogs are locked.
 */
export function useCertidaoLookupCopy(): Record<CertidaoLookupCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? certidaoLookupPtPT : certidaoLookupEnglish;
}

/**
 * The page's translate hook, shaped like `useT`:
 * `const ct = useCertidaoLookupT(); ct('certidaoLookup.title')`.
 */
export function useCertidaoLookupT(): (key: CertidaoLookupCopyKey, params?: TParams) => string {
  const copy = useCertidaoLookupCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}

/**
 * Map the API's stable registry error `code` to this module's copy key.
 *
 * Exhaustive over the nine codes `RegistryError::code()` can emit. An unknown code returns
 * `undefined` **on purpose**: the caller then shows the server's own English detail rather than a
 * Portuguese sentence invented for a failure this build does not recognise. Guessing here is how a
 * refusal ends up explained by a cause that was never established.
 */
export function certidaoLookupErrorKey(code: string | undefined): CertidaoLookupCopyKey | undefined {
  switch (code) {
    case 'registry.invalid_code':
      return 'certidaoLookup.error.invalidCode';
    case 'registry.code_rejected':
      return 'certidaoLookup.error.codeRejected';
    case 'registry.certidao_not_found':
      return 'certidaoLookup.error.certidaoNotFound';
    case 'registry.unreachable':
      return 'certidaoLookup.error.unreachable';
    case 'registry.credentials_rejected':
      return 'certidaoLookup.error.credentialsRejected';
    case 'registry.quota_exceeded':
      return 'certidaoLookup.error.quotaExceeded';
    case 'registry.upstream':
      return 'certidaoLookup.error.upstream';
    case 'registry.unrecognized':
      return 'certidaoLookup.error.unrecognized';
    case 'registry.config':
      return 'certidaoLookup.error.config';
    default:
      return undefined;
  }
}
