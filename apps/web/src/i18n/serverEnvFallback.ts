/**
 * "Ambiente do servidor" copy (t14) — the settings pane that renders the server-declared env-override
 * registry (`GET/PUT /v1/platform/env`).
 *
 * **Why this module is self-contained, not spread into the catalogs like `opsConfigFallback.ts`.**
 * The 14 locale catalogs (`locales/*.ts` + `reviewedIdenticalValues.ts`) are held under a single-writer
 * serial lock for the duration of the t11/t12/t15 batch, so t14 is not permitted to add the usual
 * "one import + one spread line per locale" wiring. Instead this module owns its keys end to end and
 * exposes its own locale-aware resolver ({@link useServerEnvT}). The component reads copy through that
 * resolver exactly as it would through `useT`, so nothing in the shared catalog moves and the
 * catalog-leak / literal-copy gates never see these strings.
 *
 * The map shape is deliberately identical to `opsConfigFallback.ts` (a pt-PT source object plus an
 * English fallback that `satisfies` its key set): if the catalog lock later releases, folding these
 * into the catalog is a mechanical spread and the component can switch to `t()` with no copy changes.
 *
 * **Two rules govern the copy here, same as the ops-config surface.**
 * 1. **Never claim an assurance the server does not make.** The panel writes an override *file* that
 *    only takes effect at the next process start; every value is resolved once at startup. The copy
 *    says "aplica-se no próximo arranque" plainly and never implies a live change.
 * 2. **Never soften a security boundary into a mere setting.** Tier C vars (CORS, rate-limit trust,
 *    TLS mode, trust anchors) and the narrow-only egress ceiling carry safety weight; the
 *    acknowledgement and narrow-only strings state the risk instead of describing "uma definição".
 *
 * pt-PT is the source. Follows the i18n agreement rules (no noun dropped into an inflected sentence)
 * and invents no anglicisms. Secrets are never echoed — Tier B shows only a configured/masked state.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const serverEnvPtPT = {
  // — Cabeçalho do painel ————————————————————————————————————————————————
  'settings.serverEnv.title': 'Ambiente do servidor',
  'settings.serverEnv.intro':
    'As variáveis de ambiente que este servidor lê no arranque, com o valor que o processo em execução resolveu. Pode substituir as não-secretas; a substituição é guardada num ficheiro e aplica-se no próximo arranque, nunca de imediato.',
  'settings.serverEnv.loading': 'A carregar o ambiente do servidor…',
  'settings.serverEnv.loadError': 'Não foi possível carregar o ambiente do servidor.',
  'settings.serverEnv.empty': 'Não há variáveis a apresentar.',
  'settings.serverEnv.overridesPath':
    'As substituições são guardadas em {path}, sob a diretoria de dados.',

  // — Reinício pendente ——————————————————————————————————————————————————
  'settings.serverEnv.restart.badge': 'Reinício pendente',
  'settings.serverEnv.restart.title': 'Guardado, ainda não aplicado',
  'settings.serverEnv.restart.body':
    'Estes valores são lidos uma única vez, no arranque do processo. As substituições estão guardadas, mas o servidor em execução continua a usar o que leu quando arrancou — reinicie-o para as aplicar.',
  'settings.serverEnv.restart.rowHint': 'A substituição guardada difere do valor em execução.',

  // — Colunas / factos por linha —————————————————————————————————————————
  'settings.serverEnv.col.name': 'Variável',
  'settings.serverEnv.col.value': 'Valor efetivo',
  'settings.serverEnv.col.source': 'Origem',
  'settings.serverEnv.col.default': 'Predefinição',
  'settings.serverEnv.col.override': 'Substituição',

  // — Origem do valor resolvido —————————————————————————————————————————
  'settings.serverEnv.source.override': 'Substituição',
  'settings.serverEnv.source.env': 'Ambiente',
  'settings.serverEnv.source.default': 'Predefinição',
  'settings.serverEnv.source.override.hint': 'O valor vem da substituição guardada neste painel.',
  'settings.serverEnv.source.env.hint': 'O valor vem do ambiente onde o serviço foi lançado.',
  'settings.serverEnv.source.default.hint':
    'Nenhuma substituição nem variável de ambiente — usa a predefinição do código.',

  // — Grupos —————————————————————————————————————————————————————————————
  'settings.serverEnv.group.logging': 'Registo',
  'settings.serverEnv.group.network': 'Rede',
  'settings.serverEnv.group.session': 'Sessões',
  'settings.serverEnv.group.notifications': 'Centro de Ações',
  'settings.serverEnv.group.rate_limit': 'Limitação de tráfego',
  'settings.serverEnv.group.hsts': 'HSTS',
  'settings.serverEnv.group.cors': 'CORS',
  'settings.serverEnv.group.database': 'Base de dados',
  'settings.serverEnv.group.credentials': 'Credenciais',
  'settings.serverEnv.group.cache': 'Cache e Redis',
  'settings.serverEnv.group.cluster': 'Cluster e nós',
  'settings.serverEnv.group.postgres_tls': 'TLS do PostgreSQL',
  'settings.serverEnv.group.trust': 'Confiança e validação',
  'settings.serverEnv.group.signing': 'Assinatura',
  'settings.serverEnv.group.csc': 'Assinatura na nuvem (CSC)',
  'settings.serverEnv.group.cmd': 'Chave Móvel Digital',
  'settings.serverEnv.group.scap': 'Atributos profissionais (SCAP)',
  'settings.serverEnv.group.connectors': 'Conectores',
  'settings.serverEnv.group.storage': 'Armazenamento',
  'settings.serverEnv.group.paper_book': 'Livros em papel (OCR)',
  'settings.serverEnv.group.mcp': 'MCP',

  // — Tier A: editável ————————————————————————————————————————————————————
  'settings.serverEnv.field.hint':
    'Deixar vazio remove a substituição e volta ao valor do ambiente ou à predefinição.',
  'settings.serverEnv.field.enumHint': 'Escolha um dos valores permitidos.',
  'settings.serverEnv.field.boolTrue': 'Ativado',
  'settings.serverEnv.field.boolFalse': 'Desativado',

  // — Tier B: secreta (apenas leitura, mascarada) ————————————————————————
  'settings.serverEnv.secret.note': '(contém uma credencial — nunca é apresentada aqui)',
  'settings.serverEnv.secret.configured': 'Configurada',
  'settings.serverEnv.secret.notConfigured': 'Não configurada',
  'settings.serverEnv.secret.body':
    'É um segredo. O painel mostra apenas se está definida, nunca o valor. Defina-a onde o serviço é lançado ou pelo fluxo de credenciais próprio.',

  // — Tier C: fronteira de segurança (com confirmação) —————————————————————
  'settings.serverEnv.boundary.badge': 'Fronteira de segurança',
  'settings.serverEnv.boundary.ackLabel': 'Confirmo que compreendo o efeito desta alteração',
  'settings.serverEnv.boundary.ackHint':
    'Esta variável define uma fronteira de segurança. Alterá-la exige confirmação explícita; sem ela o servidor recusa a gravação.',
  'settings.serverEnv.boundary.warningTitle': 'Alteração de uma fronteira de segurança',
  'settings.serverEnv.boundary.warningBody':
    'Está a alterar uma variável que controla uma fronteira de segurança. Uma configuração incorreta pode enfraquecer a postura de segurança do servidor. Confirme antes de guardar.',
  'settings.serverEnv.narrowOnly.badge': 'Só pode restringir',
  'settings.serverEnv.narrowOnly.note':
    'É um limite máximo imposto pela implementação. A substituição só o pode restringir, nunca alargar.',

  // — Tier D e excluídas (apenas leitura) ————————————————————————————————
  'settings.serverEnv.readOnly.badge': 'Apenas leitura',
  'settings.serverEnv.readOnly.note':
    'É um facto derivado do ambiente do processo e não é editável aqui. Altere-o onde o serviço é lançado.',
  'settings.serverEnv.typedSlice.note':
    'Esta variável é gerida por uma definição própria com precedência definida:',

  // — Ações ————————————————————————————————————————————————————————————————
  'settings.serverEnv.save': 'Guardar substituições',
  'settings.serverEnv.saving': 'A guardar…',
  'settings.serverEnv.saved':
    'Substituições guardadas. Aplicam-se no próximo arranque do servidor.',
  'settings.serverEnv.saveError': 'Não foi possível guardar as substituições.',
  'settings.serverEnv.discard': 'Descartar alterações',
  'settings.serverEnv.clearOverride': 'Limpar substituição',
  'settings.serverEnv.ackRequiredError':
    'Confirme cada alteração a uma fronteira de segurança antes de guardar.',

  // — Estados vazios de valor ————————————————————————————————————————————
  'settings.serverEnv.value.unset': 'Não definida',
  'settings.serverEnv.value.masked': '••••••••',
} as const;

/** The key set the "Ambiente do servidor" pane resolves. */
export type ServerEnvCopyKey = keyof typeof serverEnvPtPT;

export const serverEnvEnglish = {
  'settings.serverEnv.title': 'Server environment',
  'settings.serverEnv.intro':
    'The environment variables this server reads at startup, with the value the running process resolved. You can override the non-secret ones; an override is saved to a file and takes effect at the next start, never immediately.',
  'settings.serverEnv.loading': 'Loading the server environment…',
  'settings.serverEnv.loadError': 'Could not load the server environment.',
  'settings.serverEnv.empty': 'There are no variables to show.',
  'settings.serverEnv.overridesPath': 'Overrides are saved in {path}, under the data directory.',

  'settings.serverEnv.restart.badge': 'Restart pending',
  'settings.serverEnv.restart.title': 'Saved, not yet applied',
  'settings.serverEnv.restart.body':
    'These values are read once, when the process starts. The overrides are stored, but the running server is still using what it read at startup — restart it to apply them.',
  'settings.serverEnv.restart.rowHint': 'The saved override differs from the running value.',

  'settings.serverEnv.col.name': 'Variable',
  'settings.serverEnv.col.value': 'Effective value',
  'settings.serverEnv.col.source': 'Source',
  'settings.serverEnv.col.default': 'Default',
  'settings.serverEnv.col.override': 'Override',

  'settings.serverEnv.source.override': 'Override',
  'settings.serverEnv.source.env': 'Environment',
  'settings.serverEnv.source.default': 'Default',
  'settings.serverEnv.source.override.hint':
    'The value comes from the override saved in this panel.',
  'settings.serverEnv.source.env.hint':
    'The value comes from the environment where the service was launched.',
  'settings.serverEnv.source.default.hint':
    'No override and no environment variable — uses the code default.',

  'settings.serverEnv.group.logging': 'Logging',
  'settings.serverEnv.group.network': 'Network',
  'settings.serverEnv.group.session': 'Sessions',
  'settings.serverEnv.group.notifications': 'Action Center',
  'settings.serverEnv.group.rate_limit': 'Rate limiting',
  'settings.serverEnv.group.hsts': 'HSTS',
  'settings.serverEnv.group.cors': 'CORS',
  'settings.serverEnv.group.database': 'Database',
  'settings.serverEnv.group.credentials': 'Credentials',
  'settings.serverEnv.group.cache': 'Cache and Redis',
  'settings.serverEnv.group.cluster': 'Cluster and nodes',
  'settings.serverEnv.group.postgres_tls': 'PostgreSQL TLS',
  'settings.serverEnv.group.trust': 'Trust and validation',
  'settings.serverEnv.group.signing': 'Signing',
  'settings.serverEnv.group.csc': 'Cloud signing (CSC)',
  'settings.serverEnv.group.cmd': 'Chave Móvel Digital',
  'settings.serverEnv.group.scap': 'Professional attributes (SCAP)',
  'settings.serverEnv.group.connectors': 'Connectors',
  'settings.serverEnv.group.storage': 'Storage',
  'settings.serverEnv.group.paper_book': 'Paper books (OCR)',
  'settings.serverEnv.group.mcp': 'MCP',

  'settings.serverEnv.field.hint':
    'Leaving it empty removes the override and reverts to the environment value or the default.',
  'settings.serverEnv.field.enumHint': 'Choose one of the allowed values.',
  'settings.serverEnv.field.boolTrue': 'Enabled',
  'settings.serverEnv.field.boolFalse': 'Disabled',

  'settings.serverEnv.secret.note': '(contains a credential — never displayed here)',
  'settings.serverEnv.secret.configured': 'Configured',
  'settings.serverEnv.secret.notConfigured': 'Not configured',
  'settings.serverEnv.secret.body':
    'This is a secret. The panel shows only whether it is set, never the value. Set it where the service is launched or through its own credential flow.',

  'settings.serverEnv.boundary.badge': 'Security boundary',
  'settings.serverEnv.boundary.ackLabel': 'I understand the effect of this change',
  'settings.serverEnv.boundary.ackHint':
    'This variable defines a security boundary. Changing it requires explicit acknowledgement; without it the server refuses the save.',
  'settings.serverEnv.boundary.warningTitle': 'Changing a security boundary',
  'settings.serverEnv.boundary.warningBody':
    'You are changing a variable that controls a security boundary. A wrong setting can weaken the server’s security posture. Confirm before saving.',
  'settings.serverEnv.narrowOnly.badge': 'Can only narrow',
  'settings.serverEnv.narrowOnly.note':
    'This is a ceiling imposed by the deployment. An override can only narrow it, never widen it.',

  'settings.serverEnv.readOnly.badge': 'Read-only',
  'settings.serverEnv.readOnly.note':
    'This is a fact derived from the process environment and is not editable here. Change it where the service is launched.',
  'settings.serverEnv.typedSlice.note':
    'This variable is managed by a dedicated setting with a defined precedence:',

  'settings.serverEnv.save': 'Save overrides',
  'settings.serverEnv.saving': 'Saving…',
  'settings.serverEnv.saved': 'Overrides saved. They apply at the next server start.',
  'settings.serverEnv.saveError': 'Could not save the overrides.',
  'settings.serverEnv.discard': 'Discard changes',
  'settings.serverEnv.clearOverride': 'Clear override',
  'settings.serverEnv.ackRequiredError': 'Acknowledge each security-boundary change before saving.',

  'settings.serverEnv.value.unset': 'Not set',
  'settings.serverEnv.value.masked': '••••••••',
} as const satisfies Record<ServerEnvCopyKey, string>;

/**
 * The active copy map for the pane: pt-PT gets the reviewed source strings, every other locale gets
 * the English fallback — the exact split `opsConfigFallback` uses via the catalog spread, kept here
 * because t14 may not touch the catalogs while they are locked.
 */
export function useServerEnvCopy(): Record<ServerEnvCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? serverEnvPtPT : serverEnvEnglish;
}

/**
 * The pane's translate hook, shaped like {@link useT}: `const st = useServerEnvT(); st('settings.serverEnv.title')`.
 * Supports the same `{placeholder}` interpolation as the catalog.
 */
export function useServerEnvT(): (key: ServerEnvCopyKey, params?: TParams) => string {
  const copy = useServerEnvCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
