/**
 * "Administração" copy (t36) — the admin surface at `/admin` that hosts the operations panes and
 * the integrations subtabs (Grupos / Conectores / Repositórios ZK).
 *
 * **Why this module is self-contained, not spread into the 14 locale catalogs.** It follows the
 * exact precedent of {@link ./serverEnvFallback} and {@link ./operationsFallback}: the shared
 * catalogs move under a single-writer serial lock during the batch, so t36 owns its two keys end
 * to end and exposes its own locale-aware resolver ({@link useAdminT}) rather than adding the usual
 * per-locale import + spread wiring. Consumers read this copy exactly as they would through `useT`,
 * so nothing in the shared catalog moves and the catalog completeness / leak gates never see it.
 *
 * The map shape is deliberately identical to the sibling fallbacks (a pt-PT source object plus an
 * English fallback that `satisfies` its key set): folding these into the catalog later is a
 * mechanical spread and each consumer switches to `t()` with no copy changes.
 *
 * Only NEW copy lives here. The integrations subtab LABELS reuse the existing `operations.tabs.*`
 * catalog keys (the strip is rendered by SettingsPage in admin-surface mode), so they are not
 * duplicated here.
 *
 * Consumers:
 *  - the `/admin` nav glyph (t36-e3, `layout.tsx`) reads `nav.admin` for its `aria-label` + tooltip;
 *  - SettingsPage in admin-surface mode (t36-e2) reads `admin.title` for the page header.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const adminPtPT = {
  'nav.admin': 'Administração',
  'admin.title': 'Administração',
  // The single flat subtab strip on `/admin` (t60, Option B): the admin section level was dissolved,
  // so one strip now lists every admin area — the operations panes and the signing cards together —
  // and this is its landmark name. Distinct from the per-cluster `settings.subnav.*.aria` labels it
  // replaces, because the strip is no longer scoped to one cluster.
  'admin.subnav.aria': 'Áreas de administração',
  'admin.finder.label': 'Encontrar uma configuração',
  'admin.finder.placeholder': 'Pesquisar configurações…',
  'admin.finder.clear': 'Limpar pesquisa',
  'admin.finder.results': '{count} configurações encontradas',
  'admin.finder.noResults': 'Nenhuma configuração corresponde à pesquisa.',
  'admin.finder.open': 'Abrir {title}',
  'admin.finder.keywords.services':
    'serviços plataforma estado saúde disponibilidade reiniciar processo',
  'admin.finder.keywords.logs':
    'registos logs diagnóstico auditoria eventos níveis verbosidade histórico',
  'admin.search.title': 'Pesquisa',
  'admin.templatePreview.title': 'Amostras de pré-visualização',
  'admin.finder.keywords.search':
    'pesquisa índice indexação worker fila reconstruir pausar retomar resultados facetas memória conteúdo',
  'admin.finder.keywords.templatePreview':
    'modelos minutas atas pré-visualização amostras PDF Markdown fictícios entidade reunião ordem trabalhos convocatória provas livro',
  'admin.finder.keywords.api': 'servidor API endereço endpoint porta limites tráfego pedidos rede',
  'admin.finder.keywords.apiKeys':
    'chaves API tokens credenciais acesso utilizadores validade revogar',
  'admin.finder.keywords.database':
    'base de dados PostgreSQL ligação pool TLS servidor credenciais',
  'admin.finder.keywords.cache': 'cache Redis memória ligação servidor expiração',
  'admin.finder.keywords.storage':
    'armazenamento dados retenção limpeza exportações ficheiros capacidade',
  'admin.finder.keywords.backups': 'cópias segurança recuperação restauro RPO RTO testes retenção',
  'admin.finder.keywords.keys':
    'chaves reposição segredos criptografia rotação recuperação custódia',
  'admin.finder.keywords.mcp':
    'MCP Model Context Protocol ferramentas inteligência artificial servidor',
  'admin.finder.keywords.email': 'email correio SMTP mensagens notificações remetente teste',
  'admin.finder.keywords.env':
    'ambiente variáveis servidor arranque substituições configuração avançada',
  'admin.finder.keywords.groups':
    'grupos bibliotecas organizações entidades minutas modelos partilhados',
  'admin.finder.keywords.connectors':
    'conectores integrações trabalhos sincronização destinos exportação cópias externas',
  'admin.finder.keywords.repositories':
    'repositórios ZK objetos provas arquivo armazenamento externo',
  'admin.finder.keywords.providers':
    'assinatura fornecedores credenciais certificados integração teste',
  'admin.finder.keywords.policy':
    'política assinatura famílias perfis regras validação qualificada',
  'admin.finder.keywords.tsl': 'TSL listas confiança fontes europeias certificados atualização',
  'admin.finder.keywords.tsa': 'TSA selo temporal timestamp autoridade tempo fornecedores',
  'admin.finder.keywords.trustServices':
    'serviços confiança certificados validação prestadores âncoras',
  'admin.finder.keywords.cmd': 'CMD Chave Móvel Digital autenticação gov assinatura móvel',
} as const;

/** The key set the Administração surface resolves through this module. */
export type AdminCopyKey = keyof typeof adminPtPT;

export const adminEnglish = {
  'nav.admin': 'Administration',
  'admin.title': 'Administration',
  'admin.subnav.aria': 'Administration areas',
  'admin.finder.label': 'Find a setting',
  'admin.finder.placeholder': 'Search settings…',
  'admin.finder.clear': 'Clear search',
  'admin.finder.results': '{count} settings found',
  'admin.finder.noResults': 'No settings match your search.',
  'admin.finder.open': 'Open {title}',
  'admin.finder.keywords.services': 'services platform status health availability restart process',
  'admin.finder.keywords.logs': 'logs diagnostics audit events levels verbosity history records',
  'admin.search.title': 'Search',
  'admin.templatePreview.title': 'Preview samples',
  'admin.finder.keywords.search':
    'search index indexing worker queue rebuild pause resume results facets memory content',
  'admin.finder.keywords.templatePreview':
    'templates minutes preview samples PDF Markdown fictitious entity meeting agenda convening evidence book',
  'admin.finder.keywords.api':
    'API server address endpoint port request rate limits traffic network',
  'admin.finder.keywords.apiKeys': 'API keys tokens credentials access users expiry revoke',
  'admin.finder.keywords.database': 'database PostgreSQL connection pool TLS server credentials',
  'admin.finder.keywords.cache': 'cache Redis memory connection server expiry',
  'admin.finder.keywords.storage': 'storage data retention cleanup exports files capacity',
  'admin.finder.keywords.backups': 'backups recovery restore RPO RTO drills retention copies',
  'admin.finder.keywords.keys': 'keys recovery secrets encryption rotation custody restore',
  'admin.finder.keywords.mcp': 'MCP Model Context Protocol tools artificial intelligence server',
  'admin.finder.keywords.email': 'email mail SMTP messages notifications sender test',
  'admin.finder.keywords.env':
    'environment variables server startup overrides advanced configuration',
  'admin.finder.keywords.groups': 'groups libraries tenants entities templates shared models',
  'admin.finder.keywords.connectors':
    'connectors integrations jobs synchronisation destinations exports external backups',
  'admin.finder.keywords.repositories': 'ZK repositories objects proofs archive external storage',
  'admin.finder.keywords.providers': 'signing providers credentials certificates integration test',
  'admin.finder.keywords.policy': 'signature policy families profiles rules validation qualified',
  'admin.finder.keywords.tsl': 'TSL trusted lists sources European certificates update',
  'admin.finder.keywords.tsa': 'TSA timestamp time stamp authority providers',
  'admin.finder.keywords.trustServices': 'trust services certificates validation providers anchors',
  'admin.finder.keywords.cmd': 'CMD Digital Mobile Key autenticacao gov mobile signing',
} as const satisfies Record<AdminCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the catalog spread performs, kept here while the catalogs are locked.
 */
export function useAdminCopy(): Record<AdminCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? adminPtPT : adminEnglish;
}

/**
 * The surface's translate hook, shaped like {@link useT}:
 * `const at = useAdminT(); at('admin.title')`. Supports the same `{placeholder}` interpolation.
 */
export function useAdminT(): (key: AdminCopyKey, params?: TParams) => string {
  const copy = useAdminCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
