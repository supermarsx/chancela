/**
 * Portuguese URL slugs, kept resolving forever (t97b).
 *
 * The addresses were pt-PT until now — `/configuracoes/operacoes/email`. They are English from
 * here on, because the project's rule is that the PROGRAMMING BASE is English (identifiers,
 * filenames, directories, comments) and pt-PT is the user-facing language. A URL slug is an
 * identifier, not copy: `/books` is the address, "Livro de atas" is still the label on screen.
 * The rule's exception for the names of Portuguese legal instruments applies to CONTENT, not to
 * route slugs — so an ata is addressed at `/acts/:id` and still called an ata everywhere a
 * person reads it.
 *
 * **These translations are permanent, not a migration aid.** Every Portuguese address has been
 * addressable, several were only made addressable hours earlier, and they are bookmarked, pasted
 * into tickets and — for `/configuracoes?sec=dados` — built server-side by the dashboard alert
 * routes. There is no future release in which one of them is allowed to 404. Deleting an entry
 * from this file breaks somebody's link.
 *
 * Translation is POSITIONAL and conservative: a segment is translated only when it is a known
 * legacy slug at that position, and is otherwise passed through **raw**. That is what lets record
 * ids travel untouched — including a template id like `csc-ata-ag%2Fv1`, whose `%2F` must never
 * be decoded, re-encoded, or treated as a segment boundary.
 */

/** Level-1 and level-2 slugs under `/entidades`. */
const ENTITY_ACTIONS: Record<string, string> = { nova: 'new', importar: 'import' };
const ENTITY_SECTIONS: Record<string, string> = {
  livros: 'books',
  identificacao: 'identification',
  fiscal: 'fiscal',
  registo: 'registry',
  inscricoes: 'filings',
  cronologia: 'chronology',
};

const BOOK_ACTIONS: Record<string, string> = { novo: 'new' };
const BOOK_SECTIONS: Record<string, string> = {
  atas: 'acts',
  termo: 'opening',
  retencao: 'retention',
  importacoes: 'imports',
  'nova-ata': 'new-act',
  encerrar: 'close',
};

const TEMPLATE_SECTIONS: Record<string, string> = {
  identificacao: 'identification',
  fonte: 'source',
  blocos: 'blocks',
  campos: 'fields',
};

/** Arquivo's own `registo` is the ledger REGISTER, not a company registry — hence the divergence
 *  from the identically-spelled entity section above. Positional translation is what allows it. */
const LEDGER_SECTIONS: Record<string, string> = { registo: 'register', exportacao: 'export' };

const TOOL_SLUGS: Record<string, string> = { legislacao: 'legislation' };
/** Both second levels under Ferramentas: the PDF validator's sub-tabs and Legislação's views. */
const TOOL_SUBSECTIONS: Record<string, string> = { relatorios: 'reports', prateleira: 'shelf' };

/**
 * Settings sections, including the retired aliases the page still forwards (`identidade`,
 * `chaves-api`, `fornecedores-assinatura`). They are translated here so `RETIRED_SECTIONS` can be
 * keyed on the English ids alone rather than carrying both spellings.
 */
const SETTINGS_SECTIONS: Record<string, string> = {
  aparencia: 'appearance',
  documentos: 'documents',
  assinaturas: 'signing',
  gestao: 'management',
  operacoes: 'operations',
  privacidade: 'privacy',
  utilizadores: 'users',
  dispositivos: 'devices',
  funcoes: 'roles',
  delegacoes: 'delegations',
  integridade: 'integrity',
  dados: 'data',
  sobre: 'about',
  identidade: 'identity',
  'chaves-api': 'api-keys',
  'fornecedores-assinatura': 'signing-providers',
};

const SETTINGS_SUBSECTIONS: Record<string, string> = {
  // `plataforma` was split into Serviços + Registos (t101). The old address forwards to
  // Serviços, the panel that kept the controls it was mostly about — a real successor rather
  // than a fallback to whatever happens to sit first in the strip.
  plataforma: 'services',
  'chaves-api': 'api-keys',
  registos: 'logs',
  servicos: 'services',
  fornecedores: 'providers',
  politica: 'policy',
  prestadores: 'trust-services',
};

const USER_ACTIONS: Record<string, string> = { novo: 'new' };
const USER_SECTIONS: Record<string, string> = { editar: 'edit' };

interface LegacySurface {
  /** The English first segment. */
  to: string;
  /**
   * Per-position translations for the segments AFTER the first. A position with no entry for a
   * given segment passes it through raw — which is how record ids survive.
   */
  positions?: Record<string, string>[];
  /**
   * The query params this surface used to address its sections with, per level, outermost first.
   * A level lists alternatives because Ferramentas spelled its second level two ways.
   */
  params?: string[][];
}

/**
 * Keyed on the LEGACY first segment. `cae` and `atas`-style surfaces with no sections need no
 * `positions`; `cae` is already an acronym and is not listed at all because it does not change.
 */
const LEGACY_SURFACES: Record<string, LegacySurface> = {
  'bem-vindo': { to: 'welcome' },
  'assinatura-externa': { to: 'external-signature' },
  painel: { to: 'dashboard' },
  entidades: {
    to: 'entities',
    positions: [ENTITY_ACTIONS, { ...ENTITY_ACTIONS, ...ENTITY_SECTIONS }],
    params: [['sec']],
  },
  livros: { to: 'books', positions: [BOOK_ACTIONS, BOOK_SECTIONS], params: [['sec']] },
  atas: { to: 'acts' },
  minutas: { to: 'templates', positions: [{}, TEMPLATE_SECTIONS], params: [['sec']] },
  arquivo: { to: 'archive', positions: [LEDGER_SECTIONS], params: [['sec']] },
  notificacoes: { to: 'notifications' },
  operacoes: { to: 'operations', params: [['view']] },
  ferramentas: {
    to: 'tools',
    positions: [TOOL_SLUGS, TOOL_SUBSECTIONS],
    params: [['tool'], ['sec', 'leg']],
  },
  configuracoes: {
    to: 'settings',
    positions: [SETTINGS_SECTIONS, SETTINGS_SUBSECTIONS],
    params: [['sec'], ['sub']],
  },
  utilizadores: { to: 'users', positions: [USER_ACTIONS, USER_SECTIONS], params: [['tab']] },
};

/** Raw (still percent-encoded) path segments. */
function rawSegments(pathname: string): string[] {
  return pathname.split('/').filter((segment) => segment !== '');
}

/**
 * Normalise a whole route string — path, query and fragment together — returning it unchanged
 * when nothing about it is legacy.
 *
 * This is the entry point for routes the SERVER hands us. `crates/chancela-api` builds dashboard
 * alert and notification actions as `/configuracoes?sec=dados`, and those arrive as data rather
 * than as navigations, so they never touch the router's redirect. Normalising them here means the
 * rendered `href` is the real address rather than one that only works after a bounce — and it
 * means the surrounding allow-lists can be written against the English routes alone.
 */
export function normalizeLegacyRoute(route: string): string {
  const hashAt = route.indexOf('#');
  const hash = hashAt === -1 ? '' : route.slice(hashAt);
  const withoutHash = hashAt === -1 ? route : route.slice(0, hashAt);
  const queryAt = withoutHash.indexOf('?');
  const pathname = queryAt === -1 ? withoutHash : withoutHash.slice(0, queryAt);
  const search = queryAt === -1 ? '' : withoutHash.slice(queryAt);

  const translated = translateLegacyAddress(pathname, search);
  if (translated === null) return route;
  return `${translated.pathname}${translated.search}${hash}`;
}

export interface LegacyAddress {
  pathname: string;
  /** The query with the promoted navigation params removed; `''` when nothing is left. */
  search: string;
}

/**
 * Translate a legacy address, or return `null` when there is nothing legacy about it.
 *
 * Does BOTH halves of the migration in one hop, deliberately: every pre-t97 query-string address
 * also carried a Portuguese slug, so `/configuracoes?sec=dados` has to become `/settings/data`
 * in a single `replace` rather than bouncing through an intermediate address that would show up
 * as a Back-button stop.
 */
export function translateLegacyAddress(pathname: string, search: string): LegacyAddress | null {
  const segments = rawSegments(pathname);
  const surface = segments.length > 0 ? LEGACY_SURFACES[segments[0]] : undefined;
  if (!surface) return null;

  const params = new URLSearchParams(search);
  const promoted: string[] = [];
  for (const names of surface.params ?? []) {
    const value = names
      .map((name) => params.get(name))
      .find((v): v is string => v !== null && v !== '');
    // Stop at the first gap: a `?sub=` with no `?sec=` addressed nothing and must not be
    // promoted into a section segment it never named.
    if (value === undefined) break;
    promoted.push(value);
  }
  for (const names of surface.params ?? []) for (const name of names) params.delete(name);

  // The promoted values are section slugs and belong at the section positions, which for a
  // record surface sit after the id — exactly where the raw segments already end.
  const tail = [...segments.slice(1), ...promoted.map(encodeURIComponent)];
  const translated = tail.map((segment, index) => surface.positions?.[index]?.[segment] ?? segment);

  const rest = params.toString();
  return {
    pathname: `/${[surface.to, ...translated].join('/')}`,
    search: rest ? `?${rest}` : '',
  };
}
