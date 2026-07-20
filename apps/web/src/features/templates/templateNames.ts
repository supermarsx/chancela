/**
 * Display names for the built-in template catalog.
 *
 * The user's report: the Minutas catalog showed `assoc-ata-conselho-fiscal/v1` and nothing
 * else. Every surface that renders a template id now leads with the document's name and keeps
 * the id (with its `/vN`) as secondary detail — the version pins provenance for a sealed
 * document, so it is demoted, never dropped.
 *
 * PROVENANCE — these names are NOT invented here. `crates/chancela-templates/assets/*.json`
 * carries no `title`/`name` metadata and `TemplateSummary`
 * (`crates/chancela-api/src/documents.rs:7662`) does not expose one, so there is nothing to
 * surface directly. What the assets DO carry is an authored human heading, and every value
 * below was extracted from it by one rule:
 *
 *   1. the first `Heading` block when it is static text  → e.g. "Termo de abertura do livro de atas";
 *   2. otherwise ("Ata n.º {{ ata_number }}"), the second heading's authored default —
 *      `{% if title %}{{ title }}{% else %}X{% endif %}` or `{{ title | default("X") }}` → X;
 *   3. seven templates whose heading is a bare `{{ title }}` with no default have no authored
 *      name at all; those are marked inline and named from their family/organ.
 *
 * DRIFT — a copied map can fall behind the assets. The durable fix is a `title` on the
 * server's `TemplateSummary` so the catalog ships its own name; this map is the honest
 * interim, and is keyed by the id WITHOUT the version so a future `/v2` of the same document
 * type inherits the name rather than silently falling back.
 *
 * NOT LOCALIZED, on purpose. These are Portuguese legal document types and each asset declares
 * `"locale": "pt-PT"`. They follow the UX-21 boundary already documented in
 * `src/i18n/TRANSLATIONS.md` for the Legislação diploma shelf: legal content is rendered
 * verbatim in every locale. An invented Danish rendering of "Termo de abertura" would be a
 * worse answer than the authentic Portuguese one.
 */
const TEMPLATE_NAMES: Readonly<Record<string, string>> = {
  'assoc-ata-alteracao-estatutos': 'Assembleia geral — Alteração dos estatutos',
  'assoc-ata-conselho-fiscal': 'Reunião do conselho fiscal',
  'assoc-ata-direcao': 'Reunião da direção',
  'assoc-ata-eleicao-orgaos': 'Assembleia geral — Eleição dos órgãos sociais',
  'assoc-ata-ga': 'Ata de assembleia geral', // named here: the template heading is a free-text {{ title }}
  'assoc-ata-tomada-posse': 'Tomada de posse dos órgãos sociais',
  'assoc-certidao-ata': 'Certidão de ata',
  'assoc-convocatoria-ga': 'Convocatória — Assembleia Geral',
  'assoc-declaracao-deliberacao': 'Declaração de deliberação',
  'assoc-declaracao-voto': 'Declaração de voto',
  'assoc-extrato-ata': 'Extrato de ata',
  'assoc-lista-presencas': 'Lista de presenças',
  'assoc-ponto-ordem-trabalhos': 'Ponto da ordem de trabalhos',
  'assoc-procuracao-representacao': 'Instrumento de representação de associado',
  'assoc-termo-abertura': 'Termo de abertura do livro de atas',
  'assoc-termo-encerramento': 'Termo de encerramento do livro de atas',
  'assoc-termo-retificacao': 'Termo de retificação',
  'assoc-termo-transporte': 'Termo de transporte do livro de atas',
  'condominio-anexo-acordo-email': 'Anexo — acordo de comunicações por correio eletrónico',
  'condominio-ata-assembleia': 'Ata de assembleia de condóminos', // named here: the template heading is a free-text {{ title }}
  'condominio-aviso-convocatoria': 'Convocatória — Assembleia de condóminos',
  'condominio-certidao-ata': 'Certidão de ata',
  'condominio-comunicacao-ausentes': 'Comunicação de deliberações a condóminos ausentes',
  'condominio-declaracao-voto': 'Declaração de voto',
  'condominio-extrato-ata': 'Extrato de ata',
  'condominio-lista-presencas': 'Lista de presenças',
  'condominio-ponto-ordem-trabalhos': 'Ponto da ordem de trabalhos',
  'condominio-procuracao-representacao': 'Instrumento de representação de condómino',
  'condominio-termo-abertura': 'Termo de abertura do livro de atas',
  'condominio-termo-encerramento': 'Termo de encerramento do livro de atas',
  'condominio-termo-retificacao': 'Termo de retificação',
  'condominio-termo-transporte': 'Termo de transporte do livro de atas',
  'cooperativa-ata-ag': 'Ata de assembleia geral', // named here: the template heading is a free-text {{ title }}
  'cooperativa-ata-direcao': 'Ata de reunião da direção', // named here: the template heading is a free-text {{ title }}
  'cooperativa-certidao-ata': 'Certidão de ata',
  'cooperativa-comunicacao-registo': 'Comunicação para registo',
  'cooperativa-convocatoria-ag': 'Convocatória — Assembleia Geral',
  'cooperativa-declaracao-voto': 'Declaração de voto',
  'cooperativa-extrato-ata': 'Extrato de ata',
  'cooperativa-lista-presencas': 'Lista de presenças',
  'cooperativa-ponto-ordem-trabalhos': 'Ponto da ordem de trabalhos',
  'cooperativa-procuracao-representacao': 'Instrumento de representação de cooperador',
  'cooperativa-termo-abertura': 'Termo de abertura do livro de atas',
  'cooperativa-termo-encerramento': 'Termo de encerramento do livro de atas',
  'cooperativa-termo-retificacao': 'Termo de retificação',
  'cooperativa-termo-transporte': 'Termo de transporte do livro de atas',
  'csc-ata-ag': 'Ata de assembleia geral', // named here: the template heading is a free-text {{ title }}
  'csc-ata-alteracao-firma': 'Ata de alteração da firma',
  'csc-ata-alteracao-objeto': 'Ata de alteração do objeto social',
  'csc-ata-alteracao-sede': 'Ata de alteração da sede social',
  'csc-ata-amortizacao-quotas': 'Ata de amortização de quotas',
  'csc-ata-aprovacao-contas': 'Ata de aprovação de contas',
  'csc-ata-aumento-capital': 'Ata de aumento de capital social',
  'csc-ata-cessao-quotas': 'Ata de cessão de quotas',
  'csc-ata-cisao': 'Ata de cisão da sociedade',
  'csc-ata-delegacao-poderes': 'Ata de delegação de poderes',
  'csc-ata-designacao-gerencia': 'Ata de designação da gerência',
  'csc-ata-destituicao-gerencia': 'Ata de destituição da gerência',
  'csc-ata-dissolucao': 'Ata de dissolução da sociedade',
  'csc-ata-distribuicao-dividendos': 'Ata de distribuição de dividendos',
  'csc-ata-divisao-quotas': 'Ata de divisão de quotas',
  'csc-ata-entrada-socio': 'Ata de admissão de novo sócio',
  'csc-ata-fusao': 'Ata de fusão da sociedade',
  'csc-ata-gerencia': 'Ata de reunião da gerência',
  'csc-ata-liquidacao': 'Ata de liquidação da sociedade',
  'csc-ata-nao-remuneracao-gerencia': 'Ata de não remuneração da gerência',
  'csc-ata-prestacoes-suplementares': 'Ata de prestações suplementares',
  'csc-ata-reducao-capital': 'Ata de redução de capital social',
  'csc-ata-remuneracao-gerencia': 'Ata de fixação da remuneração da gerência',
  'csc-ata-renuncia-gerente': 'Ata de renúncia de gerente',
  'csc-ata-revogacao-poderes': 'Ata de revogação de poderes',
  'csc-ata-suprimentos': 'Ata de suprimentos',
  'csc-ata-transformacao': 'Ata de transformação da sociedade',
  'csc-ata-unificacao-quotas': 'Ata de unificação de quotas',
  'csc-certidao-ata': 'Certidão de ata',
  'csc-circular-deliberacao-escrito': 'Deliberação unânime por escrito',
  'csc-comunicacao-registo': 'Comunicação para registo comercial',
  'csc-convocatoria-ag': 'Convocatória — Assembleia Geral',
  'csc-convocatoria-gerencia': 'Convocatória — Reunião de Gerência',
  'csc-declaracao-deliberacao': 'Declaração de deliberação',
  'csc-declaracao-voto': 'Declaração de voto',
  'csc-extrato-ata': 'Extrato de ata',
  'csc-lista-presencas': 'Lista de presenças',
  'csc-ponto-ordem-trabalhos': 'Ponto da ordem de trabalhos',
  'csc-procuracao-representacao': 'Procuração e carta de representação',
  'csc-registo-telematico': 'Registo da reunião telemática',
  'csc-termo-abertura': 'Termo de abertura do livro de atas',
  'csc-termo-encerramento': 'Termo de encerramento do livro de atas',
  'csc-termo-retificacao': 'Termo de retificação',
  'csc-termo-transporte': 'Termo de transporte do livro de atas',
  'fundacao-ata-ca': 'Ata de reunião do conselho de administração', // named here: the template heading is a free-text {{ title }}
  'fundacao-ata-orgao-fiscal': 'Ata de reunião do órgão de fiscalização', // named here: the template heading is a free-text {{ title }}
  'fundacao-certidao-ata': 'Certidão de ata',
  'fundacao-comunicacao-registo': 'Comunicação para registo',
  'fundacao-convocatoria-orgao': 'Convocatória',
  'fundacao-declaracao-voto': 'Declaração de voto',
  'fundacao-extrato-ata': 'Extrato de ata',
  'fundacao-lista-presencas': 'Lista de presenças',
  'fundacao-ponto-ordem-trabalhos': 'Ponto da ordem de trabalhos',
  'fundacao-procuracao-representacao': 'Instrumento de representação em órgão da fundação',
  'fundacao-termo-abertura': 'Termo de abertura do livro de atas',
  'fundacao-termo-encerramento': 'Termo de encerramento do livro de atas',
  'fundacao-termo-retificacao': 'Termo de retificação',
  'fundacao-termo-transporte': 'Termo de transporte do livro de atas',
};

/** `assoc-ata-conselho-fiscal/v1` → `assoc-ata-conselho-fiscal`. */
export function templateBaseId(templateId: string): string {
  return templateId.trim().replace(/\/v\d+$/u, '');
}

/** `assoc-ata-conselho-fiscal/v1` → `v1`; undefined when the id carries no version. */
export function templateVersion(templateId: string): string | undefined {
  return /\/(v\d+)$/u.exec(templateId.trim())?.[1];
}

/**
 * The document type's name, or `undefined` for a template the catalog does not name — a
 * user-authored `user-…/v1`, or a built-in added after this map. Callers that need a string
 * should use {@link templateDisplayName}.
 */
export function templateName(templateId: string): string | undefined {
  return TEMPLATE_NAMES[templateBaseId(templateId)];
}

/**
 * Always renders something: the document type's name when known, else the id itself (never
 * blank, never `undefined`). The raw id stays meaningful — it is what the catalog search,
 * the export filename and the template API all key on.
 */
export function templateDisplayName(templateId: string): string {
  const trimmed = templateId.trim();
  if (!trimmed) return templateId;
  return templateName(trimmed) ?? trimmed;
}

/** True when the id resolves to a catalog name rather than falling back to itself. */
export function hasTemplateName(templateId: string): boolean {
  return templateName(templateId) !== undefined;
}
