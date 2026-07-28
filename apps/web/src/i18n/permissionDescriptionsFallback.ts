/**
 * PERMISSION DESCRIPTIONS (t74) — the sentence that says what ticking a verb actually grants.
 *
 * The RBAC matrix used to render each permission as a bare `<code>user.manage</code>`. An
 * administrator authoring a função was therefore choosing authority from an identifier alone. This
 * module supplies the human sentence rendered underneath that identifier. The identifier is NOT
 * replaced — it stays, in `mono`, as the stable thing an operator quotes; the description is added
 * beside it.
 *
 * ─── WHERE THIS LIVES, AND WHY IT IS NOT ON THE WIRE ───────────────────────────────────────────
 *
 * The authoritative catalog is Rust: `Permission::ALL` in `crates/chancela-authz/src/permission.rs`,
 * 53 verbs, served verbatim by `GET /v1/permissions`. The descriptions could have been added to
 * `PermissionInfo` so they ship next to the definition. They are not, for two reasons:
 *
 * 1. `PermissionInfo` is marked **FROZEN** in `chancela-api/src/roles.rs`. Widening a frozen wire
 *    struct to carry display copy is a contract change made for a rendering concern.
 * 2. These are user-facing sentences, and the app localises client-side over 14 locales. A
 *    `description` on the wire would be one language for every reader, and `GET /v1/permissions`
 *    does no locale negotiation. Copy belongs on the side of the boundary that knows the locale.
 *
 * This is the same split `dpiaTemplateLabels.ts` makes: stable English ids stay authoritative on
 * the wire, the client resolves them to translated copy, and a test driven off the backend's own
 * source fails when the two populations diverge.
 *
 * **Why a self-contained module rather than the shared catalogs.** `Catalog` is a total type over
 * all 14 locales, so 53 keys would be 742 edits across files that several live lanes are serialised
 * on. This follows the established escape valve — `apiErrorFallback.ts`,
 * `privacyLegalHoldFallback.ts` and ~20 siblings: a pt-PT source object plus an English tier that
 * `satisfies` the same key set, resolved through its own locale-aware hook.
 *
 * ─── THE DIVERGENCE GUARANTEE ──────────────────────────────────────────────────────────────────
 *
 * `permissionDescriptionsFallback.test.ts` parses `permission.rs` and asserts **set equality** in
 * both directions: a verb added to the Rust catalog without a description here is red, and a
 * description here for a verb the catalog no longer has is red. It also re-derives the phantom set
 * (below) from `permission_description.rs`, so a verb that starts or stops gating something forces
 * its sentence to be rewritten.
 *
 * At runtime, a verb this build has no description for still must not render as blank space —
 * {@link usePermissionDescriptionResolver} returns an explicit "not described in this version"
 * sentence with `known: false`, never an empty string.
 *
 * ─── THE VERB THAT GRANTS NOTHING ──────────────────────────────────────────────────────────────
 *
 * `book.reopen` is audited `FeatureNotBuilt` in
 * `crates/chancela-authz/src/permission_description.rs`: it is seeded into real funções and
 * rendered in this matrix, but no route reaches the capability it names. Describing it from its
 * spelling — "reabre livros" — would be a security misstatement, telling an administrator they
 * granted an authority that does not exist. Its sentence therefore states that the capability was
 * never built, which is the audited fact, not reassurance.
 *
 * It is not merely unbuilt. t77 established that reopening a closed book cannot be built without
 * contradicting a signed instrument: the termo de encerramento is co-signed with the book's
 * authoritative ata count, so reopening and registering one more ata leaves a validly-signed
 * document asserting something false. Continuing a closed book already has a sound path — a
 * successor book under its own termo de abertura — so this sentence is not a placeholder waiting
 * on a feature.
 *
 * `tenant.admin` was the second such verb until t77 built `PATCH /v1/tenants/{tenant_id}`; its
 * sentence moved from "grants nothing" to the rename it now really gates.
 * {@link PERMISSIONS_THAT_GRANT_NOTHING} pins the set and the test re-derives it from Rust, so a
 * sentence here cannot silently stay false in either direction.
 *
 * ─── AUTHORING RULES ───────────────────────────────────────────────────────────────────────────
 *
 * Written from the enforcement audit's recorded handler evidence, never from the verb's spelling.
 * Each entry is a COMPLETE standalone sentence with no placeholder: a noun interpolated into
 * Portuguese breaks article, adjective and participle agreement, so copy that varies by noun varies
 * by key (memory: `i18n-interpolated-nouns-break-agreement`). pt-PT, no invented anglicisms
 * (memory: `pt-pt-no-invented-anglicisms`). No description restates its own identifier. Permission
 * ids stay English — they are identifiers, not copy.
 */
import { useMemo } from 'react';
import type { Locale } from '../api/types';
import { useActiveLocale } from './useT';

/**
 * pt-PT is the authoring source. Keys are the catalog's stable dotted ids, in `Permission::ALL`
 * declaration order so this file reads against `permission.rs` side by side.
 */
export const permissionDescriptionsPtPT = {
  // --- Tenants ---
  'tenant.read':
    'Ver a lista de organizações desta instalação e abrir a ficha de cada uma. Quem só tem alcance sobre a sua própria organização vê apenas essa.',
  'tenant.create':
    'Criar uma organização nova nesta instalação. É um ato de aprovisionamento da plataforma, que não se limita a nenhuma organização já existente.',
  'tenant.admin':
    'Alterar o nome de uma organização já existente. Quem só tem alcance sobre a sua própria organização altera apenas essa e mais nenhuma. Não permite criar organizações novas.',

  // --- Entities ---
  'entity.read':
    'Ver as entidades e as suas fichas, os livros que lhes pertencem, a cronologia de cada uma e o painel de um grupo, incluindo os dados vindos do registo comercial.',
  'entity.create':
    'Criar entidades novas, tanto preenchendo os dados de raiz como a partir de uma importação do registo comercial.',
  'entity.update':
    'Alterar os dados de uma entidade já existente e mover entidades para dentro e para fora de grupos.',
  'entity.registry.import':
    'Trazer dados do registo comercial para uma entidade já existente e pedir a sua atualização automática.',
  'entity.archive':
    'Retirar uma entidade do trabalho corrente e voltar a trazê-la. O que já existe continua legível, pesquisável e exportável; deixa apenas de se poder começar trabalho novo.',

  // --- Books ---
  'book.read':
    'Ver os livros e o seu conteúdo, incluindo o termo de abertura, o termo de encerramento e os documentos de assinatura desses termos.',
  'book.open':
    'Abrir um livro e preparar, alterar e assinar o respetivo termo de abertura.',
  'book.close':
    'Encerrar um livro e preparar, alterar e assinar o respetivo termo de encerramento.',
  'book.export':
    'Exportar um livro e o seu pacote de arquivo, consultar o estado de descarte e gerar pacotes de leitura.',
  'book.import':
    'Importar um livro a partir de um pacote exportado e conduzir a importação de livros em papel.',
  'book.start_over':
    'Apagar o conteúdo de um livro e recomeçá-lo do zero. O que lá estava não é recuperável por esta via.',
  'book.reopen':
    'Não concede nada. Não existe forma de reabrir um livro encerrado: o modelo de dados só permite abrir e encerrar, pelo que esta permissão não protege operação nenhuma.',

  // --- Legal hold ---
  'legal_hold.manage':
    'Colocar, substituir e levantar a retenção legal de um livro, e executar o descarte do arquivo. Levantar uma retenção deixa de travar a destruição do registo.',

  // --- Acts ---
  'act.read':
    'Ver os atos e o seu conteúdo, os documentos associados, os seguimentos, as notificações e o estado das assinaturas. É a leitura mais abrangente do catálogo.',
  'act.draft':
    'Criar o rascunho de um ato novo, incluindo a partir de um livro em papel já convertido.',
  'act.edit':
    'Alterar o conteúdo de um ato antes da selagem, tratar a convocatória e gerir os seguimentos.',
  'act.advance':
    'Fazer o ato avançar para o passo seguinte do seu percurso e confirmar a revisão humana quando houve apoio de inteligência artificial.',
  'act.revert':
    'Fazer o ato recuar para um passo anterior, enquanto ainda não há assinatura. É uma autoridade distinta da de o fazer avançar.',
  'act.archive':
    'Arquivar um ato, retirando-o do trabalho corrente sem o apagar.',

  // --- Signing ---
  'signing.perform':
    'Assinar e selar. Abrange a assinatura local, o Cartão de Cidadão, a Chave Móvel Digital, a assinatura remota e em lote, os convites a assinantes externos e os carimbos temporais de arquivo.',
  'signing.configure':
    'Definir como se assina: a política de assinatura, as listas de confiança e as respetivas âncoras, as autoridades de carimbo temporal e as credenciais dos fornecedores. Não permite assinar.',

  // --- Documents ---
  'document.generate':
    'Gerar documentos a partir de um ato, importar documentos externos, rever os que foram importados e registar a prova do seu envio.',

  // --- Templates ---
  'template.manage':
    'Criar, alterar, importar e eliminar modelos de documento, e gerir as bibliotecas de modelos de um grupo. Ver e exportar modelos não depende desta permissão.',

  // --- Full search ---
  'search.read':
    'Pesquisar em todos os domínios a partir de um único ponto. Cada resultado continua sujeito à sua própria permissão de leitura, pelo que a pesquisa nunca alarga o acesso.',
  'search.manage':
    'Reconstruir, suspender e retomar a indexação da pesquisa, e alterar as definições que a governam.',

  // --- Ledger ---
  'ledger.read':
    'Consultar os acontecimentos da cadeia de registo, verificar a sua integridade e obter as atestações correspondentes.',
  'ledger.recover':
    'Consultar a prova de recuperação: os ensaios sobre cópias de segurança e a verificação prévia de uma transferência. Não altera nada.',
  'ledger.reanchor':
    'Voltar a fixar a cadeia de registo durante uma recuperação. Altera o registo e exige autenticação reforçada.',
  'ledger.restore':
    'Repor a cadeia de registo a partir de um pacote de recuperação, e correr a verificação prévia dessa reposição. Exige autenticação reforçada.',

  // --- Data ---
  'data.backup':
    'Criar cópias de segurança e materializar os artefactos que delas dependem.',
  'data.export':
    'Descarregar os objetos guardados no repositório de dados.',
  'data.wipe':
    'Apagar os dados desta instalação. O que for apagado por esta via não volta.',
  'data.start_over':
    'Repor a instalação no estado inicial, deitando abaixo o trabalho existente. O que for apagado por esta via não volta.',

  // --- Privacy & retention ---
  'privacy.manage':
    'Gerir os registos de proteção de dados — subcontratantes, avaliações de impacto, planos de resposta a violações e controlos de transferência — e responder aos pedidos dos titulares, incluindo exportação, retificação, limitação e apagamento.',
  'retention.manage':
    'Definir as políticas de retenção e conduzir o seu ciclo: candidatos em prazo, simulações, execuções e o respetivo encerramento.',

  // --- Settings ---
  'settings.read':
    'Ver as configurações da instalação e os painéis de estado que delas dependem, incluindo serviços, registos da plataforma e correio eletrónico.',
  'settings.manage':
    'Alterar as configurações da instalação: correio eletrónico, variáveis de ambiente, controlo de serviços, limpeza de dados, rotação de chaves e destinos de ligação.',

  // --- Platform operations ---
  'platform.logs.write':
    'Entregar à plataforma registos de funcionamento vindos de um processo externo. Uma recusa fica ela própria registada.',

  // --- Reference ---
  'cae.read':
    'Consultar o catálogo de atividades económicas e a lista de serviços de confiança.',
  'cae.refresh':
    'Atualizar o catálogo de atividades económicas a partir da origem que o publica.',
  'law.read':
    'Consultar legislação: diplomas, artigos, os documentos em PDF e a pesquisa no corpo legislativo.',
  'law.manage':
    'Trazer legislação nova para a instalação e remover os documentos em PDF já guardados.',

  // --- Trust services ---
  'trust.manage':
    'Importar a lista de serviços de confiança. É essa lista que decide quais as assinaturas que o produto aceita como válidas, pelo que se trata de configuração de segurança e não de dados de referência.',

  // --- Users ---
  'user.read':
    'Ver a lista de utilizadores e a ficha de cada um.',
  'user.manage':
    'Administrar utilizadores já existentes: alterar a ficha, definir e retirar segredos, emitir recuperações, gerir chaves de atestação, gerir as chaves de acesso à API e tratar a autenticação em dois passos.',
  'user.invite':
    'Convidar alguém a criar conta. Quem convida não passa a poder editar, desativar nem ver os segredos de contas já existentes, e a conta criada recebe a função predefinida para novos registos.',

  // --- RBAC meta ---
  'role.manage':
    'Criar, alterar e eliminar funções, decidindo que permissões cada uma concede. Nunca permite conceder mais do que aquilo que já se possui.',
  'role.assign':
    'Atribuir uma função a um utilizador e retirar-lha.',
  'delegation.grant':
    'Passar a outra pessoa, por tempo limitado, uma permissão que já se possui.',
  'delegation.revoke':
    'Ver as delegações em vigor, suspendê-las, retomá-las e revogá-las.',
} as const;

/** The catalog verb ids this module describes. */
export type DescribedPermissionId = keyof typeof permissionDescriptionsPtPT;

type PermissionDescriptions = Record<DescribedPermissionId, string>;

/**
 * en-US is the fallback tier every non-pt-PT locale receives (t40); en-GB shares it. Folding the
 * remaining twelve locales in later is a mechanical addition to {@link DESCRIPTIONS_BY_LOCALE}.
 */
export const permissionDescriptionsEnglish = {
  // --- Tenants ---
  'tenant.read':
    'See the organisations on this installation and open each one. Someone whose reach is limited to their own organisation sees only that one.',
  'tenant.create':
    'Create a new organisation on this installation. This is a platform provisioning act, not narrowed to any existing organisation.',
  'tenant.admin':
    'Rename an existing organisation. Someone whose reach is limited to their own organisation renames only that one. It does not allow creating new organisations.',

  // --- Entities ---
  'entity.read':
    'See entities and their records, the books belonging to them, each one’s chronology and a group dashboard, including data drawn from the commercial registry.',
  'entity.create':
    'Create new entities, either by entering the details directly or from a commercial registry import.',
  'entity.update':
    'Change the details of an existing entity, and move entities into and out of groups.',
  'entity.registry.import':
    'Pull commercial registry data into an existing entity and request its automatic update.',
  'entity.archive':
    'Retire an entity from current work and bring it back. What already exists stays readable, searchable and exportable; only starting new work stops.',

  // --- Books ---
  'book.read':
    'See books and their contents, including the opening record, the closing record and the signature documents for both.',
  'book.open': 'Open a book, and prepare, change and sign its opening record.',
  'book.close': 'Close a book, and prepare, change and sign its closing record.',
  'book.export':
    'Export a book and its archive package, check disposal status, and produce readability packages.',
  'book.import':
    'Import a book from an exported package, and carry out the import of paper books.',
  'book.start_over':
    'Erase a book’s contents and start it again from scratch. What was there is not recoverable this way.',
  'book.reopen':
    'Grants nothing. There is no way to reopen a closed book: the data model only allows opening and closing, so this permission guards no operation.',

  // --- Legal hold ---
  'legal_hold.manage':
    'Place, replace and release a book’s legal hold, and carry out archive disposal. Releasing a hold stops blocking destruction of the record.',

  // --- Acts ---
  'act.read':
    'See acts and their contents, the associated documents, follow-ups, notifications and signature status. This is the broadest read in the catalogue.',
  'act.draft': 'Create the draft of a new act, including from an already converted paper book.',
  'act.edit':
    'Change an act’s contents before sealing, handle the convening notice, and manage follow-ups.',
  'act.advance':
    'Move an act forward to the next step of its lifecycle, and confirm human review where artificial intelligence assisted.',
  'act.revert':
    'Move an act back to an earlier step while there is still no signature. This is a separate authority from moving it forward.',
  'act.archive': 'Archive an act, taking it out of current work without deleting it.',

  // --- Signing ---
  'signing.perform':
    'Sign and seal. Covers local signing, the Cartão de Cidadão, the Chave Móvel Digital, remote and batch signing, external signer invitations, and archive timestamps.',
  'signing.configure':
    'Set how signing works: the signature policy, trust lists and their anchors, timestamp authorities, and provider credentials. It does not allow signing.',

  // --- Documents ---
  'document.generate':
    'Generate documents from an act, import external documents, review imported ones, and record proof that they were sent.',

  // --- Templates ---
  'template.manage':
    'Create, change, import and delete document templates, and manage a group’s template libraries. Viewing and exporting templates does not depend on this permission.',

  // --- Full search ---
  'search.read':
    'Search across every domain from a single place. Each result stays subject to its own read permission, so search never widens access.',
  'search.manage':
    'Rebuild, pause and resume search indexing, and change the settings that govern it.',

  // --- Ledger ---
  'ledger.read':
    'Inspect ledger events, verify the chain’s integrity, and obtain the corresponding attestations.',
  'ledger.recover':
    'Inspect recovery evidence: backup recovery drills and the preflight for a handover. It changes nothing.',
  'ledger.reanchor':
    'Re-anchor the ledger during a recovery. It mutates the record and requires step-up authentication.',
  'ledger.restore':
    'Restore the ledger from a recovery bundle, and run that restore’s preflight. Requires step-up authentication.',

  // --- Data ---
  'data.backup': 'Create backups and materialise the artefacts that depend on them.',
  'data.export': 'Download the objects held in the data repository.',
  'data.wipe':
    'Erase this installation’s data. What is erased this way does not come back.',
  'data.start_over':
    'Reset the installation to its initial state, tearing down existing work. What is erased this way does not come back.',

  // --- Privacy & retention ---
  'privacy.manage':
    'Manage data protection records — processors, impact assessments, breach playbooks and transfer controls — and answer data subject requests, including export, rectification, restriction and erasure.',
  'retention.manage':
    'Set retention policies and run their lifecycle: due candidates, dry runs, executions and their closure.',

  // --- Settings ---
  'settings.read':
    'See the installation settings and the status panels that depend on them, including services, platform logs and email.',
  'settings.manage':
    'Change the installation settings: email, environment variables, service control, data cleanup, key rotation and connector targets.',

  // --- Platform operations ---
  'platform.logs.write':
    'Hand operational logs from an external process to the platform. A refusal is itself recorded.',

  // --- Reference ---
  'cae.read': 'Consult the economic activity catalogue and the trusted service list.',
  'cae.refresh': 'Update the economic activity catalogue from the source that publishes it.',
  'law.read':
    'Consult legislation: instruments, articles, the PDF documents, and search over the legal corpus.',
  'law.manage': 'Bring new legislation into the installation and remove stored PDF documents.',

  // --- Trust services ---
  'trust.manage':
    'Import the trusted service list. That list decides which signatures the product accepts as valid, so this is security configuration rather than reference data.',

  // --- Users ---
  'user.read': 'See the list of users and each user’s record.',
  'user.manage':
    'Administer existing users: change the record, set and remove secrets, issue recoveries, manage attestation keys, manage API access keys, and handle two-step authentication.',
  'user.invite':
    'Invite someone to create an account. An inviter does not thereby edit, deactivate or read the secrets of existing accounts, and the created account receives the default role for new registrations.',

  // --- RBAC meta ---
  'role.manage':
    'Create, change and delete roles, deciding which permissions each one grants. It never allows granting more than one already holds.',
  'role.assign': 'Give a role to a user and take it away.',
  'delegation.grant': 'Pass a permission one already holds to someone else, for a limited time.',
  'delegation.revoke': 'See the delegations in force, suspend them, resume them and revoke them.',
} as const satisfies PermissionDescriptions;

/**
 * The verbs whose sentence says the capability does not exist, rather than describing an authority.
 *
 * Audited as `PermissionEnforcement::FeatureNotBuilt` in
 * `crates/chancela-authz/src/permission_description.rs`; the test re-derives this set from that
 * source so it cannot silently go stale in either direction.
 */
export const PERMISSIONS_THAT_GRANT_NOTHING = [
  'book.reopen',
] as const satisfies readonly DescribedPermissionId[];

/** Shown when the served catalog carries a verb this build has no sentence for. Never blank. */
const NOT_DESCRIBED_PT_PT =
  'Esta versão da aplicação não traz uma explicação para esta permissão. Confirme o seu alcance antes de a conceder.';
const NOT_DESCRIBED_ENGLISH =
  'This version of the application carries no explanation for this permission. Confirm its reach before granting it.';

interface DescriptionTier {
  descriptions: PermissionDescriptions;
  notDescribed: string;
}

const PT_PT_TIER: DescriptionTier = {
  descriptions: permissionDescriptionsPtPT,
  notDescribed: NOT_DESCRIBED_PT_PT,
};
const ENGLISH_TIER: DescriptionTier = {
  descriptions: permissionDescriptionsEnglish,
  notDescribed: NOT_DESCRIBED_ENGLISH,
};

/** pt-PT is the source; every other locale receives the English tier until it is reviewed. */
const DESCRIPTIONS_BY_LOCALE: Partial<Record<Locale, DescriptionTier>> = {
  'pt-PT': PT_PT_TIER,
  'en-US': ENGLISH_TIER,
  'en-GB': ENGLISH_TIER,
};

/** A resolved description. `text` is never empty, so the UI can render it unconditionally. */
export interface PermissionDescription {
  /** The sentence to render. Never an empty string. */
  text: string;
  /** False when this build has no sentence for the verb the server served. */
  known: boolean;
}

/** Resolve a permission id against a tier. Exported shape used by both the hook and the test. */
export function describePermission(
  permission: string,
  tier: DescriptionTier = PT_PT_TIER,
): PermissionDescription {
  const text = (tier.descriptions as Record<string, string | undefined>)[permission];
  return text === undefined ? { text: tier.notDescribed, known: false } : { text, known: true };
}

/**
 * The matrix's description resolver, locale-aware:
 * `const describe = usePermissionDescriptionResolver(); describe(info.permission).text`.
 */
export function usePermissionDescriptionResolver(): (permission: string) => PermissionDescription {
  const locale = useActiveLocale();
  const tier = DESCRIPTIONS_BY_LOCALE[locale] ?? ENGLISH_TIER;
  return useMemo(() => (permission: string) => describePermission(permission, tier), [tier]);
}
