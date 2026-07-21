/**
 * Display labels for the **type** half of a ledger event's `scope`.
 *
 * A scope is not an enum. It is a `/`-joined path of `type:id` segments built in the API
 * (`entity:{uuid}/book:{uuid}/act:{uuid}`, `tenant:{uuid}`, `user:{uuid}`, `role:{uuid}`,
 * `delegation:{uuid}`, `tenant:{uuid}/repository:{uuid}/archive:{uuid}`), interleaved with a
 * fixed set of keyword scopes that carry no id at all (`settings`, `law`, `cae`, …). Only the
 * *type* tokens are a closed set, so only they are translated here; the *name* half is a
 * reference to a live record and is resolved at render time against data the viewer is already
 * authorized to read — see `src/features/ledger/scopeLabel.ts`.
 *
 * KEYING mirrors the wire token exactly (`enum.ledgerScopeType.provider_credentials`), so a new
 * scope type added in the API surfaces as an unlabelled token rather than as the wrong label.
 *
 * FALLBACK. An unrecognised token is never guessed at: the renderer falls back to
 * `enum.ledgerScopeType.unknown` and keeps the raw token visible beside it.
 *
 * GRAMMAR. Every value is a **bare noun phrase**, never a sentence. The renderer joins it to a
 * resolved name with a locale-invariant em dash (`Entidade — Encosto Estratégico Lda`), so no
 * substituted value is ever the subject of an inflected word — TRANSLATIONS.md rules 1 and 3 are
 * satisfied by construction rather than by careful phrasing.
 *
 * TRANSLATION STATUS. System labels, so localized in all 14 locales on the same boundary as
 * `ledgerEventLabels.ts` / `dashboardSourceLabels.ts`: pt-PT is the source, en-US/en-GB are
 * human-authored, the rest are machine-authored and pending native review. `CAE` is the
 * Portuguese economic-activity classification and stays verbatim in every locale.
 */
export const ledgerScopeLabelsPtPT = {
  'enum.ledgerScopeType.act': 'Ata',
  'enum.ledgerScopeType.api-key': 'Chaves de API',
  'enum.ledgerScopeType.archive': 'Arquivo',
  'enum.ledgerScopeType.backup': 'Cópias de segurança',
  'enum.ledgerScopeType.book': 'Livro',
  'enum.ledgerScopeType.book_archive': 'Arquivo de livros',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Delegação',
  'enum.ledgerScopeType.email': 'E-mail',
  'enum.ledgerScopeType.entity': 'Entidade',
  'enum.ledgerScopeType.global': 'Aplicação',
  'enum.ledgerScopeType.imported-document': 'Documento importado',
  'enum.ledgerScopeType.law': 'Legislação',
  'enum.ledgerScopeType.paper-book-import': 'Importação de livro em papel',
  'enum.ledgerScopeType.platform': 'Plataforma',
  'enum.ledgerScopeType.provider_credentials': 'Credenciais de fornecedores',
  'enum.ledgerScopeType.recovery': 'Recuperação da cadeia',
  'enum.ledgerScopeType.repository': 'Repositório',
  'enum.ledgerScopeType.role': 'Função',
  'enum.ledgerScopeType.settings': 'Definições',
  'enum.ledgerScopeType.tenant': 'Organização',
  'enum.ledgerScopeType.trust': 'Lista de confiança (TSL)',
  'enum.ledgerScopeType.unknown': 'Âmbito',
  'enum.ledgerScopeType.user': 'Utilizador',
  'enum.ledgerScopeType.user_accounts': 'Contas de utilizador',
};

/** The shared shape: every locale carries exactly the pt-PT key set. */
export type LedgerScopeLabels = Record<keyof typeof ledgerScopeLabelsPtPT, string>;

/** en-US — human-authored. */
export const ledgerScopeLabelsEnglish: LedgerScopeLabels = {
  'enum.ledgerScopeType.act': 'Minutes',
  'enum.ledgerScopeType.api-key': 'API keys',
  'enum.ledgerScopeType.archive': 'Archive',
  'enum.ledgerScopeType.backup': 'Backups',
  'enum.ledgerScopeType.book': 'Book',
  'enum.ledgerScopeType.book_archive': 'Book archive',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Delegation',
  'enum.ledgerScopeType.email': 'E-mail',
  'enum.ledgerScopeType.entity': 'Entity',
  'enum.ledgerScopeType.global': 'Application',
  'enum.ledgerScopeType.imported-document': 'Imported document',
  'enum.ledgerScopeType.law': 'Legislation',
  'enum.ledgerScopeType.paper-book-import': 'Paper book import',
  'enum.ledgerScopeType.platform': 'Platform',
  'enum.ledgerScopeType.provider_credentials': 'Provider credentials',
  'enum.ledgerScopeType.recovery': 'Chain recovery',
  'enum.ledgerScopeType.repository': 'Repository',
  'enum.ledgerScopeType.role': 'Role',
  'enum.ledgerScopeType.settings': 'Settings',
  'enum.ledgerScopeType.tenant': 'Organization',
  'enum.ledgerScopeType.trust': 'Trust list (TSL)',
  'enum.ledgerScopeType.unknown': 'Scope',
  'enum.ledgerScopeType.user': 'User',
  'enum.ledgerScopeType.user_accounts': 'User accounts',
};

/** en-GB — British spelling over the en-US slice. */
export const ledgerScopeLabelsEnGB: LedgerScopeLabels = {
  ...ledgerScopeLabelsEnglish,
  'enum.ledgerScopeType.tenant': 'Organisation',
};

/** pt-BR — Brazilian usage over the pt-PT source. */
export const ledgerScopeLabelsPtBR: LedgerScopeLabels = {
  'enum.ledgerScopeType.act': 'Ata',
  'enum.ledgerScopeType.api-key': 'Chaves de API',
  'enum.ledgerScopeType.archive': 'Arquivo',
  'enum.ledgerScopeType.backup': 'Backups',
  'enum.ledgerScopeType.book': 'Livro',
  'enum.ledgerScopeType.book_archive': 'Arquivo de livros',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Delegação',
  'enum.ledgerScopeType.email': 'E-mail',
  'enum.ledgerScopeType.entity': 'Entidade',
  'enum.ledgerScopeType.global': 'Aplicação',
  'enum.ledgerScopeType.imported-document': 'Documento importado',
  'enum.ledgerScopeType.law': 'Legislação',
  'enum.ledgerScopeType.paper-book-import': 'Importação de livro em papel',
  'enum.ledgerScopeType.platform': 'Plataforma',
  'enum.ledgerScopeType.provider_credentials': 'Credenciais de provedores',
  'enum.ledgerScopeType.recovery': 'Recuperação da cadeia',
  'enum.ledgerScopeType.repository': 'Repositório',
  'enum.ledgerScopeType.role': 'Função',
  'enum.ledgerScopeType.settings': 'Configurações',
  'enum.ledgerScopeType.tenant': 'Organização',
  'enum.ledgerScopeType.trust': 'Lista de confiança (TSL)',
  'enum.ledgerScopeType.unknown': 'Escopo',
  'enum.ledgerScopeType.user': 'Usuário',
  'enum.ledgerScopeType.user_accounts': 'Contas de usuário',
};

/** es-ES — machine-authored, pending native review. */
export const ledgerScopeLabelsEsES: LedgerScopeLabels = {
  'enum.ledgerScopeType.act': 'Acta',
  'enum.ledgerScopeType.api-key': 'Claves de API',
  'enum.ledgerScopeType.archive': 'Archivo',
  'enum.ledgerScopeType.backup': 'Copias de seguridad',
  'enum.ledgerScopeType.book': 'Libro',
  'enum.ledgerScopeType.book_archive': 'Archivo de libros',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Delegación',
  'enum.ledgerScopeType.email': 'Correo electrónico',
  'enum.ledgerScopeType.entity': 'Entidad',
  'enum.ledgerScopeType.global': 'Aplicación',
  'enum.ledgerScopeType.imported-document': 'Documento importado',
  'enum.ledgerScopeType.law': 'Legislación',
  'enum.ledgerScopeType.paper-book-import': 'Importación de libro en papel',
  'enum.ledgerScopeType.platform': 'Plataforma',
  'enum.ledgerScopeType.provider_credentials': 'Credenciales de proveedores',
  'enum.ledgerScopeType.recovery': 'Recuperación de la cadena',
  'enum.ledgerScopeType.repository': 'Repositorio',
  'enum.ledgerScopeType.role': 'Función',
  'enum.ledgerScopeType.settings': 'Configuración',
  'enum.ledgerScopeType.tenant': 'Organización',
  'enum.ledgerScopeType.trust': 'Lista de confianza (TSL)',
  'enum.ledgerScopeType.unknown': 'Ámbito',
  'enum.ledgerScopeType.user': 'Usuario',
  'enum.ledgerScopeType.user_accounts': 'Cuentas de usuario',
};

/** fr-FR — machine-authored, pending native review. */
export const ledgerScopeLabelsFrFR: LedgerScopeLabels = {
  'enum.ledgerScopeType.act': 'Procès-verbal',
  'enum.ledgerScopeType.api-key': 'Clés d’API',
  'enum.ledgerScopeType.archive': 'Archives',
  'enum.ledgerScopeType.backup': 'Sauvegardes',
  'enum.ledgerScopeType.book': 'Livre',
  'enum.ledgerScopeType.book_archive': 'Archives des livres',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Délégation',
  'enum.ledgerScopeType.email': 'Courriel',
  'enum.ledgerScopeType.entity': 'Entité',
  'enum.ledgerScopeType.global': 'Application',
  'enum.ledgerScopeType.imported-document': 'Document importé',
  'enum.ledgerScopeType.law': 'Législation',
  'enum.ledgerScopeType.paper-book-import': 'Importation de livre papier',
  'enum.ledgerScopeType.platform': 'Plateforme',
  'enum.ledgerScopeType.provider_credentials': 'Identifiants de fournisseurs',
  'enum.ledgerScopeType.recovery': 'Récupération de la chaîne',
  'enum.ledgerScopeType.repository': 'Référentiel',
  'enum.ledgerScopeType.role': 'Rôle',
  'enum.ledgerScopeType.settings': 'Paramètres',
  'enum.ledgerScopeType.tenant': 'Organisation',
  'enum.ledgerScopeType.trust': 'Liste de confiance (TSL)',
  'enum.ledgerScopeType.unknown': 'Portée',
  'enum.ledgerScopeType.user': 'Utilisateur',
  'enum.ledgerScopeType.user_accounts': 'Comptes d’utilisateur',
};

/** it-IT — machine-authored, pending native review. */
export const ledgerScopeLabelsItIT: LedgerScopeLabels = {
  'enum.ledgerScopeType.act': 'Verbale',
  'enum.ledgerScopeType.api-key': 'Chiavi API',
  'enum.ledgerScopeType.archive': 'Archivio',
  'enum.ledgerScopeType.backup': 'Backup',
  'enum.ledgerScopeType.book': 'Libro',
  'enum.ledgerScopeType.book_archive': 'Archivio dei libri',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Delega',
  'enum.ledgerScopeType.email': 'E-mail',
  'enum.ledgerScopeType.entity': 'Entità',
  'enum.ledgerScopeType.global': 'Applicazione',
  'enum.ledgerScopeType.imported-document': 'Documento importato',
  'enum.ledgerScopeType.law': 'Normativa',
  'enum.ledgerScopeType.paper-book-import': 'Importazione di libro cartaceo',
  'enum.ledgerScopeType.platform': 'Piattaforma',
  'enum.ledgerScopeType.provider_credentials': 'Credenziali dei fornitori',
  'enum.ledgerScopeType.recovery': 'Ripristino della catena',
  'enum.ledgerScopeType.repository': 'Repository',
  'enum.ledgerScopeType.role': 'Ruolo',
  'enum.ledgerScopeType.settings': 'Impostazioni',
  'enum.ledgerScopeType.tenant': 'Organizzazione',
  'enum.ledgerScopeType.trust': 'Elenco di fiducia (TSL)',
  'enum.ledgerScopeType.unknown': 'Ambito',
  'enum.ledgerScopeType.user': 'Utente',
  'enum.ledgerScopeType.user_accounts': 'Account utente',
};

/** de-DE — machine-authored, pending native review. */
export const ledgerScopeLabelsDeDE: LedgerScopeLabels = {
  'enum.ledgerScopeType.act': 'Protokoll',
  'enum.ledgerScopeType.api-key': 'API-Schlüssel',
  'enum.ledgerScopeType.archive': 'Archiv',
  'enum.ledgerScopeType.backup': 'Sicherungen',
  'enum.ledgerScopeType.book': 'Buch',
  'enum.ledgerScopeType.book_archive': 'Bucharchiv',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Delegation',
  'enum.ledgerScopeType.email': 'E-Mail',
  'enum.ledgerScopeType.entity': 'Rechtsträger',
  'enum.ledgerScopeType.global': 'Anwendung',
  'enum.ledgerScopeType.imported-document': 'Importiertes Dokument',
  'enum.ledgerScopeType.law': 'Gesetzgebung',
  'enum.ledgerScopeType.paper-book-import': 'Papierbuch-Import',
  'enum.ledgerScopeType.platform': 'Plattform',
  'enum.ledgerScopeType.provider_credentials': 'Anbieter-Zugangsdaten',
  'enum.ledgerScopeType.recovery': 'Kettenwiederherstellung',
  'enum.ledgerScopeType.repository': 'Repository',
  'enum.ledgerScopeType.role': 'Rolle',
  'enum.ledgerScopeType.settings': 'Einstellungen',
  'enum.ledgerScopeType.tenant': 'Organisation',
  'enum.ledgerScopeType.trust': 'Vertrauensliste (TSL)',
  'enum.ledgerScopeType.unknown': 'Geltungsbereich',
  'enum.ledgerScopeType.user': 'Benutzer',
  'enum.ledgerScopeType.user_accounts': 'Benutzerkonten',
};

/** nl-NL — machine-authored, pending native review. */
export const ledgerScopeLabelsNlNL: LedgerScopeLabels = {
  'enum.ledgerScopeType.act': 'Notulen',
  'enum.ledgerScopeType.api-key': 'API-sleutels',
  'enum.ledgerScopeType.archive': 'Archief',
  'enum.ledgerScopeType.backup': 'Back-ups',
  'enum.ledgerScopeType.book': 'Boek',
  'enum.ledgerScopeType.book_archive': 'Boekarchief',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Delegatie',
  'enum.ledgerScopeType.email': 'E-mail',
  'enum.ledgerScopeType.entity': 'Entiteit',
  'enum.ledgerScopeType.global': 'Toepassing',
  'enum.ledgerScopeType.imported-document': 'Geïmporteerd document',
  'enum.ledgerScopeType.law': 'Wetgeving',
  'enum.ledgerScopeType.paper-book-import': 'Import van papieren boek',
  'enum.ledgerScopeType.platform': 'Platform',
  'enum.ledgerScopeType.provider_credentials': 'Providergegevens',
  'enum.ledgerScopeType.recovery': 'Ketenherstel',
  'enum.ledgerScopeType.repository': 'Opslagplaats',
  'enum.ledgerScopeType.role': 'Rol',
  'enum.ledgerScopeType.settings': 'Instellingen',
  'enum.ledgerScopeType.tenant': 'Organisatie',
  'enum.ledgerScopeType.trust': 'Vertrouwenslijst (TSL)',
  'enum.ledgerScopeType.unknown': 'Bereik',
  'enum.ledgerScopeType.user': 'Gebruiker',
  'enum.ledgerScopeType.user_accounts': 'Gebruikersaccounts',
};

/** da-DK — machine-authored, pending native review. */
export const ledgerScopeLabelsDaDK: LedgerScopeLabels = {
  'enum.ledgerScopeType.act': 'Protokol',
  'enum.ledgerScopeType.api-key': 'API-nøgler',
  'enum.ledgerScopeType.archive': 'Arkiv',
  'enum.ledgerScopeType.backup': 'Sikkerhedskopier',
  'enum.ledgerScopeType.book': 'Bog',
  'enum.ledgerScopeType.book_archive': 'Bogarkiv',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Delegering',
  'enum.ledgerScopeType.email': 'E-mail',
  'enum.ledgerScopeType.entity': 'Enhed',
  'enum.ledgerScopeType.global': 'Applikation',
  'enum.ledgerScopeType.imported-document': 'Importeret dokument',
  'enum.ledgerScopeType.law': 'Lovgivning',
  'enum.ledgerScopeType.paper-book-import': 'Import af papirbog',
  'enum.ledgerScopeType.platform': 'Platform',
  'enum.ledgerScopeType.provider_credentials': 'Udbyderlegitimationsoplysninger',
  'enum.ledgerScopeType.recovery': 'Kædegendannelse',
  'enum.ledgerScopeType.repository': 'Lager',
  'enum.ledgerScopeType.role': 'Rolle',
  'enum.ledgerScopeType.settings': 'Indstillinger',
  'enum.ledgerScopeType.tenant': 'Organisation',
  'enum.ledgerScopeType.trust': 'Tillidsliste (TSL)',
  'enum.ledgerScopeType.unknown': 'Omfang',
  'enum.ledgerScopeType.user': 'Bruger',
  'enum.ledgerScopeType.user_accounts': 'Brugerkonti',
};

/** sv-SE — machine-authored, pending native review. */
export const ledgerScopeLabelsSvSE: LedgerScopeLabels = {
  'enum.ledgerScopeType.act': 'Protokoll',
  'enum.ledgerScopeType.api-key': 'API-nycklar',
  'enum.ledgerScopeType.archive': 'Arkiv',
  'enum.ledgerScopeType.backup': 'Säkerhetskopior',
  'enum.ledgerScopeType.book': 'Bok',
  'enum.ledgerScopeType.book_archive': 'Bokarkiv',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Delegering',
  'enum.ledgerScopeType.email': 'E-post',
  'enum.ledgerScopeType.entity': 'Enhet',
  'enum.ledgerScopeType.global': 'Applikation',
  'enum.ledgerScopeType.imported-document': 'Importerat dokument',
  'enum.ledgerScopeType.law': 'Lagstiftning',
  'enum.ledgerScopeType.paper-book-import': 'Import av pappersbok',
  'enum.ledgerScopeType.platform': 'Plattform',
  'enum.ledgerScopeType.provider_credentials': 'Leverantörsuppgifter',
  'enum.ledgerScopeType.recovery': 'Kedjeåterställning',
  'enum.ledgerScopeType.repository': 'Lagringsplats',
  'enum.ledgerScopeType.role': 'Roll',
  'enum.ledgerScopeType.settings': 'Inställningar',
  'enum.ledgerScopeType.tenant': 'Organisation',
  'enum.ledgerScopeType.trust': 'Förtroendelista (TSL)',
  'enum.ledgerScopeType.unknown': 'Omfattning',
  'enum.ledgerScopeType.user': 'Användare',
  'enum.ledgerScopeType.user_accounts': 'Användarkonton',
};

/**
 * sv-FI — seeded from sv-SE. These are administrative nouns with no Finland-Swedish divergence
 * of the kind TRANSLATIONS.md records for the registry vocabulary, so nothing is overridden here
 * rather than a difference being invented; the slice stays pending Finland-Swedish review.
 */
export const ledgerScopeLabelsSvFI: LedgerScopeLabels = {
  ...ledgerScopeLabelsSvSE,
};

/** fi-FI — machine-authored, pending native review. */
export const ledgerScopeLabelsFiFI: LedgerScopeLabels = {
  'enum.ledgerScopeType.act': 'Pöytäkirja',
  'enum.ledgerScopeType.api-key': 'API-avaimet',
  'enum.ledgerScopeType.archive': 'Arkisto',
  'enum.ledgerScopeType.backup': 'Varmuuskopiot',
  'enum.ledgerScopeType.book': 'Kirja',
  'enum.ledgerScopeType.book_archive': 'Kirja-arkisto',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Valtuutus',
  'enum.ledgerScopeType.email': 'Sähköposti',
  'enum.ledgerScopeType.entity': 'Yhteisö',
  'enum.ledgerScopeType.global': 'Sovellus',
  'enum.ledgerScopeType.imported-document': 'Tuotu asiakirja',
  'enum.ledgerScopeType.law': 'Lainsäädäntö',
  'enum.ledgerScopeType.paper-book-import': 'Paperikirjan tuonti',
  'enum.ledgerScopeType.platform': 'Alusta',
  'enum.ledgerScopeType.provider_credentials': 'Palveluntarjoajan tunnukset',
  'enum.ledgerScopeType.recovery': 'Ketjun palautus',
  'enum.ledgerScopeType.repository': 'Tietovarasto',
  'enum.ledgerScopeType.role': 'Rooli',
  'enum.ledgerScopeType.settings': 'Asetukset',
  'enum.ledgerScopeType.tenant': 'Organisaatio',
  'enum.ledgerScopeType.trust': 'Luottamuslista (TSL)',
  'enum.ledgerScopeType.unknown': 'Laajuus',
  'enum.ledgerScopeType.user': 'Käyttäjä',
  'enum.ledgerScopeType.user_accounts': 'Käyttäjätilit',
};

/** pl-PL — machine-authored, pending native review. */
export const ledgerScopeLabelsPlPL: LedgerScopeLabels = {
  'enum.ledgerScopeType.act': 'Protokół',
  'enum.ledgerScopeType.api-key': 'Klucze API',
  'enum.ledgerScopeType.archive': 'Archiwum',
  'enum.ledgerScopeType.backup': 'Kopie zapasowe',
  'enum.ledgerScopeType.book': 'Księga',
  'enum.ledgerScopeType.book_archive': 'Archiwum ksiąg',
  'enum.ledgerScopeType.cae': 'CAE',
  'enum.ledgerScopeType.delegation': 'Delegacja',
  'enum.ledgerScopeType.email': 'E-mail',
  'enum.ledgerScopeType.entity': 'Podmiot',
  'enum.ledgerScopeType.global': 'Aplikacja',
  'enum.ledgerScopeType.imported-document': 'Zaimportowany dokument',
  'enum.ledgerScopeType.law': 'Prawodawstwo',
  'enum.ledgerScopeType.paper-book-import': 'Import księgi papierowej',
  'enum.ledgerScopeType.platform': 'Platforma',
  'enum.ledgerScopeType.provider_credentials': 'Poświadczenia dostawców',
  'enum.ledgerScopeType.recovery': 'Odtworzenie łańcucha',
  'enum.ledgerScopeType.repository': 'Repozytorium',
  'enum.ledgerScopeType.role': 'Rola',
  'enum.ledgerScopeType.settings': 'Ustawienia',
  'enum.ledgerScopeType.tenant': 'Organizacja',
  'enum.ledgerScopeType.trust': 'Lista zaufania (TSL)',
  'enum.ledgerScopeType.unknown': 'Zakres',
  'enum.ledgerScopeType.user': 'Użytkownik',
  'enum.ledgerScopeType.user_accounts': 'Konta użytkowników',
};

const SCOPE_TYPE_PREFIX = 'enum.ledgerScopeType.';

/**
 * The scope-type tokens that carry a label, derived from the catalog so the set and the copy
 * cannot drift. `unknown` is excluded: it is the fallback, not a wire token.
 */
export const LABELLED_LEDGER_SCOPE_TYPES: ReadonlySet<string> = new Set(
  Object.keys(ledgerScopeLabelsPtPT)
    .map((key) => key.slice(SCOPE_TYPE_PREFIX.length))
    .filter((token) => token !== 'unknown'),
);
