/**
 * Seeded-role display names (t87).
 *
 * A role's `name` on the wire is **English** and code-adjacent — the workspace convention is English
 * identifiers with Portuguese reserved for user-facing copy (`crates/chancela-authz/src/role.rs`).
 * What a pt-PT operator reads is resolved here, from the role's **id**, through
 * `enum.roleName.<slug>`. The id is the stable, language-neutral key: it is deterministic per seeded
 * role, it is what assignments and ledger events store, and it never changes.
 *
 * ## Seeded versus custom — the distinction this file exists to keep
 *
 * **Operator-authored role names are data and are never translated.** Someone who names a role
 * "Gerente da filial" sees exactly that, in every locale. Two guards make that true:
 *
 * 1. Only ids in `SEEDED_ROLE_NAMES` are candidates — a custom role's id is a random UUID and is
 *    never in the map.
 * 2. A seeded id only translates while its stored name is still the canonical English one. If an
 *    operator renames the seeded Signatory role to "Assinante-chefe", the map stops applying and
 *    their words win. Without this, editing a seeded role's name would appear to do nothing.
 *
 * Everything else falls back to the stored name verbatim — never blank, never `undefined`.
 *
 * ## Retired ids stay readable forever
 *
 * `Gestor` and `Signatário` were Portuguese-named duplicates of `Company Owner` and `Signatory`
 * (byte-identical permission sets) and were merged away; their holders were migrated and the ids are
 * never reused. But the ids are **permanent**: they appear in past `role.assigned` / `role.updated`
 * ledger events, which are append-only and are never rewritten. So both stay in the map, marked
 * `retired`, and a historical event that names one still renders a name in all 14 locales instead of
 * a bare UUID. Deleting these entries would trade a duplicate role for unreadable history.
 *
 * The retired labels carry an explicit "retired role" marker in every locale, because a reader
 * looking at an old event needs to know the role is gone — not merely be shown a name that no longer
 * exists in the picker.
 *
 * TRANSLATION STATUS. pt-PT is the source and en-US/en-GB are human-authored; the remaining 11
 * slices are machine-authored and pending native review, the same tier their catalogs carry in
 * TRANSLATIONS.md. A role name is a short job title, not a legal claim, so translating it is the
 * right side of the UX-21 boundary — unlike the names of legal instruments, which stay Portuguese.
 */

/** pt-PT — the source slice. Its keys form the union every other slice must match exactly. */
export const roleNameLabelsPtPT = {
  'enum.roleName.apiClient': 'Cliente de API',
  'enum.roleName.auditor': 'Auditor',
  'enum.roleName.companyOwner': 'Proprietário da empresa',
  'enum.roleName.corporateSecretary': 'Secretário da sociedade',
  'enum.roleName.guest': 'Convidado',
  'enum.roleName.legalCounsel': 'Consultor jurídico',
  'enum.roleName.owner': 'Proprietário',
  'enum.roleName.platformAdministrator': 'Administrador da plataforma',
  'enum.roleName.reader': 'Leitor',
  'enum.roleName.recordsManager': 'Gestor de arquivo',
  'enum.roleName.retiredGestor': 'Gestor (função descontinuada)',
  'enum.roleName.retiredSignatario': 'Signatário (função descontinuada)',
  'enum.roleName.reviewer': 'Revisor',
  'enum.roleName.signatory': 'Signatário',
  'enum.roleName.tenantAdministrator': 'Administrador da organização',
};

/** One locale's complete slice: exactly the pt-PT key set, no additions, no omissions. */
export type RoleNameLabels = Record<keyof typeof roleNameLabelsPtPT, string>;

/**
 * en-US / en-GB — human-authored. These are the canonical stored names, so the translation is the
 * identity for eleven of them; the two retired entries gain their marker and the retired Gestor is
 * named by what it did ("Manager") rather than by the Portuguese word the wire used to carry.
 */
export const roleNameLabelsEnglish: RoleNameLabels = {
  'enum.roleName.apiClient': 'API Client',
  'enum.roleName.auditor': 'Auditor',
  'enum.roleName.companyOwner': 'Company Owner',
  'enum.roleName.corporateSecretary': 'Corporate Secretary',
  'enum.roleName.guest': 'Guest',
  'enum.roleName.legalCounsel': 'Legal Counsel',
  'enum.roleName.owner': 'Owner',
  'enum.roleName.platformAdministrator': 'Platform Administrator',
  'enum.roleName.reader': 'Reader',
  'enum.roleName.recordsManager': 'Records Manager',
  'enum.roleName.retiredGestor': 'Manager (retired role)',
  'enum.roleName.retiredSignatario': 'Signatory (retired role)',
  'enum.roleName.reviewer': 'Reviewer',
  'enum.roleName.signatory': 'Signatory',
  'enum.roleName.tenantAdministrator': 'Tenant Administrator',
};

/**
 * en-GB. No divergence: every one of these is a job title spelled identically in British and
 * American English, and "Tenant Administrator"/"Company Owner" are the spec ROL-02 names rather than
 * ordinary nouns, so the catalogue/organisation spelling rule does not reach them.
 */
export const roleNameLabelsEnGB: RoleNameLabels = { ...roleNameLabelsEnglish };

/** pt-BR — machine-authored, pending native review (see TRANSLATIONS.md). */
export const roleNameLabelsPtBR: RoleNameLabels = {
  'enum.roleName.apiClient': 'Cliente de API',
  'enum.roleName.auditor': 'Auditor',
  'enum.roleName.companyOwner': 'Proprietário da empresa',
  'enum.roleName.corporateSecretary': 'Secretário da companhia',
  'enum.roleName.guest': 'Convidado',
  'enum.roleName.legalCounsel': 'Consultor jurídico',
  'enum.roleName.owner': 'Proprietário',
  'enum.roleName.platformAdministrator': 'Administrador da plataforma',
  'enum.roleName.reader': 'Leitor',
  'enum.roleName.recordsManager': 'Gerente de arquivo',
  'enum.roleName.retiredGestor': 'Gestor (função descontinuada)',
  'enum.roleName.retiredSignatario': 'Signatário (função descontinuada)',
  'enum.roleName.reviewer': 'Revisor',
  'enum.roleName.signatory': 'Signatário',
  'enum.roleName.tenantAdministrator': 'Administrador da organização',
};

/** es-ES — machine-authored, pending native review (see TRANSLATIONS.md). */
export const roleNameLabelsEsES: RoleNameLabels = {
  'enum.roleName.apiClient': 'Cliente de API',
  'enum.roleName.auditor': 'Auditor',
  'enum.roleName.companyOwner': 'Propietario de la empresa',
  'enum.roleName.corporateSecretary': 'Secretario de la sociedad',
  'enum.roleName.guest': 'Invitado',
  'enum.roleName.legalCounsel': 'Asesor jurídico',
  'enum.roleName.owner': 'Propietario',
  'enum.roleName.platformAdministrator': 'Administrador de la plataforma',
  'enum.roleName.reader': 'Lector',
  'enum.roleName.recordsManager': 'Responsable de archivo',
  'enum.roleName.retiredGestor': 'Gestor (función retirada)',
  'enum.roleName.retiredSignatario': 'Firmante (función retirada)',
  'enum.roleName.reviewer': 'Revisor',
  'enum.roleName.signatory': 'Firmante',
  'enum.roleName.tenantAdministrator': 'Administrador de la organización',
};

/** fr-FR — machine-authored, pending native review (see TRANSLATIONS.md). */
export const roleNameLabelsFrFR: RoleNameLabels = {
  'enum.roleName.apiClient': 'Client API',
  'enum.roleName.auditor': 'Auditeur',
  'enum.roleName.companyOwner': "Propriétaire de l'entreprise",
  'enum.roleName.corporateSecretary': 'Secrétaire général',
  'enum.roleName.guest': 'Invité',
  'enum.roleName.legalCounsel': 'Conseiller juridique',
  'enum.roleName.owner': 'Propriétaire',
  'enum.roleName.platformAdministrator': 'Administrateur de la plateforme',
  'enum.roleName.reader': 'Lecteur',
  'enum.roleName.recordsManager': 'Responsable des archives',
  'enum.roleName.retiredGestor': 'Gestionnaire (rôle supprimé)',
  'enum.roleName.retiredSignatario': 'Signataire (rôle supprimé)',
  'enum.roleName.reviewer': 'Relecteur',
  'enum.roleName.signatory': 'Signataire',
  'enum.roleName.tenantAdministrator': "Administrateur de l'organisation",
};

/** it-IT — machine-authored, pending native review (see TRANSLATIONS.md). */
export const roleNameLabelsItIT: RoleNameLabels = {
  'enum.roleName.apiClient': 'Client API',
  'enum.roleName.auditor': 'Revisore contabile',
  'enum.roleName.companyOwner': "Titolare dell'impresa",
  'enum.roleName.corporateSecretary': 'Segretario societario',
  'enum.roleName.guest': 'Ospite',
  'enum.roleName.legalCounsel': 'Consulente legale',
  'enum.roleName.owner': 'Titolare',
  'enum.roleName.platformAdministrator': 'Amministratore della piattaforma',
  'enum.roleName.reader': 'Lettore',
  'enum.roleName.recordsManager': "Responsabile dell'archivio",
  'enum.roleName.retiredGestor': 'Gestore (ruolo dismesso)',
  'enum.roleName.retiredSignatario': 'Firmatario (ruolo dismesso)',
  'enum.roleName.reviewer': 'Verificatore',
  'enum.roleName.signatory': 'Firmatario',
  'enum.roleName.tenantAdministrator': "Amministratore dell'organizzazione",
};

/** de-DE — machine-authored, pending native review (see TRANSLATIONS.md). */
export const roleNameLabelsDeDE: RoleNameLabels = {
  'enum.roleName.apiClient': 'API-Client',
  'enum.roleName.auditor': 'Prüfer',
  'enum.roleName.companyOwner': 'Unternehmensinhaber',
  'enum.roleName.corporateSecretary': 'Gesellschaftssekretär',
  'enum.roleName.guest': 'Gast',
  'enum.roleName.legalCounsel': 'Rechtsberater',
  'enum.roleName.owner': 'Inhaber',
  'enum.roleName.platformAdministrator': 'Plattformadministrator',
  'enum.roleName.reader': 'Leser',
  'enum.roleName.recordsManager': 'Archivverwalter',
  'enum.roleName.retiredGestor': 'Verwalter (stillgelegte Rolle)',
  'enum.roleName.retiredSignatario': 'Unterzeichner (stillgelegte Rolle)',
  'enum.roleName.reviewer': 'Kontrolleur',
  'enum.roleName.signatory': 'Unterzeichner',
  'enum.roleName.tenantAdministrator': 'Organisationsadministrator',
};

/** nl-NL — machine-authored, pending native review (see TRANSLATIONS.md). */
export const roleNameLabelsNlNL: RoleNameLabels = {
  'enum.roleName.apiClient': 'API-client',
  'enum.roleName.auditor': 'Accountant',
  'enum.roleName.companyOwner': 'Eigenaar van de onderneming',
  'enum.roleName.corporateSecretary': 'Vennootschapssecretaris',
  'enum.roleName.guest': 'Gast',
  'enum.roleName.legalCounsel': 'Juridisch adviseur',
  'enum.roleName.owner': 'Eigenaar',
  'enum.roleName.platformAdministrator': 'Platformbeheerder',
  'enum.roleName.reader': 'Lezer',
  'enum.roleName.recordsManager': 'Archiefbeheerder',
  'enum.roleName.retiredGestor': 'Beheerder (vervallen rol)',
  'enum.roleName.retiredSignatario': 'Ondertekenaar (vervallen rol)',
  'enum.roleName.reviewer': 'Toetser',
  'enum.roleName.signatory': 'Ondertekenaar',
  'enum.roleName.tenantAdministrator': 'Organisatiebeheerder',
};

/** da-DK — machine-authored, pending native review (see TRANSLATIONS.md). */
export const roleNameLabelsDaDK: RoleNameLabels = {
  'enum.roleName.apiClient': 'API-klient',
  'enum.roleName.auditor': 'Revisor',
  'enum.roleName.companyOwner': 'Virksomhedsejer',
  'enum.roleName.corporateSecretary': 'Selskabssekretær',
  'enum.roleName.guest': 'Gæst',
  'enum.roleName.legalCounsel': 'Juridisk rådgiver',
  'enum.roleName.owner': 'Ejer',
  'enum.roleName.platformAdministrator': 'Platformadministrator',
  'enum.roleName.reader': 'Læser',
  'enum.roleName.recordsManager': 'Arkivansvarlig',
  'enum.roleName.retiredGestor': 'Forvalter (udgået rolle)',
  'enum.roleName.retiredSignatario': 'Underskriver (udgået rolle)',
  'enum.roleName.reviewer': 'Gennemgår',
  'enum.roleName.signatory': 'Underskriver',
  'enum.roleName.tenantAdministrator': 'Organisationsadministrator',
};

/** sv-SE — machine-authored, pending native review (see TRANSLATIONS.md). */
export const roleNameLabelsSvSE: RoleNameLabels = {
  'enum.roleName.apiClient': 'API-klient',
  'enum.roleName.auditor': 'Revisor',
  'enum.roleName.companyOwner': 'Företagsägare',
  'enum.roleName.corporateSecretary': 'Bolagssekreterare',
  'enum.roleName.guest': 'Gäst',
  'enum.roleName.legalCounsel': 'Juridisk rådgivare',
  'enum.roleName.owner': 'Ägare',
  'enum.roleName.platformAdministrator': 'Plattformsadministratör',
  'enum.roleName.reader': 'Läsare',
  'enum.roleName.recordsManager': 'Arkivansvarig',
  'enum.roleName.retiredGestor': 'Förvaltare (utgången roll)',
  'enum.roleName.retiredSignatario': 'Undertecknare (utgången roll)',
  'enum.roleName.reviewer': 'Granskare',
  'enum.roleName.signatory': 'Undertecknare',
  'enum.roleName.tenantAdministrator': 'Organisationsadministratör',
};

/**
 * sv-FI — machine-authored, pending native review. Follows the documented rule: seeded from sv-SE
 * with genuine Finland-Swedish divergence applied. `Verksamhetsledare` is the ordinary
 * Finland-Swedish title where sv-SE uses `Företagsägare`, and `arkivarie` is preferred over
 * `arkivansvarig`.
 */
export const roleNameLabelsSvFI: RoleNameLabels = {
  ...roleNameLabelsSvSE,
  'enum.roleName.companyOwner': 'Verksamhetsledare',
  'enum.roleName.recordsManager': 'Arkivarie',
};

/** fi-FI — machine-authored, pending native review (see TRANSLATIONS.md). */
export const roleNameLabelsFiFI: RoleNameLabels = {
  'enum.roleName.apiClient': 'API-asiakas',
  'enum.roleName.auditor': 'Tilintarkastaja',
  'enum.roleName.companyOwner': 'Yrityksen omistaja',
  'enum.roleName.corporateSecretary': 'Yhtiön sihteeri',
  'enum.roleName.guest': 'Vieras',
  'enum.roleName.legalCounsel': 'Lakimies',
  'enum.roleName.owner': 'Omistaja',
  'enum.roleName.platformAdministrator': 'Alustan ylläpitäjä',
  'enum.roleName.reader': 'Lukija',
  'enum.roleName.recordsManager': 'Arkistonhoitaja',
  'enum.roleName.retiredGestor': 'Hoitaja (poistettu rooli)',
  'enum.roleName.retiredSignatario': 'Allekirjoittaja (poistettu rooli)',
  'enum.roleName.reviewer': 'Tarkastaja',
  'enum.roleName.signatory': 'Allekirjoittaja',
  'enum.roleName.tenantAdministrator': 'Organisaation ylläpitäjä',
};

/** pl-PL — machine-authored, pending native review (see TRANSLATIONS.md). */
export const roleNameLabelsPlPL: RoleNameLabels = {
  'enum.roleName.apiClient': 'Klient API',
  'enum.roleName.auditor': 'Audytor',
  'enum.roleName.companyOwner': 'Właściciel firmy',
  'enum.roleName.corporateSecretary': 'Sekretarz spółki',
  'enum.roleName.guest': 'Gość',
  'enum.roleName.legalCounsel': 'Radca prawny',
  'enum.roleName.owner': 'Właściciel',
  'enum.roleName.platformAdministrator': 'Administrator platformy',
  'enum.roleName.reader': 'Czytelnik',
  'enum.roleName.recordsManager': 'Archiwista',
  'enum.roleName.retiredGestor': 'Zarządca (rola wycofana)',
  'enum.roleName.retiredSignatario': 'Sygnatariusz (rola wycofana)',
  'enum.roleName.reviewer': 'Recenzent',
  'enum.roleName.signatory': 'Sygnatariusz',
  'enum.roleName.tenantAdministrator': 'Administrator organizacji',
};

// --- The seeded-role registry: id → (slug, canonical English name) -------------------------------

/**
 * A seeded role as this client knows it: the catalog slug its name resolves through, the canonical
 * English `name` the server stores for it, and whether the id has been retired.
 */
export interface SeededRoleEntry {
  /** The `enum.roleName.<slug>` catalog key. */
  readonly slug: string;
  /**
   * The exact `name` the server seeds. The translation applies only while the stored name still
   * equals this — see the module docs.
   */
  readonly canonicalName: string;
  /**
   * A retired id: merged away and never re-seeded, but still named by past ledger events. It has no
   * canonical stored name because nothing seeds it any more, so the name check does not apply.
   */
  readonly retired?: true;
}

/**
 * Every seeded role id, keyed by the id the server issues. Mirrors the `*_ROLE_ID` constants in
 * `crates/chancela-authz/src/role.rs`; `src/api/labels.test.ts` parses that file and fails if the
 * two ever drift, so a role added or retired server-side cannot silently lose its name here.
 */
export const SEEDED_ROLE_NAMES: Readonly<Record<string, SeededRoleEntry>> = {
  '6f776e65-7200-0000-0000-000000000001': { slug: 'owner', canonicalName: 'Owner' },
  '6c656974-6f72-0000-0000-000000000004': { slug: 'reader', canonicalName: 'Reader' },
  '706c6174-6164-6d00-0000-000000000005': {
    slug: 'platformAdministrator',
    canonicalName: 'Platform Administrator',
  },
  '74656e61-646d-0000-0000-000000000006': {
    slug: 'tenantAdministrator',
    canonicalName: 'Tenant Administrator',
  },
  '61756469-746f-7200-0000-000000000007': { slug: 'auditor', canonicalName: 'Auditor' },
  '67756573-7400-0000-0000-000000000008': { slug: 'guest', canonicalName: 'Guest' },
  '61706963-6c6e-7400-0000-000000000009': { slug: 'apiClient', canonicalName: 'API Client' },
  '636f6f77-6e72-0000-0000-00000000000a': {
    slug: 'companyOwner',
    canonicalName: 'Company Owner',
  },
  '636f7270-7365-6300-0000-00000000000b': {
    slug: 'corporateSecretary',
    canonicalName: 'Corporate Secretary',
  },
  '6c65676c-636e-7300-0000-00000000000c': {
    slug: 'legalCounsel',
    canonicalName: 'Legal Counsel',
  },
  '7265636d-6772-0000-0000-00000000000d': {
    slug: 'recordsManager',
    canonicalName: 'Records Manager',
  },
  '7369676e-7472-7900-0000-00000000000e': { slug: 'signatory', canonicalName: 'Signatory' },
  '72657669-6577-7200-0000-00000000000f': { slug: 'reviewer', canonicalName: 'Reviewer' },

  // Retired (t87) — never re-seeded, never reused, still named by past ledger events.
  '67657374-6f72-0000-0000-000000000002': {
    slug: 'retiredGestor',
    canonicalName: 'Gestor',
    retired: true,
  },
  '7369676e-6174-0000-0000-000000000003': {
    slug: 'retiredSignatario',
    canonicalName: 'Signatário',
    retired: true,
  },
};
