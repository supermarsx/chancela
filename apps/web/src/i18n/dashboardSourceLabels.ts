/**
 * Display labels for the provenance identifiers a dashboard actionable carries.
 *
 * Two adjacent namespaces, both rendered on the "Fonte" meta line of the work queue and the
 * notification centre, and both raw dotted/kebab machine ids on the wire:
 *
 * 1. `DashboardAlert.source` — *what the check looked at* to raise the alert, not what happened.
 *    `entities.books` means the alert was derived from the entity's set of books
 *    (`push_lifecycle_alerts`, `crates/chancela-api/src/dashboard.rs:702`), so it reads
 *    "Livros da entidade" — a scope, not an event. Nine values are data-scope literals; the
 *    other five are rule-pack ids (`RulePack::id`, `crates/chancela-core/src/rules.rs:172`)
 *    emitted when a compliance pack raises the alert.
 * 2. `DashboardReminder.source_rule` — the reminder generator that produced the row.
 *
 * KEYING. Rule-pack ids are versioned (`csc-art63/v2`); the key drops the `/vN` suffix so a
 * future `/v3` inherits the label instead of silently falling back, exactly as
 * `src/features/templates/templateNames.ts` does. The five *profile-calendar* reminder rules are
 * deliberately absent: their reminders carry an authored `profile_calendar_plan.preset_label`
 * on the payload, so `dashboardReminderRuleLabel` prefers that over any map entry.
 *
 * FALLBACK. Both accessors return the raw identifier when a value is unmapped — never blank,
 * never `undefined`. Server-side sources grow over time and an unlabelled new one must still
 * name itself.
 *
 * TRANSLATION STATUS. These are system labels, not names of legal instruments, so they are
 * localized — the same line drawn in `ledgerEventLabels.ts`. pt-PT is the source and en-US/en-GB
 * are human-authored; the remaining slices are machine-authored and pending native review, the
 * tier their catalogs already carry in TRANSLATIONS.md. The diploma names *inside* a label
 * (CSC, DL 268/94, Código Civil, Código Cooperativo) stay verbatim in every locale, because they
 * name Portuguese legal instruments; only the words around them translate.
 */
export const dashboardSourceLabelsPtPT = {
  'enum.dashboardAlertSource.acts.by_book': 'Atas do livro',
  'enum.dashboardAlertSource.acts.state': 'Estado das atas',
  'enum.dashboardAlertSource.assoc-cc': 'Regras de associação (Código Civil)',
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Atualidade das cópias de segurança',
  'enum.dashboardAlertSource.books.legal_hold': 'Retenção legal do livro',
  'enum.dashboardAlertSource.books.termo_abertura': 'Termo de abertura do livro',
  'enum.dashboardAlertSource.condominio-dl268': 'Regras de condomínio (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Regras de cooperativa (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'Regras do CSC (artigo 63.º)',
  'enum.dashboardAlertSource.entities.books': 'Livros da entidade',
  'enum.dashboardAlertSource.fundacao-cc': 'Regras de fundação (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': 'Verificação da cadeia de registo',
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Órgãos na certidão do registo',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    'Validade da certidão do registo',
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    'Evidência de expedição a condómino ausente',
  'enum.dashboardReminderRule.act-attendance-missing': 'Presenças em falta na ata',
  'enum.dashboardReminderRule.act-convening-notice': 'Convocatória da reunião',
  'enum.dashboardReminderRule.act-follow-up': 'Seguimento de deliberação',
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence':
    'Evidência de expedição da convocatória',
  'enum.dashboardReminderRule.imported-document-review-required': 'Documento importado por rever',
  'enum.dashboardReminderRule.privacy-breach-playbook-review':
    'Revisão do plano de resposta a violações de dados',
  'enum.dashboardReminderRule.privacy-dpia-review':
    'Revisão da avaliação de impacto sobre a proteção de dados',
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'Revisão do controlo de transferências internacionais',
};

export type DashboardSourceLabels = Record<keyof typeof dashboardSourceLabelsPtPT, string>;

/** en-US source slice; en-GB spreads this and overrides only where British usage diverges. */
export const dashboardSourceLabelsEnglish: DashboardSourceLabels = {
  'enum.dashboardAlertSource.acts.by_book': 'Minutes in the book',
  'enum.dashboardAlertSource.acts.state': 'Status of the minutes',
  'enum.dashboardAlertSource.assoc-cc': 'Association rules (Código Civil)',
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Backup freshness',
  'enum.dashboardAlertSource.books.legal_hold': 'Legal hold on the book',
  'enum.dashboardAlertSource.books.termo_abertura': 'Book opening term',
  'enum.dashboardAlertSource.condominio-dl268': 'Condominium rules (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Cooperative rules (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'CSC rules (article 63)',
  'enum.dashboardAlertSource.entities.books': 'Books of the entity',
  'enum.dashboardAlertSource.fundacao-cc': 'Foundation rules (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': 'Ledger chain verification',
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Bodies in the registry extract',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    'Validity of the registry extract',
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    'Dispatch evidence for an absent owner',
  'enum.dashboardReminderRule.act-attendance-missing': 'Attendance missing from the minutes',
  'enum.dashboardReminderRule.act-convening-notice': 'Convening notice for the meeting',
  'enum.dashboardReminderRule.act-follow-up': 'Follow-up on a resolution',
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence':
    'Dispatch evidence for the convening notice',
  'enum.dashboardReminderRule.imported-document-review-required':
    'Imported document awaiting review',
  'enum.dashboardReminderRule.privacy-breach-playbook-review': 'Data breach response plan review',
  'enum.dashboardReminderRule.privacy-dpia-review': 'Data protection impact assessment review',
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'International transfer control review',
};

/** en-GB — only the keys where British usage diverges from en-US. */
export const dashboardSourceLabelsEnGB: DashboardSourceLabels = {
  ...dashboardSourceLabelsEnglish,
  'enum.dashboardAlertSource.entities.books': 'Books of the organisation',
};

/** pt-BR — shared Portuguese; only the LGPD and Brazilian-usage terms diverge from pt-PT. */
export const dashboardSourceLabelsPtBR: DashboardSourceLabels = {
  'enum.dashboardAlertSource.acts.by_book': 'Atas do livro',
  'enum.dashboardAlertSource.acts.state': 'Estado das atas',
  'enum.dashboardAlertSource.assoc-cc': 'Regras de associação (Código Civil)',
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Atualidade dos backups',
  'enum.dashboardAlertSource.books.legal_hold': 'Retenção legal do livro',
  'enum.dashboardAlertSource.books.termo_abertura': 'Termo de abertura do livro',
  'enum.dashboardAlertSource.condominio-dl268': 'Regras de condomínio (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Regras de cooperativa (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'Regras do CSC (artigo 63.º)',
  'enum.dashboardAlertSource.entities.books': 'Livros da entidade',
  'enum.dashboardAlertSource.fundacao-cc': 'Regras de fundação (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': 'Verificação da cadeia de registro',
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Órgãos na certidão do registro',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    'Validade da certidão do registro',
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    'Evidência de envio a condômino ausente',
  'enum.dashboardReminderRule.act-attendance-missing': 'Presenças faltando na ata',
  'enum.dashboardReminderRule.act-convening-notice': 'Convocação da reunião',
  'enum.dashboardReminderRule.act-follow-up': 'Acompanhamento de deliberação',
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence':
    'Evidência de envio da convocação',
  'enum.dashboardReminderRule.imported-document-review-required':
    'Documento importado a ser revisado',
  'enum.dashboardReminderRule.privacy-breach-playbook-review':
    'Revisão do plano de resposta a incidentes de dados',
  'enum.dashboardReminderRule.privacy-dpia-review':
    'Revisão do relatório de impacto à proteção de dados',
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'Revisão do controle de transferências internacionais',
};

/** es-ES — machine-authored, pending native review. */
export const dashboardSourceLabelsEsES: DashboardSourceLabels = {
  'enum.dashboardAlertSource.acts.by_book': 'Actas del libro',
  'enum.dashboardAlertSource.acts.state': 'Estado de las actas',
  'enum.dashboardAlertSource.assoc-cc': 'Reglas de asociación (Código Civil)',
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Actualidad de las copias de seguridad',
  'enum.dashboardAlertSource.books.legal_hold': 'Retención legal del libro',
  'enum.dashboardAlertSource.books.termo_abertura': 'Diligencia de apertura del libro',
  'enum.dashboardAlertSource.condominio-dl268': 'Reglas de comunidad de propietarios (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Reglas de cooperativa (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'Reglas del CSC (artículo 63)',
  'enum.dashboardAlertSource.entities.books': 'Libros de la entidad',
  'enum.dashboardAlertSource.fundacao-cc': 'Reglas de fundación (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': 'Verificación de la cadena de registro',
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Órganos en la certificación registral',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    'Vigencia de la certificación registral',
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    'Prueba de envío a propietario ausente',
  'enum.dashboardReminderRule.act-attendance-missing': 'Asistencias que faltan en el acta',
  'enum.dashboardReminderRule.act-convening-notice': 'Convocatoria de la reunión',
  'enum.dashboardReminderRule.act-follow-up': 'Seguimiento de un acuerdo',
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence':
    'Prueba de envío de la convocatoria',
  'enum.dashboardReminderRule.imported-document-review-required':
    'Documento importado pendiente de revisión',
  'enum.dashboardReminderRule.privacy-breach-playbook-review':
    'Revisión del plan de respuesta a brechas de datos',
  'enum.dashboardReminderRule.privacy-dpia-review':
    'Revisión de la evaluación de impacto en protección de datos',
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'Revisión del control de transferencias internacionales',
};

/** fr-FR — machine-authored, pending native review. */
export const dashboardSourceLabelsFrFR: DashboardSourceLabels = {
  'enum.dashboardAlertSource.acts.by_book': 'Procès-verbaux du registre',
  'enum.dashboardAlertSource.acts.state': 'État des procès-verbaux',
  'enum.dashboardAlertSource.assoc-cc': "Règles d'association (Código Civil)",
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Fraîcheur des sauvegardes',
  'enum.dashboardAlertSource.books.legal_hold': 'Conservation légale du registre',
  'enum.dashboardAlertSource.books.termo_abertura': "Acte d'ouverture du registre",
  'enum.dashboardAlertSource.condominio-dl268': 'Règles de copropriété (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Règles de coopérative (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'Règles du CSC (article 63)',
  'enum.dashboardAlertSource.entities.books': "Registres de l'entité",
  'enum.dashboardAlertSource.fundacao-cc': 'Règles de fondation (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': "Vérification de la chaîne d'enregistrement",
  'enum.dashboardAlertSource.registry_extracts.orgaos': "Organes de l'extrait du registre",
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    "Validité de l'extrait du registre",
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    "Preuve d'envoi à un copropriétaire absent",
  'enum.dashboardReminderRule.act-attendance-missing': 'Présences manquantes dans le procès-verbal',
  'enum.dashboardReminderRule.act-convening-notice': "Convocation de l'assemblée",
  'enum.dashboardReminderRule.act-follow-up': "Suivi d'une résolution",
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence':
    "Preuve d'envoi de la convocation",
  'enum.dashboardReminderRule.imported-document-review-required':
    'Document importé en attente de revue',
  'enum.dashboardReminderRule.privacy-breach-playbook-review':
    'Revue du plan de réponse aux violations de données',
  'enum.dashboardReminderRule.privacy-dpia-review':
    "Revue de l'analyse d'impact relative à la protection des données",
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'Revue du contrôle des transferts internationaux',
};

/** it-IT — machine-authored, pending native review. */
export const dashboardSourceLabelsItIT: DashboardSourceLabels = {
  'enum.dashboardAlertSource.acts.by_book': 'Verbali del libro',
  'enum.dashboardAlertSource.acts.state': 'Stato dei verbali',
  'enum.dashboardAlertSource.assoc-cc': 'Regole di associazione (Código Civil)',
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Aggiornamento dei backup',
  'enum.dashboardAlertSource.books.legal_hold': 'Blocco legale del libro',
  'enum.dashboardAlertSource.books.termo_abertura': 'Atto di apertura del libro',
  'enum.dashboardAlertSource.condominio-dl268': 'Regole di condominio (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Regole di cooperativa (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'Regole del CSC (articolo 63)',
  'enum.dashboardAlertSource.entities.books': "Libri dell'entità",
  'enum.dashboardAlertSource.fundacao-cc': 'Regole di fondazione (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': 'Verifica della catena di registro',
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Organi nella visura camerale',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    'Validità della visura camerale',
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    'Prova di invio a un condomino assente',
  'enum.dashboardReminderRule.act-attendance-missing': 'Presenze mancanti nel verbale',
  'enum.dashboardReminderRule.act-convening-notice': 'Convocazione della riunione',
  'enum.dashboardReminderRule.act-follow-up': 'Seguito di una delibera',
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence':
    'Prova di invio della convocazione',
  'enum.dashboardReminderRule.imported-document-review-required':
    'Documento importato in attesa di revisione',
  'enum.dashboardReminderRule.privacy-breach-playbook-review':
    'Revisione del piano di risposta alle violazioni di dati',
  'enum.dashboardReminderRule.privacy-dpia-review':
    "Revisione della valutazione d'impatto sulla protezione dei dati",
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'Revisione del controllo sui trasferimenti internazionali',
};

/** de-DE — machine-authored, pending native review. */
export const dashboardSourceLabelsDeDE: DashboardSourceLabels = {
  'enum.dashboardAlertSource.acts.by_book': 'Protokolle des Buchs',
  'enum.dashboardAlertSource.acts.state': 'Status der Protokolle',
  'enum.dashboardAlertSource.assoc-cc': 'Vereinsregeln (Código Civil)',
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Aktualität der Sicherungen',
  'enum.dashboardAlertSource.books.legal_hold': 'Rechtliche Sperre des Buchs',
  'enum.dashboardAlertSource.books.termo_abertura': 'Eröffnungsvermerk des Buchs',
  'enum.dashboardAlertSource.condominio-dl268': 'Regeln für Wohnungseigentum (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Genossenschaftsregeln (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'CSC-Regeln (Artikel 63)',
  'enum.dashboardAlertSource.entities.books': 'Bücher der Organisation',
  'enum.dashboardAlertSource.fundacao-cc': 'Stiftungsregeln (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': 'Prüfung der Registerkette',
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Organe im Handelsregisterauszug',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    'Gültigkeit des Handelsregisterauszugs',
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    'Versandnachweis an abwesende Eigentümer',
  'enum.dashboardReminderRule.act-attendance-missing': 'Fehlende Anwesenheiten im Protokoll',
  'enum.dashboardReminderRule.act-convening-notice': 'Einladung zur Versammlung',
  'enum.dashboardReminderRule.act-follow-up': 'Nachverfolgung eines Beschlusses',
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence':
    'Versandnachweis der Einladung',
  'enum.dashboardReminderRule.imported-document-review-required':
    'Importiertes Dokument zur Prüfung offen',
  'enum.dashboardReminderRule.privacy-breach-playbook-review':
    'Überprüfung des Reaktionsplans für Datenschutzverletzungen',
  'enum.dashboardReminderRule.privacy-dpia-review': 'Überprüfung der Datenschutz-Folgenabschätzung',
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'Überprüfung der Kontrolle internationaler Übermittlungen',
};

/** nl-NL — machine-authored, pending native review. */
export const dashboardSourceLabelsNlNL: DashboardSourceLabels = {
  'enum.dashboardAlertSource.acts.by_book': 'Notulen van het boek',
  'enum.dashboardAlertSource.acts.state': 'Status van de notulen',
  'enum.dashboardAlertSource.assoc-cc': 'Verenigingsregels (Código Civil)',
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Actualiteit van de back-ups',
  'enum.dashboardAlertSource.books.legal_hold': 'Juridische blokkering van het boek',
  'enum.dashboardAlertSource.books.termo_abertura': 'Openingsakte van het boek',
  'enum.dashboardAlertSource.condominio-dl268': 'Regels voor appartementsrecht (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Coöperatieregels (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'CSC-regels (artikel 63)',
  'enum.dashboardAlertSource.entities.books': 'Boeken van de entiteit',
  'enum.dashboardAlertSource.fundacao-cc': 'Stichtingsregels (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': 'Verificatie van de registerketen',
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Organen in het uittreksel handelsregister',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    'Geldigheid van het uittreksel handelsregister',
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    'Verzendbewijs aan een afwezige eigenaar',
  'enum.dashboardReminderRule.act-attendance-missing': 'Ontbrekende aanwezigheid in de notulen',
  'enum.dashboardReminderRule.act-convening-notice': 'Oproeping voor de vergadering',
  'enum.dashboardReminderRule.act-follow-up': 'Opvolging van een besluit',
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence':
    'Verzendbewijs van de oproeping',
  'enum.dashboardReminderRule.imported-document-review-required':
    'Geïmporteerd document wacht op beoordeling',
  'enum.dashboardReminderRule.privacy-breach-playbook-review':
    'Beoordeling van het responsplan voor datalekken',
  'enum.dashboardReminderRule.privacy-dpia-review':
    'Beoordeling van de gegevensbeschermingseffectbeoordeling',
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'Beoordeling van de controle op internationale doorgiften',
};

/** da-DK — machine-authored, pending native review. */
export const dashboardSourceLabelsDaDK: DashboardSourceLabels = {
  'enum.dashboardAlertSource.acts.by_book': 'Protokoller i bogen',
  'enum.dashboardAlertSource.acts.state': 'Protokollernes status',
  'enum.dashboardAlertSource.assoc-cc': 'Foreningsregler (Código Civil)',
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Sikkerhedskopiernes aktualitet',
  'enum.dashboardAlertSource.books.legal_hold': 'Juridisk spærring af bogen',
  'enum.dashboardAlertSource.books.termo_abertura': 'Bogens åbningspåtegning',
  'enum.dashboardAlertSource.condominio-dl268': 'Regler for ejerforeninger (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Andelsselskabsregler (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'CSC-regler (artikel 63)',
  'enum.dashboardAlertSource.entities.books': 'Enhedens bøger',
  'enum.dashboardAlertSource.fundacao-cc': 'Fondsregler (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': 'Verifikation af registerkæden',
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Organer i registerattesten',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    'Registerattestens gyldighed',
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    'Afsendelsesbevis til en fraværende ejer',
  'enum.dashboardReminderRule.act-attendance-missing': 'Manglende fremmøde i protokollen',
  'enum.dashboardReminderRule.act-convening-notice': 'Indkaldelse til mødet',
  'enum.dashboardReminderRule.act-follow-up': 'Opfølgning på en beslutning',
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence':
    'Afsendelsesbevis for indkaldelsen',
  'enum.dashboardReminderRule.imported-document-review-required':
    'Importeret dokument afventer gennemgang',
  'enum.dashboardReminderRule.privacy-breach-playbook-review':
    'Gennemgang af beredskabsplanen for brud på datasikkerheden',
  'enum.dashboardReminderRule.privacy-dpia-review': 'Gennemgang af konsekvensanalysen',
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'Gennemgang af kontrollen med internationale overførsler',
};

/** sv-SE — machine-authored, pending native review. */
export const dashboardSourceLabelsSvSE: DashboardSourceLabels = {
  'enum.dashboardAlertSource.acts.by_book': 'Protokoll i boken',
  'enum.dashboardAlertSource.acts.state': 'Protokollens status',
  'enum.dashboardAlertSource.assoc-cc': 'Föreningsregler (Código Civil)',
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Säkerhetskopiornas aktualitet',
  'enum.dashboardAlertSource.books.legal_hold': 'Rättslig spärr av boken',
  'enum.dashboardAlertSource.books.termo_abertura': 'Bokens öppningspåteckning',
  'enum.dashboardAlertSource.condominio-dl268': 'Regler för bostadsrättsföreningar (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Kooperativa regler (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'CSC-regler (artikel 63)',
  'enum.dashboardAlertSource.entities.books': 'Organisationens böcker',
  'enum.dashboardAlertSource.fundacao-cc': 'Stiftelseregler (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': 'Verifiering av registerkedjan',
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Organ i registerbeviset',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    'Registerbevisets giltighet',
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    'Bevis på utskick till en frånvarande ägare',
  'enum.dashboardReminderRule.act-attendance-missing': 'Saknad närvaro i protokollet',
  'enum.dashboardReminderRule.act-convening-notice': 'Kallelse till mötet',
  'enum.dashboardReminderRule.act-follow-up': 'Uppföljning av ett beslut',
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence':
    'Bevis på utskick av kallelsen',
  'enum.dashboardReminderRule.imported-document-review-required':
    'Importerat dokument väntar på granskning',
  'enum.dashboardReminderRule.privacy-breach-playbook-review':
    'Granskning av åtgärdsplanen vid personuppgiftsincidenter',
  'enum.dashboardReminderRule.privacy-dpia-review': 'Granskning av konsekvensbedömningen',
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'Granskning av kontrollen av internationella överföringar',
};

/**
 * sv-FI — seeded from sv-SE with the documented Finland-Swedish divergences applied
 * (`registerutdrag` for the registry extract), not independently invented.
 */
export const dashboardSourceLabelsSvFI: DashboardSourceLabels = {
  ...dashboardSourceLabelsSvSE,
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Organ i registerutdraget',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    'Registerutdragets giltighet',
  'enum.dashboardAlertSource.condominio-dl268': 'Regler för bostadsaktiebolag (DL 268/94)',
};

/** fi-FI — machine-authored, pending native review. */
export const dashboardSourceLabelsFiFI: DashboardSourceLabels = {
  'enum.dashboardAlertSource.acts.by_book': 'Kirjan pöytäkirjat',
  'enum.dashboardAlertSource.acts.state': 'Pöytäkirjojen tila',
  'enum.dashboardAlertSource.assoc-cc': 'Yhdistyssäännöt (Código Civil)',
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Varmuuskopioiden tuoreus',
  'enum.dashboardAlertSource.books.legal_hold': 'Kirjan oikeudellinen säilytysvelvoite',
  'enum.dashboardAlertSource.books.termo_abertura': 'Kirjan avaamismerkintä',
  'enum.dashboardAlertSource.condominio-dl268': 'Asunto-osakeyhtiön säännöt (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Osuuskunnan säännöt (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'CSC-säännöt (artikla 63)',
  'enum.dashboardAlertSource.entities.books': 'Organisaation kirjat',
  'enum.dashboardAlertSource.fundacao-cc': 'Säätiön säännöt (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': 'Rekisteriketjun todentaminen',
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Toimielimet rekisteriotteessa',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until':
    'Rekisteriotteen voimassaolo',
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    'Lähetystodiste poissa olevalle omistajalle',
  'enum.dashboardReminderRule.act-attendance-missing': 'Pöytäkirjasta puuttuvat läsnäolot',
  'enum.dashboardReminderRule.act-convening-notice': 'Kokouskutsu',
  'enum.dashboardReminderRule.act-follow-up': 'Päätöksen seuranta',
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence': 'Kokouskutsun lähetystodiste',
  'enum.dashboardReminderRule.imported-document-review-required':
    'Tuotu asiakirja odottaa tarkistusta',
  'enum.dashboardReminderRule.privacy-breach-playbook-review':
    'Tietoturvaloukkausten toimintasuunnitelman tarkistus',
  'enum.dashboardReminderRule.privacy-dpia-review':
    'Tietosuojaa koskevan vaikutustenarvioinnin tarkistus',
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'Kansainvälisten siirtojen valvonnan tarkistus',
};

/** pl-PL — machine-authored, pending native review. */
export const dashboardSourceLabelsPlPL: DashboardSourceLabels = {
  'enum.dashboardAlertSource.acts.by_book': 'Protokoły w księdze',
  'enum.dashboardAlertSource.acts.state': 'Status protokołów',
  'enum.dashboardAlertSource.assoc-cc': 'Zasady dla stowarzyszeń (Código Civil)',
  'enum.dashboardAlertSource.backup_recovery.freshness': 'Aktualność kopii zapasowych',
  'enum.dashboardAlertSource.books.legal_hold': 'Blokada prawna księgi',
  'enum.dashboardAlertSource.books.termo_abertura': 'Akt otwarcia księgi',
  'enum.dashboardAlertSource.condominio-dl268': 'Zasady dla wspólnot mieszkaniowych (DL 268/94)',
  'enum.dashboardAlertSource.cooperativa-ccoop': 'Zasady dla spółdzielni (Código Cooperativo)',
  'enum.dashboardAlertSource.csc-art63': 'Zasady CSC (artykuł 63)',
  'enum.dashboardAlertSource.entities.books': 'Księgi podmiotu',
  'enum.dashboardAlertSource.fundacao-cc': 'Zasady dla fundacji (Código Civil)',
  'enum.dashboardAlertSource.ledger.verify': 'Weryfikacja łańcucha rejestru',
  'enum.dashboardAlertSource.registry_extracts.orgaos': 'Organy w odpisie z rejestru',
  'enum.dashboardAlertSource.registry_extracts.provenance.valid_until': 'Ważność odpisu z rejestru',
  'enum.dashboardReminderRule.absent-owner-dispatch-evidence':
    'Dowód wysyłki do nieobecnego właściciela',
  'enum.dashboardReminderRule.act-attendance-missing': 'Brakujące obecności w protokole',
  'enum.dashboardReminderRule.act-convening-notice': 'Zawiadomienie o zebraniu',
  'enum.dashboardReminderRule.act-follow-up': 'Realizacja uchwały',
  'enum.dashboardReminderRule.generated-convening-dispatch-evidence':
    'Dowód wysyłki zawiadomienia o zebraniu',
  'enum.dashboardReminderRule.imported-document-review-required':
    'Zaimportowany dokument oczekuje na przegląd',
  'enum.dashboardReminderRule.privacy-breach-playbook-review':
    'Przegląd planu reagowania na naruszenia ochrony danych',
  'enum.dashboardReminderRule.privacy-dpia-review': 'Przegląd oceny skutków dla ochrony danych',
  'enum.dashboardReminderRule.privacy-transfer-control-review':
    'Przegląd kontroli przekazywania danych do państw trzecich',
};

const ALERT_SOURCE_PREFIX = 'enum.dashboardAlertSource.';
const REMINDER_RULE_PREFIX = 'enum.dashboardReminderRule.';

function keysUnder(prefix: string): ReadonlySet<string> {
  return new Set(
    Object.keys(dashboardSourceLabelsPtPT)
      .filter((key) => key.startsWith(prefix))
      .map((key) => key.slice(prefix.length)),
  );
}

/**
 * Alert `source` values that carry a label, derived from the catalog so the set and the copy
 * cannot drift. Rule-pack entries are stored version-free — see {@link normalizeAlertSource}.
 */
export const LABELLED_DASHBOARD_ALERT_SOURCES: ReadonlySet<string> = keysUnder(ALERT_SOURCE_PREFIX);

/** Reminder `source_rule` values that carry a label. */
export const LABELLED_DASHBOARD_REMINDER_RULES: ReadonlySet<string> =
  keysUnder(REMINDER_RULE_PREFIX);

/**
 * Drop a trailing `/vN` so a rule pack keeps its name across versions. Anything else — including
 * the dotted data-scope sources, which never carry a version — is returned unchanged.
 */
export function normalizeAlertSource(source: string): string {
  return source.replace(/\/v\d+$/, '');
}
