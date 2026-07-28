//! The 11 machine-translated email catalogs, pending native review (t70).
//!
//! These are the same 11 locales that carry the **machine · pending native review** tier in
//! `apps/web/src/i18n/TRANSLATIONS.md`, and they carry it here for the same reason: they were
//! translated in good faith from the `pt-PT` source but no native speaker has signed them off.
//! The renderer, the [`EmailCopy`] key-set and the authoritative `pt-PT` source catalog (plus the
//! two human-authored English ones) live in [`email_template`](crate::email_template); this file
//! holds only copy, so a translator works here and never touches rendering code.
//!
//! Every catalog is a complete `EmailCopy`, because a missing field is a compile error rather than
//! a blank line in somebody's mailbox. `Chancela` is the product name and is never translated, in
//! any locale, in any field.
//!
//! ## What a native reviewer should check first
//!
//! `welcome_credentials` and `welcome_never_sends`, in that order, before anything else. They are
//! anti-phishing copy: they exist so that a recipient can recognise a later message that *does*
//! carry a password or a sign-in link as a forgery. That only works if the statement is absolute.
//! A translation that softens "never" into something conditional — "normalmente não", "sollte
//! nicht", "en principe" — turns an unambiguous rule into a habit with exceptions, and a forged
//! message then reads as one of the exceptions. Check that the negation is total, that it is
//! attached to `Chancela` and not to some vaguer "the system", and that the instruction to report
//! the message survived.
//!
//! `test_not_notification` is the third to check, and firm for a related reason: it is what stops
//! a configuration test being forwarded as though it were a notice about a document or a deadline.

use crate::email_template::EmailCopy;

/// Machine translation, pending native review. Brazilian usage over the pt-PT source.
pub static PT_BR: EmailCopy = EmailCopy {
    footer_automated: "Mensagem automática enviada pela Chancela. Não responda a este endereço.",
    yes: "Sim",
    no: "Não",
    label_instance: "Instância",
    label_server: "Servidor SMTP",
    label_encryption: "Criptografia",
    label_auth: "Autenticação",
    label_sender: "Remetente",
    label_recipient: "Destinatário",
    label_sent_at: "Enviada em",
    test_subject: "Chancela — mensagem de teste da configuração de e-mail",
    test_badge: "Mensagem de teste",
    test_heading: "A configuração de e-mail está funcionando",
    test_lede: "Esta mensagem confirma que esta instância da Chancela conseguiu contatar este \
         destinatário por meio do servidor SMTP configurado.",
    test_proves: "Receber esta mensagem prova que o servidor SMTP aceitou a mensagem com esta configuração. \
         Não prova a entrega na caixa de entrada, que depende do destinatário e dos filtros pelo \
         caminho.",
    test_not_notification: "Isto é um teste de configuração solicitado por um administrador. Não é um aviso sobre \
         nenhum documento, processo ou prazo, e não deve ser encaminhado como se fosse.",
    welcome_subject: "Chancela — sua conta foi criada",
    welcome_heading: "Sua conta foi criada",
    welcome_greeting: "Olá, {name}.",
    welcome_lede: "Foi criada uma conta para você nesta instância da Chancela.",
    welcome_label_account: "Conta",
    welcome_label_created_by: "Criada por",
    welcome_label_sign_in: "Endereço de acesso",
    welcome_credentials: "Esta mensagem não contém senha. Um administrador fornecerá suas credenciais de acesso \
         separadamente.",
    welcome_never_sends: "A Chancela nunca envia senhas nem links de acesso por e-mail. Se você receber uma \
         mensagem que faça isso, comunique-a a um administrador.",
    pairing_subject: "Chancela — código de confirmação de pareamento",
    pairing_heading: "Código de confirmação de pareamento",
    pairing_lede: "Foi solicitado o pareamento de um dispositivo com a sua conta. Digite o código abaixo nesse dispositivo para confirmar.",
    pairing_label_code: "Código",
    pairing_label_device: "Dispositivo",
    pairing_label_expiry: "Validade",
    pairing_expiry: "{minutes} minutos a partir do envio desta mensagem.",
    pairing_not_requested: "Se não foi você que solicitou este pareamento, ignore esta mensagem e comunique-a a um administrador. Sem o código de pareamento exibido na sua própria tela, este código não dá acesso a nada.",
    pairing_never_asks: "A Chancela nunca pede que você encaminhe este código nem que o leia para outra pessoa. Nenhum funcionário, nem o suporte, precisa conhecê-lo.",
};

/// Machine translation, pending native review.
pub static ES_ES: EmailCopy = EmailCopy {
    footer_automated: "Mensaje automático enviado por Chancela. No responda a esta dirección.",
    yes: "Sí",
    no: "No",
    label_instance: "Instancia",
    label_server: "Servidor SMTP",
    label_encryption: "Cifrado",
    label_auth: "Autenticación",
    label_sender: "Remitente",
    label_recipient: "Destinatario",
    label_sent_at: "Enviado el",
    test_subject: "Chancela — mensaje de prueba de la configuración de correo",
    test_badge: "Mensaje de prueba",
    test_heading: "La configuración de correo funciona",
    test_lede: "Este mensaje confirma que esta instancia de Chancela ha podido contactar con este \
         destinatario a través del servidor SMTP configurado.",
    test_proves: "Recibir este mensaje demuestra que el servidor SMTP aceptó el mensaje con esta \
         configuración. No demuestra la entrega en la bandeja de entrada, que depende del \
         destinatario y de los filtros que haya por el camino.",
    test_not_notification: "Esta es una prueba de configuración solicitada por un administrador. No es un aviso \
         sobre ningún documento, procedimiento o plazo, y no debe reenviarse como si lo fuera.",
    welcome_subject: "Chancela — su cuenta ha sido creada",
    welcome_heading: "Su cuenta ha sido creada",
    welcome_greeting: "Hola, {name}.",
    welcome_lede: "Se ha creado una cuenta para usted en esta instancia de Chancela.",
    welcome_label_account: "Cuenta",
    welcome_label_created_by: "Creada por",
    welcome_label_sign_in: "Dirección de acceso",
    welcome_credentials: "Este mensaje no contiene ninguna contraseña. Un administrador le facilitará sus \
         credenciales de acceso por separado.",
    welcome_never_sends: "Chancela nunca envía contraseñas ni enlaces de acceso por correo electrónico. Si recibe \
         un mensaje que lo haga, comuníquelo a un administrador.",
    pairing_subject: "Chancela — código de confirmación de vinculación",
    pairing_heading: "Código de confirmación de vinculación",
    pairing_lede: "Se ha solicitado vincular un dispositivo con su cuenta. Escriba el código siguiente en ese dispositivo para confirmar.",
    pairing_label_code: "Código",
    pairing_label_device: "Dispositivo",
    pairing_label_expiry: "Validez",
    pairing_expiry: "{minutes} minutos desde el envío de este mensaje.",
    pairing_not_requested: "Si no ha solicitado esta vinculación, ignore este mensaje y comuníquelo a un administrador. Sin el código de vinculación mostrado en su propia pantalla, este código no da acceso a nada.",
    pairing_never_asks: "Chancela nunca le pedirá que reenvíe este código ni que se lo lea a otra persona. Ningún empleado ni el servicio de soporte necesita conocerlo.",
};

/// Machine translation, pending native review.
pub static FR_FR: EmailCopy = EmailCopy {
    footer_automated: "Message automatique envoyé par Chancela. Ne répondez pas à cette adresse.",
    yes: "Oui",
    no: "Non",
    label_instance: "Instance",
    label_server: "Serveur SMTP",
    label_encryption: "Chiffrement",
    label_auth: "Authentification",
    label_sender: "Expéditeur",
    label_recipient: "Destinataire",
    label_sent_at: "Envoyé le",
    test_subject: "Chancela — message de test de la configuration de messagerie",
    test_badge: "Message de test",
    test_heading: "La configuration de messagerie fonctionne",
    test_lede: "Ce message confirme que cette instance de Chancela a pu joindre ce destinataire via le \
         serveur SMTP configuré.",
    test_proves: "La réception de ce message prouve que le serveur SMTP a accepté le message avec cette \
         configuration. Elle ne prouve pas la remise en boîte de réception, qui dépend du \
         destinataire et des filtres rencontrés en chemin.",
    test_not_notification: "Il s'agit d'un test de configuration demandé par un administrateur. Ce n'est pas un avis \
         concernant un document, une procédure ou un délai, et il ne doit pas être transféré \
         comme s'il en était un.",
    welcome_subject: "Chancela — votre compte a été créé",
    welcome_heading: "Votre compte a été créé",
    welcome_greeting: "Bonjour {name},",
    welcome_lede: "Un compte a été créé pour vous sur cette instance de Chancela.",
    welcome_label_account: "Compte",
    welcome_label_created_by: "Créé par",
    welcome_label_sign_in: "Adresse de connexion",
    welcome_credentials: "Ce message ne contient aucun mot de passe. Un administrateur vous communiquera vos \
         identifiants de connexion séparément.",
    welcome_never_sends: "Chancela n'envoie jamais de mots de passe ni de liens de connexion par courrier \
         électronique. Si vous recevez un message qui en contient, signalez-le à un \
         administrateur.",
    pairing_subject: "Chancela — code de confirmation d’association",
    pairing_heading: "Code de confirmation d’association",
    pairing_lede: "L’association d’un appareil à votre compte a été demandée. Saisissez le code ci-dessous sur cet appareil pour confirmer.",
    pairing_label_code: "Code",
    pairing_label_device: "Appareil",
    pairing_label_expiry: "Validité",
    pairing_expiry: "{minutes} minutes à compter de l’envoi de ce message.",
    pairing_not_requested: "Si vous n’êtes pas à l’origine de cette demande, ignorez ce message et signalez-le à un administrateur. Sans le code d’association affiché sur votre propre écran, ce code ne donne accès à rien.",
    pairing_never_asks: "Chancela ne vous demandera jamais de transférer ce code ni de le communiquer à qui que ce soit. Aucun collaborateur, ni le support, n’a besoin de le connaître.",
};

/// Machine translation, pending native review.
pub static DE_DE: EmailCopy = EmailCopy {
    footer_automated: "Automatische Nachricht von Chancela. Bitte antworten Sie nicht an diese Adresse.",
    yes: "Ja",
    no: "Nein",
    label_instance: "Instanz",
    label_server: "SMTP-Server",
    label_encryption: "Verschlüsselung",
    label_auth: "Authentifizierung",
    label_sender: "Absender",
    label_recipient: "Empfänger",
    label_sent_at: "Gesendet am",
    test_subject: "Chancela — Testnachricht zur E-Mail-Konfiguration",
    test_badge: "Testnachricht",
    test_heading: "Die E-Mail-Konfiguration funktioniert",
    test_lede: "Diese Nachricht bestätigt, dass diese Chancela-Instanz diesen Empfänger über den \
         konfigurierten SMTP-Server erreichen konnte.",
    test_proves: "Der Empfang dieser Nachricht beweist, dass der SMTP-Server die Nachricht mit dieser \
         Konfiguration angenommen hat. Er beweist nicht die Zustellung im Posteingang, die vom \
         Empfänger und von den Filtern auf dem Weg abhängt.",
    test_not_notification: "Dies ist ein von einem Administrator angeforderter Konfigurationstest. Es ist kein \
         Hinweis zu einem Dokument, einem Verfahren oder einer Frist und darf nicht so \
         weitergeleitet werden, als wäre es einer.",
    welcome_subject: "Chancela — Ihr Konto wurde erstellt",
    welcome_heading: "Ihr Konto wurde erstellt",
    welcome_greeting: "Hallo {name},",
    welcome_lede: "Für Sie wurde ein Konto in dieser Chancela-Instanz erstellt.",
    welcome_label_account: "Konto",
    welcome_label_created_by: "Erstellt von",
    welcome_label_sign_in: "Anmeldeadresse",
    welcome_credentials: "Diese Nachricht enthält kein Passwort. Ein Administrator stellt Ihnen Ihre Anmeldedaten \
         gesondert zur Verfügung.",
    welcome_never_sends: "Chancela versendet niemals Passwörter oder Anmeldelinks per E-Mail. Wenn Sie eine \
         Nachricht erhalten, die das tut, melden Sie sie einem Administrator.",
    pairing_subject: "Chancela — Bestätigungscode für die Kopplung",
    pairing_heading: "Bestätigungscode für die Kopplung",
    pairing_lede: "Es wurde angefordert, ein Gerät mit Ihrem Konto zu koppeln. Geben Sie den folgenden Code auf diesem Gerät ein, um zu bestätigen.",
    pairing_label_code: "Code",
    pairing_label_device: "Gerät",
    pairing_label_expiry: "Gültigkeit",
    pairing_expiry: "{minutes} Minuten ab dem Versand dieser Nachricht.",
    pairing_not_requested: "Wenn Sie diese Kopplung nicht angefordert haben, ignorieren Sie diese Nachricht und melden Sie sie einer Administratorin oder einem Administrator. Ohne den Kopplungscode auf Ihrem eigenen Bildschirm gewährt dieser Code keinerlei Zugriff.",
    pairing_never_asks: "Chancela wird Sie niemals bitten, diesen Code weiterzuleiten oder jemandem vorzulesen. Weder Mitarbeitende noch der Support müssen ihn kennen.",
};

/// Machine translation, pending native review.
pub static IT_IT: EmailCopy = EmailCopy {
    footer_automated: "Messaggio automatico inviato da Chancela. Non risponda a questo indirizzo.",
    yes: "Sì",
    no: "No",
    label_instance: "Istanza",
    label_server: "Server SMTP",
    label_encryption: "Crittografia",
    label_auth: "Autenticazione",
    label_sender: "Mittente",
    label_recipient: "Destinatario",
    label_sent_at: "Inviato il",
    test_subject: "Chancela — messaggio di prova della configurazione email",
    test_badge: "Messaggio di prova",
    test_heading: "La configurazione email funziona",
    test_lede: "Questo messaggio conferma che questa istanza di Chancela è riuscita a raggiungere questo \
         destinatario tramite il server SMTP configurato.",
    test_proves: "Ricevere questo messaggio dimostra che il server SMTP ha accettato il messaggio con \
         questa configurazione. Non dimostra la consegna nella casella di posta, che dipende dal \
         destinatario e dai filtri lungo il percorso.",
    test_not_notification: "Questa è una prova di configurazione richiesta da un amministratore. Non è un avviso \
         relativo ad alcun documento, procedimento o scadenza e non deve essere inoltrato come se \
         lo fosse.",
    welcome_subject: "Chancela — il suo account è stato creato",
    welcome_heading: "Il suo account è stato creato",
    welcome_greeting: "Salve, {name}.",
    welcome_lede: "È stato creato un account per lei in questa istanza di Chancela.",
    welcome_label_account: "Account",
    welcome_label_created_by: "Creato da",
    welcome_label_sign_in: "Indirizzo di accesso",
    welcome_credentials: "Questo messaggio non contiene alcuna password. Un amministratore le fornirà le \
         credenziali di accesso separatamente.",
    welcome_never_sends: "Chancela non invia mai password né link di accesso per email. Se riceve un messaggio che \
         lo fa, lo segnali a un amministratore.",
    pairing_subject: "Chancela — codice di conferma dell’associazione",
    pairing_heading: "Codice di conferma dell’associazione",
    pairing_lede: "È stata richiesta l’associazione di un dispositivo al tuo account. Digita il codice qui sotto su quel dispositivo per confermare.",
    pairing_label_code: "Codice",
    pairing_label_device: "Dispositivo",
    pairing_label_expiry: "Validità",
    pairing_expiry: "{minutes} minuti dall’invio di questo messaggio.",
    pairing_not_requested: "Se non hai richiesto questa associazione, ignora questo messaggio e segnalalo a un amministratore. Senza il codice di associazione mostrato sul tuo schermo, questo codice non dà accesso a nulla.",
    pairing_never_asks: "Chancela non ti chiederà mai di inoltrare questo codice né di leggerlo a qualcuno. Nessun dipendente e nessun operatore dell’assistenza ha bisogno di conoscerlo.",
};

/// Machine translation, pending native review.
pub static NL_NL: EmailCopy = EmailCopy {
    footer_automated: "Automatisch bericht verzonden door Chancela. Beantwoord dit adres niet.",
    yes: "Ja",
    no: "Nee",
    label_instance: "Instantie",
    label_server: "SMTP-server",
    label_encryption: "Versleuteling",
    label_auth: "Authenticatie",
    label_sender: "Afzender",
    label_recipient: "Ontvanger",
    label_sent_at: "Verzonden op",
    test_subject: "Chancela — testbericht van de e-mailconfiguratie",
    test_badge: "Testbericht",
    test_heading: "De e-mailconfiguratie werkt",
    test_lede: "Dit bericht bevestigt dat deze Chancela-instantie deze ontvanger heeft kunnen bereiken \
         via de geconfigureerde SMTP-server.",
    test_proves: "De ontvangst van dit bericht bewijst dat de SMTP-server het bericht met deze \
         configuratie heeft geaccepteerd. Het bewijst geen aflevering in de inbox, die afhangt \
         van de ontvanger en van de filters onderweg.",
    test_not_notification: "Dit is een configuratietest die door een beheerder is aangevraagd. Het is geen \
         kennisgeving over enig document, enige procedure of enige termijn, en het mag niet \
         worden doorgestuurd alsof dat wel zo is.",
    welcome_subject: "Chancela — uw account is aangemaakt",
    welcome_heading: "Uw account is aangemaakt",
    welcome_greeting: "Hallo {name},",
    welcome_lede: "Er is een account voor u aangemaakt op deze Chancela-instantie.",
    welcome_label_account: "Account",
    welcome_label_created_by: "Aangemaakt door",
    welcome_label_sign_in: "Aanmeldadres",
    welcome_credentials: "Dit bericht bevat geen wachtwoord. Een beheerder verstrekt uw aanmeldgegevens apart.",
    welcome_never_sends: "Chancela verstuurt nooit wachtwoorden of aanmeldlinks per e-mail. Als u een bericht \
         ontvangt dat dat wel doet, meld het dan bij een beheerder.",
    pairing_subject: "Chancela — bevestigingscode voor koppeling",
    pairing_heading: "Bevestigingscode voor koppeling",
    pairing_lede: "Er is verzocht een apparaat aan uw account te koppelen. Typ de onderstaande code op dat apparaat om te bevestigen.",
    pairing_label_code: "Code",
    pairing_label_device: "Apparaat",
    pairing_label_expiry: "Geldigheid",
    pairing_expiry: "{minutes} minuten vanaf het verzenden van dit bericht.",
    pairing_not_requested: "Als u deze koppeling niet hebt aangevraagd, negeer dit bericht dan en meld het bij een beheerder. Zonder de koppelingscode op uw eigen scherm geeft deze code nergens toegang toe.",
    pairing_never_asks: "Chancela vraagt u nooit om deze code door te sturen of aan iemand voor te lezen. Geen enkele medewerker en ook de helpdesk hoeft de code te kennen.",
};

/// Machine translation, pending native review.
pub static DA_DK: EmailCopy = EmailCopy {
    footer_automated: "Automatisk besked sendt af Chancela. Svar ikke til denne adresse.",
    yes: "Ja",
    no: "Nej",
    label_instance: "Instans",
    label_server: "SMTP-server",
    label_encryption: "Kryptering",
    label_auth: "Godkendelse",
    label_sender: "Afsender",
    label_recipient: "Modtager",
    label_sent_at: "Sendt den",
    test_subject: "Chancela — testbesked for e-mailkonfigurationen",
    test_badge: "Testbesked",
    test_heading: "E-mailkonfigurationen virker",
    test_lede: "Denne besked bekræfter, at denne Chancela-instans kunne nå denne modtager via den \
         konfigurerede SMTP-server.",
    test_proves: "At modtage denne besked beviser, at SMTP-serveren accepterede beskeden med denne \
         konfiguration. Det beviser ikke levering i indbakken, som afhænger af modtageren og af \
         filtrene undervejs.",
    test_not_notification: "Dette er en konfigurationstest, som en administrator har anmodet om. Det er ikke en \
         meddelelse om noget dokument, nogen sag eller nogen frist, og den må ikke videresendes, \
         som om den var det.",
    welcome_subject: "Chancela — din konto er oprettet",
    welcome_heading: "Din konto er oprettet",
    welcome_greeting: "Hej {name}.",
    welcome_lede: "Der er oprettet en konto til dig på denne Chancela-instans.",
    welcome_label_account: "Konto",
    welcome_label_created_by: "Oprettet af",
    welcome_label_sign_in: "Loginadresse",
    welcome_credentials: "Denne besked indeholder ingen adgangskode. En administrator udleverer dine \
         loginoplysninger separat.",
    welcome_never_sends: "Chancela sender aldrig adgangskoder eller loginlinks med e-mail. Hvis du modtager en \
         besked, der gør det, skal du melde det til en administrator.",
    pairing_subject: "Chancela — bekræftelseskode til parring",
    pairing_heading: "Bekræftelseskode til parring",
    pairing_lede: "Der er anmodet om at parre en enhed med din konto. Indtast koden nedenfor på den enhed for at bekræfte.",
    pairing_label_code: "Kode",
    pairing_label_device: "Enhed",
    pairing_label_expiry: "Gyldighed",
    pairing_expiry: "{minutes} minutter fra afsendelsen af denne besked.",
    pairing_not_requested: "Hvis du ikke har anmodet om denne parring, så ignorér denne besked og meld den til en administrator. Uden parringskoden på din egen skærm giver denne kode ikke adgang til noget.",
    pairing_never_asks: "Chancela beder dig aldrig om at videresende denne kode eller læse den op for nogen. Hverken medarbejdere eller support har brug for at kende den.",
};

/// Machine translation, pending native review.
pub static FI_FI: EmailCopy = EmailCopy {
    footer_automated: "Chancela lähetti tämän automaattisen viestin. Älä vastaa tähän osoitteeseen.",
    yes: "Kyllä",
    no: "Ei",
    label_instance: "Instanssi",
    label_server: "SMTP-palvelin",
    label_encryption: "Salaus",
    label_auth: "Todennus",
    label_sender: "Lähettäjä",
    label_recipient: "Vastaanottaja",
    label_sent_at: "Lähetetty",
    test_subject: "Chancela — sähköpostiasetusten testiviesti",
    test_badge: "Testiviesti",
    test_heading: "Sähköpostiasetukset toimivat",
    test_lede: "Tämä viesti vahvistaa, että tämä Chancela-instanssi tavoitti tämän vastaanottajan \
         määritetyn SMTP-palvelimen kautta.",
    test_proves: "Tämän viestin vastaanottaminen todistaa, että SMTP-palvelin hyväksyi viestin näillä \
         asetuksilla. Se ei todista perilletuloa saapuneet-kansioon, joka riippuu \
         vastaanottajasta ja matkan varrella olevista suodattimista.",
    test_not_notification: "Tämä on ylläpitäjän pyytämä asetusten testi. Se ei ole ilmoitus mistään asiakirjasta, \
         menettelystä tai määräajasta, eikä sitä saa välittää eteenpäin ikään kuin se olisi \
         sellainen.",
    welcome_subject: "Chancela — tilisi on luotu",
    welcome_heading: "Tilisi on luotu",
    welcome_greeting: "Hei {name}.",
    welcome_lede: "Sinulle on luotu tili tähän Chancela-instanssiin.",
    welcome_label_account: "Tili",
    welcome_label_created_by: "Luonut",
    welcome_label_sign_in: "Kirjautumisosoite",
    welcome_credentials: "Tämä viesti ei sisällä salasanaa. Ylläpitäjä toimittaa kirjautumistietosi erikseen.",
    welcome_never_sends: "Chancela ei koskaan lähetä salasanoja eikä kirjautumislinkkejä sähköpostitse. Jos saat \
         viestin, joka sisältää niitä, ilmoita siitä ylläpitäjälle.",
    pairing_subject: "Chancela — parituksen vahvistuskoodi",
    pairing_heading: "Parituksen vahvistuskoodi",
    pairing_lede: "Laitteen parittamista tilisi kanssa on pyydetty. Kirjoita alla oleva koodi kyseiseen laitteeseen vahvistaaksesi.",
    pairing_label_code: "Koodi",
    pairing_label_device: "Laite",
    pairing_label_expiry: "Voimassaolo",
    pairing_expiry: "{minutes} minuuttia tämän viestin lähettämisestä.",
    pairing_not_requested: "Jos et pyytänyt tätä paritusta, jätä tämä viesti huomiotta ja ilmoita siitä järjestelmänvalvojalle. Ilman omalla näytölläsi näkyvää parituskoodia tämä koodi ei anna pääsyä mihinkään.",
    pairing_never_asks: "Chancela ei koskaan pyydä sinua välittämään tätä koodia tai lukemaan sitä kenellekään. Sitä ei tarvitse tietää kukaan työntekijä eikä tuki.",
};

/// Machine translation, pending native review.
pub static SV_SE: EmailCopy = EmailCopy {
    footer_automated: "Automatiskt meddelande skickat av Chancela. Svara inte till den här adressen.",
    yes: "Ja",
    no: "Nej",
    label_instance: "Instans",
    label_server: "SMTP-server",
    label_encryption: "Kryptering",
    label_auth: "Autentisering",
    label_sender: "Avsändare",
    label_recipient: "Mottagare",
    label_sent_at: "Skickat den",
    test_subject: "Chancela — testmeddelande för e-postkonfigurationen",
    test_badge: "Testmeddelande",
    test_heading: "E-postkonfigurationen fungerar",
    test_lede: "Det här meddelandet bekräftar att den här Chancela-instansen kunde nå den här mottagaren \
         via den konfigurerade SMTP-servern.",
    test_proves: "Att ta emot det här meddelandet bevisar att SMTP-servern accepterade meddelandet med den \
         här konfigurationen. Det bevisar inte leverans till inkorgen, som beror på mottagaren \
         och på filtren längs vägen.",
    test_not_notification: "Det här är ett konfigurationstest som begärts av en administratör. Det är inte ett \
         meddelande om något dokument, något ärende eller någon tidsfrist, och det får inte \
         vidarebefordras som om det vore det.",
    welcome_subject: "Chancela — ditt konto har skapats",
    welcome_heading: "Ditt konto har skapats",
    welcome_greeting: "Hej {name}.",
    welcome_lede: "Ett konto har skapats åt dig i den här Chancela-instansen.",
    welcome_label_account: "Konto",
    welcome_label_created_by: "Skapat av",
    welcome_label_sign_in: "Inloggningsadress",
    welcome_credentials: "Det här meddelandet innehåller inget lösenord. En administratör lämnar dina \
         inloggningsuppgifter separat.",
    welcome_never_sends: "Chancela skickar aldrig lösenord eller inloggningslänkar via e-post. Om du får ett \
         meddelande som gör det ska du anmäla det till en administratör.",
    pairing_subject: "Chancela — bekräftelsekod för parkoppling",
    pairing_heading: "Bekräftelsekod för parkoppling",
    pairing_lede: "Någon har begärt att parkoppla en enhet med ditt konto. Skriv in koden nedan på den enheten för att bekräfta.",
    pairing_label_code: "Kod",
    pairing_label_device: "Enhet",
    pairing_label_expiry: "Giltighet",
    pairing_expiry: "{minutes} minuter från att detta meddelande skickades.",
    pairing_not_requested: "Om du inte har begärt denna parkoppling, ignorera meddelandet och anmäl det till en administratör. Utan parkopplingskoden på din egen skärm ger den här koden inte åtkomst till någonting.",
    pairing_never_asks: "Chancela ber dig aldrig att vidarebefordra denna kod eller läsa upp den för någon. Varken medarbetare eller support behöver känna till den.",
};

/// Machine translation, pending native review. Seeded from [`SV_SE`] per the documented sv-FI rule:
/// genuine Finland-Swedish divergences are applied where they exist, and this copy contains none —
/// none of these strings touch the vocabulary (`registerutdrag`, `blanketter`, `andelslag`,
/// `föredragningslista`) where Finland-Swedish actually differs, so the columns are identical by
/// design rather than by omission. A Finland-Swedish reviewer should confirm that.
pub static SV_FI: EmailCopy = EmailCopy {
    footer_automated: "Automatiskt meddelande skickat av Chancela. Svara inte till den här adressen.",
    yes: "Ja",
    no: "Nej",
    label_instance: "Instans",
    label_server: "SMTP-server",
    label_encryption: "Kryptering",
    label_auth: "Autentisering",
    label_sender: "Avsändare",
    label_recipient: "Mottagare",
    label_sent_at: "Skickat den",
    test_subject: "Chancela — testmeddelande för e-postkonfigurationen",
    test_badge: "Testmeddelande",
    test_heading: "E-postkonfigurationen fungerar",
    test_lede: "Det här meddelandet bekräftar att den här Chancela-instansen kunde nå den här mottagaren \
         via den konfigurerade SMTP-servern.",
    test_proves: "Att ta emot det här meddelandet bevisar att SMTP-servern accepterade meddelandet med den \
         här konfigurationen. Det bevisar inte leverans till inkorgen, som beror på mottagaren \
         och på filtren längs vägen.",
    test_not_notification: "Det här är ett konfigurationstest som begärts av en administratör. Det är inte ett \
         meddelande om något dokument, något ärende eller någon tidsfrist, och det får inte \
         vidarebefordras som om det vore det.",
    welcome_subject: "Chancela — ditt konto har skapats",
    welcome_heading: "Ditt konto har skapats",
    welcome_greeting: "Hej {name}.",
    welcome_lede: "Ett konto har skapats åt dig i den här Chancela-instansen.",
    welcome_label_account: "Konto",
    welcome_label_created_by: "Skapat av",
    welcome_label_sign_in: "Inloggningsadress",
    welcome_credentials: "Det här meddelandet innehåller inget lösenord. En administratör lämnar dina \
         inloggningsuppgifter separat.",
    welcome_never_sends: "Chancela skickar aldrig lösenord eller inloggningslänkar via e-post. Om du får ett \
         meddelande som gör det ska du anmäla det till en administratör.",
    pairing_subject: "Chancela — bekräftelsekod för parkoppling",
    pairing_heading: "Bekräftelsekod för parkoppling",
    pairing_lede: "Det har begärts att en enhet ska parkopplas med ditt konto. Skriv in koden nedan på den enheten för att bekräfta.",
    pairing_label_code: "Kod",
    pairing_label_device: "Enhet",
    pairing_label_expiry: "Giltighet",
    pairing_expiry: "{minutes} minuter räknat från när detta meddelande skickades.",
    pairing_not_requested: "Om du inte har begärt den här parkopplingen, ignorera meddelandet och anmäl det till en administratör. Utan parkopplingskoden på din egen skärm ger den här koden inte åtkomst till någonting.",
    pairing_never_asks: "Chancela ber dig aldrig att vidarebefordra den här koden eller läsa upp den för någon. Varken medarbetare eller support behöver känna till den.",
};

/// Machine translation, pending native review.
pub static PL_PL: EmailCopy = EmailCopy {
    footer_automated: "Wiadomość automatyczna wysłana przez Chancela. Nie odpowiadaj na ten adres.",
    yes: "Tak",
    no: "Nie",
    label_instance: "Instancja",
    label_server: "Serwer SMTP",
    label_encryption: "Szyfrowanie",
    label_auth: "Uwierzytelnianie",
    label_sender: "Nadawca",
    label_recipient: "Odbiorca",
    label_sent_at: "Wysłano",
    test_subject: "Chancela — wiadomość testowa konfiguracji poczty",
    test_badge: "Wiadomość testowa",
    test_heading: "Konfiguracja poczty działa",
    test_lede: "Ta wiadomość potwierdza, że ta instancja Chancela zdołała skontaktować się z tym \
         odbiorcą za pośrednictwem skonfigurowanego serwera SMTP.",
    test_proves: "Otrzymanie tej wiadomości dowodzi, że serwer SMTP przyjął wiadomość z tą konfiguracją. \
         Nie dowodzi dostarczenia do skrzynki odbiorczej, które zależy od odbiorcy i od filtrów \
         po drodze.",
    test_not_notification: "To jest test konfiguracji zlecony przez administratora. Nie jest to powiadomienie o \
         żadnym dokumencie, postępowaniu ani terminie i nie należy go przekazywać dalej, jak \
         gdyby nim było.",
    welcome_subject: "Chancela — Twoje konto zostało utworzone",
    welcome_heading: "Twoje konto zostało utworzone",
    welcome_greeting: "Witaj, {name}.",
    welcome_lede: "W tej instancji Chancela utworzono dla Ciebie konto.",
    welcome_label_account: "Konto",
    welcome_label_created_by: "Utworzone przez",
    welcome_label_sign_in: "Adres logowania",
    welcome_credentials: "Ta wiadomość nie zawiera hasła. Administrator przekaże Ci dane logowania osobno.",
    welcome_never_sends: "Chancela nigdy nie wysyła haseł ani linków do logowania pocztą elektroniczną. Jeśli \
         otrzymasz wiadomość, która to robi, zgłoś ją administratorowi.",
    pairing_subject: "Chancela — kod potwierdzenia parowania",
    pairing_heading: "Kod potwierdzenia parowania",
    pairing_lede: "Zażądano sparowania urządzenia z Twoim kontem. Wpisz poniższy kod na tym urządzeniu, aby potwierdzić.",
    pairing_label_code: "Kod",
    pairing_label_device: "Urządzenie",
    pairing_label_expiry: "Ważność",
    pairing_expiry: "{minutes} minut od wysłania tej wiadomości.",
    pairing_not_requested: "Jeśli to nie Ty zażądałeś tego parowania, zignoruj tę wiadomość i zgłoś ją administratorowi. Bez kodu parowania wyświetlonego na Twoim własnym ekranie ten kod nie daje dostępu do niczego.",
    pairing_never_asks: "Chancela nigdy nie prosi o przekazanie tego kodu ani o odczytanie go komukolwiek. Ani pracownicy, ani wsparcie techniczne nie muszą go znać.",
};
