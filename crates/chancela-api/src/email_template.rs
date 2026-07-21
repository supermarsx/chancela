//! The shared themed email shell, and the two messages built on it (t70).
//!
//! ## Why this exists
//!
//! Before this module the only outbound message was the SMTP test-send's bare text block, written
//! inline in `smtp_settings.rs`. It read like a debug ping because it was one. As soon as a second
//! message existed — the welcome mail a newly created account receives — the shell needed to be
//! shared rather than copied, so a change to the footer or the palette happens once.
//!
//! ## Email HTML is not web HTML
//!
//! Nothing here is the markup you would write for a browser, and the differences are deliberate:
//!
//! - **Tables for layout, not flexbox or grid.** Outlook renders through Word's HTML engine, which
//!   has no meaningful support for either. Nested tables with fixed widths are the only layout
//!   primitive that behaves across Outlook, Gmail, Apple Mail and the webmail clients.
//! - **Inline styles only.** Gmail strips `<style>` blocks in several contexts and every client
//!   strips external stylesheets, so every declaration is on the element that needs it.
//! - **No web fonts, no JavaScript, no `class` hooks.** Web fonts are blocked or ignored; script is
//!   stripped by every client worth naming and would be a red flag to a gateway if it were not.
//! - **No remote images at all.** This is a privacy decision, not a rendering one: an `<img>`
//!   pointing at a server is a read receipt, disclosing to the sender when a message was opened and
//!   from roughly where. Most clients block them by default anyway, so the cost of relying on one is
//!   a broken layout for the majority. **The choice made here is to omit imagery entirely** — no
//!   logo file, and no inlined CID or `data:` part either. The masthead is the product name set in
//!   type, which needs no bytes and degrades perfectly. (A CID part was the alternative; it avoids
//!   the read receipt but adds an image/related MIME layer for decoration alone, and pushes every
//!   message past the size where Gmail clips it.)
//!
//! The design follows the product's aesthetic — a squareish ledger — so it is typographic and ruled
//! rather than rounded and colourful: hairline gold rules, a serif face, square corners, and the
//! same paper/green-ink palette as `apps/web/src/theme.css`. Restraint is also what survives a
//! client that strips styling.
//!
//! ## The plain-text part is mandatory
//!
//! [`RenderedEmail`] carries both bodies and [`SmtpMessage`](crate::smtp::SmtpMessage) sends them as
//! `multipart/alternative`. This is not a nicety:
//!
//! - Many corporate security gateways refuse or quarantine HTML-only mail outright.
//! - The text part is the accessible version, and the one a screen reader or a terminal client gets.
//! - It is the version that survives being forwarded, quoted, or pasted into a ticket.
//!
//! So the text body is written first and the HTML is built to say the same things in the same order.
//! `html_degrades_to_the_text_part` in the tests below pins that: every fact in the HTML is asserted
//! present in the text.
//!
//! ## Where the copy lives
//!
//! **Here, in Rust — not in the web catalogs.** These messages are rendered by the API when it sends
//! mail; the browser is not involved and often not running (the welcome mail is sent from a user
//! creation that may come from an API client). Putting the strings in `apps/web/src/i18n` would
//! oblige the server to read the front-end's catalogs, which it has no other reason to do.
//!
//! The structure mirrors the web-side convention rather than inventing one: [`EmailCopy`] is the
//! typed key-set the way `MessageKey` is, `pt-PT` is the source locale, and every other locale is a
//! complete `EmailCopy` — the same "all the columns together so a reviewer can diff a language
//! against pt-PT without opening 14 catalogs" argument that
//! `apps/web/src/i18n/ledgerEventLabels.ts` makes. Completeness is a compile error rather than a
//! runtime check, because a missing field will not build.
//!
//! The split across two files is by review tier, not by language: the source (`pt-PT`) and the two
//! human-authored English catalogs sit here beside the renderer they were written against, and the
//! 11 machine-translated catalogs pending native review are in
//! [`email_locales`](crate::email_locales) — so a translator works in one file and never has to
//! touch the rendering code.
//!
//! Quality tiers match `apps/web/src/i18n/TRANSLATIONS.md`: `pt-PT` source, `en-US`/`en-GB` human,
//! the other 11 machine and pending native review.

use std::fmt::Write as _;

use crate::email_locales::{
    DA_DK, DE_DE, ES_ES, FI_FI, FR_FR, IT_IT, NL_NL, PL_PL, PT_BR, SV_FI, SV_SE,
};

/// The product name. Not translated — it is a proper noun, and it is the masthead.
pub const PRODUCT_NAME: &str = "Chancela";

// --- Palette -------------------------------------------------------------------------------------
//
// Lifted from `apps/web/src/theme.css` so the mail looks like the product. Light-theme values only:
// there is no `prefers-color-scheme` worth relying on in mail, and a light card renders acceptably
// in a dark client whereas the reverse frequently does not.

/// Page background — the product's paper.
const PAPER: &str = "#f7f3ea";
/// The card surface.
const SURFACE: &str = "#fffdf8";
/// Body text — the product's green ink.
const INK: &str = "#10241b";
/// Secondary text.
const MUTED: &str = "#5c5344";
/// The hairline rule.
const BORDER: &str = "#dcd0b2";
/// Old gold, for the masthead rule.
const GOLD: &str = "#b8963e";
/// Deep antique gold — the light-theme accent, contrast-checked in the web theme.
const GOLD_DEEP: &str = "#6b4d12";

/// The body font stack. No web fonts: these are the faces a mail client already has.
const FONT_BODY: &str = "Georgia, 'Times New Roman', Times, serif";
/// The monospace stack, for hostnames and addresses.
const FONT_MONO: &str = "Consolas, 'Courier New', Courier, monospace";

/// The card width. 600px is the long-standing safe maximum: it is the width Outlook's reading pane
/// and most webmail columns show without horizontal scrolling.
const CARD_WIDTH: &str = "600";

// --- Output --------------------------------------------------------------------------------------

/// A rendered message: a subject, and **both** bodies.
///
/// There is deliberately no constructor that produces HTML without text. The plain-text part is
/// mandatory (see the module docs), so the type makes an HTML-only message unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedEmail {
    /// The `Subject:` header, unencoded — `SmtpMessage` applies RFC 2047 when it is not pure ASCII,
    /// which for most of these locales it is not.
    pub subject: String,
    /// The `text/plain` part. The accessible version, and the one a gateway will not strip.
    pub text_body: String,
    /// The `text/html` part.
    pub html_body: String,
}

// --- The shell -----------------------------------------------------------------------------------

/// One label/value row in a message's detail block.
struct Row<'a> {
    label: &'a str,
    value: &'a str,
    /// Render the value monospaced — for hostnames, ports and addresses, where the difference
    /// between `l` and `1` matters.
    mono: bool,
}

/// Everything the shell needs to render one message.
struct Shell<'a> {
    /// The `<title>`/masthead subtitle line, e.g. the instance name.
    instance_name: &'a str,
    /// A short all-caps flag above the heading, e.g. "TEST MESSAGE". `None` for ordinary mail.
    badge: Option<&'a str>,
    heading: &'a str,
    /// Paragraphs of body copy, before the detail rows.
    lede: Vec<&'a str>,
    rows: Vec<Row<'a>>,
    /// Paragraphs after the detail rows — the "what this means" copy.
    notes: Vec<&'a str>,
    footer: &'a str,
}

/// Escape text for HTML. Everything interpolated into the markup goes through this.
///
/// Applied to *all* interpolated values without exception, including ones that look safe. The
/// welcome mail carries a display name and an instance name that an administrator typed, and the
/// test mail carries a hostname from the settings document; none of those are trustworthy markup.
fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

impl Shell<'_> {
    /// Render the HTML part: table layout, inline styles, square corners, no images.
    fn html(&self) -> String {
        let mut out = String::new();

        // The outer table is the page: full width, paper background, everything centred inside it.
        let _ = write!(
            out,
            "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>{title}</title></head>\
             <body style=\"margin:0;padding:0;background-color:{PAPER};\">\
             <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" \
             border=\"0\" style=\"background-color:{PAPER};padding:24px 12px;\"><tr>\
             <td align=\"center\">",
            title = esc(self.heading),
        );

        // The card. Square, hairline-ruled, gold rule across the top — the ledger look.
        let _ = write!(
            out,
            "<table role=\"presentation\" width=\"{CARD_WIDTH}\" cellpadding=\"0\" \
             cellspacing=\"0\" border=\"0\" style=\"width:100%;max-width:{CARD_WIDTH}px;\
             background-color:{SURFACE};border:1px solid {BORDER};border-top:3px solid {GOLD};\">"
        );

        // Masthead: the product name in letterspaced small type, the instance beneath it.
        let _ = write!(
            out,
            "<tr><td style=\"padding:20px 28px 14px 28px;border-bottom:1px solid {BORDER};\">\
             <div style=\"font-family:{FONT_BODY};font-size:15px;letter-spacing:0.18em;\
             text-transform:uppercase;color:{GOLD_DEEP};font-weight:bold;\">{product}</div>\
             <div style=\"font-family:{FONT_BODY};font-size:13px;color:{MUTED};padding-top:4px;\">\
             {instance}</div></td></tr>",
            product = esc(PRODUCT_NAME),
            instance = esc(self.instance_name),
        );

        // Body.
        let _ = write!(out, "<tr><td style=\"padding:24px 28px 8px 28px;\">");

        if let Some(badge) = self.badge {
            // A ruled box rather than a coloured pill: it still reads as a flag when styles are
            // stripped, because the text itself says what it is.
            let _ = write!(
                out,
                "<div style=\"display:inline-block;font-family:{FONT_BODY};font-size:11px;\
                 letter-spacing:0.14em;text-transform:uppercase;color:{GOLD_DEEP};\
                 border:1px solid {GOLD};padding:4px 9px;margin-bottom:16px;\">{badge}</div>",
                badge = esc(badge),
            );
        }

        let _ = write!(
            out,
            "<h1 style=\"margin:0 0 14px 0;font-family:{FONT_BODY};font-size:22px;\
             line-height:1.3;font-weight:normal;color:{INK};\">{heading}</h1>",
            heading = esc(self.heading),
        );

        for paragraph in &self.lede {
            let _ = write!(
                out,
                "<p style=\"margin:0 0 12px 0;font-family:{FONT_BODY};font-size:15px;\
                 line-height:1.6;color:{INK};\">{p}</p>",
                p = esc(paragraph),
            );
        }
        let _ = write!(out, "</td></tr>");

        // The detail block: a ruled two-column table, which is the ledger idiom and also the thing
        // that degrades best — a stripped-styles client still shows "label / value" pairs in order.
        if !self.rows.is_empty() {
            let _ = write!(
                out,
                "<tr><td style=\"padding:8px 28px 8px 28px;\">\
                 <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" \
                 border=\"0\" style=\"border-top:1px solid {BORDER};\">"
            );
            for row in &self.rows {
                let value_font = if row.mono { FONT_MONO } else { FONT_BODY };
                let _ = write!(
                    out,
                    "<tr>\
                     <td style=\"padding:9px 12px 9px 0;border-bottom:1px solid {BORDER};\
                     font-family:{FONT_BODY};font-size:13px;color:{MUTED};\
                     vertical-align:top;white-space:nowrap;\">{label}</td>\
                     <td style=\"padding:9px 0 9px 0;border-bottom:1px solid {BORDER};\
                     font-family:{value_font};font-size:13px;color:{INK};\
                     vertical-align:top;text-align:right;word-break:break-word;\">{value}</td>\
                     </tr>",
                    label = esc(row.label),
                    value = esc(row.value),
                );
            }
            let _ = write!(out, "</table></td></tr>");
        }

        if !self.notes.is_empty() {
            let _ = write!(out, "<tr><td style=\"padding:16px 28px 4px 28px;\">");
            for note in &self.notes {
                let _ = write!(
                    out,
                    "<p style=\"margin:0 0 12px 0;font-family:{FONT_BODY};font-size:14px;\
                     line-height:1.6;color:{MUTED};\">{n}</p>",
                    n = esc(note),
                );
            }
            let _ = write!(out, "</td></tr>");
        }

        // Footer.
        let _ = write!(
            out,
            "<tr><td style=\"padding:14px 28px 20px 28px;border-top:1px solid {BORDER};\">\
             <p style=\"margin:0;font-family:{FONT_BODY};font-size:12px;line-height:1.5;\
             color:{MUTED};\">{footer}</p></td></tr>",
            footer = esc(self.footer),
        );

        out.push_str("</table></td></tr></table></body></html>");
        out
    }

    /// Render the plain-text part. Written to carry every fact the HTML carries, in the same order.
    fn text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "{PRODUCT_NAME} — {}", self.instance_name);
        // A rule of dashes: the text equivalent of the gold hairline, and a real visual break in a
        // terminal client.
        out.push_str("========================================\n\n");
        if let Some(badge) = self.badge {
            let _ = writeln!(out, "[{badge}]\n");
        }
        let _ = writeln!(out, "{}\n", self.heading);
        for paragraph in &self.lede {
            let _ = writeln!(out, "{paragraph}\n");
        }
        if !self.rows.is_empty() {
            for row in &self.rows {
                let _ = writeln!(out, "{}: {}", row.label, row.value);
            }
            out.push('\n');
        }
        for note in &self.notes {
            let _ = writeln!(out, "{note}\n");
        }
        out.push_str("----------------------------------------\n");
        let _ = writeln!(out, "{}", self.footer);
        out
    }

    fn render(&self, subject: String) -> RenderedEmail {
        RenderedEmail {
            subject,
            text_body: self.text(),
            html_body: self.html(),
        }
    }
}

// --- The test email ------------------------------------------------------------------------------

/// Everything the SMTP test message states. All of it is configuration the operator can see anyway;
/// none of it is secret.
#[derive(Debug, Clone)]
pub struct TestEmail<'a> {
    /// The instance this was sent from, as the operator named it.
    pub instance_name: &'a str,
    /// The relay host the message went through.
    pub host: &'a str,
    /// The relay port.
    pub port: u16,
    /// The transport-security mode, already in its wire form (`starttls`, `implicit_tls`, `none`).
    pub encryption: &'a str,
    /// Whether the session authenticated.
    pub authenticated: bool,
    /// The envelope sender.
    pub from_address: &'a str,
    /// The recipient this was addressed to.
    pub to_address: &'a str,
    /// When it was sent, already formatted for display.
    pub sent_at: &'a str,
    /// Which locale to render in.
    pub locale: &'a str,
}

/// Render the SMTP test message.
///
/// It states plainly what it proves — that *this* instance's SMTP settings reached *this* recipient,
/// from *this* host, at *this* time — and, just as plainly, that it is a configuration test and not
/// a notification about anything. The badge and the closing note both exist so that nobody
/// forwards it as if it were a real alert about a document or a process.
pub fn test_email(input: &TestEmail<'_>) -> RenderedEmail {
    let copy = copy_for(input.locale);
    let server = format!("{}:{}", input.host, input.port);
    let auth = if input.authenticated {
        copy.yes
    } else {
        copy.no
    };

    let shell = Shell {
        instance_name: input.instance_name,
        badge: Some(copy.test_badge),
        heading: copy.test_heading,
        lede: vec![copy.test_lede],
        rows: vec![
            Row {
                label: copy.label_instance,
                value: input.instance_name,
                mono: false,
            },
            Row {
                label: copy.label_server,
                value: &server,
                mono: true,
            },
            Row {
                label: copy.label_encryption,
                value: input.encryption,
                mono: true,
            },
            Row {
                label: copy.label_auth,
                value: auth,
                mono: false,
            },
            Row {
                label: copy.label_sender,
                value: input.from_address,
                mono: true,
            },
            Row {
                label: copy.label_recipient,
                value: input.to_address,
                mono: true,
            },
            Row {
                label: copy.label_sent_at,
                value: input.sent_at,
                mono: false,
            },
        ],
        notes: vec![copy.test_proves, copy.test_not_notification],
        footer: copy.footer_automated,
    };
    shell.render(copy.test_subject.to_owned())
}

// --- The welcome email ---------------------------------------------------------------------------

/// Everything the welcome message states.
///
/// **There is deliberately no field for a password, a token, or a sign-in link.** See
/// [`welcome_email`].
#[derive(Debug, Clone)]
pub struct WelcomeEmail<'a> {
    /// The new operator's display name, if one was recorded. The greeting is omitted without it
    /// rather than falling back to something impersonal and slightly wrong.
    pub recipient_name: Option<&'a str>,
    /// The address the account signs in with — which is the useful fact, since it is the half of the
    /// credential pair the account holder needs and the half that is not secret.
    pub recipient_email: &'a str,
    /// Who created the account. Naming them is what makes this message verifiable to the recipient:
    /// an unexpected account mail from nobody in particular is indistinguishable from phishing.
    pub created_by: Option<&'a str>,
    /// The instance the account belongs to.
    pub instance_name: &'a str,
    /// The instance's **base URL** — the front door, not a magic link. `None` omits the row.
    pub sign_in_url: Option<&'a str>,
    /// Which locale to render in.
    pub locale: &'a str,
}

/// Render the welcome message for a newly created account.
///
/// ## What it does not contain, and why that is structural
///
/// No password, no token, no magic link. [`WelcomeEmail`] has no field that could carry one, so this
/// is a property of the type rather than a discipline someone has to remember: a caller who wanted
/// to email a credential would have to change this signature first, which is exactly the review
/// this deserves.
///
/// Mail is not a confidential channel. It sits in transit on relays outside this deployment's
/// control, at rest in mailboxes and backups indefinitely, and is the single most common way an
/// initial credential leaks. So the message says an administrator will provide credentials
/// separately, and says explicitly that this product never sends passwords or sign-in links by
/// email — which is also what lets a recipient recognise a later message that *does* as a forgery.
///
/// If a credential-delivery mechanism with a real expiry is built later, this is where it plugs in:
/// add the one-time link and its expiry as new fields, and replace `welcome_credentials` with copy
/// that states the deadline. Until then the honest thing is to say nothing is coming by mail.
pub fn welcome_email(input: &WelcomeEmail<'_>) -> RenderedEmail {
    let copy = copy_for(input.locale);

    let mut lede: Vec<&str> = Vec::new();
    let greeting;
    if let Some(name) = input
        .recipient_name
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        greeting = copy.welcome_greeting.replace("{name}", name);
        lede.push(&greeting);
    }
    lede.push(copy.welcome_lede);

    let mut rows = vec![
        Row {
            label: copy.label_instance,
            value: input.instance_name,
            mono: false,
        },
        Row {
            label: copy.welcome_label_account,
            value: input.recipient_email,
            mono: true,
        },
    ];
    if let Some(created_by) = input.created_by.map(str::trim).filter(|c| !c.is_empty()) {
        rows.push(Row {
            label: copy.welcome_label_created_by,
            value: created_by,
            mono: false,
        });
    }
    if let Some(url) = input.sign_in_url.map(str::trim).filter(|u| !u.is_empty()) {
        rows.push(Row {
            label: copy.welcome_label_sign_in,
            value: url,
            mono: true,
        });
    }

    let shell = Shell {
        instance_name: input.instance_name,
        badge: None,
        heading: copy.welcome_heading,
        lede,
        rows,
        notes: vec![copy.welcome_credentials, copy.welcome_never_sends],
        footer: copy.footer_automated,
    };
    shell.render(copy.welcome_subject.to_owned())
}

// --- Copy ----------------------------------------------------------------------------------------

/// The typed key-set every locale must supply in full.
///
/// A struct rather than a map, so a locale missing a string is a compile error — the Rust-side
/// equivalent of the web catalogs' `Record<MessageKey, string>`.
pub struct EmailCopy {
    // Shell.
    /// Footer line on every message.
    pub footer_automated: &'static str,
    // Shared.
    pub yes: &'static str,
    pub no: &'static str,
    pub label_instance: &'static str,
    pub label_server: &'static str,
    pub label_encryption: &'static str,
    pub label_auth: &'static str,
    pub label_sender: &'static str,
    pub label_recipient: &'static str,
    pub label_sent_at: &'static str,
    // Test message.
    pub test_subject: &'static str,
    pub test_badge: &'static str,
    pub test_heading: &'static str,
    pub test_lede: &'static str,
    pub test_proves: &'static str,
    pub test_not_notification: &'static str,
    // Welcome message.
    pub welcome_subject: &'static str,
    pub welcome_heading: &'static str,
    /// Carries a `{name}` placeholder.
    pub welcome_greeting: &'static str,
    pub welcome_lede: &'static str,
    pub welcome_label_account: &'static str,
    pub welcome_label_created_by: &'static str,
    pub welcome_label_sign_in: &'static str,
    pub welcome_credentials: &'static str,
    pub welcome_never_sends: &'static str,
}

/// The 14 shipped locales, in the same order as `apps/web/src/i18n`.
const LOCALES: [(&str, &EmailCopy); 14] = [
    ("pt-PT", &PT_PT),
    ("en-US", &EN_US),
    ("en-GB", &EN_GB),
    ("pt-BR", &PT_BR),
    ("es-ES", &ES_ES),
    ("fr-FR", &FR_FR),
    ("de-DE", &DE_DE),
    ("it-IT", &IT_IT),
    ("nl-NL", &NL_NL),
    ("da-DK", &DA_DK),
    ("fi-FI", &FI_FI),
    ("sv-SE", &SV_SE),
    ("sv-FI", &SV_FI),
    ("pl-PL", &PL_PL),
];

/// Resolve a locale tag to its copy, falling back to the source locale.
///
/// Falls back rather than failing: an unrecognised tag should send Portuguese mail, not no mail. The
/// match is case-insensitive and also accepts a bare language subtag (`pt` → `pt-PT`), because the
/// tag may come from a user preference or an `Accept-Language` header rather than from the fixed
/// list.
pub fn copy_for(locale: &str) -> &'static EmailCopy {
    let tag = locale.trim();
    if let Some((_, copy)) = LOCALES.iter().find(|(t, _)| t.eq_ignore_ascii_case(tag)) {
        return copy;
    }
    let language = tag.split(['-', '_']).next().unwrap_or_default();
    if !language.is_empty()
        && let Some((_, copy)) = LOCALES.iter().find(|(t, _)| {
            t.split('-')
                .next()
                .is_some_and(|l| l.eq_ignore_ascii_case(language))
        })
    {
        return copy;
    }
    &PT_PT
}

/// **Source locale.** Authoritative; every other catalog below is a translation of this one.
static PT_PT: EmailCopy = EmailCopy {
    footer_automated: "Mensagem automática enviada pela Chancela. Não responda a este endereço.",
    yes: "Sim",
    no: "Não",
    label_instance: "Instância",
    label_server: "Servidor SMTP",
    label_encryption: "Encriptação",
    label_auth: "Autenticação",
    label_sender: "Remetente",
    label_recipient: "Destinatário",
    label_sent_at: "Enviada em",
    test_subject: "Chancela — mensagem de teste da configuração de email",
    test_badge: "Mensagem de teste",
    test_heading: "A configuração de email está a funcionar",
    test_lede: "Esta mensagem confirma que esta instância da Chancela conseguiu contactar este \
         destinatário através do servidor SMTP configurado.",
    test_proves: "Receber esta mensagem prova que o servidor SMTP aceitou a mensagem com esta configuração. \
         Não prova a entrega na caixa de entrada, que depende do destinatário e dos filtros pelo \
         caminho.",
    test_not_notification: "Isto é um teste de configuração pedido por um administrador. Não é um aviso sobre nenhum \
         documento, processo ou prazo, e não deve ser reencaminhado como se fosse.",
    welcome_subject: "Chancela — a sua conta foi criada",
    welcome_heading: "A sua conta foi criada",
    welcome_greeting: "Olá, {name}.",
    welcome_lede: "Foi criada uma conta para si nesta instância da Chancela.",
    welcome_label_account: "Conta",
    welcome_label_created_by: "Criada por",
    welcome_label_sign_in: "Endereço de acesso",
    welcome_credentials: "Esta mensagem não contém palavra-passe. Um administrador irá fornecer-lhe as credenciais \
         de acesso separadamente.",
    welcome_never_sends: "A Chancela nunca envia palavras-passe nem ligações de acesso por email. Se receber uma \
         mensagem que o faça, comunique-a a um administrador.",
};

/// Human-authored.
static EN_US: EmailCopy = EmailCopy {
    footer_automated: "Automated message sent by Chancela. Do not reply to this address.",
    yes: "Yes",
    no: "No",
    label_instance: "Instance",
    label_server: "SMTP server",
    label_encryption: "Encryption",
    label_auth: "Authentication",
    label_sender: "Sender",
    label_recipient: "Recipient",
    label_sent_at: "Sent at",
    test_subject: "Chancela — email configuration test message",
    test_badge: "Test message",
    test_heading: "Email configuration is working",
    test_lede: "This message confirms that this Chancela instance was able to reach this recipient \
         through the configured SMTP server.",
    test_proves: "Receiving this message proves that the SMTP server accepted mail with this configuration. \
         It does not prove inbox delivery, which depends on the recipient and on filters along the \
         way.",
    test_not_notification: "This is a configuration test requested by an administrator. It is not a notice about any \
         document, process or deadline, and should not be forwarded as though it were.",
    welcome_subject: "Chancela — your account has been created",
    welcome_heading: "Your account has been created",
    welcome_greeting: "Hello, {name}.",
    welcome_lede: "An account has been created for you on this Chancela instance.",
    welcome_label_account: "Account",
    welcome_label_created_by: "Created by",
    welcome_label_sign_in: "Sign-in address",
    welcome_credentials: "This message contains no password. An administrator will provide your sign-in credentials \
         separately.",
    welcome_never_sends: "Chancela never sends passwords or sign-in links by email. If you receive a message that \
         does, report it to an administrator.",
};

/// Human-authored; British spelling. Identical to `EN_US` for this copy: none of these strings hit
/// a spelling that diverges (no *organisation*, *catalogue* or *-ise* verb appears), so a separate
/// catalog with the same values is the honest record rather than a copy-paste oversight.
static EN_GB: EmailCopy = EmailCopy {
    footer_automated: "Automated message sent by Chancela. Do not reply to this address.",
    yes: "Yes",
    no: "No",
    label_instance: "Instance",
    label_server: "SMTP server",
    label_encryption: "Encryption",
    label_auth: "Authentication",
    label_sender: "Sender",
    label_recipient: "Recipient",
    label_sent_at: "Sent at",
    test_subject: "Chancela — email configuration test message",
    test_badge: "Test message",
    test_heading: "Email configuration is working",
    test_lede: "This message confirms that this Chancela instance was able to reach this recipient \
         through the configured SMTP server.",
    test_proves: "Receiving this message proves that the SMTP server accepted mail with this configuration. \
         It does not prove inbox delivery, which depends on the recipient and on filters along the \
         way.",
    test_not_notification: "This is a configuration test requested by an administrator. It is not a notice about any \
         document, process or deadline, and should not be forwarded as though it were.",
    welcome_subject: "Chancela — your account has been created",
    welcome_heading: "Your account has been created",
    welcome_greeting: "Hello, {name}.",
    welcome_lede: "An account has been created for you on this Chancela instance.",
    welcome_label_account: "Account",
    welcome_label_created_by: "Created by",
    welcome_label_sign_in: "Sign-in address",
    welcome_credentials: "This message contains no password. An administrator will provide your sign-in credentials \
         separately.",
    welcome_never_sends: "Chancela never sends passwords or sign-in links by email. If you receive a message that \
         does, report it to an administrator.",
};

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_test_email() -> RenderedEmail {
        test_email(&TestEmail {
            instance_name: "Encosto Estratégico Lda",
            host: "smtp.encosto-estrategico.pt",
            port: 587,
            encryption: "starttls",
            authenticated: true,
            from_address: "sistema@encosto-estrategico.pt",
            to_address: "amelia.marques@encosto-estrategico.pt",
            sent_at: "Mon, 20 Jul 2026 09:00:00 +0100",
            locale: "pt-PT",
        })
    }

    fn sample_welcome_email() -> RenderedEmail {
        welcome_email(&WelcomeEmail {
            recipient_name: Some("Amélia Marques"),
            recipient_email: "amelia.marques@encosto-estrategico.pt",
            created_by: Some("Rui Bastos"),
            instance_name: "Encosto Estratégico Lda",
            sign_in_url: Some("https://livros.encosto-estrategico.pt/"),
            locale: "pt-PT",
        })
    }

    // --- Structure --------------------------------------------------------------------------------

    #[test]
    fn both_messages_produce_a_subject_and_two_non_empty_bodies() {
        for rendered in [sample_test_email(), sample_welcome_email()] {
            assert!(!rendered.subject.trim().is_empty());
            assert!(!rendered.text_body.trim().is_empty());
            assert!(!rendered.html_body.trim().is_empty());
        }
    }

    /// The HTML is a *rendering* of the text, not a superset of it. Anything an operator could only
    /// learn from the HTML would be invisible to a recipient whose gateway stripped it, and the
    /// text part is the accessible version besides.
    #[test]
    fn every_fact_in_the_html_is_also_in_the_plain_text_part() {
        for (rendered, facts) in [
            (
                sample_test_email(),
                vec![
                    "Encosto Estratégico Lda",
                    "smtp.encosto-estrategico.pt:587",
                    "starttls",
                    "sistema@encosto-estrategico.pt",
                    "amelia.marques@encosto-estrategico.pt",
                    "Mon, 20 Jul 2026 09:00:00 +0100",
                ],
            ),
            (
                sample_welcome_email(),
                vec![
                    "Encosto Estratégico Lda",
                    "amelia.marques@encosto-estrategico.pt",
                    "Rui Bastos",
                    "https://livros.encosto-estrategico.pt/",
                    "Amélia Marques",
                ],
            ),
        ] {
            for fact in facts {
                assert!(
                    rendered.text_body.contains(fact),
                    "the plain-text part is missing {fact:?}:\n{}",
                    rendered.text_body
                );
                assert!(
                    rendered.html_body.contains(&esc(fact)),
                    "the HTML part is missing {fact:?}"
                );
            }
        }
    }

    /// Stripping every tag from the HTML must leave the same prose the text part carries. This is
    /// what "degrades to legible text" actually means, as opposed to "has a text part somewhere".
    #[test]
    fn the_html_degrades_to_the_text_part_when_markup_is_stripped() {
        let rendered = sample_test_email();
        let copy = copy_for("pt-PT");

        let mut stripped = String::new();
        let mut in_tag = false;
        for c in rendered.html_body.chars() {
            match c {
                '<' => in_tag = true,
                '>' => in_tag = false,
                _ if !in_tag => stripped.push(c),
                _ => {}
            }
        }

        for sentence in [
            copy.test_heading,
            copy.test_lede,
            copy.test_proves,
            copy.test_not_notification,
            copy.footer_automated,
        ] {
            // Entities survive tag-stripping, so the comparison is against the escaped form.
            assert!(
                stripped.contains(&esc(sentence)),
                "de-tagged HTML lost {sentence:?}:\n{stripped}"
            );
            assert!(
                rendered.text_body.contains(sentence),
                "the text part lost {sentence:?}"
            );
        }
    }

    // --- Email-HTML discipline --------------------------------------------------------------------

    /// **No remote references of any kind.** A single `<img src="https://…">` is a read receipt: it
    /// tells the sender when a message was opened and roughly from where, for every recipient, with
    /// no consent. Most clients block them by default, so relying on one also breaks the layout for
    /// the majority. The choice made here is to omit imagery entirely rather than inline a CID part.
    ///
    /// This asserts the absence of the *mechanisms*, not of one tag, so a later "just a small logo"
    /// edit fails here rather than shipping.
    #[test]
    fn the_markup_contains_no_remote_references_at_all() {
        for rendered in [sample_test_email(), sample_welcome_email()] {
            let html = &rendered.html_body;
            for forbidden in [
                "<img",
                "src=",
                "background=",
                "url(",
                "@import",
                "<link",
                "<script",
                "<iframe",
                "http://",
                "//fonts.",
                "cid:",
                "data:image",
            ] {
                assert!(
                    !html.contains(forbidden),
                    "{forbidden:?} appears in the markup — no remote or embedded asset is allowed"
                );
            }
            // The only URL anywhere is the operator-supplied sign-in address, rendered as text in a
            // table cell rather than fetched.
            let https_count = html.matches("https://").count();
            assert!(
                https_count <= 1,
                "unexpected https references in the markup ({https_count})"
            );
        }
    }

    /// Layout primitives that do not survive Outlook's Word rendering engine, and styling
    /// mechanisms that do not survive Gmail.
    #[test]
    fn the_markup_uses_table_layout_and_inline_styles_only() {
        let html = sample_test_email().html_body;
        assert!(html.contains("<table role=\"presentation\""));
        for forbidden in [
            "display:flex",
            "display:grid",
            "<style",
            "class=\"",
            "position:",
        ] {
            assert!(
                !html.contains(forbidden),
                "{forbidden:?} appears in the markup"
            );
        }
    }

    /// Every interpolated value is escaped, including ones that look safe: the instance name and the
    /// display name are free text an administrator typed.
    #[test]
    fn interpolated_values_are_html_escaped() {
        let rendered = welcome_email(&WelcomeEmail {
            recipient_name: Some("<script>alert(1)</script>"),
            recipient_email: "a\"b@example.pt",
            created_by: Some("Rui & Filhos"),
            instance_name: "<b>Encosto</b>",
            sign_in_url: None,
            locale: "pt-PT",
        });
        assert!(!rendered.html_body.contains("<script>"));
        assert!(rendered.html_body.contains("&lt;script&gt;"));
        assert!(rendered.html_body.contains("Rui &amp; Filhos"));
        assert!(rendered.html_body.contains("&lt;b&gt;Encosto&lt;/b&gt;"));
        assert!(rendered.html_body.contains("&quot;"));
    }

    // --- The test message -------------------------------------------------------------------------

    /// It has to be unmistakably a test, or someone forwards it as a real notice.
    #[test]
    fn the_test_message_says_it_is_a_test_and_not_a_notification() {
        let rendered = sample_test_email();
        let copy = copy_for("pt-PT");
        for body in [&rendered.text_body, &rendered.html_body] {
            assert!(body.contains(copy.test_badge), "the badge is missing");
            assert!(body.contains(copy.test_not_notification));
        }
        // And it states what it does *not* prove, so nobody reads it as proof of inbox delivery.
        assert!(rendered.text_body.contains(copy.test_proves));
    }

    // --- The welcome message ----------------------------------------------------------------------

    /// **The load-bearing test for this message.** No password, no token, no magic link — in any
    /// locale. `WelcomeEmail` has no field that could carry one, so this pins that no *copy* string
    /// smuggles one in either (a translation offering "your temporary password is below", say).
    #[test]
    fn the_welcome_message_never_carries_a_credential_in_any_locale() {
        for (tag, _) in LOCALES {
            let rendered = welcome_email(&WelcomeEmail {
                recipient_name: Some("Amélia Marques"),
                recipient_email: "amelia.marques@encosto-estrategico.pt",
                created_by: Some("Rui Bastos"),
                instance_name: "Encosto Estratégico Lda",
                // The base URL is the only link ever rendered, and it is the front door.
                sign_in_url: Some("https://livros.encosto-estrategico.pt/"),
                locale: tag,
            });
            for body in [&rendered.text_body, &rendered.html_body] {
                // Nothing that looks like a token: no query string carrying one, and no path beyond
                // the configured base URL.
                assert!(
                    !body.contains('?'),
                    "{tag}: a query string appeared: {body}"
                );
                assert!(
                    !body.to_lowercase().contains("token"),
                    "{tag}: the word 'token' appeared: {body}"
                );
                assert_eq!(
                    body.matches("https://").count(),
                    1,
                    "{tag}: more than the one configured sign-in URL appears"
                );
                assert!(
                    body.contains("https://livros.encosto-estrategico.pt/"),
                    "{tag}: the sign-in URL is missing"
                );
            }
        }
    }

    /// The anti-phishing pair: the message says an administrator will provide credentials
    /// separately, and says this product never sends passwords or links. The second sentence is what
    /// lets a recipient recognise a later message that *does* as a forgery, so it must be present in
    /// every locale.
    #[test]
    fn every_locale_carries_both_anti_phishing_sentences() {
        for (tag, copy) in LOCALES {
            let rendered = welcome_email(&WelcomeEmail {
                recipient_name: None,
                recipient_email: "amelia.marques@encosto-estrategico.pt",
                created_by: None,
                instance_name: "Encosto Estratégico Lda",
                sign_in_url: None,
                locale: tag,
            });
            for sentence in [copy.welcome_credentials, copy.welcome_never_sends] {
                assert!(
                    !sentence.trim().is_empty(),
                    "{tag}: empty anti-phishing copy"
                );
                assert!(
                    rendered.text_body.contains(sentence),
                    "{tag}: the text part is missing the anti-phishing copy"
                );
                // Compared against the escaped form, because the copy itself is escaped on the way
                // into the markup — French `n'envoie` is `n&#39;envoie` there. A raw comparison
                // passes for Portuguese and quietly fails for every locale with an apostrophe.
                assert!(
                    rendered.html_body.contains(&esc(sentence)),
                    "{tag}: the HTML part is missing the anti-phishing copy"
                );
            }
        }
    }

    /// Optional facts are omitted cleanly rather than rendered as an empty or placeholder row.
    #[test]
    fn absent_optional_fields_omit_their_rows_rather_than_rendering_blanks() {
        let copy = copy_for("pt-PT");
        let base = || WelcomeEmail {
            recipient_name: None,
            recipient_email: "amelia.marques@encosto-estrategico.pt",
            created_by: None,
            instance_name: "Encosto Estratégico Lda",
            sign_in_url: None,
            locale: "pt-PT",
        };

        let rendered = welcome_email(&base());
        assert!(!rendered.text_body.contains(copy.welcome_label_created_by));
        assert!(!rendered.text_body.contains(copy.welcome_label_sign_in));
        assert!(
            !rendered.text_body.contains("{name}"),
            "an unfilled placeholder reached the message"
        );

        // Whitespace-only values are treated as absent, not rendered as an empty row.
        let blank = welcome_email(&WelcomeEmail {
            recipient_name: Some("   "),
            created_by: Some(""),
            sign_in_url: Some("  "),
            ..base()
        });
        assert!(!blank.text_body.contains(copy.welcome_label_created_by));
        assert!(!blank.text_body.contains(copy.welcome_label_sign_in));
        assert!(!blank.text_body.contains("{name}"));
    }

    // --- Locales ----------------------------------------------------------------------------------

    /// Every catalog is complete and usable. The struct makes a *missing* field a compile error;
    /// this catches an *empty* one, which compiles fine and renders as a blank line.
    #[test]
    fn every_locale_is_complete_and_keeps_the_name_placeholder() {
        assert_eq!(LOCALES.len(), 14, "14 shipped locales");
        for (tag, copy) in LOCALES {
            for (field, value) in [
                ("footer_automated", copy.footer_automated),
                ("yes", copy.yes),
                ("no", copy.no),
                ("label_instance", copy.label_instance),
                ("label_server", copy.label_server),
                ("label_encryption", copy.label_encryption),
                ("label_auth", copy.label_auth),
                ("label_sender", copy.label_sender),
                ("label_recipient", copy.label_recipient),
                ("label_sent_at", copy.label_sent_at),
                ("test_subject", copy.test_subject),
                ("test_badge", copy.test_badge),
                ("test_heading", copy.test_heading),
                ("test_lede", copy.test_lede),
                ("test_proves", copy.test_proves),
                ("test_not_notification", copy.test_not_notification),
                ("welcome_subject", copy.welcome_subject),
                ("welcome_heading", copy.welcome_heading),
                ("welcome_greeting", copy.welcome_greeting),
                ("welcome_lede", copy.welcome_lede),
                ("welcome_label_account", copy.welcome_label_account),
                ("welcome_label_created_by", copy.welcome_label_created_by),
                ("welcome_label_sign_in", copy.welcome_label_sign_in),
                ("welcome_credentials", copy.welcome_credentials),
                ("welcome_never_sends", copy.welcome_never_sends),
            ] {
                assert!(!value.trim().is_empty(), "{tag}: {field} is empty");
            }
            assert!(
                copy.welcome_greeting.contains("{name}"),
                "{tag}: welcome_greeting lost its {{name}} placeholder, so the greeting would be \
                 impersonal in this locale"
            );
            // The product name is a proper noun and is never translated.
            assert!(
                copy.welcome_never_sends.contains(PRODUCT_NAME),
                "{tag}: the product name was translated out of the anti-phishing sentence"
            );
        }
    }

    /// The locale list is the shipped set, and matches the `Locale` enum the settings document uses.
    #[test]
    fn the_locale_list_matches_the_settings_locale_enum() {
        use crate::settings::Locale;
        for locale in [
            Locale::PtPt,
            Locale::PtBr,
            Locale::DaDk,
            Locale::DeDe,
            Locale::FrFr,
            Locale::FiFi,
            Locale::SvFi,
            Locale::ItIt,
            Locale::NlNl,
            Locale::PlPl,
            Locale::EnGb,
            Locale::EnUs,
            Locale::SvSe,
            Locale::EsEs,
        ] {
            assert!(
                LOCALES.iter().any(|(tag, _)| *tag == locale.as_str()),
                "{} has no email catalog, so it would silently fall back to Portuguese",
                locale.as_str()
            );
        }
    }

    /// An unknown tag sends Portuguese mail rather than no mail.
    #[test]
    fn locale_resolution_falls_back_rather_than_failing() {
        assert!(std::ptr::eq(copy_for("pt-PT"), &PT_PT));
        assert!(std::ptr::eq(copy_for("en-US"), &EN_US));
        // Case-insensitive, and tolerant of surrounding whitespace.
        assert!(std::ptr::eq(copy_for("EN-us"), &EN_US));
        assert!(std::ptr::eq(copy_for("  pt-PT  "), &PT_PT));
        // A bare language subtag resolves to that language's first catalog.
        assert!(std::ptr::eq(copy_for("pt"), &PT_PT));
        assert!(std::ptr::eq(copy_for("en"), &EN_US));
        // Anything unrecognised falls back to the source locale.
        assert!(std::ptr::eq(copy_for("kl-GL"), &PT_PT));
        assert!(std::ptr::eq(copy_for(""), &PT_PT));
    }

    /// The subject is the one string that goes through RFC 2047, and most of these locales are not
    /// pure ASCII. Pinned here so a locale whose subject loses its accents is noticed.
    #[test]
    fn the_source_locale_subject_is_non_ascii_and_therefore_exercises_rfc_2047() {
        assert!(
            !PT_PT.test_subject.is_ascii(),
            "the pt-PT test subject lost its accents, so the RFC 2047 path is no longer exercised"
        );
    }
}
