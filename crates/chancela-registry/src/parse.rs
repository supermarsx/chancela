//! Label-driven parsing of certidão HTML into a [`RegistryExtract`] ([`parse_certidao`]).
//!
//! The certidão permanente is a human-facing HTML certificate, not a structured API. The fields it
//! carries are **legally defined** (registo comercial / registo de fundações), so their Portuguese
//! labels — `NIF/NIPC`, `Firma`/`Denominação`, `Natureza Jurídica`, `Sede`, `Objecto`, `Capital`,
//! `CAE`, `Data de constituição` — are stable even as the surrounding ASP.NET markup churns. This
//! parser therefore uses `scraper` only to flatten the DOM into text lines, then extracts
//! **off those labels**, tolerating missing/optional sections (mirrors `chancela-tsl::parse`).
//!
//! A document with no recognisable Matrícula block (no NIPC / firma / matrícula) is treated as an
//! error/expired page → [`RegistryError::Unrecognized`].

use std::fmt::Write as _;

use scraper::{ElementRef, Html, Node};
use sha2::{Digest, Sha256};

use crate::error::RegistryError;
use crate::inscription::{parse_detail, rollup_officers};
use crate::model::{
    CaeRef, CaeRole, LegalForm, RegistryAnnotation, RegistryEvent, RegistryExtract,
    RegistryOfficer, RegistryProvenance,
};

/// Parse a raw certidão HTML into a typed extract.
///
/// `provenance` is assembled by this function from `masked_code` + `source_url` + `retrieved_at`
/// (all supplied by the caller) plus the computed `raw_digest` (lowercase-hex sha256 of `html`).
/// Parsing is defensive & label-driven: unknown/optional sections are skipped, never fatal. A
/// document with no recognisable Matrícula block yields [`RegistryError::Unrecognized`].
pub fn parse_certidao(
    html: &str,
    masked_code: &str,
    source_url: &str,
    retrieved_at: &str,
) -> Result<RegistryExtract, RegistryError> {
    let lines = dom_to_lines(html);

    // Split the document at the "Inscrições - Averbamentos - Anotações" header: the Matrícula block
    // is everything before it, the numbered event feed everything after.
    let insc_start = lines
        .iter()
        .position(|l| fold(l).contains("averbamentos") || fold(l).contains("inscricoes -"));
    let (matricula_lines, inscricoes_lines): (&[String], &[String]) = match insc_start {
        Some(i) => (&lines[..i], &lines[i + 1..]),
        None => (&lines[..], &[]),
    };

    let matricula = find_field(matricula_lines, |l| l.contains("matricula"));
    let nipc = find_field(matricula_lines, |l| l.contains("nipc")).map(|v| digits_only(&v));
    let firma = find_field(matricula_lines, |l| {
        l == "firma" || l.contains("denominacao")
    });
    let forma_juridica = find_field(matricula_lines, |l| {
        l.contains("natureza juridica") || l.contains("forma juridica")
    });
    let legal_form = forma_juridica.as_deref().map(map_legal_form);
    let sede = find_field(matricula_lines, |l| l == "sede");
    let objeto = find_field(matricula_lines, |l| {
        l.starts_with("objec") || l.starts_with("objet")
    });
    let capital = find_field(matricula_lines, |l| l.starts_with("capital"));
    let data_constituicao = find_field(matricula_lines, |l| {
        l.contains("data") && l.contains("constituicao")
    })
    .and_then(|v| normalize_date(&v));
    let cae = find_cae_refs(matricula_lines);

    // A certidão must carry at least one identity anchor; otherwise it is an error/expired page.
    if matricula.is_none() && nipc.is_none() && firma.is_none() {
        return Err(RegistryError::Unrecognized(
            "no Matrícula block (NIPC / firma / matrícula all absent)".to_owned(),
        ));
    }

    let (inscricoes, orgaos, anotacoes) = parse_inscricoes(inscricoes_lines);
    let (conservatoria, oficial, subscribed_on, valid_until) =
        parse_certidao_meta(inscricoes_lines);

    let raw_digest = sha256_hex(html.as_bytes());
    let provenance = RegistryProvenance {
        access_code_masked: masked_code.to_owned(),
        retrieved_at: retrieved_at.to_owned(),
        source_url: source_url.to_owned(),
        raw_digest,
        conservatoria,
        oficial,
        subscribed_on,
        valid_until,
    };

    Ok(RegistryExtract {
        matricula,
        nipc,
        firma,
        forma_juridica,
        legal_form,
        sede,
        cae,
        objeto,
        capital,
        data_constituicao,
        orgaos,
        inscricoes,
        anotacoes,
        provenance,
    })
}

// ---- DOM → text -----------------------------------------------------------------------------

/// Block-level tag names that introduce a line boundary when flattening the DOM.
fn is_block(name: &str) -> bool {
    matches!(
        name,
        "div"
            | "p"
            | "table"
            | "thead"
            | "tbody"
            | "tfoot"
            | "tr"
            | "td"
            | "th"
            | "ul"
            | "ol"
            | "li"
            | "dl"
            | "dt"
            | "dd"
            | "section"
            | "article"
            | "header"
            | "footer"
            | "main"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
    )
}

/// Flatten `html` into normalized, non-empty text lines, inserting a line boundary at every block
/// element and `<br>`. `scraper` is used ONLY for this DOM→text step; all extraction downstream is
/// label-driven so markup changes stay non-fatal.
fn dom_to_lines(html: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let mut buf = String::new();
    collect_text(document.root_element(), false, &mut buf);
    buf.lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect()
}

fn collect_text(el: ElementRef, skip: bool, out: &mut String) {
    let name = el.value().name();
    // Never emit the text of head/script/style — real ASP.NET pages carry large script blobs.
    let skip_children = skip || matches!(name, "head" | "script" | "style" | "noscript");
    let block = is_block(name);
    if block {
        out.push('\n');
    }
    for child in el.children() {
        match child.value() {
            Node::Text(text) if !skip_children => {
                out.push_str(text);
            }
            Node::Element(_) => {
                if let Some(child_el) = ElementRef::wrap(child) {
                    collect_text(child_el, skip_children, out);
                }
            }
            _ => {}
        }
    }
    if name == "br" {
        out.push('\n');
    }
    if block {
        out.push('\n');
    }
}

// ---- Field extraction -----------------------------------------------------------------------

/// Split a `Label: value` line into `(folded_label, value)`. Lines without a colon are not labels.
pub(crate) fn split_label(line: &str) -> Option<(String, String)> {
    let idx = line.find(':')?;
    let label = fold(line[..idx].trim());
    let value = line[idx + 1..].trim().to_owned();
    Some((label, value))
}

/// Find the value of the first line whose folded label satisfies `is_label`. The value may be on
/// the same line (after the colon) or, for two-cell table layouts, on the following non-empty line.
fn find_field<F: Fn(&str) -> bool>(lines: &[String], is_label: F) -> Option<String> {
    for (i, line) in lines.iter().enumerate() {
        if let Some((label, value)) = split_label(line) {
            if is_label(&label) {
                if !value.is_empty() {
                    return Some(value);
                }
                if let Some(next) = lines[i + 1..].iter().find(|l| !l.trim().is_empty()) {
                    return Some(next.trim().to_owned());
                }
            }
        }
    }
    None
}

/// Collect the role-tagged CAE codes off the Matrícula lines. A certidão prints `CAE Principal:` and
/// one or more `CAE Secundário(s):` lines (each `NNNNN` or `NNNNN - Designação`); some certidões
/// print a single unqualified `CAE:`. The role is read off the folded label suffix
/// ([`cae_role`]) and only the leading code token is kept ([`cae_code_token`]).
fn find_cae_refs(lines: &[String]) -> Vec<CaeRef> {
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some((label, value)) = split_label(line) else {
            continue;
        };
        if label != "cae" && !label.starts_with("cae ") {
            continue;
        }
        let raw = if !value.is_empty() {
            value
        } else if let Some(next) = lines[i + 1..].iter().find(|l| !l.trim().is_empty()) {
            next.trim().to_owned()
        } else {
            continue;
        };
        if let Some(code) = cae_code_token(&raw) {
            out.push(CaeRef {
                code,
                role: cae_role(&label),
            });
        }
    }
    out
}

/// Read the CAE role off a folded label. `"cae secundario"`/`"cae secundaria"`/`"cae secundário(s)"`
/// → [`CaeRole::Secundario`]; everything else (`"cae principal"` and a bare unqualified `"cae"`,
/// which certidões print for the main activity) → [`CaeRole::Principal`] — the documented default.
fn cae_role(label: &str) -> CaeRole {
    if label.contains("secundari") {
        CaeRole::Secundario
    } else {
        CaeRole::Principal
    }
}

/// Extract the leading code token from a CAE value — the secção letter or `NNNNN` digit run before
/// any whitespace or `" - Designação"` suffix. Returns `None` if the value has no leading code.
fn cae_code_token(value: &str) -> Option<String> {
    let token: String = value
        .trim()
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    (!token.is_empty()).then_some(token)
}

// ---- Inscrições / averbamentos ---------------------------------------------------------------

/// How a grouped entry was headed: a numbered `Insc.` inscrição, or an `An.` publication annotation.
enum EntryKind {
    Inscricao,
    Anotacao,
}

/// One grouped entry (header line + body lines) tagged by its header shape.
struct Entry {
    kind: EntryKind,
    lines: Vec<String>,
}

/// Parse the numbered inscrição/averbamento entries + `An.` annotations, and — rolled up off the
/// structured detail — the flat social-organ officers list (kept for the API's `RegistryOfficerView`).
fn parse_inscricoes(
    lines: &[String],
) -> (
    Vec<RegistryEvent>,
    Vec<RegistryOfficer>,
    Vec<RegistryAnnotation>,
) {
    let groups = group_entries(lines);
    let mut inscricoes: Vec<RegistryEvent> = Vec::new();
    let mut anotacoes: Vec<RegistryAnnotation> = Vec::new();
    let mut orgaos: Vec<RegistryOfficer> = Vec::new();

    for entry in &groups {
        match entry.kind {
            EntryKind::Inscricao => {
                let mut event = build_event(&entry.lines);
                let detail = parse_detail(&entry.lines);
                // Keep `kind_hint` pointing at the first parsed act kind (works whether the act
                // kind sat on the AP line or on the next line) so no existing assertion regresses.
                if let Some(first) = detail
                    .apresentacao
                    .as_ref()
                    .and_then(|a| a.act_kinds.first())
                {
                    event.kind_hint = Some(first.clone());
                }
                rollup_officers(&event, &detail, &mut orgaos);
                event.detail = Some(detail);
                inscricoes.push(event);
            }
            EntryKind::Anotacao => anotacoes.push(build_annotation(&entry.lines)),
        }
    }
    (inscricoes, orgaos, anotacoes)
}

/// Group the inscrições region into one entry per header, split on `Insc.`/`An.` header lines and
/// stopping at `Fim da Certidão` (the trailing legalese is not an entry).
fn group_entries(lines: &[String]) -> Vec<Entry> {
    let mut groups: Vec<Entry> = Vec::new();
    for line in lines {
        if fold(line).contains("fim da certidao") {
            break;
        }
        if let Some(kind) = entry_header_kind(line) {
            groups.push(Entry {
                kind,
                lines: vec![line.clone()],
            });
        } else if let Some(last) = groups.last_mut() {
            last.lines.push(line.clone());
        }
        // Lines before the first entry header are ignored (defensive).
    }
    groups
}

/// An entry header opens an inscrição (`Insc.N`) or a publication annotation (`An. N - …`); both
/// carry a number.
fn entry_header_kind(line: &str) -> Option<EntryKind> {
    if !line.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    let f = fold(line.trim());
    if f.starts_with("insc.") || f.starts_with("insc ") || f.starts_with("inscricao") {
        Some(EntryKind::Inscricao)
    } else if f.starts_with("an.") || f.starts_with("an ") {
        Some(EntryKind::Anotacao)
    } else {
        None
    }
}

fn build_event(group: &[String]) -> RegistryEvent {
    let header = &group[0];
    let (number, apresentacao) = parse_header(header);
    let date = apresentacao
        .as_deref()
        .and_then(iso_from_apresentacao)
        .or_else(|| group.iter().skip(1).find_map(|l| date_from_data_line(l)));
    let kind_hint = group
        .iter()
        .skip(1)
        .find(|l| !fold(l).starts_with("ap.") && !l.trim().is_empty())
        .map(|l| l.trim().to_owned());
    let text = group.join("\n");
    RegistryEvent {
        number,
        kind_hint,
        apresentacao,
        date,
        text,
        detail: None,
    }
}

/// Build a `RegistryAnnotation` from an `An. N - YYYYMMDD - Publicado em <url>.` group.
fn build_annotation(group: &[String]) -> RegistryAnnotation {
    let header = &group[0];
    let number = {
        let rest = strip_an_prefix(header);
        rest.split(|c: char| !c.is_ascii_alphanumeric())
            .find(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()))
            .map(str::to_owned)
    };
    let date = header
        .split(|c: char| !c.is_ascii_digit())
        .find(|t| t.len() == 8)
        .and_then(yyyymmdd_to_iso);
    let publication_url = group.iter().find_map(|l| first_http_token(l));
    RegistryAnnotation {
        number,
        date,
        publication_url,
        text: group.join("\n"),
    }
}

/// Remove a leading `An.` / `An ` (case-insensitive) from an annotation header.
fn strip_an_prefix(s: &str) -> &str {
    let t = s.trim();
    if t.len() >= 3 && t[..3].eq_ignore_ascii_case("an.")
        || t[..3.min(t.len())].eq_ignore_ascii_case("an ")
    {
        t[3..].trim_start()
    } else {
        t
    }
}

/// The first `http(s)://…` token on a line, trailing punctuation trimmed.
fn first_http_token(line: &str) -> Option<String> {
    let start = find_ascii_ci(line, "http")?;
    let token: String = line[start..]
        .chars()
        .take_while(|c| !c.is_whitespace())
        .collect();
    let trimmed = token.trim_end_matches(['.', ',', ';', ')']);
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Read the certidão-meta trailer off the whole inscrições region: the conservatória/oficial
/// signature (LAST occurrence — the final certidão signature) and the subscription/validity window.
fn parse_certidao_meta(
    lines: &[String],
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let mut conservatoria = None;
    let mut oficial = None;
    let mut subscribed_on = None;
    let mut valid_until = None;
    for line in lines {
        let f = fold(line);
        if f.contains("conservatoria do registo") {
            conservatoria = Some(line.trim().to_owned());
        }
        if f.contains("oficial de registos") {
            oficial = extract_oficial(line);
        }
        if f.contains("subscrita em") {
            let dates = scan_dates(line);
            subscribed_on = dates.first().cloned();
            valid_until = dates.get(1).cloned();
        }
    }
    (conservatoria, oficial, subscribed_on, valid_until)
}

/// Split an entry header like `Insc. 3 Av. 1 AP. 122/20230620` into `("3 Av. 1", "AP. 122/…")`.
fn parse_header(header: &str) -> (Option<String>, Option<String>) {
    let ap_pos = find_ascii_ci(header, "ap.").or_else(|| find_ascii_ci(header, "ap "));
    let (num_part, ap_part) = match ap_pos {
        Some(p) => (&header[..p], Some(header[p..].trim().to_owned())),
        None => (header, None),
    };
    let number = strip_insc_prefix(num_part);
    let number = if number.is_empty() {
        None
    } else {
        Some(number)
    };
    (number, ap_part)
}

/// Remove a leading `Insc.` / `Insc ` (case-insensitive) and surrounding whitespace.
fn strip_insc_prefix(s: &str) -> String {
    let t = s.trim();
    let lower = t.to_ascii_lowercase();
    let rest = if lower.starts_with("insc.") || lower.starts_with("insc ") {
        &t[5..]
    } else {
        t
    };
    rest.trim().to_owned()
}

// ---- Certidão-meta helpers -------------------------------------------------------------------

/// Extract the oficial's name from `O(A) Oficial de Registos, <name>` (the text after the comma
/// that follows "Registos"). Shared with the per-entry signature scan in `inscription.rs`.
pub(crate) fn extract_oficial(line: &str) -> Option<String> {
    let anchor = find_ascii_ci(line, "registos")?;
    let after = &line[anchor + "registos".len()..];
    let comma = after.find(',')?;
    let name = after[comma + 1..].trim().trim_end_matches('.').trim();
    (!name.is_empty()).then(|| name.to_owned())
}

/// All ISO dates found among a line's whitespace-separated tokens (each token stripped of
/// surrounding non-digits first, so trailing punctuation and connective words are ignored).
pub(crate) fn scan_dates(line: &str) -> Vec<String> {
    line.split_whitespace()
        .filter_map(|tok| normalize_date(tok.trim_matches(|c: char| !c.is_ascii_digit())))
        .collect()
}

// ---- Legal form ------------------------------------------------------------------------------

/// Map raw "Natureza Jurídica" text to a normalized [`LegalForm`] (accent/case-insensitive).
fn map_legal_form(raw: &str) -> LegalForm {
    let f = fold(raw);
    if f.contains("unipessoal") && f.contains("quota") {
        LegalForm::SociedadeUnipessoalPorQuotas
    } else if f.contains("quota") {
        LegalForm::SociedadePorQuotas
    } else if f.contains("anonima") {
        LegalForm::SociedadeAnonima
    } else if f.contains("comandita")
        && (f.contains("acoes") || f.contains("accoes") || f.contains(" por ac"))
    {
        LegalForm::SociedadeEmComanditaPorAcoes
    } else if f.contains("comandita") {
        LegalForm::SociedadeEmComanditaSimples
    } else if f.contains("nome colectivo") || f.contains("nome coletivo") {
        LegalForm::SociedadeEmNomeColetivo
    } else if f.contains("cooperativa") {
        LegalForm::Cooperativa
    } else if f.contains("fundacao") {
        LegalForm::Fundacao
    } else if f.contains("associacao") {
        LegalForm::Associacao
    } else {
        LegalForm::Other(raw.trim().to_owned())
    }
}

// ---- Small helpers ---------------------------------------------------------------------------

/// Accent-fold + lowercase for robust, markup-agnostic label/keyword matching.
pub(crate) fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ã' | 'ä' | 'Á' | 'À' | 'Â' | 'Ã' | 'Ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'i',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' | 'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'o',
            'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'u',
            'ç' | 'Ç' => 'c',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

/// Keep only ASCII digits (e.g. NIPC printed as `500 002 020` → `500002020`).
pub(crate) fn digits_only(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Case-insensitive ASCII substring search returning a byte index valid for slicing `haystack`.
pub(crate) fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// Extract an ISO date from an apresentação like `AP. 122/20230620` → `2023-06-20`.
fn iso_from_apresentacao(ap: &str) -> Option<String> {
    let bytes = ap.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'/' {
            let run: String = ap[i + 1..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if run.len() >= 8 {
                return yyyymmdd_to_iso(&run[..8]);
            }
        }
    }
    None
}

/// Extract an ISO date from a `Data …: <value>` line (numeric formats or a PT long date).
fn date_from_data_line(line: &str) -> Option<String> {
    let (label, value) = split_label(line)?;
    if label.starts_with("data") {
        normalize_any_date(&value)
    } else {
        None
    }
}

/// Numeric-or-long-date normalization: try [`normalize_date`] first, then [`normalize_pt_long_date`].
pub(crate) fn normalize_any_date(s: &str) -> Option<String> {
    normalize_date(s).or_else(|| normalize_pt_long_date(s))
}

/// Normalize a PT long date (`"11 de maio de 2026"`, and the real quirk `"11 da maio de 2026"`) to
/// ISO. Tolerant: scans tokens for a 1–2 digit day, a month name (accent-folded), and a 4-digit
/// year, ignoring the connectives (`de`/`da`/`do`) entirely. Returns `None` if any part is missing.
pub(crate) fn normalize_pt_long_date(s: &str) -> Option<String> {
    let mut day: Option<u32> = None;
    let mut month: Option<u32> = None;
    let mut year: Option<u32> = None;
    for tok in fold(s).split_whitespace() {
        if year.is_none() && tok.len() == 4 && tok.chars().all(|c| c.is_ascii_digit()) {
            year = tok.parse().ok();
        } else if day.is_none()
            && (1..=2).contains(&tok.len())
            && tok.chars().all(|c| c.is_ascii_digit())
        {
            day = tok.parse().ok();
        } else if month.is_none() {
            month = month_number(tok);
        }
    }
    match (day, month, year) {
        (Some(d), Some(m), Some(y)) if (1..=31).contains(&d) => {
            Some(format!("{y:04}-{m:02}-{d:02}"))
        }
        _ => None,
    }
}

/// Map a folded Portuguese month name to its 1-based number.
fn month_number(folded: &str) -> Option<u32> {
    match folded {
        "janeiro" => Some(1),
        "fevereiro" => Some(2),
        "marco" => Some(3),
        "abril" => Some(4),
        "maio" => Some(5),
        "junho" => Some(6),
        "julho" => Some(7),
        "agosto" => Some(8),
        "setembro" => Some(9),
        "outubro" => Some(10),
        "novembro" => Some(11),
        "dezembro" => Some(12),
        _ => None,
    }
}

/// Parse a printed money figure (`"100,00 Euros"`) into an amount run + trailing currency word.
/// Returns `None` when the value has no leading numeric run (e.g. a prose CAPITAL realization note).
pub(crate) fn parse_money(value: &str) -> Option<crate::model::Money> {
    let v = value.trim();
    let amount: String = v
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
        .collect();
    if amount.chars().all(|c| !c.is_ascii_digit()) {
        return None;
    }
    let currency = v[amount.len()..].trim();
    Some(crate::model::Money {
        amount_text: amount,
        currency: (!currency.is_empty()).then(|| currency.to_owned()),
    })
}

/// Parse a `CCCC - CCC LOCALIDADE` / `CCCC-CCC LOCALIDADE` postal line into `(NNNN-NNN, locality?)`.
pub(crate) fn parse_postal_line(line: &str) -> Option<(String, Option<String>)> {
    let t = line.trim();
    let mut chars = t.char_indices().peekable();
    let mut four = String::new();
    while four.len() < 4 {
        let (_, c) = *chars.peek()?;
        if !c.is_ascii_digit() {
            break;
        }
        four.push(c);
        chars.next();
    }
    if four.len() != 4 {
        return None;
    }
    // Skip separators (spaces/hyphens) between the 4- and 3-digit groups.
    while let Some((_, c)) = chars.peek() {
        if *c == ' ' || *c == '-' {
            chars.next();
        } else {
            break;
        }
    }
    let mut three = String::new();
    while three.len() < 3 {
        let Some((_, c)) = chars.peek() else { break };
        if !c.is_ascii_digit() {
            break;
        }
        three.push(*c);
        chars.next();
    }
    if three.len() != 3 {
        return None;
    }
    let rest = match chars.peek() {
        Some(&(idx, _)) => t[idx..].trim(),
        None => "",
    };
    Some((
        format!("{four}-{three}"),
        (!rest.is_empty()).then(|| rest.to_owned()),
    ))
}

/// Parse a `Distrito: … Concelho: … Freguesia: …` admin line (all three on one line) into its
/// three optional values. Returns `None` when the line does not carry a `Distrito:` label.
pub(crate) fn parse_admin_line(
    line: &str,
) -> Option<(Option<String>, Option<String>, Option<String>)> {
    find_ascii_ci(line, "distrito")?;
    let distrito = admin_value(line, "distrito", &["concelho", "freguesia"]);
    let concelho = admin_value(line, "concelho", &["freguesia"]);
    let freguesia = admin_value(line, "freguesia", &[]);
    Some((distrito, concelho, freguesia))
}

/// The value of one admin sub-label (`label:`) up to the next sub-label in `next_labels` (or the
/// end of the line). All labels are ASCII, so byte indices from [`find_ascii_ci`] are valid slices.
fn admin_value(line: &str, label: &str, next_labels: &[&str]) -> Option<String> {
    let start = find_ascii_ci(line, label)?;
    let after = &line[start + label.len()..];
    let colon = after.find(':')?;
    let val_start = start + label.len() + colon + 1;
    let mut end = line.len();
    for nl in next_labels {
        if let Some(p) = find_ascii_ci(&line[val_start..], nl) {
            end = end.min(val_start + p);
        }
    }
    let val = line[val_start..end].trim();
    (!val.is_empty()).then(|| val.to_owned())
}

/// Normalize a printed date to ISO `YYYY-MM-DD` (accepts `YYYY-MM-DD`, `YYYYMMDD`, `DD-MM-YYYY`,
/// `DD/MM/YYYY`). Returns `None` if it does not look like a date.
pub(crate) fn normalize_date(s: &str) -> Option<String> {
    let t = s.trim();
    if is_iso_date(t) {
        return Some(t.to_owned());
    }
    if t.len() == 8 && t.chars().all(|c| c.is_ascii_digit()) {
        return yyyymmdd_to_iso(t);
    }
    let parts: Vec<&str> = t.splitn(3, ['-', '/', '.']).map(str::trim).collect();
    if parts.len() == 3
        && parts[2].len() == 4
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
        && !parts[0].is_empty()
        && !parts[1].is_empty()
    {
        return Some(format!("{}-{:0>2}-{:0>2}", parts[2], parts[1], parts[0]));
    }
    None
}

pub(crate) fn yyyymmdd_to_iso(s: &str) -> Option<String> {
    if s.len() == 8 && s.chars().all(|c| c.is_ascii_digit()) {
        Some(format!("{}-{}-{}", &s[0..4], &s[4..6], &s[6..8]))
    } else {
        None
    }
}

fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[8..10].iter().all(u8::is_ascii_digit)
}

/// Lowercase-hex sha256, matching the ledger/pades digest convention.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        write!(out, "{b:02x}").expect("writing to a String never fails");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_the_common_legal_forms() {
        assert_eq!(
            map_legal_form("Sociedade por quotas"),
            LegalForm::SociedadePorQuotas
        );
        assert_eq!(
            map_legal_form("Sociedade unipessoal por quotas"),
            LegalForm::SociedadeUnipessoalPorQuotas
        );
        assert_eq!(
            map_legal_form("Sociedade Anónima"),
            LegalForm::SociedadeAnonima
        );
        assert_eq!(map_legal_form("Fundação"), LegalForm::Fundacao);
        assert_eq!(
            map_legal_form("Sociedade em comandita por acções"),
            LegalForm::SociedadeEmComanditaPorAcoes
        );
        assert_eq!(
            map_legal_form("Agrupamento Complementar de Empresas"),
            LegalForm::Other("Agrupamento Complementar de Empresas".to_owned())
        );
    }

    #[test]
    fn normalizes_date_formats() {
        assert_eq!(normalize_date("2020-01-15").as_deref(), Some("2020-01-15"));
        assert_eq!(normalize_date("20200115").as_deref(), Some("2020-01-15"));
        assert_eq!(normalize_date("15-01-2020").as_deref(), Some("2020-01-15"));
        assert_eq!(normalize_date("15/01/2020").as_deref(), Some("2020-01-15"));
        assert_eq!(normalize_date("not a date"), None);
    }

    #[test]
    fn iso_from_apresentacao_reads_the_trailing_date() {
        assert_eq!(
            iso_from_apresentacao("AP. 122/20230620").as_deref(),
            Some("2023-06-20")
        );
        assert_eq!(iso_from_apresentacao("AP. 122").as_deref(), None);
    }

    #[test]
    fn reads_cae_roles_off_the_label() {
        let lines: Vec<String> = [
            "CAE Principal: 70220 - Consultoria em gestão",
            "CAE Secundário: 82990",
            "CAE Secundária: 63110",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let refs = find_cae_refs(&lines);
        assert_eq!(
            refs,
            vec![
                CaeRef {
                    code: "70220".to_owned(),
                    role: CaeRole::Principal,
                },
                CaeRef {
                    code: "82990".to_owned(),
                    role: CaeRole::Secundario,
                },
                CaeRef {
                    code: "63110".to_owned(),
                    role: CaeRole::Secundario,
                },
            ]
        );
    }

    #[test]
    fn bare_cae_label_defaults_to_principal() {
        let lines = vec!["CAE: 41200".to_owned()];
        let refs = find_cae_refs(&lines);
        assert_eq!(
            refs,
            vec![CaeRef {
                code: "41200".to_owned(),
                role: CaeRole::Principal,
            }]
        );
    }

    #[test]
    fn cae_code_token_strips_trailing_designation() {
        assert_eq!(cae_code_token("70220").as_deref(), Some("70220"));
        assert_eq!(
            cae_code_token("70220 - Consultoria em gestão").as_deref(),
            Some("70220")
        );
        assert_eq!(cae_code_token("A - Agricultura").as_deref(), Some("A"));
        assert_eq!(cae_code_token("   ").as_deref(), None);
    }

    #[test]
    fn dom_to_lines_splits_on_blocks_and_skips_script() {
        let html = "<html><body><p>Firma:</p><p>Encosto Estratégico, Lda</p>\
            <script>var x = 'Objecto: leak';</script></body></html>";
        let lines = dom_to_lines(html);
        assert!(lines.iter().any(|l| l == "Firma:"));
        assert!(lines.iter().any(|l| l == "Encosto Estratégico, Lda"));
        assert!(!lines.iter().any(|l| l.contains("leak")));
    }

    #[test]
    fn normalizes_pt_long_dates_including_the_da_quirk() {
        assert_eq!(
            normalize_pt_long_date("11 de maio de 2026").as_deref(),
            Some("2026-05-11")
        );
        // The real "da" quirk (sic — should be "de").
        assert_eq!(
            normalize_pt_long_date("11 da maio de 2026").as_deref(),
            Some("2026-05-11")
        );
        assert_eq!(
            normalize_pt_long_date("1 de Janeiro de 2020").as_deref(),
            Some("2020-01-01")
        );
        assert_eq!(
            normalize_pt_long_date("30 de Dezembro de 1999").as_deref(),
            Some("1999-12-30")
        );
        assert_eq!(normalize_pt_long_date("qualquer coisa"), None);
        // `normalize_any_date` still accepts the numeric forms.
        assert_eq!(
            normalize_any_date("2020-01-15").as_deref(),
            Some("2020-01-15")
        );
        assert_eq!(
            normalize_any_date("11 da maio de 2026").as_deref(),
            Some("2026-05-11")
        );
    }

    #[test]
    fn parses_money_and_the_realization_note() {
        let m = parse_money("100,00 Euros").unwrap();
        assert_eq!(m.amount_text, "100,00");
        assert_eq!(m.currency.as_deref(), Some("Euros"));

        let m = parse_money("5.000,00 EUR").unwrap();
        assert_eq!(m.amount_text, "5.000,00");
        assert_eq!(m.currency.as_deref(), Some("EUR"));

        assert_eq!(parse_money("1,00").unwrap().currency, None);
        // A prose CAPITAL line is not money → None (routed to the realization note).
        assert_eq!(parse_money("A entregar nos cofres da sociedade"), None);
    }

    #[test]
    fn parses_postal_and_admin_lines() {
        assert_eq!(
            parse_postal_line("4000-111 PORTO"),
            Some(("4000-111".to_owned(), Some("PORTO".to_owned())))
        );
        // Spaced/hyphenated separator variant, no locality.
        assert_eq!(
            parse_postal_line("2705 - 839"),
            Some(("2705-839".to_owned(), None))
        );
        assert_eq!(parse_postal_line("Rua do Exemplo"), None);

        let (d, c, f) =
            parse_admin_line("Distrito: Porto Concelho: Vila Nova de Gaia Freguesia: Mafamude")
                .unwrap();
        assert_eq!(d.as_deref(), Some("Porto"));
        assert_eq!(c.as_deref(), Some("Vila Nova de Gaia"));
        assert_eq!(f.as_deref(), Some("Mafamude"));
        assert_eq!(parse_admin_line("Rua do Exemplo, n.º 11"), None);
    }

    #[test]
    fn scan_dates_reads_the_validity_window() {
        let dates =
            scan_dates("Certidão permanente subscrita em 05/07/2026 e válida até 05/07/2027.");
        assert_eq!(
            dates,
            vec!["2026-07-05".to_owned(), "2027-07-05".to_owned()]
        );
    }
}
