//! The structured inscription layer: a line-oriented state machine that reads an
//! [`InscriptionDetail`] off one grouped inscrição's lines, on top of the raw
//! [`RegistryEvent`](crate::model::RegistryEvent) text (which always stays byte-for-byte).
//!
//! The certidão inscrição bodies are label-driven Portuguese prose, printed with real-world
//! inconsistencies — `CAPITAL :` vs `CAPITAL:`, act kinds on the apresentação line *or* the next
//! line, the `11 da maio de 2026` long-date quirk, multi-line addresses with a separate
//! `Distrito/Concelho/Freguesia` line and a `CCCC-CCC LOCALIDADE` postal line. This parser mirrors
//! [`crate::parse`]'s temperament: match labels, tolerate the variants, never panic. A body that
//! matches no v1-structured act yields `payload: None` — the raw text still carries everything.

use crate::model::{
    AmendmentPayload, Apresentacao, CessationPayload, ConstitutionPayload, DesignationPayload,
    InscriptionDetail, InscriptionPayload, Organ, OrganMember, Person, Quota, RegistryEvent,
    RegistryOfficer, RegistryOfficialSignature,
};
use crate::parse::{
    digits_only, extract_oficial, find_ascii_ci, fold, normalize_any_date, parse_admin_line,
    parse_money, parse_postal_line, split_label, yyyymmdd_to_iso,
};

/// Read the structured detail layer off one grouped inscrição (`group[0]` is the `Insc.` header,
/// `group[1..]` the body). Always returns a value; `payload`/`apresentacao` are best-effort.
pub fn parse_detail(group: &[String]) -> InscriptionDetail {
    let body: &[String] = group.get(1..).unwrap_or(&[]);
    let apresentacao = parse_apresentacao(group.first().map_or("", String::as_str), body);
    let blob = classification_blob(&apresentacao, body);
    let payload = parse_payload(&blob, body);
    let signatures = collect_signatures(body);
    InscriptionDetail {
        apresentacao,
        payload,
        signatures,
    }
}

// ---- Apresentação ----------------------------------------------------------------------------

/// Parse the apresentação header (`AP. N/YYYYMMDD HH:MM:SS UTC - ACT, ACT`), tolerating the act
/// kind(s) on the AP line or — falling back — on the first plain body line.
fn parse_apresentacao(header: &str, body: &[String]) -> Option<Apresentacao> {
    let mut a = Apresentacao::default();
    if let Some(p) = find_ascii_ci(header, "ap.").or_else(|| find_ascii_ci(header, "ap ")) {
        let after = header[p + 3..].trim_start();
        let (stub, tail) = match after.find(" - ") {
            Some(d) => (&after[..d], Some(after[d + 3..].trim())),
            None => (after, None),
        };
        parse_ap_stub(stub, &mut a);
        if let Some(t) = tail {
            a.act_kinds = split_acts(t);
        }
    }
    if a.act_kinds.is_empty() {
        // Fallback: the act kind on the first plain (colon-less, non-AP) body line.
        if let Some(first) = body.iter().find(|l| {
            !l.trim().is_empty() && split_label(l).is_none() && !fold(l).starts_with("ap.")
        }) {
            a.act_kinds = split_acts(first);
        }
    }
    if a.number.is_none() && a.date.is_none() && a.time.is_none() && a.act_kinds.is_empty() {
        None
    } else {
        Some(a)
    }
}

/// Parse the `N/YYYYMMDD HH:MM:SS UTC` stub into number/date/time.
fn parse_ap_stub(stub: &str, a: &mut Apresentacao) {
    let stub = stub.trim();
    match stub.find('/') {
        Some(slash) => {
            a.number = ne(stub[..slash].to_owned());
            let rest = stub[slash + 1..].trim_start();
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if digits.len() >= 8 {
                a.date = yyyymmdd_to_iso(&digits[..8]);
            }
            let time = rest[digits.len()..].trim();
            a.time = ne(time.to_owned());
        }
        None => a.number = ne(stub.to_owned()),
    }
}

/// Comma-split act kinds, each trimmed, empties dropped.
fn split_acts(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

// ---- Classification --------------------------------------------------------------------------

/// The folded text used to classify the act: the parsed act kinds, else the first plain body line.
fn classification_blob(ap: &Option<Apresentacao>, body: &[String]) -> String {
    if let Some(a) = ap
        && !a.act_kinds.is_empty()
    {
        return fold(&a.act_kinds.join(", "));
    }
    body.iter()
        .find(|l| !l.trim().is_empty() && split_label(l).is_none() && !fold(l).starts_with("ap."))
        .map(|l| fold(l))
        .unwrap_or_default()
}

/// Classify + parse the body into a payload. Precedence: Constitution > Cessation > Designation >
/// ContractAmendment (a constitution that co-lists designações is still a Constitution, which
/// absorbs the organs). Unrecognized acts (transmissão/dissolução, …) → `None` (raw text kept).
fn parse_payload(blob: &str, body: &[String]) -> Option<InscriptionPayload> {
    if blob.contains("constituicao") {
        Some(InscriptionPayload::Constitution(parse_constitution(body)))
    } else if blob.contains("cessacao") || blob.contains("renuncia") || blob.contains("exoneracao")
    {
        Some(InscriptionPayload::Cessation(parse_cessation(body)))
    } else if blob.contains("designacao") || blob.contains("nomeacao") {
        Some(InscriptionPayload::Designation(parse_designation(body)))
    } else if blob.contains("altera")
        && [
            "contrato",
            "sede",
            "objec",
            "objet",
            "capital",
            "firma",
            "denominacao",
        ]
        .iter()
        .any(|k| blob.contains(k))
    {
        Some(InscriptionPayload::ContractAmendment(parse_amendment(body)))
    } else {
        None
    }
}

// ---- Constitution ----------------------------------------------------------------------------

/// Which section of a constitution body the cursor is walking.
#[derive(Clone, Copy, PartialEq)]
enum Section {
    Top,
    Socios,
    Orgaos,
}

fn parse_constitution(body: &[String]) -> ConstitutionPayload {
    let mut p = ConstitutionPayload::default();
    let mut section = Section::Top;
    let mut i = 0;
    while i < body.len() {
        let line = &body[i];
        let Some((label, value)) = split_label(line) else {
            i += 1;
            continue;
        };
        // Fields that may appear under any section.
        if label == "data da deliberacao" {
            p.deliberation_date = normalize_any_date(&value);
            i += 1;
            continue;
        }
        if label == "forma de obrigar" {
            p.forma_de_obrigar = ne(value);
            i += 1;
            continue;
        }
        // Section markers.
        if label.contains("socios") && label.contains("quota") {
            section = Section::Socios;
            i += 1;
            continue;
        }
        if label.contains("orgao") && label.contains("designad") {
            section = Section::Orgaos;
            i += 1;
            continue;
        }
        i = match section {
            Section::Socios => socios_line(&mut p, body, i, &label, value),
            Section::Orgaos => organ_line(&mut p.orgaos, body, i, &label, &value, line),
            Section::Top => top_line(&mut p, body, i, &label, value),
        };
    }
    p
}

/// Handle one top-level constitution field line; returns the next index.
fn top_line(
    p: &mut ConstitutionPayload,
    body: &[String],
    i: usize,
    label: &str,
    value: String,
) -> usize {
    match label {
        "firma" => p.firma = ne(value),
        "nipc" | "nif/nipc" => p.nipc = ne(digits_only(&value)),
        "natureza juridica" | "forma juridica" => p.natureza_juridica = ne(value),
        "sede" => {
            let mut j = i + 1;
            let addr = consume_address(body, &mut j, value);
            if !addr.is_empty() {
                p.sede = Some(addr);
            }
            return j;
        }
        "objecto" | "objeto" => {
            let mut j = i + 1;
            let obj = consume_objecto(body, &mut j, value);
            if !obj.is_empty() {
                p.objecto = Some(obj);
            }
            return j;
        }
        l if l.starts_with("capital") => match parse_money(&value) {
            Some(m) => p.capital = Some(m),
            None => p.capital_realization_note = ne(value),
        },
        l if l.starts_with("data de encerramento") => p.fiscal_year_end = ne(value),
        _ => {}
    }
    i + 1
}

/// Handle one line inside the SÓCIOS E QUOTAS section; returns the next index.
fn socios_line(
    p: &mut ConstitutionPayload,
    body: &[String],
    i: usize,
    label: &str,
    value: String,
) -> usize {
    if label.starts_with("quota") {
        p.socios.push(Quota {
            amount: parse_money(&value).unwrap_or_default(),
            titular: Person::default(),
        });
        return i + 1;
    }
    let Some(q) = p.socios.last_mut() else {
        return i + 1;
    };
    match label {
        "titular" => q.titular.name = value,
        "nif/nipc" | "nipc" => q.titular.nif = ne(digits_only(&value)),
        "estado civil" => q.titular.estado_civil = ne(value),
        "nacionalidade" => q.titular.nacionalidade = ne(value),
        "residencia/sede" | "residencia" => {
            let mut j = i + 1;
            let addr = consume_address(body, &mut j, value);
            if !addr.is_empty() {
                q.titular.residencia = Some(addr);
            }
            return j;
        }
        _ => {}
    }
    i + 1
}

// ---- Organs (shared by Constitution + Designation) -------------------------------------------

fn parse_designation(body: &[String]) -> DesignationPayload {
    let (orgaos, deliberation_date) = parse_organs(body);
    DesignationPayload {
        orgaos,
        deliberation_date,
    }
}

/// Collect the organ/member structure from a body, plus the deliberation date if printed.
fn parse_organs(body: &[String]) -> (Vec<Organ>, Option<String>) {
    let mut organs: Vec<Organ> = Vec::new();
    let mut delib = None;
    let mut i = 0;
    while i < body.len() {
        let line = &body[i];
        let Some((label, value)) = split_label(line) else {
            i += 1;
            continue;
        };
        if label == "data da deliberacao" {
            delib = normalize_any_date(&value);
            i += 1;
            continue;
        }
        if label.contains("orgao") && label.contains("designad") {
            i += 1;
            continue;
        }
        i = organ_line(&mut organs, body, i, &label, &value, line);
    }
    (organs, delib)
}

/// Handle one line inside an organ region; returns the next index. A bare organ header (empty
/// value naming a known organ) opens a new organ; `Nome/Firma:` opens a new member under it.
fn organ_line(
    organs: &mut Vec<Organ>,
    body: &[String],
    i: usize,
    label: &str,
    value: &str,
    line: &str,
) -> usize {
    match label {
        "nome/firma" => {
            ensure_organ(organs);
            if let Some(o) = organs.last_mut() {
                o.members.push(OrganMember {
                    name: value.to_owned(),
                    ..OrganMember::default()
                });
            }
        }
        "nif/nipc" | "nipc" => {
            if let Some(m) = last_member(organs) {
                m.nif = ne(digits_only(value));
            }
        }
        "cargo" => {
            if let Some(m) = last_member(organs) {
                m.cargo = ne(value.to_owned());
            }
        }
        "nacionalidade" => {
            if let Some(m) = last_member(organs) {
                m.nacionalidade = ne(value.to_owned());
            }
        }
        "residencia/sede" | "residencia" => {
            let mut j = i + 1;
            let addr = consume_address(body, &mut j, value.to_owned());
            if let Some(m) = last_member(organs)
                && !addr.is_empty()
            {
                m.residencia = Some(addr);
            }
            return j;
        }
        _ => {
            if value.trim().is_empty() && is_organ_header(label) {
                organs.push(Organ {
                    name: printed_label(line),
                    members: Vec::new(),
                });
            }
        }
    }
    i + 1
}

/// Ensure at least one organ exists to attach members to (a designation may print members with no
/// explicit organ header).
fn ensure_organ(organs: &mut Vec<Organ>) {
    if organs.is_empty() {
        organs.push(Organ::default());
    }
}

fn last_member(organs: &mut [Organ]) -> Option<&mut OrganMember> {
    organs.last_mut().and_then(|o| o.members.last_mut())
}

/// Whether a folded label names a social organ (so a bare `LABEL:` opens a new organ).
fn is_organ_header(label: &str) -> bool {
    [
        "gerencia",
        "administracao",
        "conselho",
        "fiscal",
        "direcao",
        "direccao",
        "mesa",
        "comissao",
        "secretaria",
    ]
    .iter()
    .any(|k| label.contains(k))
}

// ---- Cessation & amendment -------------------------------------------------------------------

fn parse_cessation(body: &[String]) -> CessationPayload {
    let mut members: Vec<OrganMember> = Vec::new();
    let mut cause = None;
    let mut date = None;
    for line in body {
        let Some((label, value)) = split_label(line) else {
            continue;
        };
        match label.as_str() {
            "nome/firma" => members.push(OrganMember {
                name: value,
                ..OrganMember::default()
            }),
            "cargo" => {
                if let Some(m) = members.last_mut() {
                    m.cargo = ne(value);
                }
            }
            "nif/nipc" | "nipc" => {
                if let Some(m) = members.last_mut() {
                    m.nif = ne(digits_only(&value));
                }
            }
            "nacionalidade" => {
                if let Some(m) = members.last_mut() {
                    m.nacionalidade = ne(value);
                }
            }
            "causa" => cause = ne(value),
            l if l.starts_with("data") && date.is_none() => date = normalize_any_date(&value),
            _ => {}
        }
    }
    CessationPayload {
        members,
        cause,
        date,
    }
}

fn parse_amendment(body: &[String]) -> AmendmentPayload {
    let mut a = AmendmentPayload::default();
    let mut i = 0;
    while i < body.len() {
        let line = &body[i];
        let Some((label, value)) = split_label(line) else {
            i += 1;
            continue;
        };
        let l = label.as_str();
        if l.starts_with("data") {
            if a.deliberation_date.is_none() {
                a.deliberation_date = normalize_any_date(&value);
            }
            i += 1;
        } else if l.contains("sede") {
            let mut j = i + 1;
            let addr = consume_address(body, &mut j, value);
            if !addr.is_empty() {
                a.new_sede = Some(addr);
            }
            i = j;
        } else if l.contains("firma") || l.contains("denominacao") {
            a.new_firma = ne(value);
            i += 1;
        } else if l.contains("objec") || l.contains("objet") {
            let mut j = i + 1;
            let obj = consume_objecto(body, &mut j, value);
            if !obj.is_empty() {
                a.new_objecto = Some(obj);
            }
            i = j;
        } else if l.contains("capital") {
            if let Some(m) = parse_money(&value) {
                a.new_capital = Some(m);
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    a
}

// ---- Address / free-text accumulation --------------------------------------------------------

/// Greedily consume an address starting after its label line: the value line 1, then following
/// lines until a boundary — folding a `Distrito/Concelho/Freguesia` line and a postal line into
/// the structured fields. `*i` starts at the first continuation line and ends past the address.
fn consume_address(body: &[String], i: &mut usize, first_value: String) -> crate::model::Address {
    let mut addr = crate::model::Address::default();
    let first = first_value.trim();
    if !first.is_empty() {
        addr.lines.push(first.to_owned());
    }
    while *i < body.len() {
        let line = &body[*i];
        if let Some((d, c, f)) = parse_admin_line(line) {
            addr.distrito = addr.distrito.take().or(d);
            addr.concelho = addr.concelho.take().or(c);
            addr.freguesia = addr.freguesia.take().or(f);
            *i += 1;
            continue;
        }
        if let Some((pc, loc)) = parse_postal_line(line) {
            addr.postal_code = Some(pc);
            addr.locality = addr.locality.take().or(loc);
            *i += 1;
            continue;
        }
        if is_boundary(line) {
            break;
        }
        addr.lines.push(line.trim().to_owned());
        *i += 1;
    }
    addr
}

/// Join the objecto value with following free lines until a boundary (objecto is multi-sentence).
fn consume_objecto(body: &[String], i: &mut usize, first_value: String) -> String {
    let mut parts: Vec<String> = Vec::new();
    let first = first_value.trim();
    if !first.is_empty() {
        parts.push(first.to_owned());
    }
    while *i < body.len() {
        let line = &body[*i];
        if is_boundary(line) {
            break;
        }
        parts.push(line.trim().to_owned());
        *i += 1;
    }
    parts.join(" ")
}

/// Whether a line ends an address/objecto accumulation: a bare or known field label, a section /
/// organ header, or a trailer line.
fn is_boundary(line: &str) -> bool {
    match split_label(line) {
        Some((label, value)) => value.trim().is_empty() || is_known_label(&label),
        None => is_trailer(line),
    }
}

/// Folded field labels that terminate a free-text accumulation.
fn is_known_label(label: &str) -> bool {
    const EXACT: &[&str] = &[
        "firma",
        "nipc",
        "nif/nipc",
        "natureza juridica",
        "forma juridica",
        "sede",
        "objecto",
        "objeto",
        "titular",
        "estado civil",
        "nacionalidade",
        "residencia/sede",
        "residencia",
        "nome/firma",
        "cargo",
        "forma de obrigar",
        "data da deliberacao",
        "causa",
    ];
    EXACT.contains(&label)
        || label.starts_with("capital")
        || label.starts_with("quota")
        || label.starts_with("data de encerramento")
        || (label.contains("orgao") && label.contains("designad"))
        || (label.contains("socios") && label.contains("quota"))
}

/// Whether a line is part of the certidão trailer (stops an accumulation that ran into the tail).
fn is_trailer(line: &str) -> bool {
    let f = fold(line);
    f.contains("conservatoria do registo")
        || f.contains("oficial de registos")
        || f.contains("certidao permanente subscrita")
        || f.contains("fim da certidao")
}

/// The label text as printed (before the colon), original casing/accents kept — organ names.
fn printed_label(line: &str) -> String {
    match line.find(':') {
        Some(idx) => line[..idx].trim().to_owned(),
        None => line.trim().to_owned(),
    }
}

// ---- Signatures ------------------------------------------------------------------------------

/// Collect any `Conservatória … / O(A) Oficial de Registos, <name>` pairs inside this body.
fn collect_signatures(body: &[String]) -> Vec<RegistryOfficialSignature> {
    let mut out = Vec::new();
    for (idx, line) in body.iter().enumerate() {
        if fold(line).contains("conservatoria do registo") {
            let oficial = body
                .iter()
                .skip(idx + 1)
                .take(3)
                .find(|l| fold(l).contains("oficial de registos"))
                .and_then(|l| extract_oficial(l));
            out.push(RegistryOfficialSignature {
                conservatoria: ne(line.trim().to_owned()),
                oficial,
            });
        }
    }
    out
}

// ---- Officer roll-up (feeds the flat RegistryExtract.orgaos) ----------------------------------

/// Roll the structured organ members of one inscrição into the flat `RegistryOfficer` list that
/// the API's `RegistryOfficerView` consumes (constitution/designation → appointments; cessation →
/// a cessation date attached to the matching appointed officer, or a standalone record).
pub(crate) fn rollup_officers(
    event: &RegistryEvent,
    detail: &InscriptionDetail,
    orgaos: &mut Vec<RegistryOfficer>,
) {
    match detail.payload.as_ref() {
        Some(InscriptionPayload::Constitution(c)) => {
            officers_from_organs(&c.orgaos, c.deliberation_date.as_deref(), event, orgaos);
        }
        Some(InscriptionPayload::Designation(d)) => {
            officers_from_organs(&d.orgaos, d.deliberation_date.as_deref(), event, orgaos);
        }
        Some(InscriptionPayload::Cessation(c)) => {
            officers_ceased(&c.members, c.date.as_deref(), event, orgaos);
        }
        _ => {}
    }
}

fn officers_from_organs(
    organs: &[Organ],
    deliberation: Option<&str>,
    event: &RegistryEvent,
    orgaos: &mut Vec<RegistryOfficer>,
) {
    let appointment = deliberation
        .map(str::to_owned)
        .or_else(|| event.date.clone());
    for organ in organs {
        for m in &organ.members {
            orgaos.push(RegistryOfficer {
                name: m.name.clone(),
                role: m.cargo.clone(),
                appointment_date: appointment.clone(),
                cessation_date: None,
                source_event: event.number.clone(),
            });
        }
    }
}

fn officers_ceased(
    members: &[OrganMember],
    date: Option<&str>,
    event: &RegistryEvent,
    orgaos: &mut Vec<RegistryOfficer>,
) {
    let cessation = date.map(str::to_owned).or_else(|| event.date.clone());
    for m in members {
        if let Some(existing) = orgaos
            .iter_mut()
            .find(|o| fold(&o.name) == fold(&m.name) && o.cessation_date.is_none())
        {
            existing.cessation_date = cessation.clone();
        } else {
            orgaos.push(RegistryOfficer {
                name: m.name.clone(),
                role: m.cargo.clone(),
                appointment_date: None,
                cessation_date: cessation.clone(),
                source_event: event.number.clone(),
            });
        }
    }
}

// ---- Small helpers ---------------------------------------------------------------------------

/// A trimmed value as `Some`, or `None` when empty.
fn ne(s: String) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn apresentacao_multi_act_on_the_ap_line() {
        let group = lines(&[
            "Insc. 1 AP. 1/20260501 00:55:25 UTC - CONSTITUIÇÃO DE SOCIEDADE, DESIGNAÇÃO DE MEMBRO(S)",
            "FIRMA: Exemplo, Lda",
        ]);
        let ap = parse_apresentacao(&group[0], &group[1..]).unwrap();
        assert_eq!(ap.number.as_deref(), Some("1"));
        assert_eq!(ap.date.as_deref(), Some("2026-05-01"));
        assert_eq!(ap.time.as_deref(), Some("00:55:25 UTC"));
        assert_eq!(ap.act_kinds.len(), 2);
    }

    #[test]
    fn apresentacao_act_kind_on_the_next_line_fallback() {
        let group = lines(&["Insc. 1 AP. 47/20210310", "CESSAÇÃO DE FUNÇÕES"]);
        let ap = parse_apresentacao(&group[0], &group[1..]).unwrap();
        assert_eq!(ap.number.as_deref(), Some("47"));
        assert_eq!(ap.date.as_deref(), Some("2021-03-10"));
        assert_eq!(ap.time, None);
        assert_eq!(ap.act_kinds, vec!["CESSAÇÃO DE FUNÇÕES".to_owned()]);
    }

    #[test]
    fn classification_precedence_and_unrecognized_none() {
        // Constitution wins even when a designação is co-listed.
        assert!(matches!(
            parse_payload("constituicao de sociedade, designacao de membros", &[]),
            Some(InscriptionPayload::Constitution(_))
        ));
        assert!(matches!(
            parse_payload("cessacao de funcoes", &[]),
            Some(InscriptionPayload::Cessation(_))
        ));
        assert!(matches!(
            parse_payload("designacao de membros", &[]),
            Some(InscriptionPayload::Designation(_))
        ));
        assert!(matches!(
            parse_payload("alteracoes ao contrato de sociedade - sede", &[]),
            Some(InscriptionPayload::ContractAmendment(_))
        ));
        // Deferred kinds (transmissão/dissolução) are recognized only as raw → no payload.
        assert!(parse_payload("transmissao de quotas", &[]).is_none());
        assert!(parse_payload("dissolucao e encerramento da liquidacao", &[]).is_none());
    }
}
