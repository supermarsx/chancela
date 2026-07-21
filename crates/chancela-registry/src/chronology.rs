//! Normalized chronology / relationship graph over a [`RegistryExtract`] (spec DOC-30/31/32).
//!
//! This is the **explainable** intelligence layer, a stated product differentiator: it interprets
//! the already-parsed certidão event feed (never re-parses HTML) into
//!
//! - **DOC-30** — a normalized, ordered [`Chronology`] of typed [`ChronologyEvent`]s (constitutions,
//!   designations, cessations, capital/seat/object changes, quota transfers, dissolutions, …), each
//!   carrying its **`source_inscription`** so every fact traces back to a numbered registry entry
//!   (DOC-32 provenance);
//! - **DOC-31** — deterministic graph views: **Mermaid** diagram strings plus structured
//!   `nodes`/`edges` data for shareholders, organs, and inter-company relationship evidence.
//!
//! Everything here is a **pure function of the extract** — no clock, no network, no randomness — so
//! the same extract always yields the same chronology and the same Mermaid text (ordering follows
//! the inscrição feed, which the parser already keeps in printed order). The raw
//! [`RegistryEvent::text`] remains the ground truth; this layer is additive and never lossy.

use serde::{Deserialize, Serialize};

use crate::model::{
    AmendmentPayload, CessationPayload, ConstitutionPayload, InscriptionPayload, Organ,
    RegistryEvent, RegistryExtract,
};

/// The normalized kind of a registry act on the timeline (DOC-30). A single inscrição may yield
/// several events (e.g. an `ALTERAÇÕES AO CONTRATO` touching both capital and seat) — one per
/// distinct legal change — so this classifies an *event*, not an inscrição.
///
/// Serialized as the bare serde variant name (`"Constitution"`, `"CapitalChange"`, …), the house
/// convention shared with `CaeRole`/`LegalForm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChronologyKind {
    Constitution,
    Designation,
    Cessation,
    CapitalChange,
    SeatChange,
    ObjectChange,
    QuotaTransfer,
    Dissolution,
    /// Any recognized-but-unmodelled act (kept honest rather than forced into a wrong bucket).
    Other,
}

/// One normalized act on the timeline. Every event MUST carry a non-empty [`source_inscription`]
/// (DOC-32): the registry entry number (`"1"`, `"3 Av. 1"`) it was derived from, so a reader can
/// trace the fact back to the certidão.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChronologyEvent {
    /// ISO `YYYY-MM-DD` best-effort (from the entry, its apresentação, or the act's deliberation
    /// date); `None` when the certidão printed no resolvable date.
    pub date: Option<String>,
    pub kind: ChronologyKind,
    /// Human-readable PT description of what happened.
    pub description: String,
    /// The inscrição/averbamento number this event traces to — never empty (DOC-32 provenance).
    pub source_inscription: String,
    /// Named parties involved (sócios, designated/ceased organ members), in printed order.
    pub actors: Vec<String>,
}

/// A deterministic structured graph bundle mirroring the chronology Mermaid views. It is technical
/// evidence data only: labels come from parsed registry facts, while `kind`/`category` values are
/// stable English machine categories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChronologyGraphBundle {
    pub shareholders: ChronologyGraph,
    pub organs: ChronologyGraph,
    pub relationships: ChronologyGraph,
}

/// A small source-linked graph: stable node/edge ids, source labels, and warnings when the parser
/// has no structured evidence for a richer graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChronologyGraph {
    pub nodes: Vec<ChronologyGraphNode>,
    pub edges: Vec<ChronologyGraphEdge>,
    pub warnings: Vec<String>,
}

/// One graph node. `source_inscription` / `source_date` point to the parsed registry entry when the
/// node comes from inscription evidence; the subject entity node may have no single source marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChronologyGraphNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub category: Option<String>,
    pub source_inscription: Option<String>,
    pub source_date: Option<String>,
}

/// One graph edge, labelled with the parsed fact it represents and linked back to its source entry
/// when available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChronologyGraphEdge {
    pub id: String,
    pub from: String,
    pub to: String,
    pub label: String,
    pub kind: String,
    pub source_inscription: Option<String>,
    pub source_date: Option<String>,
}

/// The normalized, ordered event timeline for an entity (DOC-30). Ordering follows the inscrição
/// feed as printed on the certidão — deterministic, no clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chronology {
    pub events: Vec<ChronologyEvent>,
}

impl Chronology {
    /// Build the normalized chronology from a parsed [`RegistryExtract`]. Pure and deterministic:
    /// events come out in inscrição order, each tagged with its source entry.
    pub fn build(extract: &RegistryExtract) -> Self {
        let mut events = Vec::new();
        for (idx, insc) in extract.inscricoes.iter().enumerate() {
            let source = source_ref(insc, idx);
            let date = event_date(insc);
            events_for_inscription(insc, &source, date, &mut events);
        }
        Chronology { events }
    }

    /// DOC-31 shareholders/quotas diagram: the entity at the centre, each founding sócio linked by
    /// an edge labelled with their quota. Starts with `graph`.
    pub fn shareholders_mermaid(&self, extract: &RegistryExtract) -> String {
        shareholders_mermaid(extract, &self.events)
    }

    /// DOC-31 órgãos-over-time diagram: designations and cessations as a Mermaid `timeline`, keyed
    /// by date. Starts with `timeline`.
    pub fn organs_mermaid(&self, extract: &RegistryExtract) -> String {
        organs_mermaid(extract)
    }

    /// DOC-31 inter-company relationship stub: the entity linked to any party that looks like a
    /// legal person (company/association/foundation). A single-node `graph` when none is detected.
    pub fn relationships_mermaid(&self, extract: &RegistryExtract) -> String {
        relationships_mermaid(extract)
    }

    /// Structured graph data for the same three DOC-31 views. The builders use the same parsed
    /// extract / chronology evidence as the Mermaid helpers and keep empty graphs explicit.
    pub fn graph(&self, extract: &RegistryExtract) -> ChronologyGraphBundle {
        ChronologyGraphBundle {
            shareholders: shareholders_graph(extract, &self.events),
            organs: organs_graph(extract, &self.events),
            relationships: relationships_graph(extract),
        }
    }
}

// --- Event derivation -------------------------------------------------------------------------

/// The provenance reference for an inscrição: its number, else its raw apresentação line, else a
/// positional fallback — guaranteed non-empty so every event can be traced (DOC-32).
fn source_ref(insc: &RegistryEvent, idx: usize) -> String {
    if let Some(n) = insc
        .number
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return n.to_owned();
    }
    if let Some(a) = insc
        .apresentacao
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return a.to_owned();
    }
    format!("#{}", idx + 1)
}

/// Best-effort ISO date for an inscrição: the entry date, else its apresentação date, else the
/// structured payload's deliberation/cessation date.
fn event_date(insc: &RegistryEvent) -> Option<String> {
    if let Some(d) = insc.date.clone() {
        return Some(d);
    }
    if let Some(d) = insc
        .detail
        .as_ref()
        .and_then(|d| d.apresentacao.as_ref().and_then(|a| a.date.clone()))
    {
        return Some(d);
    }
    match insc.detail.as_ref().and_then(|d| d.payload.as_ref()) {
        Some(InscriptionPayload::Constitution(c)) => c.deliberation_date.clone(),
        Some(InscriptionPayload::Designation(d)) => d.deliberation_date.clone(),
        Some(InscriptionPayload::Cessation(c)) => c.date.clone(),
        Some(InscriptionPayload::ContractAmendment(a)) => a.deliberation_date.clone(),
        None => None,
    }
}

/// Push the one-or-more chronology events for a single inscrição.
fn events_for_inscription(
    insc: &RegistryEvent,
    source: &str,
    date: Option<String>,
    out: &mut Vec<ChronologyEvent>,
) {
    match insc.detail.as_ref().and_then(|d| d.payload.as_ref()) {
        Some(InscriptionPayload::Constitution(c)) => {
            out.push(ChronologyEvent {
                date,
                kind: ChronologyKind::Constitution,
                description: constitution_description(c),
                source_inscription: source.to_owned(),
                actors: constitution_actors(c),
            });
        }
        Some(InscriptionPayload::Designation(d)) => {
            out.push(ChronologyEvent {
                date,
                kind: ChronologyKind::Designation,
                description: "Designação de membro(s) de órgão(s) social(ais)".to_owned(),
                source_inscription: source.to_owned(),
                actors: organ_member_names(&d.orgaos),
            });
        }
        Some(InscriptionPayload::Cessation(c)) => {
            out.push(ChronologyEvent {
                date,
                kind: ChronologyKind::Cessation,
                description: cessation_description(c),
                source_inscription: source.to_owned(),
                actors: c.members.iter().map(|m| m.name.clone()).collect(),
            });
        }
        Some(InscriptionPayload::ContractAmendment(a)) => {
            amendment_events(a, source, date, out);
        }
        None => {
            // No structured payload: classify off the printed act-kind label / kind hint. The raw
            // text still carries everything; we surface an honest, provenance-tagged event.
            let (kind, description) = classify_raw(insc);
            out.push(ChronologyEvent {
                date,
                kind,
                description,
                source_inscription: source.to_owned(),
                actors: Vec::new(),
            });
        }
    }
}

fn constitution_description(c: &ConstitutionPayload) -> String {
    match c.firma.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(firma) => format!("Constituição de sociedade — {firma}"),
        None => "Constituição de sociedade".to_owned(),
    }
}

fn constitution_actors(c: &ConstitutionPayload) -> Vec<String> {
    let mut actors: Vec<String> = Vec::new();
    for socio in &c.socios {
        push_unique(&mut actors, socio.titular.name.clone());
    }
    for name in organ_member_names(&c.orgaos) {
        push_unique(&mut actors, name);
    }
    actors
}

fn cessation_description(c: &CessationPayload) -> String {
    match c.cause.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(cause) => format!("Cessação de funções ({cause})"),
        None => "Cessação de funções de membro(s) de órgão(s) social(ais)".to_owned(),
    }
}

/// An `ALTERAÇÕES AO CONTRATO` can touch several things at once — emit one typed event per changed
/// aspect (each sharing the inscrição's provenance), so capital / seat / object changes are
/// individually classifiable. Falls back to a single `Other` when nothing structured was captured.
fn amendment_events(
    a: &AmendmentPayload,
    source: &str,
    date: Option<String>,
    out: &mut Vec<ChronologyEvent>,
) {
    let before = out.len();

    if let Some(m) = a.new_capital.as_ref() {
        out.push(ChronologyEvent {
            date: date.clone(),
            kind: ChronologyKind::CapitalChange,
            description: format!("Alteração do capital social para {}", m.to_display()),
            source_inscription: source.to_owned(),
            actors: Vec::new(),
        });
    }
    if let Some(sede) = a.new_sede.as_ref() {
        out.push(ChronologyEvent {
            date: date.clone(),
            kind: ChronologyKind::SeatChange,
            description: format!("Alteração da sede para {}", sede.to_single_line()),
            source_inscription: source.to_owned(),
            actors: Vec::new(),
        });
    }
    if a.new_objecto.is_some() {
        out.push(ChronologyEvent {
            date: date.clone(),
            kind: ChronologyKind::ObjectChange,
            description: "Alteração do objecto social".to_owned(),
            source_inscription: source.to_owned(),
            actors: Vec::new(),
        });
    }
    if let Some(firma) = a
        .new_firma
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        out.push(ChronologyEvent {
            date: date.clone(),
            kind: ChronologyKind::Other,
            description: format!("Alteração da firma para {firma}"),
            source_inscription: source.to_owned(),
            actors: Vec::new(),
        });
    }

    if out.len() == before {
        out.push(ChronologyEvent {
            date,
            kind: ChronologyKind::Other,
            description: "Alterações ao contrato de sociedade".to_owned(),
            source_inscription: source.to_owned(),
            actors: Vec::new(),
        });
    }
}

/// Classify an inscrição that has no structured payload from its printed act-kind label(s) and
/// kind hint. Order matters — the more specific verbs are tested before the broad ones.
fn classify_raw(insc: &RegistryEvent) -> (ChronologyKind, String) {
    let label = raw_label(insc);
    let folded = fold_upper(&label);

    let kind = if folded.contains("CONSTITUI") {
        ChronologyKind::Constitution
    } else if folded.contains("TRANSMISS")
        || folded.contains("DIVISAO DE QUOTA")
        || folded.contains("UNIFICACAO DE QUOTA")
        || (folded.contains("CESSAO") && folded.contains("QUOTA"))
    {
        ChronologyKind::QuotaTransfer
    } else if folded.contains("DISSOLU")
        || folded.contains("ENCERRAMENTO DA LIQUIDA")
        || folded.contains("LIQUIDACAO")
    {
        ChronologyKind::Dissolution
    } else if folded.contains("CESSACAO") {
        ChronologyKind::Cessation
    } else if folded.contains("DESIGNA") {
        ChronologyKind::Designation
    } else if folded.contains("CAPITAL") {
        ChronologyKind::CapitalChange
    } else if folded.contains("SEDE") {
        ChronologyKind::SeatChange
    } else if folded.contains("OBJECT") || folded.contains("OBJET") {
        ChronologyKind::ObjectChange
    } else {
        ChronologyKind::Other
    };

    // Description: the printed act label, tidied; a generic fallback when nothing was printed.
    let description = if label.trim().is_empty() {
        "Acto registral".to_owned()
    } else {
        tidy(&label)
    };
    (kind, description)
}

/// The best available act-kind label for a raw inscrição: the joined apresentação act kinds, else
/// the entry's `kind_hint`.
fn raw_label(insc: &RegistryEvent) -> String {
    if let Some(ap) = insc.detail.as_ref().and_then(|d| d.apresentacao.as_ref())
        && !ap.act_kinds.is_empty()
    {
        return ap.act_kinds.join(", ");
    }
    match insc.kind_hint.as_deref().map(str::trim) {
        Some(hint) if !hint.is_empty() && !is_address_fragment(hint) => hint.to_owned(),
        _ => String::new(),
    }
}

/// Is this line part of an address rather than an act label?
///
/// `kind_hint` is a *positional* guess — the first body line that does not look like an
/// apresentação — so on a layout whose inscrição body the segmenter has not seen before it can land
/// on an address line instead of the act. That is how a seat's postal line once became the printed
/// description of a registry act. A postal line (`2705 - 839 TERRUGEM SNT`) or a
/// `Distrito: … Concelho: … Freguesia: …` line is never an act, so it is dropped and the event
/// falls back to the generic description rather than asserting an address as the act performed.
fn is_address_fragment(hint: &str) -> bool {
    crate::parse::parse_postal_line(hint).is_some()
        || crate::parse::parse_admin_line(hint).is_some()
}

fn organ_member_names(orgaos: &[Organ]) -> Vec<String> {
    let mut names = Vec::new();
    for organ in orgaos {
        for member in &organ.members {
            push_unique(&mut names, member.name.clone());
        }
    }
    names
}

fn push_unique(v: &mut Vec<String>, s: String) {
    let s = s.trim().to_owned();
    if !s.is_empty() && !v.iter().any(|e| e == &s) {
        v.push(s);
    }
}

// --- Structured graph generation (DOC-31) -----------------------------------------------------

#[derive(Debug, Clone)]
struct SourceMarker {
    inscription: Option<String>,
    date: Option<String>,
}

impl SourceMarker {
    fn has_any(&self) -> bool {
        self.inscription.is_some() || self.date.is_some()
    }
}

fn shareholders_graph(extract: &RegistryExtract, events: &[ChronologyEvent]) -> ChronologyGraph {
    let mut graph = graph_with_entity(extract);

    if let Some((idx, insc, c)) = constitution_entry(extract) {
        let source = source_from_inscription(insc, idx);
        for (i, socio) in c.socios.iter().enumerate() {
            let node_id = format!("shareholder-{i}");
            let label = party_label(&socio.titular.name, &format!("Shareholder {}", i + 1));
            graph.nodes.push(graph_node(
                node_id.clone(),
                label.clone(),
                party_kind(&label),
                Some("shareholder"),
                Some(&source),
            ));
            graph.edges.push(graph_edge(
                format!("shareholding-{i}"),
                "entity",
                &node_id,
                socio.amount.to_display(),
                "shareholding",
                Some(&source),
            ));
        }
        if c.socios.is_empty() {
            graph.warnings.push(
                "Structured constitution evidence contains no shareholder quota entries."
                    .to_owned(),
            );
        }
    } else {
        graph.warnings.push(
            "No structured constitution evidence is available for shareholder graphing.".to_owned(),
        );
    }

    let transfers = events
        .iter()
        .filter(|e| e.kind == ChronologyKind::QuotaTransfer)
        .count();
    if transfers > 0 {
        graph.warnings.push(format!(
            "{transfers} quota transfer event(s) are present but not parsed into ownership edges."
        ));
    }

    graph
}

fn organs_graph(extract: &RegistryExtract, events: &[ChronologyEvent]) -> ChronologyGraph {
    let mut graph = graph_with_entity(extract);

    if extract.orgaos.is_empty() {
        graph
            .warnings
            .push("No structured organ evidence was detected.".to_owned());
        return graph;
    }

    for (i, officer) in extract.orgaos.iter().enumerate() {
        let node_id = format!("officer-{i}");
        let label = party_label(&officer.name, &format!("Officer {}", i + 1));
        let appointment_source = appointment_source_for_officer(officer, events);
        let cessation_source = cessation_source_for_officer(officer, events);
        let node_source = appointment_source
            .as_ref()
            .filter(|s| s.has_any())
            .or_else(|| cessation_source.as_ref().filter(|s| s.has_any()));

        graph.nodes.push(graph_node(
            node_id.clone(),
            label.clone(),
            party_kind(&label),
            Some("officer"),
            node_source,
        ));

        if let Some(source) = appointment_source.as_ref() {
            graph.edges.push(graph_edge(
                format!("organ-designation-{i}"),
                "entity",
                &node_id,
                officer
                    .role
                    .as_deref()
                    .map(str::trim)
                    .filter(|r| !r.is_empty())
                    .unwrap_or("appointment"),
                "organ_designation",
                Some(source),
            ));
        }

        if let Some(source) = cessation_source.as_ref() {
            graph.edges.push(graph_edge(
                format!("organ-cessation-{i}"),
                "entity",
                &node_id,
                "cessation",
                "organ_cessation",
                Some(source),
            ));
        }
    }

    graph
}

fn relationships_graph(extract: &RegistryExtract) -> ChronologyGraph {
    let mut graph = graph_with_entity(extract);
    let mut related_names: Vec<String> = Vec::new();

    if let Some((idx, insc, c)) = constitution_entry(extract) {
        let source = source_from_inscription(insc, idx);
        for socio in &c.socios {
            if looks_like_company(&socio.titular.name) {
                push_relationship(
                    &mut graph,
                    &mut related_names,
                    socio.titular.name.clone(),
                    "corporate_shareholder",
                    "shareholder",
                    &source,
                );
            }
        }
        for organ in &c.orgaos {
            for member in &organ.members {
                if looks_like_company(&member.name) {
                    push_relationship(
                        &mut graph,
                        &mut related_names,
                        member.name.clone(),
                        "corporate_officer",
                        "officer",
                        &source,
                    );
                }
            }
        }
    } else {
        graph.warnings.push(
            "No structured constitution evidence is available for relationship graphing."
                .to_owned(),
        );
    }

    if graph.edges.is_empty() {
        graph.warnings.push(
            "No structured corporate relationship evidence was detected; graph contains only the subject entity."
                .to_owned(),
        );
    }

    graph
}

fn graph_with_entity(extract: &RegistryExtract) -> ChronologyGraph {
    ChronologyGraph {
        nodes: vec![graph_node(
            "entity",
            entity_label(extract),
            "entity",
            Some("subject"),
            None,
        )],
        edges: Vec::new(),
        warnings: Vec::new(),
    }
}

fn graph_node(
    id: impl Into<String>,
    label: impl Into<String>,
    kind: &str,
    category: Option<&str>,
    source: Option<&SourceMarker>,
) -> ChronologyGraphNode {
    ChronologyGraphNode {
        id: id.into(),
        label: tidy(&label.into()),
        kind: kind.to_owned(),
        category: category.map(str::to_owned),
        source_inscription: source.and_then(|s| s.inscription.clone()),
        source_date: source.and_then(|s| s.date.clone()),
    }
}

fn graph_edge(
    id: impl Into<String>,
    from: impl Into<String>,
    to: impl Into<String>,
    label: impl Into<String>,
    kind: &str,
    source: Option<&SourceMarker>,
) -> ChronologyGraphEdge {
    ChronologyGraphEdge {
        id: id.into(),
        from: from.into(),
        to: to.into(),
        label: tidy(&label.into()),
        kind: kind.to_owned(),
        source_inscription: source.and_then(|s| s.inscription.clone()),
        source_date: source.and_then(|s| s.date.clone()),
    }
}

fn constitution_entry(
    extract: &RegistryExtract,
) -> Option<(usize, &RegistryEvent, &ConstitutionPayload)> {
    extract
        .inscricoes
        .iter()
        .enumerate()
        .find_map(
            |(idx, event)| match event.detail.as_ref()?.payload.as_ref()? {
                InscriptionPayload::Constitution(c) => Some((idx, event, c)),
                _ => None,
            },
        )
}

fn source_from_inscription(insc: &RegistryEvent, idx: usize) -> SourceMarker {
    SourceMarker {
        inscription: Some(source_ref(insc, idx)),
        date: event_date(insc),
    }
}

fn source_from_event(event: &ChronologyEvent) -> SourceMarker {
    SourceMarker {
        inscription: non_empty(event.source_inscription.clone()),
        date: event.date.clone().and_then(non_empty),
    }
}

fn source_from_values(inscription: Option<String>, date: Option<String>) -> SourceMarker {
    SourceMarker {
        inscription: inscription.and_then(non_empty),
        date: date.and_then(non_empty),
    }
}

fn appointment_source_for_officer(
    officer: &crate::model::RegistryOfficer,
    events: &[ChronologyEvent],
) -> Option<SourceMarker> {
    event_source_for_actor(events, ChronologyKind::Constitution, &officer.name, None)
        .map(|source| source_with_date(source, officer.appointment_date.as_deref()))
        .or_else(|| {
            event_source_for_actor(
                events,
                ChronologyKind::Designation,
                &officer.name,
                officer.appointment_date.as_deref(),
            )
            .map(|source| source_with_date(source, officer.appointment_date.as_deref()))
        })
        .or_else(|| {
            officer.appointment_date.as_ref().map(|_| {
                source_from_values(
                    officer.source_event.clone(),
                    officer.appointment_date.clone(),
                )
            })
        })
}

fn cessation_source_for_officer(
    officer: &crate::model::RegistryOfficer,
    events: &[ChronologyEvent],
) -> Option<SourceMarker> {
    officer.cessation_date.as_ref()?;
    event_source_for_actor(
        events,
        ChronologyKind::Cessation,
        &officer.name,
        officer.cessation_date.as_deref(),
    )
    .map(|source| source_with_date(source, officer.cessation_date.as_deref()))
    .or_else(|| {
        let fallback_inscription = if officer.appointment_date.is_none() {
            officer.source_event.clone()
        } else {
            None
        };
        Some(source_from_values(
            fallback_inscription,
            officer.cessation_date.clone(),
        ))
    })
}

fn event_source_for_actor(
    events: &[ChronologyEvent],
    kind: ChronologyKind,
    actor: &str,
    date: Option<&str>,
) -> Option<SourceMarker> {
    let mut first = None;
    for event in events.iter().filter(|event| {
        event.kind == kind
            && event
                .actors
                .iter()
                .any(|candidate| same_party(candidate, actor))
    }) {
        let source = source_from_event(event);
        if first.is_none() {
            first = Some(source.clone());
        }
        if date.is_none() || event.date.as_deref() == date {
            return Some(source);
        }
    }
    first
}

fn source_with_date(mut source: SourceMarker, date: Option<&str>) -> SourceMarker {
    if let Some(date) = date.and_then(|d| non_empty(d.to_owned())) {
        source.date = Some(date);
    }
    source
}

fn push_relationship(
    graph: &mut ChronologyGraph,
    related_names: &mut Vec<String>,
    name: String,
    kind: &str,
    label: &str,
    source: &SourceMarker,
) {
    let label_name = party_label(
        &name,
        &format!("Related entity {}", related_names.len() + 1),
    );
    let idx = match related_names
        .iter()
        .position(|existing| same_party(existing, &label_name))
    {
        Some(idx) => idx,
        None => {
            let idx = related_names.len();
            related_names.push(label_name.clone());
            graph.nodes.push(graph_node(
                format!("related-{idx}"),
                label_name,
                "legal_person",
                Some("related_entity"),
                Some(source),
            ));
            idx
        }
    };
    let to = format!("related-{idx}");
    if graph
        .edges
        .iter()
        .any(|edge| edge.to == to && edge.kind == kind)
    {
        return;
    }
    graph.edges.push(graph_edge(
        format!("relationship-{}", graph.edges.len()),
        "entity",
        to,
        label,
        kind,
        Some(source),
    ));
}

fn party_label(name: &str, fallback: &str) -> String {
    let label = tidy(name);
    if label.is_empty() {
        fallback.to_owned()
    } else {
        label
    }
}

fn party_kind(label: &str) -> &'static str {
    if looks_like_company(label) {
        "legal_person"
    } else {
        "person"
    }
}

fn same_party(a: &str, b: &str) -> bool {
    fold_upper(&tidy(a)) == fold_upper(&tidy(b))
}

fn non_empty(s: String) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

// --- Mermaid generation (DOC-31) --------------------------------------------------------------

/// Shareholders/quotas `graph`: the entity node linked to each founding sócio, edge = quota. When
/// the extract carries no constitution/sócios, a single entity node is emitted (still valid). Any
/// later quota transfers (kept raw in v1) are acknowledged as a Mermaid comment so the diagram
/// stays honest about what it does and does not model.
fn shareholders_mermaid(extract: &RegistryExtract, events: &[ChronologyEvent]) -> String {
    let mut out = String::from("graph LR\n");
    let entity_label = entity_label(extract);
    out.push_str(&format!("  entity[\"{}\"]\n", sanitize(&entity_label)));

    if let Some(c) = extract.constitution() {
        for (i, socio) in c.socios.iter().enumerate() {
            let name = if socio.titular.name.trim().is_empty() {
                format!("Sócio {}", i + 1)
            } else {
                socio.titular.name.clone()
            };
            out.push_str(&format!("  s{i}[\"{}\"]\n", sanitize(&name)));
            out.push_str(&format!(
                "  entity -->|\"{}\"| s{i}\n",
                sanitize(&socio.amount.to_display())
            ));
        }
    }

    let transfers = events
        .iter()
        .filter(|e| e.kind == ChronologyKind::QuotaTransfer)
        .count();
    if transfers > 0 {
        out.push_str(&format!(
            "  %% {transfers} transmissão(ões) de quota registada(s) — ver cronologia\n"
        ));
    }
    out
}

/// Órgãos-over-time `timeline`: each designation/cessation from the rolled-up officers, grouped by
/// date (ISO dates sort chronologically; undated entries fall under "Sem data").
fn organs_mermaid(extract: &RegistryExtract) -> String {
    // (date_key, is_undated, line) collected then stably ordered by the ISO date string.
    let mut dated: Vec<(String, String)> = Vec::new();
    let mut undated: Vec<String> = Vec::new();

    for officer in &extract.orgaos {
        let role = officer
            .role
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let appointment = match role {
            Some(r) => format!("Designação — {} ({})", officer.name, r),
            None => format!("Designação — {}", officer.name),
        };
        match officer.appointment_date.clone() {
            Some(d) => dated.push((d, appointment)),
            None => undated.push(appointment),
        }
        if let Some(d) = officer.cessation_date.clone() {
            dated.push((d, format!("Cessação — {}", officer.name)));
        }
    }

    // Deterministic chronological grouping: stable sort by ISO date, then fold same-date entries.
    dated.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::from("timeline\n");
    out.push_str("  title Órgãos sociais\n");

    if dated.is_empty() && undated.is_empty() {
        out.push_str("  Sem registo : Nenhum órgão social registado\n");
        return out;
    }

    let mut i = 0;
    while i < dated.len() {
        let day = &dated[i].0;
        let mut line = format!("  {} : {}", sanitize(day), sanitize(&dated[i].1));
        let mut j = i + 1;
        while j < dated.len() && &dated[j].0 == day {
            line.push_str(&format!(" : {}", sanitize(&dated[j].1)));
            j += 1;
        }
        line.push('\n');
        out.push_str(&line);
        i = j;
    }
    for entry in &undated {
        out.push_str(&format!("  Sem data : {}\n", sanitize(entry)));
    }
    out
}

/// Inter-company relationship stub `graph`: the entity linked to any founding sócio or organ member
/// whose name looks like a legal person (company/association/foundation). Emits a single entity
/// node when no such party is present — an honest empty stub rather than an invented edge.
fn relationships_mermaid(extract: &RegistryExtract) -> String {
    let mut out = String::from("graph LR\n");
    let entity_label = entity_label(extract);
    out.push_str(&format!("  self[\"{}\"]\n", sanitize(&entity_label)));

    let mut related: Vec<(String, String)> = Vec::new(); // (name, relation)
    if let Some(c) = extract.constitution() {
        for socio in &c.socios {
            if looks_like_company(&socio.titular.name) {
                push_related(&mut related, socio.titular.name.clone(), "sócio");
            }
        }
        for organ in &c.orgaos {
            for member in &organ.members {
                if looks_like_company(&member.name) {
                    push_related(&mut related, member.name.clone(), "órgão");
                }
            }
        }
    }

    for (i, (name, relation)) in related.iter().enumerate() {
        out.push_str(&format!("  r{i}[\"{}\"]\n", sanitize(name)));
        out.push_str(&format!("  self ---|\"{}\"| r{i}\n", sanitize(relation)));
    }
    out
}

fn push_related(v: &mut Vec<(String, String)>, name: String, relation: &str) {
    let name = name.trim().to_owned();
    if !name.is_empty() && !v.iter().any(|(n, _)| n == &name) {
        v.push((name, relation.to_owned()));
    }
}

/// A display label for the entity: firma (matrícula block or constitution body), else the NIPC,
/// else a generic placeholder.
fn entity_label(extract: &RegistryExtract) -> String {
    extract
        .effective_firma()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| extract.effective_nipc().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "Entidade".to_owned())
}

/// Heuristic: does this party name denote a legal person (not a natural person)? Matches the common
/// PT corporate/association/foundation suffixes and forms after accent-folding.
fn looks_like_company(name: &str) -> bool {
    let f = fold_upper(name);
    const NEEDLES: [&str; 12] = [
        "LDA",
        "L.DA",
        "S.A",
        "SGPS",
        "UNIPESSOAL",
        "SOCIEDADE",
        "COOPERATIVA",
        "LIMITADA",
        "ASSOCIACAO",
        "FUNDACAO",
        "S. A.",
        ", S A",
    ];
    NEEDLES.iter().any(|n| f.contains(n))
}

// --- Text helpers -----------------------------------------------------------------------------

/// Uppercase + strip common Portuguese diacritics, for accent-insensitive matching. Dependency-free
/// (mirrors the crate's "no extra deps" temperament).
fn fold_upper(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ã' | 'ä' | 'Á' | 'À' | 'Â' | 'Ã' | 'Ä' => 'A',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'E',
            'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'I',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' | 'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'O',
            'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'U',
            'ç' | 'Ç' => 'C',
            other => other.to_ascii_uppercase(),
        })
        .collect()
}

/// Collapse internal whitespace/newlines to single spaces and trim (for a one-line description).
fn tidy(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Make a string safe inside a Mermaid quoted label / edge label: drop the delimiters that would
/// break the syntax (`"`, `|`, brackets) and collapse whitespace.
fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| match c {
            '"' => '\'',
            '|' | '[' | ']' | '{' | '}' | '<' | '>' => ' ',
            '\n' | '\r' | '\t' => ' ',
            other => other,
        })
        .collect();
    tidy(&cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Apresentacao, InscriptionDetail, Money, RegistryProvenance};

    fn blank_provenance() -> RegistryProvenance {
        RegistryProvenance {
            access_code_masked: "****-****-0000".to_owned(),
            retrieved_at: "2026-01-01T00:00:00Z".to_owned(),
            source_url: "mock://x".to_owned(),
            raw_digest: "0".repeat(64),
            conservatoria: None,
            oficial: None,
            subscribed_on: None,
            valid_until: None,
        }
    }

    /// A minimal extract carrying a hand-built inscrição feed (no HTML), for classification tests.
    fn extract_with(events: Vec<RegistryEvent>) -> RegistryExtract {
        RegistryExtract {
            matricula: None,
            nipc: Some("500000000".to_owned()),
            firma: Some("Exemplo, Lda".to_owned()),
            forma_juridica: None,
            legal_form: None,
            sede: None,
            cae: Vec::new(),
            objeto: None,
            capital: None,
            data_constituicao: None,
            orgaos: Vec::new(),
            inscricoes: events,
            anotacoes: Vec::new(),
            provenance: blank_provenance(),
        }
    }

    fn raw_event(number: &str, act_kind: &str, date: Option<&str>) -> RegistryEvent {
        RegistryEvent {
            number: Some(number.to_owned()),
            kind_hint: Some(act_kind.to_owned()),
            apresentacao: None,
            date: date.map(str::to_owned),
            text: format!("Insc. {number} — {act_kind}"),
            detail: Some(InscriptionDetail {
                apresentacao: Some(Apresentacao {
                    number: Some(number.to_owned()),
                    date: date.map(str::to_owned),
                    time: None,
                    act_kinds: vec![act_kind.to_owned()],
                }),
                payload: None,
                signatures: Vec::new(),
            }),
        }
    }

    #[test]
    fn classifies_quota_transfer_and_dissolution_from_raw_labels() {
        let extract = extract_with(vec![
            raw_event("5", "TRANSMISSÃO DE QUOTA(S)", Some("2023-01-10")),
            raw_event(
                "6",
                "DISSOLUÇÃO E ENCERRAMENTO DA LIQUIDAÇÃO",
                Some("2024-02-20"),
            ),
        ]);
        let chrono = Chronology::build(&extract);
        assert_eq!(chrono.events.len(), 2);
        assert_eq!(chrono.events[0].kind, ChronologyKind::QuotaTransfer);
        assert_eq!(chrono.events[0].source_inscription, "5");
        assert_eq!(chrono.events[0].date.as_deref(), Some("2023-01-10"));
        assert_eq!(chrono.events[1].kind, ChronologyKind::Dissolution);
        assert_eq!(chrono.events[1].source_inscription, "6");
    }

    /// An unseen layout can leave `kind_hint` pointing at an address line instead of the act. The
    /// event must stay honest about knowing nothing rather than describing the act as a postal code
    /// — the exact wrong description a real certidão produced before the segmenter was fixed.
    #[test]
    fn an_address_line_is_never_reported_as_the_act() {
        for hint in [
            "2705 - 839 TERRUGEM SNT",
            "1250-096 ALDEIA NOVA XPT",
            "Distrito: Lisboa Concelho: Sintra Freguesia: Terrugem",
        ] {
            let mut event = raw_event("1", hint, Some("2026-05-11"));
            // No apresentação act kinds: the positional `kind_hint` is all the classifier has.
            event.detail = None;
            let chrono = Chronology::build(&extract_with(vec![event]));
            assert_eq!(chrono.events.len(), 1);
            let e = &chrono.events[0];
            assert_eq!(e.kind, ChronologyKind::Other);
            assert_eq!(e.description, "Acto registral", "hint was {hint:?}");
            // Provenance survives — the entry is still traceable (DOC-32).
            assert_eq!(e.source_inscription, "1");
            assert_eq!(e.date.as_deref(), Some("2026-05-11"));
        }
    }

    #[test]
    fn cessao_de_quota_is_a_transfer_not_a_cessation() {
        // "CESSÃO DE QUOTA" (a transfer) must not be mistaken for "CESSAÇÃO DE FUNÇÕES".
        let extract = extract_with(vec![raw_event("2", "CESSÃO DE QUOTA", None)]);
        let chrono = Chronology::build(&extract);
        assert_eq!(chrono.events[0].kind, ChronologyKind::QuotaTransfer);
    }

    #[test]
    fn unknown_act_is_other_but_keeps_provenance_and_label() {
        let extract = extract_with(vec![raw_event("9", "PRESTAÇÃO DE CONTAS", None)]);
        let chrono = Chronology::build(&extract);
        assert_eq!(chrono.events[0].kind, ChronologyKind::Other);
        assert_eq!(chrono.events[0].source_inscription, "9");
        assert_eq!(chrono.events[0].description, "PRESTAÇÃO DE CONTAS");
    }

    #[test]
    fn source_ref_falls_back_when_number_is_missing() {
        let mut e = raw_event("ignored", "CONSTITUIÇÃO DE SOCIEDADE", None);
        e.number = None;
        e.apresentacao = Some("AP. 1/20200101".to_owned());
        let extract = extract_with(vec![e]);
        let chrono = Chronology::build(&extract);
        assert_eq!(chrono.events[0].source_inscription, "AP. 1/20200101");
    }

    #[test]
    fn fold_upper_strips_accents() {
        assert_eq!(fold_upper("Dissolução"), "DISSOLUCAO");
        assert_eq!(fold_upper("Constituição"), "CONSTITUICAO");
    }

    #[test]
    fn looks_like_company_detects_legal_persons() {
        assert!(looks_like_company("Holding Central, Lda"));
        assert!(looks_like_company("Grupo X, S.A."));
        assert!(looks_like_company("Cooperativa Agrícola"));
        assert!(!looks_like_company("Rui Tavares Nogueira"));
    }

    #[test]
    fn sanitize_neutralizes_mermaid_delimiters() {
        assert_eq!(sanitize("A \"quoted\" | piped [x]"), "A 'quoted' piped x");
    }

    #[test]
    fn organs_timeline_is_empty_state_when_no_officers() {
        let extract = extract_with(vec![]);
        let chrono = Chronology::build(&extract);
        let m = chrono.organs_mermaid(&extract);
        assert!(m.starts_with("timeline"));
        assert!(m.contains("Nenhum órgão social registado"));
    }

    #[test]
    fn amendment_with_money_uses_capital_kind() {
        let mut e = raw_event("4", "ALTERAÇÕES AO CONTRATO DE SOCIEDADE - CAPITAL", None);
        e.detail.as_mut().unwrap().payload =
            Some(InscriptionPayload::ContractAmendment(AmendmentPayload {
                new_firma: None,
                new_sede: None,
                new_objecto: None,
                new_capital: Some(Money {
                    amount_text: "50.000,00".to_owned(),
                    currency: Some("Euros".to_owned()),
                }),
                deliberation_date: None,
            }));
        let extract = extract_with(vec![e]);
        let chrono = Chronology::build(&extract);
        assert_eq!(chrono.events.len(), 1);
        assert_eq!(chrono.events[0].kind, ChronologyKind::CapitalChange);
        assert!(chrono.events[0].description.contains("50.000,00 Euros"));
    }
}
