//! Arquivo PDF/A export (t67-E1).
//!
//! `GET /v1/ledger/archive/document` is an on-demand, read-only rendering of the ledger archive. It
//! does not persist a document and does not append a ledger event; it projects the filtered ledger
//! state into the existing `DocumentModel` seam and reuses the frozen PDF/A-2u writer.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::Response;
use chancela_authz::{Permission, Scope};
use chancela_core::{Block, BookKind, DocumentModel, KvRow, Run};
use chancela_ledger::{ChainId, ChainStatus, Event, ReanchorRecord};
use serde::{Deserialize, Deserializer};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime, Time};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::documents::PDFA_PROFILE;
use crate::error::ApiError;
use crate::hex::hex;

#[derive(Debug, Deserialize)]
pub struct ArchiveDocumentQuery {
    /// Canonical chain id: `global`, `application`, `company:{uuid}`, or `book:{uuid}`.
    pub chain: Option<String>,
    /// Existing substring scope filter.
    pub scope: Option<String>,
    /// Repeatable and CSV-compatible event-kind filter.
    #[serde(default, deserialize_with = "deserialize_kind_query")]
    pub kind: Vec<String>,
    /// Exact actor filter.
    pub actor: Option<String>,
    /// Inclusive lower timestamp bound: RFC 3339 timestamp or `YYYY-MM-DD`.
    pub from: Option<String>,
    /// Upper timestamp bound: RFC 3339 inclusive, or `YYYY-MM-DD` covering that whole day.
    pub to: Option<String>,
    /// Last-N limit after filters. Omitted means the whole filtered archive.
    pub limit: Option<usize>,
}

fn deserialize_kind_query<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Ok(match Option::<OneOrMany>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(OneOrMany::One(value)) => vec![value],
        Some(OneOrMany::Many(values)) => values,
    })
}

#[derive(Debug)]
struct ArchiveFilters {
    scope: Option<String>,
    kinds: HashSet<String>,
    actor: Option<String>,
    from: Option<OffsetDateTime>,
    to: Option<UpperBound>,
}

#[derive(Debug)]
enum UpperBound {
    Inclusive(OffsetDateTime),
    Exclusive(OffsetDateTime),
}

impl UpperBound {
    fn contains(&self, timestamp: OffsetDateTime) -> bool {
        match self {
            UpperBound::Inclusive(to) => timestamp <= *to,
            UpperBound::Exclusive(to) => timestamp < *to,
        }
    }
}

impl ArchiveFilters {
    fn from_query(q: &ArchiveDocumentQuery) -> Result<Self, ApiError> {
        Ok(Self {
            scope: q.scope.as_ref().filter(|s| !s.is_empty()).cloned(),
            kinds: parse_kind_filter(&q.kind),
            actor: q.actor.as_ref().filter(|s| !s.is_empty()).cloned(),
            from: q.from.as_deref().map(parse_from_bound).transpose()?,
            to: q.to.as_deref().map(parse_to_bound).transpose()?,
        })
    }

    fn matches(&self, event: &Event) -> bool {
        if let Some(scope) = &self.scope {
            if !event.scope.contains(scope) {
                return false;
            }
        }
        if !self.kinds.is_empty() && !self.kinds.contains(&event.kind) {
            return false;
        }
        if let Some(actor) = &self.actor {
            if &event.actor != actor {
                return false;
            }
        }
        if let Some(from) = self.from {
            if event.timestamp < from {
                return false;
            }
        }
        if let Some(to) = &self.to {
            if !to.contains(event.timestamp) {
                return false;
            }
        }
        true
    }
}

fn parse_kind_filter(raw: &[String]) -> HashSet<String> {
    raw.iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_from_bound(raw: &str) -> Result<OffsetDateTime, ApiError> {
    if let Ok(ts) = OffsetDateTime::parse(raw, &Rfc3339) {
        return Ok(ts);
    }
    parse_date(raw).map(|date| date.with_time(Time::MIDNIGHT).assume_utc())
}

fn parse_to_bound(raw: &str) -> Result<UpperBound, ApiError> {
    if let Ok(ts) = OffsetDateTime::parse(raw, &Rfc3339) {
        return Ok(UpperBound::Inclusive(ts));
    }
    let date = parse_date(raw)?;
    let next = date.next_day().ok_or_else(|| {
        ApiError::Unprocessable("invalid to date: cannot advance past maximum date".to_owned())
    })?;
    Ok(UpperBound::Exclusive(
        next.with_time(Time::MIDNIGHT).assume_utc(),
    ))
}

fn parse_date(raw: &str) -> Result<Date, ApiError> {
    let fmt = format_description!("[year]-[month]-[day]");
    Date::parse(raw, &fmt).map_err(|_| {
        ApiError::Unprocessable(format!(
            "invalid timestamp {raw:?}; expected RFC 3339 or YYYY-MM-DD"
        ))
    })
}

fn parse_chain(raw: Option<&str>) -> Result<ChainId, ApiError> {
    match raw {
        None | Some("") => Ok(ChainId::Global),
        Some(s) => ChainId::from_str(s).map_err(|_| {
            ApiError::Unprocessable(format!(
                "invalid chain {s:?}; expected global, application, company:<id>, or book:<id>"
            ))
        }),
    }
}

fn filtered_events<'a>(
    events: Vec<&'a Event>,
    filters: &ArchiveFilters,
    limit: Option<usize>,
) -> Vec<&'a Event> {
    let mut events: Vec<&Event> = events
        .into_iter()
        .filter(|event| filters.matches(event))
        .collect();
    if let Some(limit) = limit {
        let start = events.len().saturating_sub(limit);
        events.drain(..start);
    }
    events
}

/// `GET /v1/ledger/archive/document` — render the filtered ledger archive as PDF/A-2u bytes.
pub async fn export_archive_document(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(q): Query<ArchiveDocumentQuery>,
) -> Result<Response, ApiError> {
    require_permission(&state, &actor, Permission::LedgerRead, Scope::Global).await?;

    let chain = parse_chain(q.chain.as_deref())?;
    let filters = ArchiveFilters::from_query(&q)?;
    let sources = label_sources(&state).await;
    let instance_name = state
        .settings
        .read()
        .await
        .organization
        .name
        .clone()
        .unwrap_or_else(|| "Chancela".to_owned());

    let (status, records, reanchors) = {
        let ledger = state.ledger.read().await;
        let status = ledger.chain_status(&chain).ok_or(ApiError::NotFound)?;
        let events = filtered_events(ledger.events_in_chain(&chain), &filters, q.limit);
        let records = events
            .into_iter()
            .map(|event| RenderRecord::from_event(event, &chain))
            .collect::<Vec<_>>();
        (status, records, ledger.reanchored_segments())
    };
    let degraded = *state.degraded.read().await;

    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let filter_summary = filter_summary(&chain, &filters, q.limit);
    let model = build_archive_document(ArchiveDocumentInput {
        chain: &chain,
        status: &status,
        records: &records,
        reanchors: &reanchors,
        degraded,
        sources: &sources,
        instance_name: &instance_name,
        generated_at: &generated_at,
        filter_summary: &filter_summary,
    });
    let bytes = chancela_doc::pdfa::write(&model)
        .map_err(|e| ApiError::Internal(format!("PDF/A generation failed: {e}")))?;

    let filename = format!("arquivo-{}.pdf", chain.canonical().replace(':', "-"));
    Response::builder()
        .header(CONTENT_TYPE, PDFA_PROFILE)
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(bytes))
        .map_err(|e| ApiError::Internal(format!("failed to build pdf response: {e}")))
}

struct RenderRecord {
    chain_seq: u64,
    chain_prev_hash: String,
    chains: Vec<String>,
    seq: u64,
    kind: String,
    scope: String,
    actor: String,
    justification: Option<String>,
    timestamp: String,
    payload_digest: String,
    hash: String,
}

impl RenderRecord {
    fn from_event(event: &Event, chain: &ChainId) -> Self {
        let (chain_seq, chain_prev_hash) = chain_link_of(event, chain);
        Self {
            chain_seq,
            chain_prev_hash,
            chains: event_chains(event),
            seq: event.seq,
            kind: event.kind.clone(),
            scope: event.scope.clone(),
            actor: event.actor.clone(),
            justification: event.justification.clone(),
            timestamp: event.timestamp.format(&Rfc3339).unwrap_or_default(),
            payload_digest: hex(&event.payload_digest),
            hash: hex(&event.hash),
        }
    }
}

fn chain_link_of(event: &Event, chain: &ChainId) -> (u64, String) {
    if chain.is_global() {
        return (event.seq, hex(&event.prev_hash));
    }
    match event.links.iter().find(|l| &l.chain == chain) {
        Some(link) => (link.seq, hex(&link.prev_hash)),
        None => (event.seq, hex(&event.prev_hash)),
    }
}

fn event_chains(event: &Event) -> Vec<String> {
    std::iter::once("global".to_owned())
        .chain(event.links.iter().map(|link| link.chain.canonical()))
        .collect()
}

struct ArchiveDocumentInput<'a> {
    chain: &'a ChainId,
    status: &'a ChainStatus,
    records: &'a [RenderRecord],
    reanchors: &'a [ReanchorRecord],
    degraded: bool,
    sources: &'a LabelSources,
    instance_name: &'a str,
    generated_at: &'a str,
    filter_summary: &'a str,
}

fn build_archive_document(input: ArchiveDocumentInput<'_>) -> DocumentModel {
    let label = input.sources.label(input.chain);
    let title = if input.chain.is_global() {
        "Arquivo - registo de eventos".to_owned()
    } else {
        format!("Arquivo - cadeia {label}")
    };
    let head = input
        .status
        .head
        .as_ref()
        .map(hex)
        .unwrap_or_else(|| "-".to_owned());
    let verified = if input.status.verified {
        "Verificada"
    } else {
        "Quebrada"
    };
    let system_mode = if input.degraded {
        "So-leitura (modo degradado)"
    } else {
        "Normal"
    };
    let (entity_name, entity_nipc) = input
        .sources
        .document_entity(input.chain)
        .unwrap_or_else(|| (input.instance_name.to_owned(), None));

    let mut blocks = Vec::with_capacity(input.records.len() * 2 + 8);
    blocks.push(Block::Heading {
        level: 1,
        text: title.clone(),
    });
    blocks.push(Block::KeyValue {
        rows: vec![
            kv("Cadeia", input.chain.canonical()),
            kv("Identificacao", label),
            kv("Gerado em", input.generated_at),
            kv("Filtros", input.filter_summary),
            kv("Eventos exportados", input.records.len().to_string()),
            kv("Extensao da cadeia", input.status.length.to_string()),
            kv("Digest de topo", head),
            kv("Estado da cadeia", verified),
            kv("Modo do sistema", system_mode),
        ],
    });

    if !input.status.verified || input.degraded {
        let detail = input
            .status
            .first_break
            .as_ref()
            .map(|b| format!(" Primeira quebra detetada: {}.", b.message))
            .unwrap_or_default();
        let text = if !input.status.verified {
            format!(
                "Esta cadeia nao verifica: foi detetada uma quebra de integridade.{detail} O \
                 relatorio apresenta o estado observado sem ocultar a quebra."
            )
        } else {
            "O sistema esta em modo so-leitura porque a integridade global esta degradada; este \
             relatorio apresenta o estado observado."
                .to_owned()
        };
        blocks.push(Block::Heading {
            level: 2,
            text: "Aviso de integridade".to_owned(),
        });
        blocks.push(Block::Paragraph {
            runs: vec![Run {
                text,
                bold: true,
                italic: false,
            }],
        });
    }

    append_reanchor_disclosure(&mut blocks, input.reanchors);

    blocks.push(Block::Rule);
    if input.records.is_empty() {
        blocks.push(Block::Paragraph {
            runs: vec![Run {
                text: "Nenhum evento corresponde aos filtros aplicados.".to_owned(),
                bold: false,
                italic: false,
            }],
        });
    } else {
        for record in input.records {
            blocks.push(Block::Heading {
                level: 3,
                text: format!("{} - {}", record.seq, record.kind),
            });
            let mut rows = vec![
                kv("Seq. global", record.seq.to_string()),
                kv("Seq. na cadeia", record.chain_seq.to_string()),
                kv("Acao", &record.kind),
                kv("Cadeias", record.chains.join(", ")),
                kv("Ambito", &record.scope),
                kv("Autor", &record.actor),
                kv("Data", &record.timestamp),
            ];
            if let Some(justification) = &record.justification {
                rows.push(kv("Justificacao", justification));
            }
            rows.push(kv("Digest do conteudo", &record.payload_digest));
            rows.push(kv("Ligacao anterior na cadeia", &record.chain_prev_hash));
            rows.push(kv("Hash do registo", &record.hash));
            blocks.push(Block::KeyValue { rows });
            blocks.push(Block::Rule);
        }
    }

    DocumentModel {
        title,
        entity_name,
        entity_nipc,
        subject: input.filter_summary.to_owned(),
        language: "pt-PT".to_owned(),
        created_at: Some(input.generated_at.to_owned()),
        blocks,
    }
}

fn append_reanchor_disclosure(blocks: &mut Vec<Block>, records: &[ReanchorRecord]) {
    if records.is_empty() {
        return;
    }
    blocks.push(Block::Heading {
        level: 2,
        text: "Re-ancoragens registadas".to_owned(),
    });
    for record in records {
        let affected = record
            .affected
            .iter()
            .map(|s| {
                format!(
                    "{} [{}..{}]",
                    s.chain.canonical(),
                    s.from_chain_seq,
                    s.to_chain_seq
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        blocks.push(Block::KeyValue {
            rows: vec![
                kv("Autor", &record.actor),
                kv("Data", record.at.format(&Rfc3339).unwrap_or_default()),
                kv("Motivo", &record.reason),
                kv("Segmentos afetados", affected),
                kv(
                    "Digest antes da re-ancoragem",
                    hex(&record.pre_reanchor_digest),
                ),
                kv("Novo topo global", hex(&record.new_global_head)),
            ],
        });
    }
}

fn kv(key: impl Into<String>, value: impl Into<String>) -> KvRow {
    KvRow {
        key: key.into(),
        value: value.into(),
    }
}

fn filter_summary(chain: &ChainId, filters: &ArchiveFilters, limit: Option<usize>) -> String {
    let mut parts = vec![format!("cadeia={}", chain.canonical())];
    if let Some(scope) = &filters.scope {
        parts.push(format!("scope contem {scope}"));
    }
    if !filters.kinds.is_empty() {
        let mut kinds: Vec<&str> = filters.kinds.iter().map(String::as_str).collect();
        kinds.sort_unstable();
        parts.push(format!("kind={}", kinds.join(",")));
    }
    if let Some(actor) = &filters.actor {
        parts.push(format!("actor={actor}"));
    }
    if let Some(from) = filters.from {
        parts.push(format!(
            "from={}",
            from.format(&Rfc3339).unwrap_or_default()
        ));
    }
    if let Some(to) = &filters.to {
        let value = match to {
            UpperBound::Inclusive(ts) | UpperBound::Exclusive(ts) => {
                ts.format(&Rfc3339).unwrap_or_default()
            }
        };
        parts.push(format!("to={value}"));
    }
    if let Some(limit) = limit {
        parts.push(format!("limit={limit}"));
    }
    parts.join("; ")
}

fn chain_kind_label(chain: &ChainId) -> &'static str {
    match chain {
        ChainId::Global => "Global",
        ChainId::Application => "Aplicacao",
        ChainId::Company(_) => "Entidade",
        ChainId::Book(_) => "Livro",
    }
}

fn book_kind_label(kind: BookKind) -> &'static str {
    match kind {
        BookKind::AssembleiaGeral => "Livro da assembleia geral",
        BookKind::GerenciaAdministracao => "Livro da gerencia/administracao",
        BookKind::ConselhoFiscal => "Livro do conselho fiscal",
        BookKind::Condominio => "Livro do condominio",
    }
}

fn short_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

struct LabelSources {
    entities: HashMap<String, (String, String)>,
    books: HashMap<String, (String, BookKind)>,
}

impl LabelSources {
    fn label(&self, chain: &ChainId) -> String {
        match chain {
            ChainId::Global => "Registo global".to_owned(),
            ChainId::Application => "Cadeia de auditoria da aplicacao".to_owned(),
            ChainId::Company(id) => match self.entities.get(id) {
                Some((name, _)) => format!("{} - {name}", chain_kind_label(chain)),
                None => format!("Entidade {}", short_id(id)),
            },
            ChainId::Book(id) => match self.books.get(id) {
                Some((entity_id, kind)) => match self.entities.get(entity_id) {
                    Some((name, _)) => format!("{} - {name}", book_kind_label(*kind)),
                    None => book_kind_label(*kind).to_owned(),
                },
                None => format!("Livro {}", short_id(id)),
            },
        }
    }

    fn document_entity(&self, chain: &ChainId) -> Option<(String, Option<String>)> {
        match chain {
            ChainId::Company(id) => self
                .entities
                .get(id)
                .map(|(name, nipc)| (name.clone(), Some(nipc.clone()))),
            ChainId::Book(id) => self.books.get(id).and_then(|(entity_id, _)| {
                self.entities
                    .get(entity_id)
                    .map(|(name, nipc)| (name.clone(), Some(nipc.clone())))
            }),
            ChainId::Global | ChainId::Application => None,
        }
    }
}

async fn label_sources(state: &AppState) -> LabelSources {
    let entities = {
        let entities = state.entities.read().await;
        entities
            .values()
            .map(|e| (e.id.0.to_string(), (e.name.clone(), e.nipc.to_string())))
            .collect()
    };
    let books = {
        let books = state.books.read().await;
        books
            .values()
            .map(|b| (b.id.0.to_string(), (b.entity_id.0.to_string(), b.kind)))
            .collect()
    };
    LabelSources { entities, books }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_ledger::Ledger;

    #[test]
    fn filtered_events_applies_kind_scope_actor_and_last_limit() {
        let mut ledger = Ledger::new();
        ledger.append("amelia.marques", "settings", "settings.updated", None, b"1");
        ledger.append("bruno.dias", "entity:e1/book:b1", "book.opened", None, b"2");
        ledger.append(
            "amelia.marques",
            "entity:e1/book:b1",
            "document.generated",
            None,
            b"3",
        );
        ledger.append(
            "amelia.marques",
            "entity:e1/book:b1",
            "act.sealed",
            None,
            b"4",
        );

        let filters = ArchiveFilters {
            scope: Some("book:b1".to_owned()),
            kinds: HashSet::from(["document.generated".to_owned(), "act.sealed".to_owned()]),
            actor: Some("amelia.marques".to_owned()),
            from: None,
            to: None,
        };
        let selected = filtered_events(ledger.events().iter().collect(), &filters, Some(1));

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].kind, "act.sealed");
    }

    #[test]
    fn csv_and_repeatable_kind_filters_normalize_to_one_set() {
        let raw = vec![
            "book.opened, document.generated".to_owned(),
            "act.sealed".to_owned(),
            " ".to_owned(),
        ];
        let kinds = parse_kind_filter(&raw);
        assert_eq!(kinds.len(), 3);
        assert!(kinds.contains("book.opened"));
        assert!(kinds.contains("document.generated"));
        assert!(kinds.contains("act.sealed"));
    }
}
