//! Arquivo PDF/A export (t67-E1).
//!
//! `GET /v1/ledger/archive/document` is an on-demand, read-only rendering of the ledger archive. It
//! does not persist a document and does not append a ledger event; it projects the filtered ledger
//! state into the existing `DocumentModel` seam and reuses the frozen PDF/A-2u writer.

use std::collections::HashMap;
use std::str::FromStr;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::Response;
use chancela_authz::{Permission, Scope};
use chancela_core::{Block, BookKind, DocumentModel, KvRow, Run};
use chancela_ledger::{ChainId, ChainStatus, Event, ReanchorRecord};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::documents::PDFA_PROFILE;
use crate::error::ApiError;
use crate::hex::hex;
use crate::ledger_events_page::{LedgerEventsSelectorQuery, select_ledger_events_page};
use crate::ledger_filter::{LedgerEventFilters, filter_summary, normalized_page_limit};

#[derive(Debug, Deserialize)]
pub struct ArchiveDocumentQuery {
    /// Free-text search across event id, seq, kind, scope, actor, justification, chains and hashes.
    pub q: Option<String>,
    /// Canonical chain id: `global`, `application`, `company:{uuid}`, or `book:{uuid}`.
    pub chain: Option<String>,
    /// Existing substring scope filter.
    pub scope: Option<String>,
    /// Repeatable and CSV-compatible event-kind filter.
    #[serde(
        default,
        deserialize_with = "crate::ledger_filter::deserialize_kind_query"
    )]
    pub kind: Vec<String>,
    /// Exact actor filter.
    pub actor: Option<String>,
    /// Inclusive lower timestamp bound: RFC 3339 timestamp or `YYYY-MM-DD`.
    pub from: Option<String>,
    /// Upper timestamp bound: RFC 3339 inclusive, or `YYYY-MM-DD` covering that whole day.
    pub to: Option<String>,
    /// Last-N limit after filters. Omitted uses the bounded archive page default.
    pub limit: Option<usize>,
    /// Export format. `pdfa` is the canonical preserved-evidence rendering; the others are
    /// audit/interchange exports of the same filtered event set.
    pub format: Option<ArchiveExportFormat>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveExportFormat {
    Pdfa,
    Json,
    Txt,
    Csv,
    Html,
}

impl<'de> Deserialize<'de> for ArchiveExportFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "pdf" | "pdfa" | "pdf/a" | "pdf-a" => Ok(Self::Pdfa),
            "json" => Ok(Self::Json),
            "txt" | "text" => Ok(Self::Txt),
            "csv" => Ok(Self::Csv),
            "html" => Ok(Self::Html),
            other => Err(serde::de::Error::custom(format!(
                "invalid archive format {other:?}; expected pdfa, json, txt, csv, or html"
            ))),
        }
    }
}

impl ArchiveExportFormat {
    fn extension(self) -> &'static str {
        match self {
            Self::Pdfa => "pdf",
            Self::Json => "json",
            Self::Txt => "txt",
            Self::Csv => "csv",
            Self::Html => "html",
        }
    }
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

/// `GET /v1/ledger/archive/document` — render the filtered ledger archive as PDF/A-2u bytes.
pub async fn export_archive_document(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(q): Query<ArchiveDocumentQuery>,
) -> Result<Response, ApiError> {
    require_permission(&state, &actor, Permission::LedgerRead, Scope::Global).await?;

    let chain = parse_chain(q.chain.as_deref())?;
    let format = q.format.unwrap_or(ArchiveExportFormat::Pdfa);
    let filters = LedgerEventFilters::from_parts(
        q.q.clone(),
        q.scope.clone(),
        &q.kind,
        q.actor.clone(),
        q.from.as_deref(),
        q.to.as_deref(),
    )?;
    let limit = normalized_page_limit(q.limit);
    let sources = label_sources(&state).await;
    let instance_name = state
        .settings
        .read()
        .await
        .organization
        .name
        .clone()
        .unwrap_or_else(|| "Chancela".to_owned());

    let (status, reanchors) = {
        let ledger = state.ledger.read().await;
        let status = ledger.chain_status(&chain).ok_or(ApiError::NotFound)?;
        (status, ledger.reanchored_segments())
    };
    let selected = select_ledger_events_page(
        &state,
        LedgerEventsSelectorQuery {
            before_seq: None,
            limit,
            chain: Some(chain.clone()),
            filters: &filters,
        },
    )
    .await?;
    let records = selected
        .events
        .iter()
        .map(|event| RenderRecord::from_event(event, &chain))
        .collect::<Vec<_>>();
    let degraded = *state.degraded.read().await;

    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let filter_summary = filter_summary(&chain.canonical(), &filters, Some(limit));
    if format == ArchiveExportFormat::Pdfa {
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
        return build_export_response(PDFA_PROFILE, filename, bytes);
    }

    let filename = format!(
        "arquivo-{}-audit-interchange.{}",
        chain.canonical().replace(':', "-"),
        format.extension()
    );
    let (content_type, bytes) = render_interchange_export(InterchangeInput {
        format,
        chain: &chain,
        status: &status,
        records: &records,
        degraded,
        generated_at: &generated_at,
        filter_summary: &filter_summary,
    })?;
    build_export_response(content_type, filename, bytes)
}

fn build_export_response(
    content_type: impl Into<String>,
    filename: String,
    bytes: Vec<u8>,
) -> Result<Response, ApiError> {
    Response::builder()
        .header(CONTENT_TYPE, content_type.into())
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(bytes))
        .map_err(|e| ApiError::Internal(format!("failed to build archive response: {e}")))
}

struct InterchangeInput<'a> {
    format: ArchiveExportFormat,
    chain: &'a ChainId,
    status: &'a ChainStatus,
    records: &'a [RenderRecord],
    degraded: bool,
    generated_at: &'a str,
    filter_summary: &'a str,
}

fn render_interchange_export(
    input: InterchangeInput<'_>,
) -> Result<(&'static str, Vec<u8>), ApiError> {
    let chain = input.chain.canonical();
    let head = input
        .status
        .head
        .as_ref()
        .map(hex)
        .unwrap_or_else(|| "-".to_owned());
    let export_notice =
        "Audit/interchange export only; PDF/A remains the canonical preserved evidence export.";
    let bytes = match input.format {
        ArchiveExportFormat::Json => serde_json::to_vec_pretty(&json!({
            "export_kind": "audit_interchange",
            "canonical_preserved_evidence": false,
            "canonical_evidence_format": "pdfa",
            "notice": export_notice,
            "format": "json",
            "chain": chain,
            "generated_at": input.generated_at,
            "filters": input.filter_summary,
            "event_count": input.records.len(),
            "chain_length": input.status.length,
            "chain_head": head,
            "chain_verified": input.status.verified,
            "system_degraded": input.degraded,
            "order": "seq_desc",
            "events": input.records,
        }))
        .map_err(|e| ApiError::Internal(format!("JSON archive export failed: {e}")))?,
        ArchiveExportFormat::Txt => render_txt(&input, &head, export_notice).into_bytes(),
        ArchiveExportFormat::Csv => render_csv(&input, export_notice).into_bytes(),
        ArchiveExportFormat::Html => render_html(&input, &head, export_notice).into_bytes(),
        ArchiveExportFormat::Pdfa => unreachable!("PDF/A is rendered by the document path"),
    };
    let content_type = match input.format {
        ArchiveExportFormat::Json => "application/json",
        ArchiveExportFormat::Txt => "text/plain; charset=utf-8",
        ArchiveExportFormat::Csv => "text/csv; charset=utf-8",
        ArchiveExportFormat::Html => "text/html; charset=utf-8",
        ArchiveExportFormat::Pdfa => PDFA_PROFILE,
    };
    Ok((content_type, bytes))
}

fn render_txt(input: &InterchangeInput<'_>, head: &str, notice: &str) -> String {
    let mut out = String::new();
    out.push_str("Arquivo - registo de eventos\n");
    out.push_str(notice);
    out.push('\n');
    out.push_str(&format!("Cadeia: {}\n", input.chain.canonical()));
    out.push_str(&format!("Gerado em: {}\n", input.generated_at));
    out.push_str(&format!("Filtros: {}\n", input.filter_summary));
    out.push_str(&format!("Eventos exportados: {}\n", input.records.len()));
    out.push_str(&format!("Extensao da cadeia: {}\n", input.status.length));
    out.push_str(&format!("Digest de topo: {head}\n"));
    out.push_str(&format!("Estado da cadeia: {}\n", input.status.verified));
    out.push_str(&format!("Modo degradado: {}\n\n", input.degraded));
    for record in input.records {
        out.push_str(&format!(
            "seq={} kind={} timestamp={} actor={} scope={}\n",
            record.seq, record.kind, record.timestamp, record.actor, record.scope
        ));
        out.push_str(&format!("chains={}\n", record.chains.join(",")));
        out.push_str(&format!("payload_digest={}\n", record.payload_digest));
        out.push_str(&format!("prev_hash={}\n", record.chain_prev_hash));
        out.push_str(&format!("hash={}\n\n", record.hash));
    }
    out
}

fn render_csv(input: &InterchangeInput<'_>, notice: &str) -> String {
    let mut out = String::new();
    out.push_str("# ");
    out.push_str(notice);
    out.push('\n');
    out.push_str("seq,chain_seq,kind,scope,actor,timestamp,chains,payload_digest,prev_hash,hash,justification\n");
    for record in input.records {
        let row = [
            record.seq.to_string(),
            record.chain_seq.to_string(),
            record.kind.clone(),
            record.scope.clone(),
            record.actor.clone(),
            record.timestamp.clone(),
            record.chains.join("|"),
            record.payload_digest.clone(),
            record.chain_prev_hash.clone(),
            record.hash.clone(),
            record.justification.clone().unwrap_or_default(),
        ]
        .into_iter()
        .map(csv_escape)
        .collect::<Vec<_>>()
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

fn render_html(input: &InterchangeInput<'_>, head: &str, notice: &str) -> String {
    let mut out = String::new();
    out.push_str("<!doctype html><html lang=\"pt-PT\"><head><meta charset=\"utf-8\"><title>Arquivo - audit interchange</title></head><body>");
    out.push_str("<h1>Arquivo - registo de eventos</h1>");
    out.push_str(&format!("<p>{}</p>", html_escape(notice)));
    out.push_str("<dl>");
    for (key, value) in [
        ("Cadeia", input.chain.canonical()),
        ("Gerado em", input.generated_at.to_owned()),
        ("Filtros", input.filter_summary.to_owned()),
        ("Eventos exportados", input.records.len().to_string()),
        ("Extensao da cadeia", input.status.length.to_string()),
        ("Digest de topo", head.to_owned()),
        ("Estado da cadeia", input.status.verified.to_string()),
        ("Modo degradado", input.degraded.to_string()),
    ] {
        out.push_str(&format!(
            "<dt>{}</dt><dd>{}</dd>",
            html_escape(key),
            html_escape(&value)
        ));
    }
    out.push_str("</dl><table><thead><tr><th>Seq</th><th>Acao</th><th>Ambito</th><th>Autor</th><th>Data</th><th>Hash</th></tr></thead><tbody>");
    for record in input.records {
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            record.seq,
            html_escape(&record.kind),
            html_escape(&record.scope),
            html_escape(&record.actor),
            html_escape(&record.timestamp),
            html_escape(&record.hash)
        ));
    }
    out.push_str("</tbody></table></body></html>");
    out
}

fn csv_escape(value: String) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[derive(Serialize)]
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

    #[tokio::test]
    async fn filtered_events_applies_kind_scope_actor_and_last_limit() {
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

        let filters = LedgerEventFilters::from_parts(
            None,
            Some("book:b1".to_owned()),
            &["document.generated".to_owned(), "act.sealed".to_owned()],
            Some("amelia.marques".to_owned()),
            None,
            None,
        )
        .expect("filters parse");
        let state = AppState::default();
        *state.ledger.write().await = ledger;
        let selected = select_ledger_events_page(
            &state,
            LedgerEventsSelectorQuery {
                before_seq: None,
                limit: 1,
                chain: Some(ChainId::Global),
                filters: &filters,
            },
        )
        .await
        .expect("events selected");

        assert_eq!(selected.events.len(), 1);
        assert_eq!(selected.events[0].kind, "act.sealed");
    }
}
