//! Arquivo ledger export (t67-E1).
//!
//! `GET /v1/ledger/archive/document` is an on-demand, read-only rendering of the ledger archive. It
//! does not persist a document and does not append a ledger event; PDF/A projects the filtered
//! ledger state into the existing `DocumentModel` seam and reuses the frozen PDF/A-2u writer.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::Response;
use chancela_authz::{Permission, Scope};
use chancela_core::{Block, BookKind, DocumentModel, KvRow, Run};
use chancela_ledger::{ChainId, ChainStatus, Event, ReanchorRecord};
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::documents::PDFA_PROFILE;
use crate::error::ApiError;
use crate::hex::hex;
use crate::ledger_events_page::{LedgerEventsSelectorQuery, select_ledger_events_page};
use crate::ledger_filter::{
    LedgerEventFilters, LedgerOrder, MAX_LEDGER_PAGE_LIMIT, filter_summary, normalized_page_limit,
};

const ALL_FILTERED_EXPORT_BATCH_LIMIT: usize = MAX_LEDGER_PAGE_LIMIT;
const ALL_FILTERED_PDFA_RECORD_CAP: usize = 1_000;

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
    /// Not supported for archive documents; use `export_scope=all_filtered` for bulk export.
    pub before_seq: Option<u64>,
    /// Last-N limit after filters. Omitted uses the bounded archive page default.
    pub limit: Option<usize>,
    /// Newest-first order contract for the bounded export page. Defaults to `desc`.
    pub order: Option<String>,
    /// Export scope. Omitted preserves the historical bounded first-page export.
    pub export_scope: Option<ArchiveDocumentScope>,
    /// Export format. `pdfa` is the canonical preserved-evidence rendering; the others are
    /// audit/interchange exports of the same filtered event set.
    pub format: Option<ArchiveExportFormat>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveDocumentScope {
    BoundedFirstPage,
    AllFiltered,
}

impl<'de> Deserialize<'de> for ArchiveDocumentScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "current_page" | "current-page" | "bounded_first_page" | "bounded-first-page"
            | "first_page" | "first-page" => Ok(Self::BoundedFirstPage),
            "all_filtered" | "all-filtered" | "all" => Ok(Self::AllFiltered),
            other => Err(serde::de::Error::custom(format!(
                "invalid archive export_scope {other:?}; expected current_page or all_filtered"
            ))),
        }
    }
}

impl ArchiveDocumentScope {
    fn code(self) -> &'static str {
        match self {
            Self::BoundedFirstPage => "bounded_first_page",
            Self::AllFiltered => "all_filtered",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::BoundedFirstPage => {
                "Exports only the first filtered newest-first page after limit normalization, not every matching ledger event."
            }
            Self::AllFiltered => {
                "Exports every matching filtered ledger event server-side in newest-first order, without requiring the browser page to load all records."
            }
        }
    }
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

    fn content_type(self) -> &'static str {
        match self {
            Self::Pdfa => PDFA_PROFILE,
            Self::Json => "application/json",
            Self::Txt => "text/plain; charset=utf-8",
            Self::Csv => "text/csv; charset=utf-8",
            Self::Html => "text/html; charset=utf-8",
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

/// `GET /v1/ledger/archive/document` — render a filtered newest-first archive export.
///
/// By default the export is intentionally bounded by the same normalized page limit as
/// `/v1/ledger/events/page`. Callers may opt into `export_scope=all_filtered` to have the server
/// walk the same filtered newest-first result set in chunks without using `before_seq` as an
/// external bulk-export cursor.
pub async fn export_archive_document(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(q): Query<ArchiveDocumentQuery>,
) -> Result<Response, ApiError> {
    require_permission(&state, &actor, Permission::LedgerRead, Scope::Global).await?;

    let chain = parse_chain(q.chain.as_deref())?;
    let format = q.format.unwrap_or(ArchiveExportFormat::Pdfa);
    let order = LedgerOrder::from_query(q.order.as_deref())?;
    let export_scope = q
        .export_scope
        .unwrap_or(ArchiveDocumentScope::BoundedFirstPage);
    if q.before_seq.is_some() {
        return Err(ApiError::Unprocessable(
            "ledger archive document exports do not accept before_seq; omit it for the first filtered page or set export_scope=all_filtered for a server-side all-filtered export"
                .to_owned(),
        ));
    }
    let filters = LedgerEventFilters::from_parts(
        q.q.clone(),
        q.scope.clone(),
        &q.kind,
        q.actor.clone(),
        q.from.as_deref(),
        q.to.as_deref(),
    )?;
    let limit = normalized_page_limit(q.limit);
    let (status, reanchors) = {
        let ledger = state.ledger.read().await;
        let status = ledger.chain_status(&chain).ok_or(ApiError::NotFound)?;
        (status, ledger.reanchored_segments())
    };
    let degraded = *state.degraded.read().await;
    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let filter_summary = filter_summary(
        &chain.canonical(),
        &filters,
        (export_scope == ArchiveDocumentScope::BoundedFirstPage).then_some(limit),
        Some(order),
    );
    let filename_scope = if export_scope == ArchiveDocumentScope::AllFiltered {
        "-all-filtered"
    } else {
        ""
    };

    if export_scope == ArchiveDocumentScope::AllFiltered && format != ArchiveExportFormat::Pdfa {
        let first_page = select_ledger_events_page(
            &state,
            LedgerEventsSelectorQuery {
                before_seq: None,
                limit: ALL_FILTERED_EXPORT_BATCH_LIMIT,
                order,
                chain: Some(chain.clone()),
                filters: &filters,
            },
        )
        .await?;
        let filename = format!(
            "arquivo-{}{}-audit-interchange.{}",
            chain.canonical().replace(':', "-"),
            filename_scope,
            format.extension()
        );
        let page_meta = ArchivePageMeta {
            scope: export_scope,
            order,
            page_limit: None,
            internal_batch_limit: Some(first_page.limit),
            has_more: false,
            next_cursor: None,
            record_cap: None,
            streamed: true,
        };
        let body = stream_all_filtered_interchange_export(
            state,
            filters,
            first_page,
            StreamInterchangeInput {
                format,
                chain,
                status,
                page_meta,
                degraded,
                generated_at,
                filter_summary,
            },
        );
        return build_streaming_export_response(format.content_type(), filename, body);
    }

    let selected = match export_scope {
        ArchiveDocumentScope::BoundedFirstPage => {
            select_ledger_events_page(
                &state,
                LedgerEventsSelectorQuery {
                    before_seq: None,
                    limit,
                    order,
                    chain: Some(chain.clone()),
                    filters: &filters,
                },
            )
            .await?
        }
        ArchiveDocumentScope::AllFiltered => {
            select_all_filtered_ledger_events(
                &state,
                &chain,
                order,
                &filters,
                Some(ALL_FILTERED_PDFA_RECORD_CAP),
            )
            .await?
        }
    };
    let records = selected
        .events
        .iter()
        .map(|event| RenderRecord::from_event(event, &chain))
        .collect::<Vec<_>>();
    let page_meta = ArchivePageMeta {
        scope: export_scope,
        order,
        page_limit: (export_scope == ArchiveDocumentScope::BoundedFirstPage)
            .then_some(selected.limit),
        internal_batch_limit: (export_scope == ArchiveDocumentScope::AllFiltered)
            .then_some(selected.limit),
        has_more: selected.has_more,
        next_cursor: selected.next_cursor,
        record_cap: (export_scope == ArchiveDocumentScope::AllFiltered
            && format == ArchiveExportFormat::Pdfa)
            .then_some(ALL_FILTERED_PDFA_RECORD_CAP),
        streamed: false,
    };
    if format == ArchiveExportFormat::Pdfa {
        let sources = label_sources(&state).await;
        let instance_name = state
            .settings
            .read()
            .await
            .organization
            .name
            .clone()
            .unwrap_or_else(|| "Chancela".to_owned());
        let model = build_archive_document(ArchiveDocumentInput {
            chain: &chain,
            status: &status,
            records: &records,
            page_meta,
            reanchors: &reanchors,
            degraded,
            sources: &sources,
            instance_name: &instance_name,
            generated_at: &generated_at,
            filter_summary: &filter_summary,
        });
        let bytes = chancela_doc::pdfa::write(&model)
            .map_err(|e| ApiError::Internal(format!("PDF/A generation failed: {e}")))?;

        let filename = format!(
            "arquivo-{}{}.pdf",
            chain.canonical().replace(':', "-"),
            filename_scope
        );
        return build_export_response(PDFA_PROFILE, filename, bytes);
    }

    let filename = format!(
        "arquivo-{}{}-audit-interchange.{}",
        chain.canonical().replace(':', "-"),
        filename_scope,
        format.extension()
    );
    let (content_type, bytes) = render_interchange_export(InterchangeInput {
        format,
        chain: &chain,
        status: &status,
        records: &records,
        page_meta,
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

fn build_streaming_export_response(
    content_type: impl Into<String>,
    filename: String,
    body: Body,
) -> Result<Response, ApiError> {
    Response::builder()
        .header(CONTENT_TYPE, content_type.into())
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(body)
        .map_err(|e| ApiError::Internal(format!("failed to build streaming archive response: {e}")))
}

async fn select_all_filtered_ledger_events(
    state: &AppState,
    chain: &ChainId,
    order: LedgerOrder,
    filters: &LedgerEventFilters,
    record_cap: Option<usize>,
) -> Result<crate::ledger_events_page::LedgerEventsSelection, ApiError> {
    let mut events = Vec::new();
    let mut before_seq = None;

    loop {
        let page = select_ledger_events_page(
            state,
            LedgerEventsSelectorQuery {
                before_seq,
                limit: ALL_FILTERED_EXPORT_BATCH_LIMIT,
                order,
                chain: Some(chain.clone()),
                filters,
            },
        )
        .await?;
        if let Some(cap) = record_cap {
            if events.len().saturating_add(page.events.len()) > cap {
                return Err(ApiError::Unprocessable(format!(
                    "all_filtered PDF/A ledger archive exports are capped at {cap} records to bound memory use; narrow the filters or export JSON, CSV, TXT, or HTML for a streamed all-filtered audit/interchange file. No records were truncated."
                )));
            }
        }
        events.extend(page.events);
        if !page.has_more {
            break;
        }
        let Some(next_cursor) = page.next_cursor else {
            return Err(ApiError::Internal(
                "ledger all-filtered archive export pager reported more records without a cursor"
                    .to_owned(),
            ));
        };
        before_seq = Some(next_cursor);
    }

    Ok(crate::ledger_events_page::LedgerEventsSelection {
        events,
        next_cursor: None,
        has_more: false,
        limit: ALL_FILTERED_EXPORT_BATCH_LIMIT,
    })
}

type ArchiveChunk = Result<Bytes, io::Error>;
type ArchiveChunkSender = mpsc::Sender<ArchiveChunk>;

struct ArchiveBodyStream {
    receiver: mpsc::Receiver<ArchiveChunk>,
}

impl Stream for ArchiveBodyStream {
    type Item = ArchiveChunk;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

struct StreamInterchangeInput {
    format: ArchiveExportFormat,
    chain: ChainId,
    status: ChainStatus,
    page_meta: ArchivePageMeta,
    degraded: bool,
    generated_at: String,
    filter_summary: String,
}

fn stream_all_filtered_interchange_export(
    state: AppState,
    filters: LedgerEventFilters,
    first_page: crate::ledger_events_page::LedgerEventsSelection,
    input: StreamInterchangeInput,
) -> Body {
    let (tx, receiver) = mpsc::channel(8);
    tokio::spawn(async move {
        if let Err(err) =
            write_all_filtered_interchange_stream(&tx, state, filters, first_page, input).await
        {
            let _ = tx.send(Err(err)).await;
        }
    });
    Body::from_stream(ArchiveBodyStream { receiver })
}

async fn write_all_filtered_interchange_stream(
    tx: &ArchiveChunkSender,
    state: AppState,
    filters: LedgerEventFilters,
    first_page: crate::ledger_events_page::LedgerEventsSelection,
    input: StreamInterchangeInput,
) -> io::Result<()> {
    let head = input
        .status
        .head
        .as_ref()
        .map(hex)
        .unwrap_or_else(|| "-".to_owned());
    let export_notice =
        "Audit/interchange export only; PDF/A remains the canonical preserved evidence export.";
    match input.format {
        ArchiveExportFormat::Json => {
            send_chunk(tx, render_json_stream_header(&input, &head, export_notice)?).await?
        }
        ArchiveExportFormat::Txt => {
            send_chunk(tx, render_txt_stream_header(&input, &head, export_notice)).await?
        }
        ArchiveExportFormat::Csv => {
            send_chunk(tx, render_csv_stream_header(&input, export_notice)).await?
        }
        ArchiveExportFormat::Html => {
            send_chunk(tx, render_html_stream_header(&input, &head, export_notice)).await?
        }
        ArchiveExportFormat::Pdfa => unreachable!("PDF/A is rendered by the document path"),
    }

    let mut page = first_page;
    let mut event_count = 0_usize;
    loop {
        let has_more = page.has_more;
        let next_cursor = page.next_cursor;
        for event in page.events {
            let record = RenderRecord::from_event(&event, &input.chain);
            match input.format {
                ArchiveExportFormat::Json => {
                    if event_count > 0 {
                        send_chunk(tx, ",\n").await?;
                    }
                    send_chunk(tx, render_json_record(&record)?).await?;
                }
                ArchiveExportFormat::Txt => send_chunk(tx, render_txt_record(&record)).await?,
                ArchiveExportFormat::Csv => send_chunk(tx, render_csv_record(&record)).await?,
                ArchiveExportFormat::Html => send_chunk(tx, render_html_record(&record)).await?,
                ArchiveExportFormat::Pdfa => unreachable!("PDF/A is rendered by the document path"),
            }
            event_count += 1;
        }
        if !has_more {
            break;
        }
        let Some(cursor) = next_cursor else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "ledger all-filtered archive export pager reported more records without a cursor",
            ));
        };
        page = select_ledger_events_page(
            &state,
            LedgerEventsSelectorQuery {
                before_seq: Some(cursor),
                limit: ALL_FILTERED_EXPORT_BATCH_LIMIT,
                order: input.page_meta.order,
                chain: Some(input.chain.clone()),
                filters: &filters,
            },
        )
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")))?;
    }

    match input.format {
        ArchiveExportFormat::Json => {
            send_chunk(tx, render_json_stream_footer(event_count)?).await?
        }
        ArchiveExportFormat::Txt => {
            send_chunk(
                tx,
                format!("\nTotal de eventos exportados: {event_count}\n"),
            )
            .await?
        }
        ArchiveExportFormat::Csv => {
            send_chunk(tx, format!("# event_count={event_count}\n")).await?
        }
        ArchiveExportFormat::Html => {
            send_chunk(
                tx,
                format!("</tbody></table><p>Eventos exportados: {event_count}</p></body></html>"),
            )
            .await?
        }
        ArchiveExportFormat::Pdfa => unreachable!("PDF/A is rendered by the document path"),
    }
    Ok(())
}

async fn send_chunk(tx: &ArchiveChunkSender, chunk: impl Into<Bytes>) -> io::Result<()> {
    tx.send(Ok(chunk.into())).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "archive export client disconnected",
        )
    })
}

fn json_value(value: impl Serialize) -> io::Result<String> {
    serde_json::to_string(&value).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("JSON archive export failed: {e}"),
        )
    })
}

fn render_json_stream_header(
    input: &StreamInterchangeInput,
    head: &str,
    notice: &str,
) -> io::Result<String> {
    Ok(format!(
        concat!(
            "{{\n",
            "  \"export_kind\": \"audit_interchange\",\n",
            "  \"canonical_preserved_evidence\": false,\n",
            "  \"canonical_evidence_format\": \"pdfa\",\n",
            "  \"notice\": {},\n",
            "  \"format\": \"json\",\n",
            "  \"chain\": {},\n",
            "  \"generated_at\": {},\n",
            "  \"filters\": {},\n",
            "  \"export_scope\": {},\n",
            "  \"export_scope_description\": {},\n",
            "  \"page_limit\": null,\n",
            "  \"internal_batch_limit\": {},\n",
            "  \"record_cap\": null,\n",
            "  \"streamed\": true,\n",
            "  \"streaming_mode\": \"streamed\",\n",
            "  \"has_more\": false,\n",
            "  \"next_cursor\": null,\n",
            "  \"chain_length\": {},\n",
            "  \"chain_head\": {},\n",
            "  \"chain_verified\": {},\n",
            "  \"system_degraded\": {},\n",
            "  \"order\": {},\n",
            "  \"event_order\": {},\n",
            "  \"events\": [\n"
        ),
        json_value(notice)?,
        json_value(input.chain.canonical())?,
        json_value(&input.generated_at)?,
        json_value(&input.filter_summary)?,
        json_value(input.page_meta.scope_code())?,
        json_value(input.page_meta.scope_description())?,
        input
            .page_meta
            .internal_batch_limit
            .map(|limit| limit.to_string())
            .unwrap_or_else(|| "null".to_owned()),
        input.status.length,
        json_value(head)?,
        input.status.verified,
        input.degraded,
        json_value(input.page_meta.order.as_query_value())?,
        json_value(input.page_meta.order.event_order_label())?
    ))
}

fn render_json_record(record: &RenderRecord) -> io::Result<String> {
    Ok(format!("    {}", json_value(record)?))
}

fn render_json_stream_footer(event_count: usize) -> io::Result<String> {
    Ok(format!("\n  ],\n  \"event_count\": {event_count}\n}}\n"))
}

fn render_txt_stream_header(input: &StreamInterchangeInput, head: &str, notice: &str) -> String {
    let mut out = String::new();
    out.push_str("Arquivo - registo de eventos\n");
    out.push_str(notice);
    out.push('\n');
    out.push_str(&format!("Cadeia: {}\n", input.chain.canonical()));
    out.push_str(&format!("Gerado em: {}\n", input.generated_at));
    out.push_str(&format!("Filtros: {}\n", input.filter_summary));
    out.push_str(&format!(
        "Ambito da exportacao: {} - {}\n",
        input.page_meta.scope_code(),
        input.page_meta.scope_description()
    ));
    out.push_str("Limite da pagina: sem limite de pagina\n");
    out.push_str(&format!(
        "Lote interno da exportacao: {}\n",
        input.page_meta.internal_batch_limit_label()
    ));
    out.push_str("Limite de registos: sem limite de registos\n");
    out.push_str("Modo de geracao: streamed\n");
    out.push_str(&format!(
        "Ordem: {}\n",
        input.page_meta.order.display_label()
    ));
    out.push_str("Ha mais eventos: false\n");
    out.push_str("Cursor seguinte: -\n");
    out.push_str("Eventos exportados: calculado no fim do fluxo\n");
    out.push_str(&format!("Extensao da cadeia: {}\n", input.status.length));
    out.push_str(&format!("Digest de topo: {head}\n"));
    out.push_str(&format!("Estado da cadeia: {}\n", input.status.verified));
    out.push_str(&format!("Modo degradado: {}\n\n", input.degraded));
    out
}

fn render_txt_record(record: &RenderRecord) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "seq={} kind={} timestamp={} actor={} scope={}\n",
        record.seq, record.kind, record.timestamp, record.actor, record.scope
    ));
    out.push_str(&format!("chains={}\n", record.chains.join(",")));
    out.push_str(&format!("payload_digest={}\n", record.payload_digest));
    out.push_str(&format!("prev_hash={}\n", record.chain_prev_hash));
    out.push_str(&format!("hash={}\n\n", record.hash));
    out
}

fn render_csv_stream_header(input: &StreamInterchangeInput, notice: &str) -> String {
    let mut out = String::new();
    out.push_str("# ");
    out.push_str(notice);
    out.push('\n');
    out.push_str(&format!(
        "# export_scope={}\n",
        input.page_meta.scope_code()
    ));
    out.push_str("# page_limit=sem limite de pagina\n");
    out.push_str(&format!(
        "# internal_batch_limit={}\n",
        input.page_meta.internal_batch_limit_label()
    ));
    out.push_str("# record_cap=sem limite de registos\n");
    out.push_str("# streaming_mode=streamed\n");
    out.push_str(&format!(
        "# order={}\n",
        input.page_meta.order.as_query_value()
    ));
    out.push_str("# has_more=false\n");
    out.push_str("# next_cursor=-\n");
    out.push_str("seq,chain_seq,kind,scope,actor,timestamp,chains,payload_digest,prev_hash,hash,justification\n");
    out
}

fn render_csv_record(record: &RenderRecord) -> String {
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
    format!("{row}\n")
}

fn render_html_stream_header(input: &StreamInterchangeInput, head: &str, notice: &str) -> String {
    let mut out = String::new();
    out.push_str("<!doctype html><html lang=\"pt-PT\"><head><meta charset=\"utf-8\"><title>Arquivo - audit interchange</title></head><body>");
    out.push_str("<h1>Arquivo - registo de eventos</h1>");
    out.push_str(&format!("<p>{}</p>", html_escape(notice)));
    out.push_str("<dl>");
    for (key, value) in [
        ("Cadeia", input.chain.canonical()),
        ("Gerado em", input.generated_at.clone()),
        ("Filtros", input.filter_summary.clone()),
        (
            "Ambito da exportacao",
            format!(
                "{} - {}",
                input.page_meta.scope_code(),
                input.page_meta.scope_description()
            ),
        ),
        ("Limite da pagina", "sem limite de pagina".to_owned()),
        (
            "Lote interno da exportacao",
            input.page_meta.internal_batch_limit_label(),
        ),
        ("Limite de registos", "sem limite de registos".to_owned()),
        ("Modo de geracao", "streamed".to_owned()),
        ("Ordem", input.page_meta.order.display_label().to_owned()),
        ("Ha mais eventos", "false".to_owned()),
        ("Cursor seguinte", "-".to_owned()),
        ("Eventos exportados", "calculado no fim do fluxo".to_owned()),
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
    out
}

fn render_html_record(record: &RenderRecord) -> String {
    format!(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
        record.seq,
        html_escape(&record.kind),
        html_escape(&record.scope),
        html_escape(&record.actor),
        html_escape(&record.timestamp),
        html_escape(&record.hash)
    )
}

struct InterchangeInput<'a> {
    format: ArchiveExportFormat,
    chain: &'a ChainId,
    status: &'a ChainStatus,
    records: &'a [RenderRecord],
    page_meta: ArchivePageMeta,
    degraded: bool,
    generated_at: &'a str,
    filter_summary: &'a str,
}

#[derive(Clone, Copy)]
struct ArchivePageMeta {
    scope: ArchiveDocumentScope,
    order: LedgerOrder,
    page_limit: Option<usize>,
    internal_batch_limit: Option<usize>,
    has_more: bool,
    next_cursor: Option<u64>,
    record_cap: Option<usize>,
    streamed: bool,
}

impl ArchivePageMeta {
    fn scope_code(self) -> &'static str {
        self.scope.code()
    }

    fn scope_description(self) -> &'static str {
        self.scope.description()
    }

    fn next_cursor_label(self) -> String {
        self.next_cursor
            .map(|cursor| cursor.to_string())
            .unwrap_or_else(|| "-".to_owned())
    }

    fn page_limit_label(self) -> String {
        self.page_limit
            .map(|limit| limit.to_string())
            .unwrap_or_else(|| "sem limite de pagina".to_owned())
    }

    fn internal_batch_limit_label(self) -> String {
        self.internal_batch_limit
            .map(|limit| limit.to_string())
            .unwrap_or_else(|| "-".to_owned())
    }

    fn record_cap_label(self) -> String {
        self.record_cap
            .map(|limit| limit.to_string())
            .unwrap_or_else(|| "sem limite de registos".to_owned())
    }

    fn streaming_label(self) -> &'static str {
        if self.streamed {
            "streamed"
        } else {
            "buffered"
        }
    }
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
            "export_scope": input.page_meta.scope_code(),
            "export_scope_description": input.page_meta.scope_description(),
            "page_limit": input.page_meta.page_limit,
            "internal_batch_limit": input.page_meta.internal_batch_limit,
            "record_cap": input.page_meta.record_cap,
            "streamed": input.page_meta.streamed,
            "streaming_mode": input.page_meta.streaming_label(),
            "has_more": input.page_meta.has_more,
            "next_cursor": input.page_meta.next_cursor,
            "event_count": input.records.len(),
            "chain_length": input.status.length,
            "chain_head": head,
            "chain_verified": input.status.verified,
            "system_degraded": input.degraded,
            "order": input.page_meta.order.as_query_value(),
            "event_order": input.page_meta.order.event_order_label(),
            "events": input.records,
        }))
        .map_err(|e| ApiError::Internal(format!("JSON archive export failed: {e}")))?,
        ArchiveExportFormat::Txt => render_txt(&input, &head, export_notice).into_bytes(),
        ArchiveExportFormat::Csv => render_csv(&input, export_notice).into_bytes(),
        ArchiveExportFormat::Html => render_html(&input, &head, export_notice).into_bytes(),
        ArchiveExportFormat::Pdfa => unreachable!("PDF/A is rendered by the document path"),
    };
    Ok((input.format.content_type(), bytes))
}

fn render_txt(input: &InterchangeInput<'_>, head: &str, notice: &str) -> String {
    let mut out = String::new();
    out.push_str("Arquivo - registo de eventos\n");
    out.push_str(notice);
    out.push('\n');
    out.push_str(&format!("Cadeia: {}\n", input.chain.canonical()));
    out.push_str(&format!("Gerado em: {}\n", input.generated_at));
    out.push_str(&format!("Filtros: {}\n", input.filter_summary));
    out.push_str(&format!(
        "Ambito da exportacao: {} - {}\n",
        input.page_meta.scope_code(),
        input.page_meta.scope_description()
    ));
    out.push_str(&format!(
        "Limite da pagina: {}\n",
        input.page_meta.page_limit_label()
    ));
    out.push_str(&format!(
        "Lote interno da exportacao: {}\n",
        input.page_meta.internal_batch_limit_label()
    ));
    out.push_str(&format!(
        "Limite de registos: {}\n",
        input.page_meta.record_cap_label()
    ));
    out.push_str(&format!(
        "Modo de geracao: {}\n",
        input.page_meta.streaming_label()
    ));
    out.push_str(&format!(
        "Ordem: {}\n",
        input.page_meta.order.display_label()
    ));
    out.push_str(&format!("Ha mais eventos: {}\n", input.page_meta.has_more));
    out.push_str(&format!(
        "Cursor seguinte: {}\n",
        input.page_meta.next_cursor_label()
    ));
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
    out.push_str(&format!(
        "# export_scope={}\n",
        input.page_meta.scope_code()
    ));
    out.push_str(&format!(
        "# page_limit={}\n",
        input.page_meta.page_limit_label()
    ));
    out.push_str(&format!(
        "# internal_batch_limit={}\n",
        input.page_meta.internal_batch_limit_label()
    ));
    out.push_str(&format!(
        "# record_cap={}\n",
        input.page_meta.record_cap_label()
    ));
    out.push_str(&format!(
        "# streaming_mode={}\n",
        input.page_meta.streaming_label()
    ));
    out.push_str(&format!(
        "# order={}\n",
        input.page_meta.order.as_query_value()
    ));
    out.push_str(&format!("# has_more={}\n", input.page_meta.has_more));
    out.push_str(&format!(
        "# next_cursor={}\n",
        input.page_meta.next_cursor_label()
    ));
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
        (
            "Ambito da exportacao",
            format!(
                "{} - {}",
                input.page_meta.scope_code(),
                input.page_meta.scope_description()
            ),
        ),
        ("Limite da pagina", input.page_meta.page_limit_label()),
        (
            "Lote interno da exportacao",
            input.page_meta.internal_batch_limit_label(),
        ),
        ("Limite de registos", input.page_meta.record_cap_label()),
        (
            "Modo de geracao",
            input.page_meta.streaming_label().to_owned(),
        ),
        ("Ordem", input.page_meta.order.display_label().to_owned()),
        ("Ha mais eventos", input.page_meta.has_more.to_string()),
        ("Cursor seguinte", input.page_meta.next_cursor_label()),
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
    page_meta: ArchivePageMeta,
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
            kv("Ambito da exportacao", input.page_meta.scope_code()),
            kv(
                "Descricao da exportacao",
                input.page_meta.scope_description(),
            ),
            kv("Limite da pagina", input.page_meta.page_limit_label()),
            kv(
                "Lote interno da exportacao",
                input.page_meta.internal_batch_limit_label(),
            ),
            kv("Limite de registos", input.page_meta.record_cap_label()),
            kv("Modo de geracao", input.page_meta.streaming_label()),
            kv("Ordem", input.page_meta.order.display_label()),
            kv("Ha mais eventos", input.page_meta.has_more.to_string()),
            kv("Cursor seguinte", input.page_meta.next_cursor_label()),
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
                order: LedgerOrder::Desc,
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
