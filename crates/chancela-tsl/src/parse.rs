//! ETSI TS 119 612 Trusted List parsing into a trust-service-provider / trust-service model.
//!
//! The parser is a deliberately small, defensive event-driven reader over `quick-xml`: it
//! extracts only the elements `chancela-tsl` needs to answer the qualified-status query
//! (SIG-10..13) and tolerates the many optional elements a real list carries (risk #7 in
//! `.orchestration/plans/t4.md`). Namespaces are handled by matching on *local* names, so a
//! list that prefixes the default namespace parses identically to one that does not.

use time::OffsetDateTime;

use crate::error::TslError;

// ---- ETSI TS 119 612 well-known URIs (SIG-10..13) --------------------------------------------

/// `ServiceTypeIdentifier` for a CA issuing **qualified certificates** — the service kind that
/// makes an issuer a QTSP for qualified e-signatures/e-seals.
pub const SVCTYPE_CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";

/// `ServiceStatus` — the service is currently granted/qualified.
pub const STATUS_GRANTED: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";

/// `ServiceStatus` — the service is withdrawn/no longer qualified.
pub const STATUS_WITHDRAWN: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";

/// `AdditionalServiceInformation` URI marking a service as usable **for e-signatures**.
pub const FOR_ESIGNATURES: &str =
    "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures";

/// `AdditionalServiceInformation` URI marking a service as usable **for e-seals**.
pub const FOR_ESEALS: &str = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals";

/// `AdditionalServiceInformation` URI marking a service as usable **for web-site authentication**.
pub const FOR_WEB_AUTH: &str =
    "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication";

// ---- Model -----------------------------------------------------------------------------------

/// The current status of a trust service, as resolved from the list's `ServiceStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceStatus {
    /// `Svcstatus/granted` — currently granted/qualified.
    Granted,
    /// `Svcstatus/withdrawn` — withdrawn/no longer qualified.
    Withdrawn,
    /// A revoked status URI (for example `supervisionRevoked` / `accreditationRevoked`), kept
    /// verbatim because ETSI status vocabularies have several revoked-like forms.
    Revoked(String),
    /// Any other (historical or national) status URI, kept verbatim for inspection.
    Other(String),
}

impl ServiceStatus {
    fn from_uri(uri: &str) -> Self {
        match uri {
            STATUS_GRANTED => ServiceStatus::Granted,
            STATUS_WITHDRAWN => ServiceStatus::Withdrawn,
            other if other.to_ascii_lowercase().contains("revoked") => {
                ServiceStatus::Revoked(other.to_owned())
            }
            other => ServiceStatus::Other(other.to_owned()),
        }
    }
}

/// A text value with its optional `xml:lang` language tag preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalizedText {
    /// The `xml:lang` / `lang` attribute, if present.
    pub lang: Option<String>,
    /// The element text.
    pub value: String,
}

/// One digital identity of a trust service (`ServiceDigitalIdentity/DigitalId`). A service may
/// carry several — a full certificate, a subject name, and/or a subject-key-identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigitalIdentity {
    /// A full X.509 certificate, DER-decoded from the `X509Certificate` base64.
    Certificate(Vec<u8>),
    /// An X.509 subject distinguished name (`X509SubjectName`).
    SubjectName(String),
    /// A subject-key-identifier, decoded from the `X509SKI` base64 (raw key-id bytes).
    SubjectKeyId(Vec<u8>),
}

/// One historical service-information entry from `ServiceHistory/ServiceHistoryInstance`.
///
/// Current trust decisions deliberately ignore history, but retaining it lets catalog tooling
/// explain withdrawn/revoked predecessors and makes search hits less surprising.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceHistoryEntry {
    /// Historical `ServiceTypeIdentifier` URI.
    pub service_type: String,
    /// Preferred historical service name (English when available).
    pub name: String,
    /// Every historical `ServiceName/Name` value, including duplicates and language variants.
    pub names: Vec<LocalizedText>,
    /// Historical service status.
    pub status: ServiceStatus,
    /// Parsed historical `StatusStartingTime`, if parseable.
    pub status_starting_time: Option<OffsetDateTime>,
    /// Raw historical `StatusStartingTime`, retained when the date is malformed.
    pub status_starting_time_raw: Option<String>,
    /// Historical digital identities.
    pub digital_identities: Vec<DigitalIdentity>,
    /// Historical `AdditionalServiceInformation` URIs.
    pub additional_service_info: Vec<String>,
    /// Historical `ServiceSupplyPoint` values.
    pub service_supply_points: Vec<String>,
}

/// A single trust service offered by a provider (a `TSPService`'s current `ServiceInformation`).
///
/// The current service information is what the qualified-status query is defined over. Historical
/// service information is retained in [`Self::history`] for diagnostics/search only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustService {
    /// `ServiceTypeIdentifier` URI (e.g. [`SVCTYPE_CA_QC`]).
    pub service_type: String,
    /// Human-readable service name (English preferred).
    pub name: String,
    /// Every `ServiceName/Name` value, including duplicates and language variants.
    pub names: Vec<LocalizedText>,
    /// Current status.
    pub status: ServiceStatus,
    /// When the current status took effect (`StatusStartingTime`), if parseable.
    pub status_starting_time: Option<OffsetDateTime>,
    /// Raw `StatusStartingTime`, retained when the date is malformed.
    pub status_starting_time_raw: Option<String>,
    /// The service's digital identities (certs / subject names / SKIs).
    pub digital_identities: Vec<DigitalIdentity>,
    /// `AdditionalServiceInformation` URIs (used to tell e-signatures from e-seals/web-auth).
    pub additional_service_info: Vec<String>,
    /// `ServiceSupplyPoint` endpoint values, if the TSL publishes them.
    pub service_supply_points: Vec<String>,
    /// Historical service-information entries. These never affect current qualified status.
    pub history: Vec<ServiceHistoryEntry>,
}

impl TrustService {
    /// Whether this service is a CA issuing qualified certificates ([`SVCTYPE_CA_QC`]).
    pub fn is_ca_qc(&self) -> bool {
        self.service_type == SVCTYPE_CA_QC
    }

    /// Whether the current status is `granted`.
    pub fn is_granted(&self) -> bool {
        self.status == ServiceStatus::Granted
    }

    /// Whether the current status is effective at `now` (its `StatusStartingTime` is at or
    /// before `now`). A service with no parseable starting time is treated as effective.
    pub fn is_effective_at(&self, now: OffsetDateTime) -> bool {
        self.status_starting_time.is_none_or(|start| start <= now)
    }

    /// Whether this service is usable for **e-signatures**. A service is for e-signatures when it
    /// carries the [`FOR_ESIGNATURES`] marker, or when it carries none of the
    /// signature/seal/web-auth markers at all (legacy/ambiguous lists, where a CA/QC defaults to
    /// signatures). A service that is marked *only* for e-seals or web-auth is not.
    pub fn qualifies_for_esig(&self) -> bool {
        let has = |uri: &str| self.additional_service_info.iter().any(|u| u == uri);
        if has(FOR_ESIGNATURES) {
            return true;
        }
        !has(FOR_ESEALS) && !has(FOR_WEB_AUTH)
    }
}

/// A trust-service provider (`TrustServiceProvider`) and its services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustServiceProvider {
    /// Provider name (English preferred).
    pub name: String,
    /// Every `TSPName/Name` value, including language variants.
    pub names: Vec<LocalizedText>,
    /// Provider trade names / aliases, in document order.
    pub trade_names: Vec<String>,
    /// Provider trade names / aliases with language tags preserved.
    pub localized_trade_names: Vec<LocalizedText>,
    /// Provider information URIs.
    pub information_uris: Vec<String>,
    /// The provider's trust services.
    pub services: Vec<TrustService>,
}

/// A parsed Trusted List (`TrustServiceStatusList`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedList {
    /// `SchemeOperatorName` (English preferred).
    pub scheme_operator_name: String,
    /// Every `SchemeOperatorName/Name` value, including language variants.
    pub scheme_operator_names: Vec<LocalizedText>,
    /// `SchemeName` (English preferred).
    pub scheme_name: String,
    /// Every `SchemeName/Name` value, including language variants.
    pub scheme_names: Vec<LocalizedText>,
    /// `SchemeTerritory` (e.g. `PT`).
    pub scheme_territory: String,
    /// `TSLSequenceNumber`, if present.
    pub sequence_number: Option<u32>,
    /// `ListIssueDateTime`, if parseable.
    pub issue_date_time: Option<OffsetDateTime>,
    /// `NextUpdate/dateTime` — the validity window used for cache staleness, if parseable.
    pub next_update: Option<OffsetDateTime>,
    /// The list's trust-service providers.
    pub providers: Vec<TrustServiceProvider>,
}

impl TrustedList {
    /// Iterate every trust service across all providers.
    pub fn services(&self) -> impl Iterator<Item = &TrustService> {
        self.providers.iter().flat_map(|p| p.services.iter())
    }
}

// ---- Parsing ---------------------------------------------------------------------------------

/// Parse an ETSI TS 119 612 Trusted List from XML bytes.
///
/// This does **not** validate the list's XML-DSig signature; call
/// [`crate::source::validate_tsl_signature`] separately when the parsed result is used for trust
/// decisions. The parser only extracts structure, statuses, identities, history and catalog
/// metadata.
pub fn parse_tsl(xml: &[u8]) -> Result<TrustedList, TslError> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut saw_root = false;

    let mut list = TrustedList {
        scheme_operator_name: String::new(),
        scheme_operator_names: Vec::new(),
        scheme_name: String::new(),
        scheme_names: Vec::new(),
        scheme_territory: String::new(),
        sequence_number: None,
        issue_date_time: None,
        next_update: None,
        providers: Vec::new(),
    };

    // In-flight builders.
    let mut cur_tsp: Option<TrustServiceProvider> = None;
    let mut cur_service: Option<TrustService> = None;
    let mut cur_history: Option<ServiceHistoryEntry> = None;
    // xml:lang of the Name element currently open, to prefer English names.
    let mut cur_name_lang: Option<String> = None;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let name = local_name(e.name().as_ref());
                match name.as_str() {
                    "TrustServiceStatusList" => saw_root = true,
                    "TrustServiceProvider" if !in_history(&stack) => {
                        cur_tsp = Some(TrustServiceProvider {
                            name: String::new(),
                            names: Vec::new(),
                            trade_names: Vec::new(),
                            localized_trade_names: Vec::new(),
                            information_uris: Vec::new(),
                            services: Vec::new(),
                        });
                    }
                    "TSPService" if !in_history(&stack) => {
                        cur_service = Some(empty_trust_service());
                    }
                    "ServiceHistoryInstance" if cur_service.is_some() => {
                        cur_history = Some(empty_history_entry());
                    }
                    "Name" => cur_name_lang = xml_lang(&e)?,
                    _ => {}
                }
                stack.push(name);
            }
            Event::Text(e) => {
                let text = e.decode().map_err(|_| TslError::Utf8)?.trim().to_owned();
                if !text.is_empty() {
                    handle_text(
                        &stack,
                        &text,
                        cur_name_lang.as_deref(),
                        &mut list,
                        cur_tsp.as_mut(),
                        cur_service.as_mut(),
                        cur_history.as_mut(),
                    )?;
                }
            }
            Event::End(e) => {
                let name = local_name(e.name().as_ref());
                stack.pop();
                match name.as_str() {
                    "ServiceHistoryInstance" => {
                        if let (Some(history), Some(service)) =
                            (cur_history.take(), cur_service.as_mut())
                        {
                            service.history.push(history);
                        }
                    }
                    "TSPService" if !in_history(&stack) => {
                        if let (Some(svc), Some(tsp)) = (cur_service.take(), cur_tsp.as_mut()) {
                            tsp.services.push(svc);
                        }
                    }
                    "TrustServiceProvider" if !in_history(&stack) => {
                        if let Some(tsp) = cur_tsp.take() {
                            list.providers.push(tsp);
                        }
                    }
                    "Name" => cur_name_lang = None,
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    if !saw_root {
        return Err(TslError::Structure(
            "missing root <TrustServiceStatusList> element".to_owned(),
        ));
    }
    Ok(list)
}

fn empty_trust_service() -> TrustService {
    TrustService {
        service_type: String::new(),
        name: String::new(),
        names: Vec::new(),
        status: ServiceStatus::Other(String::new()),
        status_starting_time: None,
        status_starting_time_raw: None,
        digital_identities: Vec::new(),
        additional_service_info: Vec::new(),
        service_supply_points: Vec::new(),
        history: Vec::new(),
    }
}

fn empty_history_entry() -> ServiceHistoryEntry {
    ServiceHistoryEntry {
        service_type: String::new(),
        name: String::new(),
        names: Vec::new(),
        status: ServiceStatus::Other(String::new()),
        status_starting_time: None,
        status_starting_time_raw: None,
        digital_identities: Vec::new(),
        additional_service_info: Vec::new(),
        service_supply_points: Vec::new(),
    }
}

/// Dispatch a text node to the right model field based on the element stack.
fn handle_text(
    stack: &[String],
    text: &str,
    name_lang: Option<&str>,
    list: &mut TrustedList,
    tsp: Option<&mut TrustServiceProvider>,
    service: Option<&mut TrustService>,
    history: Option<&mut ServiceHistoryEntry>,
) -> Result<(), TslError> {
    let top = stack.last().map(String::as_str).unwrap_or("");
    // Current trust decisions ignore history, but parser/search tooling keeps it structured.
    if in_history_instance(stack) {
        if let Some(history) = history {
            handle_history_text(stack, text, name_lang, history)?;
        }
        return Ok(());
    }

    match top {
        "Name" if under(stack, "SchemeOperatorName") => {
            set_preferred_name(&mut list.scheme_operator_name, text, name_lang);
            push_localized_text(&mut list.scheme_operator_names, text, name_lang);
        }
        "Name" if under(stack, "SchemeName") => {
            set_preferred_name(&mut list.scheme_name, text, name_lang);
            push_localized_text(&mut list.scheme_names, text, name_lang);
        }
        "SchemeTerritory" if under(stack, "SchemeInformation") => {
            list.scheme_territory = text.to_owned();
        }
        "TSLSequenceNumber" if under(stack, "SchemeInformation") => {
            list.sequence_number = text.parse().ok();
        }
        "ListIssueDateTime" if under(stack, "SchemeInformation") => {
            list.issue_date_time = parse_datetime(text);
        }
        "dateTime" if under(stack, "NextUpdate") => {
            list.next_update = parse_datetime(text);
        }
        "Name" if under(stack, "TSPName") => {
            if let Some(tsp) = tsp {
                set_preferred_name(&mut tsp.name, text, name_lang);
                push_localized_text(&mut tsp.names, text, name_lang);
            }
        }
        "Name" if under(stack, "TSPTradeName") => {
            if let Some(tsp) = tsp {
                push_localized_text(&mut tsp.localized_trade_names, text, name_lang);
                if !tsp.trade_names.iter().any(|name| name == text) {
                    tsp.trade_names.push(text.to_owned());
                }
            }
        }
        "URI" if under(stack, "TSPInformationURI") => {
            if let Some(tsp) = tsp {
                if !tsp.information_uris.iter().any(|uri| uri == text) {
                    tsp.information_uris.push(text.to_owned());
                }
            }
        }
        "ServiceTypeIdentifier" => {
            if let Some(svc) = service {
                svc.service_type = text.to_owned();
            }
        }
        "Name" if under(stack, "ServiceName") => {
            if let Some(svc) = service {
                set_preferred_name(&mut svc.name, text, name_lang);
                push_localized_text(&mut svc.names, text, name_lang);
            }
        }
        "ServiceStatus" => {
            if let Some(svc) = service {
                svc.status = ServiceStatus::from_uri(text);
            }
        }
        "StatusStartingTime" => {
            if let Some(svc) = service {
                svc.status_starting_time_raw = Some(text.to_owned());
                svc.status_starting_time = parse_datetime(text);
            }
        }
        "X509Certificate" if under(stack, "DigitalId") => {
            if let Some(svc) = service {
                let der = decode_base64(text)?;
                svc.digital_identities
                    .push(DigitalIdentity::Certificate(der));
            }
        }
        "X509SubjectName" if under(stack, "DigitalId") => {
            if let Some(svc) = service {
                svc.digital_identities
                    .push(DigitalIdentity::SubjectName(text.to_owned()));
            }
        }
        "X509SKI" if under(stack, "DigitalId") => {
            if let Some(svc) = service {
                let ski = decode_base64(text)?;
                svc.digital_identities
                    .push(DigitalIdentity::SubjectKeyId(ski));
            }
        }
        "URI" if under(stack, "AdditionalServiceInformation") => {
            if let Some(svc) = service {
                svc.additional_service_info.push(text.to_owned());
            }
        }
        "ServiceSupplyPoint" if under(stack, "ServiceSupplyPoints") => {
            if let Some(svc) = service {
                push_unique_string(&mut svc.service_supply_points, text);
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_history_text(
    stack: &[String],
    text: &str,
    name_lang: Option<&str>,
    history: &mut ServiceHistoryEntry,
) -> Result<(), TslError> {
    let top = stack.last().map(String::as_str).unwrap_or("");
    match top {
        "ServiceTypeIdentifier" => {
            history.service_type = text.to_owned();
        }
        "Name" if under(stack, "ServiceName") => {
            set_preferred_name(&mut history.name, text, name_lang);
            push_localized_text(&mut history.names, text, name_lang);
        }
        "ServiceStatus" => {
            history.status = ServiceStatus::from_uri(text);
        }
        "StatusStartingTime" => {
            history.status_starting_time_raw = Some(text.to_owned());
            history.status_starting_time = parse_datetime(text);
        }
        "X509Certificate" if under(stack, "DigitalId") => {
            history
                .digital_identities
                .push(DigitalIdentity::Certificate(decode_base64(text)?));
        }
        "X509SubjectName" if under(stack, "DigitalId") => {
            history
                .digital_identities
                .push(DigitalIdentity::SubjectName(text.to_owned()));
        }
        "X509SKI" if under(stack, "DigitalId") => {
            history
                .digital_identities
                .push(DigitalIdentity::SubjectKeyId(decode_base64(text)?));
        }
        "URI" if under(stack, "AdditionalServiceInformation") => {
            history.additional_service_info.push(text.to_owned());
        }
        "ServiceSupplyPoint" if under(stack, "ServiceSupplyPoints") => {
            push_unique_string(&mut history.service_supply_points, text);
        }
        _ => {}
    }
    Ok(())
}

/// Take a name if we have none yet, or if this one is the English (`en`) rendering — so the
/// English name wins regardless of element order.
fn set_preferred_name(slot: &mut String, text: &str, lang: Option<&str>) {
    let is_en = lang.is_some_and(|l| l.eq_ignore_ascii_case("en"));
    if slot.is_empty() || is_en {
        *slot = text.to_owned();
    }
}

fn push_localized_text(slot: &mut Vec<LocalizedText>, text: &str, lang: Option<&str>) {
    slot.push(LocalizedText {
        lang: lang.map(str::to_owned),
        value: text.to_owned(),
    });
}

fn push_unique_string(slot: &mut Vec<String>, text: &str) {
    if !slot.iter().any(|value| value == text) {
        slot.push(text.to_owned());
    }
}

/// True when the element stack is inside a `ServiceHistory` subtree.
fn in_history(stack: &[String]) -> bool {
    stack.iter().any(|s| s == "ServiceHistory")
}

fn in_history_instance(stack: &[String]) -> bool {
    stack.iter().any(|s| s == "ServiceHistoryInstance")
}

/// True when `ancestor` appears anywhere in the (non-top) element stack.
fn under(stack: &[String], ancestor: &str) -> bool {
    let end = stack.len().saturating_sub(1);
    stack[..end].iter().any(|s| s == ancestor)
}

/// Strip any namespace prefix, returning the local element name as an owned string.
fn local_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    match s.rsplit_once(':') {
        Some((_, local)) => local.to_owned(),
        None => s.into_owned(),
    }
}

/// Read the `xml:lang` (or `lang`) attribute of an element start, if present. Language tags are
/// ASCII, so the raw attribute bytes are decoded directly.
fn xml_lang(e: &quick_xml::events::BytesStart<'_>) -> Result<Option<String>, TslError> {
    for attr in e.attributes() {
        let attr = attr?;
        if local_name(attr.key.as_ref()) == "lang" {
            return Ok(Some(String::from_utf8_lossy(&attr.value).into_owned()));
        }
    }
    Ok(None)
}

/// Parse an xsd:dateTime / RFC 3339 timestamp; returns `None` on any parse failure so that a
/// malformed optional date never fails the whole list (defensive parsing, risk #7).
fn parse_datetime(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text.trim(), &time::format_description::well_known::Rfc3339).ok()
}

/// Decode standard-alphabet base64 (RFC 4648), tolerating embedded ASCII whitespace/newlines as
/// real Trusted Lists wrap long `X509Certificate` values. Implemented locally to avoid adding a
/// base64 dependency to this crate's manifest (owned by t4-e1).
pub(crate) fn decode_base64(input: &str) -> Result<Vec<u8>, TslError> {
    fn sextet(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    for &c in input.as_bytes() {
        match c {
            b'=' => break,
            _ if c.is_ascii_whitespace() => continue,
            _ => {
                let v = sextet(c).ok_or_else(|| {
                    TslError::Base64(format!("invalid character {:?}", c as char))
                })?;
                acc = (acc << 6) | u32::from(v);
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((acc >> bits) as u8);
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_base64_padding_and_whitespace() {
        assert_eq!(decode_base64("").unwrap(), b"");
        assert_eq!(decode_base64("Zg==").unwrap(), b"f");
        assert_eq!(decode_base64("Zm8=").unwrap(), b"fo");
        assert_eq!(decode_base64("Zm9v").unwrap(), b"foo");
        // Embedded newlines/spaces (as real lists wrap long certificates) are tolerated.
        assert_eq!(decode_base64("Zm9v\n  YmFy").unwrap(), b"foobar");
    }

    #[test]
    fn decode_base64_rejects_invalid_character() {
        assert!(matches!(decode_base64("Zm9v*"), Err(TslError::Base64(_))));
    }

    #[test]
    fn missing_root_element_is_a_structure_error() {
        let err = parse_tsl(b"<Nonsense/>").unwrap_err();
        assert!(matches!(err, TslError::Structure(_)));
    }

    #[test]
    fn parses_namespace_prefixed_elements_by_local_name() {
        // Same structure a real list uses when the default namespace is given a prefix.
        let xml = br#"<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#">
          <tsl:SchemeInformation><tsl:SchemeTerritory>PT</tsl:SchemeTerritory></tsl:SchemeInformation>
          <tsl:TrustServiceProviderList>
            <tsl:TrustServiceProvider>
              <tsl:TSPInformation><tsl:TSPName><tsl:Name xml:lang="en">ACME</tsl:Name></tsl:TSPName></tsl:TSPInformation>
              <tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation>
                <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
                <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus>
              </tsl:ServiceInformation></tsl:TSPService></tsl:TSPServices>
            </tsl:TrustServiceProvider>
          </tsl:TrustServiceProviderList>
        </tsl:TrustServiceStatusList>"#;
        let list = parse_tsl(xml).unwrap();
        assert_eq!(list.scheme_territory, "PT");
        assert_eq!(list.providers.len(), 1);
        assert_eq!(list.providers[0].name, "ACME");
        assert!(list.providers[0].services[0].is_ca_qc());
        assert!(list.providers[0].services[0].is_granted());
    }

    fn service_with(info: Vec<&str>) -> TrustService {
        TrustService {
            service_type: SVCTYPE_CA_QC.to_owned(),
            name: "svc".to_owned(),
            names: vec![LocalizedText {
                lang: Some("en".to_owned()),
                value: "svc".to_owned(),
            }],
            status: ServiceStatus::Granted,
            status_starting_time: None,
            status_starting_time_raw: None,
            digital_identities: Vec::new(),
            additional_service_info: info.into_iter().map(str::to_owned).collect(),
            service_supply_points: Vec::new(),
            history: Vec::new(),
        }
    }

    #[test]
    fn qualifies_for_esig_marker_logic() {
        // Explicit e-signatures marker qualifies.
        assert!(service_with(vec![FOR_ESIGNATURES]).qualifies_for_esig());
        // No markers at all: legacy/ambiguous CA/QC defaults to signatures.
        assert!(service_with(vec![]).qualifies_for_esig());
        // e-signatures alongside e-seals still qualifies.
        assert!(service_with(vec![FOR_ESIGNATURES, FOR_ESEALS]).qualifies_for_esig());
        // Seal-only / web-auth-only do NOT qualify for signatures.
        assert!(!service_with(vec![FOR_ESEALS]).qualifies_for_esig());
        assert!(!service_with(vec![FOR_WEB_AUTH]).qualifies_for_esig());
    }
}
