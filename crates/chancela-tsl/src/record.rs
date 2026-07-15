//! Flat searchable records projected from parsed ETSI Trusted Lists.
//!
//! The parser keeps the TSL hierarchy intact. This module provides a small, deterministic record
//! layer for catalog/search surfaces without coupling those surfaces to HTTP DTOs.

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::parse::{
    DigitalIdentity, LocalizedText, ServiceHistoryEntry, ServiceStatus, TrustService, TrustedList,
};

/// Identifier material extracted from a service digital identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordIdentifier {
    /// Identifier kind.
    pub kind: RecordIdentifierKind,
    /// Stable display/search value: subject DN, SKI hex, or certificate SHA-256 hex.
    pub value: String,
}

/// The kind of identifier carried by a [`RecordIdentifier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordIdentifierKind {
    CertificateSha256,
    SubjectName,
    SubjectKeyId,
}

/// Coarse input class used by record identity lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordLookupInputKind {
    CertificateSha256,
    SubjectKeyId,
    Text,
}

/// Field that caused a record lookup hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordLookupField {
    CertificateSha256,
    SubjectKeyId,
    SubjectName,
    Provider,
    Service,
    ServiceType,
    SupplyPoint,
    AdditionalServiceInfo,
}

/// Deterministic lookup outcome. `Unknown` means the input is not specific enough to prove a
/// technical match, not that the certificate/service is trusted or untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordLookupOutcome {
    Match,
    NoMatch,
    Unknown,
}

/// A single matched record and the fields that matched the lookup input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TslRecordLookupMatch {
    pub record: TslRecord,
    pub fields: Vec<RecordLookupField>,
}

/// Structured technical lookup result over projected records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TslRecordLookup {
    pub input: String,
    pub normalized_input: Option<String>,
    pub input_kind: Option<RecordLookupInputKind>,
    pub outcome: RecordLookupOutcome,
    pub matches: Vec<TslRecordLookupMatch>,
}

/// Normalized status kind for filtering while preserving the raw URI on the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordStatusKind {
    Granted,
    Withdrawn,
    Revoked,
    Other,
}

/// A flat service record suitable for deterministic catalog search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TslRecord {
    /// Stable derived id within this parsed list.
    pub id: String,
    /// Stable derived provider id within this parsed list.
    pub provider_id: String,
    /// Preferred provider name.
    pub provider_name: String,
    /// Provider name variants and trade names.
    pub provider_aliases: Vec<String>,
    /// Scheme territory/country, for example `PT`.
    pub country: String,
    /// Preferred service name.
    pub service_name: String,
    /// Service name variants.
    pub service_aliases: Vec<String>,
    /// ETSI `ServiceTypeIdentifier` URI.
    pub service_type: String,
    /// Normalized service status.
    pub status: RecordStatusKind,
    /// Raw status URI for non-basic statuses.
    pub status_uri: Option<String>,
    /// Parsed `StatusStartingTime`, if present and valid.
    pub valid_from: Option<OffsetDateTime>,
    /// Raw `StatusStartingTime`, retained for malformed optional dates.
    pub valid_from_raw: Option<String>,
    /// `ServiceSupplyPoint` endpoint/evidence references.
    pub supply_points: Vec<String>,
    /// Provider information URI evidence references.
    pub provider_information_uris: Vec<String>,
    /// Additional service information URIs.
    pub additional_service_info: Vec<String>,
    /// Deduplicated identifiers in first-seen order.
    pub identifiers: Vec<RecordIdentifier>,
    /// Whether this record represents a timestamp-authority service.
    pub is_tsa: bool,
    /// Whether this record is a qualified timestamp service (`TSA/QTST`).
    pub is_qualified_timestamp_service: bool,
    /// Whether the service status is granted and effective at projection time.
    pub granted_and_effective: bool,
    /// Number of structured historical service entries retained by the parser.
    pub history_count: usize,
    /// Folded deterministic search blob.
    search_text: String,
}

/// Optional filters for [`filter_records`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordSearch {
    pub text: Option<String>,
    pub country: Option<String>,
    pub provider: Option<String>,
    pub service_type: Option<String>,
    pub status: Option<RecordStatusKind>,
    pub identifier: Option<String>,
    pub tsa_only: bool,
    pub qualified_timestamp_only: bool,
    pub granted_only: bool,
    pub has_supply_point: Option<bool>,
    pub limit: Option<usize>,
}

/// Project every current trust service into flat records.
pub fn trust_service_records(list: &TrustedList, now: OffsetDateTime) -> Vec<TslRecord> {
    let list_text = folded_parts([
        list.scheme_operator_name.as_str(),
        &localized_values(&list.scheme_operator_names),
        list.scheme_name.as_str(),
        &localized_values(&list.scheme_names),
        list.scheme_territory.as_str(),
    ]);

    let mut out = Vec::new();
    for (provider_index, provider) in list.providers.iter().enumerate() {
        let provider_id = provider_id(provider_index, provider.name.as_str());
        let provider_aliases = provider_aliases(provider);
        let provider_text = folded_parts([
            provider.name.as_str(),
            &provider_aliases.join(" "),
            &provider.information_uris.join(" "),
        ]);
        for (service_index, service) in provider.services.iter().enumerate() {
            let service_aliases = localized_values_vec(&service.names);
            let identifiers = record_identifiers(&service.digital_identities);
            let status = record_status(&service.status);
            let status_uri = status_uri(&service.status);
            let valid_from = service.status_starting_time;
            let is_tsa = is_tsa_service(service);
            let is_qualified_timestamp_service = is_qualified_timestamp_service(service);
            let granted_and_effective = service.is_granted() && service.is_effective_at(now);
            let search_text = folded_parts([
                &list_text,
                &provider_text,
                service.name.as_str(),
                &service_aliases.join(" "),
                service.service_type.as_str(),
                &status_search_text(&service.status),
                service.status_starting_time_raw.as_deref().unwrap_or(""),
                &service.additional_service_info.join(" "),
                &service.service_supply_points.join(" "),
                &identifier_search_text(&identifiers),
                &history_search_text(&service.history),
            ]);
            out.push(TslRecord {
                id: service_id(&provider_id, service_index, service),
                provider_id: provider_id.clone(),
                provider_name: provider.name.clone(),
                provider_aliases: provider_aliases.clone(),
                country: list.scheme_territory.clone(),
                service_name: service.name.clone(),
                service_aliases,
                service_type: service.service_type.clone(),
                status,
                status_uri,
                valid_from,
                valid_from_raw: service.status_starting_time_raw.clone(),
                supply_points: service.service_supply_points.clone(),
                provider_information_uris: provider.information_uris.clone(),
                additional_service_info: service.additional_service_info.clone(),
                identifiers,
                is_tsa,
                is_qualified_timestamp_service,
                granted_and_effective,
                history_count: service.history.len(),
                search_text,
            });
        }
    }
    out
}

/// Project only timestamp-authority records.
pub fn tsa_records(list: &TrustedList, now: OffsetDateTime) -> Vec<TslRecord> {
    trust_service_records(list, now)
        .into_iter()
        .filter(|record| record.is_tsa)
        .collect()
}

/// Deterministically filter projected records in source order.
pub fn filter_records(records: &[TslRecord], search: &RecordSearch) -> Vec<TslRecord> {
    let text = search.text.as_deref().map(fold);
    let country = search.country.as_deref().map(fold);
    let provider = search.provider.as_deref().map(fold);
    let service_type = search.service_type.as_deref().map(fold);
    let identifier = search.identifier.as_deref().map(fold);
    let limit = search.limit.unwrap_or(usize::MAX);

    records
        .iter()
        .filter(|record| {
            text.as_deref()
                .is_none_or(|needle| matches_folded(&record.search_text, needle))
                && country
                    .as_deref()
                    .is_none_or(|needle| fold(&record.country).contains(needle))
                && provider.as_deref().is_none_or(|needle| {
                    matches_folded(
                        &folded_parts([
                            record.provider_name.as_str(),
                            &record.provider_aliases.join(" "),
                        ]),
                        needle,
                    )
                })
                && service_type
                    .as_deref()
                    .is_none_or(|needle| fold(&record.service_type).contains(needle))
                && search.status.is_none_or(|status| record.status == status)
                && identifier.as_deref().is_none_or(|needle| {
                    record
                        .identifiers
                        .iter()
                        .any(|id| fold(&id.value).contains(needle))
                })
                && (!search.tsa_only || record.is_tsa)
                && (!search.qualified_timestamp_only || record.is_qualified_timestamp_service)
                && (!search.granted_only || record.granted_and_effective)
                && search
                    .has_supply_point
                    .is_none_or(|want| record.supply_points.is_empty() != want)
        })
        .take(limit)
        .cloned()
        .collect()
}

/// Look up certificate/service identity material across projected records.
///
/// Fingerprint-like input is intentionally strict: SHA-256 certificate fingerprints must be
/// complete 64-character hex after common separators are removed, and SKIs must be complete
/// 40-character hex. Short or malformed fingerprint-like input returns [`RecordLookupOutcome::Unknown`]
/// instead of attempting a partial match. Non-hex text is treated as a bounded catalog search over
/// subject names, provider/service labels, service type, supply points and additional service info.
pub fn lookup_records(records: &[TslRecord], input: &str, limit: Option<usize>) -> TslRecordLookup {
    let original = input.trim().to_owned();
    let Some(lookup) = normalize_lookup_input(input) else {
        return TslRecordLookup {
            input: original,
            normalized_input: None,
            input_kind: None,
            outcome: RecordLookupOutcome::Unknown,
            matches: Vec::new(),
        };
    };

    let max = limit.unwrap_or(usize::MAX);
    let mut matches = Vec::new();
    for record in records {
        let fields = lookup_fields(record, &lookup);
        if !fields.is_empty() {
            matches.push(TslRecordLookupMatch {
                record: record.clone(),
                fields,
            });
            if matches.len() >= max {
                break;
            }
        }
    }

    let outcome = if matches.is_empty() {
        RecordLookupOutcome::NoMatch
    } else {
        RecordLookupOutcome::Match
    };
    TslRecordLookup {
        input: original,
        normalized_input: Some(lookup.value),
        input_kind: Some(lookup.kind),
        outcome,
        matches,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedLookup {
    kind: RecordLookupInputKind,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HexLikeInput {
    Hex(String),
    Malformed,
    Text,
}

fn normalize_lookup_input(input: &str) -> Option<NormalizedLookup> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    match compact_fingerprint_hex(trimmed) {
        HexLikeInput::Hex(compact_hex) => {
            return match compact_hex.len() {
                64 => Some(NormalizedLookup {
                    kind: RecordLookupInputKind::CertificateSha256,
                    value: compact_hex,
                }),
                40 => Some(NormalizedLookup {
                    kind: RecordLookupInputKind::SubjectKeyId,
                    value: compact_hex,
                }),
                _ => None,
            };
        }
        HexLikeInput::Malformed => return None,
        HexLikeInput::Text => {}
    }

    let text = fold(trimmed);
    (text.chars().filter(|c| c.is_alphanumeric()).count() >= 3).then_some(NormalizedLookup {
        kind: RecordLookupInputKind::Text,
        value: text,
    })
}

fn compact_fingerprint_hex(input: &str) -> HexLikeInput {
    let mut out = String::new();
    let mut saw_separator = false;
    for c in input.chars() {
        if c.is_ascii_hexdigit() {
            out.push(c.to_ascii_lowercase());
        } else if c == ':' || c == '-' || c.is_ascii_whitespace() {
            saw_separator = true;
            continue;
        } else {
            return if saw_separator {
                HexLikeInput::Malformed
            } else {
                HexLikeInput::Text
            };
        }
    }
    if out.is_empty() {
        HexLikeInput::Text
    } else {
        HexLikeInput::Hex(out)
    }
}

fn lookup_fields(record: &TslRecord, lookup: &NormalizedLookup) -> Vec<RecordLookupField> {
    let mut fields = Vec::new();
    match lookup.kind {
        RecordLookupInputKind::CertificateSha256 => {
            if record.identifiers.iter().any(|id| {
                id.kind == RecordIdentifierKind::CertificateSha256 && id.value == lookup.value
            }) {
                fields.push(RecordLookupField::CertificateSha256);
            }
        }
        RecordLookupInputKind::SubjectKeyId => {
            if record
                .identifiers
                .iter()
                .any(|id| id.kind == RecordIdentifierKind::SubjectKeyId && id.value == lookup.value)
            {
                fields.push(RecordLookupField::SubjectKeyId);
            }
        }
        RecordLookupInputKind::Text => {
            if record.identifiers.iter().any(|id| {
                id.kind == RecordIdentifierKind::SubjectName
                    && matches_folded(&fold(&id.value), &lookup.value)
            }) {
                fields.push(RecordLookupField::SubjectName);
            }
            if matches_folded(
                &folded_parts([
                    record.provider_name.as_str(),
                    &record.provider_aliases.join(" "),
                ]),
                &lookup.value,
            ) {
                fields.push(RecordLookupField::Provider);
            }
            if matches_folded(
                &folded_parts([
                    record.service_name.as_str(),
                    &record.service_aliases.join(" "),
                ]),
                &lookup.value,
            ) {
                fields.push(RecordLookupField::Service);
            }
            if matches_folded(&fold(&record.service_type), &lookup.value) {
                fields.push(RecordLookupField::ServiceType);
            }
            if matches_folded(&fold(&record.supply_points.join(" ")), &lookup.value) {
                fields.push(RecordLookupField::SupplyPoint);
            }
            if matches_folded(
                &fold(&record.additional_service_info.join(" ")),
                &lookup.value,
            ) {
                fields.push(RecordLookupField::AdditionalServiceInfo);
            }
        }
    }
    fields
}

fn provider_aliases(provider: &crate::parse::TrustServiceProvider) -> Vec<String> {
    let mut out = Vec::new();
    push_unique(&mut out, &provider.name);
    for name in &provider.names {
        push_unique(&mut out, &name.value);
    }
    for name in &provider.trade_names {
        push_unique(&mut out, name);
    }
    for name in &provider.localized_trade_names {
        push_unique(&mut out, &name.value);
    }
    out
}

fn record_identifiers(identities: &[DigitalIdentity]) -> Vec<RecordIdentifier> {
    let mut out = Vec::new();
    for identity in identities {
        let id = match identity {
            DigitalIdentity::Certificate(der) => RecordIdentifier {
                kind: RecordIdentifierKind::CertificateSha256,
                value: hex(&Sha256::digest(der)),
            },
            DigitalIdentity::SubjectName(name) => RecordIdentifier {
                kind: RecordIdentifierKind::SubjectName,
                value: name.clone(),
            },
            DigitalIdentity::SubjectKeyId(ski) => RecordIdentifier {
                kind: RecordIdentifierKind::SubjectKeyId,
                value: hex(ski),
            },
        };
        if !out.iter().any(|existing| existing == &id) {
            out.push(id);
        }
    }
    out
}

fn record_status(status: &ServiceStatus) -> RecordStatusKind {
    match status {
        ServiceStatus::Granted => RecordStatusKind::Granted,
        ServiceStatus::Withdrawn => RecordStatusKind::Withdrawn,
        ServiceStatus::Revoked(_) => RecordStatusKind::Revoked,
        ServiceStatus::Other(_) => RecordStatusKind::Other,
    }
}

fn status_uri(status: &ServiceStatus) -> Option<String> {
    match status {
        ServiceStatus::Revoked(uri) | ServiceStatus::Other(uri) => Some(uri.clone()),
        ServiceStatus::Granted | ServiceStatus::Withdrawn => None,
    }
}

fn status_search_text(status: &ServiceStatus) -> String {
    match status {
        ServiceStatus::Granted => "granted".to_owned(),
        ServiceStatus::Withdrawn => "withdrawn".to_owned(),
        ServiceStatus::Revoked(uri) | ServiceStatus::Other(uri) => uri.clone(),
    }
}

fn is_tsa_service(service: &TrustService) -> bool {
    fold(&service.service_type).contains("/tsa/")
}

fn is_qualified_timestamp_service(service: &TrustService) -> bool {
    service.service_type == "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
}

fn provider_id(provider_index: usize, provider_name: &str) -> String {
    let mut h = Sha256::new();
    h.update(provider_index.to_be_bytes());
    h.update([0]);
    h.update(provider_name.as_bytes());
    format!("tsp-{}", short_hash(h))
}

fn service_id(provider_id: &str, service_index: usize, service: &TrustService) -> String {
    let mut h = Sha256::new();
    h.update(provider_id.as_bytes());
    h.update([0]);
    h.update(service_index.to_be_bytes());
    h.update([0]);
    h.update(service.service_type.as_bytes());
    h.update([0]);
    h.update(service.name.as_bytes());
    h.update([0]);
    h.update(status_search_text(&service.status).as_bytes());
    h.update([0]);
    if let Some(start) = service.status_starting_time {
        h.update(format_time(start).as_bytes());
    }
    h.update([0]);
    if let Some(raw) = &service.status_starting_time_raw {
        h.update(raw.as_bytes());
    }
    format!("svc-{}", short_hash(h))
}

fn short_hash(hasher: Sha256) -> String {
    let digest = hasher.finalize();
    hex(&digest)[..20].to_owned()
}

fn history_search_text(history: &[ServiceHistoryEntry]) -> String {
    history
        .iter()
        .map(|entry| {
            folded_parts([
                entry.name.as_str(),
                &localized_values(&entry.names),
                entry.service_type.as_str(),
                &status_search_text(&entry.status),
                entry.status_starting_time_raw.as_deref().unwrap_or(""),
                &entry.additional_service_info.join(" "),
                &entry.service_supply_points.join(" "),
                &identifier_search_text(&record_identifiers(&entry.digital_identities)),
            ])
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn identifier_search_text(identifiers: &[RecordIdentifier]) -> String {
    identifiers
        .iter()
        .map(|id| id.value.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

fn localized_values(values: &[LocalizedText]) -> String {
    localized_values_vec(values).join(" ")
}

fn localized_values_vec(values: &[LocalizedText]) -> Vec<String> {
    values.iter().map(|value| value.value.clone()).collect()
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !value.is_empty() && !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn folded_parts<const N: usize>(parts: [&str; N]) -> String {
    fold(&parts.join(" "))
}

fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().flat_map(|c| c.to_lowercase()) {
        match c {
            '\u{00e0}' | '\u{00e1}' | '\u{00e2}' | '\u{00e3}' | '\u{00e4}' | '\u{00e5}' => {
                out.push('a')
            }
            '\u{00e7}' => out.push('c'),
            '\u{00e8}' | '\u{00e9}' | '\u{00ea}' | '\u{00eb}' => out.push('e'),
            '\u{00ec}' | '\u{00ed}' | '\u{00ee}' | '\u{00ef}' => out.push('i'),
            '\u{00f1}' => out.push('n'),
            '\u{00f2}' | '\u{00f3}' | '\u{00f4}' | '\u{00f5}' | '\u{00f6}' => out.push('o'),
            '\u{00f9}' | '\u{00fa}' | '\u{00fb}' | '\u{00fc}' => out.push('u'),
            '\u{00fd}' | '\u{00ff}' => out.push('y'),
            '\u{00e6}' => out.push_str("ae"),
            '\u{0153}' => out.push_str("oe"),
            '\u{00df}' => out.push_str("ss"),
            other => out.push(other),
        }
    }
    out
}

fn matches_folded(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
        || needle
            .split_whitespace()
            .filter(|term| !term.is_empty())
            .all(|term| haystack.contains(term))
}

fn format_time(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("high nibble < 16"));
        s.push(char::from_digit((b & 0x0f) as u32, 16).expect("low nibble < 16"));
    }
    s
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::parse::{
        FOR_ESIGNATURES, LocalizedText, SVCTYPE_CA_QC, TrustServiceProvider, parse_tsl,
    };

    const FIXTURE: &[u8] = include_bytes!("../fixtures/pt-tsl-sample.xml");
    const NOW: OffsetDateTime = datetime!(2026-07-06 12:00:00 UTC);

    #[test]
    fn projects_fixture_into_searchable_records() {
        let list = parse_tsl(FIXTURE).unwrap();
        let records = trust_service_records(&list, NOW);

        assert_eq!(records.len(), list.services().count());
        let multicert = records
            .iter()
            .find(|record| record.provider_name.contains("MULTICERT"))
            .expect("multicert record");
        assert_eq!(multicert.country, "PT");
        assert_eq!(multicert.status, RecordStatusKind::Granted);
        assert_eq!(multicert.valid_from, Some(datetime!(2020-01-01 0:00 UTC)));
        assert!(multicert.granted_and_effective);
        assert!(multicert.identifiers.iter().any(|id| {
            id.kind == RecordIdentifierKind::CertificateSha256 && id.value.len() == 64
        }));
        assert!(multicert.identifiers.iter().any(|id| {
            id.kind == RecordIdentifierKind::SubjectName
                && id
                    .value
                    .contains("MULTICERT CA para Assinatura Qualificada")
        }));
        assert_eq!(multicert.history_count, 1);
    }

    #[test]
    fn filters_are_deterministic_and_accent_insensitive() {
        let list = parse_tsl(FIXTURE).unwrap();
        let records = trust_service_records(&list, NOW);

        let hits = filter_records(
            &records,
            &RecordSearch {
                text: Some("ancora sao tome".to_owned()),
                tsa_only: true,
                limit: Some(10),
                ..RecordSearch::default()
            },
        );
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|record| record.is_tsa));

        let qtst = filter_records(
            &records,
            &RecordSearch {
                service_type: Some("/TSA/QTST".to_owned()),
                status: Some(RecordStatusKind::Granted),
                qualified_timestamp_only: true,
                has_supply_point: Some(true),
                ..RecordSearch::default()
            },
        );
        assert_eq!(qtst.len(), 1);
        assert_eq!(
            qtst[0].service_type,
            "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
        );

        let no_match = filter_records(
            &records,
            &RecordSearch {
                text: Some("sem resultado deterministico".to_owned()),
                ..RecordSearch::default()
            },
        );
        assert!(no_match.is_empty());
    }

    #[test]
    fn duplicate_identifiers_are_deduplicated_and_malformed_dates_are_retained() {
        let list = TrustedList {
            scheme_operator_name: "Operador".to_owned(),
            scheme_operator_names: Vec::new(),
            scheme_name: "Lista".to_owned(),
            scheme_names: Vec::new(),
            scheme_territory: "PT".to_owned(),
            sequence_number: None,
            issue_date_time: None,
            next_update: None,
            other_tsl_pointers: Vec::new(),
            providers: vec![TrustServiceProvider {
                name: "Fornecedor".to_owned(),
                names: vec![LocalizedText {
                    lang: Some("pt".to_owned()),
                    value: "Fornecedor".to_owned(),
                }],
                trade_names: vec!["Fornecedor".to_owned()],
                localized_trade_names: Vec::new(),
                information_uris: vec!["https://example.test/evidence".to_owned()],
                services: vec![TrustService {
                    service_type: SVCTYPE_CA_QC.to_owned(),
                    name: "Servico sem data valida".to_owned(),
                    names: Vec::new(),
                    status: ServiceStatus::Granted,
                    status_starting_time: None,
                    status_starting_time_raw: Some("31-13-2026".to_owned()),
                    digital_identities: vec![
                        DigitalIdentity::SubjectName("CN=Duplicado,O=Teste,C=PT".to_owned()),
                        DigitalIdentity::SubjectName("CN=Duplicado,O=Teste,C=PT".to_owned()),
                        DigitalIdentity::SubjectKeyId(vec![0xab, 0xcd]),
                        DigitalIdentity::SubjectKeyId(vec![0xab, 0xcd]),
                    ],
                    additional_service_info: vec![FOR_ESIGNATURES.to_owned()],
                    service_supply_points: Vec::new(),
                    history: Vec::new(),
                }],
            }],
        };

        let records = trust_service_records(&list, NOW);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].valid_from, None);
        assert_eq!(records[0].valid_from_raw.as_deref(), Some("31-13-2026"));
        assert_eq!(records[0].identifiers.len(), 2);

        let hits = filter_records(
            &records,
            &RecordSearch {
                identifier: Some("abcd".to_owned()),
                granted_only: true,
                ..RecordSearch::default()
            },
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].provider_information_uris,
            vec!["https://example.test/evidence".to_owned()]
        );
    }

    #[test]
    fn tsa_records_returns_only_tsa_service_types() {
        let list = parse_tsl(FIXTURE).unwrap();
        let records = tsa_records(&list, NOW);
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|record| record.service_type.contains("/TSA/"))
        );
    }

    #[test]
    fn lookup_matches_complete_certificate_fingerprint_and_ski_only() {
        let list = parse_tsl(FIXTURE).unwrap();
        let records = trust_service_records(&list, NOW);
        let multicert = records
            .iter()
            .find(|record| record.provider_name.contains("MULTICERT"))
            .expect("multicert record");
        let fingerprint = multicert
            .identifiers
            .iter()
            .find(|id| id.kind == RecordIdentifierKind::CertificateSha256)
            .expect("certificate fingerprint")
            .value
            .clone();
        let ski = multicert
            .identifiers
            .iter()
            .find(|id| id.kind == RecordIdentifierKind::SubjectKeyId)
            .expect("ski")
            .value
            .clone();

        let fingerprint_with_separators = fingerprint
            .as_bytes()
            .chunks(2)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let by_fingerprint = lookup_records(&records, &fingerprint_with_separators, Some(10));
        assert_eq!(by_fingerprint.outcome, RecordLookupOutcome::Match);
        assert_eq!(
            by_fingerprint.input_kind,
            Some(RecordLookupInputKind::CertificateSha256)
        );
        assert_eq!(by_fingerprint.matches.len(), 1);
        assert_eq!(
            by_fingerprint.matches[0].fields,
            vec![RecordLookupField::CertificateSha256]
        );

        let by_ski = lookup_records(&records, &ski.to_uppercase(), Some(10));
        assert_eq!(by_ski.outcome, RecordLookupOutcome::Match);
        assert_eq!(by_ski.input_kind, Some(RecordLookupInputKind::SubjectKeyId));
        assert_eq!(by_ski.matches.len(), 1);
        assert_eq!(
            by_ski.matches[0].fields,
            vec![RecordLookupField::SubjectKeyId]
        );
    }

    #[test]
    fn lookup_matches_subject_provider_service_and_tsa_hints_as_text() {
        let list = parse_tsl(FIXTURE).unwrap();
        let records = trust_service_records(&list, NOW);

        let by_subject = lookup_records(
            &records,
            "CN=MULTICERT CA para Assinatura Qualificada",
            Some(10),
        );
        assert_eq!(by_subject.outcome, RecordLookupOutcome::Match);
        assert!(
            by_subject.matches[0]
                .fields
                .contains(&RecordLookupField::SubjectName)
        );

        let by_provider = lookup_records(&records, "ancora sao tome", Some(10));
        assert_eq!(by_provider.outcome, RecordLookupOutcome::Match);
        assert_eq!(by_provider.matches.len(), 2);
        assert!(by_provider.matches.iter().all(|hit| hit.record.is_tsa));

        let by_qtst = lookup_records(&records, "/TSA/QTST", Some(10));
        assert_eq!(by_qtst.outcome, RecordLookupOutcome::Match);
        assert_eq!(by_qtst.matches.len(), 1);
        assert!(by_qtst.matches[0].record.is_qualified_timestamp_service);
        assert!(
            by_qtst.matches[0]
                .fields
                .contains(&RecordLookupField::ServiceType)
        );
    }

    #[test]
    fn lookup_reports_no_match_without_inferring_and_unknown_for_partial_hex() {
        let list = parse_tsl(FIXTURE).unwrap();
        let records = trust_service_records(&list, NOW);

        let no_match = lookup_records(
            &records,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            Some(10),
        );
        assert_eq!(no_match.outcome, RecordLookupOutcome::NoMatch);
        assert_eq!(
            no_match.input_kind,
            Some(RecordLookupInputKind::CertificateSha256)
        );
        assert!(no_match.matches.is_empty());

        let partial_fingerprint = lookup_records(&records, "84:b7:8a:44", Some(10));
        assert_eq!(partial_fingerprint.outcome, RecordLookupOutcome::Unknown);
        assert_eq!(partial_fingerprint.input_kind, None);
        assert!(partial_fingerprint.matches.is_empty());

        let malformed = lookup_records(&records, "ab:cd:not-hex", Some(10));
        assert_eq!(malformed.outcome, RecordLookupOutcome::Unknown);
        assert_eq!(malformed.input_kind, None);

        let too_short = lookup_records(&records, "ca", Some(10));
        assert_eq!(too_short.outcome, RecordLookupOutcome::Unknown);
    }
}
