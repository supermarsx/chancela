//! Qualified-status query: is a given certificate issuer a currently-qualified QTSP for
//! **e-signatures** (SIG-10..13)?
//!
//! The query resolves an *issuer certificate* (the CA that issued a signer's certificate) against
//! a parsed [`TrustedList`]. An issuer is qualified for e-signatures when the list carries a
//! `CA/QC` service whose digital identity matches the issuer, whose status is `granted` and
//! effective now, and which is usable for e-signatures (see
//! [`TrustService::qualifies_for_esig`]).

use der::Decode;
use time::OffsetDateTime;

use crate::cache::CachedTsl;
use crate::error::TslError;
use crate::parse::{DigitalIdentity, TrustService, TrustedList, parse_tsl};
use crate::source::TslSource;

/// Whether a certificate or issuer is currently qualified for the requested service class per the
/// TSL.
///
/// Maps one-to-one onto `chancela_signing::TrustedListStatus` (`Granted`/`Withdrawn`/`Unknown`);
/// the mapping lives in `chancela-signing` (t4-e8) so this crate stays free of that dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum QualifiedStatus {
    /// The issuer is present and currently granted/qualified for e-signatures.
    Granted,
    /// The issuer is present on the list but not currently granted for e-signatures (withdrawn,
    /// not yet effective, or granted only for e-seals/web-authentication).
    Withdrawn,
    /// The issuer is not present on the list at all.
    Unknown,
}

/// A TSL service that matched a QTST identity lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QtstServiceMatch {
    /// Trust-service provider name.
    pub provider_name: String,
    /// Trust-service name.
    pub service_name: String,
    /// The raw service status resolved from the TSL.
    pub service_status: crate::parse::ServiceStatus,
    /// Whether the service is granted and effective at the lookup time.
    pub granted_and_effective: bool,
    /// Full DER certificate identities published for this service.
    pub trust_anchor_ders: Vec<Vec<u8>>,
}

/// Detailed QTST lookup result, including DER anchors from granted matching services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QtstMatchDetails {
    /// Coarse qualified timestamp status.
    pub status: QualifiedStatus,
    /// Matching services, including withdrawn/not-yet-effective matches for diagnostics.
    pub matches: Vec<QtstServiceMatch>,
    /// DER certificate identities from matching granted/effective `TSA/QTST` services.
    pub trust_anchor_ders: Vec<Vec<u8>>,
    /// Whether the cached list was authenticated when this result came from [`TslClient`].
    pub authenticated: bool,
}

/// The OID of the X.509 Subject Key Identifier extension (2.5.29.14).
const SKI_OID: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.14");

/// Identifying material extracted from a certificate, used to match it against a trust
/// service's digital identities. Certificate-DER equality is the strong match; SKI and subject
/// name are fallbacks for lists that publish only an identifier.
struct CertificateId<'a> {
    der: &'a [u8],
    ski: Option<Vec<u8>>,
    subject: Option<String>,
}

impl<'a> CertificateId<'a> {
    fn from_der(der: &'a [u8]) -> Self {
        let (ski, subject) = match x509_cert::Certificate::from_der(der) {
            Ok(cert) => (
                ski_of(&cert),
                Some(cert.tbs_certificate.subject.to_string()),
            ),
            // If the bytes are not a decodable certificate we can still match by DER equality.
            Err(_) => (None, None),
        };
        Self { der, ski, subject }
    }

    /// Whether `service` carries a digital identity that identifies this issuer.
    fn matches(&self, service: &TrustService) -> bool {
        service.digital_identities.iter().any(|id| match id {
            DigitalIdentity::Certificate(cert) => cert.as_slice() == self.der,
            DigitalIdentity::SubjectKeyId(ski) => self.ski.as_deref() == Some(ski.as_slice()),
            DigitalIdentity::SubjectName(name) => self
                .subject
                .as_deref()
                .is_some_and(|subject| subject.eq_ignore_ascii_case(name)),
        })
    }
}

/// Extract the Subject Key Identifier (raw key-id bytes) from a certificate, if present.
fn ski_of(cert: &x509_cert::Certificate) -> Option<Vec<u8>> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    let ext = extensions.iter().find(|e| e.extn_id == SKI_OID)?;
    // extn_value wraps the DER of `SubjectKeyIdentifier ::= OCTET STRING`; unwrap one layer.
    let inner = der::asn1::OctetString::from_der(ext.extn_value.as_bytes()).ok()?;
    Some(inner.as_bytes().to_vec())
}

/// Resolve whether `issuer_cert_der` is a currently-qualified QTSP for e-signatures in `list`
/// as of `now`.
///
/// Returns [`QualifiedStatus::Unknown`] when no service identifies the issuer at all;
/// [`QualifiedStatus::Granted`] when a matching `CA/QC` service is granted, effective and for
/// e-signatures; and [`QualifiedStatus::Withdrawn`] when the issuer is present but no such
/// service currently qualifies it.
pub fn resolve_esig_status(
    list: &TrustedList,
    issuer_cert_der: &[u8],
    now: OffsetDateTime,
) -> QualifiedStatus {
    let issuer = CertificateId::from_der(issuer_cert_der);
    let mut found = false;
    let mut qualified = false;
    for service in list.services().filter(|s| issuer.matches(s)) {
        found = true;
        if service.is_ca_qc()
            && service.is_granted()
            && service.is_effective_at(now)
            && service.qualifies_for_esig()
        {
            qualified = true;
            break;
        }
    }
    match (found, qualified) {
        (_, true) => QualifiedStatus::Granted,
        (true, false) => QualifiedStatus::Withdrawn,
        (false, false) => QualifiedStatus::Unknown,
    }
}

/// Resolve whether `tsa_cert_der` identifies a currently-granted qualified timestamp service
/// (`TSA/QTST`) in `list` as of `now`.
///
/// This is a technical trusted-list status lookup for the TSA signer certificate or published TSA
/// service identity. It does not validate the timestamp token, build the TSA certificate path, or
/// make a legal-validation statement.
pub fn resolve_qtst_status(
    list: &TrustedList,
    tsa_cert_der: &[u8],
    now: OffsetDateTime,
) -> QualifiedStatus {
    let tsa = CertificateId::from_der(tsa_cert_der);
    let mut found = false;
    let mut qualified = false;
    for service in list.services().filter(|s| tsa.matches(s)) {
        found = true;
        if service.is_tsa_qtst() && service.is_granted() && service.is_effective_at(now) {
            qualified = true;
            break;
        }
    }
    match (found, qualified) {
        (_, true) => QualifiedStatus::Granted,
        (true, false) => QualifiedStatus::Withdrawn,
        (false, false) => QualifiedStatus::Unknown,
    }
}

/// Resolve QTST match details and DER anchors for `tsa_cert_der`.
///
/// This is a technical offline lookup against the supplied parsed TSL. It does not validate a
/// timestamp token or certificate path, and it does not make a legal qualification claim.
pub fn resolve_qtst_match_details(
    list: &TrustedList,
    tsa_cert_der: &[u8],
    now: OffsetDateTime,
) -> QtstMatchDetails {
    let tsa = CertificateId::from_der(tsa_cert_der);
    let mut matches = Vec::new();
    let mut trust_anchor_ders = Vec::new();
    let mut granted = false;

    for provider in &list.providers {
        for service in provider.services.iter().filter(|s| tsa.matches(s)) {
            let granted_and_effective =
                service.is_tsa_qtst() && service.is_granted() && service.is_effective_at(now);
            let service_anchor_ders = service
                .digital_identities
                .iter()
                .filter_map(|id| match id {
                    DigitalIdentity::Certificate(der) => Some(der.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if granted_and_effective {
                granted = true;
                for der in &service_anchor_ders {
                    if !trust_anchor_ders.iter().any(|existing| existing == der) {
                        trust_anchor_ders.push(der.clone());
                    }
                }
            }
            matches.push(QtstServiceMatch {
                provider_name: provider.name.clone(),
                service_name: service.name.clone(),
                service_status: service.status.clone(),
                granted_and_effective,
                trust_anchor_ders: service_anchor_ders,
            });
        }
    }

    let status = match (matches.is_empty(), granted) {
        (_, true) => QualifiedStatus::Granted,
        (false, false) => QualifiedStatus::Withdrawn,
        (true, false) => QualifiedStatus::Unknown,
    };

    QtstMatchDetails {
        status,
        matches,
        trust_anchor_ders,
        authenticated: true,
    }
}

/// List every service currently granted and qualified for e-signatures as of `now` (SIG-12
/// discovery/listing).
pub fn qualified_esig_services(list: &TrustedList, now: OffsetDateTime) -> Vec<&TrustService> {
    list.services()
        .filter(|s| {
            s.is_ca_qc() && s.is_granted() && s.is_effective_at(now) && s.qualifies_for_esig()
        })
        .collect()
}

/// List every service currently granted as a qualified timestamp service (`TSA/QTST`) as of `now`.
pub fn qualified_timestamp_services(list: &TrustedList, now: OffsetDateTime) -> Vec<&TrustService> {
    list.services()
        .filter(|s| s.is_tsa_qtst() && s.is_granted() && s.is_effective_at(now))
        .collect()
}

/// A Trusted List client that ties a [`TslSource`] to a validity-window [`CachedTsl`] and answers
/// the qualified-status query, re-fetching only when the cache is stale (SIG-10..13).
#[derive(Debug, Clone)]
pub struct TslClient<S: TslSource> {
    source: S,
    cache: Option<CachedTsl>,
}

impl<S: TslSource> TslClient<S> {
    /// Build a client over `source` with an empty cache.
    pub fn new(source: S) -> Self {
        Self {
            source,
            cache: None,
        }
    }

    /// The currently-cached list, if any has been fetched.
    pub fn cached(&self) -> Option<&CachedTsl> {
        self.cache.as_ref()
    }

    /// Fetch and parse the list unconditionally, replacing the cache with an entry stamped `now`.
    ///
    /// After parsing, the list's XML-DSig signature is validated (SIG-11, audit t41/C2). The
    /// validation result is stored on the cache entry and consulted by
    /// [`is_qualified_for_esig`](Self::is_qualified_for_esig). A signature failure does NOT
    /// error here — the parsed list is still cached so the caller can inspect it; but the
    /// qualified-status query downgrades `Granted` to `Unknown` when the signature did not verify.
    pub fn refresh(&mut self, now: OffsetDateTime) -> Result<(), TslError> {
        let bytes = self.source.fetch()?;
        let list = parse_tsl(&bytes)?;
        let signature_valid = crate::source::validate_tsl_signature(&bytes).is_ok();
        self.cache = Some(CachedTsl::with_signature_valid(list, now, signature_valid));
        Ok(())
    }

    /// Ensure the cache holds a list that is fresh as of `now`, fetching if it is empty or stale.
    pub fn ensure_fresh(&mut self, now: OffsetDateTime) -> Result<(), TslError> {
        let stale = self.cache.as_ref().is_none_or(|c| c.is_stale(now));
        if stale {
            self.refresh(now)?;
        }
        Ok(())
    }

    /// Resolve the qualified-for-e-signatures status of `issuer_cert_der` as of `now`, refreshing
    /// the cache first if needed.
    ///
    /// **Security (audit t41/C2):** if the list's XML-DSig signature did not verify at fetch
    /// time, [`QualifiedStatus::Granted`] is downgraded to [`QualifiedStatus::Unknown`]. A list
    /// whose authenticity cannot be confirmed MUST NOT be the basis for trusting a certificate.
    /// [`QualifiedStatus::Withdrawn`] is reported as-is (the issuer is on the unverified list but
    /// not currently qualified — still useful as an advisory).
    pub fn is_qualified_for_esig(
        &mut self,
        issuer_cert_der: &[u8],
        now: OffsetDateTime,
    ) -> Result<QualifiedStatus, TslError> {
        self.ensure_fresh(now)?;
        let cache = self
            .cache
            .as_ref()
            .expect("cache populated by ensure_fresh");
        let list = cache.list();
        let raw = resolve_esig_status(list, issuer_cert_der, now);
        // Signature gate: refuse to vouch for an issuer when the list is not authenticated.
        Ok(match (raw, cache.signature_valid()) {
            (QualifiedStatus::Granted, false) => QualifiedStatus::Unknown,
            (other, _) => other,
        })
    }

    /// Resolve whether `tsa_cert_der` identifies a currently-granted qualified timestamp service
    /// (`TSA/QTST`) as of `now`, refreshing the cache first if needed.
    ///
    /// As with [`Self::is_qualified_for_esig`], `Granted` is downgraded to `Unknown` when the TSL
    /// XML-DSig signature did not verify. An unauthenticated TSL is not used to vouch for TSA
    /// qualified status.
    pub fn is_qualified_timestamp_service(
        &mut self,
        tsa_cert_der: &[u8],
        now: OffsetDateTime,
    ) -> Result<QualifiedStatus, TslError> {
        self.ensure_fresh(now)?;
        let cache = self
            .cache
            .as_ref()
            .expect("cache populated by ensure_fresh");
        let raw = resolve_qtst_status(cache.list(), tsa_cert_der, now);
        Ok(match (raw, cache.signature_valid()) {
            (QualifiedStatus::Granted, false) => QualifiedStatus::Unknown,
            (other, _) => other,
        })
    }

    /// Resolve detailed QTST status and DER trust anchors, refreshing the cache first if needed.
    ///
    /// If the cached TSL XML-DSig signature did not verify, `Granted` is downgraded to `Unknown`
    /// and no trust anchors are returned. The unauthenticated matches remain visible for
    /// diagnostics only.
    pub fn qtst_match_details(
        &mut self,
        tsa_cert_der: &[u8],
        now: OffsetDateTime,
    ) -> Result<QtstMatchDetails, TslError> {
        self.ensure_fresh(now)?;
        let cache = self
            .cache
            .as_ref()
            .expect("cache populated by ensure_fresh");
        let mut details = resolve_qtst_match_details(cache.list(), tsa_cert_der, now);
        details.authenticated = cache.signature_valid();
        if details.status == QualifiedStatus::Granted && !cache.signature_valid() {
            details.status = QualifiedStatus::Unknown;
            details.trust_anchor_ders.clear();
        }
        Ok(details)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::parse::{
        FOR_ESIGNATURES, LocalizedText, SVCTYPE_CA_QC, SVCTYPE_TSA_QTST, ServiceStatus,
        TrustServiceProvider, parse_tsl,
    };

    const FIXTURE: &[u8] = include_bytes!("../fixtures/pt-tsl-sample.xml");
    const NOW: OffsetDateTime = datetime!(2026-07-06 12:00:00 UTC);
    // The SubjectKeyIdentifier of the fixture's MULTICERT CA (openssl: 84:B7:...:A6).
    const MULTICERT_SKI: [u8; 20] = [
        0x84, 0xB7, 0x8A, 0x44, 0x99, 0xDC, 0x5F, 0xA7, 0x69, 0x17, 0x5C, 0x6B, 0x8B, 0xA3, 0x2B,
        0x9B, 0x4D, 0x85, 0x28, 0xA6,
    ];

    fn multicert_cert() -> Vec<u8> {
        let list = parse_tsl(FIXTURE).unwrap();
        list.services()
            .flat_map(|s| s.digital_identities.iter())
            .find_map(|id| match id {
                DigitalIdentity::Certificate(der) => Some(der.clone()),
                _ => None,
            })
            .expect("fixture has a certificate")
    }

    fn list_with_identity(id: DigitalIdentity, starting: Option<OffsetDateTime>) -> TrustedList {
        list_with_service(
            id,
            SVCTYPE_CA_QC,
            starting,
            vec![FOR_ESIGNATURES.to_owned()],
        )
    }

    fn list_with_service(
        id: DigitalIdentity,
        service_type: &str,
        starting: Option<OffsetDateTime>,
        additional_service_info: Vec<String>,
    ) -> TrustedList {
        TrustedList {
            scheme_operator_name: String::new(),
            scheme_operator_names: Vec::new(),
            scheme_name: String::new(),
            scheme_names: Vec::new(),
            scheme_territory: "PT".to_owned(),
            sequence_number: None,
            issue_date_time: None,
            next_update: None,
            other_tsl_pointers: Vec::new(),
            providers: vec![TrustServiceProvider {
                name: "p".to_owned(),
                names: vec![LocalizedText {
                    lang: Some("en".to_owned()),
                    value: "p".to_owned(),
                }],
                trade_names: Vec::new(),
                localized_trade_names: Vec::new(),
                information_uris: Vec::new(),
                services: vec![TrustService {
                    service_type: service_type.to_owned(),
                    name: "svc".to_owned(),
                    names: vec![LocalizedText {
                        lang: Some("en".to_owned()),
                        value: "svc".to_owned(),
                    }],
                    status: ServiceStatus::Granted,
                    status_starting_time: starting,
                    status_starting_time_raw: starting.map(format_time_for_test),
                    digital_identities: vec![id],
                    additional_service_info,
                    service_supply_points: Vec::new(),
                    history: Vec::new(),
                }],
            }],
        }
    }

    fn format_time_for_test(t: OffsetDateTime) -> String {
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }

    #[test]
    fn extracts_subject_key_identifier() {
        let cert = multicert_cert();
        let parsed = x509_cert::Certificate::from_der(&cert).unwrap();
        assert_eq!(ski_of(&parsed).as_deref(), Some(&MULTICERT_SKI[..]));
    }

    #[test]
    fn matches_issuer_by_ski_only() {
        // A service identified solely by the issuer's SKI (no full cert) still matches.
        let list = list_with_identity(DigitalIdentity::SubjectKeyId(MULTICERT_SKI.to_vec()), None);
        assert_eq!(
            resolve_esig_status(&list, &multicert_cert(), NOW),
            QualifiedStatus::Granted
        );
    }

    #[test]
    fn matches_issuer_by_subject_name_only() {
        let cert = multicert_cert();
        let subject = x509_cert::Certificate::from_der(&cert)
            .unwrap()
            .tbs_certificate
            .subject
            .to_string();
        let list = list_with_identity(DigitalIdentity::SubjectName(subject), None);
        assert_eq!(
            resolve_esig_status(&list, &cert, NOW),
            QualifiedStatus::Granted
        );
    }

    #[test]
    fn granted_but_not_yet_effective_is_withdrawn() {
        // Matches the issuer, granted and for e-sig, but the status only starts in the future.
        let future = datetime!(2030-01-01 0:00 UTC);
        let list = list_with_identity(
            DigitalIdentity::SubjectKeyId(MULTICERT_SKI.to_vec()),
            Some(future),
        );
        assert_eq!(
            resolve_esig_status(&list, &multicert_cert(), NOW),
            QualifiedStatus::Withdrawn
        );
    }

    #[test]
    fn resolves_granted_qualified_timestamp_service() {
        let list = list_with_service(
            DigitalIdentity::Certificate(b"tsa-cert".to_vec()),
            SVCTYPE_TSA_QTST,
            None,
            Vec::new(),
        );

        assert_eq!(
            resolve_qtst_status(&list, b"tsa-cert", NOW),
            QualifiedStatus::Granted
        );
        assert_eq!(qualified_timestamp_services(&list, NOW).len(), 1);
        assert_eq!(qualified_esig_services(&list, NOW).len(), 0);
    }

    #[test]
    fn resolves_qtst_match_details_with_anchors() {
        let list = list_with_service(
            DigitalIdentity::Certificate(b"tsa-cert".to_vec()),
            SVCTYPE_TSA_QTST,
            None,
            Vec::new(),
        );

        let details = resolve_qtst_match_details(&list, b"tsa-cert", NOW);
        assert_eq!(details.status, QualifiedStatus::Granted);
        assert_eq!(details.trust_anchor_ders, vec![b"tsa-cert".to_vec()]);
        assert_eq!(details.matches.len(), 1);
        assert!(details.matches[0].granted_and_effective);
    }
}
