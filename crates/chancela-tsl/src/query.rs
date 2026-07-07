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

/// Whether a certificate issuer is currently a qualified QTSP for e-signatures per the TSL.
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

/// The OID of the X.509 Subject Key Identifier extension (2.5.29.14).
const SKI_OID: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.14");

/// Identifying material extracted from an issuer certificate, used to match it against a trust
/// service's digital identities. Certificate-DER equality is the strong match; SKI and subject
/// name are fallbacks for lists that publish only an identifier.
struct IssuerId<'a> {
    der: &'a [u8],
    ski: Option<Vec<u8>>,
    subject: Option<String>,
}

impl<'a> IssuerId<'a> {
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
    let issuer = IssuerId::from_der(issuer_cert_der);
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

/// List every service currently granted and qualified for e-signatures as of `now` (SIG-12
/// discovery/listing).
pub fn qualified_esig_services(list: &TrustedList, now: OffsetDateTime) -> Vec<&TrustService> {
    list.services()
        .filter(|s| {
            s.is_ca_qc() && s.is_granted() && s.is_effective_at(now) && s.qualifies_for_esig()
        })
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
    pub fn refresh(&mut self, now: OffsetDateTime) -> Result<(), TslError> {
        let bytes = self.source.fetch()?;
        let list = parse_tsl(&bytes)?;
        self.cache = Some(CachedTsl::new(list, now));
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
    pub fn is_qualified_for_esig(
        &mut self,
        issuer_cert_der: &[u8],
        now: OffsetDateTime,
    ) -> Result<QualifiedStatus, TslError> {
        self.ensure_fresh(now)?;
        let list = self
            .cache
            .as_ref()
            .expect("cache populated by ensure_fresh")
            .list();
        Ok(resolve_esig_status(list, issuer_cert_der, now))
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::parse::{
        FOR_ESIGNATURES, SVCTYPE_CA_QC, ServiceStatus, TrustServiceProvider, parse_tsl,
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
        TrustedList {
            scheme_territory: "PT".to_owned(),
            sequence_number: None,
            issue_date_time: None,
            next_update: None,
            providers: vec![TrustServiceProvider {
                name: "p".to_owned(),
                services: vec![TrustService {
                    service_type: SVCTYPE_CA_QC.to_owned(),
                    name: "svc".to_owned(),
                    status: ServiceStatus::Granted,
                    status_starting_time: starting,
                    digital_identities: vec![id],
                    additional_service_info: vec![FOR_ESIGNATURES.to_owned()],
                }],
            }],
        }
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
}
