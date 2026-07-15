//! Trust-anchor store aggregated from an authenticated Trusted List — **Phase-A frozen seam
//! (wp26 E5)**.
//!
//! Once a member-state TSL has been authenticated (its XML-DSig verified against a certificate
//! carried by a pointer inside a verified LOTL, wp26 §2.1), the CA/QC and TSA/QTST services it
//! lists that are *granted and effective* are the trust anchors an end-entity signer must chain to.
//! This module extracts those anchors into a [`TslTrustStore`] that the cert-path builder
//! ([`crate::certpath`]) and the signing crate consume.
//!
//! Phase A freezes the public API; **E5 replaces the stub bodies** with real aggregation over
//! [`crate::parse::TrustedList`].

use time::OffsetDateTime;

use crate::parse::{DigitalIdentity, TrustedList};

/// Trust anchors aggregated from an authenticated Trusted List.
///
/// `authenticated`/`stale` carry the provenance of the list the anchors came from so downstream
/// trust decisions never silently upgrade an unverified or stale list (fail-closed, wp26 §2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TslTrustStore {
    /// DER-encoded certificates of granted+effective CA/QC (qualified-certificate issuer) services —
    /// the anchors an end-entity **signing** certificate is path-built to.
    pub qc_anchors: Vec<Vec<u8>>,
    /// DER-encoded certificates of granted+effective TSA/QTST (qualified timestamp) services — the
    /// anchors a **timestamp** signer is path-built to.
    pub qtst_anchors: Vec<Vec<u8>>,
    /// Whether the list these anchors came from was cryptographically authenticated (LOTL-derived
    /// signer verification). Anchors from an unauthenticated list MUST NOT ground a trust decision.
    pub authenticated: bool,
    /// Whether the list these anchors came from was served from a stale cache (fetch failed, fell
    /// back to a previously-cached copy). Stale anchors may be reported but flagged.
    pub stale: bool,
}

impl TslTrustStore {
    /// Aggregate the granted+effective CA/QC and TSA/QTST anchors from `list` as of `now`.
    ///
    /// `authenticated` records whether `list` itself was authenticated (its own signature verified
    /// via the LOTL-derived path); `stale` records whether it came from a fallback cache. Both are
    /// carried through onto the returned store unchanged.
    ///
    /// **Phase-A stub (wp26 E5 owns the implementation).**
    pub fn from_list(
        list: &TrustedList,
        authenticated: bool,
        stale: bool,
        now: OffsetDateTime,
    ) -> Self {
        let mut qc_anchors: Vec<Vec<u8>> = Vec::new();
        let mut qtst_anchors: Vec<Vec<u8>> = Vec::new();

        for service in list.services() {
            // Only currently granted services whose status is already in effect ground trust.
            // A withdrawn/revoked service, or one whose grant starts in the future, contributes
            // no anchors (fail-closed, wp26 §2.1).
            if !(service.is_granted() && service.is_effective_at(now)) {
                continue;
            }
            // A service may carry a subject name and/or a subject-key-id alongside (or instead of)
            // a full certificate; only a full DER certificate can serve as a path-build anchor.
            let certs = service
                .digital_identities
                .iter()
                .filter_map(|identity| match identity {
                    DigitalIdentity::Certificate(der) => Some(der),
                    DigitalIdentity::SubjectName(_) | DigitalIdentity::SubjectKeyId(_) => None,
                });

            if service.is_ca_qc() {
                for der in certs {
                    push_unique(&mut qc_anchors, der);
                }
            } else if service.is_tsa_qtst() {
                for der in certs {
                    push_unique(&mut qtst_anchors, der);
                }
            }
        }

        Self {
            qc_anchors,
            qtst_anchors,
            authenticated,
            stale,
        }
    }

    /// Whether the store carries no anchors at all (nothing to chain to — fail-closed).
    pub fn is_empty(&self) -> bool {
        self.qc_anchors.is_empty() && self.qtst_anchors.is_empty()
    }
}

/// Append `der` to `slot` unless an identical DER encoding is already present. Real lists can list
/// the same CA certificate under several services (e.g. for e-signatures and e-seals), and a single
/// anchor is all the path builder needs.
fn push_unique(slot: &mut Vec<Vec<u8>>, der: &[u8]) {
    if !slot.iter().any(|existing| existing.as_slice() == der) {
        slot.push(der.to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{
        LocalizedText, SVCTYPE_CA_QC, SVCTYPE_TSA_QTST, ServiceStatus, TrustService,
        TrustServiceProvider,
    };

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).expect("valid unix time")
    }

    /// A trust service of `service_type` with the given `status`, carrying `cert` as its sole
    /// digital identity and taking effect at `starting_time`.
    fn service(
        service_type: &str,
        status: ServiceStatus,
        cert: &[u8],
        starting_time: Option<OffsetDateTime>,
    ) -> TrustService {
        TrustService {
            service_type: service_type.to_owned(),
            name: "svc".to_owned(),
            names: vec![LocalizedText {
                lang: Some("en".to_owned()),
                value: "svc".to_owned(),
            }],
            status,
            status_starting_time: starting_time,
            status_starting_time_raw: None,
            digital_identities: vec![DigitalIdentity::Certificate(cert.to_vec())],
            additional_service_info: Vec::new(),
            service_supply_points: Vec::new(),
            history: Vec::new(),
        }
    }

    fn list_with(services: Vec<TrustService>) -> TrustedList {
        TrustedList {
            scheme_operator_name: "op".to_owned(),
            scheme_operator_names: Vec::new(),
            scheme_name: "scheme".to_owned(),
            scheme_names: Vec::new(),
            scheme_territory: "PT".to_owned(),
            sequence_number: None,
            issue_date_time: None,
            next_update: None,
            other_tsl_pointers: Vec::new(),
            providers: vec![TrustServiceProvider {
                name: "tsp".to_owned(),
                names: Vec::new(),
                trade_names: Vec::new(),
                localized_trade_names: Vec::new(),
                information_uris: Vec::new(),
                services,
            }],
        }
    }

    #[test]
    fn collects_only_granted_effective_ca_qc_certs() {
        let now = at(1_750_000_000);
        let granted = b"granted-ca-qc-der";
        let withdrawn = b"withdrawn-ca-qc-der";
        let list = list_with(vec![
            service(SVCTYPE_CA_QC, ServiceStatus::Granted, granted, None),
            service(SVCTYPE_CA_QC, ServiceStatus::Withdrawn, withdrawn, None),
        ]);

        let store = TslTrustStore::from_list(&list, true, false, now);

        assert_eq!(store.qc_anchors, vec![granted.to_vec()]);
        assert!(store.qtst_anchors.is_empty());
        assert!(!store.is_empty());
    }

    #[test]
    fn separates_qc_from_qtst_anchors() {
        let now = at(1_750_000_000);
        let qc = b"ca-qc-der";
        let qtst = b"tsa-qtst-der";
        let list = list_with(vec![
            service(SVCTYPE_CA_QC, ServiceStatus::Granted, qc, None),
            service(SVCTYPE_TSA_QTST, ServiceStatus::Granted, qtst, None),
        ]);

        let store = TslTrustStore::from_list(&list, true, false, now);

        assert_eq!(store.qc_anchors, vec![qc.to_vec()]);
        assert_eq!(store.qtst_anchors, vec![qtst.to_vec()]);
    }

    #[test]
    fn excludes_services_not_yet_effective() {
        let now = at(1_750_000_000);
        let future = b"future-ca-qc-der";
        let list = list_with(vec![service(
            SVCTYPE_CA_QC,
            ServiceStatus::Granted,
            future,
            Some(at(1_760_000_000)),
        )]);

        let store = TslTrustStore::from_list(&list, true, false, now);

        assert!(store.qc_anchors.is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn dedups_identical_der_across_services() {
        let now = at(1_750_000_000);
        let cert = b"shared-ca-qc-der";
        let list = list_with(vec![
            service(SVCTYPE_CA_QC, ServiceStatus::Granted, cert, None),
            service(SVCTYPE_CA_QC, ServiceStatus::Granted, cert, None),
        ]);

        let store = TslTrustStore::from_list(&list, true, false, now);

        assert_eq!(store.qc_anchors, vec![cert.to_vec()]);
    }

    #[test]
    fn carries_authenticated_and_stale_through_unchanged() {
        let now = at(1_750_000_000);
        let list = list_with(vec![service(
            SVCTYPE_CA_QC,
            ServiceStatus::Granted,
            b"der",
            None,
        )]);

        let store = TslTrustStore::from_list(&list, false, true, now);
        assert!(!store.authenticated);
        assert!(store.stale);

        let store = TslTrustStore::from_list(&list, true, false, now);
        assert!(store.authenticated);
        assert!(!store.stale);
    }
}
