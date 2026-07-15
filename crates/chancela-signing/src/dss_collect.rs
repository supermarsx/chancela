//! DSS evidence collector — assemble a complete PAdES `/DSS` payload from a validated chain.
//!
//! Given a validated signer chain (leaf-first, anchor-last, as produced by
//! `chancela_tsl::certpath::build_path`) plus a live revocation provider, [`collect_dss_evidence`]
//! assembles a complete [`DssEvidence`] — **every** chain certificate plus **one** validated
//! revocation response per issuing link — ready for PAdES B-LT `/DSS` embedding so the signature
//! verifies long-term offline.
//!
//! ## Assembly rule
//! `chain_der` is `[leaf, intermediate…, anchor]`. For each issuing link
//! `(signer = chain_der[i], issuer = chain_der[i + 1])`, `i` in `0..len-1`, we ask the provider for
//! one validated revocation response (OCSP preferred, CRL otherwise — `collect_for_signer` already
//! encodes that preference) and merge its DSS material into the aggregate. Every certificate in the
//! chain is embedded regardless.
//!
//! ## Anchor exemption
//! A **self-issued** certificate (its subject Distinguished Name equals its issuer DN, i.e. a
//! self-signed trust anchor) is trusted by inclusion in the trusted list, not by revocation status,
//! and typically publishes no CRL/OCSP endpoint covering itself; such a certificate is skipped when
//! it appears in *signer* position. In a well-formed leaf-first/anchor-last chain the only
//! self-issued certificate is the final anchor at index `len-1`, which is never a signer
//! (`i` ranges over `0..len-1`) — so in practice **every** real issuing link IS revocation-checked
//! (e.g. a `[leaf, intermediate, root]` chain checks both the leaf→intermediate and
//! intermediate→root links) and only the anchor's own revocation is exempt. The self-issued guard
//! additionally protects against a caller passing a root in a non-terminal position.
//!
//! ## Fail-closed
//! A B-LT DSS must carry revocation for the chain, so any *non-exempt* link whose revocation cannot
//! be obtained aborts the whole assembly with an error rather than emitting an incomplete DSS that
//! merely looks complete. A chain shorter than two certificates (no issuer) is rejected, as is an
//! assembly that produced no revocation material at all.
//!
//! ## Determinism
//! Output byte order is stable so PAdES embedding and its tests are reproducible: certificates are
//! emitted in chain order (leaf-first) followed by any responder certificates discovered per link
//! in link order, and revocation responses in link order. All three vectors are de-duplicated by
//! SHA-256 with first-seen order preserved — mirroring how `chancela_pades::dss` de-duplicates
//! embedded streams — so identical DER bytes never appear twice and repeated runs are byte-identical.

use std::collections::HashSet;

use der::Decode;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_cert::certificate::Certificate;

use crate::DssEvidence;
use crate::SigningError;
use crate::revocation::{RevocationEvidenceProvider, RevocationHttpTransport};

/// Assemble a complete [`DssEvidence`] (every chain certificate + one validated revocation response
/// per issuing link) for a validated signer chain, ready for PAdES `/DSS` embedding. `chain_der` is
/// leaf-first, anchor-last (as produced by `chancela_tsl::certpath::build_path`).
///
/// Returns an error when the chain has fewer than two certificates (no issuer to build long-term
/// material against), when any non–anchor-exempt link's revocation cannot be validated (fail-closed
/// — never emit a DSS that silently omits a link's revocation), or when the assembled DSS carries no
/// revocation material at all. See the module documentation for the full assembly rule, anchor
/// exemption, fail-closed semantics, and determinism guarantees.
pub fn collect_dss_evidence<T: RevocationHttpTransport>(
    chain_der: &[Vec<u8>],
    provider: &RevocationEvidenceProvider<T>,
    validation_time: OffsetDateTime,
) -> Result<DssEvidence, SigningError> {
    // A B-LT DSS needs at least one issuing link (a leaf plus its issuer). An empty chain or a
    // lone leaf cannot carry long-term revocation material, so fail closed.
    if chain_der.len() < 2 {
        return Err(SigningError::MissingIssuerCertificate);
    }

    let mut cert_seen = HashSet::new();
    let mut certificates = Vec::new();
    let mut ocsp_seen = HashSet::new();
    let mut ocsp_responses = Vec::new();
    let mut crl_seen = HashSet::new();
    let mut crls = Vec::new();

    // 1. Embed the full chain (leaf-first) so the signature validates offline.
    for cert in chain_der {
        push_unique(&mut cert_seen, &mut certificates, cert);
    }

    // 2. Collect one validated revocation response per issuing link and merge its DSS material
    //    (responder certs + OCSP/CRL) into the aggregate.
    for window in chain_der.windows(2) {
        let signer = &window[0];
        let issuer = &window[1];

        // Anchor exemption: a self-issued (self-signed) trust anchor publishes no revocation of
        // itself and is trusted by list inclusion. Skip it in signer position; see module docs.
        if is_self_issued(signer) {
            continue;
        }

        let evidence = provider
            .collect_for_signer(signer, issuer, validation_time)
            .map_err(|err| SigningError::TrustedList(err.to_string()))?;

        for cert in &evidence.dss.certificates {
            push_unique(&mut cert_seen, &mut certificates, cert);
        }
        for ocsp in &evidence.dss.ocsp_responses {
            push_unique(&mut ocsp_seen, &mut ocsp_responses, ocsp);
        }
        for crl in &evidence.dss.crls {
            push_unique(&mut crl_seen, &mut crls, crl);
        }
    }

    let dss = DssEvidence {
        certificates,
        ocsp_responses,
        crls,
    };

    // Fail-closed: a B-LT DSS must carry revocation. If every link was anchor-exempt (a degenerate
    // chain) no revocation was gathered — refuse rather than emit a certs-only DSS pretending to be
    // long-term complete.
    if !dss.has_revocation_evidence() {
        return Err(SigningError::TrustedList(
            "assembled DSS carries no revocation evidence for any chain link".to_string(),
        ));
    }

    Ok(dss)
}

/// Append `item` to `out` unless a byte-identical entry was already seen, tracking membership by
/// SHA-256 (mirroring `chancela_pades::dss` stream de-duplication). First-seen order is preserved,
/// keeping output byte order deterministic.
fn push_unique(seen: &mut HashSet<[u8; 32]>, out: &mut Vec<Vec<u8>>, item: &[u8]) {
    let digest: [u8; 32] = Sha256::digest(item).into();
    if seen.insert(digest) {
        out.push(item.to_vec());
    }
}

/// Whether `cert_der` is a self-issued (self-signed) trust anchor: its subject DN equals its issuer
/// DN. Undecodable DER is treated as *not* self-issued so the link is still attempted and the
/// provider surfaces the decode error (fail-closed).
fn is_self_issued(cert_der: &[u8]) -> bool {
    match Certificate::from_der(cert_der) {
        Ok(cert) => cert.tbs_certificate.subject == cert.tbs_certificate.issuer,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::time::{Duration as StdDuration, SystemTime};

    use der::asn1::{Any, BitString, Ia5String, Null, ObjectIdentifier, OctetString};
    use der::{Decode, Encode};
    use rsa::pkcs8::EncodePublicKey;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
    use sha1::Sha1;
    use sha2::{Digest, Sha256};
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use time::OffsetDateTime;
    use x509_cert::certificate::{Certificate, TbsCertificate, Version};
    use x509_cert::crl::{CertificateList, TbsCertList};
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::crl::CrlDistributionPoints;
    use x509_cert::ext::pkix::crl::dp::DistributionPoint;
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
    use x509_cert::ext::pkix::{AccessDescription, AuthorityInfoAccessSyntax};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};
    use x509_ocsp::{
        BasicOcspResponse, CertId, CertStatus, OcspGeneralizedTime, OcspResponse, ResponderId,
        ResponseData, SingleResponse, Version as OcspVersion,
    };

    use super::*;
    use crate::revocation::{
        RevocationError, RevocationFetchLimits, RevocationHttpResponse, RevocationHttpTransport,
    };

    const OID_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
    const OID_AUTHORITY_INFO_ACCESS: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
    const OID_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
    const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    const OID_SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    // --- Certificate / key minting helpers -------------------------------------------------------

    fn rsa_key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa key")
    }

    fn spki_of(key: &RsaPrivateKey) -> SubjectPublicKeyInfoOwned {
        let public = RsaPublicKey::from(key);
        SubjectPublicKeyInfoOwned::from_der(
            public.to_public_key_der().expect("spki der").as_bytes(),
        )
        .expect("spki")
    }

    fn rsa_sig_alg() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: OID_SHA256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        }
    }

    fn uri(value: &str) -> GeneralName {
        GeneralName::UniformResourceIdentifier(Ia5String::new(value).expect("ia5 uri"))
    }

    fn extension(oid: ObjectIdentifier, value: Vec<u8>) -> Extension {
        Extension {
            extn_id: oid,
            critical: false,
            extn_value: OctetString::new(value).expect("extension value"),
        }
    }

    fn crl_cdp_extension(url: &str) -> Extension {
        let cdp = CrlDistributionPoints(vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![uri(url)])),
            reasons: None,
            crl_issuer: None,
        }]);
        extension(OID_CRL_DISTRIBUTION_POINTS, cdp.to_der().expect("cdp der"))
    }

    fn ocsp_aia_extension(url: &str) -> Extension {
        let aia = AuthorityInfoAccessSyntax(vec![AccessDescription {
            access_method: OID_OCSP,
            access_location: uri(url),
        }]);
        extension(OID_AUTHORITY_INFO_ACCESS, aia.to_der().expect("aia der"))
    }

    /// Mint a certificate with an explicit subject and issuer (so self-issued vs. delegated can be
    /// controlled). The certificate signature is a placeholder — the revocation provider validates
    /// CRL/OCSP signatures against the issuer key, not the certificate chain signatures.
    fn make_cert(
        subject: &Name,
        issuer: &Name,
        key: &RsaPrivateKey,
        serial: &[u8],
        extensions: Vec<Extension>,
    ) -> Certificate {
        let sig_alg = rsa_sig_alg();
        Certificate {
            tbs_certificate: TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(serial).expect("serial"),
                signature: sig_alg.clone(),
                issuer: issuer.clone(),
                validity: Validity::from_now(StdDuration::from_secs(3600 * 24 * 365))
                    .expect("validity"),
                subject: subject.clone(),
                subject_public_key_info: spki_of(key),
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: if extensions.is_empty() {
                    None
                } else {
                    Some(extensions)
                },
            },
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&[0; 256]).expect("signature"),
        }
    }

    fn to_x509_time(dt: OffsetDateTime) -> Time {
        let secs = dt.unix_timestamp();
        assert!(secs >= 0, "test times are post-epoch");
        let system = SystemTime::UNIX_EPOCH + StdDuration::from_secs(secs as u64);
        Time::try_from(system).expect("x509 time")
    }

    fn to_ocsp_time(dt: OffsetDateTime) -> OcspGeneralizedTime {
        // `OcspGeneralizedTime: TryFrom<SystemTime>` is gated behind the x509-ocsp `std` feature
        // (not enabled here); go through `x509_cert::time::Time`, which has an unconditional `From`.
        OcspGeneralizedTime::from(to_x509_time(dt))
    }

    fn rsa_sign(key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
        let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
        digest_info.extend_from_slice(&Sha256::digest(message));
        key.sign(Pkcs1v15Sign::new_unprefixed(), &digest_info)
            .expect("rsa signature")
    }

    /// Build a DER CRL issued and signed by `issuer` covering none of the presented serials.
    fn build_good_crl(
        issuer: &Certificate,
        issuer_key: &RsaPrivateKey,
        now: OffsetDateTime,
    ) -> Vec<u8> {
        let sig_alg = rsa_sig_alg();
        let tbs = TbsCertList {
            version: x509_cert::certificate::Version::V2,
            signature: sig_alg.clone(),
            issuer: issuer.tbs_certificate.subject.clone(),
            this_update: to_x509_time(now - time::Duration::hours(1)),
            next_update: Some(to_x509_time(now + time::Duration::hours(24))),
            revoked_certificates: None,
            crl_extensions: None,
        };
        let signature = rsa_sign(issuer_key, &tbs.to_der().expect("tbs der"));
        CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&signature).expect("crl signature bits"),
        }
        .to_der()
        .expect("crl der")
    }

    /// Build the RFC 6960 `CertID` the provider will request for `(signer, issuer)` — must match
    /// `revocation::ocsp_cert_id` exactly so the SingleResponse is selected.
    fn cert_id_for(signer: &Certificate, issuer: &Certificate) -> CertId {
        CertId {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: OID_SHA1,
                parameters: Some(Null.into()),
            },
            issuer_name_hash: OctetString::new(
                Sha1::digest(
                    issuer
                        .tbs_certificate
                        .subject
                        .to_der()
                        .expect("subject der"),
                )
                .to_vec(),
            )
            .expect("name hash"),
            issuer_key_hash: OctetString::new(
                Sha1::digest(
                    issuer
                        .tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .raw_bytes(),
                )
                .to_vec(),
            )
            .expect("key hash"),
            serial_number: signer.tbs_certificate.serial_number.clone(),
        }
    }

    /// Build a good, issuer-signed (direct-responder) OCSP response for `signer` under `issuer`.
    fn build_good_ocsp(
        signer: &Certificate,
        issuer: &Certificate,
        issuer_key: &RsaPrivateKey,
        now: OffsetDateTime,
    ) -> Vec<u8> {
        let single = SingleResponse {
            cert_id: cert_id_for(signer, issuer),
            cert_status: CertStatus::Good(Null),
            this_update: to_ocsp_time(now - time::Duration::hours(1)),
            next_update: Some(to_ocsp_time(now + time::Duration::hours(24))),
            single_extensions: None,
        };
        let tbs = ResponseData {
            version: OcspVersion::V1,
            responder_id: ResponderId::ByName(issuer.tbs_certificate.subject.clone()),
            produced_at: to_ocsp_time(now - time::Duration::minutes(30)),
            responses: vec![single],
            response_extensions: None,
        };
        let signature = rsa_sign(issuer_key, &tbs.to_der().expect("tbs response data der"));
        let basic = BasicOcspResponse {
            tbs_response_data: tbs,
            signature_algorithm: rsa_sig_alg(),
            signature: BitString::from_bytes(&signature).expect("ocsp signature bits"),
            certs: None,
        };
        OcspResponse::successful(basic)
            .expect("ocsp response")
            .to_der()
            .expect("ocsp der")
    }

    // --- Mock transports -------------------------------------------------------------------------

    /// Serves a fixed OCSP response for any POST and refuses CRL fetches.
    #[derive(Clone)]
    struct StaticOcspTransport {
        ocsp_der: Vec<u8>,
    }

    impl RevocationHttpTransport for StaticOcspTransport {
        fn get_crl(
            &self,
            _url: &str,
            _limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            panic!("OCSP test exposes no CRL endpoint")
        }

        fn post_ocsp(
            &self,
            _url: &str,
            _request_der: &[u8],
            _limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            Ok(RevocationHttpResponse {
                status: 200,
                body: self.ocsp_der.clone(),
            })
        }
    }

    /// Serves CRLs keyed by request URL and refuses OCSP fetches.
    struct MapCrlTransport {
        crls: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl RevocationHttpTransport for MapCrlTransport {
        fn get_crl(
            &self,
            url: &str,
            _limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            let crls = self.crls.lock().expect("crl map");
            match crls.get(url) {
                Some(body) => Ok(RevocationHttpResponse {
                    status: 200,
                    body: body.clone(),
                }),
                None => Err(RevocationError::HttpStatus {
                    url: url.to_string(),
                    status: 404,
                }),
            }
        }

        fn post_ocsp(
            &self,
            _url: &str,
            _request_der: &[u8],
            _limits: &RevocationFetchLimits,
        ) -> Result<RevocationHttpResponse, RevocationError> {
            panic!("CRL test exposes no OCSP endpoint")
        }
    }

    // --- Scenario builders -----------------------------------------------------------------------

    /// A 2-cert chain `[leaf, issuer]` where `leaf` advertises an OCSP responder, plus a provider
    /// backed by a good direct-responder OCSP answer.
    fn two_cert_ocsp_scenario(
        now: OffsetDateTime,
    ) -> (
        Vec<Vec<u8>>,
        RevocationEvidenceProvider<StaticOcspTransport>,
    ) {
        let issuer_key = rsa_key();
        let issuer_name = Name::from_str("CN=Encosto Estrategico Issuer CA").expect("issuer name");
        let issuer = make_cert(&issuer_name, &issuer_name, &issuer_key, &[0x0a], Vec::new());

        let leaf_key = rsa_key();
        let leaf_name = Name::from_str("CN=Encosto Estrategico Signer").expect("leaf name");
        let leaf = make_cert(
            &leaf_name,
            &issuer_name,
            &leaf_key,
            &[0x12, 0x34],
            vec![ocsp_aia_extension("http://ocsp.example/responder")],
        );

        let ocsp_der = build_good_ocsp(&leaf, &issuer, &issuer_key, now);
        let provider = RevocationEvidenceProvider::new(
            StaticOcspTransport { ocsp_der },
            RevocationFetchLimits::default(),
        );

        let chain = vec![
            leaf.to_der().expect("leaf der"),
            issuer.to_der().expect("issuer der"),
        ];
        (chain, provider)
    }

    /// A 3-cert chain `[leaf, intermediate, root]` (root self-signed), each non-root cert
    /// advertising a distinct CRL distribution point, plus a provider backed by good CRLs for both
    /// issuing links.
    fn three_cert_crl_scenario(
        now: OffsetDateTime,
    ) -> (Vec<Vec<u8>>, RevocationEvidenceProvider<MapCrlTransport>) {
        let root_key = rsa_key();
        let root_name = Name::from_str("CN=Encosto Estrategico Root CA").expect("root name");
        let root = make_cert(&root_name, &root_name, &root_key, &[0x01], Vec::new());

        let int_key = rsa_key();
        let int_name = Name::from_str("CN=Encosto Estrategico Intermediate CA").expect("int name");
        let intermediate = make_cert(
            &int_name,
            &root_name,
            &int_key,
            &[0x02],
            vec![crl_cdp_extension("http://crl.example/intermediate.crl")],
        );

        let leaf_key = rsa_key();
        let leaf_name = Name::from_str("CN=Encosto Estrategico Leaf").expect("leaf name");
        let leaf = make_cert(
            &leaf_name,
            &int_name,
            &leaf_key,
            &[0x03],
            vec![crl_cdp_extension("http://crl.example/leaf.crl")],
        );

        // leaf link: CRL issued by the intermediate; intermediate link: CRL issued by the root.
        let leaf_crl = build_good_crl(&intermediate, &int_key, now);
        let int_crl = build_good_crl(&root, &root_key, now);

        let mut crls = HashMap::new();
        crls.insert("http://crl.example/leaf.crl".to_string(), leaf_crl);
        crls.insert("http://crl.example/intermediate.crl".to_string(), int_crl);
        let provider = RevocationEvidenceProvider::new(
            MapCrlTransport {
                crls: Mutex::new(crls),
            },
            RevocationFetchLimits::default(),
        );

        let chain = vec![
            leaf.to_der().expect("leaf der"),
            intermediate.to_der().expect("intermediate der"),
            root.to_der().expect("root der"),
        ];
        (chain, provider)
    }

    // --- Tests -----------------------------------------------------------------------------------

    #[test]
    fn two_cert_chain_with_good_ocsp_carries_both_certs_and_one_ocsp() {
        let now = OffsetDateTime::now_utc();
        let (chain, provider) = two_cert_ocsp_scenario(now);

        let dss = collect_dss_evidence(&chain, &provider, now).expect("assembled DSS");

        assert_eq!(dss.certificates.len(), 2, "leaf + issuer embedded");
        assert_eq!(dss.ocsp_responses.len(), 1, "one OCSP for the single link");
        assert!(dss.crls.is_empty(), "OCSP was preferred, no CRL");
        assert!(dss.has_revocation_evidence());
        // Both chain certs are present verbatim.
        assert!(dss.certificates.contains(&chain[0]));
        assert!(dss.certificates.contains(&chain[1]));
    }

    #[test]
    fn three_cert_chain_covers_both_links_with_deduped_certs() {
        let now = OffsetDateTime::now_utc();
        let (chain, provider) = three_cert_crl_scenario(now);

        let dss = collect_dss_evidence(&chain, &provider, now).expect("assembled DSS");

        assert_eq!(
            dss.certificates.len(),
            3,
            "leaf + intermediate + root, deduped"
        );
        assert_eq!(dss.crls.len(), 2, "one CRL per issuing link");
        assert!(dss.ocsp_responses.is_empty());
        assert!(dss.has_revocation_evidence());

        // No duplicate certificate DER despite the intermediate appearing as both a link's signer
        // and its predecessor's issuer.
        let mut deduped = dss.certificates.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            dss.certificates.len(),
            "certificates are unique"
        );
    }

    #[test]
    fn link_without_obtainable_revocation_fails_closed() {
        let now = OffsetDateTime::now_utc();
        // Leaf advertises no CRL/OCSP endpoint at all -> the provider cannot validate revocation.
        let issuer_key = rsa_key();
        let issuer_name = Name::from_str("CN=Encosto Estrategico Issuer CA").expect("issuer name");
        let issuer = make_cert(&issuer_name, &issuer_name, &issuer_key, &[0x0a], Vec::new());
        let leaf_key = rsa_key();
        let leaf_name = Name::from_str("CN=Encosto Estrategico Signer").expect("leaf name");
        let leaf = make_cert(&leaf_name, &issuer_name, &leaf_key, &[0x12], Vec::new());
        let chain = vec![
            leaf.to_der().expect("leaf der"),
            issuer.to_der().expect("issuer der"),
        ];
        let provider = RevocationEvidenceProvider::new(
            StaticOcspTransport {
                ocsp_der: Vec::new(),
            },
            RevocationFetchLimits::default(),
        );

        let err = collect_dss_evidence(&chain, &provider, now).unwrap_err();
        assert!(
            matches!(err, SigningError::TrustedList(_)),
            "unobtainable revocation must fail closed, got {err:?}"
        );
    }

    #[test]
    fn chain_shorter_than_two_certificates_is_rejected() {
        let now = OffsetDateTime::now_utc();
        let (chain, provider) = two_cert_ocsp_scenario(now);

        let empty: Vec<Vec<u8>> = Vec::new();
        assert!(matches!(
            collect_dss_evidence(&empty, &provider, now).unwrap_err(),
            SigningError::MissingIssuerCertificate
        ));

        let leaf_only = vec![chain[0].clone()];
        assert!(matches!(
            collect_dss_evidence(&leaf_only, &provider, now).unwrap_err(),
            SigningError::MissingIssuerCertificate
        ));
    }

    #[test]
    fn assembly_is_deterministic_across_runs() {
        let now = OffsetDateTime::now_utc();
        let (chain, provider) = three_cert_crl_scenario(now);

        let first = collect_dss_evidence(&chain, &provider, now).expect("first run");
        let second = collect_dss_evidence(&chain, &provider, now).expect("second run");

        // Byte-identical across runs: same certificates, OCSPs and CRLs in the same order.
        assert_eq!(first, second);
        assert_eq!(first.certificates, second.certificates);
        assert_eq!(first.crls, second.crls);
    }
}
