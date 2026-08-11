//! Fixture-based, fully offline tests for `chancela-tsl` (no network).
//!
//! Drives the public API against the bundled sample Portuguese Trusted List
//! (`fixtures/pt-tsl-sample.xml`) and an unlisted CA certificate (`fixtures/unlisted-ca.der`).
//! See `crates/chancela-tsl/TESTING.md`.

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration as StdDuration;

use chancela_tsl::parse::{FOR_ESEALS, FOR_ESIGNATURES, SVCTYPE_CA_QC};
use chancela_tsl::{
    BytesTslSource, DigitalIdentity, FileTslSource, QualifiedStatus, ServiceStatus, TrustedList,
    TslClient, TslError, TslTrustAnchors, parse_tsl, qualified_esig_services, resolve_esig_status,
    resolve_qtst_match_details, validate_tsl_signature, validate_tsl_signature_with_anchors,
};
use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use time::macros::datetime;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::{Certificate, TbsCertificate, Version};

/// A moment inside the fixture's validity window (issued 2026-01-15, next update 2026-07-15).
const NOW: OffsetDateTime = datetime!(2026-07-06 12:00:00 UTC);
/// A moment after the fixture's `NextUpdate` — the cache should be stale here.
const AFTER_NEXT_UPDATE: OffsetDateTime = datetime!(2026-08-01 00:00:00 UTC);

const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const C14N_10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const EXC_C14N_10: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const SHA256_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const ENVELOPED_SIGNATURE_TRANSFORM: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

struct SignedFixture {
    xml: Vec<u8>,
    signature_value: Vec<u8>,
    /// The DER of the certificate embedded in `<ds:KeyInfo>` — the anchor a well-configured
    /// deployment would pin for this list.
    signer_cert_der: Vec<u8>,
}

/// The trust anchors a well-configured deployment would hold for `fixture`: a pin of the exact
/// certificate the list is signed with.
fn anchors_for(fixture: &SignedFixture) -> TslTrustAnchors {
    TslTrustAnchors::new().with_cert_der(&fixture.signer_cert_der)
}

/// Validate a Trusted List's XML-DSig with **no** trust anchor configured — the hermetic
/// equivalent of the env entry point (`validate_tsl_signature`) in an unconfigured environment.
///
/// The structural, algorithm, digest, and signature-verification rejections these tests assert are
/// all decided *before* the trust-anchor gate (the anchor check is the final step of
/// `xmldsig::verify`), so passing an explicitly-empty anchor set is behaviourally identical to the
/// env entry point for every rejection case — while being immune to any ambient
/// `CHANCELA_TSL_TRUST_ANCHOR[_SHA256]` in the test runner's environment. Using the env entry point
/// here instead coupled these tests to the runner's environment: with an anchor env var set (a
/// legitimate deployment/dev-machine configuration) `from_env()` could return a different error and
/// flip the asserted variant, spuriously failing ~16 tests at once.
fn validate_unanchored(xml: &[u8]) -> Result<(), TslError> {
    validate_tsl_signature_with_anchors(xml, &TslTrustAnchors::new())
}

#[derive(Clone, Copy)]
enum EcdsaSignatureEncoding {
    Raw,
    Der,
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn load_list() -> TrustedList {
    parse_tsl(&load_xml()).expect("parse fixture")
}

/// Read the XML fixture, normalising CRLF -> LF.
///
/// These tests perform byte-exact string surgery on the fixture — locating `  </ds:Signature>\n`,
/// `</TrustServiceStatusList>`, and element boundaries — all written against LF line endings. A git
/// checkout that materialises the fixture with CRLF (observed in a fresh `git worktree` even under
/// `core.autocrlf=false`, because the committed blob is LF but the working tree gets CR-injected)
/// would otherwise make `str::find` miss the `\n`-terminated patterns and panic every
/// signed-fixture test — ~22 at once — while the line-ending-tolerant `parse_tsl` tests still pass.
/// Normalising here makes the whole suite deterministic regardless of how the fixture was checked
/// out. (A crate-local `.gitattributes` also pins the fixture to `eol=lf`, fixing the checkout at
/// the source; this belt-and-suspenders keeps the tests robust even where that has not taken
/// effect yet.)
fn load_xml() -> Vec<u8> {
    let raw = std::fs::read(fixture_dir().join("pt-tsl-sample.xml")).expect("read fixture");
    if raw.contains(&b'\r') {
        raw.into_iter().filter(|&b| b != b'\r').collect()
    } else {
        raw
    }
}

fn fixture_without_signature() -> Vec<u8> {
    let mut xml = String::from_utf8(load_xml()).expect("fixture is UTF-8");
    let start = xml.find("  <ds:Signature").expect("signature start");
    let end_tag = "  </ds:Signature>\n";
    let end = xml[start..].find(end_tag).expect("signature end") + start + end_tag.len();
    xml.replace_range(start..end, "");
    xml.into_bytes()
}

fn signed_fixture() -> SignedFixture {
    let unsigned_xml = String::from_utf8(fixture_without_signature()).expect("fixture is UTF-8");
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
    let spki =
        SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
    let cert_der = build_self_signed("TSL XML-DSig test signer", 7, spki);
    let digest = Sha256::digest(unsigned_xml.as_bytes());
    let signed_info = format!(
        r#"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC_C14N_10}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/><ds:Reference URI=""><ds:DigestMethod Algorithm="{SHA256_DIGEST}"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#,
        base64_standard(&digest)
    );
    let signed_info_hash: [u8; 32] = Sha256::digest(signed_info.as_bytes()).into();
    let signature_value = sign_rsa_digest_info(&key, &signed_info_hash);
    let signature = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
        base64_standard(&signature_value),
        base64_standard(&cert_der)
    );
    let insert_at = unsigned_xml
        .find("</TrustServiceStatusList>")
        .expect("fixture root close");
    let xml = format!(
        "{}{}{}",
        &unsigned_xml[..insert_at],
        signature,
        &unsigned_xml[insert_at..]
    );
    SignedFixture {
        xml: xml.into_bytes(),
        signature_value,
        signer_cert_der: cert_der,
    }
}

fn signed_ecdsa_fixture(encoding: EcdsaSignatureEncoding) -> SignedFixture {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use rsa::rand_core::OsRng;

    let unsigned_xml = String::from_utf8(fixture_without_signature()).expect("fixture is UTF-8");
    let key = SigningKey::random(&mut OsRng);
    let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("p256 spki");
    let cert_der = build_p256_self_signed("TSL XML-DSig P-256 test signer", 10, spki);
    let digest = Sha256::digest(unsigned_xml.as_bytes());
    let signed_info = format!(
        r#"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC_C14N_10}"/><ds:SignatureMethod Algorithm="{ECDSA_SHA256}"/><ds:Reference URI=""><ds:DigestMethod Algorithm="{SHA256_DIGEST}"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#,
        base64_standard(&digest)
    );
    let signature: p256::ecdsa::Signature = key.sign(signed_info.as_bytes());
    let signature_value = match encoding {
        EcdsaSignatureEncoding::Raw => signature.to_bytes().to_vec(),
        EcdsaSignatureEncoding::Der => signature.to_der().as_bytes().to_vec(),
    };
    let signature = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
        base64_standard(&signature_value),
        base64_standard(&cert_der)
    );
    let insert_at = unsigned_xml
        .find("</TrustServiceStatusList>")
        .expect("fixture root close");
    let xml = format!(
        "{}{}{}",
        &unsigned_xml[..insert_at],
        signature,
        &unsigned_xml[insert_at..]
    );
    SignedFixture {
        xml: xml.into_bytes(),
        signature_value,
        signer_cert_der: cert_der,
    }
}

fn signed_fragment_fixture() -> SignedFixture {
    let unsigned_xml = String::from_utf8(fixture_without_signature()).expect("fixture is UTF-8");
    let unsigned_xml = unsigned_xml.replacen(
        "<TrustServiceStatusList",
        r#"<TrustServiceStatusList Id="TSL-Fragment""#,
        1,
    );
    let root_start = unsigned_xml
        .find("<TrustServiceStatusList")
        .expect("fixture root start");
    let root_end = unsigned_xml[root_start..]
        .find("</TrustServiceStatusList>")
        .expect("fixture root end")
        + root_start
        + "</TrustServiceStatusList>".len();
    let root_bytes = &unsigned_xml.as_bytes()[root_start..root_end];

    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
    let spki =
        SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
    let cert_der = build_self_signed("TSL XML-DSig fragment test signer", 8, spki);
    let digest = Sha256::digest(root_bytes);
    let signed_info = format!(
        r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC_C14N_10}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/><ds:Reference URI="#TSL-Fragment"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED_SIGNATURE_TRANSFORM}"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256_DIGEST}"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
        base64_standard(&digest)
    );
    let signed_info_hash: [u8; 32] = Sha256::digest(signed_info.as_bytes()).into();
    let signature_value = sign_rsa_digest_info(&key, &signed_info_hash);
    let signature = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
        base64_standard(&signature_value),
        base64_standard(&cert_der)
    );
    let insert_at = unsigned_xml
        .find("</TrustServiceStatusList>")
        .expect("fixture root close");
    let xml = format!(
        "{}{}{}",
        &unsigned_xml[..insert_at],
        signature,
        &unsigned_xml[insert_at..]
    );
    SignedFixture {
        xml: xml.into_bytes(),
        signature_value,
        signer_cert_der: cert_der,
    }
}

fn signed_non_root_fragment_fixture() -> SignedFixture {
    let unsigned_xml = String::from_utf8(fixture_without_signature()).expect("fixture is UTF-8");
    let unsigned_xml = unsigned_xml.replacen(
        "<SchemeInformation>",
        r#"<SchemeInformation Id="Scheme-Only">"#,
        1,
    );
    let target_start = unsigned_xml
        .find(r#"<SchemeInformation Id="Scheme-Only">"#)
        .expect("target start");
    let target_end = unsigned_xml[target_start..]
        .find("</SchemeInformation>")
        .expect("target end")
        + target_start
        + "</SchemeInformation>".len();
    let target_bytes = &unsigned_xml.as_bytes()[target_start..target_end];

    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
    let spki =
        SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
    let cert_der = build_self_signed("TSL XML-DSig non-root fragment test signer", 9, spki);
    let digest = Sha256::digest(target_bytes);
    let signed_info = format!(
        r##"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC_C14N_10}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/><ds:Reference URI="#Scheme-Only"><ds:DigestMethod Algorithm="{SHA256_DIGEST}"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
        base64_standard(&digest)
    );
    let signed_info_hash: [u8; 32] = Sha256::digest(signed_info.as_bytes()).into();
    let signature_value = sign_rsa_digest_info(&key, &signed_info_hash);
    let signature = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
        base64_standard(&signature_value),
        base64_standard(&cert_der)
    );
    let insert_at = unsigned_xml
        .find("</TrustServiceStatusList>")
        .expect("fixture root close");
    let xml = format!(
        "{}{}{}",
        &unsigned_xml[..insert_at],
        signature,
        &unsigned_xml[insert_at..]
    );
    SignedFixture {
        xml: xml.into_bytes(),
        signature_value,
        signer_cert_der: cert_der,
    }
}

fn build_self_signed(cn: &str, serial: u8, spki: SubjectPublicKeyInfoOwned) -> Vec<u8> {
    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_SHA256_WITH_RSA,
        parameters: Some(Any::null()),
    };
    build_test_cert(cn, serial, spki, sig_alg, vec![0u8; 256])
}

fn build_p256_self_signed(cn: &str, serial: u8, spki: SubjectPublicKeyInfoOwned) -> Vec<u8> {
    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_ECDSA_WITH_SHA256,
        parameters: None,
    };
    build_test_cert(cn, serial, spki, sig_alg, vec![0u8; 64])
}

fn build_test_cert(
    cn: &str,
    serial: u8,
    spki: SubjectPublicKeyInfoOwned,
    sig_alg: AlgorithmIdentifierOwned,
    signature: Vec<u8>,
) -> Vec<u8> {
    let name = Name::from_str(&format!("CN={cn}")).expect("name");
    let validity = Validity::from_now(StdDuration::from_secs(365 * 24 * 3600)).expect("validity");
    let cert = Certificate {
        tbs_certificate: TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[serial]).expect("serial"),
            signature: sig_alg.clone(),
            issuer: name.clone(),
            validity,
            subject: name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        },
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&signature).expect("bitstring"),
    };
    cert.to_der().expect("cert der")
}

fn sign_rsa_digest_info(key: &rsa::RsaPrivateKey, digest: &[u8; 32]) -> Vec<u8> {
    let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
    digest_info.extend_from_slice(digest);
    key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
        .expect("rsa sign")
}

fn base64_standard(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// The DER of the first `X509Certificate` identity of the first service of the provider whose
/// name contains `name_substr`.
fn issuer_cert(list: &TrustedList, name_substr: &str) -> Vec<u8> {
    let provider = list
        .providers
        .iter()
        .find(|p| p.name.contains(name_substr))
        .unwrap_or_else(|| panic!("provider containing {name_substr:?} not found"));
    provider.services[0]
        .digital_identities
        .iter()
        .find_map(|id| match id {
            DigitalIdentity::Certificate(der) => Some(der.clone()),
            _ => None,
        })
        .expect("service carries an X509Certificate identity")
}

#[test]
fn parses_scheme_information() {
    let list = load_list();
    assert_eq!(list.scheme_operator_name, "National Security Authority");
    assert_eq!(
        list.scheme_name,
        "PT:Supervision/Accreditation Status List of certification services from Certification Service Providers"
    );
    assert_eq!(list.scheme_territory, "PT");
    assert_eq!(list.sequence_number, Some(52));
    assert_eq!(list.issue_date_time, Some(datetime!(2026-01-15 0:00 UTC)));
    assert_eq!(list.next_update, Some(datetime!(2026-07-15 0:00 UTC)));
    assert_eq!(list.providers.len(), 4);
}

#[test]
fn parses_provider_service_status_and_identity_report_fields() {
    let list = load_list();
    let multicert = list
        .providers
        .iter()
        .find(|p| p.name.contains("MULTICERT"))
        .expect("MULTICERT provider");
    assert_eq!(
        multicert.name,
        "MULTICERT - Electronic Certification Services SA"
    );
    assert_eq!(multicert.trade_names, vec!["MULTICERT"]);
    assert_eq!(
        multicert.information_uris,
        vec!["https://www.multicert.com/"]
    );

    let service = &multicert.services[0];
    assert_eq!(service.service_type, SVCTYPE_CA_QC);
    assert_eq!(service.name, "MULTICERT CA para Assinatura Qualificada");
    assert_eq!(
        service
            .names
            .iter()
            .filter(|name| name.value == "MULTICERT CA para Assinatura Qualificada")
            .count(),
        3,
        "duplicate/multilingual service names are retained for catalog search"
    );
    assert_eq!(service.status, ServiceStatus::Granted);
    assert_eq!(
        service.status_starting_time,
        Some(datetime!(2020-01-01 0:00 UTC))
    );
    assert_eq!(
        service.additional_service_info,
        vec![FOR_ESIGNATURES.to_owned()]
    );
    assert!(service.digital_identities.iter().any(|id| matches!(
        id,
        DigitalIdentity::Certificate(der) if der.len() > 512
    )));
    assert!(service.digital_identities.iter().any(|id| matches!(
        id,
        DigitalIdentity::SubjectName(name) if name.contains("MULTICERT CA para Assinatura Qualificada")
    )));
    assert!(service.digital_identities.iter().any(|id| matches!(
        id,
        DigitalIdentity::SubjectKeyId(ski) if ski.len() == 20
    )));

    let digitalsign = list
        .providers
        .iter()
        .find(|p| p.name.contains("DigitalSign"))
        .expect("DigitalSign provider");
    assert_eq!(digitalsign.services[0].status, ServiceStatus::Withdrawn);
    assert_eq!(digitalsign.services[0].status_starting_time, None);
    assert_eq!(
        digitalsign.services[0].status_starting_time_raw.as_deref(),
        Some("not-a-date")
    );

    let egia = list
        .providers
        .iter()
        .find(|p| p.name == "EGIA")
        .expect("EGIA provider");
    assert_eq!(
        egia.services[0].additional_service_info,
        vec![FOR_ESEALS.to_owned()]
    );

    let tsa = list
        .providers
        .iter()
        .find(|p| p.name == "Cartorio Notarial Timestamping")
        .expect("TSA provider");
    assert!(
        tsa.names
            .iter()
            .any(|name| name.value == "Cartório Âncora Carimbo do Tempo")
    );
    assert_eq!(tsa.trade_names, vec!["Âncora TSA São Tomé"]);
    assert_eq!(tsa.services.len(), 2);
    assert_eq!(
        tsa.services[0].service_supply_points,
        vec!["http://tsa.cartorio.example.test/tsa/server"]
    );
    let revoked_tsa = &tsa.services[1];
    assert!(
        revoked_tsa.name.is_empty(),
        "missing ServiceName stays empty"
    );
    assert!(matches!(
        revoked_tsa.status,
        ServiceStatus::Revoked(ref uri) if uri.ends_with("/supervisionRevoked")
    ));
    assert_eq!(revoked_tsa.status_starting_time, None);
    assert_eq!(
        revoked_tsa.status_starting_time_raw.as_deref(),
        Some("not-a-date")
    );
}

#[test]
fn granted_qtsp_is_qualified_for_esig() {
    let list = load_list();
    let cert = issuer_cert(&list, "MULTICERT");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Granted
    );
}

#[test]
fn withdrawn_service_is_not_qualified() {
    let list = load_list();
    let cert = issuer_cert(&list, "DigitalSign");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Withdrawn
    );
}

#[test]
fn seal_only_ca_is_not_qualified_for_esig() {
    // EGIA's CA/QC is granted, but only for e-seals — not e-signatures.
    let list = load_list();
    let cert = issuer_cert(&list, "EGIA");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Withdrawn
    );
}

#[test]
fn unlisted_issuer_is_unknown() {
    let list = load_list();
    let cert = std::fs::read(fixture_dir().join("unlisted-ca.der")).expect("read unlisted cert");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Unknown
    );
}

#[test]
fn garbage_issuer_bytes_are_unknown_not_an_error() {
    let list = load_list();
    assert_eq!(
        resolve_esig_status(&list, b"not-a-certificate", NOW),
        QualifiedStatus::Unknown
    );
}

#[test]
fn service_history_is_ignored() {
    // MULTICERT carries a withdrawn ServiceHistory instance with an all-zero SKI; the parser must
    // keep that history structured without mixing it into the *current* granted service.
    let list = load_list();
    let svc = &list
        .providers
        .iter()
        .find(|p| p.name.contains("MULTICERT"))
        .unwrap()
        .services[0];
    assert_eq!(svc.status, ServiceStatus::Granted);
    // Exactly one certificate identity and one (non-zero) SKI — the history entries are absent.
    let ski_count = svc
        .digital_identities
        .iter()
        .filter(|id| matches!(id, DigitalIdentity::SubjectKeyId(_)))
        .count();
    assert_eq!(ski_count, 1);
    assert!(
        svc.digital_identities
            .iter()
            .any(|id| matches!(id, DigitalIdentity::SubjectKeyId(s) if s.iter().any(|&b| b != 0)))
    );
    assert_eq!(svc.history.len(), 1);
    assert_eq!(svc.history[0].status, ServiceStatus::Withdrawn);
    assert!(
        svc.history[0]
            .digital_identities
            .iter()
            .any(|id| matches!(id, DigitalIdentity::SubjectKeyId(s) if s.iter().all(|&b| b == 0)))
    );
}

#[test]
fn discovery_lists_only_the_granted_esig_service() {
    let list = load_list();
    let services = qualified_esig_services(&list, NOW);
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, "MULTICERT CA para Assinatura Qualificada");
}

#[test]
fn client_caches_and_reports_staleness() {
    let source = FileTslSource::new(fixture_dir().join("pt-tsl-sample.xml"));
    let mut client = TslClient::new(source);

    // Cold cache: nothing yet.
    assert!(client.cached().is_none());

    client.ensure_fresh(NOW).expect("fetch + parse");
    let cached = client.cached().expect("cache populated");
    assert!(!cached.is_stale(NOW));
    assert!(cached.is_stale(AFTER_NEXT_UPDATE));
}

#[test]
fn client_downgrades_granted_to_unknown_when_signature_does_not_verify() {
    // Security audit t41/C2: the fixture carries a placeholder <ds:Signature> that does not
    // verify (no <ds:Reference>, no <ds:KeyInfo>, fake SignatureValue). TslClient MUST NOT
    // report Granted for an issuer on an unauthenticated list — Granted is downgraded to
    // Unknown. (resolve_esig_status, the pure function, still returns Granted — the gate lives
    // in TslClient, not in the status resolver.)
    let source = FileTslSource::new(fixture_dir().join("pt-tsl-sample.xml"));
    let mut client = TslClient::new(source);
    client.ensure_fresh(NOW).unwrap();
    let cert = issuer_cert(client.cached().unwrap().list(), "MULTICERT");

    assert_eq!(
        client.is_qualified_for_esig(&cert, NOW).unwrap(),
        QualifiedStatus::Unknown,
        "an unauthenticated list must not vouch for an issuer"
    );
    // The pure resolver still returns Granted — the cache carries the raw status for inspection.
    assert_eq!(
        resolve_esig_status(client.cached().unwrap().list(), &cert, NOW),
        QualifiedStatus::Granted
    );
    assert!(
        !client.cached().unwrap().signature_valid(),
        "fixture signature is not valid"
    );
}

#[test]
fn qtst_match_details_return_anchors_and_downgrade_when_unauthenticated() {
    let xml = br#"<TrustServiceStatusList>
      <SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation>
      <TrustServiceProviderList>
        <TrustServiceProvider>
          <TSPInformation><TSPName><Name xml:lang="en">Unsigned TSA</Name></TSPName></TSPInformation>
          <TSPServices><TSPService><ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Unsigned TSA QTST</Name></ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <ServiceDigitalIdentity><DigitalId><X509Certificate>dHNhLWNlcnQ=</X509Certificate></DigitalId></ServiceDigitalIdentity>
          </ServiceInformation></TSPService></TSPServices>
        </TrustServiceProvider>
      </TrustServiceProviderList>
    </TrustServiceStatusList>"#;
    let cert = b"tsa-cert".to_vec();
    let list = parse_tsl(xml).unwrap();
    let raw = resolve_qtst_match_details(&list, &cert, NOW);
    assert_eq!(raw.status, QualifiedStatus::Granted);
    assert_eq!(raw.trust_anchor_ders, vec![cert.clone()]);
    assert_eq!(raw.matches.len(), 1);
    assert!(raw.matches[0].granted_and_effective);

    let source = BytesTslSource::new(xml.to_vec());
    let mut client = TslClient::new(source);
    let details = client.qtst_match_details(&cert, NOW).unwrap();
    assert_eq!(details.status, QualifiedStatus::Unknown);
    assert!(details.trust_anchor_ders.is_empty());
    assert!(!details.authenticated);
    assert_eq!(details.matches.len(), 1);
}

#[test]
fn client_downgrades_granted_to_unknown_when_signature_is_missing() {
    let xml = fixture_without_signature();
    let list = parse_tsl(&xml).unwrap();
    let cert = issuer_cert(&list, "MULTICERT");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Granted
    );

    let mut client = TslClient::new(BytesTslSource::new(xml));
    assert_eq!(
        client.is_qualified_for_esig(&cert, NOW).unwrap(),
        QualifiedStatus::Unknown,
        "an unsigned list must not vouch for an issuer"
    );
    assert!(!client.cached().unwrap().signature_valid());
}

#[test]
fn tsl_signature_validation_rejects_missing_signature_metadata() {
    let err = validate_unanchored(&fixture_without_signature()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureStructure(_)),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_unsupported_canonicalization_metadata() {
    let xml = br#"<TrustServiceStatusList>
      <SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation>
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
          <ds:CanonicalizationMethod Algorithm="urn:unsupported-c14n"/>
          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
          <ds:Reference URI="">
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
      </ds:Signature>
    </TrustServiceStatusList>"#;
    let err = validate_unanchored(xml).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureUnsupportedAlgorithm(ref alg) if alg.contains("canonicalization")),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_unsupported_signature_method_metadata() {
    let mut signed = String::from_utf8(signed_fixture().xml).expect("signed fixture is UTF-8");
    signed = signed.replace(RSA_SHA256, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");

    let err = validate_unanchored(signed.as_bytes()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureUnsupportedAlgorithm(ref alg) if alg.contains("signature method")),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_malformed_signature_value_base64() {
    let signed = signed_fixture();
    let good = base64_standard(&signed.signature_value);
    let xml = String::from_utf8(signed.xml)
        .expect("signed fixture is UTF-8")
        .replace(&good, "not-base64*");

    let err = validate_unanchored(xml.as_bytes()).unwrap_err();
    assert!(matches!(err, TslError::Base64(_)), "got {err:?}");
}

/// Multi-reference signatures are supported (real Trusted Lists sign the document plus a XAdES
/// `SignedProperties`), but every reference is checked. This is the previous
/// "multiple references are refused outright" test, re-pointed at the stronger guarantee that
/// replaced it: an extra reference whose digest is wrong now fails the signature on that digest
/// rather than on the reference count, so the extra reference is genuinely being verified and not
/// merely counted. `crates/chancela-tsl/src/xmldsig.rs` covers the multi-reference happy path.
#[test]
fn tsl_signature_validation_rejects_an_added_reference_with_a_bad_digest() {
    let xml = String::from_utf8(signed_fixture().xml)
        .expect("signed fixture is UTF-8")
        .replace(
            "</ds:Reference></ds:SignedInfo>",
            &format!(
                "</ds:Reference><ds:Reference URI=\"\"><ds:DigestMethod Algorithm=\"{SHA256_DIGEST}\"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference></ds:SignedInfo>"
            ),
        );

    let err = validate_unanchored(xml.as_bytes()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureDigestMismatch),
        "got {err:?}"
    );
}

/// A `<ds:Reference>` outside `<ds:SignedInfo>` (here inside a `<ds:Manifest>` in a `<ds:Object>`)
/// is not covered by `<ds:SignatureValue>`, so an attacker can append one at will. It must be
/// ignored entirely: neither verified — its `DigestValue` here is garbage — nor able to satisfy the
/// document-coverage rule. The list's single in-scope reference still carries the verdict.
#[test]
fn tsl_signature_validation_ignores_a_reference_outside_signed_info() {
    let signed = signed_fixture();
    let anchors = anchors_for(&signed);
    let xml = String::from_utf8(signed.xml)
        .expect("signed fixture is UTF-8")
        .replace(
            "</ds:KeyInfo>",
            &format!(
                "</ds:KeyInfo><ds:Object><ds:Manifest><ds:Reference URI=\"#not-in-the-document\"><ds:Transforms><ds:Transform Algorithm=\"urn:unsupported-transform\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{SHA256_DIGEST}\"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference></ds:Manifest></ds:Object>"
            ),
        );

    // Appending the unsigned Object changes the enveloped reference's content only if the
    // signature element is not stripped — it is, so the list still validates.
    validate_tsl_signature_with_anchors(xml.as_bytes(), &anchors)
        .expect("an out-of-scope <ds:Reference> must not affect the verdict");
}

#[test]
fn tsl_signature_validation_rejects_unsupported_reference_transform() {
    let xml = String::from_utf8(signed_fixture().xml)
        .expect("signed fixture is UTF-8")
        .replace(
            "<ds:DigestMethod",
            r#"<ds:Transforms><ds:Transform Algorithm="urn:unsupported-transform"/></ds:Transforms><ds:DigestMethod"#,
        );

    let err = validate_unanchored(xml.as_bytes()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureUnsupportedAlgorithm(ref alg) if alg.contains("transform")),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_digest_mismatch_metadata() {
    let xml = br#"<TrustServiceStatusList>
      <SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation>
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
          <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
          <ds:Reference URI="">
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
      </ds:Signature>
    </TrustServiceStatusList>"#;
    let err = validate_unanchored(xml).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureDigestMismatch),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_accepts_supported_fixture_shape_signed_by_anchored_cert() {
    let signed = signed_fixture();
    validate_tsl_signature_with_anchors(&signed.xml, &anchors_for(&signed))
        .expect("supported XML-DSig shape signed by the anchored cert verifies");
}

#[test]
fn tsl_signature_validation_accepts_p256_ecdsa_signed_by_anchored_cert() {
    let signed = signed_ecdsa_fixture(EcdsaSignatureEncoding::Raw);
    validate_tsl_signature_with_anchors(&signed.xml, &anchors_for(&signed))
        .expect("P-256 ECDSA XML-DSig shape signed by the anchored cert verifies");
}

#[test]
fn tsl_signature_validation_accepts_same_document_root_uri_fragment() {
    let signed = signed_fragment_fixture();
    validate_tsl_signature_with_anchors(&signed.xml, &anchors_for(&signed))
        .expect("root URI fragment XML-DSig shape signed by the anchored cert verifies");
}

#[test]
fn tsl_signature_validation_pins_anchor_by_sha256_fingerprint() {
    // Configuring the anchor by the DER cert's SHA-256 fingerprint is equivalent to shipping the
    // cert file.
    let signed = signed_fixture();
    let fingerprint: [u8; 32] = Sha256::digest(&signed.signer_cert_der).into();
    let anchors = TslTrustAnchors::new().with_fingerprint(fingerprint);
    validate_tsl_signature_with_anchors(&signed.xml, &anchors)
        .expect("a list signed by the fingerprint-pinned cert verifies");
}

#[test]
fn tsl_signature_validation_rejects_self_signed_list_not_matching_anchor() {
    // The core of audit t41/C2 part H4: a list that verifies against the certificate it *itself*
    // carries, but whose signer does not match the configured anchor, MUST be untrusted. Here the
    // configured anchor is a *different* signer (the ECDSA fixture's cert).
    let signed = signed_fixture();
    let other = signed_ecdsa_fixture(EcdsaSignatureEncoding::Raw);
    let anchors = TslTrustAnchors::new().with_cert_der(&other.signer_cert_der);

    let err = validate_tsl_signature_with_anchors(&signed.xml, &anchors).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureUntrusted(_)),
        "a self-attested list whose signer is not the anchor must be untrusted, got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_fails_closed_with_empty_anchor_set() {
    // No anchor configured -> even a cryptographically self-consistent list is untrusted.
    let signed = signed_fixture();
    let err =
        validate_tsl_signature_with_anchors(&signed.xml, &TslTrustAnchors::new()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureUntrusted(_)),
        "an empty anchor set must trust no list, got {err:?}"
    );
}

#[test]
fn tsl_signature_env_entry_point_fails_closed_without_configured_anchor() {
    // The public `validate_tsl_signature` resolves anchors from the environment and MUST fail
    // closed when none is configured. The fail-closed invariant is asserted hermetically here —
    // against an explicitly-empty anchor set, exactly what `from_env` yields when unconfigured — so
    // this test is robust to any ambient CHANCELA_TSL_TRUST_ANCHOR[_SHA256] in the runner's
    // environment. (The earlier form asserted `from_env().is_empty()` unconditionally and so failed
    // on any machine/CI that legitimately exports a TSL trust anchor.)
    let signed = signed_fixture();
    let err =
        validate_tsl_signature_with_anchors(&signed.xml, &TslTrustAnchors::new()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureUntrusted(_)),
        "an unconfigured (empty) anchor set must fail closed, got {err:?}"
    );

    // Additionally, when this binary's environment is itself unconfigured (the CI default), the
    // env-resolving entry point resolves that same empty set and fails closed identically. Skipped
    // when an anchor happens to be configured — then the env path's outcome depends on that anchor
    // and is not this test's concern.
    if TslTrustAnchors::from_env().is_ok_and(|anchors| anchors.is_empty()) {
        let env_err = validate_tsl_signature(&signed.xml).unwrap_err();
        assert!(
            matches!(env_err, TslError::SignatureUntrusted(_)),
            "env entry point must fail closed without a configured anchor, got {env_err:?}"
        );
    }
}

#[test]
fn tsl_signature_validation_rejects_missing_same_document_uri_fragment_target() {
    let xml = String::from_utf8(signed_fragment_fixture().xml)
        .expect("signed fixture is UTF-8")
        .replacen(r#" Id="TSL-Fragment""#, "", 1);

    let err = validate_unanchored(xml.as_bytes()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureStructure(ref msg) if msg.contains("did not match")),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_non_root_same_document_uri_fragment_target() {
    let err = validate_unanchored(&signed_non_root_fragment_fixture().xml).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureStructure(ref msg) if msg.contains("TrustServiceStatusList root")),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_tampered_signed_info() {
    let xml = String::from_utf8(signed_fixture().xml)
        .expect("signed fixture is UTF-8")
        .replace(EXC_C14N_10, C14N_10);

    let err = validate_unanchored(xml.as_bytes()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureVerificationFailed),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_tampered_referenced_content() {
    let xml = String::from_utf8(signed_fixture().xml)
        .expect("signed fixture is UTF-8")
        .replace(
            "<SchemeTerritory>PT</SchemeTerritory>",
            "<SchemeTerritory>ES</SchemeTerritory>",
        );

    let err = validate_unanchored(xml.as_bytes()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureDigestMismatch),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_tampered_same_document_uri_fragment_content() {
    let xml = String::from_utf8(signed_fragment_fixture().xml)
        .expect("signed fixture is UTF-8")
        .replace(
            "<SchemeTerritory>PT</SchemeTerritory>",
            "<SchemeTerritory>ES</SchemeTerritory>",
        );

    let err = validate_unanchored(xml.as_bytes()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureDigestMismatch),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_tampered_signature_value() {
    let signed = signed_fixture();
    let mut bad_signature = signed.signature_value.clone();
    bad_signature[0] ^= 0x01;
    let xml = String::from_utf8(signed.xml)
        .expect("signed fixture is UTF-8")
        .replace(
            &base64_standard(&signed.signature_value),
            &base64_standard(&bad_signature),
        );

    let err = validate_unanchored(xml.as_bytes()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureVerificationFailed),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_tampered_p256_ecdsa_signature_value() {
    let signed = signed_ecdsa_fixture(EcdsaSignatureEncoding::Raw);
    let mut bad_signature = signed.signature_value.clone();
    bad_signature[0] ^= 0x01;
    let xml = String::from_utf8(signed.xml)
        .expect("signed fixture is UTF-8")
        .replace(
            &base64_standard(&signed.signature_value),
            &base64_standard(&bad_signature),
        );

    let err = validate_unanchored(xml.as_bytes()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureVerificationFailed),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_der_encoded_p256_ecdsa_signature_value() {
    let signed = signed_ecdsa_fixture(EcdsaSignatureEncoding::Der);

    let err = validate_unanchored(&signed.xml).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureStructure(ref msg) if msg.contains("raw r||s")),
        "got {err:?}"
    );
}

#[test]
fn client_downgrades_granted_to_unknown_when_reference_digest_is_tampered() {
    let xml = String::from_utf8(signed_fixture().xml)
        .expect("signed fixture is UTF-8")
        .replace(
            "<SchemeTerritory>PT</SchemeTerritory>",
            "<SchemeTerritory>ES</SchemeTerritory>",
        )
        .into_bytes();
    let list = parse_tsl(&xml).unwrap();
    let cert = issuer_cert(&list, "MULTICERT");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Granted
    );

    let mut client = TslClient::new(BytesTslSource::new(xml));
    assert_eq!(
        client.is_qualified_for_esig(&cert, NOW).unwrap(),
        QualifiedStatus::Unknown,
        "a digest-tampered list must not vouch for an issuer"
    );
    assert!(!client.cached().unwrap().signature_valid());
}

#[test]
fn client_with_explicit_anchors_authenticates_a_list_the_env_path_would_reject() {
    // t61-e1: the seam the signing-time trust policy now walks. Anchors supplied by the caller
    // (in production: `signing.tsl_trust_anchor_*` unioned with the environment) authenticate the
    // list, so the issuer stays `Granted`. The same client without them resolves the environment,
    // which cannot vouch for this ephemeral signer, and fails closed to `Unknown`.
    let signed = signed_fixture();
    let list = parse_tsl(&signed.xml).expect("signed fixture parses");
    let cert = issuer_cert(&list, "MULTICERT");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Granted,
        "the unauthenticated list is Granted, so the anchor is what the assertions below isolate"
    );

    let mut anchored =
        TslClient::new(BytesTslSource::new(signed.xml.clone())).with_anchors(anchors_for(&signed));
    assert_eq!(
        anchored.is_qualified_for_esig(&cert, NOW).unwrap(),
        QualifiedStatus::Granted,
        "explicitly-supplied anchors must authenticate the list"
    );
    assert!(anchored.cached().unwrap().signature_valid());

    let mut unanchored = TslClient::new(BytesTslSource::new(signed.xml.clone()))
        .with_anchors(TslTrustAnchors::new());
    assert_eq!(
        unanchored.is_qualified_for_esig(&cert, NOW).unwrap(),
        QualifiedStatus::Unknown,
        "an empty anchor set must trust no list (fail closed)"
    );
    assert!(!unanchored.cached().unwrap().signature_valid());

    // `new()` alone keeps its pre-existing behaviour: resolve from the environment. On a runner
    // with no anchor configured that is the fail-closed empty set.
    assert!(
        TslClient::new(BytesTslSource::new(signed.xml))
            .anchors()
            .is_none()
    );
}

#[test]
fn tsl_signature_validation_rejects_incomplete_fixture_signature() {
    // The bundled fixture carries a placeholder <ds:Signature> with only a CanonicalizationMethod,
    // SignatureMethod, and a fake SignatureValue — no <ds:Reference>, no <ds:KeyInfo>. The
    // validator MUST detect this and reject it rather than silently accepting the list.
    let xml = load_xml();
    let err = validate_unanchored(&xml).unwrap_err();
    // The exact variant depends on which structural check trips first (missing Reference, missing
    // KeyInfo, etc.), but it MUST be a signature-structure/digest/verification error, never the
    // old `SignatureValidationNotImplemented`.
    assert!(
        matches!(
            err,
            TslError::SignatureStructure(_)
                | TslError::SignatureDigestMismatch
                | TslError::SignatureVerificationFailed
                | TslError::SignatureUnsupportedAlgorithm(_)
        ),
        "got {err:?}"
    );
}

// =================================================================================================
// Durable Trusted List cache (`disk_cache`)
// =================================================================================================
//
// The fault these cover: the configured Trusted List URL is reachable from the operator's own host
// but not from wherever the server runs (container egress, a proxy, DNS), so every qualified
// signature is refused with `signing_trusted_list_unavailable`. The cache makes a transient fetch
// failure survivable — and the tests below pin the boundary of *how* survivable, because a cache
// that quietly outlives the list it holds is how a withdrawn trust service keeps reading as granted.
mod durable_cache {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use chancela_tsl::{
        CachingTslSource, DEFAULT_MAX_STALE, LEGACY_SHA1_DIGEST, QualifiedStatus,
        TslAlgorithmPolicy, TslCacheLoad, TslCacheRefusal, TslClient, TslClock, TslDiskCache,
        TslError, TslFetchProvenance, TslSource, TslTrustAnchors,
        validate_tsl_signature_with_policy,
    };
    use sha1::Sha1;
    use sha2::{Digest, Sha256};
    use time::macros::datetime;
    use time::{Duration, OffsetDateTime};

    use super::{
        EXC_C14N_10, RSA_SHA256, SignedFixture, anchors_for, base64_standard, build_self_signed,
        fixture_without_signature, issuer_cert, sign_rsa_digest_info,
    };

    /// Inside the fixture's validity window (issued 2026-01-15, `NextUpdate` 2026-07-15).
    const NOW: OffsetDateTime = datetime!(2026-07-06 12:00:00 UTC);
    /// One day past the fixture's `NextUpdate` — inside the seven-day grace.
    const ONE_DAY_STALE: OffsetDateTime = datetime!(2026-07-16 0:00 UTC);
    /// Eight days past it — one day beyond the grace.
    const PAST_MAX_AGE: OffsetDateTime = datetime!(2026-07-23 12:00 UTC);

    const SOURCE_ID: &str = "pt-gns";
    const LOCATION: &str = "url:https://tsl.example.invalid/TSL.xml";
    /// The terminal cause the offline source reports. It is the shape of the real fault: the outer
    /// `error sending request for url (…)` plus the cause that actually decides where an operator
    /// should look.
    const OFFLINE_CAUSE: &str = "dns error: failed to lookup address information";

    /// A source that can be taken offline, standing in for the egress fault. It counts fetches so a
    /// test can prove the durable cache was consulted rather than the network.
    struct ToggleSource {
        bytes: Vec<u8>,
        online: AtomicBool,
        attempts: AtomicUsize,
    }

    impl ToggleSource {
        fn online(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                online: AtomicBool::new(true),
                attempts: AtomicUsize::new(0),
            }
        }

        fn offline(bytes: Vec<u8>) -> Self {
            let source = Self::online(bytes);
            source.online.store(false, Ordering::SeqCst);
            source
        }
    }

    impl TslSource for ToggleSource {
        fn fetch(&self) -> Result<Vec<u8>, TslError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if self.online.load(Ordering::SeqCst) {
                Ok(self.bytes.clone())
            } else {
                Err(TslError::Structure(format!(
                    "error sending request for url (https://tsl.example.invalid/TSL.xml): \
                     {OFFLINE_CAUSE}"
                )))
            }
        }
    }

    /// A scratch directory unique to one test, removed on the way in.
    fn scratch(tag: &str) -> std::path::PathBuf {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "chancela-tsl-durable-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// A client over `source`, caching into `dir` and reading `now` as the current instant.
    fn client_at(
        source: ToggleSource,
        dir: &std::path::Path,
        anchors: TslTrustAnchors,
        now: OffsetDateTime,
    ) -> TslClient<CachingTslSource<ToggleSource>> {
        let cached = CachingTslSource::new(
            source,
            TslDiskCache::new(dir),
            SOURCE_ID,
            LOCATION,
            DEFAULT_MAX_STALE,
        )
        .with_clock(TslClock::Pinned(now));
        TslClient::new(cached).with_anchors(anchors)
    }

    /// A Trusted List signed with a SHA-1 reference digest — a broken algorithm no install accepts
    /// unless its exact URI was opted into. Otherwise identical in shape to `signed_fixture`.
    fn signed_sha1_digest_fixture() -> SignedFixture {
        let unsigned_xml =
            String::from_utf8(fixture_without_signature()).expect("fixture is UTF-8");
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
        let spki = spki::SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key))
            .expect("rsa spki");
        let cert_der = build_self_signed("TSL SHA-1 digest test signer", 21, spki);
        let digest = Sha1::digest(unsigned_xml.as_bytes());
        let signed_info = format!(
            r#"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC_C14N_10}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/><ds:Reference URI=""><ds:DigestMethod Algorithm="{LEGACY_SHA1_DIGEST}"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#,
            base64_standard(&digest)
        );
        let signed_info_hash: [u8; 32] = Sha256::digest(signed_info.as_bytes()).into();
        let signature_value = sign_rsa_digest_info(&key, &signed_info_hash);
        let signature = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
            base64_standard(&signature_value),
            base64_standard(&cert_der)
        );
        let insert_at = unsigned_xml
            .find("</TrustServiceStatusList>")
            .expect("fixture root close");
        let xml = format!(
            "{}{}{}",
            &unsigned_xml[..insert_at],
            signature,
            &unsigned_xml[insert_at..]
        );
        SignedFixture {
            xml: xml.into_bytes(),
            signature_value,
            signer_cert_der: cert_der,
        }
    }

    /// The headline case. A first fetch succeeds and is cached; the source then goes dark, exactly
    /// as it did in production; a fresh client — a new signature, a new process — still resolves the
    /// issuer to `Granted`, and says the answer came from the cache.
    #[test]
    fn a_failed_fetch_falls_back_to_the_cache_and_the_signature_proceeds() {
        let dir = scratch("fallback");
        let fixture = super::signed_fixture();
        let anchors = anchors_for(&fixture);

        let mut online = client_at(
            ToggleSource::online(fixture.xml.clone()),
            &dir,
            anchors.clone(),
            NOW,
        );
        online.refresh(NOW).expect("the first fetch succeeds");
        let issuer = issuer_cert(online.cached().expect("cache").list(), "MULTICERT");
        assert_eq!(
            online.is_qualified_for_esig(&issuer, NOW).expect("status"),
            QualifiedStatus::Granted
        );
        assert_eq!(
            online.source().last_fetch_provenance(),
            TslFetchProvenance::Fetched,
            "a successful fetch is not a cache serve"
        );

        // A new process, and the network is gone.
        let mut offline = client_at(
            ToggleSource::offline(fixture.xml.clone()),
            &dir,
            anchors,
            NOW,
        );
        offline
            .refresh(NOW)
            .expect("the durable cache answers what the network could not");
        assert_eq!(
            offline.is_qualified_for_esig(&issuer, NOW).expect("status"),
            QualifiedStatus::Granted,
            "a transient fetch failure must not make qualified signing impossible"
        );

        match offline.source().last_fetch_provenance() {
            TslFetchProvenance::ServedFromCache(serve) => {
                assert!(!serve.stale, "inside NextUpdate the cache is not stale");
                assert!(
                    serve.fetch_error.contains(OFFLINE_CAUSE),
                    "the serve record must carry why the fetch failed, got {:?}",
                    serve.fetch_error
                );
            }
            other => panic!("expected a cache serve, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Past `NextUpdate` the cache is still served — an operator mid-outage is not helped by a
    /// refusal — but the answer is **marked**, because on a stale list a trust service the scheme
    /// operator has withdrawn since then still reads as granted.
    #[test]
    fn a_cached_list_past_next_update_is_served_but_marked_stale() {
        let dir = scratch("stale");
        let fixture = super::signed_fixture();
        let anchors = anchors_for(&fixture);

        client_at(
            ToggleSource::online(fixture.xml.clone()),
            &dir,
            anchors.clone(),
            NOW,
        )
        .refresh(NOW)
        .expect("seed the cache");

        let mut offline = client_at(
            ToggleSource::offline(fixture.xml.clone()),
            &dir,
            anchors,
            ONE_DAY_STALE,
        );
        offline.refresh(ONE_DAY_STALE).expect("cache answers");

        let serve = match offline.source().last_fetch_provenance() {
            TslFetchProvenance::ServedFromCache(serve) => serve,
            other => panic!("expected a cache serve, got {other:?}"),
        };
        assert!(
            serve.stale,
            "past NextUpdate the serve must be marked stale"
        );
        assert_eq!(serve.code(), chancela_tsl::CODE_TSL_SERVED_FROM_STALE_CACHE);
        assert_eq!(serve.expires_at, datetime!(2026-07-15 0:00 UTC));

        // ...and the mark is durable, so a surface that never saw the signature can still report it.
        let recorded = TslDiskCache::new(&dir)
            .last_serve(&TslDiskCache::key_for(SOURCE_ID, LOCATION))
            .expect("the stale serve is recorded on disk");
        assert_eq!(recorded, serve);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Past the bound, the cache is refused rather than served, and the caller sees the fetch
    /// failure — the same refusal it would have seen with no cache at all.
    #[test]
    fn a_cached_list_past_the_maximum_age_is_refused_not_served() {
        let dir = scratch("too-old");
        let fixture = super::signed_fixture();
        let anchors = anchors_for(&fixture);

        client_at(
            ToggleSource::online(fixture.xml.clone()),
            &dir,
            anchors.clone(),
            NOW,
        )
        .refresh(NOW)
        .expect("seed the cache");

        let mut offline = client_at(
            ToggleSource::offline(fixture.xml.clone()),
            &dir,
            anchors,
            PAST_MAX_AGE,
        );
        let err = offline
            .refresh(PAST_MAX_AGE)
            .expect_err("a cache eight days past NextUpdate must not be served");
        assert!(
            err.to_string().contains(OFFLINE_CAUSE),
            "the caller must see the fetch failure, not a cache error: {err}"
        );
        assert!(
            offline.cached().is_none(),
            "nothing may be parsed from a refused cache"
        );

        // And the refusal names the bound it tripped, for the operator-facing diagnostic.
        match TslDiskCache::new(&dir).load(
            &TslDiskCache::key_for(SOURCE_ID, LOCATION),
            PAST_MAX_AGE,
            DEFAULT_MAX_STALE,
        ) {
            TslCacheLoad::Refused(TslCacheRefusal::TooOld { usable_until, .. }) => {
                assert_eq!(
                    usable_until,
                    datetime!(2026-07-15 0:00 UTC) + Duration::days(7)
                );
            }
            other => panic!("expected a TooOld refusal, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The cached thing is bytes, not a verdict.** Revoke the anchor that made the list authentic
    /// and the very next use of the same cached bytes stops vouching for anybody — no cache
    /// invalidation step, because there is no verdict on disk to invalidate.
    #[test]
    fn revoking_the_trust_anchor_invalidates_the_cache_immediately() {
        let dir = scratch("anchor-revoked");
        let fixture = super::signed_fixture();

        let mut seeded = client_at(
            ToggleSource::online(fixture.xml.clone()),
            &dir,
            anchors_for(&fixture),
            NOW,
        );
        seeded.refresh(NOW).expect("seed the cache");
        let issuer = issuer_cert(seeded.cached().expect("cache").list(), "MULTICERT");
        assert_eq!(
            seeded.is_qualified_for_esig(&issuer, NOW).expect("status"),
            QualifiedStatus::Granted
        );

        // The operator revokes that anchor and provisions a different one. Same bytes on disk.
        let replaced = TslTrustAnchors::new().with_cert_der(b"a different scheme signing cert");
        let mut after = client_at(
            ToggleSource::offline(fixture.xml.clone()),
            &dir,
            replaced,
            NOW,
        );
        after.refresh(NOW).expect("the cache still returns bytes");
        assert!(
            after
                .source()
                .last_fetch_provenance()
                .cache_serve()
                .is_some(),
            "this test is only meaningful if the bytes came from the cache"
        );
        assert!(
            !after.cached().expect("cache").signature_valid(),
            "a revoked anchor must not still authenticate the cached list"
        );
        assert_eq!(
            after.is_qualified_for_esig(&issuer, NOW).expect("status"),
            QualifiedStatus::Unknown,
            "a cached list authenticated under a revoked anchor must vouch for nobody"
        );

        // Fail-closed all the way down: an empty anchor set trusts nothing either.
        let mut unanchored = client_at(
            ToggleSource::offline(fixture.xml.clone()),
            &dir,
            TslTrustAnchors::new(),
            NOW,
        );
        unanchored.refresh(NOW).expect("cache answers");
        assert!(!unanchored.cached().expect("cache").signature_valid());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same property for the algorithm policy: a list whose signature verified only because a
    /// broken algorithm was permitted stops verifying the moment that permission is withdrawn, even
    /// though the bytes it is judged from never changed.
    ///
    /// This drives `validate_tsl_signature_with_policy` over the cached bytes, because that is the
    /// entry point the operator's `signing.tsl_legacy_algorithms` reaches; `TslClient` itself always
    /// uses the strict entry point, which permits no broken algorithm at all.
    #[test]
    fn tightening_the_algorithm_policy_invalidates_the_cache_immediately() {
        let dir = scratch("policy-tightened");
        let fixture = signed_sha1_digest_fixture();
        let anchors = anchors_for(&fixture);
        let permissive = TslAlgorithmPolicy::new()
            .with_legacy_algorithm(LEGACY_SHA1_DIGEST)
            .expect("SHA-1 is a known legacy algorithm");

        let cache = TslDiskCache::new(&dir);
        let key = TslDiskCache::key_for(SOURCE_ID, LOCATION);
        cache
            .store(&key, SOURCE_ID, &fixture.xml, NOW)
            .expect("seed the cache");
        let cached = match cache.load(&key, NOW, DEFAULT_MAX_STALE) {
            TslCacheLoad::Usable(cached) => cached.bytes,
            other => panic!("expected a usable entry, got {other:?}"),
        };
        assert_eq!(cached, fixture.xml, "the cache returns the fetched bytes");

        let report = validate_tsl_signature_with_policy(&cached, &anchors, &permissive)
            .expect("the list verifies while SHA-1 is permitted");
        assert!(
            !report.weak_algorithms.is_empty(),
            "and says the verdict depended on it"
        );

        // The operator clears `signing.tsl_legacy_algorithms`. Nothing on disk changed.
        let err = validate_tsl_signature_with_policy(&cached, &anchors, &TslAlgorithmPolicy::new())
            .expect_err("a tightened policy must refuse the cached list at once");
        assert!(
            matches!(err, TslError::SignatureUnsupportedAlgorithm(ref m) if m.contains(LEGACY_SHA1_DIGEST)),
            "got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unchanged behaviour where it matters: with nothing cached and no fetch, the signature is
    /// still refused. The cache adds resilience, never authority.
    #[test]
    fn no_cache_and_no_fetch_still_refuses() {
        let dir = scratch("empty");
        let fixture = super::signed_fixture();
        let mut client = client_at(
            ToggleSource::offline(fixture.xml.clone()),
            &dir,
            anchors_for(&fixture),
            NOW,
        );

        let err = client
            .refresh(NOW)
            .expect_err("an empty cache cannot answer for an unreachable list");
        assert!(err.to_string().contains(OFFLINE_CAUSE), "got {err}");
        assert!(client.cached().is_none());
        assert_eq!(
            client.source().last_fetch_provenance(),
            TslFetchProvenance::Fetched,
            "nothing was served from the cache, so nothing is reported as having been"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A later successful fetch retires the record of having fallen back — the current answer came
    /// from the network, so a surface reading the record must not keep warning about a past outage.
    #[test]
    fn a_successful_fetch_retires_the_cache_serve_record() {
        let dir = scratch("recovered");
        let fixture = super::signed_fixture();
        let anchors = anchors_for(&fixture);
        let key = TslDiskCache::key_for(SOURCE_ID, LOCATION);

        client_at(
            ToggleSource::online(fixture.xml.clone()),
            &dir,
            anchors.clone(),
            NOW,
        )
        .refresh(NOW)
        .expect("seed");
        client_at(
            ToggleSource::offline(fixture.xml.clone()),
            &dir,
            anchors.clone(),
            ONE_DAY_STALE,
        )
        .refresh(ONE_DAY_STALE)
        .expect("fall back");
        assert!(TslDiskCache::new(&dir).last_serve(&key).is_some());

        client_at(
            ToggleSource::online(fixture.xml.clone()),
            &dir,
            anchors,
            ONE_DAY_STALE,
        )
        .refresh(ONE_DAY_STALE)
        .expect("the network is back");
        assert!(
            TslDiskCache::new(&dir).last_serve(&key).is_none(),
            "a live fetch must clear the fallback record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
