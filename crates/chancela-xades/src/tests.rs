//! Offline, deterministic round-trip tests for XMLDSig/XAdES build → sign → validate.
//!
//! Test certificates and keys are generated ephemerally in-test (no private keys are checked in,
//! mirroring `chancela-cades`). Both supported profiles are exercised: RSA-PKCS1-SHA256 (Cartão de
//! Cidadão v1 / Chave Móvel Digital) and ECDSA-P256-SHA256 (CC v2). These live in-crate (not under
//! `tests/`) so they can reach the crate's own crypto dependencies (`rsa`, `p256`, `x509-cert`).

use std::str::FromStr;
use std::time::Duration as StdDuration;

use chancela_cades::{RawSignature, SignatureAlgorithm};
use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::c14n::{self, C14nAlgorithm};
use crate::validate::validate_xades;
use crate::xades::{
    DetachedRef, EnvelopedDocument, EnvelopingObject, ObjectContent, SignaturePackaging,
    XadesContext, XadesLevel, XadesSignRequest, prepare_xades,
};
use crate::xmldsig::{DIGEST_SHA256, DS_NS, Reference, XADES_NS, XmlDsigBuilder};

const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// A test signer bundling an ephemeral key and its self-signed certificate.
enum TestSigner {
    Rsa {
        key: Box<rsa::RsaPrivateKey>,
        cert_der: Vec<u8>,
    },
    Ecdsa {
        key: p256::ecdsa::SigningKey,
        cert_der: Vec<u8>,
    },
}

impl TestSigner {
    fn new_rsa(cn: &str, serial: u8) -> Self {
        use rsa::rand_core::OsRng;
        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let public = rsa::RsaPublicKey::from(&key);
        let spki = SubjectPublicKeyInfoOwned::from_key(public).expect("rsa spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        };
        let signer_key = key.clone();
        let cert_der = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            sign_rsa_digest_info(&signer_key, &sha256(tbs))
        });
        Self::Rsa {
            key: Box::new(key),
            cert_der,
        }
    }

    fn new_ecdsa(cn: &str, serial: u8) -> Self {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;
        use rsa::rand_core::OsRng;
        let key = SigningKey::random(&mut OsRng);
        let verifying = *key.verifying_key();
        let spki = SubjectPublicKeyInfoOwned::from_key(verifying).expect("ec spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None,
        };
        let signer_key = key.clone();
        let cert_der = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            let sig: p256::ecdsa::Signature = signer_key.sign(tbs);
            sig.to_der().as_bytes().to_vec()
        });
        Self::Ecdsa { key, cert_der }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            TestSigner::Rsa { .. } => SignatureAlgorithm::RsaPkcs1Sha256,
            TestSigner::Ecdsa { .. } => SignatureAlgorithm::EcdsaP256Sha256,
        }
    }

    fn cert_der(&self) -> Vec<u8> {
        match self {
            TestSigner::Rsa { cert_der, .. } | TestSigner::Ecdsa { cert_der, .. } => {
                cert_der.clone()
            }
        }
    }

    /// Sign a 32-byte digest exactly as the real token/remote signer would: RSA → PKCS#1 v1.5 over
    /// `DigestInfo`; ECDSA → raw over the prehash, DER-encoded (r, s) as the [`RawSignature`] contract.
    fn sign_digest(&self, digest: &[u8; 32]) -> Vec<u8> {
        match self {
            TestSigner::Rsa { key, .. } => sign_rsa_digest_info(key, digest),
            TestSigner::Ecdsa { key, .. } => {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                let sig: p256::ecdsa::Signature =
                    key.sign_prehash(digest).expect("ecdsa prehash sign");
                sig.to_der().as_bytes().to_vec()
            }
        }
    }

    fn raw_signature(&self, digest: &[u8; 32]) -> RawSignature {
        RawSignature::new(
            self.algorithm(),
            self.sign_digest(digest),
            self.cert_der(),
            vec![],
        )
    }
}

fn sign_rsa_digest_info(key: &rsa::RsaPrivateKey, digest: &[u8; 32]) -> Vec<u8> {
    let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
    digest_info.extend_from_slice(digest);
    key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
        .expect("rsa sign")
}

fn build_self_signed(
    cn: &str,
    serial: u8,
    spki: SubjectPublicKeyInfoOwned,
    sig_alg: AlgorithmIdentifierOwned,
    sign: impl Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let name = Name::from_str(&format!("CN={cn}")).expect("name");
    let validity = Validity::from_now(StdDuration::from_secs(365 * 24 * 3600)).expect("validity");
    let tbs = TbsCertificate {
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
    };
    let tbs_der = tbs.to_der().expect("tbs der");
    let signature = sign(&tbs_der);
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&signature).expect("bitstring"),
    };
    cert.to_der().expect("cert der")
}

fn fixed_time() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

fn context() -> XadesContext {
    XadesContext {
        signing_time: fixed_time(),
    }
}

fn enveloping_request(signer: &TestSigner, level: XadesLevel) -> XadesSignRequest {
    XadesSignRequest {
        signature_id: "sig-1".into(),
        signing_cert_der: signer.cert_der(),
        sig_alg: signer.algorithm(),
        level,
        context: context(),
        packaging: SignaturePackaging::Enveloping(vec![EnvelopingObject {
            id: "obj-1".into(),
            content: ObjectContent::Text("Chancela: livro de atas, ato numero 42".into()),
        }]),
    }
}

fn sign_to_bytes(signer: &TestSigner, req: XadesSignRequest) -> Vec<u8> {
    let prepared = prepare_xades(req).expect("prepare");
    let digest = prepared.signed_info_digest();
    let raw = signer.raw_signature(&digest);
    let assembled = prepared.assemble(&raw).expect("assemble");
    assembled.into_bytes().expect("into_bytes")
}

fn assert_valid_b(xml: &[u8]) {
    let report = validate_xades(xml).expect("validate");
    assert!(
        report.signature_valid,
        "signature must verify over SignedInfo"
    );
    assert!(report.references_valid, "all references must match");
    assert!(
        report.signed_properties_present,
        "XAdES-B needs SignedProperties"
    );
    assert!(
        report.signing_certificate_v2_present,
        "XAdES-B needs SigningCertificateV2"
    );
    assert!(
        report.signed_properties_signed,
        "a verified reference must cover the SignedProperties"
    );
    assert!(report.is_valid_b(), "overall XAdES-B validity");
    assert_eq!(report.level, XadesLevel::B);
    assert_eq!(
        report.signing_time.expect("signing time").unix_timestamp(),
        1_750_000_000
    );
}

#[test]
fn xades_b_enveloping_roundtrip_rsa() {
    let signer = TestSigner::new_rsa("Chancela RSA XAdES", 1);
    let xml = sign_to_bytes(&signer, enveloping_request(&signer, XadesLevel::B));
    assert_valid_b(&xml);
    let report = validate_xades(&xml).unwrap();
    // Data object + SignedProperties.
    assert_eq!(report.reference_count, 2);
    assert_eq!(report.references_checked, 2);
    assert_eq!(
        report.signer_cert_der.as_deref(),
        Some(signer.cert_der().as_slice())
    );
}

#[test]
fn xades_b_enveloping_roundtrip_ecdsa() {
    let signer = TestSigner::new_ecdsa("Chancela P256 XAdES", 2);
    let xml = sign_to_bytes(&signer, enveloping_request(&signer, XadesLevel::B));
    assert_valid_b(&xml);
}

#[test]
fn xades_b_detached_roundtrip() {
    let signer = TestSigner::new_ecdsa("Detached", 3);
    let req = XadesSignRequest {
        signature_id: "sig-det".into(),
        signing_cert_der: signer.cert_der(),
        sig_alg: signer.algorithm(),
        level: XadesLevel::B,
        context: context(),
        packaging: SignaturePackaging::Detached(vec![DetachedRef {
            uri: "document.pdf".into(),
            bytes: b"%PDF-1.7 detached content".to_vec(),
        }]),
    };
    let xml = sign_to_bytes(&signer, req);
    let report = validate_xades(&xml).expect("validate");
    assert!(report.signature_valid);
    assert!(report.is_valid_b());
    assert_eq!(report.reference_count, 2);
    // The external detached reference cannot be dereferenced from a bare signature; only the
    // same-document SignedProperties reference is checked here.
    assert_eq!(report.references_checked, 1);
}

#[test]
fn xades_b_enveloped_roundtrip() {
    let signer = TestSigner::new_rsa("Enveloped", 4);
    let doc = b"<Invoice xmlns=\"urn:chancela:test\"><Id>42</Id><Total>100</Total></Invoice>";
    let req = XadesSignRequest {
        signature_id: "sig-env".into(),
        signing_cert_der: signer.cert_der(),
        sig_alg: signer.algorithm(),
        level: XadesLevel::B,
        context: context(),
        packaging: SignaturePackaging::Enveloped(EnvelopedDocument { xml: doc.to_vec() }),
    };
    let xml = sign_to_bytes(&signer, req);
    let report = validate_xades(&xml).expect("validate");
    assert!(report.signature_valid, "enveloped signature verifies");
    assert!(
        report.references_valid,
        "enveloped + signedprops references match"
    );
    assert!(report.is_valid_b());
    assert_eq!(report.reference_count, 2);
    assert_eq!(report.references_checked, 2);
}

#[test]
fn corrupted_signature_is_rejected() {
    let signer = TestSigner::new_rsa("Corrupt", 5);
    let prepared = prepare_xades(enveloping_request(&signer, XadesLevel::B)).unwrap();
    let digest = prepared.signed_info_digest();
    let mut raw = signer.raw_signature(&digest);
    let last = raw.signature.len() - 1;
    raw.signature[last] ^= 0xff;
    let xml = prepared.assemble(&raw).unwrap().into_bytes().unwrap();
    let report = validate_xades(&xml).expect("validate");
    assert!(
        !report.signature_valid,
        "a corrupted signature must not verify"
    );
    assert!(!report.is_valid_b());
}

#[test]
fn tampered_object_breaks_reference_digest() {
    // Sign one object, then swap the embedded object bytes in the assembled XML → its reference
    // digest must no longer match.
    let signer = TestSigner::new_ecdsa("Tamper", 6);
    let xml = sign_to_bytes(&signer, enveloping_request(&signer, XadesLevel::B));
    let text = String::from_utf8(xml).unwrap();
    let tampered = text.replace("ato numero 42", "ato numero 99").into_bytes();
    let report = validate_xades(&tampered).expect("validate");
    assert!(
        !report.references_valid,
        "tampered object must fail its digest"
    );
    assert!(!report.is_valid_b());
}

#[test]
fn wrong_algorithm_declared_is_rejected() {
    // The signer must produce the algorithm the SignedInfo declares.
    let rsa = TestSigner::new_rsa("A", 7);
    let ecdsa = TestSigner::new_ecdsa("B", 8);
    let prepared = prepare_xades(enveloping_request(&rsa, XadesLevel::B)).unwrap();
    let digest = prepared.signed_info_digest();
    // Feed an ECDSA RawSignature where the SignedInfo declares RSA.
    let raw = ecdsa.raw_signature(&digest);
    assert!(prepared.assemble(&raw).is_err());
}

#[test]
fn xades_lt_lta_are_typed_not_yet_supported() {
    let signer = TestSigner::new_rsa("LT", 9);
    for level in [XadesLevel::LT, XadesLevel::LTA] {
        assert!(
            matches!(
                prepare_xades(enveloping_request(&signer, level)),
                Err(crate::XadesError::NotYetSupported(_))
            ),
            "level {level:?} must report NotYetSupported"
        );
    }
}

#[test]
fn xades_t_embeds_and_reports_signature_timestamp() {
    use chancela_tsa::mock::{FIXTURE_DIGEST, FIXTURE_NONCE};
    use chancela_tsa::{MockTsaTransport, TsaClient};

    let signer = TestSigner::new_ecdsa("XAdES-T", 10);
    let prepared = prepare_xades(enveloping_request(&signer, XadesLevel::T)).unwrap();
    let digest = prepared.signed_info_digest();
    let raw = signer.raw_signature(&digest);
    let assembled = prepared.assemble(&raw).unwrap();

    // The digest that a production TSA would timestamp (exc-c14n of ds:SignatureValue).
    let _ts_digest = assembled.signature_timestamp_digest().expect("ts digest");

    // Obtain a genuine RFC 3161 TimeStampToken via chancela-tsa's offline fixture transport. (The
    // fixture token covers the fixture digest; binding the token imprint to SignatureValue is a
    // trust-layer / XAdES-LT concern, out of scope for the XAdES-T structural embedding.)
    let client = TsaClient::new(MockTsaTransport::from_fixture());
    let request = chancela_tsa::TimestampRequest::new(FIXTURE_DIGEST)
        .without_certificate()
        .with_nonce(FIXTURE_NONCE);
    let timestamp = client.stamp(&request).expect("verify fixture token");

    let xml = assembled
        .with_signature_timestamp(&timestamp.token_der)
        .expect("embed timestamp");

    let report = validate_xades(&xml).expect("validate");
    assert!(report.signature_valid, "T signature still verifies");
    assert!(report.references_valid);
    assert!(
        report.signature_timestamp_present,
        "SignatureTimeStamp must be present"
    );
    assert_eq!(report.level, XadesLevel::T);
}

/// H1 (t68) — a genuinely valid XMLDSig over body content, plus an *unsigned* SignedProperties /
/// SigningCertificateV2 blob appended in the signature, must NOT be reported XAdES-B valid: no
/// digest-verified reference covers the qualifying properties, so the signer never committed to
/// them. The old whole-document existence check reported this as valid.
#[test]
fn unsigned_signed_properties_blob_is_not_valid_b() {
    let signer = TestSigner::new_rsa("H1 unsigned props", 20);

    // Digest of the enveloping payload object over its exclusive-C14N, computed exactly as the
    // validator recomputes it (the `ds` prefix declared on an ancestor).
    let object_xml = "<ds:Object Id=\"payload\">Chancela: ato numero 7</ds:Object>";
    let obj_wrapper = format!("<ds:Signature xmlns:ds=\"{DS_NS}\">{object_xml}</ds:Signature>");
    let obj_c14n = c14n::canonicalize_element_by_id(
        obj_wrapper.as_bytes(),
        "payload",
        C14nAlgorithm::ExclusiveWithoutComments,
        &[],
    )
    .expect("c14n object");
    let obj_digest = sha256(&obj_c14n);

    // A plain XMLDSig: the only signed reference is the payload; there is NO SignedProperties
    // reference in SignedInfo.
    let mut builder = XmlDsigBuilder::new("sig-h1", signer.algorithm());
    builder.declare_ns("xades", XADES_NS);
    builder.add_cert(signer.cert_der());
    builder.add_reference(Reference {
        uri: "#payload".into(),
        id: None,
        ref_type: None,
        transforms: vec![C14nAlgorithm::ExclusiveWithoutComments.uri().to_string()],
        digest: obj_digest,
    });
    builder.add_object(object_xml.to_string());
    // Append an unsigned SignedProperties carrying SigningTime + SigningCertificateV2, not covered
    // by any reference — the "append a qualifying blob anywhere" attack.
    builder.add_object(format!(
        "<ds:Object><xades:QualifyingProperties Target=\"#sig-h1\">\
         <xades:SignedProperties Id=\"forged-props\"><xades:SignedSignatureProperties>\
         <xades:SigningTime>2026-01-01T00:00:00Z</xades:SigningTime>\
         <xades:SigningCertificateV2><xades:Cert><xades:CertDigest>\
         <ds:DigestMethod Algorithm=\"{DIGEST_SHA256}\"></ds:DigestMethod>\
         <ds:DigestValue>AAAA</ds:DigestValue></xades:CertDigest></xades:Cert>\
         </xades:SigningCertificateV2></xades:SignedSignatureProperties>\
         </xades:SignedProperties></xades:QualifyingProperties></ds:Object>"
    ));

    let digest = builder.signed_info_digest().expect("signed_info digest");
    let raw = signer.raw_signature(&digest);
    let xml = builder.assemble(&raw).expect("assemble");

    let report = validate_xades(&xml).expect("validate");
    // The underlying XMLDSig really is cryptographically sound over its body reference.
    assert!(report.signature_valid, "the XMLDSig itself verifies");
    assert!(report.references_valid, "the body reference matches");
    assert_eq!(report.references_checked, 1);
    // The permissive presence flags are still true — which is exactly why they must not gate validity.
    assert!(report.signed_properties_present);
    assert!(report.signing_certificate_v2_present);
    // But nothing signed covers the SignedProperties, so it is not XAdES-B valid.
    assert!(
        !report.signed_properties_signed,
        "no verified reference covers the appended SignedProperties"
    );
    assert!(
        !report.is_valid_b(),
        "an unsigned SignedProperties blob must not satisfy XAdES-B"
    );
}

/// H2 (t68) — a document carrying two elements with the same `Id` is rejected outright: `Id`
/// resolution must fail closed rather than silently pick the first match (the signature-wrapping /
/// XSW lever). A unique-`Id` document still validates.
#[test]
fn duplicate_id_is_rejected() {
    let signer = TestSigner::new_ecdsa("H2 duplicate id", 21);
    let xml = sign_to_bytes(&signer, enveloping_request(&signer, XadesLevel::B));
    // Baseline: the genuine, unique-Id document validates.
    assert!(
        validate_xades(&xml).expect("validate genuine").is_valid_b(),
        "the unique-Id document is valid"
    );

    // Inject a second element carrying the payload's Id ("obj-1") — the XSW wrapper. The genuine
    // reference still digests the original, but resolution is now ambiguous and must be rejected.
    let text = String::from_utf8(xml).unwrap();
    let injected = "<ds:Object Id=\"obj-1\">forged</ds:Object></ds:Signature>";
    let tampered = text.replace("</ds:Signature>", injected).into_bytes();

    let result = validate_xades(&tampered);
    assert!(
        result.is_err(),
        "a document with a duplicate Id must be rejected, got {result:?}"
    );
}
