//! PKCS#12/PFX software-certificate provider tests.
//!
//! Fixtures are generated locally in-process: no OS certificate store, no network, and no checked-in
//! private keys. The PFX wrapper uses `p12`'s legacy 3DES/RC2 profiles because that is the bounded
//! parser/decrypter this crate exposes for the soft-certificate foundation.

use std::str::FromStr;
use std::time::Duration as StdDuration;

use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use p12::PFX;
use rsa::pkcs8::{AlgorithmIdentifierRef, EncodePrivateKey, PrivateKeyInfo};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use zeroize::Zeroizing;

use chancela_signing::{
    EvidentiaryLevel, Pkcs12IdentitySelector, Pkcs12SigningSource, SignerProvider, SigningFamily,
    SoftCertificateError, sign_detached_cades,
};

const PASSWORD: &str = "correct horse battery staple";
const CONTENT_DIGEST: [u8; 32] = [0x5a; 32];
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

fn build_self_signed(
    cn: &str,
    serial: u8,
    spki: SubjectPublicKeyInfoOwned,
    sig_alg: AlgorithmIdentifierOwned,
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
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&[0u8; 64]).expect("bitstring"),
    };
    cert.to_der().expect("cert der")
}

fn rsa_cert_for(key: &rsa::RsaPrivateKey, cn: &str, serial: u8) -> Vec<u8> {
    let public = rsa::RsaPublicKey::from(key);
    let spki = SubjectPublicKeyInfoOwned::from_key(public).expect("rsa spki");
    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_SHA256_WITH_RSA,
        parameters: Some(Any::null()),
    };
    build_self_signed(cn, serial, spki, sig_alg)
}

fn p256_cert_for(key: &p256::ecdsa::SigningKey, cn: &str, serial: u8) -> Vec<u8> {
    let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("p256 spki");
    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_ECDSA_WITH_SHA256,
        parameters: None,
    };
    build_self_signed(cn, serial, spki, sig_alg)
}

fn issuer_cert() -> Vec<u8> {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("issuer key");
    rsa_cert_for(&key, "Chancela Soft Cert Issuer", 99)
}

fn rsa_pfx(name: &str) -> Vec<u8> {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
    let cert = rsa_cert_for(&key, "Chancela Soft RSA", 1);
    let ca = issuer_cert();
    let key_der = key.to_pkcs8_der().expect("rsa pkcs8");
    PFX::new_with_cas(&cert, key_der.as_bytes(), &[&ca], PASSWORD, name)
        .expect("pfx")
        .to_der()
}

fn p256_pfx(name: &str) -> Vec<u8> {
    let key = p256::ecdsa::SigningKey::random(&mut rsa::rand_core::OsRng);
    let cert = p256_cert_for(&key, "Chancela Soft P256", 2);
    let ca = issuer_cert();
    let key_der = key.to_pkcs8_der().expect("p256 pkcs8");
    PFX::new_with_cas(&cert, key_der.as_bytes(), &[&ca], PASSWORD, name)
        .expect("pfx")
        .to_der()
}

fn unsupported_key_pkcs8_der() -> Vec<u8> {
    let alg = AlgorithmIdentifierRef {
        oid: OID_ED25519,
        parameters: None,
    };
    PrivateKeyInfo::new(alg, &[1, 2, 3])
        .to_der()
        .expect("unsupported pkcs8 der")
}

fn password() -> Zeroizing<String> {
    Zeroizing::new(PASSWORD.to_owned())
}

fn assert_cades_round_trip(source: &Pkcs12SigningSource) {
    let cms = sign_detached_cades(source, &CONTENT_DIGEST, fixed_time()).expect("sign CAdES");
    let validation = chancela_cades::validate_cades_b(&cms, &CONTENT_DIGEST).expect("validate");
    assert!(validation.attrs_ok);
    assert_eq!(
        validation.signer_cert_der,
        source.signing_certificate_der().unwrap()
    );
}

#[test]
fn rsa_pkcs12_source_signs_detached_cades() {
    let pfx = rsa_pfx("rsa signing identity");
    let source = Pkcs12SigningSource::from_der_with_selector(
        &pfx,
        &password(),
        &Pkcs12IdentitySelector::by_friendly_name("rsa signing identity"),
    )
    .expect("load pfx");

    assert_eq!(source.family(), SigningFamily::QualifiedCertificate);
    assert_eq!(source.evidentiary_level(), EvidentiaryLevel::Advanced);
    assert_eq!(
        source.identity().friendly_name.as_deref(),
        Some("rsa signing identity")
    );
    assert_eq!(source.identity().chain_der.len(), 1);
    assert_eq!(
        source.issuer_certificate_der().unwrap(),
        source.identity().chain_der.first().cloned()
    );
    assert_cades_round_trip(&source);
}

#[test]
fn p256_pkcs12_source_signs_detached_cades() {
    let pfx = p256_pfx("p256 signing identity");
    let source = Pkcs12SigningSource::from_der(&pfx, &password()).expect("load pfx");

    assert_eq!(source.evidentiary_level(), EvidentiaryLevel::Advanced);
    assert_cades_round_trip(&source);
}

#[test]
fn wrong_password_is_typed() {
    let pfx = rsa_pfx("wrong password");
    let wrong = Zeroizing::new("not the password".to_owned());

    let err = Pkcs12SigningSource::from_der(&pfx, &wrong).unwrap_err();
    assert!(matches!(err, SoftCertificateError::WrongPassword));
}

#[test]
fn missing_private_key_is_typed() {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
    let cert = rsa_cert_for(&key, "No Key", 3);
    let pfx = PFX::new(&cert, &[], None, PASSWORD, "no-key")
        .expect("pfx without key")
        .to_der();

    let err = Pkcs12SigningSource::from_der(&pfx, &password()).unwrap_err();
    assert!(matches!(err, SoftCertificateError::MissingPrivateKey));
}

#[test]
fn empty_certificate_chain_is_typed() {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
    let key_der = key.to_pkcs8_der().expect("rsa pkcs8");
    let pfx = PFX::new(&[], key_der.as_bytes(), None, PASSWORD, "no-certs")
        .expect("pfx without certs")
        .to_der();

    let err = Pkcs12SigningSource::from_der(&pfx, &password()).unwrap_err();
    assert!(matches!(err, SoftCertificateError::EmptyCertificateChain));
}

#[test]
fn unsupported_private_key_algorithm_is_typed() {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
    let cert = rsa_cert_for(&key, "Unsupported Key", 4);
    let key_der = unsupported_key_pkcs8_der();
    let pfx = PFX::new(&cert, &key_der, None, PASSWORD, "unsupported")
        .expect("pfx")
        .to_der();

    let err = Pkcs12SigningSource::from_der(&pfx, &password()).unwrap_err();
    assert!(matches!(
        err,
        SoftCertificateError::UnsupportedKeyAlgorithm { .. }
    ));
}

#[test]
fn malformed_pkcs12_input_is_typed() {
    let err = Pkcs12SigningSource::from_der(b"not a pfx", &password()).unwrap_err();
    assert!(matches!(err, SoftCertificateError::MalformedInput(_)));
}
