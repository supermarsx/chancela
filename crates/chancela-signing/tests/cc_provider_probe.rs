//! Focused regression tests for the non-document Cartão de Cidadão provider probe.

use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration as StdDuration;

use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use rsa::rand_core::OsRng;
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_cades::SignatureAlgorithm;
use chancela_signing::{
    EvidentiaryLevel, MockProvider, RawSignature, SignerProvider, SigningError, SigningFamily,
    SmartcardProvider, probe_cc_provider, sign_detached_cades,
};
use chancela_smartcard::token::LABEL_SIGNATURE_CERT;
use chancela_smartcard::{CryptoToken, SmartcardError, TokenCertificate};

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

fn sign_digest(key: &rsa::RsaPrivateKey, digest: &[u8; 32]) -> Vec<u8> {
    let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
    digest_info.extend_from_slice(digest);
    key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
        .expect("RSA signature")
}

fn test_identity() -> (Arc<rsa::RsaPrivateKey>, Vec<u8>) {
    let key = Arc::new(rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key"));
    let spki =
        SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(key.as_ref())).expect("SPKI");
    let algorithm = AlgorithmIdentifierOwned {
        oid: OID_SHA256_WITH_RSA,
        parameters: Some(Any::null()),
    };
    let name = Name::from_str("CN=Chancela CC Provider Probe").expect("name");
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[1]).expect("serial"),
        signature: algorithm.clone(),
        issuer: name.clone(),
        validity: Validity::from_now(StdDuration::from_secs(24 * 60 * 60)).expect("validity"),
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };
    let signature = sign_digest(&key, &Sha256::digest(tbs.to_der().expect("TBS DER")).into());
    let certificate = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature).expect("signature bits"),
    }
    .to_der()
    .expect("certificate DER");
    (key, certificate)
}

#[test]
fn cc_provider_probe_signs_and_verifies_without_document_or_trust_policy() {
    let (key, certificate) = test_identity();
    let signer = key.clone();
    let provider = MockProvider::new(
        SigningFamily::CartaoDeCidadao,
        EvidentiaryLevel::Qualified,
        SignatureAlgorithm::RsaPkcs1Sha256,
        certificate,
        move |digest| Ok(sign_digest(&signer, digest)),
    );
    let challenge: [u8; 32] = Sha256::digest(b"chancela:cartao-cidadao:provider-probe:test").into();

    let result = probe_cc_provider(&provider, &challenge, OffsetDateTime::now_utc())
        .expect("probe must verify");

    assert_eq!(result.algorithm, SignatureAlgorithm::RsaPkcs1Sha256);
}

#[test]
fn cc_provider_probe_rejects_non_cc_family_before_invoking_signer() {
    let (_key, certificate) = test_identity();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_sign = calls.clone();
    let provider = MockProvider::new(
        SigningFamily::ChaveMovelDigital,
        EvidentiaryLevel::Qualified,
        SignatureAlgorithm::RsaPkcs1Sha256,
        certificate,
        move |_| {
            calls_for_sign.fetch_add(1, Ordering::SeqCst);
            Ok(vec![0; 256])
        },
    );

    let error = probe_cc_provider(&provider, &[7; 32], OffsetDateTime::now_utc())
        .expect_err("wrong family must fail");

    assert!(matches!(
        error,
        SigningError::FamilyMismatch {
            requested: SigningFamily::CartaoDeCidadao,
            provided: SigningFamily::ChaveMovelDigital,
        }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

struct SwitchingProvider {
    advertised_certificate: Vec<u8>,
    signer_key: Arc<rsa::RsaPrivateKey>,
    signer_certificate: Vec<u8>,
}

impl SignerProvider for SwitchingProvider {
    fn family(&self) -> SigningFamily {
        SigningFamily::CartaoDeCidadao
    }

    fn evidentiary_level(&self) -> EvidentiaryLevel {
        EvidentiaryLevel::Qualified
    }

    fn signing_certificate_der(&self) -> Result<Vec<u8>, SigningError> {
        Ok(self.advertised_certificate.clone())
    }

    fn issuer_certificate_der(&self) -> Result<Option<Vec<u8>>, SigningError> {
        Ok(None)
    }

    fn sign_signed_attributes(
        &self,
        signed_attrs_digest: &[u8; 32],
    ) -> Result<RawSignature, SigningError> {
        Ok(RawSignature::new(
            SignatureAlgorithm::RsaPkcs1Sha256,
            sign_digest(&self.signer_key, signed_attrs_digest),
            self.signer_certificate.clone(),
            Vec::new(),
        ))
    }
}

#[test]
fn cc_provider_probe_rejects_certificate_switch_after_challenge_construction() {
    let (_advertised_key, advertised_certificate) = test_identity();
    let (signer_key, signer_certificate) = test_identity();
    let provider = SwitchingProvider {
        advertised_certificate,
        signer_key,
        signer_certificate,
    };

    let error = probe_cc_provider(&provider, &[0xA5; 32], OffsetDateTime::now_utc())
        .expect_err("a replacement signing identity must fail closed");

    assert!(
        matches!(error, SigningError::Cades(message) if message.contains("changed signing certificate"))
    );
}

struct SwitchingToken {
    advertised_certificate: Vec<u8>,
    signer_key: Arc<rsa::RsaPrivateKey>,
    signer_certificate: Vec<u8>,
}

impl CryptoToken for SwitchingToken {
    fn list_certificates(&self) -> Result<Vec<TokenCertificate>, SmartcardError> {
        Ok(vec![TokenCertificate {
            label: LABEL_SIGNATURE_CERT.to_owned(),
            cert_der: self.advertised_certificate.clone(),
            algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
        }])
    }

    fn sign_digest(
        &self,
        _cert: &TokenCertificate,
        digest: &[u8; 32],
    ) -> Result<RawSignature, SmartcardError> {
        Ok(RawSignature::new(
            SignatureAlgorithm::RsaPkcs1Sha256,
            sign_digest(&self.signer_key, digest),
            self.signer_certificate.clone(),
            Vec::new(),
        ))
    }
}

#[test]
fn smartcard_provider_rejects_token_identity_switch_at_crypto_token_boundary() {
    let (_advertised_key, advertised_certificate) = test_identity();
    let (signer_key, signer_certificate) = test_identity();
    let provider = SmartcardProvider::new(SwitchingToken {
        advertised_certificate,
        signer_key,
        signer_certificate,
    });

    let error = provider
        .sign_signed_attributes(&[0x71; 32])
        .expect_err("token-returned identity must match selected leaf exactly");

    assert!(
        matches!(error, SigningError::Provider(message) if message.contains("changed signing certificate"))
    );
}

struct ForgedCertificateProvider {
    advertised_certificate: Vec<u8>,
    signer_key: Arc<rsa::RsaPrivateKey>,
}

impl SignerProvider for ForgedCertificateProvider {
    fn family(&self) -> SigningFamily {
        SigningFamily::CartaoDeCidadao
    }

    fn evidentiary_level(&self) -> EvidentiaryLevel {
        EvidentiaryLevel::Qualified
    }

    fn requires_cms_post_validation(&self) -> bool {
        true
    }

    fn signing_certificate_der(&self) -> Result<Vec<u8>, SigningError> {
        Ok(self.advertised_certificate.clone())
    }

    fn issuer_certificate_der(&self) -> Result<Option<Vec<u8>>, SigningError> {
        Ok(None)
    }

    fn sign_signed_attributes(
        &self,
        signed_attrs_digest: &[u8; 32],
    ) -> Result<RawSignature, SigningError> {
        Ok(RawSignature::new(
            SignatureAlgorithm::RsaPkcs1Sha256,
            sign_digest(&self.signer_key, signed_attrs_digest),
            self.advertised_certificate.clone(),
            Vec::new(),
        ))
    }
}

#[test]
fn detached_cc_cades_rejects_signature_from_key_outside_advertised_certificate() {
    let (_advertised_key, advertised_certificate) = test_identity();
    let (signer_key, _signer_certificate) = test_identity();
    let provider = ForgedCertificateProvider {
        advertised_certificate,
        signer_key,
    };

    let error = sign_detached_cades(&provider, &[0xC3; 32], OffsetDateTime::now_utc())
        .expect_err("invalid identity-switched CMS must never be returned");

    assert!(matches!(error, SigningError::Cades(_)));
}
