//! Local ASiC integration tests (t67-e7): ASiC-S/CAdES, ASiC-S/XAdES, and ASiC-E multi-signature
//! containers mixing CAdES and XAdES over one payload set, with a per-signature `ASiCManifest` and
//! an `ASiCArchiveManifest` archive timestamp. They exercise the real signing seam and the local
//! [`validate_asic_container`] report, without claiming complete ASiC/XAdES conformance, trust
//! status, or legal qualification.
//!
//! Signers mint ephemeral RSA-2048 / P-256 keys and self-signed certificates (no private keys are
//! checked in, plan §6), wrapped as [`MockProvider`] so the digest flows through the crate exactly
//! as a card / CMD signer would. The archive timestamp replays the bundled `chancela-tsa` OpenSSL
//! fixture with its message imprint rewritten to the archive-manifest digest (the technique from
//! `tests/ltv_execution.rs`), so the stored token's RFC 3161 imprint binds the manifest it protects.

use std::io::{Cursor, Read, Write};
use std::str::FromStr;
use std::time::Duration as StdDuration;

use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_signing::asic::AsicSignatureMemberKind;
use chancela_signing::{
    AsicContainerKind, AsicEMultiSignRequest, AsicPayload, AsicSignatureProfile, EvidentiaryLevel,
    MockProvider, SignerProvider, SigningError, SigningFamily, Timestamp, TimestampProvider,
    XadesLevel, sign_asic_e_multi, sign_asic_s, sign_asic_s_xades, validate_asic_container,
};

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

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
        signature: BitString::from_bytes(&[0u8; 32]).expect("bitstring"),
    };
    cert.to_der().expect("cert der")
}

/// A qualified provider backed by a real ephemeral RSA-2048 key.
fn rsa_provider(family: SigningFamily) -> MockProvider {
    use rsa::rand_core::OsRng;
    let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
    let spki =
        SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_SHA256_WITH_RSA,
        parameters: Some(Any::null()),
    };
    let cert_der = build_self_signed("Chancela RSA Signer", 1, spki, sig_alg);
    MockProvider::new(
        family,
        EvidentiaryLevel::Qualified,
        chancela_signing::SignatureAlgorithm::RsaPkcs1Sha256,
        cert_der,
        move |digest| {
            let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
            digest_info.extend_from_slice(digest);
            key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
                .map_err(|e| SigningError::Provider(e.to_string()))
        },
    )
}

/// A qualified provider backed by a real ephemeral P-256 key.
fn ecdsa_provider(family: SigningFamily) -> MockProvider {
    use p256::ecdsa::SigningKey;
    use rsa::rand_core::OsRng;
    let key = SigningKey::random(&mut OsRng);
    let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("ec spki");
    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_ECDSA_WITH_SHA256,
        parameters: None,
    };
    let cert_der = build_self_signed("Chancela P256 Signer", 2, spki, sig_alg);
    MockProvider::new(
        family,
        EvidentiaryLevel::Qualified,
        chancela_signing::SignatureAlgorithm::EcdsaP256Sha256,
        cert_der,
        move |digest| {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let sig: p256::ecdsa::Signature = key
                .sign_prehash(digest)
                .map_err(|e| SigningError::Provider(e.to_string()))?;
            Ok(sig.to_der().as_bytes().to_vec())
        },
    )
}

/// A TSA that replays the bundled fixture token with its imprint rewritten to the requested digest,
/// so the stored archive-timestamp imprint attests the manifest bytes it protects.
struct PatchingTsa;

fn patched_timestamp(digest: &[u8; 32]) -> Timestamp {
    let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
    let request = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
        .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
        .without_certificate();
    let mut ts = tsa.stamp(&request).expect("fixture timestamp");
    let pos = ts
        .token_der
        .windows(chancela_tsa::mock::FIXTURE_DIGEST.len())
        .position(|w| w == chancela_tsa::mock::FIXTURE_DIGEST)
        .expect("fixture imprint present in token");
    ts.token_der[pos..pos + digest.len()].copy_from_slice(digest);
    ts
}

impl TimestampProvider for PatchingTsa {
    fn timestamp_digest(&self, digest: &[u8; 32]) -> Result<Timestamp, SigningError> {
        Ok(patched_timestamp(digest))
    }
    fn timestamp_data(&self, data: &[u8]) -> Result<Timestamp, SigningError> {
        let digest: [u8; 32] = Sha256::digest(data).into();
        Ok(patched_timestamp(&digest))
    }
}

/// Rebuild a container replacing one member's bytes (used to forge a tampered payload).
fn replace_member(container: &[u8], target: &str, new_bytes: &[u8]) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(container)).expect("read zip");
    let stored = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(zip::DateTime::default());
    let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).expect("member");
        let name = file.name().to_owned();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).expect("read member");
        if name == target {
            bytes = new_bytes.to_vec();
        }
        out.start_file(&name, stored).expect("start member");
        out.write_all(&bytes).expect("write member");
    }
    out.finish().expect("finish zip").into_inner()
}

// --- ASiC-S -------------------------------------------------------------------------------------

#[test]
fn asic_s_cades_validates_through_full_surface() {
    let provider = rsa_provider(SigningFamily::CartaoDeCidadao);
    let content = b"approved minutes payload for ASiC-S/CAdES";
    let (container, _cades) =
        sign_asic_s(&provider, "minutes.txt", content, fixed_time()).expect("sign ASiC-S/CAdES");

    let report = validate_asic_container(&container).expect("validate ASiC-S/CAdES");
    assert_eq!(report.container_kind, AsicContainerKind::AsicS);
    assert_eq!(report.signature_profile, AsicSignatureProfile::Cades);
    assert!(report.is_valid(), "{:?}", report);
    assert_eq!(report.signatures.len(), 1);
    let sig = &report.signatures[0];
    assert_eq!(sig.kind, AsicSignatureMemberKind::Cades);
    assert!(sig.valid);
    assert_eq!(sig.covered_data_objects, vec!["minutes.txt".to_string()]);
    assert_eq!(
        sig.signer_cert_der.as_deref(),
        Some(provider.signing_certificate_der().unwrap().as_slice())
    );
    assert_eq!(
        sig.signing_time.map(|t| t.unix_timestamp()),
        Some(1_750_000_000)
    );
}

#[test]
fn asic_s_xades_round_trip() {
    let provider = ecdsa_provider(SigningFamily::CartaoDeCidadao);
    let content = b"approved minutes payload for ASiC-S/XAdES";
    let container = sign_asic_s_xades(
        &provider,
        "minutes.txt",
        content,
        fixed_time(),
        XadesLevel::B,
        None,
    )
    .expect("sign ASiC-S/XAdES");

    let report = validate_asic_container(&container).expect("validate ASiC-S/XAdES");
    assert_eq!(report.container_kind, AsicContainerKind::AsicS);
    assert_eq!(report.signature_profile, AsicSignatureProfile::Xades);
    assert!(report.is_valid(), "{:?}", report);
    let sig = &report.signatures[0];
    assert_eq!(sig.kind, AsicSignatureMemberKind::Xades);
    assert!(sig.valid);
    assert_eq!(sig.xades_level, Some(XadesLevel::B));
    assert!(!sig.has_signature_timestamp);
    assert_eq!(sig.covered_data_objects, vec!["minutes.txt".to_string()]);
    assert_eq!(
        sig.signer_cert_der.as_deref(),
        Some(provider.signing_certificate_der().unwrap().as_slice())
    );
}

#[test]
fn asic_s_xades_t_embeds_signature_timestamp() {
    let provider = rsa_provider(SigningFamily::ChaveMovelDigital);
    let content = b"minutes needing a signature timestamp";
    let container = sign_asic_s_xades(
        &provider,
        "minutes.txt",
        content,
        fixed_time(),
        XadesLevel::T,
        Some(&PatchingTsa),
    )
    .expect("sign ASiC-S/XAdES-T");

    let report = validate_asic_container(&container).expect("validate ASiC-S/XAdES-T");
    let sig = &report.signatures[0];
    assert_eq!(sig.xades_level, Some(XadesLevel::T));
    assert!(sig.has_signature_timestamp, "XAdES-T timestamp embedded");
    assert!(sig.valid, "{:?}", sig);
}

// --- ASiC-E multi-signature ---------------------------------------------------------------------

fn payloads() -> [(&'static str, &'static [u8]); 2] {
    [
        (
            "minutes.txt",
            b"approved minutes payload for ASiC-E" as &[u8],
        ),
        (
            "attachments/votes.csv",
            b"member,vote\nA,yes\nB,yes\n" as &[u8],
        ),
    ]
}

fn asic_payloads<'a>(raw: &'a [(&'a str, &'a [u8])]) -> Vec<AsicPayload<'a>> {
    raw.iter()
        .map(|(name, bytes)| AsicPayload {
            name,
            bytes,
            mime_type: Some("application/octet-stream"),
        })
        .collect()
}

#[test]
fn asic_e_multi_sig_mixed_cades_xades_with_archive_manifest() {
    let cades = rsa_provider(SigningFamily::CartaoDeCidadao);
    let xades = ecdsa_provider(SigningFamily::CartaoDeCidadao);
    let raw = payloads();
    let payloads = asic_payloads(&raw);

    let container = sign_asic_e_multi(AsicEMultiSignRequest {
        payloads: &payloads,
        cades_signers: &[&cades],
        xades_signers: &[&xades],
        signing_time: fixed_time(),
        xades_level: XadesLevel::B,
        xades_tsa: None,
        archive_tsa: Some(&PatchingTsa),
    })
    .expect("sign ASiC-E multi");

    let report = validate_asic_container(&container).expect("validate ASiC-E multi");
    assert_eq!(report.container_kind, AsicContainerKind::AsicE);
    assert_eq!(report.signature_profile, AsicSignatureProfile::Mixed);
    assert!(report.is_valid(), "{:?}", report);
    assert_eq!(
        report.signatures.len(),
        2,
        "one CAdES + one XAdES signature"
    );

    let cades_sig = report
        .signatures
        .iter()
        .find(|s| s.kind == AsicSignatureMemberKind::Cades)
        .expect("cades signature");
    assert!(cades_sig.valid);
    assert_eq!(
        cades_sig.manifest_path.as_deref(),
        Some("META-INF/ASiCManifest001.xml"),
        "per-signature ASiCManifest"
    );
    assert_eq!(cades_sig.covered_data_objects.len(), 2);
    assert_eq!(
        cades_sig.signer_cert_der.as_deref(),
        Some(cades.signing_certificate_der().unwrap().as_slice())
    );

    let xades_sig = report
        .signatures
        .iter()
        .find(|s| s.kind == AsicSignatureMemberKind::Xades)
        .expect("xades signature");
    assert!(xades_sig.valid);
    assert_eq!(xades_sig.covered_data_objects.len(), 2);
    assert_eq!(xades_sig.xades_level, Some(XadesLevel::B));

    assert_eq!(report.archive_timestamps.len(), 1);
    let archive = &report.archive_timestamps[0];
    assert_eq!(archive.manifest_path, "META-INF/ASiCArchiveManifest.xml");
    assert_eq!(archive.timestamp_path, "META-INF/ASiCArchiveManifest.tst");
    assert!(
        archive.imprint_matches_manifest,
        "archive TS binds the manifest"
    );
    assert!(archive.references_valid);
    assert!(archive.valid, "{:?}", archive);
    // The archive manifest covers both payloads plus every signature/manifest member.
    assert!(archive.covered_members.len() >= 2 + 3);
}

#[test]
fn asic_e_multi_sig_two_cades_signers_each_get_a_manifest() {
    let chair = rsa_provider(SigningFamily::CartaoDeCidadao);
    let secretary = ecdsa_provider(SigningFamily::CartaoDeCidadao);
    let raw = payloads();
    let payloads = asic_payloads(&raw);

    let container = sign_asic_e_multi(AsicEMultiSignRequest {
        payloads: &payloads,
        cades_signers: &[&chair, &secretary],
        xades_signers: &[],
        signing_time: fixed_time(),
        xades_level: XadesLevel::B,
        xades_tsa: None,
        archive_tsa: None,
    })
    .expect("sign two-CAdES ASiC-E");

    let report = validate_asic_container(&container).expect("validate two-CAdES ASiC-E");
    assert_eq!(report.signature_profile, AsicSignatureProfile::Cades);
    assert!(report.is_valid(), "{:?}", report);
    assert_eq!(report.signatures.len(), 2);
    let mut manifests: Vec<_> = report
        .signatures
        .iter()
        .map(|s| s.manifest_path.clone().expect("manifest per signature"))
        .collect();
    manifests.sort();
    assert_eq!(
        manifests,
        vec![
            "META-INF/ASiCManifest001.xml".to_string(),
            "META-INF/ASiCManifest002.xml".to_string()
        ]
    );
}

#[test]
fn asic_e_multi_sig_tampered_payload_is_rejected() {
    let cades = rsa_provider(SigningFamily::CartaoDeCidadao);
    let xades = ecdsa_provider(SigningFamily::CartaoDeCidadao);
    let raw = payloads();
    let payloads = asic_payloads(&raw);

    let container = sign_asic_e_multi(AsicEMultiSignRequest {
        payloads: &payloads,
        cades_signers: &[&cades],
        xades_signers: &[&xades],
        signing_time: fixed_time(),
        xades_level: XadesLevel::B,
        xades_tsa: None,
        archive_tsa: Some(&PatchingTsa),
    })
    .expect("sign ASiC-E multi");

    // Flip one payload's bytes after signing: every binding over it must now fail.
    let tampered = replace_member(&container, "minutes.txt", b"tampered minutes");
    let report = validate_asic_container(&tampered).expect("validate tampered ASiC-E");
    assert!(!report.is_valid(), "tampered payload must be rejected");

    let cades_sig = report
        .signatures
        .iter()
        .find(|s| s.kind == AsicSignatureMemberKind::Cades)
        .expect("cades signature");
    assert!(!cades_sig.valid);
    assert!(
        cades_sig
            .failure_reasons
            .iter()
            .any(|r| r.contains("digest mismatch")),
        "{:?}",
        cades_sig.failure_reasons
    );

    let xades_sig = report
        .signatures
        .iter()
        .find(|s| s.kind == AsicSignatureMemberKind::Xades)
        .expect("xades signature");
    assert!(!xades_sig.valid);
    assert!(
        xades_sig
            .failure_reasons
            .iter()
            .any(|r| r.contains("minutes.txt")),
        "{:?}",
        xades_sig.failure_reasons
    );

    let archive = &report.archive_timestamps[0];
    assert!(
        !archive.valid,
        "archive manifest must reject the tampered payload"
    );
    assert!(!archive.references_valid);
}
