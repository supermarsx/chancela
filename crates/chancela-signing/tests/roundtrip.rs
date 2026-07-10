//! Cryptographic round-trip tests: drive a real in-test key through `chancela-signing`'s pipeline
//! (detached CAdES-B and PAdES-B-B / B-T) and validate the result end to end.
//!
//! The in-test signer mints an ephemeral RSA-2048 / P-256 key and a self-signed certificate (no
//! private keys are checked in, plan §6), mirroring `chancela-cades/src/tests.rs` and
//! `chancela-pades/src/tests.rs`. It is wrapped as a [`MockProvider`] so the signature flows through
//! this crate's `sign_slot` / pipeline exactly as a real provider would. The B-T timestamp is driven
//! from the bundled `chancela-tsa` OpenSSL fixture.

use std::io::{Cursor, Write};
use std::str::FromStr;
use std::time::Duration as StdDuration;

use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_signing::{
    ASICE_CADES_SIGNATURE_PATH, ASICE_MANIFEST_PATH, ASICE_MIMETYPE, ASICS_MIMETYPE, AsicPayload,
    BaselineProfile, DocumentInput, EvidentiaryLevel, MockProvider, SignOptions, SignatureArtifact,
    SignatureEnvelope, SignatureFormat, SignatureRequest, SignerCapacity, SignerProvider,
    SigningError, SigningFamily, SigningJob, SigningOrder, StaticTrustPolicy, Timestamp,
    TimestampProvider, TrustedListStatus, create_asic_e_container, create_asic_s_container,
    extract_asic_e_container, extract_asic_s_container, sha256_content_digest, sign_slot,
    validate_signature,
};

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const CONTENT_DIGEST: [u8; 32] = [0x42; 32];

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

// --- In-test signers wrapped as MockProviders ----------------------------------------------------

/// Hand-build a self-signed certificate. The signature bytes are a placeholder: certificate-chain
/// validation is out of scope for `validate_cades_b`, which only reads the subject public key.
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

// --- Minimal base PDF (classic cross-reference table, mirrors chancela-pades tests) --------------

fn assemble_pdf(objects: &[(u32, &str)], root: u32) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::new();
    for (id, body) in objects {
        offsets.push((*id, buf.len()));
        buf.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    let xref_off = buf.len();
    let max_id = objects.iter().map(|(id, _)| *id).max().unwrap();
    buf.extend_from_slice(format!("xref\n0 {}\n", max_id + 1).as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f\r\n");
    for id in 1..=max_id {
        let off = offsets
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, o)| *o)
            .unwrap();
        buf.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {} /Root {root} 0 R >>\n", max_id + 1).as_bytes(),
    );
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

fn base_pdf() -> Vec<u8> {
    assemble_pdf(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
        ],
        1,
    )
}

/// A `TimestampProvider` that replays the bundled `chancela-tsa` OpenSSL fixture regardless of the
/// input digest (the fixture attests a fixed digest; the embedding logic under test is independent
/// of which digest the token covers).
struct FixtureTsa;

impl FixtureTsa {
    fn token() -> Result<Timestamp, SigningError> {
        let request = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
            .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
            .without_certificate();
        chancela_tsa::verify_response(
            chancela_tsa::mock::FIXTURE_RESPONSE_DER,
            &request,
            &chancela_tsa::QualifiedTimestampPolicy::Any,
        )
        .map_err(|e| SigningError::Timestamp(e.to_string()))
    }
}

impl TimestampProvider for FixtureTsa {
    fn timestamp_digest(&self, _digest: &[u8; 32]) -> Result<Timestamp, SigningError> {
        Self::token()
    }
    fn timestamp_data(&self, _data: &[u8]) -> Result<Timestamp, SigningError> {
        Self::token()
    }
}

fn request(
    family: SigningFamily,
    format: SignatureFormat,
    profile: BaselineProfile,
) -> SignatureRequest {
    SignatureRequest {
        family,
        format,
        profile,
        capacity: SignerCapacity::Chair,
        document_digest: CONTENT_DIGEST,
    }
}

// --- CAdES round-trips ---------------------------------------------------------------------------

fn cades_round_trip(provider: &dyn chancela_signing::SignerProvider) {
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            provider.family(),
            SignatureFormat::CAdES,
            BaselineProfile::B_B,
        )],
    );
    sign_slot(
        &mut env,
        0,
        SigningJob {
            provider,
            policy: None,
            tsa: None,
            input: DocumentInput::Digest(&CONTENT_DIGEST),
            signing_time: fixed_time(),
            pdf_options: SignOptions::default(),
        },
    )
    .expect("sign detached CAdES");

    let artifact = &env.artifacts[0];
    let report = validate_signature(artifact, Some(&CONTENT_DIGEST)).expect("validate CAdES");
    assert!(report.cryptographically_valid);
    assert_eq!(report.evidentiary_level, EvidentiaryLevel::Qualified);
    assert_eq!(
        report.signer_cert_der,
        provider.signing_certificate_der().unwrap()
    );
    assert_eq!(
        report.signing_time.map(|t| t.unix_timestamp()),
        Some(1_750_000_000)
    );
    assert!(!report.has_signature_timestamp);
}

#[test]
fn cades_detached_round_trip_rsa() {
    cades_round_trip(&rsa_provider(SigningFamily::CartaoDeCidadao));
}

#[test]
fn cades_detached_round_trip_ecdsa() {
    cades_round_trip(&ecdsa_provider(SigningFamily::CartaoDeCidadao));
}

#[test]
fn tampered_content_digest_fails_cades_validation() {
    let provider = rsa_provider(SigningFamily::CartaoDeCidadao);
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::CAdES,
            BaselineProfile::B_B,
        )],
    );
    sign_slot(
        &mut env,
        0,
        SigningJob {
            provider: &provider,
            policy: None,
            tsa: None,
            input: DocumentInput::Digest(&CONTENT_DIGEST),
            signing_time: fixed_time(),
            pdf_options: SignOptions::default(),
        },
    )
    .unwrap();
    // Validating against a different content digest must fail (message-digest mismatch).
    let other = [0x11u8; 32];
    let err = validate_signature(&env.artifacts[0], Some(&other)).unwrap_err();
    assert!(matches!(err, SigningError::Cades(_)), "got {err:?}");
}

// --- PAdES round-trips ---------------------------------------------------------------------------

#[test]
fn pades_b_b_round_trip_rsa() {
    let provider = rsa_provider(SigningFamily::CartaoDeCidadao);
    let pdf = base_pdf();
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::PAdES,
            BaselineProfile::B_B,
        )],
    );
    sign_slot(
        &mut env,
        0,
        SigningJob {
            provider: &provider,
            policy: None,
            tsa: None,
            input: DocumentInput::Pdf(&pdf),
            signing_time: fixed_time(),
            pdf_options: SignOptions {
                reason: Some("Ata aprovada em assembleia".into()),
                ..SignOptions::default()
            },
        },
    )
    .expect("sign PAdES");

    let artifact = &env.artifacts[0];
    assert_eq!(artifact.profile, BaselineProfile::B_B);
    assert!(artifact.timestamp_token_der.is_none());

    let report = validate_signature(artifact, None).expect("validate PAdES");
    assert!(report.cryptographically_valid);
    assert_eq!(report.covers_whole_file, Some(true));
    assert!(!report.has_signature_timestamp);
    assert_eq!(report.evidentiary_level, EvidentiaryLevel::Qualified);
    assert_eq!(
        report.signer_cert_der,
        provider.signing_certificate_der().unwrap()
    );
}

#[test]
fn pades_b_t_round_trip_embeds_timestamp() {
    let provider = ecdsa_provider(SigningFamily::CartaoDeCidadao);
    let pdf = base_pdf();
    let tsa = FixtureTsa;
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        // Requesting an archival profile (B-LTA) reaches B-T here; LT/LTA are phase-2.
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::PAdES,
            BaselineProfile::B_LTA,
        )],
    );
    sign_slot(
        &mut env,
        0,
        SigningJob {
            provider: &provider,
            policy: None,
            tsa: Some(&tsa),
            input: DocumentInput::Pdf(&pdf),
            signing_time: fixed_time(),
            pdf_options: SignOptions::default(),
        },
    )
    .expect("sign PAdES B-T");

    let artifact = &env.artifacts[0];
    assert_eq!(
        artifact.profile,
        BaselineProfile::B_T,
        "timestamp reached B-T"
    );
    assert!(artifact.timestamp_token_der.is_some());

    let report = validate_signature(artifact, None).expect("validate B-T");
    assert!(
        report.has_signature_timestamp,
        "signature timestamp embedded"
    );
    assert_eq!(
        report.covers_whole_file,
        Some(true),
        "B-B signature undisturbed"
    );
}

#[test]
fn cades_timestamp_is_attached_as_external_evidence() {
    // For detached CAdES, a requested timestamp is captured as external evidence (in-CMS B-T
    // embedding is a phase-2 seam); the profile stays honestly at B-B.
    let provider = rsa_provider(SigningFamily::ChaveMovelDigital);
    let tsa = FixtureTsa;
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::ChaveMovelDigital,
            SignatureFormat::CAdES,
            BaselineProfile::B_T,
        )],
    );
    sign_slot(
        &mut env,
        0,
        SigningJob {
            provider: &provider,
            policy: None,
            tsa: Some(&tsa),
            input: DocumentInput::Digest(&CONTENT_DIGEST),
            signing_time: fixed_time(),
            pdf_options: SignOptions::default(),
        },
    )
    .unwrap();

    let artifact = &env.artifacts[0];
    assert_eq!(artifact.profile, BaselineProfile::B_B);
    assert!(
        artifact.timestamp_token_der.is_some(),
        "timestamp token attached"
    );
    let report = validate_signature(artifact, Some(&CONTENT_DIGEST)).unwrap();
    assert!(report.has_signature_timestamp);
}

// --- ASiC-S/CAdES round-trips --------------------------------------------------------------------

fn asic_artifact(signature: Vec<u8>) -> SignatureArtifact {
    SignatureArtifact {
        id: uuid::Uuid::nil(),
        slot: 0,
        family: SigningFamily::CartaoDeCidadao,
        format: SignatureFormat::ASiC,
        profile: BaselineProfile::B_B,
        evidentiary_level: EvidentiaryLevel::Qualified,
        signed_at: Some(fixed_time()),
        signature,
        trusted_list_status: None,
        timestamp_token_der: None,
    }
}

fn zip_container(members: &[(&str, &[u8])]) -> Vec<u8> {
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(zip::DateTime::default());
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in members {
        zip.start_file(*name, options).expect("start zip member");
        zip.write_all(bytes).expect("write zip member");
    }
    zip.finish().expect("finish zip").into_inner()
}

#[test]
fn asic_s_cades_round_trip_rsa() {
    let provider = rsa_provider(SigningFamily::CartaoDeCidadao);
    let content = b"approved minutes payload for ASiC-S";
    let expected_digest = sha256_content_digest(content);
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::ASiC,
            BaselineProfile::B_B,
        )],
    );

    sign_slot(
        &mut env,
        0,
        SigningJob {
            provider: &provider,
            policy: None,
            tsa: None,
            input: DocumentInput::AsicContent {
                name: "minutes.txt",
                bytes: content,
            },
            signing_time: fixed_time(),
            pdf_options: SignOptions::default(),
        },
    )
    .expect("sign ASiC-S");

    let artifact = &env.artifacts[0];
    assert_eq!(artifact.format, SignatureFormat::ASiC);
    assert_eq!(artifact.profile, BaselineProfile::B_B);
    assert!(
        artifact.signature.starts_with(b"PK"),
        "ASiC artifact is a ZIP container"
    );

    let parsed = extract_asic_s_container(&artifact.signature).expect("parse ASiC-S");
    assert_eq!(parsed.content_name, "minutes.txt");
    assert_eq!(parsed.content, content);
    assert!(!parsed.cades_signature_der.is_empty());

    let report =
        validate_signature(artifact, Some(&expected_digest)).expect("validate ASiC-S/CAdES");
    assert!(report.cryptographically_valid);
    assert_eq!(report.evidentiary_level, EvidentiaryLevel::Qualified);
    assert_eq!(
        report.signer_cert_der,
        provider.signing_certificate_der().unwrap()
    );
    assert!(!report.has_signature_timestamp);
    assert_eq!(report.covers_whole_file, None);
}

#[test]
fn asic_s_payload_tamper_fails_cades_validation() {
    let provider = rsa_provider(SigningFamily::CartaoDeCidadao);
    let content = b"original ASiC-S payload";
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::ASiC,
            BaselineProfile::B_B,
        )],
    );
    sign_slot(
        &mut env,
        0,
        SigningJob {
            provider: &provider,
            policy: None,
            tsa: None,
            input: DocumentInput::AsicContent {
                name: "minutes.txt",
                bytes: content,
            },
            signing_time: fixed_time(),
            pdf_options: SignOptions::default(),
        },
    )
    .unwrap();

    let parsed = extract_asic_s_container(&env.artifacts[0].signature).unwrap();
    let tampered = create_asic_s_container(
        &parsed.content_name,
        b"tampered ASiC-S payload",
        &parsed.cades_signature_der,
    )
    .unwrap();
    let mut artifact = env.artifacts[0].clone();
    artifact.signature = tampered;

    let err = validate_signature(&artifact, None).unwrap_err();
    assert!(matches!(err, SigningError::Cades(_)), "got {err:?}");
}

#[test]
fn asic_e_cades_manifest_round_trip_rsa() {
    let provider = rsa_provider(SigningFamily::CartaoDeCidadao);
    let payloads = [
        AsicPayload {
            name: "minutes.txt",
            bytes: b"approved minutes payload for ASiC-E",
            mime_type: Some("text/plain"),
        },
        AsicPayload {
            name: "attachments/votes.csv",
            bytes: b"member,vote\nA,yes\nB,yes\n",
            mime_type: Some("text/csv"),
        },
    ];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::ASiC,
            BaselineProfile::B_B,
        )],
    );

    sign_slot(
        &mut env,
        0,
        SigningJob {
            provider: &provider,
            policy: None,
            tsa: None,
            input: DocumentInput::AsicPayloads(&payloads),
            signing_time: fixed_time(),
            pdf_options: SignOptions::default(),
        },
    )
    .expect("sign ASiC-E");

    let artifact = &env.artifacts[0];
    assert_eq!(artifact.format, SignatureFormat::ASiC);
    assert_eq!(artifact.profile, BaselineProfile::B_B);
    assert!(
        artifact.signature.starts_with(b"PK"),
        "ASiC-E artifact is a ZIP container"
    );

    let parsed = extract_asic_e_container(&artifact.signature).expect("parse ASiC-E");
    assert_eq!(parsed.signature_path, ASICE_CADES_SIGNATURE_PATH);
    assert!(String::from_utf8_lossy(&parsed.manifest).contains("ASiCManifest"));
    assert_eq!(parsed.data_objects.len(), 2);
    assert_eq!(parsed.data_objects[0].name, "minutes.txt");
    assert_eq!(parsed.data_objects[0].bytes, payloads[0].bytes);
    assert_eq!(
        parsed.data_objects[0].sha256_digest,
        sha256_content_digest(payloads[0].bytes)
    );
    assert_eq!(parsed.data_objects[1].name, "attachments/votes.csv");

    let report = validate_signature(artifact, None).expect("validate ASiC-E/CAdES");
    assert!(report.cryptographically_valid);
    assert_eq!(report.evidentiary_level, EvidentiaryLevel::Qualified);
    assert_eq!(
        report.signer_cert_der,
        provider.signing_certificate_der().unwrap()
    );
    assert!(!report.has_signature_timestamp);
    assert_eq!(report.covers_whole_file, None);

    let err =
        validate_signature(artifact, Some(&sha256_content_digest(payloads[0].bytes))).unwrap_err();
    assert!(
        matches!(err, SigningError::Asic(ref msg) if msg.contains("multiple payloads")),
        "got {err:?}"
    );
}

#[test]
fn asic_e_payload_tamper_fails_manifest_validation() {
    let provider = rsa_provider(SigningFamily::CartaoDeCidadao);
    let payloads = [
        AsicPayload {
            name: "minutes.txt",
            bytes: b"original ASiC-E minutes",
            mime_type: Some("text/plain"),
        },
        AsicPayload {
            name: "attachment.bin",
            bytes: b"attached evidence",
            mime_type: Some("application/octet-stream"),
        },
    ];
    let mut env = SignatureEnvelope::new(
        SigningOrder::Parallel,
        vec![request(
            SigningFamily::CartaoDeCidadao,
            SignatureFormat::ASiC,
            BaselineProfile::B_B,
        )],
    );
    sign_slot(
        &mut env,
        0,
        SigningJob {
            provider: &provider,
            policy: None,
            tsa: None,
            input: DocumentInput::AsicPayloads(&payloads),
            signing_time: fixed_time(),
            pdf_options: SignOptions::default(),
        },
    )
    .unwrap();

    let parsed = extract_asic_e_container(&env.artifacts[0].signature).unwrap();
    let tampered = zip_container(&[
        ("mimetype", ASICE_MIMETYPE.as_bytes()),
        ("minutes.txt", b"tampered ASiC-E minutes" as &[u8]),
        ("attachment.bin", payloads[1].bytes),
        (ASICE_MANIFEST_PATH, parsed.manifest.as_slice()),
        (
            ASICE_CADES_SIGNATURE_PATH,
            parsed.cades_signature_der.as_slice(),
        ),
    ]);
    let mut artifact = env.artifacts[0].clone();
    artifact.signature = tampered;

    let err = validate_signature(&artifact, None).unwrap_err();
    assert!(
        matches!(err, SigningError::Asic(ref msg) if msg.contains("digest mismatch")),
        "got {err:?}"
    );
}

#[test]
fn asic_unsupported_container_shapes_report_precise_gaps() {
    let asice = zip_container(&[
        ("mimetype", ASICE_MIMETYPE.as_bytes()),
        ("payload.txt", b"payload" as &[u8]),
        (ASICE_CADES_SIGNATURE_PATH, b"cms" as &[u8]),
    ]);
    let err = validate_signature(&asic_artifact(asice), None).unwrap_err();
    assert!(matches!(err, SigningError::Asic(msg) if msg.contains("ASiCManifest")));

    let xades = zip_container(&[
        ("mimetype", ASICS_MIMETYPE.as_bytes()),
        ("payload.txt", b"payload" as &[u8]),
        ("META-INF/signatures.xml", b"<Signature/>" as &[u8]),
    ]);
    let err = validate_signature(&asic_artifact(xades), None).unwrap_err();
    assert!(matches!(err, SigningError::Asic(msg) if msg.contains("XAdES")));

    let multi_payload = zip_container(&[
        ("mimetype", ASICS_MIMETYPE.as_bytes()),
        ("one.txt", b"one" as &[u8]),
        ("two.txt", b"two" as &[u8]),
        ("META-INF/signatures.p7s", b"cms" as &[u8]),
    ]);
    let err = validate_signature(&asic_artifact(multi_payload), None).unwrap_err();
    assert!(matches!(err, SigningError::Asic(msg) if msg.contains("multi-payload")));

    let lowercase_meta_inf = zip_container(&[
        ("mimetype", ASICS_MIMETYPE.as_bytes()),
        ("payload.txt", b"payload" as &[u8]),
        ("meta-inf/extra.bin", b"reserved" as &[u8]),
        ("META-INF/signatures.p7s", b"cms" as &[u8]),
    ]);
    let err = validate_signature(&asic_artifact(lowercase_meta_inf), None).unwrap_err();
    assert!(matches!(err, SigningError::Asic(msg) if msg.contains("META-INF")));

    let err = create_asic_s_container("meta-inf/payload.txt", b"payload", b"cms").unwrap_err();
    assert!(matches!(err, SigningError::Asic(msg) if msg.contains("META-INF")));

    let duplicate_payload = [
        AsicPayload {
            name: "payload.txt",
            bytes: b"one",
            mime_type: Some("text/plain"),
        },
        AsicPayload {
            name: "PAYLOAD.txt",
            bytes: b"two",
            mime_type: Some("text/plain"),
        },
    ];
    let err = create_asic_e_container(&duplicate_payload, b"cms").unwrap_err();
    assert!(matches!(err, SigningError::Asic(msg) if msg.contains("duplicate")));
}

// --- Full envelope with the trusted-list policy gate ---------------------------------------------

#[test]
fn serial_envelope_two_signatories_with_granted_policy() {
    let chair = rsa_provider(SigningFamily::CartaoDeCidadao);
    let secretary = ecdsa_provider(SigningFamily::CartaoDeCidadao);
    let mut policy_a = StaticTrustPolicy::granted();
    let mut policy_b = StaticTrustPolicy::granted();

    let mut env = SignatureEnvelope::new(
        SigningOrder::Serial,
        vec![
            request(
                SigningFamily::CartaoDeCidadao,
                SignatureFormat::CAdES,
                BaselineProfile::B_B,
            ),
            request(
                SigningFamily::CartaoDeCidadao,
                SignatureFormat::CAdES,
                BaselineProfile::B_B,
            ),
        ],
    );

    sign_slot(
        &mut env,
        0,
        SigningJob {
            provider: &chair,
            policy: Some(&mut policy_a),
            tsa: None,
            input: DocumentInput::Digest(&CONTENT_DIGEST),
            signing_time: fixed_time(),
            pdf_options: SignOptions::default(),
        },
    )
    .unwrap();
    sign_slot(
        &mut env,
        1,
        SigningJob {
            provider: &secretary,
            policy: Some(&mut policy_b),
            tsa: None,
            input: DocumentInput::Digest(&CONTENT_DIGEST),
            signing_time: fixed_time(),
            pdf_options: SignOptions::default(),
        },
    )
    .unwrap();

    assert!(chancela_signing::is_complete(&env));
    for slot in 0..2 {
        let artifact = env.artifact_for(slot).unwrap();
        assert_eq!(
            artifact.trusted_list_status,
            Some(TrustedListStatus::Granted)
        );
        let report = validate_signature(artifact, Some(&CONTENT_DIGEST)).expect("validate");
        assert!(report.cryptographically_valid);
        assert_eq!(report.trusted_list_status, Some(TrustedListStatus::Granted));
    }
}
