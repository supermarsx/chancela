use std::env;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration as StdDuration;

use der::Encode;
use der::asn1::{BitString, ObjectIdentifier, UtcTime};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

use chancela_cades::{
    RawSignature, SignatureAlgorithm, assemble_cades_b, signed_attributes_digest,
};
use chancela_pades::{
    DssEvidence, SignOptions, add_doc_timestamp_revision, add_dss_revision,
    add_signature_timestamp, sign_pdf, validate_pdf_signature,
};

const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OCSP_DER_FIXTURE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];
const CRL_DER_FIXTURE: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04];
const DOC_TIMESTAMP_TOKEN_DER_FIXTURE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x07];
const FIXED_P256_SCALAR: [u8; 32] = [
    0x18, 0xd1, 0x2b, 0x43, 0x6d, 0x74, 0xa9, 0x55, 0x31, 0xec, 0x02, 0xc8, 0xa4, 0x0f, 0x5d, 0x66,
    0x10, 0x17, 0x5f, 0x73, 0x86, 0x0d, 0xa3, 0x89, 0x1c, 0x26, 0x45, 0x3f, 0xf0, 0x9b, 0x2e, 0x71,
];

struct CorpusSigner {
    key: SigningKey,
    cert_der: Vec<u8>,
}

impl CorpusSigner {
    fn new(cn: &str, serial: u8) -> Self {
        let key = SigningKey::from_slice(&FIXED_P256_SCALAR).expect("fixed p256 key");
        let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_ECDSA_WITH_SHA256,
            parameters: None,
        };
        let cert_der = build_self_signed(cn, serial, spki, sig_alg, &key);
        Self { key, cert_der }
    }

    fn cert_der(&self) -> Vec<u8> {
        self.cert_der.clone()
    }

    fn raw_signature(&self, digest: &[u8; 32]) -> RawSignature {
        RawSignature::new(
            SignatureAlgorithm::EcdsaP256Sha256,
            sign_p256_prehash(&self.key, digest),
            self.cert_der(),
            vec![],
        )
    }
}

#[test]
fn validator_corpus_fixtures_are_generated_or_current() {
    let Some(root) = corpus_root() else {
        return;
    };

    let fixtures = build_fixtures();
    for (case_id, bytes) in fixtures {
        let path = root
            .join("cases")
            .join(case_id)
            .join("input")
            .join(format!("{case_id}.pdf"));
        fs::create_dir_all(path.parent().expect("input dir")).expect("create input dir");
        fs::write(&path, bytes).expect("write fixture PDF");
        println!("wrote {}", path.display());
    }
}

fn corpus_root() -> Option<PathBuf> {
    env::var_os("CHANCELA_WRITE_VALIDATOR_CORPUS").map(PathBuf::from)
}

fn build_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let signer = CorpusSigner::new("Chancela Validator Corpus", 1);
    let bb = sign_with(&base_pdf(), &signer);
    validate_pdf_signature(&bb).expect("B-B validates");

    let bt = add_fixture_timestamp(&bb);
    let bt_report = validate_pdf_signature(&bt).expect("B-T validates");
    assert!(bt_report.has_signature_timestamp);

    let evidence = DssEvidence {
        certificates: vec![signer.cert_der()],
        ocsp_responses: vec![OCSP_DER_FIXTURE.to_vec()],
        crls: vec![CRL_DER_FIXTURE.to_vec()],
    };
    let bt_dss = add_dss_revision(&bt, &evidence).expect("DSS append");
    let dss_report = validate_pdf_signature(&bt_dss).expect("B-T+DSS validates");
    assert!(dss_report.has_signature_timestamp);
    assert!(dss_report.dss.present);

    let mut tampered_covered = bb.clone();
    tampered_covered[11] ^= 0xff;
    assert!(validate_pdf_signature(&tampered_covered).is_err());

    let mut tampered_dss = bt_dss.clone();
    let dss_offset = find_after(&tampered_dss, OCSP_DER_FIXTURE, bt.len()).expect("OCSP in DSS");
    tampered_dss[dss_offset + OCSP_DER_FIXTURE.len() - 1] ^= 0xff;

    let doc_ts = add_doc_timestamp_revision(&bt_dss, DOC_TIMESTAMP_TOKEN_DER_FIXTURE)
        .expect("DocTimeStamp append");
    let doc_ts_report = validate_pdf_signature(&doc_ts).expect("DocTimeStamp validates");
    assert!(doc_ts_report.doc_timestamps.present);

    vec![
        ("bb-basic", bb),
        ("bt-timestamped", bt),
        ("bt-dss-local", bt_dss),
        ("tampered-covered-byte", tampered_covered),
        ("tampered-dss-only", tampered_dss),
        ("future-doctimestamp", doc_ts),
    ]
}

fn fixed_time() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

fn sign_with(pdf: &[u8], signer: &CorpusSigner) -> Vec<u8> {
    let signing_time = fixed_time();
    let cert = signer.cert_der();
    sign_pdf(pdf, &SignOptions::default(), |digest| {
        let attrs = signed_attributes_digest(digest, &cert, signing_time)?;
        let raw = signer.raw_signature(&attrs);
        assemble_cades_b(&raw, digest, signing_time)
    })
    .expect("sign_pdf")
}

fn add_fixture_timestamp(signed: &[u8]) -> Vec<u8> {
    let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
    let req = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
        .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
        .without_certificate();
    add_signature_timestamp(signed, |_sig_digest| tsa.stamp(&req)).expect("B-T")
}

fn build_self_signed(
    cn: &str,
    serial: u8,
    spki: SubjectPublicKeyInfoOwned,
    sig_alg: AlgorithmIdentifierOwned,
    key: &SigningKey,
) -> Vec<u8> {
    let name = Name::from_str(&format!("CN={cn}")).expect("name");
    let validity = Validity {
        not_before: x509_time(1_700_000_000),
        not_after: x509_time(1_900_000_000),
    };
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
    let signature = sign_p256_prehash(key, &Sha256::digest(&tbs_der).into());
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&signature).expect("bitstring"),
    };
    cert.to_der().expect("cert der")
}

fn sign_p256_prehash(key: &SigningKey, digest: &[u8; 32]) -> Vec<u8> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    let sig: p256::ecdsa::Signature = key.sign_prehash(digest).expect("p256 prehash sign");
    sig.to_der().as_bytes().to_vec()
}

fn x509_time(unix_timestamp: u64) -> Time {
    Time::UtcTime(
        UtcTime::from_unix_duration(StdDuration::from_secs(unix_timestamp)).expect("utc time"),
    )
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

fn find_after(haystack: &[u8], needle: &[u8], offset: usize) -> Option<usize> {
    haystack
        .get(offset..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|pos| pos + offset)
}
