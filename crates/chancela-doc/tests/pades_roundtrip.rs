//! t48-e3 — the **Wave-D-unblock proof**: a `chancela-doc` PDF/A-2u document, produced from a
//! representative `DocumentModel`, is accepted by the real `chancela-pades` incremental signer and
//! the resulting PAdES-B-B signature **validates** cryptographically via `chancela-cades`.
//!
//! This is the cross-crate byte-shape contract asserted end-to-end (plan §4-e3): generate → sign →
//! validate. It closes the loop `chancela-doc::pdfa::write` ⇒ `chancela-pades::sign_pdf` ⇒
//! `chancela-pades::validate_pdf_signature` for the first time, proving the writer's output is the
//! exact shape the signer appends to.
//!
//! Signing keys/certs are generated **ephemerally in-test** (no private keys checked in), mirroring
//! `chancela-pades/src/tests.rs` — the pades test signer is `#[cfg(test)]`-private, so the minimal
//! self-signed-cert + RawSignature scaffolding is reproduced here against the *public* cades API.
//!
//! Fixtures use the fictional "Encosto Estratégico Lda" / "Amélia Marques" — never a real entity.

use std::str::FromStr;
use std::time::Duration as StdDuration;

use chancela_core::{Block, DocumentModel, KvRow, Run, SignatureSlot, VoteRow};
use chancela_doc::pdfa;

use chancela_cades::{
    RawSignature, SignatureAlgorithm, assemble_cades_b, signed_attributes_digest,
};
use chancela_pades::{SignOptions, sign_pdf, validate_pdf_signature};

use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use sha2::{Digest, Sha256};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::Validity;

// --- The representative document (a real-shaped CSC general-meeting ata) --------------------------

/// A multi-block ata exercising every `DocumentModel` block kind (headings at two levels, a
/// multi-run paragraph with bold/italic, a key/value table, a vote table, a rule, a signature
/// block) with pt-PT diacritics — the kind of document Wave D will sign in production.
fn ata_fixture() -> DocumentModel {
    let mut doc = DocumentModel::new(
        "Ata da Assembleia Geral",
        "Encosto Estratégico Lda",
        "Deliberação sobre contas e distribuição de resultados",
    );
    doc.entity_nipc = Some("500123456".to_string());
    doc.created_at = Some("2026-07-06T10:30:00Z".to_string());
    doc.blocks = vec![
        Block::Heading {
            level: 1,
            text: "Ata número três".to_string(),
        },
        Block::Paragraph {
            runs: vec![
                Run {
                    text: "Aos seis dias do mês de julho de dois mil e vinte e seis, reuniu a \
                           assembleia geral da sociedade, com a presença de "
                        .to_string(),
                    bold: false,
                    italic: false,
                },
                Run {
                    text: "todos os sócios".to_string(),
                    bold: true,
                    italic: false,
                },
                Run {
                    text: ", para deliberação dos pontos da ordem de trabalhos. A reunião \
                           decorreu na sede social, sita na Rua das Oliveiras, em Lisboa."
                        .to_string(),
                    bold: false,
                    italic: true,
                },
            ],
        },
        Block::KeyValue {
            rows: vec![
                KvRow {
                    key: "Presidente da mesa".to_string(),
                    value: "Amélia Marques".to_string(),
                },
                KvRow {
                    key: "Secretário".to_string(),
                    value: "João Nogueira".to_string(),
                },
                KvRow {
                    key: "Data".to_string(),
                    value: "6 de julho de 2026".to_string(),
                },
            ],
        },
        Block::Heading {
            level: 2,
            text: "Deliberações e votação".to_string(),
        },
        Block::VoteTable {
            rows: vec![
                VoteRow {
                    label: "Aprovação das contas do exercício".to_string(),
                    favor: 3,
                    against: 0,
                    abstain: 1,
                },
                VoteRow {
                    label: "Distribuição de resultados".to_string(),
                    favor: 4,
                    against: 0,
                    abstain: 0,
                },
            ],
        },
        Block::Rule,
        Block::SignatureBlock {
            slots: vec![
                SignatureSlot {
                    role: "Presidente da mesa".to_string(),
                    name: "Amélia Marques".to_string(),
                },
                SignatureSlot {
                    role: "Secretário".to_string(),
                    name: "João Nogueira".to_string(),
                },
            ],
        },
    ];
    doc
}

// --- In-test signer (mirrors chancela-pades/src/tests.rs; drives the public cades API) -----------

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// 2025-06-15T14:26:40Z — whole seconds, inside the CAdES UTCTime window.
fn fixed_time() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

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
        let spki =
            SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        };
        let signer = key.clone();
        let cert_der = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            sign_rsa_digest_info(&signer, &sha256(tbs))
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
        let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("ec spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_ECDSA_WITH_SHA256,
            parameters: None,
        };
        let signer = key.clone();
        let cert_der = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            let sig: p256::ecdsa::Signature = signer.sign(tbs);
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

/// Sign `pdf` with `signer`, wiring the CAdES-B assembly into the pades signing callback — exactly
/// how `chancela-signing` will drive it in production.
fn sign_with(pdf: &[u8], signer: &TestSigner, opts: &SignOptions) -> Vec<u8> {
    let signing_time = fixed_time();
    let cert = signer.cert_der();
    sign_pdf(pdf, opts, |digest| {
        let attrs = signed_attributes_digest(digest, &cert, signing_time)?;
        let raw = signer.raw_signature(&attrs);
        assemble_cades_b(&raw, digest, signing_time)
    })
    .expect("sign_pdf must accept the chancela-doc PDF")
}

/// First occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// --- The proof -----------------------------------------------------------------------------------

/// THE core Wave-D-unblock proof: generate a PDF/A-2u ata → PAdES-sign it (RSA) → validate the
/// signature cryptographically. Also asserts the incremental-update discipline (original bytes are
/// a strict prefix) and that the signer injected `/ByteRange` + `/Contents` (the base had neither).
#[test]
fn generate_sign_validate_roundtrip_rsa() {
    // 1. Generate the base document from the model.
    let base = pdfa::write(&ata_fixture()).expect("chancela-doc writes the PDF/A base");
    assert!(base.starts_with(b"%PDF-1.7"), "PDF/A-2u header");

    // Pre-sign invariant: the base carries NEITHER placeholder, so the signer's first-match scans
    // latch onto its OWN appended update (e2's guarantee, re-checked at the seam here).
    assert!(
        find(&base, b"/Contents <").is_none(),
        "base doc must not contain `/Contents <`"
    );
    assert!(
        find(&base, b"/ByteRange").is_none(),
        "base doc must not contain `/ByteRange`"
    );
    // Pre-sign shape: classic xref, no AcroForm (the pades preconditions, by construction).
    assert!(find(&base, b"\nxref\n").is_some(), "classic xref table");
    assert!(find(&base, b"/AcroForm").is_none(), "no AcroForm pre-sign");

    // 2. Sign it with the real pades incremental signer (this is the acceptance assertion — the
    //    `.expect` inside `sign_with` fails the test if the writer's output is not signable).
    let opts = SignOptions {
        field_name: Some("Assinatura".into()),
        signing_time: Some("D:20260706142640Z".into()),
        reason: Some("Ata aprovada em assembleia".into()),
        location: Some("Lisboa".into()),
        contact_info: None,
    };
    let signer = TestSigner::new_rsa("Amélia Marques (teste)", 1);
    let signed = sign_with(&base, &signer, &opts);

    // 3. Incremental-update discipline: the signer APPENDED, it did not rewrite — the original
    //    document bytes are an untouched strict prefix of the signed output.
    assert!(
        signed.len() > base.len(),
        "signing must grow the file (incremental section appended)"
    );
    assert_eq!(
        &signed[..base.len()],
        &base[..],
        "original bytes must be a byte-identical prefix (incremental update, not a rewrite)"
    );

    // 4. The signer injected the signature machinery the base lacked.
    assert!(
        find(&signed, b"/ByteRange").is_some(),
        "signer injected /ByteRange"
    );
    assert!(
        find(&signed, b"/Contents <").is_some(),
        "signer injected the /Contents placeholder"
    );
    // The cosmetic /Sig options round-tripped into the appended dictionary.
    assert!(find(&signed, b"(Assinatura)").is_some());
    assert!(find(&signed, b"(Ata aprovada em assembleia)").is_some());

    // 5. The signed output is still a loadable PDF.
    let reparsed =
        lopdf::Document::load_mem(&signed).expect("signed output still parses via lopdf");
    assert!(reparsed.trailer.has(b"Root"));

    // 6. THE VALIDATION: recompute the ByteRange digest and cryptographically verify the CAdES-B
    //    signature. This is what makes the round-trip a *proof* and not just "it didn't error".
    let report = validate_pdf_signature(&signed).expect("signature must validate");
    assert!(
        report.covers_whole_file_except_contents,
        "ByteRange must cover the whole file except the /Contents value"
    );
    assert_eq!(
        report.total_len,
        signed.len(),
        "validation ran over the whole signed file"
    );
    assert_eq!(
        report.cades.signer_cert_der,
        signer.cert_der(),
        "the validated signer certificate is the one we signed with"
    );
    assert!(
        report.cades.signing_certificate_v2_present,
        "CAdES-B signing-certificate-v2 attribute present"
    );
    assert_eq!(
        report.cades.signing_time.map(|t| t.unix_timestamp()),
        Some(1_750_000_000),
        "authoritative signing time is carried in the signed attributes"
    );
    assert!(
        !report.has_signature_timestamp,
        "B-B (no signature timestamp) — B-T is a separate, tested path"
    );
}

/// The same round-trip on the ECDSA P-256 profile (Cartão de Cidadão v2), proving the byte-shape is
/// profile-agnostic.
#[test]
fn generate_sign_validate_roundtrip_ecdsa() {
    let base = pdfa::write(&ata_fixture()).expect("write base");
    let signer = TestSigner::new_ecdsa("Amélia Marques P256 (teste)", 2);
    let signed = sign_with(&base, &signer, &SignOptions::default());

    assert_eq!(
        &signed[..base.len()],
        &base[..],
        "strict-prefix incremental"
    );
    let report = validate_pdf_signature(&signed).expect("ECDSA signature validates");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signer.cert_der());
}

/// Negative control: the validation is *real*, not vacuous. Flipping a byte inside the signed
/// (ByteRange-covered) region must make validation fail — so a passing validation above genuinely
/// attests document integrity.
#[test]
fn tampering_the_signed_document_breaks_validation() {
    let base = pdfa::write(&ata_fixture()).expect("write base");
    let signer = TestSigner::new_rsa("Amélia Marques Tamper (teste)", 3);
    let mut signed = sign_with(&base, &signer, &SignOptions::default());

    // Flip a byte in the PDF binary header comment (offset 11) — inside range1 of the ByteRange,
    // still leaves the file lopdf-parseable, so the failure is a digest mismatch, not a parse error.
    signed[11] ^= 0xff;
    assert!(
        validate_pdf_signature(&signed).is_err(),
        "a tampered signed document must not validate"
    );
}

/// Determinism-adjacent sanity at the seam (e2 owns the exhaustive determinism test): the same
/// model yields byte-identical pre-sign bytes, so the signable input — and thus the whole pipeline
/// — is reproducible.
#[test]
fn presign_bytes_are_deterministic() {
    let a = pdfa::write(&ata_fixture()).expect("write a");
    let b = pdfa::write(&ata_fixture()).expect("write b");
    assert_eq!(a, b, "same DocumentModel ⇒ identical pre-sign bytes");
}
