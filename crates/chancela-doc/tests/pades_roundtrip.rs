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

// --- The reach proof (t12-e1): the file we actually ship is structurally validated ---------------
//
// `pdfa::write` self-checks the bytes it is about to return, so it can only ever see the
// *pre-signature* document. `chancela-pades` then appends an incremental update, and until these
// tests existed nothing re-validated the result — the file Chancela ships was structurally
// unvalidated. `selfcheck::verify_signed` closes that, and the mutants below prove it is a real
// gate rather than a rubber stamp.
//
// Every mutant is **equal-length**: a length-changing edit shifts every xref offset after it, so
// the file fails with a generic "object missing" that attributes nothing.

use chancela_doc::selfcheck::{self, UaClaim};

/// Overwrite the first occurrence of `from` with `to`, which must be the same length.
fn replace_once(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len(), "replacement must preserve offsets");
    let at = find(bytes, from)
        .unwrap_or_else(|| panic!("missing pattern: {}", String::from_utf8_lossy(from)));
    bytes[at..at + from.len()].copy_from_slice(to);
}

/// Change one hex digit in place, wrapping `F` to `0` — an equal-length mutation, so no
/// cross-reference offset moves and the failure that follows is the rule's, not the file's.
fn bump_hex_digit(bytes: &mut [u8], at: usize) {
    bytes[at] = match bytes[at] {
        b'f' | b'F' => b'0',
        b'9' => b'A',
        digit => digit + 1,
    };
}

/// The same, for a decimal digit (a `/W` width stays an integer of the same width).
fn bump_decimal_digit(bytes: &mut [u8], at: usize) {
    bytes[at] = if bytes[at] == b'9' {
        b'1'
    } else {
        bytes[at] + 1
    };
}

/// A signed document to mutate.
fn signed_fixture(serial: u8) -> (Vec<u8>, Vec<u8>) {
    let base = pdfa::write(&ata_fixture()).expect("write base");
    let signer = TestSigner::new_rsa("Amélia Marques Selo (teste)", serial);
    let signed = sign_with(&base, &signer, &SignOptions::default());
    (base, signed)
}

/// THE reach assertion: the signed bytes — not merely the unsigned base — satisfy the structural
/// PDF/A-2u invariants, including the ones only a signed file can violate (a `/Prev`-chained xref
/// chain, `/ID` in the *file* trailer, the `/AcroForm`, and the widget's flags and appearance).
#[test]
fn signed_output_satisfies_the_structural_invariants() {
    let (base, signed) = signed_fixture(10);
    selfcheck::verify(&base).expect("the unsigned base verifies");
    selfcheck::verify_signed(&signed).expect("the SIGNED file verifies");
    // And the on-disk entry point reaches the same verdict without being told which it is.
    selfcheck::verify_any(&base).expect("auto-detected base");
    selfcheck::verify_any(&signed).expect("auto-detected signed");
}

/// The two profiles are not interchangeable — which is what makes checking under the right one
/// meaningful. An unsigned file must not pass the signed profile (it has no signature at all), and
/// a signed file must not pass the unsigned one (it has an `/AcroForm` the writer never emits).
#[test]
fn the_signed_and_unsigned_profiles_are_not_interchangeable() {
    let (base, signed) = signed_fixture(11);
    let err = selfcheck::verify_signed(&base).expect_err("an unsigned file is not a signed one");
    assert!(
        err.to_string().contains("no incremental signature update"),
        "unexpected error: {err}"
    );
    let err = selfcheck::verify(&signed).expect_err("a signed file is not an unsigned one");
    assert!(
        err.to_string().contains("expected exactly 1"),
        "unexpected error: {err}"
    );
}

/// ISO 19005-2 6.1.3 requires the **file** trailer — the newest one — to carry `/ID`. `lopdf`
/// merges the revision chain and drops `/ID` when the newest trailer omits it, so this can only be
/// checked against the raw trailer bytes. It is exactly the rule the signer used to break.
#[test]
fn the_signed_file_trailer_must_carry_the_document_identifier() {
    let (_, mut signed) = signed_fixture(12);
    // Rename the key in the *last* trailer only; every offset stays put.
    let last_trailer = signed
        .windows(7)
        .rposition(|w| w == b"trailer")
        .expect("trailer");
    replace_once(&mut signed[last_trailer..], b"/ID [", b"/Iz [");

    let err = selfcheck::verify_signed(&signed).expect_err("a trailer without /ID must fail");
    assert!(err.to_string().contains("6.1.3"), "unexpected error: {err}");
}

/// PDF/A-2 6.3.1: an annotation must set Print and must not set Hidden, Invisible or NoView. The
/// signer emits `/F 132` (Print + Locked); `/F 130` is Hidden + Locked with Print cleared.
#[test]
fn the_signature_widget_annotation_flags_are_enforced() {
    let (_, mut signed) = signed_fixture(13);
    replace_once(&mut signed, b"/F 132", b"/F 130");

    let err = selfcheck::verify_signed(&signed).expect_err("bad annotation flags must fail");
    assert!(
        err.to_string().contains("Print flag"),
        "unexpected error: {err}"
    );
}

/// The only annotation subtype this pipeline may produce is a signature widget. Anything else means
/// something other than our signer wrote to the file.
#[test]
fn a_non_widget_annotation_is_rejected() {
    let (_, mut signed) = signed_fixture(14);
    replace_once(&mut signed, b"/Subtype /Widget", b"/Subtype /Wodget");

    let err = selfcheck::verify_signed(&signed).expect_err("a foreign annotation must fail");
    assert!(
        err.to_string().contains("/Wodget"),
        "unexpected error: {err}"
    );
}

/// Sign `base` with a visible text seal carrying `name`.
fn sign_with_text_seal(base: &[u8], name: &str, serial: u8) -> Vec<u8> {
    use chancela_pades::{
        SealAppearance, SealContent, SealPlacement, TextSeal, sign_pdf_with_appearance,
    };

    let signer = TestSigner::new_rsa("Amélia Marques Visível (teste)", serial);
    let cert = signer.cert_der();
    let appearance = SealAppearance {
        placement: SealPlacement {
            page: 0,
            x: 60.0,
            y: 60.0,
            w: 200.0,
            h: 60.0,
        },
        content: SealContent::Text(TextSeal::signed_by(
            "Assinado por",
            name,
            "2026-07-06 12:00 UTC",
        )),
    };
    sign_pdf_with_appearance(base, &SignOptions::default(), Some(&appearance), |digest| {
        let attrs = signed_attributes_digest(digest, &cert, fixed_time())?;
        assemble_cades_b(&signer.raw_signature(&attrs), digest, fixed_time())
    })
    .expect("visible-seal signing")
}

/// A visible text seal used to draw with standard-14 Helvetica, which has no font program to embed,
/// so every visibly-sealed file was silently non-conformant. The seal now draws with the *document's
/// own* embedded face, and the whole signed file — appearance stream included — satisfies the
/// structural profile. The seal's Portuguese accents are the point: they are what an unembedded
/// WinAnsi face mangled, and the `/ToUnicode` round-trip through the font's own `cmap` is what
/// proves they survive.
#[test]
fn a_visible_text_seal_embeds_its_font_and_the_signed_file_verifies() {
    let base = pdfa::write(&ata_fixture()).expect("write base");
    let signed = sign_with_text_seal(&base, "Amélia Marques Gonçalves", 15);

    selfcheck::verify_signed(&signed).expect("a visibly-sealed signed file is conformant");
    assert!(
        find(&signed, b"Helvetica").is_none(),
        "the seal must not fall back to a standard-14 face"
    );
}

/// The pin for the defect itself: reintroduce a non-embedded seal font and the check must still
/// say so. Without this, "the seal verifies" could mean the seal font rule stopped firing.
#[test]
fn a_seal_font_without_an_embedded_program_is_still_caught() {
    let base = pdfa::write(&ata_fixture()).expect("write base");
    let mut signed = sign_with_text_seal(&base, "Amélia Marques Gonçalves", 17);
    // Break the *seal's* descendant font link to the document's /FontDescriptor — the last such key
    // in the file, in the appended revision — leaving a seal font with no embedded program. Equal
    // length, so every xref offset stays put.
    let at = signed
        .windows(15)
        .rposition(|w| w == b"/FontDescriptor")
        .expect("the seal CIDFont /FontDescriptor");
    replace_once(&mut signed[at..], b"/FontDescriptor", b"/FontDescriptoz");

    let err = selfcheck::verify_signed(&signed)
        .expect_err("a seal drawn with a non-embedded face is not PDF/A conformant");
    assert!(
        err.to_string().contains("no embedded font program"),
        "unexpected error: {err}"
    );
}

/// The seal's `/ToUnicode` is checked against the embedded font's own `cmap`, not merely for
/// existence: repointing one entry's target makes the seal extract as a character the font maps to a
/// different glyph, and the check must say so. Presence checks cannot see this.
#[test]
fn a_seal_tounicode_that_disagrees_with_the_font_is_caught() {
    let base = pdfa::write(&ata_fixture()).expect("write base");
    let mut signed = sign_with_text_seal(&base, "Amélia Marques Gonçalves", 19);
    // The last bfchar section is the seal's; bump the last digit of its first target scalar.
    let section = signed
        .windows(12)
        .rposition(|w| w == b"beginbfchar\n")
        .expect("the seal /ToUnicode")
        + 12;
    let target = find(&signed[section..], b"> <").expect("a bfchar entry") + section + 3;
    bump_hex_digit(&mut signed, target + 3);

    let err = selfcheck::verify_signed(&signed).expect_err("a wrong seal /ToUnicode must fail");
    assert!(
        err.to_string().contains("/ToUnicode maps glyph"),
        "unexpected error: {err}"
    );
}

/// The seal's `/W` widths are checked against the embedded `hmtx`. A width that no longer matches
/// would lay the seal text out wrong in any viewer that trusts the PDF over the font.
#[test]
fn a_seal_width_that_disagrees_with_the_embedded_font_is_caught() {
    let base = pdfa::write(&ata_fixture()).expect("write base");
    let mut signed = sign_with_text_seal(&base, "Amélia Marques Gonçalves", 21);
    // The seal CIDFont's `/W [gid [width] …]` is the last one in the file.
    let widths = signed
        .windows(4)
        .rposition(|w| w == b"/W [")
        .expect("the seal /W array")
        + 4;
    let first_width = find(&signed[widths..], b"[").expect("a width array") + widths + 1;
    bump_decimal_digit(&mut signed, first_width);

    let err = selfcheck::verify_signed(&signed).expect_err("a wrong seal /W width must fail");
    assert!(
        err.to_string().contains("the embedded hmtx gives"),
        "unexpected error: {err}"
    );
}

/// The signature widget is not in the structure tree, which ISO 14289-1 7.18.1 requires of a visible
/// annotation — so a signed file may not go on claiming PDF/UA-1. The signer now **supersedes** the
/// XMP in the signature revision to drop the claim (the base bytes the `/ByteRange` covers are
/// untouched), so a signed file claims nothing rather than claiming something false.
///
/// Both halves matter. `NotClaimed` alone would also be reached by a writer that stopped claiming
/// PDF/UA at all, so the unsigned base is asserted to still claim it *and hold it*; and the
/// falsified state is re-created below to show the detector that found this has not gone quiet.
#[test]
fn signing_drops_the_pdf_ua_claim_rather_than_falsifying_it() {
    let (base, signed) = signed_fixture(16);
    assert_eq!(
        selfcheck::ua_claim(&base).expect("base UA claim"),
        UaClaim::Claimed,
        "the unsigned document's PDF/UA-1 claim holds"
    );
    assert_eq!(
        selfcheck::ua_claim(&signed).expect("signed UA claim"),
        UaClaim::NotClaimed,
        "a signed file must make no PDF/UA-1 claim, having an untagged signature widget"
    );
}

/// The falsification detector must still fire. Restoring the claim into the superseded XMP — one
/// equal-length edit, in the *appended* revision, so no offset moves — puts the file back in the
/// state finding 2 described, and `ua_claim` must say `Falsified` again.
#[test]
fn a_signed_file_that_kept_its_ua_claim_is_still_reported_falsified() {
    let (_, mut signed) = signed_fixture(18);
    // The *last* copy of the packet is the superseded one the signature revision appended; putting
    // the identifier back into it, over an equal-length run, restores the false claim without
    // moving a single offset.
    let at = signed
        .windows(30)
        .rposition(|w| w == b"<dc:format>application/pdf</dc")
        .expect("the superseded XMP");
    replace_once(
        &mut signed[at..],
        b"<dc:format>application/pdf</dc",
        b"<pdfuaid:part>1</pdfuaid:part>",
    );

    match selfcheck::ua_claim(&signed).expect("signed UA claim") {
        UaClaim::Falsified(reason) => {
            assert!(reason.contains("7.18.1"), "unexpected reason: {reason}")
        }
        other => panic!("expected the restored UA claim to be falsified, got {other:?}"),
    }
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
