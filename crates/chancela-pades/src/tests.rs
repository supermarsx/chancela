//! Offline, deterministic round-trip tests for PAdES-B-B / B-T signing and validation.
//!
//! Signing keys and certificates are generated ephemerally in-test (no private keys are checked
//! in, per `.orchestration/plans/t4.md` §6), mirroring `chancela-cades/src/tests.rs`. Both CAdES
//! profiles are exercised: RSA-PKCS1-SHA256 and ECDSA-P256-SHA256. B-T uses the bundled
//! `chancela-tsa` OpenSSL fixture via `MockTsaTransport::from_fixture()`.

use std::str::FromStr;
use std::time::Duration as StdDuration;

use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use sha2::{Digest, Sha256};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::Validity;

use chancela_cades::{
    RawSignature, SignatureAlgorithm, assemble_cades_b, signed_attributes_digest,
};

use crate::error::PadesError;
use crate::renewal::{LtvRenewalDeadlineStatus, LtvRenewalPolicy, plan_ltv_renewal_with_policy};
use crate::sign::MAX_CONTENTS_BYTES;
use crate::validate::PdfSignatureCoverage;
use crate::{
    DocTimeStampFailureReason, DocTimeStampReport, DocTimeStampSemanticStatus, DssEvidence,
    DssReport, ImageSeal, LtvRenewalPlanAction, LtvRenewalPlanInput, LtvRenewalPlanScope,
    SealAppearance, SealContent, SealImageFormat, SealPlacement, SignOptions, TextSeal,
    add_doc_timestamp_revision, add_dss_revision, add_dss_revision_with_validation_time,
    add_signature_timestamp, inspect_doc_timestamps, inspect_dss,
    prepare_signature_with_appearance, sign_pdf, sign_pdf_with_appearance, validate_pdf_signature,
};

// --- OIDs used only for the in-test self-signed certificates -------------------------------------

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Public, synthetic DER fixture used as caller-supplied OCSP bytes in DSS tests. The PAdES layer
/// preserves DER blobs but does not semantically validate revocation protocol payloads.
const OCSP_DER_FIXTURE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];

/// Public, synthetic DER fixture used as caller-supplied CRL bytes in DSS tests.
const CRL_DER_FIXTURE: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04];

/// Public, synthetic complete DER fixture used as caller-supplied `/DocTimeStamp` token bytes.
const DOC_TIMESTAMP_TOKEN_DER_FIXTURE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x07];

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn fixed_time() -> time::OffsetDateTime {
    // 2025-06-15T14:26:40Z — whole seconds, inside the UTCTime window.
    time::OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

// --- In-test signer (mirrors chancela-cades/src/tests.rs) ----------------------------------------

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

// --- Minimal base PDF (classic cross-reference table) --------------------------------------------

/// Assemble a minimal classic-xref PDF from `(id, dict-body)` object bodies (ids 1..=max, contiguous).
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

/// Sign `pdf` with `signer`, wiring the CAdES assembly into the signing callback.
fn sign_with(pdf: &[u8], signer: &TestSigner, opts: &SignOptions) -> Vec<u8> {
    let signing_time = fixed_time();
    let cert = signer.cert_der();
    sign_pdf(pdf, opts, |digest| {
        let attrs = signed_attributes_digest(digest, &cert, signing_time)?;
        let raw = signer.raw_signature(&attrs);
        assemble_cades_b(&raw, digest, signing_time)
    })
    .expect("sign_pdf")
}

/// Sign `pdf` with `signer` placing a visible seal `appearance`.
fn sign_with_appearance(
    pdf: &[u8],
    signer: &TestSigner,
    opts: &SignOptions,
    appearance: &SealAppearance,
) -> Vec<u8> {
    let signing_time = fixed_time();
    let cert = signer.cert_der();
    sign_pdf_with_appearance(pdf, opts, Some(appearance), |digest| {
        let attrs = signed_attributes_digest(digest, &cert, signing_time)?;
        let raw = signer.raw_signature(&attrs);
        assemble_cades_b(&raw, digest, signing_time)
    })
    .expect("sign_pdf_with_appearance")
}

/// A two-page classic-xref PDF (page objects 3 and 4; page index 1 = object 4).
fn base_pdf_two_pages() -> Vec<u8> {
    assemble_pdf(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
            (
                4,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
        ],
        1,
    )
}

// --- A base PDF that embeds a font, as a sealed document must ------------------------------------

/// Characters the synthetic test face covers: printable ASCII plus the Portuguese accented letters
/// a seal is most likely to carry. `Ω` is deliberately *absent*, so a test can show that a
/// character the face lacks is refused rather than drawn as a blank box.
fn test_face_chars() -> Vec<char> {
    let mut chars: Vec<char> = (0x20u8..=0x7Eu8).map(char::from).collect();
    chars.extend("áàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ".chars());
    chars.sort_unstable();
    chars.dedup();
    chars
}

/// Build a minimal but structurally real TrueType programme covering [`test_face_chars`].
///
/// Every glyph is empty (zero-length `glyf` entry) and 600/1000 em wide. That is enough for the
/// tables a seal reads — `cmap` for glyph ids, `hmtx` for `/W` widths, `head` for the design grid —
/// and it keeps the fixture small. Glyph ids are assigned in code-point order starting at 1, so
/// glyph 0 stays `.notdef`.
fn synthetic_truetype() -> Vec<u8> {
    let chars = test_face_chars();
    let num_glyphs = chars.len() as u16 + 1;

    let mut head = vec![0u8; 54];
    head[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes()); // version
    head[18..20].copy_from_slice(&1000u16.to_be_bytes()); // unitsPerEm
    head[50..52].copy_from_slice(&0u16.to_be_bytes()); // indexToLocFormat = short

    let mut hhea = vec![0u8; 36];
    hhea[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    hhea[34..36].copy_from_slice(&num_glyphs.to_be_bytes()); // numberOfHMetrics

    let mut maxp = vec![0u8; 32];
    maxp[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    maxp[4..6].copy_from_slice(&num_glyphs.to_be_bytes());

    // hmtx: one (advanceWidth, leftSideBearing) pair per glyph.
    let mut hmtx = Vec::new();
    for _ in 0..num_glyphs {
        hmtx.extend_from_slice(&600u16.to_be_bytes());
        hmtx.extend_from_slice(&0i16.to_be_bytes());
    }

    // loca (short): numGlyphs + 1 zeros, i.e. every glyph has an empty outline.
    let loca = vec![0u8; (num_glyphs as usize + 1) * 2];
    let glyf: Vec<u8> = Vec::new();

    // cmap format 4: one single-character segment per covered char (idRangeOffset 0, so the glyph
    // is `code + idDelta`), then the mandatory 0xFFFF terminator.
    let mut segments: Vec<(u16, u16, i16)> = chars
        .iter()
        .enumerate()
        .map(|(index, &ch)| {
            let code = ch as u16;
            let gid = index as u16 + 1;
            (code, code, (gid as i32 - code as i32) as i16)
        })
        .collect();
    segments.push((0xFFFF, 0xFFFF, 1));
    let seg_count = segments.len() as u16;
    let mut subtable = Vec::new();
    subtable.extend_from_slice(&4u16.to_be_bytes()); // format
    subtable.extend_from_slice(&0u16.to_be_bytes()); // length, patched below
    subtable.extend_from_slice(&0u16.to_be_bytes()); // language
    subtable.extend_from_slice(&(seg_count * 2).to_be_bytes());
    subtable.extend_from_slice(&0u16.to_be_bytes()); // searchRange (unused by our readers)
    subtable.extend_from_slice(&0u16.to_be_bytes()); // entrySelector
    subtable.extend_from_slice(&0u16.to_be_bytes()); // rangeShift
    for &(_, end, _) in &segments {
        subtable.extend_from_slice(&end.to_be_bytes());
    }
    subtable.extend_from_slice(&0u16.to_be_bytes()); // reservedPad
    for &(start, _, _) in &segments {
        subtable.extend_from_slice(&start.to_be_bytes());
    }
    for &(_, _, delta) in &segments {
        subtable.extend_from_slice(&delta.to_be_bytes());
    }
    for _ in &segments {
        subtable.extend_from_slice(&0u16.to_be_bytes()); // idRangeOffset
    }
    let length = subtable.len() as u16;
    subtable[2..4].copy_from_slice(&length.to_be_bytes());

    let mut cmap = Vec::new();
    cmap.extend_from_slice(&0u16.to_be_bytes()); // version
    cmap.extend_from_slice(&1u16.to_be_bytes()); // numTables
    cmap.extend_from_slice(&3u16.to_be_bytes()); // platformID = Windows
    cmap.extend_from_slice(&1u16.to_be_bytes()); // encodingID = BMP
    cmap.extend_from_slice(&12u32.to_be_bytes()); // subtable offset
    cmap.extend_from_slice(&subtable);

    // Assemble the sfnt: header, table directory, then the tables (each 4-byte aligned).
    let tables: Vec<(&[u8; 4], Vec<u8>)> = vec![
        (b"cmap", cmap),
        (b"glyf", glyf),
        (b"head", head),
        (b"hhea", hhea),
        (b"hmtx", hmtx),
        (b"loca", loca),
        (b"maxp", maxp),
    ];
    let num_tables = tables.len() as u16;
    let mut out = Vec::new();
    out.extend_from_slice(&0x0001_0000u32.to_be_bytes());
    out.extend_from_slice(&num_tables.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // searchRange
    out.extend_from_slice(&0u16.to_be_bytes()); // entrySelector
    out.extend_from_slice(&0u16.to_be_bytes()); // rangeShift
    let directory = out.len();
    out.resize(directory + tables.len() * 16, 0);
    for (index, (tag, data)) in tables.iter().enumerate() {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        let offset = out.len() as u32;
        let entry = directory + index * 16;
        out[entry..entry + 4].copy_from_slice(*tag);
        out[entry + 8..entry + 12].copy_from_slice(&offset.to_be_bytes());
        out[entry + 12..entry + 16].copy_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// Assemble a classic-xref PDF from byte-valued object bodies (ids 1..=max, contiguous).
fn assemble_pdf_bytes(objects: &[(u32, Vec<u8>)], root: u32) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::new();
    for (id, body) in objects {
        offsets.push((*id, buf.len()));
        buf.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
        buf.extend_from_slice(body);
        buf.extend_from_slice(b"\nendobj\n");
    }
    let xref_off = buf.len();
    let max_id = objects.iter().map(|(id, _)| *id).max().unwrap();
    buf.extend_from_slice(format!("xref\n0 {}\n", max_id + 1).as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f\r\n");
    for id in 1..=max_id {
        let off = offsets.iter().find(|(i, _)| *i == id).map(|(_, o)| *o);
        buf.extend_from_slice(format!("{:010} 00000 n\r\n", off.unwrap()).as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {} /Root {root} 0 R >>\n", max_id + 1).as_bytes(),
    );
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

/// A one-page PDF whose page declares a `Type0` / `Identity-H` font with an embedded `/FontFile2` —
/// the shape a real Chancela document has, and the shape a visible text seal now requires.
///
/// `metadata` is an optional XMP packet attached to the catalog as `/Metadata` (object 9).
fn base_pdf_with_font(metadata: Option<&str>) -> Vec<u8> {
    let program = synthetic_truetype();
    let mut font_stream = format!(
        "<< /Length {} /Length1 {} >>\nstream\n",
        program.len(),
        program.len()
    )
    .into_bytes();
    font_stream.extend_from_slice(&program);
    font_stream.extend_from_slice(b"\nendstream");

    let catalog = match metadata {
        Some(_) => "<< /Type /Catalog /Pages 2 0 R /Metadata 8 0 R >>",
        None => "<< /Type /Catalog /Pages 2 0 R >>",
    };
    let mut objects: Vec<(u32, Vec<u8>)> = vec![
        (1, catalog.as_bytes().to_vec()),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec()),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /Font << /F1 4 0 R >> >> >>"
                .to_vec(),
        ),
        (
            4,
            b"<< /Type /Font /Subtype /Type0 /BaseFont /TestFace /Encoding /Identity-H \
              /DescendantFonts [5 0 R] >>"
                .to_vec(),
        ),
        (
            5,
            b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /TestFace \
              /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> \
              /FontDescriptor 6 0 R /CIDToGIDMap /Identity /DW 500 >>"
                .to_vec(),
        ),
        (
            6,
            b"<< /Type /FontDescriptor /FontName /TestFace /Flags 34 /FontBBox [0 -200 600 800] \
              /ItalicAngle 0 /Ascent 800 /Descent -200 /CapHeight 700 /StemV 80 \
              /FontFile2 7 0 R >>"
                .to_vec(),
        ),
        (7, font_stream),
    ];
    if let Some(packet) = metadata {
        objects.push((
            8,
            format!(
                "<< /Type /Metadata /Subtype /XML /Length {} >>\nstream\n{packet}\nendstream",
                packet.len()
            )
            .into_bytes(),
        ));
    }
    assemble_pdf_bytes(&objects, 1)
}

/// Encode a 2×2 RGBA PNG (one fully transparent pixel, one semi-transparent) so the decode path
/// exercises the alpha → `/SMask` split.
fn tiny_rgba_png() -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, 2, 2);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().expect("png header");
        let data: [u8; 16] = [
            255, 0, 0, 255, // opaque red
            0, 255, 0, 128, // semi-transparent green
            0, 0, 255, 255, // opaque blue
            0, 0, 0, 0, // fully transparent
        ];
        writer.write_image_data(&data).expect("png data");
    }
    out
}

/// The signature widget annotation (the merged `/FT /Sig` + `/Subtype /Widget` field) of a signed
/// PDF, cloned out of the parsed document.
fn signature_widget(pdf: &[u8]) -> lopdf::Dictionary {
    let doc = lopdf::Document::load_mem(pdf).expect("parse signed PDF");
    doc.objects
        .values()
        .find_map(|obj| {
            let dict = obj.as_dict().ok()?;
            let is_widget = matches!(dict.get(b"Subtype").ok()?.as_name().ok(), Some(b"Widget"));
            let is_sig = matches!(
                dict.get(b"FT").ok().and_then(|o| o.as_name().ok()),
                Some(b"Sig")
            );
            (is_widget && is_sig).then(|| dict.clone())
        })
        .expect("signature widget present")
}

/// The four `/Rect` numbers of the signature widget.
fn widget_rect(widget: &lopdf::Dictionary) -> [f32; 4] {
    let arr = widget
        .get(b"Rect")
        .and_then(|o| o.as_array())
        .expect("Rect");
    assert_eq!(arr.len(), 4, "Rect has four numbers");
    // Whole-number coordinates serialize without a decimal point, so lopdf reparses them as
    // Integer; `as_float` accepts both Integer and Real.
    [
        arr[0].as_float().unwrap(),
        arr[1].as_float().unwrap(),
        arr[2].as_float().unwrap(),
        arr[3].as_float().unwrap(),
    ]
}

/// Assert the widget's `/AP /N` references a `/Subtype /Form` XObject in `pdf`, returning the
/// referenced object id.
fn assert_ap_is_form_xobject(pdf: &[u8], widget: &lopdf::Dictionary) -> (u32, u16) {
    let ap = widget
        .get(b"AP")
        .and_then(|o| o.as_dict())
        .expect("/AP dictionary present");
    let n_ref = ap
        .get(b"N")
        .and_then(|o| o.as_reference())
        .expect("/AP /N reference");
    let doc = lopdf::Document::load_mem(pdf).expect("parse signed PDF");
    let form = doc
        .get_object(n_ref)
        .and_then(|o| o.as_stream())
        .expect("/AP /N is a stream");
    assert_eq!(
        form.dict.get(b"Subtype").and_then(|o| o.as_name()).ok(),
        Some(b"Form".as_ref()),
        "appearance stream is a form XObject"
    );
    n_ref
}

fn add_fixture_timestamp(signed: &[u8]) -> Vec<u8> {
    // Drive B-T from the bundled chancela-tsa OpenSSL fixture. The fixture covers a fixed digest;
    // the embedding logic under test is independent of which digest the token attests, so the
    // callback ignores the CMS-signature digest and stamps the fixture digest+nonce.
    let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
    let req = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
        .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
        .without_certificate();
    add_signature_timestamp(signed, |_sig_digest| tsa.stamp(&req)).expect("B-T")
}

fn fixture_timestamp_token() -> Vec<u8> {
    let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
    let req = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
        .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
        .without_certificate();
    tsa.stamp(&req).expect("fixture token").token_der
}

fn token_with_replaced_fixture_imprint(imprint: &[u8; 32]) -> Vec<u8> {
    let mut token = fixture_timestamp_token();
    let pos = token
        .windows(chancela_tsa::mock::FIXTURE_DIGEST.len())
        .position(|w| w == chancela_tsa::mock::FIXTURE_DIGEST)
        .expect("fixture imprint present");
    token[pos..pos + imprint.len()].copy_from_slice(imprint);
    token
}

fn doc_timestamp_token_for_revision(pdf: &[u8]) -> Vec<u8> {
    let placeholder =
        add_doc_timestamp_revision(pdf, &fixture_timestamp_token()).expect("placeholder DTS");
    let report = inspect_doc_timestamps(&placeholder).expect("inspect placeholder DTS");
    let digest = report.validations[0]
        .document_digest
        .expect("DocTimeStamp ByteRange digest");
    token_with_replaced_fixture_imprint(&digest)
}

fn fixture_dss_evidence(signer: &TestSigner) -> DssEvidence {
    let issuer = TestSigner::new_rsa("PAdES DSS Issuer", 42);
    DssEvidence {
        certificates: vec![signer.cert_der(), issuer.cert_der()],
        ocsp_responses: vec![OCSP_DER_FIXTURE.to_vec()],
        crls: vec![CRL_DER_FIXTURE.to_vec()],
    }
}

// --- Tests ---------------------------------------------------------------------------------------

#[test]
fn base_pdf_is_parseable() {
    let pdf = base_pdf();
    let doc = lopdf::Document::load_mem(&pdf).expect("base parses");
    assert_eq!(doc.max_id, 3);
}

#[test]
fn rsa_sign_validates() {
    let signer = TestSigner::new_rsa("PAdES RSA", 1);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    let report = validate_pdf_signature(&signed).expect("validate");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signer.cert_der());
    assert!(report.cades.signing_certificate_v2_present);
    assert!(!report.has_signature_timestamp);
    assert!(!report.doc_timestamps.present);
    assert_eq!(
        report.ltv_renewal_plan.scope,
        LtvRenewalPlanScope::LocalTechnicalEvidenceOnly
    );
    assert_eq!(
        report.ltv_renewal_plan.missing_inputs,
        vec![
            LtvRenewalPlanInput::SignatureTimestamp,
            LtvRenewalPlanInput::DssRevocationEvidence,
            LtvRenewalPlanInput::DssValidationTime,
            LtvRenewalPlanInput::DocumentTimestamp,
        ]
    );
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::AddSignatureTimestamp
    );
    assert!(report.ltv_renewal_plan.has_local_evidence_gap());
    assert_eq!(
        report.cades.signing_time.map(|t| t.unix_timestamp()),
        Some(1_750_000_000)
    );
}

#[test]
fn ecdsa_sign_validates() {
    let signer = TestSigner::new_ecdsa("PAdES P256", 2);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    let report = validate_pdf_signature(&signed).expect("validate");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signer.cert_der());
}

#[test]
fn byte_range_excludes_exactly_the_contents_placeholder() {
    let signer = TestSigner::new_rsa("PAdES Range", 3);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    // The excluded gap is exactly the `<` + hex placeholder + `>`.
    let report = validate_pdf_signature(&signed).unwrap();
    let excluded = report.total_len - report.covered_len;
    assert_eq!(excluded, MAX_CONTENTS_BYTES * 2 + 2, "gap = <..> inclusive");

    // ByteRange starts at 0 and its second range ends exactly at EOF.
    let [s1, l1, s2, l2] = report.byte_range;
    assert_eq!(s1, 0);
    assert_eq!((s2 + l2) as usize, report.total_len);
    // The gap boundary lines up with the '<' / '>' of /Contents.
    let lt = crate_find(&signed, b"/Contents <").unwrap() + b"/Contents ".len();
    assert_eq!(l1 as usize, lt, "range1 ends at the '<'");
    assert_eq!(
        s2 as usize,
        lt + 1 + MAX_CONTENTS_BYTES * 2 + 1,
        "range2 starts after '>'"
    );
}

#[test]
fn coverage_verdicts_distinguish_rendered_document_binding() {
    let signer = TestSigner::new_rsa("PAdES Coverage", 24);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    let report = validate_pdf_signature(&signed).expect("validate whole-document signature");
    assert_eq!(report.coverage, PdfSignatureCoverage::WholeDocument);
    assert!(report.coverage.covers_rendered_document());

    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let with_dss = add_dss_revision(&with_ts, &evidence).expect("DSS append");
    let report = validate_pdf_signature(&with_dss).expect("validate LTV-augmented signature");
    assert_eq!(
        report.coverage,
        PdfSignatureCoverage::LtvAugmentedSignedRevision
    );
    assert!(report.coverage.covers_rendered_document());

    let content_override = append_object_override(
        &signed,
        3,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Resources << >> >>",
    );
    let report = validate_pdf_signature(&content_override).expect("validate altered PDF");
    assert_eq!(report.coverage, PdfSignatureCoverage::AlteredAfterSigning);
    assert!(!report.coverage.covers_rendered_document());
    assert!(report.covers_signed_revision_except_contents);
    assert!(report.has_later_incremental_updates);

    let overwide_gap = sign_with_overwide_gap(&signer);
    let report = validate_pdf_signature(&overwide_gap).expect("validate overwide ByteRange gap");
    assert_eq!(report.coverage, PdfSignatureCoverage::Malformed);
    assert!(!report.coverage.covers_rendered_document());
    assert!(!report.covers_signed_revision_except_contents);
}

#[test]
fn tampered_byte_in_range_fails_validation() {
    let signer = TestSigner::new_rsa("PAdES Tamper", 4);
    let mut signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    // Flip a byte in the binary comment (offset 11) — inside ByteRange range1, keeps the PDF
    // parseable, so the failure is a digest mismatch (not a parse error).
    signed[11] ^= 0xff;
    let err = validate_pdf_signature(&signed).unwrap_err();
    assert!(
        matches!(
            err,
            PadesError::Cades(chancela_cades::CadesError::MessageDigestMismatch)
        ),
        "got {err:?}"
    );
}

#[test]
fn tampered_byte_after_gap_fails_validation() {
    let signer = TestSigner::new_ecdsa("PAdES Tamper2", 5);
    let mut signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    // Flip a byte in the trailing incremental section (the last '%%EOF' region is in range2).
    let idx = signed.len() - 3;
    signed[idx] ^= 0xff;
    assert!(validate_pdf_signature(&signed).is_err());
}

#[test]
fn sign_options_are_emitted() {
    let signer = TestSigner::new_rsa("PAdES Opts", 6);
    let opts = SignOptions {
        field_name: Some("Assinatura".into()),
        signing_time: Some("D:20260706142640Z".into()),
        reason: Some("Ata aprovada".into()),
        location: Some("Lisboa".into()),
        contact_info: None,
    };
    let signed = sign_with(&base_pdf(), &signer, &opts);
    // Still valid, and the field name / reason are present in the bytes.
    validate_pdf_signature(&signed).expect("validate");
    assert!(crate_find(&signed, b"(Assinatura)").is_some());
    assert!(crate_find(&signed, b"(Ata aprovada)").is_some());
    assert!(crate_find(&signed, b"D:20260706142640Z").is_some());
}

#[test]
fn b_t_signature_timestamp_embeds_and_validates() {
    let signer = TestSigner::new_rsa("PAdES BT", 7);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    let with_ts = add_fixture_timestamp(&signed);

    let report = validate_pdf_signature(&with_ts).expect("validate B-T");
    assert!(
        report.has_signature_timestamp,
        "signature timestamp present"
    );
    assert_eq!(
        report.ltv_renewal_plan.missing_inputs,
        vec![
            LtvRenewalPlanInput::DssRevocationEvidence,
            LtvRenewalPlanInput::DssValidationTime,
            LtvRenewalPlanInput::DocumentTimestamp,
        ]
    );
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::EmbedDssRevocationEvidence
    );
    // Adding the unsigned attribute must not disturb the ByteRange / B-B signature.
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signer.cert_der());
}

#[test]
fn dss_revision_appends_to_b_t_and_reports_counts_hashes() {
    let signer = TestSigner::new_rsa("PAdES DSS", 8);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);

    let with_dss = add_dss_revision(&with_ts, &evidence).expect("DSS append");
    let repeated = add_dss_revision(&with_ts, &evidence).expect("deterministic DSS append");

    assert_ne!(with_dss, with_ts);
    assert!(with_dss.starts_with(&with_ts));
    assert_eq!(with_dss, repeated);

    let report = validate_pdf_signature(&with_dss).expect("validate B-T + DSS");
    assert!(report.has_signature_timestamp);
    assert!(report.covers_signed_revision_except_contents);
    assert!(!report.covers_whole_file_except_contents);
    assert!(report.has_later_incremental_updates);
    assert_eq!(report.signed_revision_len, with_ts.len());
    assert_eq!(report.total_len, with_dss.len());
    assert!(report.dss.present);
    assert_eq!(report.dss.vri_count, 1);
    assert_eq!(report.dss.vri_keys.len(), 1);
    assert_eq!(report.dss.vri_keys[0].len(), 64);
    assert_eq!(report.dss.vri_tu_count, 0);
    assert!(report.dss.vri_tu_keys.is_empty());
    assert!(!report.dss.has_vri_tu());
    assert_eq!(report.dss.certificate_count(), 2);
    assert_eq!(report.dss.ocsp_count(), 1);
    assert_eq!(report.dss.crl_count(), 1);
    assert_eq!(report.dss.ocsp_hashes, vec![sha256(OCSP_DER_FIXTURE)]);
    assert_eq!(report.dss.crl_hashes, vec![sha256(CRL_DER_FIXTURE)]);
    assert_eq!(
        report.ltv_renewal_plan.missing_inputs,
        vec![
            LtvRenewalPlanInput::DssValidationTime,
            LtvRenewalPlanInput::DocumentTimestamp,
        ]
    );
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::RecordDssValidationTime
    );

    let direct_dss = inspect_dss(&with_dss).expect("inspect DSS");
    assert_eq!(direct_dss, report.dss);
}

#[test]
fn doc_timestamp_revision_appends_and_reports_without_lta_claim() {
    let signer = TestSigner::new_rsa("PAdES DocTimeStamp", 13);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let with_dss = add_dss_revision(&with_ts, &evidence).expect("DSS append");

    let with_doc_ts =
        add_doc_timestamp_revision(&with_dss, DOC_TIMESTAMP_TOKEN_DER_FIXTURE).expect("DTS append");
    let repeated =
        add_doc_timestamp_revision(&with_dss, DOC_TIMESTAMP_TOKEN_DER_FIXTURE).expect("repeat DTS");

    assert_ne!(with_doc_ts, with_dss);
    assert!(with_doc_ts.starts_with(&with_dss));
    assert_eq!(with_doc_ts, repeated);
    assert!(crate_find(&with_doc_ts, b"/Type /DocTimeStamp").is_some());
    assert!(crate_find(&with_doc_ts, b"/SubFilter /ETSI.RFC3161").is_some());

    let report = validate_pdf_signature(&with_doc_ts).expect("validate DTS revision");
    assert!(report.has_signature_timestamp);
    assert!(report.dss.present);
    assert!(report.covers_signed_revision_except_contents);
    assert!(!report.covers_whole_file_except_contents);
    assert!(report.has_later_incremental_updates);
    assert_eq!(report.total_len, with_doc_ts.len());
    assert_eq!(report.signed_revision_len, with_ts.len());
    assert!(report.doc_timestamps.present);
    assert_eq!(report.doc_timestamps.count, 1);
    assert_eq!(report.doc_timestamps.token_count(), 1);
    assert_eq!(
        report.doc_timestamps.token_hashes,
        vec![sha256(DOC_TIMESTAMP_TOKEN_DER_FIXTURE)]
    );
    assert_eq!(
        report.doc_timestamps.validations[0].status,
        DocTimeStampSemanticStatus::Failed
    );
    assert_eq!(
        report.doc_timestamps.validations[0].failure_reason,
        Some(DocTimeStampFailureReason::MalformedToken)
    );
    assert!(!report.doc_timestamps.all_imprints_valid());
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::ReviewDocumentTimestamp
    );
    assert!(
        report
            .ltv_renewal_plan
            .missing_inputs
            .contains(&LtvRenewalPlanInput::DocumentTimestampImprintBinding)
    );

    let direct = inspect_doc_timestamps(&with_doc_ts).expect("inspect DTS");
    assert_eq!(direct, report.doc_timestamps);
}

#[test]
fn doc_timestamp_reports_valid_rfc3161_imprint_binding() {
    let signer = TestSigner::new_rsa("PAdES DocTimeStamp Valid", 15);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let token = doc_timestamp_token_for_revision(&signed);

    let with_doc_ts = add_doc_timestamp_revision(&signed, &token).expect("DTS append");
    let report = validate_pdf_signature(&with_doc_ts).expect("validate DTS PDF");

    assert!(report.doc_timestamps.present);
    assert_eq!(report.doc_timestamps.count, 1);
    assert!(report.doc_timestamps.all_imprints_valid());
    let validation = &report.doc_timestamps.validations[0];
    assert_eq!(validation.status, DocTimeStampSemanticStatus::Valid);
    assert_eq!(validation.failure_reason, None);
    assert_eq!(
        validation.token_imprint.as_deref(),
        Some(validation.document_digest.as_ref().unwrap().as_slice())
    );
    assert_eq!(
        validation.token_hash_algorithm.as_deref(),
        Some("2.16.840.1.101.3.4.2.1")
    );
}

#[test]
fn doc_timestamp_reports_tampered_rfc3161_imprint_binding() {
    let signer = TestSigner::new_rsa("PAdES DocTimeStamp Tampered", 16);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let stale_token = fixture_timestamp_token();

    let with_doc_ts = add_doc_timestamp_revision(&signed, &stale_token).expect("DTS append");
    let report = validate_pdf_signature(&with_doc_ts).expect("validate DTS PDF");

    let validation = &report.doc_timestamps.validations[0];
    assert_eq!(validation.status, DocTimeStampSemanticStatus::Failed);
    assert_eq!(
        validation.failure_reason,
        Some(DocTimeStampFailureReason::ImprintMismatch)
    );
    assert_ne!(
        validation.token_imprint.as_deref(),
        Some(validation.document_digest.as_ref().unwrap().as_slice())
    );
    assert!(!report.doc_timestamps.all_imprints_valid());
}

#[test]
fn invalid_doc_timestamp_token_is_rejected() {
    let signer = TestSigner::new_rsa("PAdES Bad DocTimeStamp", 14);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    let err = add_doc_timestamp_revision(&signed, b"not der").unwrap_err();
    assert!(
        matches!(err, PadesError::InvalidDocTimeStampToken),
        "got {err:?}"
    );
}

#[test]
fn dss_revision_keeps_signed_revision_tamper_detection() {
    let signer = TestSigner::new_rsa("PAdES DSS Tamper", 9);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let mut with_dss = add_dss_revision(&with_ts, &evidence).expect("DSS append");

    // Flip a byte in the signed revision. The later DSS revision remains parseable, but the
    // ByteRange digest no longer matches the embedded CMS.
    with_dss[11] ^= 0xff;
    let err = validate_pdf_signature(&with_dss).unwrap_err();
    assert!(
        matches!(
            err,
            PadesError::Cades(chancela_cades::CadesError::MessageDigestMismatch)
        ),
        "got {err:?}"
    );
}

#[test]
fn empty_dss_evidence_is_rejected() {
    let signer = TestSigner::new_rsa("PAdES Empty DSS", 10);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    let err = add_dss_revision(&signed, &DssEvidence::default()).unwrap_err();
    assert!(matches!(err, PadesError::DssEvidenceEmpty), "got {err:?}");
}

#[test]
fn existing_dss_is_merged_and_deduped() {
    let signer = TestSigner::new_rsa("PAdES Existing DSS", 11);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let mut evidence = fixture_dss_evidence(&signer);
    evidence.certificates.push(evidence.certificates[0].clone());
    evidence.ocsp_responses.push(OCSP_DER_FIXTURE.to_vec());
    evidence.crls.push(CRL_DER_FIXTURE.to_vec());
    let with_dss = add_dss_revision(&signed, &evidence).expect("first DSS append");
    let first_cert_refs = dss_array_refs(&with_dss, b"Certs");
    let first_ocsp_refs = dss_array_refs(&with_dss, b"OCSPs");
    let first_crl_refs = dss_array_refs(&with_dss, b"CRLs");

    let merged = add_dss_revision(&with_dss, &evidence).expect("merged DSS append");
    let report = inspect_dss(&merged).expect("inspect merged DSS");

    assert!(merged.starts_with(&with_dss));
    assert_eq!(report.vri_count, 1);
    assert_eq!(report.certificate_count(), 2);
    assert_eq!(report.ocsp_count(), 1);
    assert_eq!(report.crl_count(), 1);
    assert_eq!(report.ocsp_hashes, vec![sha256(OCSP_DER_FIXTURE)]);
    assert_eq!(report.crl_hashes, vec![sha256(CRL_DER_FIXTURE)]);
    assert_eq!(dss_array_refs(&merged, b"Certs"), first_cert_refs);
    assert_eq!(dss_array_refs(&merged, b"OCSPs"), first_ocsp_refs);
    assert_eq!(dss_array_refs(&merged, b"CRLs"), first_crl_refs);
}

#[test]
fn dss_validation_time_is_written_as_vri_tu_and_reported() {
    let signer = TestSigner::new_rsa("PAdES DSS TU", 12);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);

    let with_dss = add_dss_revision_with_validation_time(&with_ts, &evidence, "D:20260709120000Z")
        .expect("DSS append with TU");
    let report = validate_pdf_signature(&with_dss).expect("validate DSS TU");

    assert!(report.has_signature_timestamp);
    assert!(report.dss.present);
    assert_eq!(report.dss.vri_count, 1);
    assert_eq!(report.dss.vri_tu_count, 1);
    assert_eq!(report.dss.vri_tu_keys, report.dss.vri_keys);
    assert!(report.dss.has_vri_tu());
    assert!(report.dss.has_vri_tu_for_key(&report.dss.vri_keys[0]));
    assert!(crate_find(&with_dss, b"/TU (D:20260709120000Z)").is_some());
    assert_eq!(
        report.ltv_renewal_plan.missing_inputs,
        vec![LtvRenewalPlanInput::DocumentTimestamp]
    );
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::AddDocumentTimestamp
    );
}

#[test]
fn ltv_renewal_plan_monitors_when_local_evidence_inputs_are_present() {
    let signer = TestSigner::new_rsa("PAdES Renewal Plan", 17);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let with_dss = add_dss_revision_with_validation_time(&with_ts, &evidence, "D:20260709120000Z")
        .expect("DSS append with TU");
    let token = doc_timestamp_token_for_revision(&with_dss);

    let with_doc_ts = add_doc_timestamp_revision(&with_dss, &token).expect("DTS append");
    let report = validate_pdf_signature(&with_doc_ts).expect("validate renewal plan PDF");

    assert!(report.has_signature_timestamp);
    assert!(report.dss.has_revocation_evidence());
    assert!(report.dss.has_vri_tu());
    assert!(report.doc_timestamps.all_imprints_valid());
    assert_eq!(
        report.ltv_renewal_plan.scope,
        LtvRenewalPlanScope::LocalTechnicalEvidenceOnly
    );
    assert!(report.ltv_renewal_plan.missing_inputs.is_empty());
    assert!(!report.ltv_renewal_plan.has_local_evidence_gap());
    assert!(report.ltv_renewal_plan.has_all_local_planning_inputs());
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::MonitorTimestampRenewal
    );
}

#[test]
fn ltv_renewal_policy_classifies_caller_supplied_deadlines_only() {
    let policy = LtvRenewalPolicy {
        now_unix_seconds: Some(1_750_000_000),
        renewal_deadline_unix_seconds: Some(1_750_000_300),
        due_soon_window_seconds: Some(600),
    };
    let plan = plan_ltv_renewal_with_policy(
        false,
        &DssReport::default(),
        &DocTimeStampReport::default(),
        policy,
    );

    assert_eq!(plan.policy, policy);
    assert_eq!(
        plan.renewal_deadline.status,
        LtvRenewalDeadlineStatus::DueSoon
    );
    assert_eq!(plan.renewal_deadline.seconds_until_deadline, Some(300));
    assert_eq!(
        plan.next_action,
        LtvRenewalPlanAction::AddSignatureTimestamp
    );

    let past_due = plan_ltv_renewal_with_policy(
        true,
        &DssReport::default(),
        &DocTimeStampReport::default(),
        LtvRenewalPolicy {
            now_unix_seconds: Some(1_750_000_000),
            renewal_deadline_unix_seconds: Some(1_749_999_999),
            due_soon_window_seconds: None,
        },
    );
    assert_eq!(
        past_due.renewal_deadline.status,
        LtvRenewalDeadlineStatus::PastDue
    );
    assert_eq!(past_due.renewal_deadline.seconds_until_deadline, Some(-1));
}

#[test]
fn multi_signature_renewal_plan_reports_each_signature_vri_coverage() {
    let signer = TestSigner::new_rsa("PAdES Multi Renewal", 18);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let with_dss = add_dss_revision_with_validation_time(&with_ts, &evidence, "D:20260709120000Z")
        .expect("DSS append with TU");
    let token = doc_timestamp_token_for_revision(&with_dss);
    let with_doc_ts = add_doc_timestamp_revision(&with_dss, &token).expect("DTS append");
    let with_second_sig =
        append_synthetic_sig_dictionary(&with_doc_ts, DOC_TIMESTAMP_TOKEN_DER_FIXTURE);

    let report = validate_pdf_signature(&with_second_sig).expect("validate first signature");

    assert_eq!(report.multi_signature_ltv_renewal_plan.signature_count, 2);
    assert_eq!(
        report
            .multi_signature_ltv_renewal_plan
            .signatures_with_local_evidence_gaps,
        vec![1]
    );
    assert!(
        report.multi_signature_ltv_renewal_plan.signatures[0].dss_vri_present,
        "real signature has a matching DSS VRI entry"
    );
    assert!(
        report.multi_signature_ltv_renewal_plan.signatures[0].dss_vri_validation_time_present,
        "real signature VRI has /TU"
    );
    assert!(
        !report.multi_signature_ltv_renewal_plan.signatures[1].dss_vri_present,
        "synthetic second signature has no matching DSS VRI entry"
    );
    assert!(
        report.multi_signature_ltv_renewal_plan.signatures[1]
            .plan
            .missing_inputs
            .contains(&LtvRenewalPlanInput::SignatureDssVri)
    );
    assert_eq!(
        report.multi_signature_ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::AddSignatureDssVri
    );
}

#[test]
fn multi_signature_renewal_plan_matches_tu_to_the_specific_vri_key() {
    let signer = TestSigner::new_rsa("PAdES Multi Renewal TU Key", 19);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let with_first_tu =
        add_dss_revision_with_validation_time(&with_ts, &evidence, "D:20260709120000Z")
            .expect("first DSS append with TU");
    let with_second_sig = append_synthetic_sig_dictionary_with_signed_revision_len(
        &with_first_tu,
        DOC_TIMESTAMP_TOKEN_DER_FIXTURE,
        with_first_tu.len() + 1,
    );

    let with_second_vri =
        add_dss_revision(&with_second_sig, &evidence).expect("second DSS append without TU");
    let report = validate_pdf_signature(&with_second_vri).expect("validate first signature");

    assert_eq!(report.dss.vri_count, 2);
    assert_eq!(report.dss.vri_tu_count, 1);
    assert_eq!(report.dss.vri_tu_keys.len(), 1);
    assert_eq!(report.multi_signature_ltv_renewal_plan.signature_count, 2);

    let first_signature = &report.multi_signature_ltv_renewal_plan.signatures[0];
    assert!(first_signature.dss_vri_present);
    assert!(first_signature.dss_vri_validation_time_present);
    assert!(report.dss.has_vri_tu_for_key(&first_signature.vri_key));

    let second_signature = &report.multi_signature_ltv_renewal_plan.signatures[1];
    assert!(second_signature.dss_vri_present);
    assert!(!second_signature.dss_vri_validation_time_present);
    assert!(!report.dss.has_vri_tu_for_key(&second_signature.vri_key));
    assert!(
        second_signature
            .plan
            .missing_inputs
            .contains(&LtvRenewalPlanInput::SignatureDssValidationTime)
    );
}

#[test]
fn validation_rejects_unsigned_pdf() {
    let err = validate_pdf_signature(&base_pdf()).unwrap_err();
    assert!(matches!(err, PadesError::NoSignature), "got {err:?}");
}

#[test]
fn signing_non_pdf_input_is_a_parse_error() {
    // Garbage bytes cannot be loaded as a PDF; signing must fail up front (before the callback).
    let err = sign_pdf(
        b"this is definitely not a PDF",
        &SignOptions::default(),
        |_| Ok::<_, std::io::Error>(Vec::new()),
    )
    .unwrap_err();
    assert!(matches!(err, PadesError::PdfParse(_)), "got {err:?}");
}

#[test]
fn a_failing_signing_callback_surfaces_as_signer_error() {
    // The ByteRange is computed successfully, then the caller's signing callback fails: the error
    // is carried through the boxed `Signer` variant rather than swallowed.
    let err = sign_pdf(&base_pdf(), &SignOptions::default(), |_digest| {
        Err(std::io::Error::other("card removed mid-sign"))
    })
    .unwrap_err();
    match err {
        PadesError::Signer(source) => {
            assert!(source.to_string().contains("card removed"));
        }
        other => panic!("expected Signer, got {other:?}"),
    }
}

#[test]
fn a_cms_larger_than_the_placeholder_is_rejected() {
    // A CMS exceeding the fixed 16 KiB `/Contents` placeholder cannot be embedded; the produced /
    // capacity sizes are reported so the caller can diagnose the overflow.
    let oversized = MAX_CONTENTS_BYTES + 1;
    let err = sign_pdf(&base_pdf(), &SignOptions::default(), move |_digest| {
        Ok::<_, std::io::Error>(vec![0u8; oversized])
    })
    .unwrap_err();
    match err {
        PadesError::ContentsPlaceholderTooSmall { produced, capacity } => {
            assert_eq!(produced, oversized);
            assert_eq!(capacity, MAX_CONTENTS_BYTES);
        }
        other => panic!("expected ContentsPlaceholderTooSmall, got {other:?}"),
    }
}

#[test]
fn a_pdf_with_an_existing_acroform_is_rejected() {
    // Phase-1 does not merge into a pre-existing form; a catalog already carrying an /AcroForm is a
    // `MalformedStructure` rejection, not a silent double-form.
    let pdf = assemble_pdf(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
            (4, "<< /Fields [] /SigFlags 3 >>"),
        ],
        1,
    );
    let err = sign_pdf(&pdf, &SignOptions::default(), |_| {
        Ok::<_, std::io::Error>(Vec::new())
    })
    .unwrap_err();
    match err {
        PadesError::MalformedStructure(msg) => assert!(msg.contains("AcroForm"), "got {msg}"),
        other => panic!("expected MalformedStructure, got {other:?}"),
    }
}

// --- Visible-seal (t67-e3) -----------------------------------------------------------------------

#[test]
fn visible_text_seal_places_rect_and_ap_and_still_validates() {
    let signer = TestSigner::new_rsa("PAdES Seal Text", 20);
    let placement = SealPlacement {
        page: 0,
        x: 72.0,
        y: 700.0,
        w: 180.0,
        h: 48.0,
    };
    let seal = SealAppearance {
        placement,
        // memory: fictional example name, never a real person.
        content: SealContent::Text(TextSeal::name_date("Amélia Marques", "2026-07-11")),
    };
    let signed = sign_with_appearance(
        &base_pdf_with_font(None),
        &signer,
        &SignOptions::default(),
        &seal,
    );

    // The B-B signature still validates and covers the whole file except /Contents.
    let report = validate_pdf_signature(&signed).expect("validate visible-seal PDF");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signer.cert_der());

    // Real /Rect = [x, y, x+w, y+h] and a form-XObject appearance stream.
    let widget = signature_widget(&signed);
    assert_eq!(widget_rect(&widget), [72.0, 700.0, 252.0, 748.0]);
    assert_ap_is_form_xobject(&signed, &widget);
    // Widget bound to the requested page (object 3 = first page).
    assert_eq!(
        widget.get(b"P").and_then(|o| o.as_reference()).unwrap(),
        (3, 0)
    );
    // The invisible zero-Rect placeholder is gone.
    assert!(crate_find(&signed, b"/Rect [0 0 0 0]").is_none());
}

/// The seal's own font objects, resolved from a signed file: `(Type0, descendant CIDFont)`.
fn seal_font_dicts(signed: &[u8]) -> (lopdf::Dictionary, lopdf::Dictionary) {
    let doc = lopdf::Document::load_mem(signed).expect("parse");
    let widget = signature_widget(signed);
    let form_ref = widget
        .get(b"AP")
        .and_then(|o| o.as_dict())
        .and_then(|ap| ap.get(b"N"))
        .and_then(|o| o.as_reference())
        .expect("/AP /N");
    let form = doc
        .get_object(form_ref)
        .and_then(|o| o.as_stream())
        .expect("form");
    let font_ref = form
        .dict
        .get(b"Resources")
        .and_then(|o| o.as_dict())
        .and_then(|r| r.get(b"Font"))
        .and_then(|o| o.as_dict())
        .and_then(|f| f.get(b"F1"))
        .and_then(|o| o.as_reference())
        .expect("seal /Font /F1");
    let type0 = doc
        .get_object(font_ref)
        .and_then(|o| o.as_dict())
        .expect("Type0")
        .clone();
    let cid_ref = type0
        .get(b"DescendantFonts")
        .and_then(|o| o.as_array())
        .and_then(|a| a[0].as_reference())
        .expect("descendant");
    let cid = doc
        .get_object(cid_ref)
        .and_then(|o| o.as_dict())
        .expect("CIDFont")
        .clone();
    (type0, cid)
}

/// A visible text seal must be drawn with an embedded face, and the appearance stream must carry
/// enough to extract its text again: a `Type0`/`Identity-H` font whose `/FontDescriptor` is the
/// document's own (so no font programme is copied), a `/ToUnicode` entry per shown glyph, and `/W`
/// widths taken from the embedded `hmtx`.
#[test]
fn visible_text_seal_draws_with_the_documents_embedded_font() {
    let signer = TestSigner::new_rsa("PAdES Seal Embedded", 30);
    let seal = SealAppearance {
        placement: SealPlacement {
            page: 0,
            x: 72.0,
            y: 700.0,
            w: 180.0,
            h: 48.0,
        },
        // memory: fictional example name, never a real person. The accents matter: they are what a
        // standard-14 seal used to mangle, and what the /ToUnicode round-trip must preserve.
        content: SealContent::Text(TextSeal::signed_by(
            "Assinado por",
            "Amélia Marques",
            "2026-07-11",
        )),
    };
    let base = base_pdf_with_font(None);
    let signed = sign_with_appearance(&base, &signer, &SignOptions::default(), &seal);
    assert!(
        validate_pdf_signature(&signed)
            .expect("validate")
            .covers_whole_file_except_contents
    );

    // No standard-14 face anywhere, and the seal is not drawn with literal-string text.
    assert!(crate_find(&signed, b"Helvetica").is_none());
    assert!(crate_find(&signed, b"WinAnsiEncoding").is_none());

    let (type0, cid) = seal_font_dicts(&signed);
    assert_eq!(
        type0.get(b"Encoding").and_then(|o| o.as_name()).unwrap(),
        b"Identity-H"
    );
    assert!(type0.has(b"ToUnicode"));
    // The descriptor is the *document's* — object 6 of `base_pdf_with_font` — so the seal adds no
    // font programme of its own.
    assert_eq!(
        cid.get(b"FontDescriptor")
            .and_then(|o| o.as_reference())
            .unwrap(),
        (6, 0)
    );
    // Exactly one /FontFile2 in the whole signed file: the base document's.
    assert_eq!(
        signed.windows(11).filter(|w| *w == b"/FontFile2 ").count(),
        1
    );

    // Every glyph the appearance shows round-trips: /ToUnicode gives back the character, and the
    // /W width is the one the embedded hmtx declares (600/1000 em for this face).
    let doc = lopdf::Document::load_mem(&signed).expect("parse");
    let to_unicode_ref = type0
        .get(b"ToUnicode")
        .and_then(|o| o.as_reference())
        .unwrap();
    let cmap = doc
        .get_object(to_unicode_ref)
        .and_then(|o| o.as_stream())
        .map(|s| String::from_utf8(s.content.clone()).expect("utf-8 cmap"))
        .unwrap();
    let chars = test_face_chars();
    for ch in "Assinado por Amélia Marques 2026-07-11".chars() {
        let gid = chars.iter().position(|&c| c == ch).expect("covered") as u16 + 1;
        let mut units = [0u16; 2];
        let target: String = ch
            .encode_utf16(&mut units)
            .iter()
            .map(|u| format!("{u:04X}"))
            .collect();
        assert!(
            cmap.contains(&format!("<{gid:04X}> <{target}>")),
            "no /ToUnicode entry mapping glyph {gid} back to {ch:?}"
        );
        assert!(
            crate_find(&signed, format!("{gid} [600]").as_bytes()).is_some(),
            "no /W width entry for glyph {gid}"
        );
    }
}

/// The `.notdef` gate, at the seal: a character the embedded face has no glyph for would render as
/// a blank box whose extracted text is whichever character reached `.notdef` first. Silently wrong
/// output is worse than a refused signature, so it is refused.
#[test]
fn a_seal_character_the_embedded_font_lacks_is_refused() {
    let seal = SealAppearance {
        placement: SealPlacement {
            page: 0,
            x: 10.0,
            y: 10.0,
            w: 120.0,
            h: 40.0,
        },
        content: SealContent::Text(TextSeal::name_date("Ω Marques", "2026-07-11")),
    };
    let err = prepare_signature_with_appearance(
        &base_pdf_with_font(None),
        &SignOptions::default(),
        Some(&seal),
    )
    .unwrap_err();
    match err {
        PadesError::MalformedStructure(msg) => {
            assert!(msg.contains("no glyph for"), "got {msg}");
            assert!(msg.contains("U+03A9"), "got {msg}");
        }
        other => panic!("expected MalformedStructure, got {other:?}"),
    }
}

/// A text seal on a document with no embedded font cannot be drawn conformantly. Falling back to a
/// standard-14 face is exactly the silent non-conformance this replaced, so it is an error.
#[test]
fn a_text_seal_needs_the_document_to_embed_a_font() {
    let seal = SealAppearance {
        placement: SealPlacement {
            page: 0,
            x: 10.0,
            y: 10.0,
            w: 120.0,
            h: 40.0,
        },
        content: SealContent::Text(TextSeal::name_date("Amélia Marques", "2026-07-11")),
    };
    let err = prepare_signature_with_appearance(&base_pdf(), &SignOptions::default(), Some(&seal))
        .unwrap_err();
    match err {
        PadesError::MalformedStructure(msg) => {
            assert!(msg.contains("embedded font"), "got {msg}")
        }
        other => panic!("expected MalformedStructure, got {other:?}"),
    }
}

// --- Dropping the PDF/UA-1 claim on signing (t12-e2) ----------------------------------------------

/// An XMP packet shaped like `chancela-doc`'s: PDF/A-2U identification plus a PDF/UA-1 claim and
/// the `pdfaExtension` schema description a PDF/A file must carry for the `pdfuaid` schema.
const XMP_CLAIMING_PDF_UA: &str = "<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n\
 <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
  <rdf:Description rdf:about=\"\"\n\
      xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\"\n\
      xmlns:pdfuaid=\"http://www.aiim.org/pdfua/ns/id/\"\n\
      xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\n\
   <pdfaid:part>2</pdfaid:part>\n\
   <pdfaid:conformance>U</pdfaid:conformance>\n\
   <pdfuaid:part>1</pdfuaid:part>\n\
   <dc:format>application/pdf</dc:format>\n\
  </rdf:Description>\n\
  <rdf:Description rdf:about=\"\"\n\
      xmlns:pdfaExtension=\"http://www.aiim.org/pdfa/ns/extension/\"\n\
      xmlns:pdfaSchema=\"http://www.aiim.org/pdfa/ns/schema#\">\n\
   <pdfaExtension:schemas>\n\
    <rdf:Bag>\n\
     <rdf:li rdf:parseType=\"Resource\">\n\
      <pdfaSchema:namespaceURI>http://www.aiim.org/pdfua/ns/id/</pdfaSchema:namespaceURI>\n\
      <pdfaSchema:prefix>pdfuaid</pdfaSchema:prefix>\n\
     </rdf:li>\n\
    </rdf:Bag>\n\
   </pdfaExtension:schemas>\n\
  </rdf:Description>\n\
 </rdf:RDF>\n\
</x:xmpmeta>\n\
<?xpacket end=\"w\"?>";

/// Resolve the catalog's `/Metadata` stream content from a document.
fn metadata_packet(pdf: &[u8]) -> String {
    let doc = lopdf::Document::load_mem(pdf).expect("parse");
    let root = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .expect("root");
    let metadata_ref = doc
        .get_object(root)
        .and_then(lopdf::Object::as_dict)
        .and_then(|catalog| catalog.get(b"Metadata"))
        .and_then(lopdf::Object::as_reference)
        .expect("/Metadata");
    let stream = doc
        .get_object(metadata_ref)
        .and_then(lopdf::Object::as_stream)
        .expect("metadata stream");
    String::from_utf8(stream.content.clone()).expect("utf-8 packet")
}

/// A signature widget is not in the structure tree (ISO 14289-1 7.18.1), so a signed file may not
/// go on claiming PDF/UA-1. The claim is dropped by **superseding** the metadata object in the
/// incremental update: the signed base bytes are untouched — which the `/ByteRange` requires — and
/// the newest definition is the one a reader resolves.
#[test]
fn signing_supersedes_the_xmp_to_drop_the_pdf_ua_claim() {
    let signer = TestSigner::new_rsa("PAdES UA", 31);
    let base = base_pdf_with_font(Some(XMP_CLAIMING_PDF_UA));
    assert!(metadata_packet(&base).contains("<pdfuaid:part>1</pdfuaid:part>"));

    let signed = sign_with(&base, &signer, &SignOptions::default());

    // Nothing in the base revision moved: the signature is an append, not an edit.
    assert_eq!(&signed[..base.len()], &base[..]);
    // The original packet is still there, verbatim, in the bytes the signature covers.
    assert!(crate_find(&signed[..base.len()], b"<pdfuaid:part>1</pdfuaid:part>").is_some());

    // But the document now resolves to a packet with no UA claim at all — identifier, namespace
    // declaration and extension schema description are all gone.
    let packet = metadata_packet(&signed);
    assert!(!packet.contains("pdfuaid"), "residual UA claim: {packet}");
    assert!(!packet.contains("pdfaExtension"), "residual: {packet}");
    // And the PDF/A identification it *does* satisfy is untouched.
    assert!(packet.contains("<pdfaid:part>2</pdfaid:part>"));
    assert!(packet.contains("<pdfaid:conformance>U</pdfaid:conformance>"));
    assert!(packet.contains("<dc:format>application/pdf</dc:format>"));

    // The signature still validates over the whole file, superseded metadata included.
    let report = validate_pdf_signature(&signed).expect("validate");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signer.cert_der());
}

/// A document that never claimed PDF/UA is signed exactly as before — no metadata object is
/// re-emitted, so the incremental update stays as small as it was.
#[test]
fn signing_a_document_without_a_ua_claim_supersedes_nothing() {
    let signer = TestSigner::new_rsa("PAdES No UA", 32);
    let packet = "<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n\
 <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
  <rdf:Description rdf:about=\"\"\n\
      xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\">\n\
   <pdfaid:part>2</pdfaid:part>\n\
   <pdfaid:conformance>U</pdfaid:conformance>\n\
  </rdf:Description>\n\
 </rdf:RDF>\n\
</x:xmpmeta>\n\
<?xpacket end=\"w\"?>";
    let base = base_pdf_with_font(Some(packet));
    let signed = sign_with(&base, &signer, &SignOptions::default());

    let appended = &signed[base.len()..];
    assert!(
        crate_find(appended, b"/Type /Metadata").is_none(),
        "an unclaimed document had its metadata re-emitted anyway"
    );
    assert!(
        validate_pdf_signature(&signed)
            .expect("validate")
            .covers_whole_file_except_contents
    );
}

#[test]
fn visible_image_seal_embeds_png_with_smask_on_requested_page_and_validates() {
    let signer = TestSigner::new_ecdsa("PAdES Seal Image", 21);
    let placement = SealPlacement {
        page: 1, // second page of a two-page document
        x: 100.0,
        y: 120.0,
        w: 96.0,
        h: 64.0,
    };
    let seal = SealAppearance {
        placement,
        content: SealContent::Image(ImageSeal {
            data: tiny_rgba_png(),
            format: SealImageFormat::Png,
        }),
    };
    let signed = sign_with_appearance(
        &base_pdf_two_pages(),
        &signer,
        &SignOptions::default(),
        &seal,
    );

    // Signature integrity preserved.
    let report = validate_pdf_signature(&signed).expect("validate image-seal PDF");
    assert!(report.covers_whole_file_except_contents);

    // /Rect on the requested page and an /AP /N form XObject.
    let widget = signature_widget(&signed);
    assert_eq!(widget_rect(&widget), [100.0, 120.0, 196.0, 184.0]);
    let form_ref = assert_ap_is_form_xobject(&signed, &widget);
    // Widget bound to page index 1 (object 4 = second page).
    assert_eq!(
        widget.get(b"P").and_then(|o| o.as_reference()).unwrap(),
        (4, 0)
    );

    // The appearance form references an image XObject, and the RGBA source produced an /SMask.
    let doc = lopdf::Document::load_mem(&signed).expect("parse");
    let form = doc
        .get_object(form_ref)
        .and_then(|o| o.as_stream())
        .unwrap();
    let xobjects = form
        .dict
        .get(b"Resources")
        .and_then(|o| o.as_dict())
        .and_then(|r| r.get(b"XObject"))
        .and_then(|o| o.as_dict())
        .expect("form /Resources /XObject");
    let im_ref = xobjects
        .get(b"Im0")
        .and_then(|o| o.as_reference())
        .expect("/Im0 image reference");
    let image = doc.get_object(im_ref).and_then(|o| o.as_stream()).unwrap();
    assert_eq!(
        image.dict.get(b"Subtype").and_then(|o| o.as_name()).ok(),
        Some(b"Image".as_ref())
    );
    assert_eq!(
        image.dict.get(b"Width").and_then(|o| o.as_i64()).ok(),
        Some(2)
    );
    assert_eq!(
        image.dict.get(b"ColorSpace").and_then(|o| o.as_name()).ok(),
        Some(b"DeviceRGB".as_ref())
    );
    let smask_ref = image
        .dict
        .get(b"SMask")
        .and_then(|o| o.as_reference())
        .expect("RGBA image carries an /SMask");
    let smask = doc
        .get_object(smask_ref)
        .and_then(|o| o.as_stream())
        .unwrap();
    assert_eq!(
        smask.dict.get(b"ColorSpace").and_then(|o| o.as_name()).ok(),
        Some(b"DeviceGray".as_ref())
    );
}

#[test]
fn visible_jpeg_seal_embeds_verbatim_dctdecode() {
    let signer = TestSigner::new_rsa("PAdES Seal JPEG", 22);
    // A minimal baseline-JPEG header: SOI, an APP0/JFIF stub, then a SOF0 declaring 8×8 3-component,
    // then SOS. Enough for the frame-header scan; the bytes are embedded verbatim as /DCTDecode.
    let jpeg: Vec<u8> = vec![
        0xFF, 0xD8, // SOI
        0xFF, 0xC0, 0x00, 0x11, // SOF0, length 17
        0x08, // precision 8
        0x00, 0x08, // height 8
        0x00, 0x08, // width 8
        0x03, // 3 components
        0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, // component specs
        0xFF, 0xDA, 0x00, 0x02, // SOS
        0xFF, 0xD9, // EOI
    ];
    let placement = SealPlacement {
        page: 0,
        x: 40.0,
        y: 40.0,
        w: 72.0,
        h: 72.0,
    };
    let seal = SealAppearance {
        placement,
        content: SealContent::Image(ImageSeal {
            data: jpeg.clone(),
            format: SealImageFormat::Jpeg,
        }),
    };
    let signed = sign_with_appearance(&base_pdf(), &signer, &SignOptions::default(), &seal);

    let report = validate_pdf_signature(&signed).expect("validate jpeg-seal PDF");
    assert!(report.covers_whole_file_except_contents);

    let widget = signature_widget(&signed);
    let form_ref = assert_ap_is_form_xobject(&signed, &widget);
    let doc = lopdf::Document::load_mem(&signed).expect("parse");
    let form = doc
        .get_object(form_ref)
        .and_then(|o| o.as_stream())
        .unwrap();
    let im_ref = form
        .dict
        .get(b"Resources")
        .and_then(|o| o.as_dict())
        .and_then(|r| r.get(b"XObject"))
        .and_then(|o| o.as_dict())
        .and_then(|x| x.get(b"Im0"))
        .and_then(|o| o.as_reference())
        .unwrap();
    let image = doc.get_object(im_ref).and_then(|o| o.as_stream()).unwrap();
    assert_eq!(
        image.dict.get(b"Filter").and_then(|o| o.as_name()).ok(),
        Some(b"DCTDecode".as_ref()),
        "JPEG embedded as DCTDecode"
    );
    assert_eq!(image.content, jpeg, "JPEG bytes embedded verbatim");
    assert_eq!(
        image.dict.get(b"ColorSpace").and_then(|o| o.as_name()).ok(),
        Some(b"DeviceRGB".as_ref())
    );
}

#[test]
fn invisible_default_is_unchanged_with_appearance_api() {
    // Driving the appearance-capable path with `None` must reproduce the byte-identical invisible
    // signature the legacy `sign_pdf` produces (backward compatibility).
    let signer = TestSigner::new_rsa("PAdES Invisible Default", 23);
    let opts = SignOptions {
        signing_time: Some("D:20260706142640Z".into()),
        ..SignOptions::default()
    };
    let via_legacy = sign_with(&base_pdf(), &signer, &opts);

    let signing_time = fixed_time();
    let cert = signer.cert_der();
    let via_new = sign_pdf_with_appearance(&base_pdf(), &opts, None, |digest| {
        let attrs = signed_attributes_digest(digest, &cert, signing_time)?;
        let raw = signer.raw_signature(&attrs);
        assemble_cades_b(&raw, digest, signing_time)
    })
    .expect("sign_pdf_with_appearance(None)");

    assert_eq!(via_legacy, via_new);
    assert!(crate_find(&via_new, b"/Rect [0 0 0 0]").is_some());
    assert!(crate_find(&via_new, b"/AP").is_none());
}

#[test]
fn seal_page_out_of_range_is_rejected() {
    let seal = SealAppearance {
        placement: SealPlacement {
            page: 5, // base_pdf has one page
            x: 10.0,
            y: 10.0,
            w: 50.0,
            h: 20.0,
        },
        content: SealContent::Text(TextSeal::name_date("Amélia Marques", "2026-07-11")),
    };
    let err = prepare_signature_with_appearance(&base_pdf(), &SignOptions::default(), Some(&seal))
        .unwrap_err();
    match err {
        PadesError::MalformedStructure(msg) => assert!(msg.contains("out of range"), "got {msg}"),
        other => panic!("expected MalformedStructure, got {other:?}"),
    }
}

#[test]
fn seal_zero_size_is_rejected() {
    let seal = SealAppearance {
        placement: SealPlacement {
            page: 0,
            x: 10.0,
            y: 10.0,
            w: 0.0,
            h: 20.0,
        },
        content: SealContent::Text(TextSeal::name_date("Amélia Marques", "2026-07-11")),
    };
    let err = prepare_signature_with_appearance(&base_pdf(), &SignOptions::default(), Some(&seal))
        .unwrap_err();
    assert!(
        matches!(err, PadesError::MalformedStructure(_)),
        "got {err:?}"
    );
}

/// Tiny helper: first occurrence of `needle` in `haystack` (tests avoid depending on `pdf` internals).
fn crate_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn dss_array_refs(pdf: &[u8], key: &[u8]) -> Vec<(u32, u16)> {
    let doc = lopdf::Document::load_mem(pdf).expect("parse PDF");
    let root = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .expect("root");
    let catalog = doc
        .get_object(root)
        .and_then(lopdf::Object::as_dict)
        .expect("catalog");
    let (_, dss_obj) = doc
        .dereference(catalog.get(b"DSS").expect("DSS"))
        .expect("DSS ref");
    let dss = dss_obj.as_dict().expect("DSS dict");
    let (_, array_obj) = doc
        .dereference(dss.get(key).expect("array"))
        .expect("array ref");
    array_obj
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item.as_reference().expect("stream ref"))
        .collect()
}

fn append_synthetic_sig_dictionary(pdf: &[u8], contents_der: &[u8]) -> Vec<u8> {
    append_synthetic_sig_dictionary_with_signed_revision_len(pdf, contents_der, 0)
}

fn append_synthetic_sig_dictionary_with_signed_revision_len(
    pdf: &[u8],
    contents_der: &[u8],
    signed_revision_len: usize,
) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(pdf).expect("parse PDF");
    let root = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .expect("root");
    let prev_startxref = crate::pdf::last_startxref(pdf).expect("startxref");
    let sig_id = doc.max_id + 1;
    let mut out = pdf.to_vec();
    let obj_offset = out.len() + 1;
    out.extend_from_slice(b"\n");
    out.extend_from_slice(format!("{sig_id} 0 obj\n").as_bytes());
    out.extend_from_slice(b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached ");
    out.extend_from_slice(
        format!("/ByteRange [0 0 {signed_revision_len} 0] /Contents <").as_bytes(),
    );
    out.extend_from_slice(&crate::pdf::to_hex(contents_der));
    out.extend_from_slice(b"> >>\nendobj\n");
    let xref_offset = out.len();
    out.extend_from_slice(
        format!(
            "xref\n{sig_id} 1\n{obj_offset:010} 00000 n\r\ntrailer\n<< /Size {} /Root {} 0 R /Prev {prev_startxref} >>\nstartxref\n{xref_offset}\n%%EOF\n",
            sig_id + 1,
            root.0
        )
        .as_bytes(),
    );
    out
}

/// Append an incremental update that redefines the existing object `obj_id` with `new_body`. Later
/// revisions win, so a viewer (and `lopdf`) renders `new_body` in place of the signed object — a
/// content-bearing tamper the first signature never covered (C3).
fn append_object_override(pdf: &[u8], obj_id: u32, new_body: &str) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(pdf).expect("parse PDF");
    let root = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .expect("root");
    let prev_startxref = crate::pdf::last_startxref(pdf).expect("startxref");
    let mut out = pdf.to_vec();
    let obj_offset = out.len() + 1;
    out.extend_from_slice(b"\n");
    out.extend_from_slice(format!("{obj_id} 0 obj\n{new_body}\nendobj\n").as_bytes());
    let xref_offset = out.len();
    out.extend_from_slice(
        format!(
            "xref\n{obj_id} 1\n{obj_offset:010} 00000 n\r\ntrailer\n<< /Size {} /Root {} 0 R /Prev {prev_startxref} >>\nstartxref\n{xref_offset}\n%%EOF\n",
            doc.max_id + 1,
            root.0
        )
        .as_bytes(),
    );
    out
}

/// Build a self-contained signed PDF whose signature `/ByteRange` gap deliberately spans **more**
/// than the `/Contents` token (it also excludes the space right after the closing `>`), yet whose
/// CMS is computed over exactly that widened gap so the cryptographic check still passes. Exercises
/// the C3 MEDIUM: a signature whose excluded gap is not exactly `/Contents` must not be reported
/// clean.
fn sign_with_overwide_gap(signer: &TestSigner) -> Vec<u8> {
    // Placeholder hex-byte capacity; a self-signed CAdES-B CMS fits with zero padding.
    const CAPACITY: usize = 4096;
    let signing_time = fixed_time();
    let cert = signer.cert_der();

    let mut sig_body = String::from(
        "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 0000000000 0000000000 0000000000] /Contents <",
    );
    sig_body.push_str(&"0".repeat(CAPACITY * 2));
    sig_body.push_str("> >>");
    let objects: [(u32, &str); 4] = [
        (1, "<< /Type /Catalog /Pages 2 0 R >>"),
        (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
        ),
        (4, sig_body.as_str()),
    ];

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::new();
    for (id, body) in &objects {
        offsets.push((*id, buf.len()));
        buf.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n0 5\n0000000000 65535 f\r\n");
    for id in 1..=4u32 {
        let off = offsets.iter().find(|(i, _)| *i == id).unwrap().1;
        buf.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
    }
    buf.extend_from_slice(b"trailer\n<< /Size 5 /Root 1 0 R >>\n");
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());

    let lt = crate_find(&buf, b"/Contents <").unwrap() + b"/Contents ".len();
    let hex_start = lt + 1;
    let gt = hex_start + CAPACITY * 2;
    assert_eq!(buf[gt], b'>', "closing '>' where expected");
    // Widen the excluded gap one byte past '>' (the following space), so it is no longer the lone
    // '<...>' /Contents token.
    let l1 = lt;
    let s2 = gt + 2;
    let range2_len = buf.len() - s2;

    let br_marker = crate_find(&buf, b"/ByteRange [0 ").unwrap() + b"/ByteRange [0 ".len();
    let br = format!("{l1:010} {s2:010} {range2_len:010}");
    buf[br_marker..br_marker + br.len()].copy_from_slice(br.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&buf[0..l1]);
    hasher.update(&buf[s2..s2 + range2_len]);
    let digest: [u8; 32] = hasher.finalize().into();

    let attrs = signed_attributes_digest(&digest, &cert, signing_time).expect("signed attrs");
    let raw = signer.raw_signature(&attrs);
    let cms = assemble_cades_b(&raw, &digest, signing_time).expect("cades");
    assert!(cms.len() <= CAPACITY, "CMS must fit the placeholder");

    let hex = crate::pdf::to_hex(&cms);
    buf[hex_start..hex_start + hex.len()].copy_from_slice(&hex);
    buf
}
