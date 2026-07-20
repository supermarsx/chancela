//! t57 Slice 2 — the **two-phase resumable CMD signing** round-trip, end to end, offline.
//!
//! Proves the F5 seam: `prepare_signature` (compute the ByteRange digest) → `cmd_initiate`
//! (`GetCertificate` + trusted-list gate + `CCMovelSign`) → suspend → `cmd_confirm` (`ValidateOtp`
//! → assemble CMS) → `embed_signature` → `validate_pdf_signature`. All SCMD traffic is served by
//! `chancela_cmd::MockScmdTransport` (no network, t57 gate).
//!
//! To make the signature *cryptographically* valid — the mock's canned fixture signature is not —
//! the test mints an ephemeral RSA-2048 key + self-signed certificate and drives the two
//! `MockScmdTransport`s with responses derived from it: `GetCertificate` returns the cert PEM, and
//! `ValidateOtp` returns a real PKCS#1 v1.5 signature over the signed-attributes digest the session
//! reports. This mirrors the real deployment's two stateless requests (two client instances) while
//! staying fully offline. No private keys are checked in (plan §6).
//!
//! Fixtures use the fictional "Encosto Estratégico Lda" / "Amélia Marques" — never a real entity.

use std::str::FromStr;
use std::time::Duration as StdDuration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::asn1::{Any, BitString, ObjectIdentifier};
use der::pem::LineEnding;
use der::{Encode, EncodePem};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_cmd::soap::{ACTION_CCMOVEL_SIGN, ACTION_GET_CERTIFICATE, ACTION_VALIDATE_OTP};
use chancela_cmd::{MockScmdTransport, ScmdClient};

use chancela_cades::signed_attributes_digest;
use chancela_pades::{SignOptions, prepare_signature, validate_pdf_signature};
use chancela_signing::{
    CmdInitiate, CmdSignSession, StaticTrustPolicy, TrustedListStatus, cmd_confirm, cmd_initiate,
    embed_signature,
};

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const APP_ID: &str = "CHANCELA-PREPROD-0001";
const PHONE: &str = "+351 912345678";
const PIN: &str = "271828";
const OTP: &str = "314159";

/// 2025-06-15T14:26:40Z — whole seconds, inside the CAdES UTCTime window.
fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

// --- Ephemeral in-test RSA signer (mirrors chancela-pades/src/tests.rs) ---------------------------

struct RsaSigner {
    key: rsa::RsaPrivateKey,
    cert: Certificate,
}

impl RsaSigner {
    fn new(cn: &str, serial: u8) -> Self {
        use rsa::rand_core::OsRng;
        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let spki =
            SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        };
        let signer = key.clone();
        let cert = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            sign_rsa_digest_info(&signer, &Sha256::digest(tbs).into())
        });
        Self { key, cert }
    }

    fn cert_pem(&self) -> String {
        self.cert.to_pem(LineEnding::LF).expect("cert pem")
    }

    /// Raw PKCS#1 v1.5 signature over the SHA-256 DigestInfo of `digest` — exactly the shape SCMD's
    /// `ValidateOtp` returns.
    fn sign_digest(&self, digest: &[u8; 32]) -> Vec<u8> {
        sign_rsa_digest_info(&self.key, digest)
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
) -> Certificate {
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
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&signature).expect("bitstring"),
    }
}

// --- Minimal base PDF (classic cross-reference table, mirrors chancela-pades tests) ---------------

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

// --- Mock SCMD SOAP responses derived from the ephemeral signer -----------------------------------

fn get_certificate_response(leaf_pem: &str, issuer_pem: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <GetCertificateResponse xmlns="http://tempuri.org/">
      <GetCertificateResult>{leaf_pem}{issuer_pem}</GetCertificateResult>
    </GetCertificateResponse>
  </s:Body>
</s:Envelope>"#
    )
}

fn validate_otp_response(signature_b64: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <ValidateOtpResponse xmlns="http://tempuri.org/">
      <ValidateOtpResult xmlns:a="http://schemas.datacontract.org/2004/07/Ama.Authentication.Service.Services.CMDService" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <a:Signature>{signature_b64}</a:Signature>
        <a:Status>
          <a:Code>200</a:Code>
          <a:Message>Signature completed.</a:Message>
        </a:Status>
      </ValidateOtpResult>
    </ValidateOtpResponse>
  </s:Body>
</s:Envelope>"#
    )
}

// --- The proof ------------------------------------------------------------------------------------

/// THE t57 Slice-2 proof: `prepare_signature` → `cmd_initiate` → (persist session) → `cmd_confirm`
/// → `embed_signature` → `validate_pdf_signature`, over `MockScmdTransport`. The trusted-list gate
/// is exercised (granted). The persisted session is asserted to carry no PIN/OTP.
#[test]
fn prepare_initiate_confirm_embed_validate_round_trip() {
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let pdf = base_pdf();
    let signing_time = fixed_time();

    // Phase 0: prepare the incremental update — compute the ByteRange digest to sign.
    let opts = SignOptions {
        field_name: Some("Assinatura".into()),
        signing_time: Some("D:20250615142640Z".into()),
        reason: Some("Ata aprovada em assembleia".into()),
        location: Some("Lisboa".into()),
        contact_info: None,
    };
    let prepared = prepare_signature(&pdf, &opts).expect("prepare");

    // --- REQUEST 1: initiate (GetCertificate + TSL gate + CCMovelSign) ---
    let init_transport = MockScmdTransport::empty()
        .with_response(
            ACTION_GET_CERTIFICATE,
            get_certificate_response(&leaf.cert_pem(), &issuer.cert_pem()),
        )
        .with_response(ACTION_CCMOVEL_SIGN, chancela_cmd::mock::CCMOVEL_SIGN_OK);
    let init_client = ScmdClient::new(init_transport, APP_ID);

    let mut policy = StaticTrustPolicy::granted();
    let session = cmd_initiate(
        &init_client,
        &CmdInitiate {
            user_id: PHONE,
            pin: PIN,
            doc_name: "livro-de-atas.pdf",
            signing_time,
        },
        &prepared,
        Some(&mut policy),
    )
    .expect("initiate");

    assert_eq!(
        session.trusted_list_status,
        Some(TrustedListStatus::Granted),
        "the trusted-list gate resolved and passed"
    );
    assert_eq!(
        &session.byterange_digest,
        prepared.byterange_digest(),
        "session digest links to the prepared signature"
    );

    // The session is the persisted, resumable, NON-SECRET handle: it must not carry the PIN/OTP.
    let persisted = serde_json::to_string(&session).expect("session serializes");
    assert!(!persisted.contains(PIN), "PIN must never be in the session");
    assert!(!persisted.contains(OTP), "OTP must never be in the session");
    assert!(
        !format!("{session:?}").contains(PIN),
        "PIN must not leak via Debug"
    );
    // Round-trip the session through persistence, as the api layer will between the two requests.
    let session: CmdSignSession = serde_json::from_str(&persisted).expect("session deserializes");

    // Out-of-band: the citizen receives the SMS OTP and the server prepares to confirm. Build the
    // ValidateOtp response = a real RSA signature over the signed-attributes digest the session
    // reports (this stands in for AMA signing after the OTP is validated).
    let signed_attrs = signed_attributes_digest(
        &session.byterange_digest,
        &session.signing_cert_der,
        session.signing_time,
    )
    .expect("signed attrs digest");
    let raw_sig = leaf.sign_digest(&signed_attrs);
    assert_eq!(raw_sig.len(), 256, "RSA-2048 signature");

    // --- REQUEST 2: confirm (ValidateOtp -> assemble CMS) ---
    let confirm_transport = MockScmdTransport::empty()
        .with_response(
            ACTION_GET_CERTIFICATE,
            get_certificate_response(&leaf.cert_pem(), &issuer.cert_pem()),
        )
        .with_response(
            ACTION_VALIDATE_OTP,
            validate_otp_response(&STANDARD.encode(&raw_sig)),
        );
    let confirm_client = ScmdClient::new(confirm_transport, APP_ID);

    let cms = cmd_confirm(&confirm_client, &session, OTP).expect("confirm");

    // Phase 3: embed the CMS into the reserved placeholder and validate the signed PDF.
    let signed_pdf = embed_signature(&prepared, &cms).expect("embed");
    assert_eq!(
        &signed_pdf[..pdf.len()],
        &pdf[..],
        "incremental update: original bytes are an untouched prefix"
    );

    let report = validate_pdf_signature(&signed_pdf).expect("signature must validate");
    assert!(
        report.covers_whole_file_except_contents,
        "ByteRange covers the whole file except /Contents"
    );
    assert_eq!(
        report.total_len,
        signed_pdf.len(),
        "validation ran over the whole signed file"
    );
    assert_eq!(
        report.cades.signer_cert_der, session.signing_cert_der,
        "validated signer cert is the session's leaf"
    );
    assert!(
        report.cades.signing_certificate_v2_present,
        "CAdES-B signing-certificate-v2 present"
    );
    assert_eq!(
        report.cades.signing_time.map(|t| t.unix_timestamp()),
        Some(1_750_000_000),
        "authoritative signing time carried in the signed attributes"
    );
    assert!(
        !report.has_signature_timestamp,
        "B-B — no signature timestamp"
    );
}

/// The trusted-list gate rejects a non-granted issuer at initiate, before any OTP is dispatched.
#[test]
fn initiate_rejects_untrusted_issuer() {
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let pdf = base_pdf();
    let prepared = prepare_signature(&pdf, &SignOptions::default()).expect("prepare");

    let transport = MockScmdTransport::empty()
        .with_response(
            ACTION_GET_CERTIFICATE,
            get_certificate_response(&leaf.cert_pem(), &issuer.cert_pem()),
        )
        .with_response(ACTION_CCMOVEL_SIGN, chancela_cmd::mock::CCMOVEL_SIGN_OK);
    let client = ScmdClient::new(transport, APP_ID);

    let mut policy = StaticTrustPolicy::withdrawn();
    let err = cmd_initiate(
        &client,
        &CmdInitiate {
            user_id: PHONE,
            pin: PIN,
            doc_name: "d.pdf",
            signing_time: fixed_time(),
        },
        &prepared,
        Some(&mut policy),
    )
    .expect_err("withdrawn issuer must be rejected");

    match err {
        chancela_signing::SigningError::UntrustedService { status } => {
            assert_eq!(status, TrustedListStatus::Withdrawn);
        }
        other => panic!("expected UntrustedService, got {other:?}"),
    }
    // CCMovelSign must NOT have been called — no OTP dispatched to an untrusted signer.
    let called_sign = client
        .transport()
        .calls()
        .iter()
        .any(|c| c.action == ACTION_CCMOVEL_SIGN);
    assert!(!called_sign, "no signature started for an untrusted issuer");
}
