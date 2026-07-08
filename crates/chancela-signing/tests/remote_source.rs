//! t59 Slice 1 — the **`RemoteSigningSource`** trait contract, proven end to end, offline.
//!
//! Two proofs:
//!
//! 1. **A mock `RemoteSigningSource` round-trips the whole pipeline** — `prepare_signature` →
//!    `initiate` → (persist the secret-free session) → `confirm` → `embed_signature` →
//!    `validate_pdf_signature`. This exercises the frozen trait contract with an arbitrary provider
//!    (not CMD), the shape a CSC-v2 QTSP adapter (`chancela-csc`, t59 Slice 2) will take.
//! 2. **The CMD impl (`CmdRemoteSource`) satisfies the trait** and its two-phase behaviour is
//!    **byte-identical** to the t57 `cmd_initiate`/`cmd_confirm` façades — the same driven over
//!    `MockScmdTransport`, asserting the produced CMS bytes match exactly.
//!
//! All SCMD traffic is served by `chancela_cmd::MockScmdTransport`; the mock provider signs with an
//! ephemeral RSA-2048 key. No network, no private keys checked in (plan §6). Fixtures use the
//! fictional "Encosto Estratégico Lda" / "Amélia Marques" — never a real entity.

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
use zeroize::Zeroizing;

use chancela_cmd::soap::{ACTION_CCMOVEL_SIGN, ACTION_GET_CERTIFICATE, ACTION_VALIDATE_OTP};
use chancela_cmd::{MockScmdTransport, ScmdClient};

use chancela_cades::{
    RawSignature, SignatureAlgorithm, assemble_cades_b, signed_attributes_digest,
};
use chancela_pades::{SignOptions, prepare_signature, validate_pdf_signature};
use chancela_signing::{
    CmdInitiate, CmdSignSession, EvidentiaryLevel, RemoteInitiate, RemoteSignSession,
    RemoteSigningSource, SigningError, SigningFamily, StaticTrustPolicy, TrustPolicy,
    TrustedListStatus, cmd_confirm, cmd_initiate, embed_signature,
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

// --- Ephemeral in-test RSA signer (mirrors tests/cmd_two_phase.rs) --------------------------------

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

    fn cert_der(&self) -> Vec<u8> {
        self.cert.to_der().expect("cert der")
    }

    /// Raw PKCS#1 v1.5 signature over the SHA-256 DigestInfo of `digest`.
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

fn sign_opts() -> SignOptions {
    SignOptions {
        field_name: Some("Assinatura".into()),
        signing_time: Some("D:20250615142640Z".into()),
        reason: Some("Ata aprovada em assembleia".into()),
        location: Some("Lisboa".into()),
        contact_info: None,
    }
}

// --- Mock SCMD SOAP responses derived from an ephemeral signer ------------------------------------

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

// --- A mock RemoteSigningSource — the shape a CSC-v2 QTSP adapter (t59 Slice 2) will take ----------

/// An in-test [`RemoteSigningSource`] backed by an ephemeral RSA key. Stands in for any remote QTSP:
/// `initiate` resolves the (ephemeral) signer cert, gates it, and opens a session with a synthetic
/// provider reference; `confirm` validates the activation, signs the session's signed-attributes
/// digest, and assembles the detached CAdES-B CMS — exactly what a CSC `signatures/signHash` +
/// CMS-assembly step produces.
struct MockRemoteSource {
    provider_id: String,
    signer: RsaSigner,
    issuer: RsaSigner,
    /// The one activation value this source will accept at `confirm` (the "OTP/SAD").
    expected_activation: String,
}

impl RemoteSigningSource for MockRemoteSource {
    fn family(&self) -> SigningFamily {
        // A CSC-standard external QTSP is a qualified-certificate source (plan ruling 4).
        SigningFamily::QualifiedCertificate
    }

    fn evidentiary_level(&self) -> EvidentiaryLevel {
        EvidentiaryLevel::Qualified
    }

    fn initiate(
        &self,
        req: &RemoteInitiate<'_>,
        prepared: &chancela_signing::PreparedSignature,
        policy: Option<&mut dyn TrustPolicy>,
    ) -> Result<RemoteSignSession, SigningError> {
        let issuer_der = self.issuer.cert_der();
        let trusted_list_status = match policy {
            Some(policy) => {
                let status = policy.issuer_status(&issuer_der, req.signing_time)?;
                if status != TrustedListStatus::Granted {
                    return Err(SigningError::UntrustedService { status });
                }
                Some(status)
            }
            None => None,
        };
        Ok(RemoteSignSession {
            provider_id: self.provider_id.clone(),
            // A synthetic credential/authorization reference (a CSC `credentials/authorize` id).
            provider_ref: format!("auth-{}", req.user_ref),
            user_ref: req.user_ref.to_string(),
            signing_cert_der: self.signer.cert_der(),
            chain_der: vec![issuer_der],
            trusted_list_status,
            byterange_digest: *prepared.byterange_digest(),
            signing_time: req.signing_time,
        })
    }

    fn confirm(
        &self,
        session: &RemoteSignSession,
        activation: &Zeroizing<String>,
    ) -> Result<Vec<u8>, SigningError> {
        if activation.as_str() != self.expected_activation {
            return Err(SigningError::Provider("activation rejected".to_string()));
        }
        let signed_attrs = signed_attributes_digest(
            &session.byterange_digest,
            &session.signing_cert_der,
            session.signing_time,
        )
        .map_err(|e| SigningError::Cades(e.to_string()))?;
        let raw = RawSignature::new(
            SignatureAlgorithm::RsaPkcs1Sha256,
            self.signer.sign_digest(&signed_attrs),
            session.signing_cert_der.clone(),
            session.chain_der.clone(),
        );
        assemble_cades_b(&raw, &session.byterange_digest, session.signing_time)
            .map_err(|e| SigningError::Cades(e.to_string()))
    }
}

/// PROOF 1 — an arbitrary `RemoteSigningSource` round-trips the whole two-phase pipeline through the
/// trait object, producing a PDF that validates. Also asserts the session is secret-free.
#[test]
fn mock_remote_source_round_trips_prepare_initiate_confirm_embed_validate() {
    let source = MockRemoteSource {
        provider_id: "encosto-qtsp".to_string(),
        signer: RsaSigner::new("Amélia Marques (QTSP teste)", 1),
        issuer: RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2),
        expected_activation: OTP.to_string(),
    };
    // Drive it purely through the object-safe trait, as the api will (`dyn RemoteSigningSource`).
    let source: &dyn RemoteSigningSource = &source;

    assert_eq!(source.family(), SigningFamily::QualifiedCertificate);
    assert!(source.evidentiary_level().is_qualified_signature());

    let pdf = base_pdf();
    let prepared = prepare_signature(&pdf, &sign_opts()).expect("prepare");

    // Phase 1: initiate (with the trusted-list gate).
    let mut policy = StaticTrustPolicy::granted();
    let pin = Zeroizing::new(PIN.to_string());
    let session = source
        .initiate(
            &RemoteInitiate {
                user_ref: PHONE,
                credential: &pin,
                doc_name: "livro-de-atas.pdf",
                signing_time: fixed_time(),
            },
            &prepared,
            Some(&mut policy),
        )
        .expect("initiate");

    assert_eq!(session.provider_id, "encosto-qtsp");
    assert_eq!(
        session.trusted_list_status,
        Some(TrustedListStatus::Granted)
    );
    assert_eq!(&session.byterange_digest, prepared.byterange_digest());

    // The persisted session is secret-free: neither the PIN nor the activation appears.
    let persisted = serde_json::to_string(&session).expect("session serializes");
    assert!(!persisted.contains(PIN), "PIN must never be in the session");
    assert!(
        !persisted.contains(OTP),
        "activation must never be in the session"
    );
    assert!(
        !format!("{session:?}").contains(PIN),
        "PIN must not leak via Debug"
    );
    let session: RemoteSignSession =
        serde_json::from_str(&persisted).expect("session deserializes");

    // Phase 2: confirm with the activation → CMS → embed → validate.
    let activation = Zeroizing::new(OTP.to_string());
    let cms = source.confirm(&session, &activation).expect("confirm");
    let signed_pdf = embed_signature(&prepared, &cms).expect("embed");

    let report = validate_pdf_signature(&signed_pdf).expect("signature must validate");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, session.signing_cert_der);
    assert!(report.cades.signing_certificate_v2_present);
    assert_eq!(
        report.cades.signing_time.map(|t| t.unix_timestamp()),
        Some(1_750_000_000)
    );
}

/// PROOF 1b — the trait's trusted-list gate fails closed for a withdrawn issuer (no artifact).
#[test]
fn mock_remote_source_rejects_untrusted_issuer() {
    let source = MockRemoteSource {
        provider_id: "encosto-qtsp".to_string(),
        signer: RsaSigner::new("Amélia Marques (QTSP teste)", 1),
        issuer: RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2),
        expected_activation: OTP.to_string(),
    };
    let prepared = prepare_signature(&base_pdf(), &SignOptions::default()).expect("prepare");
    let pin = Zeroizing::new(PIN.to_string());
    let mut policy = StaticTrustPolicy::withdrawn();
    let err = source
        .initiate(
            &RemoteInitiate {
                user_ref: PHONE,
                credential: &pin,
                doc_name: "d.pdf",
                signing_time: fixed_time(),
            },
            &prepared,
            Some(&mut policy),
        )
        .expect_err("withdrawn issuer must be rejected");
    assert!(matches!(
        err,
        SigningError::UntrustedService {
            status: TrustedListStatus::Withdrawn
        }
    ));
}

/// PROOF 2 — `CmdRemoteSource` satisfies `RemoteSigningSource`, and driving CMD through the trait is
/// **byte-identical** to the t57 `cmd_initiate`/`cmd_confirm` façades: same session material, same
/// CMS bytes, over the same `MockScmdTransport` fixtures.
#[test]
fn cmd_remote_source_is_byte_identical_to_the_cmd_facade() {
    let leaf = RsaSigner::new("Amélia Marques (CMD teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let pdf = base_pdf();
    let signing_time = fixed_time();
    let prepared = prepare_signature(&pdf, &sign_opts()).expect("prepare");

    // Build fresh initiate transports (the mock consumes each canned response once per client).
    let make_init = || {
        let transport = MockScmdTransport::empty()
            .with_response(
                ACTION_GET_CERTIFICATE,
                get_certificate_response(&leaf.cert_pem(), &issuer.cert_pem()),
            )
            .with_response(ACTION_CCMOVEL_SIGN, chancela_cmd::mock::CCMOVEL_SIGN_OK);
        ScmdClient::new(transport, APP_ID)
    };

    // --- via the trait (CmdRemoteSource) ---
    use chancela_signing::CmdRemoteSource;
    let source = CmdRemoteSource::new(make_init());
    assert_eq!(source.family(), SigningFamily::ChaveMovelDigital);
    assert!(source.evidentiary_level().is_qualified_signature());
    let pin = Zeroizing::new(PIN.to_string());
    let mut policy_a = StaticTrustPolicy::granted();
    let trait_session = source
        .initiate(
            &RemoteInitiate {
                user_ref: PHONE,
                credential: &pin,
                doc_name: "livro-de-atas.pdf",
                signing_time,
            },
            &prepared,
            Some(&mut policy_a),
        )
        .expect("trait initiate");
    assert_eq!(trait_session.provider_id, "cmd");

    // --- via the t57 façade (cmd_initiate) ---
    let facade_client = make_init();
    let mut policy_b = StaticTrustPolicy::granted();
    let facade_session = cmd_initiate(
        &facade_client,
        &CmdInitiate {
            user_id: PHONE,
            pin: PIN,
            doc_name: "livro-de-atas.pdf",
            signing_time,
        },
        &prepared,
        Some(&mut policy_b),
    )
    .expect("facade initiate");

    // The façade session is exactly the trait session narrowed onto the CMD shape.
    assert_eq!(
        CmdSignSession::from(trait_session.clone()),
        facade_session,
        "trait and façade produce identical session material"
    );

    // Build the ValidateOtp response = a real RSA signature over the shared signed-attrs digest.
    // (initiate hashes the same inputs both ways, so one response serves both confirm paths.)
    let signed_attrs = signed_attributes_digest(
        &trait_session.byterange_digest,
        &trait_session.signing_cert_der,
        trait_session.signing_time,
    )
    .expect("signed attrs digest");
    let raw_sig = leaf.sign_digest(&signed_attrs);
    let otp_response = validate_otp_response(&STANDARD.encode(&raw_sig));

    // Each confirm is its own stateless request = its own transport (mirrors the deployment).
    let make_confirm_client = || {
        let transport = MockScmdTransport::empty()
            .with_response(
                ACTION_GET_CERTIFICATE,
                get_certificate_response(&leaf.cert_pem(), &issuer.cert_pem()),
            )
            .with_response(ACTION_VALIDATE_OTP, otp_response.clone());
        ScmdClient::new(transport, APP_ID)
    };

    // Confirm via the trait (fresh CmdRemoteSource) and via the t57 façade; assert identical CMS.
    let confirm_source = CmdRemoteSource::new(make_confirm_client());
    let cms_trait = confirm_source
        .confirm(&trait_session, &Zeroizing::new(OTP.to_string()))
        .expect("trait confirm");
    let cms_facade =
        cmd_confirm(&make_confirm_client(), &facade_session, OTP).expect("facade confirm");
    assert_eq!(
        cms_trait, cms_facade,
        "trait and façade confirm produce byte-identical CMS"
    );

    // And the trait-produced CMS embeds into a PDF that validates.
    let signed_pdf = embed_signature(&prepared, &cms_trait).expect("embed");
    let report = validate_pdf_signature(&signed_pdf).expect("validate");
    assert_eq!(report.cades.signer_cert_der, trait_session.signing_cert_der);
}
