//! The **resumable** Chave Móvel Digital signing bridge (t57 Slice 2, F5).
//!
//! [`CmdProvider`](crate::provider::CmdProvider) runs the CMD SIG-02 flow *synchronously* — it
//! pulls the OTP from a blocking closure inside a single [`SignerProvider`](crate::SignerProvider)
//! call. That model cannot span the two stateless HTTP requests a real interactive OTP flow needs
//! (initiate → user receives an SMS → submit OTP). This module splits the flow in two:
//!
//! - [`cmd_initiate`] — `GetCertificate` → trusted-list gate (SIG-11/23) → hash the PAdES prepared
//!   ByteRange digest into the CAdES signed-attributes digest → `CCMovelSign` (dispatches the OTP)
//!   → return a [`CmdSignSession`], the resumable handle.
//! - [`cmd_confirm`] — given the session + the OTP → `ValidateOtp` → [`RawSignature`] → assemble a
//!   detached CAdES-B CMS, ready to embed into the prepared PDF with
//!   [`chancela_pades::embed_signature`].
//!
//! The [`CmdSignSession`] carries only **non-secret** resumable state — the SCMD process id, the
//! citizen's (public) account id and certificate, the resolved trusted-list status, the ByteRange
//! digest, and the fixed signing time. It **never** holds the PIN or the OTP: those are transient
//! inputs consumed by the single call that receives them (the PIN by [`cmd_initiate`], the OTP by
//! [`cmd_confirm`]) and are never persisted (SIG-02; t57 ruling 4).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use chancela_cades::{RawSignature, assemble_cades_b, signed_attributes_digest};
use chancela_cmd::rand_core::OsRng;
use chancela_cmd::{CmdError, ProcessHandle, ScmdClient, ScmdTransport, SignRequest};
use chancela_pades::PreparedSignature;

use crate::policy::TrustPolicy;
use crate::{SigningError, TrustedListStatus};

/// The transient inputs to [`cmd_initiate`].
///
/// The `pin` is a secret **knowledge factor** consumed by this single call — it is passed straight
/// to `CCMovelSign` and is **never** copied into the returned [`CmdSignSession`] or otherwise
/// retained. Hold it in a `Zeroizing` buffer at the call site.
pub struct CmdInitiate<'a> {
    /// The citizen mobile number in SCMD format (`+351 XXXXXXXXX`).
    pub user_id: &'a str,
    /// The CMD signature PIN (knowledge factor). **Transient — never persisted.**
    pub pin: &'a str,
    /// A human-readable document label shown on the citizen's device.
    pub doc_name: &'a str,
    /// The fixed signing time. It MUST be reused unchanged at [`cmd_confirm`] time; the CAdES
    /// signed attributes are rebuilt from it, so a drift would make the signature invalid.
    pub signing_time: OffsetDateTime,
}

/// The **non-secret**, resumable handle bridging CMD's two-request OTP flow (t57 F5).
///
/// Produced by [`cmd_initiate`] and consumed by [`cmd_confirm`]. It is safe to persist between the
/// two requests (it derives `Serialize`/`Deserialize`): every field is public signature material or
/// correlation state — **never** the PIN or the OTP (SIG-02; t57 ruling 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CmdSignSession {
    /// The SCMD `ProcessId` correlating the pending OTP confirmation to the started signature.
    pub process_id: String,
    /// The citizen mobile number (`+351 XXXXXXXXX`). A public account identifier — **not** a
    /// credential — retained because `ValidateOtp` re-fetches the certificate keyed by it.
    pub user_id: String,
    /// The signer's leaf certificate (DER) resolved at initiate. The signed attributes were hashed
    /// over *this* certificate, so [`cmd_confirm`] reassembles the CMS with it (not any re-fetched
    /// copy) to guarantee the attributes reproduce the digest CMD actually signed.
    pub signing_cert_der: Vec<u8>,
    /// The issuer chain above the leaf (DER, leaf excluded), for CMS assembly and trust resolution.
    pub chain_der: Vec<Vec<u8>>,
    /// The trusted-list status of the signer's issuer resolved at initiate (SIG-11/23), if a
    /// policy was consulted. Only [`TrustedListStatus::Granted`] passes the gate.
    pub trusted_list_status: Option<TrustedListStatus>,
    /// The PAdES `/ByteRange` digest this signature covers — the "prepared" digest linking this
    /// session to its [`PreparedSignature`]. Non-secret.
    pub byterange_digest: [u8; 32],
    /// The fixed signing time carried over from [`cmd_initiate`] (identical across both phases).
    #[serde(with = "time::serde::rfc3339")]
    pub signing_time: OffsetDateTime,
}

/// **Phase 1 of the resumable CMD signature (t57 F5).**
///
/// Fetch the signer certificate, gate it against the trusted list (SIG-11/23) when a `policy` is
/// supplied, compute the CAdES signed-attributes digest over `prepared`'s ByteRange digest, and
/// start the signature with `CCMovelSign` — which dispatches the OTP to the citizen's device.
/// Returns the resumable [`CmdSignSession`] (no PIN, no OTP).
///
/// `client` drives the SCMD SOAP service; inject a `chancela_cmd::MockScmdTransport` in tests.
pub fn cmd_initiate<T: ScmdTransport>(
    client: &ScmdClient<T>,
    init: &CmdInitiate<'_>,
    prepared: &PreparedSignature,
    policy: Option<&mut dyn TrustPolicy>,
) -> Result<CmdSignSession, SigningError> {
    // 1. GetCertificate — the leaf is needed to build the signed attributes and the issuer to gate.
    let chain = client.get_certificate(init.user_id).map_err(provider_err)?;

    // 2. Trusted-list gate on the issuer (SIG-11/23): a qualified signature must not skip it.
    let trusted_list_status = match policy {
        Some(policy) => {
            let issuer = chain
                .chain_der
                .first()
                .ok_or(SigningError::MissingIssuerCertificate)?;
            let status = policy.issuer_status(issuer, init.signing_time)?;
            if status != TrustedListStatus::Granted {
                return Err(SigningError::UntrustedService { status });
            }
            Some(status)
        }
        None => None,
    };

    // 3. The CAdES signed-attributes digest over the PAdES ByteRange digest — this is what CMD
    //    signs (the OTP is only a confirmation step; the artifact is the qualified signature).
    let signed_attrs_digest = signed_attributes_digest(
        prepared.byterange_digest(),
        &chain.leaf_der,
        init.signing_time,
    )
    .map_err(cades_err)?;

    // 4. CCMovelSign — dispatches the OTP. `OsRng` is consumed only by the PROD field-encryption
    //    hook; cleartext (preprod) ignores it (mirrors `CmdProvider`).
    let mut rng = OsRng;
    let handle = client
        .request_signature(
            &mut rng,
            &SignRequest {
                user_id: init.user_id.to_string(),
                // Copied into `SignRequest`, whose `Drop` zeroizes the PIN; never stored below.
                pin: init.pin.to_string(),
                doc_name: init.doc_name.to_string(),
                hash: signed_attrs_digest.to_vec(),
            },
        )
        .map_err(provider_err)?;

    // 5. The resumable session — non-secret state only.
    Ok(CmdSignSession {
        process_id: handle.process_id,
        user_id: handle.user_id,
        signing_cert_der: chain.leaf_der,
        chain_der: chain.chain_der,
        trusted_list_status,
        byterange_digest: *prepared.byterange_digest(),
        signing_time: init.signing_time,
    })
}

/// **Phase 2 of the resumable CMD signature (t57 F5).**
///
/// Confirm the possession factor (`ValidateOtp`) and assemble the detached CAdES-B CMS over the
/// session's ByteRange digest, returning the CMS bytes ready to embed with
/// [`chancela_pades::embed_signature`]. The `otp` is transient — consumed here, never persisted.
///
/// The CMS is reassembled from the **session's** certificate/chain and signing time (the exact
/// inputs whose signed attributes were hashed at initiate), so the attributes reproduce the digest
/// CMD signed regardless of what `ValidateOtp`'s internal certificate re-fetch returns.
pub fn cmd_confirm<T: ScmdTransport>(
    client: &ScmdClient<T>,
    session: &CmdSignSession,
    otp: &str,
) -> Result<Vec<u8>, SigningError> {
    // Reconstruct the pending process handle from the non-secret session state. `code`/`message`
    // are informational on `CCMovelSign`'s result and unused by `ValidateOtp`.
    let handle = ProcessHandle {
        process_id: session.process_id.clone(),
        user_id: session.user_id.clone(),
        code: String::new(),
        message: String::new(),
    };

    let mut rng = OsRng;
    let raw = client
        .confirm_otp(&mut rng, &handle, otp)
        .map_err(provider_err)?;

    // Reassemble with the session's certificate material (not the re-fetched copy), pinning the
    // attributes to exactly what was signed at initiate.
    let raw = RawSignature::new(
        raw.algorithm,
        raw.signature,
        session.signing_cert_der.clone(),
        session.chain_der.clone(),
    );
    assemble_cades_b(&raw, &session.byterange_digest, session.signing_time).map_err(cades_err)
}

fn provider_err(e: CmdError) -> SigningError {
    SigningError::Provider(e.to_string())
}

fn cades_err(e: chancela_cades::CadesError) -> SigningError {
    SigningError::Cades(e.to_string())
}
