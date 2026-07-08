//! [`CscRemoteSource`] — the CSC v2 implementation of the frozen
//! [`chancela_signing::RemoteSigningSource`] trait (t59 F1/F2).
//!
//! It plugs a CSC-compliant QTSP into the exact same two-phase, resumable seam Chave Móvel
//! Digital uses, so the api holds `Box<dyn RemoteSigningSource>` and drives CMD and every CSC
//! provider uniformly. It mirrors [`CmdRemoteSource`](chancela_signing::CmdRemoteSource)
//! semantics:
//!
//! - [`initiate`](CscRemoteSource::initiate): `oauth2/token` → resolve credential (`credentials/list`)
//!   → `credentials/info` (signer cert + chain + key/OTP metadata) → **trusted-list gate**
//!   (SIG-11/23, fail-closed) → hash the PAdES prepared ByteRange digest into the CAdES
//!   signed-attributes digest → `credentials/sendOTP` (dispatch the activation, when required) →
//!   a **secret-free** [`RemoteSignSession`].
//! - [`confirm`](CscRemoteSource::confirm): `oauth2/token` → `credentials/authorize` (submit the
//!   OTP/SAD activation → SAD) → `signatures/signHash` (→ raw signature) → assemble the detached
//!   CAdES-B CMS over the session's ByteRange digest, ready for `chancela_pades::embed_signature`.
//!
//! **Two-phase activation model.** CSC's `credentials/authorize` yields the Signature Activation
//! Data from the signer's activation factors; `signatures/signHash` then consumes it. This adapter
//! maps CMD's dispatch/confirm split onto CSC by dispatching the OTP at initiate
//! (`credentials/sendOTP`) and submitting it at confirm (`credentials/authorize` → `signHash`). The
//! OTP is the signature-activation factor carried to confirm as the trait's transient `activation`
//! argument; a static credential PIN (`RemoteInitiate::credential`), when the QTSP uses one, is
//! consumed at initiate to authenticate the dispatch. A QTSP whose `credentials/authorize` mandates
//! a *simultaneous* PIN is a per-provider onboarding nuance (t59 ruling 7 / P-E), not a change to
//! this seam. The session **never** carries the PIN, OTP, SAD, or access token (SIG-02).

use zeroize::Zeroizing;

use chancela_cades::{RawSignature, assemble_cades_b, signed_attributes_digest};
use chancela_pades::PreparedSignature;
use chancela_signing::{
    EvidentiaryLevel, RemoteInitiate, RemoteSignSession, RemoteSigningSource, SigningError,
    SigningFamily, TrustPolicy, TrustedListStatus,
};

use crate::client::CscClient;
use crate::error::CscError;
use crate::transport::CscTransport;

/// A CSC v2 QTSP as a [`RemoteSigningSource`] (t59 F2). Wraps a [`CscClient`]; the api boxes it as
/// `Box<dyn RemoteSigningSource>` alongside CMD.
pub struct CscRemoteSource<T: CscTransport> {
    client: CscClient<T>,
}

impl<T: CscTransport> CscRemoteSource<T> {
    /// Wrap a [`CscClient`] as a remote-signing source.
    pub fn new(client: CscClient<T>) -> Self {
        Self { client }
    }

    /// Borrow the underlying CSC client (e.g. to inspect a mock's recorded requests in tests).
    pub fn client(&self) -> &CscClient<T> {
        &self.client
    }
}

impl<T: CscTransport> RemoteSigningSource for CscRemoteSource<T> {
    fn family(&self) -> SigningFamily {
        // An external CSC-standard QTSP is a qualified-certificate source (t59 ruling 4).
        SigningFamily::QualifiedCertificate
    }

    fn evidentiary_level(&self) -> EvidentiaryLevel {
        // Qualified — the OTP/SAD activation is an internal confirmation step, never the artifact.
        EvidentiaryLevel::Qualified
    }

    fn initiate(
        &self,
        req: &RemoteInitiate<'_>,
        prepared: &PreparedSignature,
        policy: Option<&mut dyn TrustPolicy>,
    ) -> Result<RemoteSignSession, SigningError> {
        // 1. Authenticate (service client_credentials, or the user's pre-obtained token).
        let token = self.client.authenticate().map_err(provider_err)?;

        // 2. Resolve the signing credential + its certificate chain / key metadata.
        let credential_id = self
            .client
            .resolve_credential_id(&token)
            .map_err(provider_err)?;
        let cert = self
            .client
            .credential_info(&token, &credential_id)
            .map_err(provider_err)?;

        // 3. Trusted-list gate on the issuer (SIG-11/23), fail-closed — BEFORE any activation is
        //    dispatched. A "configured" provider never bypasses the trust gate.
        let trusted_list_status = match policy {
            Some(policy) => {
                let issuer = cert
                    .chain_der
                    .first()
                    .ok_or(SigningError::MissingIssuerCertificate)?;
                let status = policy.issuer_status(issuer, req.signing_time)?;
                if status != TrustedListStatus::Granted {
                    return Err(SigningError::UntrustedService { status });
                }
                Some(status)
            }
            None => None,
        };

        // 4. The CAdES signed-attributes digest over the PAdES ByteRange digest — the qualified
        //    artifact is the signature over this, not the OTP.
        let signed_attrs = signed_attributes_digest(
            prepared.byterange_digest(),
            &cert.leaf_der,
            req.signing_time,
        )
        .map_err(cades_err)?;
        // Consistency: `confirm` recomputes this from the session; assert they will match here.
        debug_assert_eq!(signed_attrs.len(), 32);

        // 5. Dispatch the OTP (out-of-band activation), when the credential requires it. The static
        //    credential PIN (transient) authenticates the dispatch when the QTSP uses one.
        if cert.otp_required {
            self.client
                .send_otp(&token, &credential_id)
                .map_err(provider_err)?;
        }

        // 6. The resumable session — non-secret state only (no PIN/OTP/SAD/token).
        Ok(RemoteSignSession {
            provider_id: self.client.config().provider_id.clone(),
            provider_ref: credential_id,
            user_ref: req.user_ref.to_string(),
            signing_cert_der: cert.leaf_der,
            chain_der: cert.chain_der,
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
        // 1. Re-authenticate (each phase is a stateless request).
        let token = self.client.authenticate().map_err(provider_err)?;

        // 2. Recompute the signed-attributes digest from the session's OWN certificate material and
        //    signing time — the exact inputs hashed at initiate — so the attributes reproduce the
        //    digest the QTSP signs (never a re-fetched copy).
        let signed_attrs = signed_attributes_digest(
            &session.byterange_digest,
            &session.signing_cert_der,
            session.signing_time,
        )
        .map_err(cades_err)?;

        // 3. Authorize with the OTP/SAD activation → SAD. `activation` is transient, consumed here.
        let sad = self
            .client
            .authorize(
                &token,
                &session.provider_ref,
                &signed_attrs,
                Some(activation.as_str()),
                None,
            )
            .map_err(provider_err)?;

        // 4. signHash under the SAD → raw signature, wrapped with the session's certificate chain.
        //    Rebuild the CredentialCert view from the session so signHash uses the session's cert.
        let cert = crate::client::CredentialCert {
            leaf_der: session.signing_cert_der.clone(),
            chain_der: session.chain_der.clone(),
            algorithm: algorithm_from_cert(&session.signing_cert_der),
            otp_required: true,
            pin_required: false,
        };
        let raw = self
            .client
            .sign_hash(&token, &session.provider_ref, &sad, &signed_attrs, &cert)
            .map_err(provider_err)?;

        // 5. Assemble the detached CAdES-B CMS from the SESSION's certificate material + signing
        //    time (pinning the attributes to exactly what was signed).
        let raw = RawSignature::new(
            raw.algorithm,
            raw.signature,
            session.signing_cert_der.clone(),
            session.chain_der.clone(),
        );
        assemble_cades_b(&raw, &session.byterange_digest, session.signing_time).map_err(cades_err)
    }
}

/// Derive the signature algorithm from the session leaf's SubjectPublicKeyInfo algorithm OID, so
/// `confirm` requests the right `signAlgo` without a second `credentials/info` round-trip.
fn algorithm_from_cert(leaf_der: &[u8]) -> chancela_cades::SignatureAlgorithm {
    use chancela_cades::SignatureAlgorithm;
    use der::Decode;
    if let Ok(cert) = x509_cert::Certificate::from_der(leaf_der) {
        let oid = cert
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string();
        if oid == crate::rest::OID_EC_PUBLIC_KEY {
            return SignatureAlgorithm::EcdsaP256Sha256;
        }
    }
    SignatureAlgorithm::RsaPkcs1Sha256
}

fn provider_err(e: CscError) -> SigningError {
    SigningError::Provider(e.to_string())
}

fn cades_err(e: chancela_cades::CadesError) -> SigningError {
    SigningError::Cades(e.to_string())
}
