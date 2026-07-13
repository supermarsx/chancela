//! Stored-PKCS#12 act signing with multi-key priority + failover (wp13 Phase C.2).
//!
//! This is the "configurable PKCS#12" deliverable: an operator stores one or more PFX entries under
//! [`CredentialMode::LocalPkcs12`] (a `provider_id` identity label) through the Phase B write API
//! ([`crate::provider_credentials_write`]), then signs a sealed act with the **highest-priority
//! enabled** stored entry — falling through to the next entry when a higher one is unusable.
//!
//! ## How this reuses the existing local-PKCS#12 signer
//!
//! The per-request-upload endpoint [`crate::signature::sign_local_pkcs12_signature`] already owns the
//! full local-PKCS#12 pipeline (decode PFX → [`Pkcs12SigningSource`] → PAdES sign → finalize →
//! persist → sanitized audit → response). That handler's signing/persist core is not cleanly
//! factorable out of the very large (and concurrently-owned) `signature.rs` without heavy edits, so
//! rather than refactor it this module is a **thin wrapper**:
//!
//! 1. **Select + fail over** ([`select_stored_pkcs12_candidate`]) — resolve the provider's enabled
//!    stored entries in priority order via [`resolve_candidates`] (env fallback is `None`: PKCS#12 is
//!    a stored-only mode), then [`try_in_order`] picks the first entry whose PFX actually
//!    loads/decrypts offline. Because every [`SoftCertificateError`] is terminal (a wrong passphrase
//!    must never fail over onto — and burn — another stored identity), a bad higher-priority entry
//!    stops the walk immediately; a *disabled* higher entry is skipped by resolution so the next
//!    enabled one is used.
//! 2. **Sign** — hand the chosen entry's decoded PFX + passphrase + identity selector to the existing
//!    [`sign_local_pkcs12_signature`] so the produced signature is **byte-for-byte the same
//!    evidentiary artifact** (same family/level, same honest labelling, same sanitized audit) as the
//!    upload path. No PFX bytes, passphrase, or private key are logged or persisted; the audit the
//!    delegated handler writes already records `pkcs12_persisted:false` / `passphrase_persisted:false`.
//!
//! Gating is the same permission the upload path uses ([`Permission::SigningPerform`]).

use axum::Json;
use axum::extract::{Path, State};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_authz::Permission;
use chancela_core::ActId;
use chancela_signing::{Pkcs12SigningSource, SoftCertificateError};
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_act};
use crate::credential_resolve::{
    FailoverError, Pkcs12AssembleError, ResolveError, ResolvedSource, assemble_pkcs12_input,
    resolve_candidates, try_in_order,
};
use crate::error::ApiError;
use crate::secretstore_persist::{CredentialMode, ProviderCredentialStore};
use crate::signature::{
    self, LocalPkcs12SignRequest, LocalPkcs12SignResponse, SealAppearanceRequest,
};

/// JSON envelope accepted by `POST /v1/acts/{id}/signature/local/pkcs12/sign-stored`.
///
/// Unlike the upload endpoint, this body carries **no secret material** — only the non-secret
/// `provider_id` (the operator identity label the PFX was stored under) and an optional `entry_id`
/// override. The PFX bytes and passphrase are read from the encrypted store, never from the request.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPkcs12SignRequest {
    /// The stored PKCS#12 identity label (`CredentialMode::LocalPkcs12` `provider_id`) to sign with.
    pub provider_id: String,
    /// Optional: pin the signature to one specific stored entry id instead of taking the
    /// highest-priority enabled entry. The entry must exist and be enabled.
    #[serde(default)]
    pub entry_id: Option<String>,
    /// The capacity in which the signer acts (optional, informational; threaded to the delegate).
    #[serde(default)]
    pub capacity: Option<String>,
    /// Actor override for attribution.
    #[serde(default)]
    pub actor: Option<String>,
    /// Optional visible-seal appearance, passed through to the underlying signer.
    #[serde(default)]
    pub seal: Option<SealAppearanceRequest>,
}

/// The stored entry chosen for signing, resolved from the priority-ordered candidate list. Holds the
/// decoded PFX/passphrase only long enough to build the delegated [`LocalPkcs12SignRequest`]; nothing
/// here is logged or persisted.
struct ChosenPkcs12Entry {
    /// The stored entry id that was selected (for diagnostics/tests).
    entry_id: Option<String>,
    /// The identity selector's friendly name, if any (threaded to the delegated signer).
    friendly_name: Option<String>,
    /// base64(PFX DER) — a transient copy handed to the existing upload signer, which already treats
    /// it as write-only, non-persisted material.
    pkcs12_base64: String,
    /// The PKCS#12 passphrase — transient, handed to the existing signer, never logged/persisted.
    passphrase: String,
}

impl std::fmt::Debug for ChosenPkcs12Entry {
    /// Redacts the PFX bytes and passphrase so a chosen-entry value can never leak secret material
    /// through a log line, panic, or test assertion message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChosenPkcs12Entry")
            .field("entry_id", &self.entry_id)
            .field("friendly_name", &self.friendly_name)
            .field("pkcs12_base64", &"<redacted>")
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

/// `POST /v1/acts/{id}/signature/local/pkcs12/sign-stored` — sign a sealed act with a **stored**
/// PKCS#12 software certificate, selected by priority + failover from the provider's stored entries.
///
/// Gated by [`Permission::SigningPerform`] (the same permission the upload path uses). The actual
/// signing/persist/audit is delegated to [`sign_local_pkcs12_signature`] so the produced artifact is
/// identical to the upload path — only the credential *source* differs (encrypted store vs request).
pub async fn sign_local_pkcs12_stored_signature(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<StoredPkcs12SignRequest>,
) -> Result<Json<LocalPkcs12SignResponse>, ApiError> {
    // RBAC first, before any store access, for a clean 403.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;

    // Cheap parity with the upload path: local software-certificate signing is a desktop-only flow.
    if !state.local_signing {
        return Err(ApiError::Conflict(
            "a assinatura local com certificado PKCS#12 só está disponível na aplicação de secretária"
                .to_owned(),
        ));
    }

    let provider_id = req.provider_id.trim();
    if provider_id.is_empty() {
        return Err(ApiError::Unprocessable(
            "provider_id é obrigatório para a assinatura com PKCS#12 armazenado".to_owned(),
        ));
    }

    let chosen = select_stored_pkcs12_candidate(
        &state.provider_credentials,
        provider_id,
        req.entry_id.as_deref(),
    )?;

    // Delegate to the existing upload signer so persistence/finalization/audit/response are identical.
    // The chosen entry's decoded PFX + passphrase are the only secret material and are dropped with
    // `delegated` after the call returns.
    let delegated = LocalPkcs12SignRequest {
        pkcs12_base64: chosen.pkcs12_base64,
        passphrase: chosen.passphrase,
        friendly_name: chosen.friendly_name,
        capacity: req.capacity,
        actor: req.actor,
        seal: req.seal,
    };

    signature::sign_local_pkcs12_signature(State(state), Path(id), actor, attestor, Json(delegated))
        .await
}

/// Resolve the priority-ordered stored candidate list for `(LocalPkcs12, provider_id)` and pick the
/// first entry whose PFX loads/decrypts (offline). PKCS#12 has **no env fallback** — it is a
/// stored-only mode — so an empty candidate list is a definitive "nothing to sign with".
///
/// Failover policy (from [`try_in_order`] + [`SoftCertificateError`]'s classification): a wrong
/// passphrase / malformed PFX is *terminal* and stops the walk (never failing over onto another
/// stored identity), while a *disabled* higher-priority entry is skipped during resolution so the
/// next enabled entry is used. Kept separate from the HTTP handler so the selection + failover logic
/// is unit-testable without a sealed act.
fn select_stored_pkcs12_candidate(
    store: &ProviderCredentialStore,
    provider_id: &str,
    entry_id_override: Option<&str>,
) -> Result<ChosenPkcs12Entry, ApiError> {
    let mut candidates = resolve_candidates(
        store,
        CredentialMode::LocalPkcs12,
        provider_id,
        assemble_pkcs12_input,
        // Stored-only mode: no environment fallback for a private signing key.
        || Ok::<_, Pkcs12AssembleError>(None),
    )
    .map_err(map_resolve_error)?;

    // Optional pin to one specific stored entry id (must exist AND be enabled → present as a
    // resolved candidate).
    if let Some(wanted) = entry_id_override {
        candidates.retain(
            |c| matches!(&c.source, ResolvedSource::Stored { entry_id, .. } if entry_id == wanted),
        );
        if candidates.is_empty() {
            return Err(ApiError::Conflict(format!(
                "a entrada PKCS#12 '{wanted}' não existe ou está desativada para o fornecedor '{provider_id}'"
            )));
        }
    }

    if candidates.is_empty() {
        // Nothing stored (or every entry disabled) and no env fallback for PKCS#12.
        return Err(ApiError::Conflict(format!(
            "não há nenhuma credencial PKCS#12 armazenada e ativa para o fornecedor '{provider_id}'; \
             o modo PKCS#12 é exclusivamente armazenado (sem fallback por variável de ambiente)"
        )));
    }

    try_in_order(&candidates, |cred| {
        let input = &cred.config;
        // Offline load: decrypts the PFX + selects the identity. This is the failover decision point —
        // a WrongPassword/malformed PFX surfaces as a terminal `SoftCertificateError` (no fail-over).
        Pkcs12SigningSource::from_der_with_selector(
            input.pfx_der.as_slice(),
            &input.passphrase,
            &input.selector,
        )?;
        let entry_id = match &cred.source {
            ResolvedSource::Stored { entry_id, .. } => Some(entry_id.clone()),
            ResolvedSource::Env => None,
        };
        Ok::<ChosenPkcs12Entry, SoftCertificateError>(ChosenPkcs12Entry {
            entry_id,
            friendly_name: input.selector.friendly_name.clone(),
            pkcs12_base64: B64.encode(input.pfx_der.as_slice()),
            passphrase: input.passphrase.as_str().to_owned(),
        })
    })
    .map_err(map_failover_error)
}

/// Map a candidate-resolution failure onto an [`ApiError`]. A malformed stored entry is a 422; a
/// store/config failure (no key source, corrupt sidecar, …) is a 409 the operator must repair.
fn map_resolve_error(err: ResolveError<Pkcs12AssembleError>) -> ApiError {
    match err {
        ResolveError::Assemble(e) => ApiError::Unprocessable(format!(
            "a credencial PKCS#12 armazenada está malformada: {e}"
        )),
        ResolveError::Store(e) => ApiError::Conflict(format!(
            "não foi possível ler as credenciais PKCS#12 armazenadas: {e}"
        )),
    }
}

/// Map a failover exhaustion onto an [`ApiError`]. For local PKCS#12 every failure is terminal, so
/// this almost always renders a terminal `SoftCertificateError` (e.g. a wrong stored passphrase).
fn map_failover_error(err: FailoverError<SoftCertificateError>) -> ApiError {
    match err {
        FailoverError::Terminal(e) | FailoverError::Exhausted(e) => match e {
            SoftCertificateError::WrongPassword => ApiError::Unprocessable(
                "a frase-passe da credencial PKCS#12 armazenada está incorreta".to_owned(),
            ),
            other => ApiError::Unprocessable(format!(
                "não foi possível abrir a credencial PKCS#12 armazenada: {other}"
            )),
        },
        FailoverError::NoCandidates => ApiError::Conflict(
            "não há nenhuma credencial PKCS#12 armazenada e ativa para este fornecedor".to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

    use der::Encode;
    use der::asn1::{Any, BitString, ObjectIdentifier};
    use p12::PFX;
    use rsa::pkcs8::EncodePrivateKey;
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::certificate::{Certificate, TbsCertificate, Version};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;
    use zeroize::Zeroizing;

    use super::*;
    use crate::secretstore_persist::{
        CredentialFieldSet, EntryMetadata, EntrySelectors, Pkcs12CredentialFields,
    };

    // --- temp store scaffolding ------------------------------------------------------------

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    const TEST_DB_KEY: &[u8] = b"wp13-phase-c2-stored-pkcs12-test-key-01";

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(name: &str) -> Self {
            let seq = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "chancela-stored-pkcs12-{name}-{}-{seq}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn store(dir: &Path) -> ProviderCredentialStore {
        ProviderCredentialStore::load_with_db_key(dir, TEST_DB_KEY, false)
    }

    const OID_SHA256_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    const PFX_PASSWORD: &str = "correct horse battery staple";

    /// Build a self-signed RSA PFX (DER) with the given friendly name and passphrase, mirroring the
    /// in-process fixture pattern in `chancela-signing/tests/soft_cert_pkcs12.rs` (no checked-in keys,
    /// no network, no OS store).
    fn rsa_pfx(friendly_name: &str, password: &str) -> Vec<u8> {
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
        let public = rsa::RsaPublicKey::from(&key);
        let spki = SubjectPublicKeyInfoOwned::from_key(public).expect("rsa spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        };
        let name = Name::from_str("CN=Amélia Marques").expect("name");
        let validity =
            Validity::from_now(StdDuration::from_secs(365 * 24 * 3600)).expect("validity");
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[1]).expect("serial"),
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
            signature: BitString::from_bytes(&[0u8; 64]).expect("bitstring"),
        };
        let cert_der = cert.to_der().expect("cert der");
        let key_der = key.to_pkcs8_der().expect("rsa pkcs8");
        PFX::new(&cert_der, key_der.as_bytes(), None, password, friendly_name)
            .expect("pfx")
            .to_der()
    }

    fn put_pkcs12_entry(
        store: &ProviderCredentialStore,
        provider_id: &str,
        entry_id: &str,
        priority: i32,
        enabled: bool,
        friendly_name: &str,
        stored_password: &str,
    ) {
        let pfx = rsa_pfx(friendly_name, PFX_PASSWORD);
        let pfx_b64 = B64.encode(&pfx);
        let mut selectors = EntrySelectors::new();
        selectors.insert(
            crate::credential_resolve::SELECTOR_PKCS12_FRIENDLY_NAME.to_owned(),
            friendly_name.to_owned(),
        );
        store
            .put_entry(
                CredentialMode::LocalPkcs12,
                provider_id,
                entry_id,
                Some(EntryMetadata {
                    label: format!("entry-{entry_id}"),
                    priority,
                    enabled,
                    endpoint: None,
                    selectors,
                }),
                Pkcs12CredentialFields {
                    pfx_der_b64: Some(Zeroizing::new(pfx_b64)),
                    passphrase: Some(Zeroizing::new(stored_password.to_owned())),
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put pkcs12 entry");
    }

    // --- tests -----------------------------------------------------------------------------

    #[test]
    fn highest_priority_enabled_entry_is_selected() {
        let dir = TempDir::new("priority");
        let store = store(dir.path());
        // Insert out of priority order; both correct passphrases.
        put_pkcs12_entry(
            &store,
            "amelia",
            "secondary",
            5,
            true,
            "secondary",
            PFX_PASSWORD,
        );
        put_pkcs12_entry(
            &store,
            "amelia",
            "primary",
            1,
            true,
            "primary",
            PFX_PASSWORD,
        );

        let chosen =
            select_stored_pkcs12_candidate(&store, "amelia", None).expect("select candidate");
        assert_eq!(chosen.entry_id.as_deref(), Some("primary"));
        assert_eq!(chosen.friendly_name.as_deref(), Some("primary"));
        assert!(!chosen.pkcs12_base64.is_empty());
    }

    #[test]
    fn disabling_the_top_entry_falls_over_to_the_next() {
        let dir = TempDir::new("failover");
        let store = store(dir.path());
        // Priority-0 primary is DISABLED; priority-1 secondary is enabled.
        put_pkcs12_entry(
            &store,
            "amelia",
            "primary",
            0,
            false,
            "primary",
            PFX_PASSWORD,
        );
        put_pkcs12_entry(
            &store,
            "amelia",
            "secondary",
            1,
            true,
            "secondary",
            PFX_PASSWORD,
        );

        let chosen =
            select_stored_pkcs12_candidate(&store, "amelia", None).expect("select candidate");
        assert_eq!(
            chosen.entry_id.as_deref(),
            Some("secondary"),
            "a disabled higher-priority entry must be skipped in favour of the next enabled one"
        );
    }

    #[test]
    fn wrong_stored_passphrase_is_terminal_and_does_not_fail_over() {
        let dir = TempDir::new("terminal");
        let store = store(dir.path());
        // Highest-priority entry has a WRONG stored passphrase; a valid lower-priority entry follows.
        put_pkcs12_entry(
            &store,
            "amelia",
            "primary",
            0,
            true,
            "primary",
            "not-the-password",
        );
        put_pkcs12_entry(
            &store,
            "amelia",
            "secondary",
            1,
            true,
            "secondary",
            PFX_PASSWORD,
        );

        let err = select_stored_pkcs12_candidate(&store, "amelia", None)
            .expect_err("wrong passphrase must be terminal");
        match err {
            ApiError::Unprocessable(msg) => assert!(
                msg.contains("frase-passe"),
                "expected a wrong-passphrase message, got: {msg}"
            ),
            other => panic!("expected Unprocessable, got {other:?}"),
        }
        // The valid `secondary` entry must NOT have been reached — a terminal error on a higher key
        // never fails over (this is the PIN/passphrase-burn guard). Verified by the terminal error
        // above surfacing rather than a successful selection of `secondary`.
    }

    #[test]
    fn no_stored_entry_is_a_clear_conflict_with_no_env_fallback() {
        let dir = TempDir::new("empty");
        let store = store(dir.path());

        let err = select_stored_pkcs12_candidate(&store, "unconfigured", None)
            .expect_err("no stored entry must fail closed");
        match err {
            ApiError::Conflict(msg) => assert!(
                msg.contains("exclusivamente armazenado"),
                "expected the stored-only (no env fallback) message, got: {msg}"
            ),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn all_disabled_entries_yield_a_conflict() {
        let dir = TempDir::new("all-disabled");
        let store = store(dir.path());
        put_pkcs12_entry(
            &store,
            "amelia",
            "primary",
            0,
            false,
            "primary",
            PFX_PASSWORD,
        );

        let err = select_stored_pkcs12_candidate(&store, "amelia", None)
            .expect_err("all-disabled must fail closed (env is never consulted for PKCS#12)");
        assert!(matches!(err, ApiError::Conflict(_)));
    }

    #[test]
    fn entry_id_override_pins_a_specific_entry() {
        let dir = TempDir::new("override");
        let store = store(dir.path());
        put_pkcs12_entry(
            &store,
            "amelia",
            "primary",
            0,
            true,
            "primary",
            PFX_PASSWORD,
        );
        put_pkcs12_entry(
            &store,
            "amelia",
            "secondary",
            1,
            true,
            "secondary",
            PFX_PASSWORD,
        );

        let chosen = select_stored_pkcs12_candidate(&store, "amelia", Some("secondary"))
            .expect("override selects the named entry");
        assert_eq!(chosen.entry_id.as_deref(), Some("secondary"));
    }

    #[test]
    fn entry_id_override_for_a_disabled_entry_is_rejected() {
        let dir = TempDir::new("override-disabled");
        let store = store(dir.path());
        put_pkcs12_entry(
            &store,
            "amelia",
            "primary",
            0,
            true,
            "primary",
            PFX_PASSWORD,
        );
        put_pkcs12_entry(
            &store,
            "amelia",
            "disabled",
            1,
            false,
            "disabled",
            PFX_PASSWORD,
        );

        let err = select_stored_pkcs12_candidate(&store, "amelia", Some("disabled"))
            .expect_err("pinning a disabled entry must fail");
        match err {
            ApiError::Conflict(msg) => {
                assert!(msg.contains("desativada") || msg.contains("não existe"))
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }
}
