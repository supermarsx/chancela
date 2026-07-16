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
use chancela_signing::{Pkcs12IdentitySelector, Pkcs12SigningSource, SoftCertificateError};
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
    self, LocalPkcs12SignRequest, LocalPkcs12SignResponse, ScapCapacityEvidenceRequest,
    SealAppearanceRequest,
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
    /// Optional SCAP-backed capacity evidence request; threaded to the delegate unchanged.
    #[serde(default, alias = "scap_evidence")]
    pub scap_capacity_evidence: Option<ScapCapacityEvidenceRequest>,
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
    /// `true` when the identity the operator's FULL selector (friendly_name + local_key_id) validated
    /// is the **same** identity the delegated upload signer would select from its reduced
    /// `friendly_name`-only selector. When `false`, delegating would sign with a different identity
    /// than the operator chose (H1) and the sign path must refuse rather than silently sign the wrong
    /// key. See [`select_stored_pkcs12_candidate`].
    identity_honored: bool,
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
    signature::require_act_signing(&state, ActId(id)).await?;

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
        scap_capacity_evidence: req.scap_capacity_evidence,
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

    let chosen = try_in_order(&candidates, |cred| {
        let input = &cred.config;
        // Offline load: decrypts the PFX + selects the identity with the operator's FULL selector
        // (friendly_name + local_key_id). This is the failover decision point — a WrongPassword /
        // malformed PFX surfaces as a terminal `SoftCertificateError` (no fail-over). It is also the
        // identity the operator actually selected.
        let selected = Pkcs12SigningSource::from_der_with_selector(
            input.pfx_der.as_slice(),
            &input.passphrase,
            &input.selector,
        )?;
        // H1 fail-safe: the delegated upload signer (`signature::sign_local_pkcs12_signature`) rebuilds
        // the selector as `friendly_name.map(by_friendly_name).unwrap_or_else(any)` — it drops any
        // `local_key_id`. Replicate that reduced selector EXACTLY and load the same PFX under it, then
        // compare identities. If a multi-identity PFX was disambiguated only by `local_key_id`, the
        // delegate's `any()` (or a non-unique friendly_name) can resolve to a DIFFERENT key, so we must
        // detect and refuse that case rather than validate identity A and sign with identity B.
        let delegate_selector = input
            .selector
            .friendly_name
            .clone()
            .map(Pkcs12IdentitySelector::by_friendly_name)
            .unwrap_or_else(Pkcs12IdentitySelector::any);
        let delegated = Pkcs12SigningSource::from_der_with_selector(
            input.pfx_der.as_slice(),
            &input.passphrase,
            &delegate_selector,
        )?;
        let identity_honored = selected.identity().local_key_id
            == delegated.identity().local_key_id
            && selected.identity().signing_certificate_der
                == delegated.identity().signing_certificate_der;
        let entry_id = match &cred.source {
            ResolvedSource::Stored { entry_id, .. } => Some(entry_id.clone()),
            ResolvedSource::Env => None,
        };
        Ok::<ChosenPkcs12Entry, SoftCertificateError>(ChosenPkcs12Entry {
            entry_id,
            friendly_name: input.selector.friendly_name.clone(),
            pkcs12_base64: B64.encode(input.pfx_der.as_slice()),
            passphrase: input.passphrase.as_str().to_owned(),
            identity_honored,
        })
    })
    .map_err(map_failover_error)?;

    // H1: refuse the ambiguous case fail-safe. The chosen entry loaded and validated one identity, but
    // the delegated sign path would honor a different one — signing here would produce evidence under
    // the wrong key. Reject with a clear, actionable 409 instead.
    if !chosen.identity_honored {
        return Err(ApiError::Conflict(format!(
            "esta entrada PKCS#12 seleciona uma identidade por local_key_id que o percurso de \
             assinatura atual não consegue honrar; atribua à entrada um friendly_name único ou use um \
             PFX de identidade única (fornecedor '{provider_id}')"
        )));
    }

    Ok(chosen)
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

    /// Store a PKCS#12 entry from raw PFX bytes and an explicit selector map (unlike
    /// [`put_pkcs12_entry`], which always synthesises a single-identity PFX + friendly_name selector).
    fn put_pkcs12_entry_raw(
        store: &ProviderCredentialStore,
        provider_id: &str,
        entry_id: &str,
        pfx: &[u8],
        stored_password: &str,
        selectors: EntrySelectors,
    ) {
        let pfx_b64 = B64.encode(pfx);
        store
            .put_entry(
                CredentialMode::LocalPkcs12,
                provider_id,
                entry_id,
                Some(EntryMetadata {
                    label: format!("entry-{entry_id}"),
                    priority: 0,
                    enabled: true,
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

    /// The PKCS#12 BMPString encoding of `password` (matches p12's internal `bmp_string`), needed to
    /// (re)encrypt the merged cert bags and recompute the MAC of a hand-assembled PFX.
    fn bmp_password(password: &str) -> Vec<u8> {
        let utf16: Vec<u16> = password.encode_utf16().collect();
        let mut bytes = Vec::with_capacity(utf16.len() * 2 + 2);
        for code_unit in utf16 {
            bytes.push((code_unit / 256) as u8);
            bytes.push((code_unit % 256) as u8);
        }
        bytes.push(0);
        bytes.push(0);
        bytes
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    /// Read the private-key bag's `localKeyId` out of a (single-identity) PFX.
    fn key_local_key_id(pfx: &[u8], password: &str) -> Vec<u8> {
        p12::PFX::parse(pfx)
            .expect("parse pfx")
            .bags(password)
            .expect("read bags")
            .into_iter()
            .find_map(|bag| match &bag.bag {
                p12::SafeBagKind::Pkcs8ShroudedKeyBag(_) => bag.local_key_id(),
                _ => None,
            })
            .expect("key bag local_key_id")
    }

    /// Build a genuine two-identity PFX by merging the key + cert bags of two independent
    /// single-identity PFXes. Each identity keeps its own distinct `localKeyId` (sha1 of its cert),
    /// friendly name, private key, and certificate. The first identity's key bag is placed first, so a
    /// delegate that reduces the selector to `any()` (first key bag) resolves to the FIRST identity.
    /// Returns `(pfx_der, first_local_key_id, second_local_key_id)`.
    fn two_identity_pfx(name_a: &str, name_b: &str, password: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut key_bags: Vec<p12::SafeBag> = Vec::new();
        let mut cert_bags: Vec<p12::SafeBag> = Vec::new();
        let mut local_key_ids: Vec<Vec<u8>> = Vec::new();
        for name in [name_a, name_b] {
            let single = rsa_pfx(name, password);
            let pfx = p12::PFX::parse(&single).expect("parse single-identity pfx");
            for bag in pfx.bags(password).expect("read single-identity bags") {
                match &bag.bag {
                    p12::SafeBagKind::Pkcs8ShroudedKeyBag(_) => {
                        if let Some(id) = bag.local_key_id() {
                            local_key_ids.push(id);
                        }
                        key_bags.push(bag);
                    }
                    p12::SafeBagKind::CertBag(_) => cert_bags.push(bag),
                    _ => {}
                }
            }
        }
        assert_eq!(local_key_ids.len(), 2, "expected two distinct key bags");
        assert_ne!(
            local_key_ids[0], local_key_ids[1],
            "the two identities must have distinct local key ids"
        );

        let bmp = bmp_password(password);
        let encrypted_certs =
            p12::EncryptedData::from_safe_bags(&cert_bags, &bmp).expect("encrypt merged cert bags");
        // `p12` 0.6.3 (the latest release) still uses yasna 0.5 internally. Obtain its complete
        // SafeContents DER through the public encrypt/decrypt helpers, then embed complete DER
        // objects with current yasna. This avoids coupling the fixture to p12's private writer type.
        let key_safe_contents = p12::EncryptedData::from_safe_bags(&key_bags, &bmp)
            .and_then(|encrypted| encrypted.data(&bmp))
            .expect("encode merged key bags");
        let content_infos = [
            p12::ContentInfo::EncryptedData(encrypted_certs).to_der(),
            p12::ContentInfo::Data(key_safe_contents).to_der(),
        ];
        let contents = yasna::construct_der(|w| {
            w.write_sequence_of(|w| {
                for content_info in &content_infos {
                    w.next().write_der(content_info);
                }
            });
        });
        let mac_data = p12::MacData::new(&contents, &bmp);
        let pfx = p12::PFX {
            version: 3,
            auth_safe: p12::ContentInfo::Data(contents),
            mac_data: Some(mac_data),
        };
        (
            pfx.to_der(),
            local_key_ids[0].clone(),
            local_key_ids[1].clone(),
        )
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

    // --- H1: wrong-identity fail-safe ------------------------------------------------------

    #[test]
    fn stored_sign_rejects_local_key_id_selection_the_delegate_cannot_honor() {
        // A two-identity PFX (no distinguishing friendly_name) disambiguated ONLY by local_key_id: the
        // full selector validates the SECOND identity, but the delegated sign path drops local_key_id
        // and its `any()` resolves to the FIRST identity. This must be refused fail-safe, not signed.
        let dir = TempDir::new("h1-reject");
        let store = store(dir.path());
        let (pfx, _first, second) =
            two_identity_pfx("Amélia Marques", "Amélia Marques", PFX_PASSWORD);
        let mut selectors = EntrySelectors::new();
        selectors.insert(
            crate::credential_resolve::SELECTOR_PKCS12_LOCAL_KEY_ID_HEX.to_owned(),
            hex_encode(&second),
        );
        put_pkcs12_entry_raw(&store, "amelia", "multi", &pfx, PFX_PASSWORD, selectors);

        let err = select_stored_pkcs12_candidate(&store, "amelia", None).expect_err(
            "an ambiguous local_key_id selection must be refused, not silently mis-signed",
        );
        match err {
            ApiError::Conflict(msg) => assert!(
                msg.contains("local_key_id"),
                "expected the H1 wrong-identity refusal, got: {msg}"
            ),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn stored_sign_allows_unique_friendly_name_in_multi_identity_pfx() {
        // Two identities with DISTINCT friendly names, selected by the unique friendly_name: the full
        // selector and the delegate's `by_friendly_name` resolve to the same identity, so it signs.
        let dir = TempDir::new("h1-friendly-ok");
        let store = store(dir.path());
        let (pfx, _first, _second) = two_identity_pfx("Amélia A", "Amélia B", PFX_PASSWORD);
        let mut selectors = EntrySelectors::new();
        selectors.insert(
            crate::credential_resolve::SELECTOR_PKCS12_FRIENDLY_NAME.to_owned(),
            "Amélia B".to_owned(),
        );
        put_pkcs12_entry_raw(&store, "amelia", "multi", &pfx, PFX_PASSWORD, selectors);

        let chosen = select_stored_pkcs12_candidate(&store, "amelia", None)
            .expect("a unique friendly_name in a multi-identity PFX must still sign");
        assert_eq!(chosen.friendly_name.as_deref(), Some("Amélia B"));
        assert!(chosen.identity_honored);
    }

    #[test]
    fn stored_sign_allows_local_key_id_selection_on_single_identity_pfx() {
        // A single-identity PFX selected by local_key_id: the delegate's `any()` resolves to the same
        // (only) identity, so signing is honored.
        let dir = TempDir::new("h1-single-ok");
        let store = store(dir.path());
        let pfx = rsa_pfx("Amélia Marques", PFX_PASSWORD);
        let lkid = key_local_key_id(&pfx, PFX_PASSWORD);
        let mut selectors = EntrySelectors::new();
        selectors.insert(
            crate::credential_resolve::SELECTOR_PKCS12_LOCAL_KEY_ID_HEX.to_owned(),
            hex_encode(&lkid),
        );
        put_pkcs12_entry_raw(&store, "amelia", "single", &pfx, PFX_PASSWORD, selectors);

        let chosen = select_stored_pkcs12_candidate(&store, "amelia", None)
            .expect("a single-identity PFX selected by local_key_id must still sign");
        assert_eq!(chosen.entry_id.as_deref(), Some("single"));
        assert!(chosen.identity_honored);
    }
}
