//! Real [`Pkcs11Token`] over `cryptoki` (Autenticação.gov middleware).
//!
//! This is the only module that talks to the card. Its logic mirrors
//! [`crate::mock::MockToken`] so the branching it performs (RSA vs P-256, NULL-PIN
//! login) is proven offline; the real I/O here is exercised only by the
//! `hardware-tests` suite (see `TESTING.md`). It compiles on all platforms —
//! `pcsc`/`cryptoki` link the built-in Windows/macOS stacks and prebuilt
//! bindings (plan §1.1).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use chancela_cades::{RawSignature, SignatureAlgorithm};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;

use crate::crypto;
use crate::error::SmartcardError;
use crate::token::{CryptoToken, TokenCertificate};

/// Environment variable overriding the PKCS#11 module path (plan §2.3). Needed
/// because the Linux Flatpak middleware ships the module inside its sandbox
/// rather than at the canonical `/usr/local/lib` path.
pub const ENV_MODULE_PATH: &str = "CHANCELA_PTEID_PKCS11_MODULE";

/// The per-OS default Autenticação.gov PKCS#11 module path (plan §1.2).
#[must_use]
pub fn default_module_path() -> &'static Path {
    #[cfg(target_os = "windows")]
    {
        Path::new(r"C:\Windows\System32\pteidpkcs11.dll")
    }
    #[cfg(target_os = "macos")]
    {
        Path::new("/usr/local/lib/libpteidpkcs11.dylib")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Path::new("/usr/local/lib/libpteidpkcs11.so")
    }
}

/// Resolve the module path: the `CHANCELA_PTEID_PKCS11_MODULE` override if set
/// and non-empty, else the per-OS default. Pure over its input so it is unit
/// tested without touching the process environment.
fn resolve_module_path_from(override_value: Option<OsString>) -> PathBuf {
    match override_value {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => default_module_path().to_path_buf(),
    }
}

/// Resolve the PKCS#11 module path from the environment (see
/// [`resolve_module_path_from`]).
#[must_use]
pub fn resolve_module_path() -> PathBuf {
    resolve_module_path_from(std::env::var_os(ENV_MODULE_PATH))
}

/// Map the CKA_LABEL of a certificate object to the label of its private key,
/// e.g. `"CITIZEN SIGNATURE CERTIFICATE"` → `"CITIZEN SIGNATURE KEY"`.
fn key_label_for(cert_label: &str) -> String {
    cert_label.replace("CERTIFICATE", "KEY")
}

fn pkcs11_err(e: cryptoki::error::Error) -> SmartcardError {
    SmartcardError::Pkcs11(e.to_string())
}

/// A live handle to a Cartão de Cidadão over PKCS#11.
#[derive(Debug)]
pub struct Pkcs11Token {
    pkcs11: Pkcs11,
    slot: Slot,
}

impl Pkcs11Token {
    /// Load the middleware module, initialise it, and select the first slot that
    /// has a token (card) present.
    ///
    /// # Errors
    /// [`SmartcardError::ModuleLoad`] if the module cannot be loaded (middleware
    /// not installed), [`SmartcardError::NoCardPresent`] if no slot holds a card,
    /// or [`SmartcardError::Pkcs11`] on any other PKCS#11 failure.
    pub fn open() -> Result<Self, SmartcardError> {
        let path = resolve_module_path();
        let pkcs11 = Pkcs11::new(&path).map_err(|e| SmartcardError::ModuleLoad {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(pkcs11_err)?;

        let slot = pkcs11
            .get_slots_with_token()
            .map_err(pkcs11_err)?
            .into_iter()
            .next()
            .ok_or(SmartcardError::NoCardPresent)?;

        Ok(Self { pkcs11, slot })
    }

    fn open_session(&self) -> Result<Session, SmartcardError> {
        self.pkcs11.open_ro_session(self.slot).map_err(pkcs11_err)
    }

    /// Locate the private-key object backing `cert`: match by CKA_ID (the robust
    /// path), falling back to the mapped key label.
    fn find_key(
        session: &Session,
        cert: &TokenCertificate,
    ) -> Result<ObjectHandle, SmartcardError> {
        let cert_handle = session
            .find_objects(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::Label(cert.label.clone().into_bytes()),
            ])
            .map_err(pkcs11_err)?
            .into_iter()
            .next()
            .ok_or_else(|| SmartcardError::CertificateNotFound(cert.label.clone()))?;

        let ck_id = session
            .get_attributes(cert_handle, &[AttributeType::Id])
            .map_err(pkcs11_err)?
            .into_iter()
            .find_map(|a| match a {
                Attribute::Id(bytes) => Some(bytes),
                _ => None,
            });

        let key_template = match ck_id {
            Some(id) => vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Id(id),
            ],
            None => vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(key_label_for(&cert.label).into_bytes()),
            ],
        };

        session
            .find_objects(&key_template)
            .map_err(pkcs11_err)?
            .into_iter()
            .next()
            .ok_or_else(|| SmartcardError::KeyNotFound(cert.label.clone()))
    }
}

impl CryptoToken for Pkcs11Token {
    fn list_certificates(&self) -> Result<Vec<TokenCertificate>, SmartcardError> {
        let session = self.open_session()?;
        let handles = session
            .find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])
            .map_err(pkcs11_err)?;

        let mut certs = Vec::new();
        for handle in handles {
            let attrs = session
                .get_attributes(handle, &[AttributeType::Label, AttributeType::Value])
                .map_err(pkcs11_err)?;

            let mut label = None;
            let mut value = None;
            for attr in attrs {
                match attr {
                    Attribute::Label(bytes) => {
                        label = Some(String::from_utf8_lossy(&bytes).into_owned());
                    }
                    Attribute::Value(bytes) => value = Some(bytes),
                    _ => {}
                }
            }

            let (Some(label), Some(cert_der)) = (label, value) else {
                continue;
            };
            // Skip objects whose key algorithm we cannot sign with (e.g. an odd
            // CA cert); the CC leaf certs are RSA (v1) or P-256 (v2).
            let Ok(algorithm) = crypto::algorithm_from_cert_der(&cert_der) else {
                continue;
            };
            certs.push(TokenCertificate {
                label,
                cert_der,
                algorithm,
            });
        }
        Ok(certs)
    }

    fn sign_digest(
        &self,
        cert: &TokenCertificate,
        digest: &[u8; 32],
    ) -> Result<RawSignature, SmartcardError> {
        let session = self.open_session()?;
        let key = Self::find_key(&session, cert)?;

        // NULL-PIN login: the middleware advertises a protected authentication
        // path and owns the PIN/CAN dialog — we never build our own PIN UI
        // (plan §1.2). The signature key is CKA_ALWAYS_AUTHENTICATE, so real
        // middleware prompts per operation; context-specific re-auth for such
        // keys is tuned against hardware (see TESTING.md).
        session.login(UserType::User, None).map_err(pkcs11_err)?;

        let signature = match cert.algorithm {
            SignatureAlgorithm::RsaPkcs1Sha256 => {
                // CC v1: the card does raw RSA + PKCS#1 v1.5, so present the full
                // SHA-256 DigestInfo to CKM_RSA_PKCS.
                let digest_info = crypto::sha256_digest_info(digest);
                session
                    .sign(&Mechanism::RsaPkcs, key, &digest_info)
                    .map_err(pkcs11_err)?
            }
            SignatureAlgorithm::EcdsaP256Sha256 => {
                // CC v2: CKM_ECDSA over the bare digest returns IEEE-P1363 r‖s;
                // re-encode to DER for CMS.
                let raw = session
                    .sign(&Mechanism::Ecdsa, key, digest)
                    .map_err(pkcs11_err)?;
                crypto::ecdsa_signature_to_der(&raw)?
            }
            // `SignatureAlgorithm` is non-exhaustive; a future variant we cannot
            // drive is a clean error, not a panic.
            other => {
                return Err(SmartcardError::UnsupportedKeyAlgorithm(format!(
                    "{other:?}"
                )));
            }
        };

        Ok(RawSignature::new(
            cert.algorithm,
            signature,
            cert.cert_der.clone(),
            Vec::new(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_env_override() {
        let over = resolve_module_path_from(Some(OsString::from("/custom/pteid.so")));
        assert_eq!(over, PathBuf::from("/custom/pteid.so"));
    }

    #[test]
    fn resolve_ignores_empty_override() {
        let resolved = resolve_module_path_from(Some(OsString::new()));
        assert_eq!(resolved, default_module_path());
    }

    #[test]
    fn resolve_falls_back_to_default() {
        let resolved = resolve_module_path_from(None);
        assert_eq!(resolved, default_module_path());
    }

    #[test]
    fn key_label_maps_from_cert_label() {
        assert_eq!(
            key_label_for("CITIZEN SIGNATURE CERTIFICATE"),
            "CITIZEN SIGNATURE KEY"
        );
        assert_eq!(
            key_label_for("CITIZEN AUTHENTICATION CERTIFICATE"),
            "CITIZEN AUTHENTICATION KEY"
        );
    }
}
