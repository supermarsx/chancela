//! Software-certificate signing from PKCS#12/PFX material.
//!
//! This module is deliberately bounded: it loads one software private key and its X.509
//! certificate chain from caller-supplied PKCS#12 bytes, keeps the private key only in process
//! memory, and implements [`SignerProvider`] so the existing CAdES/PAdES pipeline can use it.
//! It does **not** claim a qualified signature by itself, perform SCAP/attribute validation, or
//! consult OS certificate stores. Callers that need qualified status must still run the issuer
//! through a trusted-list policy above this provider.

use core::fmt;

use p256::ecdsa::signature::hazmat::PrehashSigner;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, ObjectIdentifier, PrivateKeyInfo};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};
use zeroize::Zeroizing;

use chancela_cades::{RawSignature, SignatureAlgorithm};

use crate::provider::SignerProvider;
use crate::{EvidentiaryLevel, SigningError, SigningFamily};

const RSA_ENCRYPTION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Typed failures for PKCS#12 software-certificate loading/signing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SoftCertificateError {
    /// The password failed the PKCS#12 MAC/decryption gate.
    #[error("PKCS#12 password is incorrect")]
    WrongPassword,
    /// No decryptable private-key bag was present.
    #[error("PKCS#12 material does not contain a private key")]
    MissingPrivateKey,
    /// The selected key is not one of the algorithms this signing stack can emit.
    #[error("PKCS#12 private key algorithm is not supported{algorithm}")]
    UnsupportedKeyAlgorithm {
        /// Human-readable algorithm OID context when it could be parsed.
        algorithm: AlgorithmLabel,
    },
    /// No X.509 certificate bag was present for the selected identity.
    #[error("PKCS#12 material does not contain a certificate chain")]
    EmptyCertificateChain,
    /// The PFX, private key, or certificate bytes were malformed.
    #[error("malformed PKCS#12 input: {0}")]
    MalformedInput(String),
}

/// Human-readable key-algorithm context for [`SoftCertificateError::UnsupportedKeyAlgorithm`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmLabel(Option<String>);

impl AlgorithmLabel {
    fn oid(oid: ObjectIdentifier, parameters: Option<ObjectIdentifier>) -> Self {
        let label = match parameters {
            Some(parameters) => format!(": {oid} with parameters {parameters}"),
            None => format!(": {oid}"),
        };
        Self(Some(label))
    }
}

impl fmt::Display for AlgorithmLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(label) = &self.0 {
            f.write_str(label)
        } else {
            Ok(())
        }
    }
}

/// Selects which PKCS#12 identity to load when a PFX carries more than one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Pkcs12IdentitySelector {
    /// Match a PKCS#12 `friendlyName` bag attribute.
    pub friendly_name: Option<String>,
    /// Match a PKCS#12 `localKeyId` bag attribute.
    pub local_key_id: Option<Vec<u8>>,
}

impl Pkcs12IdentitySelector {
    /// Accept the first key/certificate pair that matches by localKeyId, friendlyName, or public
    /// key.
    pub fn any() -> Self {
        Self::default()
    }

    /// Select an identity by its PKCS#12 friendly name.
    pub fn by_friendly_name(name: impl Into<String>) -> Self {
        Self {
            friendly_name: Some(name.into()),
            local_key_id: None,
        }
    }

    /// Select an identity by its PKCS#12 local key id.
    pub fn by_local_key_id(local_key_id: impl Into<Vec<u8>>) -> Self {
        Self {
            friendly_name: None,
            local_key_id: Some(local_key_id.into()),
        }
    }

    fn matches(&self, metadata: &BagMetadata) -> bool {
        if let Some(expected) = &self.friendly_name {
            if metadata.friendly_name.as_ref() != Some(expected) {
                return false;
            }
        }
        if let Some(expected) = &self.local_key_id {
            if metadata.local_key_id.as_ref() != Some(expected) {
                return false;
            }
        }
        true
    }
}

/// Public metadata for the selected software-certificate identity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SoftCertificateIdentity {
    /// The selected signer leaf certificate (DER).
    pub signing_certificate_der: Vec<u8>,
    /// The issuer chain above the leaf (DER, leaf excluded).
    pub chain_der: Vec<Vec<u8>>,
    /// The matched PKCS#12 friendly name, if present.
    pub friendly_name: Option<String>,
    /// The matched PKCS#12 local key id, if present.
    pub local_key_id: Option<Vec<u8>>,
}

/// A selected PKCS#12 software certificate and in-memory private key.
///
/// The provider defaults to [`EvidentiaryLevel::Advanced`]. A PFX can contain a qualified
/// certificate, but this local loader alone does not establish qualified status; callers must use
/// trusted-list and policy checks before presenting any result as qualified.
pub struct Pkcs12SigningSource {
    identity: SoftCertificateIdentity,
    private_key: SoftPrivateKey,
}

impl Pkcs12SigningSource {
    /// Parse/decrypt `pkcs12_der` with `password` and select a signing identity.
    pub fn from_der(
        pkcs12_der: &[u8],
        password: &Zeroizing<String>,
    ) -> Result<Self, SoftCertificateError> {
        Self::from_der_with_selector(pkcs12_der, password, &Pkcs12IdentitySelector::any())
    }

    /// Parse/decrypt `pkcs12_der` with `password` and select an identity using `selector`.
    pub fn from_der_with_selector(
        pkcs12_der: &[u8],
        password: &Zeroizing<String>,
        selector: &Pkcs12IdentitySelector,
    ) -> Result<Self, SoftCertificateError> {
        let pfx = p12::PFX::parse(pkcs12_der)
            .map_err(|_| SoftCertificateError::MalformedInput("PFX DER is not valid".into()))?;

        let mac_present = pfx.mac_data.is_some();
        if !pfx.verify_mac(password.as_str()) {
            return Err(SoftCertificateError::WrongPassword);
        }

        let bags = pfx.bags(password.as_str()).map_err(|_| {
            if mac_present {
                SoftCertificateError::MalformedInput("PFX safe bags are invalid".into())
            } else {
                SoftCertificateError::WrongPassword
            }
        })?;
        let password_bmp = Zeroizing::new(pkcs12_bmp_string(password.as_str()));
        let (keys, certs) = collect_bags(bags, selector, &password_bmp, mac_present)?;

        let key = keys
            .into_iter()
            .next()
            .ok_or(SoftCertificateError::MissingPrivateKey)?;
        let (private_key, public_key_spki_der) = SoftPrivateKey::from_pkcs8_der(&key.key_der)?;
        let cert = select_certificate(&key.metadata, certs, &public_key_spki_der)?;
        let chain_der = certs_to_chain(cert.index, cert.all_certs);

        Ok(Self {
            identity: SoftCertificateIdentity {
                signing_certificate_der: cert.leaf_der,
                chain_der,
                friendly_name: cert.metadata.friendly_name,
                local_key_id: cert.metadata.local_key_id,
            },
            private_key,
        })
    }

    /// Public metadata and certificate material for the selected identity.
    pub fn identity(&self) -> &SoftCertificateIdentity {
        &self.identity
    }
}

impl fmt::Debug for Pkcs12SigningSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs12SigningSource")
            .field("identity", &self.identity)
            .field("evidentiary_level", &EvidentiaryLevel::Advanced)
            .finish_non_exhaustive()
    }
}

impl SignerProvider for Pkcs12SigningSource {
    fn family(&self) -> SigningFamily {
        SigningFamily::QualifiedCertificate
    }

    fn evidentiary_level(&self) -> EvidentiaryLevel {
        // Honest default for a locally loaded software certificate: the cryptographic artifact may
        // be strong, but this loader alone does not prove a qualified trust-service status.
        EvidentiaryLevel::Advanced
    }

    fn signing_certificate_der(&self) -> Result<Vec<u8>, SigningError> {
        Ok(self.identity.signing_certificate_der.clone())
    }

    fn issuer_certificate_der(&self) -> Result<Option<Vec<u8>>, SigningError> {
        Ok(self.identity.chain_der.first().cloned())
    }

    fn sign_signed_attributes(
        &self,
        signed_attrs_digest: &[u8; 32],
    ) -> Result<RawSignature, SigningError> {
        let (algorithm, signature) = self.private_key.sign_digest(signed_attrs_digest)?;
        Ok(RawSignature::new(
            algorithm,
            signature,
            self.identity.signing_certificate_der.clone(),
            self.identity.chain_der.clone(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BagMetadata {
    friendly_name: Option<String>,
    local_key_id: Option<Vec<u8>>,
}

impl BagMetadata {
    fn from_bag(bag: &p12::SafeBag) -> Self {
        Self {
            friendly_name: bag.friendly_name(),
            local_key_id: bag.local_key_id(),
        }
    }
}

struct KeyCandidate {
    key_der: Zeroizing<Vec<u8>>,
    metadata: BagMetadata,
}

#[derive(Clone)]
struct CertCandidate {
    der: Vec<u8>,
    metadata: BagMetadata,
    public_key_spki_der: Vec<u8>,
}

struct SelectedCertificate {
    leaf_der: Vec<u8>,
    metadata: BagMetadata,
    index: usize,
    all_certs: Vec<CertCandidate>,
}

fn collect_bags(
    bags: Vec<p12::SafeBag>,
    selector: &Pkcs12IdentitySelector,
    password_bmp: &[u8],
    mac_present: bool,
) -> Result<(Vec<KeyCandidate>, Vec<CertCandidate>), SoftCertificateError> {
    let mut keys = Vec::new();
    let mut certs = Vec::new();
    let mut key_decrypt_failed = false;

    for bag in bags {
        let metadata = BagMetadata::from_bag(&bag);
        match bag.bag {
            p12::SafeBagKind::Pkcs8ShroudedKeyBag(key_bag) => {
                if !selector.matches(&metadata) {
                    continue;
                }
                match key_bag.decrypt(password_bmp) {
                    Some(key_der) if !key_der.is_empty() => {
                        keys.push(KeyCandidate {
                            key_der: Zeroizing::new(key_der),
                            metadata,
                        });
                    }
                    Some(_) => {}
                    None => key_decrypt_failed = true,
                }
            }
            p12::SafeBagKind::CertBag(p12::CertBag::X509(cert_der)) => {
                if cert_der.is_empty() {
                    continue;
                }
                let public_key_spki_der = certificate_public_key_spki_der(&cert_der)?;
                certs.push(CertCandidate {
                    der: cert_der,
                    metadata,
                    public_key_spki_der,
                });
            }
            _ => {}
        }
    }

    if keys.is_empty() {
        if key_decrypt_failed {
            return if mac_present {
                Err(SoftCertificateError::MalformedInput(
                    "private key bag could not be decrypted".into(),
                ))
            } else {
                Err(SoftCertificateError::WrongPassword)
            };
        }
        return Err(SoftCertificateError::MissingPrivateKey);
    }
    if certs.is_empty() {
        return Err(SoftCertificateError::EmptyCertificateChain);
    }
    Ok((keys, certs))
}

fn pkcs12_bmp_string(password: &str) -> Vec<u8> {
    let utf16: Vec<u16> = password.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2 + 2);
    for code_unit in utf16 {
        bytes.push((code_unit >> 8) as u8);
        bytes.push((code_unit & 0xff) as u8);
    }
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

fn select_certificate(
    key_metadata: &BagMetadata,
    certs: Vec<CertCandidate>,
    public_key_spki_der: &[u8],
) -> Result<SelectedCertificate, SoftCertificateError> {
    let selected = certs
        .iter()
        .enumerate()
        .find(|(_, cert)| {
            key_metadata.local_key_id.is_some()
                && cert.metadata.local_key_id == key_metadata.local_key_id
                && cert.public_key_spki_der == public_key_spki_der
        })
        .or_else(|| {
            certs.iter().enumerate().find(|(_, cert)| {
                key_metadata.friendly_name.is_some()
                    && cert.metadata.friendly_name == key_metadata.friendly_name
                    && cert.public_key_spki_der == public_key_spki_der
            })
        })
        .or_else(|| {
            certs
                .iter()
                .enumerate()
                .find(|(_, cert)| cert.public_key_spki_der == public_key_spki_der)
        })
        .ok_or_else(|| {
            SoftCertificateError::MalformedInput(
                "private key does not match any certificate in the PFX".into(),
            )
        })?;

    Ok(SelectedCertificate {
        leaf_der: selected.1.der.clone(),
        metadata: selected.1.metadata.clone(),
        index: selected.0,
        all_certs: certs,
    })
}

fn certs_to_chain(leaf_index: usize, certs: Vec<CertCandidate>) -> Vec<Vec<u8>> {
    certs
        .into_iter()
        .enumerate()
        .filter_map(|(index, cert)| (index != leaf_index).then_some(cert.der))
        .collect()
}

fn certificate_public_key_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, SoftCertificateError> {
    let cert = Certificate::from_der(cert_der).map_err(|_| {
        SoftCertificateError::MalformedInput("certificate bag is not X.509 DER".into())
    })?;
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| {
            SoftCertificateError::MalformedInput("certificate public key is invalid".into())
        })
}

enum SoftPrivateKey {
    Rsa(Box<rsa::RsaPrivateKey>),
    EcdsaP256(p256::ecdsa::SigningKey),
}

impl SoftPrivateKey {
    fn from_pkcs8_der(key_der: &[u8]) -> Result<(Self, Vec<u8>), SoftCertificateError> {
        let private_key_info = PrivateKeyInfo::try_from(key_der).map_err(|_| {
            SoftCertificateError::MalformedInput("private key is not PKCS#8 DER".into())
        })?;
        let (algorithm, parameters) = private_key_info.algorithm.oids().map_err(|_| {
            SoftCertificateError::MalformedInput(
                "private-key algorithm identifier is invalid".into(),
            )
        })?;

        if algorithm == RSA_ENCRYPTION_OID {
            let key = rsa::RsaPrivateKey::from_pkcs8_der(key_der).map_err(|_| {
                SoftCertificateError::MalformedInput("RSA private key is invalid".into())
            })?;
            let public_key_der = rsa::RsaPublicKey::from(&key)
                .to_public_key_der()
                .map_err(|_| {
                    SoftCertificateError::MalformedInput("RSA public key is invalid".into())
                })?
                .as_bytes()
                .to_vec();
            return Ok((Self::Rsa(Box::new(key)), public_key_der));
        }

        if algorithm == EC_PUBLIC_KEY_OID && parameters == Some(PRIME256V1_OID) {
            let key = p256::ecdsa::SigningKey::from_pkcs8_der(key_der).map_err(|_| {
                SoftCertificateError::MalformedInput("P-256 private key is invalid".into())
            })?;
            let public_key_der = key
                .verifying_key()
                .to_public_key_der()
                .map_err(|_| {
                    SoftCertificateError::MalformedInput("P-256 public key is invalid".into())
                })?
                .as_bytes()
                .to_vec();
            return Ok((Self::EcdsaP256(key), public_key_der));
        }

        Err(SoftCertificateError::UnsupportedKeyAlgorithm {
            algorithm: if algorithm == EC_PUBLIC_KEY_OID {
                AlgorithmLabel::oid(algorithm, parameters)
            } else {
                AlgorithmLabel::oid(algorithm, None)
            },
        })
    }

    fn sign_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<(SignatureAlgorithm, Vec<u8>), SigningError> {
        match self {
            Self::Rsa(key) => {
                let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
                digest_info.extend_from_slice(digest);
                let signature = key
                    .sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
                    .map_err(|e| SigningError::Provider(e.to_string()))?;
                Ok((SignatureAlgorithm::RsaPkcs1Sha256, signature))
            }
            Self::EcdsaP256(key) => {
                let signature: p256::ecdsa::Signature = key
                    .sign_prehash(digest)
                    .map_err(|e| SigningError::Provider(e.to_string()))?;
                Ok((
                    SignatureAlgorithm::EcdsaP256Sha256,
                    signature.to_der().as_bytes().to_vec(),
                ))
            }
        }
    }
}

impl From<SoftCertificateError> for SigningError {
    fn from(error: SoftCertificateError) -> Self {
        SigningError::SoftCertificate(error)
    }
}
