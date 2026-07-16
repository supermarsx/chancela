//! Generic X.509 certificate-path builder — **Phase-A frozen seam (wp26 E5)**.
//!
//! Builds a path from an end-entity signer certificate, through any intermediate CA certificates
//! carried alongside it (e.g. from a CMS `SignedData` certificate set), up to a trust anchor
//! extracted from an authenticated Trusted List ([`crate::trust_store::TslTrustStore`]). This is the
//! missing piece over today's fingerprint pin: real chaining with validity, basic-constraints,
//! path-length, key-usage, and child-signature checks.
//!
//! The algorithm mirrors the conservative offline builder in `chancela-tsa/src/path.rs` (RSA-SHA256
//! and P-256 ECDSA-SHA256 only; reject unknown algorithms rather than guess). The cross-crate
//! duplication is deliberate and acceptable for now — a shared helper is a documented future
//! cleanup (wp26 §5 risk 3), not part of this work package.
//!
//! Phase A freezes the public API; **E5 replaces the stub body** with the real path build.

use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

use crate::error::TslError;

/// `sha256WithRSAEncryption` (PKCS#1) — the only RSA certificate-signature algorithm accepted.
const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// `ecdsa-with-SHA256` (ANSI X9.62) — the only ECDSA certificate-signature algorithm accepted.
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Maximum number of certificates walked before giving up. Bounds the search so a cross-signed or
/// cyclic set of intermediates cannot loop forever (wp26 §5 risk 3).
const MAX_PATH_DEPTH: usize = 8;

/// Options controlling a path build.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PathBuildOptions {
    /// The instant at which certificate validity (`notBefore`/`notAfter`) is evaluated — typically
    /// the signing time or a trusted timestamp, not wall-clock now.
    pub validation_time: OffsetDateTime,
}

impl PathBuildOptions {
    /// Build options that evaluate validity at `validation_time`.
    pub fn at(validation_time: OffsetDateTime) -> Self {
        Self { validation_time }
    }
}

/// A successfully built certificate path: the DER certificates from the end-entity leaf up to and
/// including the matched trust anchor, in chain order (`certs_der[0]` is the signer).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CertPath {
    /// The chain, leaf-first, anchor-last. Each certificate is DER-encoded.
    pub certs_der: Vec<Vec<u8>>,
}

impl CertPath {
    /// The end-entity (leaf) certificate DER — the signer whose path was built.
    pub fn leaf(&self) -> &[u8] {
        // The leaf is always present in a built path; an empty path is never constructed.
        self.certs_der.first().map(Vec::as_slice).unwrap_or(&[])
    }

    /// The matched trust-anchor certificate DER (the last element of the chain).
    pub fn anchor(&self) -> &[u8] {
        self.certs_der.last().map(Vec::as_slice).unwrap_or(&[])
    }

    /// The number of certificates in the path (leaf + intermediates + anchor).
    pub fn len(&self) -> usize {
        self.certs_der.len()
    }

    /// Whether the path carries no certificates (never true for a built path).
    pub fn is_empty(&self) -> bool {
        self.certs_der.is_empty()
    }

    /// Issuer of the signer within the built path — the certificate that signed the leaf. For a
    /// directly anchor-issued leaf this is the anchor. Returns the leaf itself only for a
    /// degenerate single-element self-issued path.
    pub fn signer_issuer(&self) -> &[u8] {
        self.certs_der
            .get(1)
            .or_else(|| self.certs_der.first())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Build a certificate path from `signer_der` to one of `anchors`, using `intermediates` to bridge
/// the gap.
///
/// - `signer_der`: the end-entity signer certificate (DER).
/// - `intermediates`: candidate intermediate CA certificates (DER), order-independent — typically
///   the certificate set embedded in the CMS/PAdES signature.
/// - `anchors`: DER trust-anchor certificates (a `TslTrustStore`'s `qc_anchors` or `qtst_anchors`).
/// - `opts`: validity evaluation instant.
///
/// Verifies at each link: the child's issuer matches the parent's subject, the parent is a CA
/// (basic constraints) with a sufficient path length and a `keyCertSign` key usage, every
/// certificate is temporally valid at `opts.validation_time`, and the child's signature verifies
/// against the parent's public key (RSA-SHA256 / P-256 ECDSA-SHA256 only).
///
/// Returns the built [`CertPath`] (leaf-first, anchor-last) or [`TslError::CertPath`] when no path
/// to a configured anchor exists. **Fail-closed:** an empty `anchors` set yields an error.
///
/// **Phase-A stub (wp26 E5 owns the implementation).**
pub fn build_path(
    signer_der: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    opts: &PathBuildOptions,
) -> Result<CertPath, TslError> {
    // Fail-closed: with no configured anchors there is nothing to chain to.
    if anchors.is_empty() {
        return Err(path_error("no trust anchors configured"));
    }

    let when = opts.validation_time;

    let leaf = parse_cert(signer_der, "signer")?;
    check_validity(&leaf, when, "signer")?;

    let intermediates = intermediates
        .iter()
        .enumerate()
        .map(|(i, der)| parse_cert(der, &format!("intermediate {i}")).map(|cert| (der, cert)))
        .collect::<Result<Vec<_>, _>>()?;
    let anchors = anchors
        .iter()
        .enumerate()
        .map(|(i, der)| parse_cert(der, &format!("trust anchor {i}")).map(|cert| (der, cert)))
        .collect::<Result<Vec<_>, _>>()?;

    let mut path_der = vec![signer_der.to_vec()];
    let mut current = leaf;
    let mut current_der: Vec<u8> = signer_der.to_vec();
    let mut used_intermediates = vec![false; intermediates.len()];

    // Each continued iteration extends the chain through exactly one intermediate (branches (a) and
    // (b) return), so the loop index equals the number of CA certificates already below `current` —
    // the value `pathLenConstraint` is checked against.
    for ca_count_below_current in 0..MAX_PATH_DEPTH {
        // (a) Exact-DER anchor match: `current` is itself a configured anchor. It is already the
        // last element of `path_der` and was validity-checked when it was added, so the chain is
        // complete.
        if anchors
            .iter()
            .any(|(der, _)| der.as_slice() == current_der.as_slice())
        {
            return Ok(CertPath {
                certs_der: path_der,
            });
        }

        // (b) Issuer-based anchor match: an anchor's subject issues `current`. Verify the anchor is
        // a temporally-valid CA and that it actually signed `current`, then close the chain.
        for (anchor_der, anchor) in &anchors {
            if names_match(&current, anchor) {
                check_validity(anchor, when, "trust anchor")?;
                check_ca_constraints(anchor, ca_count_below_current, "trust anchor")?;
                verify_child_signature(&current, anchor)?;
                path_der.push((*anchor_der).clone());
                return Ok(CertPath {
                    certs_der: path_der,
                });
            }
        }

        // (c) Otherwise extend the chain through an unused intermediate that issued `current`.
        let Some((pos, issuer_der, issuer)) =
            intermediates
                .iter()
                .enumerate()
                .find_map(|(pos, (der, candidate))| {
                    (!used_intermediates[pos] && names_match(&current, candidate))
                        .then_some((pos, der, candidate))
                })
        else {
            return Err(path_error(
                "no chain from signer to a configured trust anchor",
            ));
        };

        check_validity(issuer, when, "intermediate")?;
        check_ca_constraints(issuer, ca_count_below_current, "intermediate")?;
        verify_child_signature(&current, issuer)?;
        path_der.push((*issuer_der).clone());
        used_intermediates[pos] = true;
        current_der = (*issuer_der).clone();
        current = issuer.clone();
    }

    Err(path_error(
        "certificate path exceeded maximum depth without reaching a trust anchor",
    ))
}

/// Whether `parent`'s subject issues `child` — compared over the encoded `Name` DER so an
/// attribute-encoding difference between two logically-equal names does not defeat the match.
fn names_match(child: &Certificate, parent: &Certificate) -> bool {
    match (
        child.tbs_certificate.issuer.to_der(),
        parent.tbs_certificate.subject.to_der(),
    ) {
        (Ok(issuer), Ok(subject)) => issuer == subject,
        // A name that will not re-encode cannot be trusted to match.
        _ => false,
    }
}

fn parse_cert(der: &[u8], label: &str) -> Result<Certificate, TslError> {
    Certificate::from_der(der).map_err(|e| path_error(format!("{label} certificate DER: {e}")))
}

fn check_validity(cert: &Certificate, when: OffsetDateTime, label: &str) -> Result<(), TslError> {
    let not_before = offset_from_x509_time(cert.tbs_certificate.validity.not_before)?;
    let not_after = offset_from_x509_time(cert.tbs_certificate.validity.not_after)?;
    if when < not_before {
        return Err(path_error(format!(
            "{label} certificate is not yet valid at validation time"
        )));
    }
    if when > not_after {
        return Err(path_error(format!(
            "{label} certificate is expired at validation time"
        )));
    }
    Ok(())
}

fn offset_from_x509_time(t: x509_cert::time::Time) -> Result<OffsetDateTime, TslError> {
    let secs = i64::try_from(t.to_unix_duration().as_secs())
        .map_err(|e| path_error(format!("certificate validity time out of range: {e}")))?;
    OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|e| path_error(format!("certificate validity time out of range: {e}")))
}

/// Verify the parent is a CA usable to issue `current`: `basicConstraints` marks a CA, the
/// `pathLenConstraint` (if any) is not exceeded, and `keyUsage` (if present) permits `keyCertSign`.
fn check_ca_constraints(
    cert: &Certificate,
    ca_count_below: usize,
    label: &str,
) -> Result<(), TslError> {
    let basic = cert
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|e| path_error(format!("{label} basicConstraints extension: {e}")))?
        .ok_or_else(|| path_error(format!("{label} certificate has no basicConstraints")))?;
    if !basic.1.ca {
        return Err(path_error(format!(
            "{label} basicConstraints does not mark a CA"
        )));
    }
    if let Some(max) = basic.1.path_len_constraint
        && ca_count_below > usize::from(max)
    {
        return Err(path_error(format!("{label} pathLenConstraint exceeded")));
    }

    if let Some((_, usage)) = cert
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|e| path_error(format!("{label} keyUsage extension: {e}")))?
        && !usage.key_cert_sign()
    {
        return Err(path_error(format!(
            "{label} keyUsage is present but does not allow keyCertSign"
        )));
    }

    Ok(())
}

fn verify_child_signature(child: &Certificate, issuer: &Certificate) -> Result<(), TslError> {
    if child.signature_algorithm.oid != child.tbs_certificate.signature.oid {
        return Err(path_error(
            "certificate signatureAlgorithm does not match TBSCertificate signature",
        ));
    }
    let signature = child
        .signature
        .as_bytes()
        .ok_or_else(|| path_error("certificate signature BIT STRING has unused bits"))?;
    let tbs_der = child
        .tbs_certificate
        .to_der()
        .map_err(|e| path_error(format!("TBSCertificate DER: {e}")))?;

    if child.signature_algorithm.oid == SHA256_WITH_RSA_ENCRYPTION {
        verify_cert_rsa_sha256(issuer, signature, &tbs_der)
    } else if child.signature_algorithm.oid == ECDSA_WITH_SHA256 {
        verify_cert_ecdsa_sha256(issuer, signature, &tbs_der)
    } else {
        // Unknown algorithm: fail closed rather than guess (wp26 §5 risk 3).
        Err(path_error(format!(
            "unsupported certificate signature algorithm: {}",
            child.signature_algorithm.oid
        )))
    }
}

fn verify_cert_rsa_sha256(
    issuer: &Certificate,
    signature: &[u8],
    message: &[u8],
) -> Result<(), TslError> {
    use der::referenced::OwnedToRef;
    use rsa::{Pkcs1v15Sign, RsaPublicKey};

    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();
    let public_key =
        RsaPublicKey::try_from(spki).map_err(|e| path_error(format!("issuer RSA key: {e}")))?;
    let hash = Sha256::digest(message);
    let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    digest_info.extend_from_slice(&hash);
    public_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, signature)
        .map_err(|_| path_error("certificate signature verification failed"))
}

fn verify_cert_ecdsa_sha256(
    issuer: &Certificate,
    signature: &[u8],
    message: &[u8],
) -> Result<(), TslError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let spki_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| path_error(format!("issuer SPKI DER: {e}")))?;
    let verifying_key = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|e| path_error(format!("issuer ECDSA key: {e}")))?;
    let sig = Signature::from_der(signature)
        .map_err(|_| path_error("certificate ECDSA signature encoding"))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| path_error("certificate signature verification failed"))
}

fn path_error(message: impl Into<String>) -> TslError {
    TslError::CertPath(message.into())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::{Duration as StdDuration, UNIX_EPOCH};

    use der::asn1::{Any, BitString, OctetString};
    use rsa::pkcs8::EncodePublicKey;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey, rand_core::OsRng};
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::certificate::{TbsCertificate, Version};
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::KeyUsages;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    use super::*;

    /// Fixed validation instant used across the tests (a plain unix timestamp).
    const T: u64 = 1_750_000_000;
    const DAY: u64 = 86_400;

    const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

    /// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    fn sha256_rsa_alg() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: SHA256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        }
    }

    fn rsa_key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa key")
    }

    fn spki_of(key: &RsaPrivateKey) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned::from_der(
            RsaPublicKey::from(key)
                .to_public_key_der()
                .expect("public key der")
                .as_bytes(),
        )
        .expect("spki")
    }

    fn rsa_sign(key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
        let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
        digest_info.extend_from_slice(&Sha256::digest(message));
        key.sign(Pkcs1v15Sign::new_unprefixed(), &digest_info)
            .expect("rsa sign")
    }

    fn time_at(unix: u64) -> Time {
        Time::try_from(UNIX_EPOCH + StdDuration::from_secs(unix)).expect("time")
    }

    fn ca_extensions() -> Vec<Extension> {
        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        let ku = KeyUsage(KeyUsages::KeyCertSign.into());
        vec![
            Extension {
                extn_id: OID_BASIC_CONSTRAINTS,
                critical: true,
                extn_value: OctetString::new(bc.to_der().expect("bc der")).expect("bc value"),
            },
            Extension {
                extn_id: OID_KEY_USAGE,
                critical: true,
                extn_value: OctetString::new(ku.to_der().expect("ku der")).expect("ku value"),
            },
        ]
    }

    /// Build a DER certificate for `subject_cn`/`subject_key`, issued (and signed) by
    /// `issuer_name`/`issuer_key`, valid over `[not_before, not_after]` unix seconds, marked as a CA
    /// (with `keyCertSign`) when `is_ca`.
    #[allow(clippy::too_many_arguments)]
    fn make_cert(
        subject_cn: &str,
        serial: u8,
        subject_key: &RsaPrivateKey,
        issuer_name: &Name,
        issuer_key: &RsaPrivateKey,
        is_ca: bool,
        not_before: u64,
        not_after: u64,
    ) -> Vec<u8> {
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[serial]).expect("serial"),
            signature: sha256_rsa_alg(),
            issuer: issuer_name.clone(),
            validity: Validity {
                not_before: time_at(not_before),
                not_after: time_at(not_after),
            },
            subject: Name::from_str(&format!("CN={subject_cn}")).expect("subject name"),
            subject_public_key_info: spki_of(subject_key),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: is_ca.then(ca_extensions),
        };
        let tbs_der = tbs.to_der().expect("tbs der");
        let signature = rsa_sign(issuer_key, &tbs_der);
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sha256_rsa_alg(),
            signature: BitString::from_bytes(&signature).expect("signature bits"),
        }
        .to_der()
        .expect("cert der")
    }

    /// A CA (root or intermediate) — its signing key, its distinguished name and its DER.
    struct Ca {
        key: RsaPrivateKey,
        name: Name,
        der: Vec<u8>,
    }

    fn root(cn: &str, serial: u8) -> Ca {
        let key = rsa_key();
        let name = Name::from_str(&format!("CN={cn}")).expect("name");
        let der = make_cert(cn, serial, &key, &name, &key, true, T - DAY, T + DAY);
        Ca { key, name, der }
    }

    fn intermediate(cn: &str, serial: u8, parent: &Ca) -> Ca {
        let key = rsa_key();
        let name = Name::from_str(&format!("CN={cn}")).expect("name");
        let der = make_cert(
            cn,
            serial,
            &key,
            &parent.name,
            &parent.key,
            true,
            T - DAY,
            T + DAY,
        );
        Ca { key, name, der }
    }

    /// Issue an end-entity signer certificate under `issuer`, valid over the given window.
    fn leaf(cn: &str, serial: u8, issuer: &Ca, not_before: u64, not_after: u64) -> Vec<u8> {
        let key = rsa_key();
        make_cert(
            cn,
            serial,
            &key,
            &issuer.name,
            &issuer.key,
            false,
            not_before,
            not_after,
        )
    }

    fn opts() -> PathBuildOptions {
        PathBuildOptions::at(
            OffsetDateTime::from_unix_timestamp(T as i64).expect("validation time"),
        )
    }

    #[test]
    fn signer_directly_under_anchor_builds_two_cert_path() {
        let anchor = root("Chancela Test Root", 1);
        let signer = leaf("Chancela Signer", 7, &anchor, T - DAY, T + DAY);

        let path = build_path(&signer, &[], std::slice::from_ref(&anchor.der), &opts())
            .expect("path builds");

        assert_eq!(path.len(), 2);
        assert_eq!(path.leaf(), signer.as_slice());
        assert_eq!(path.anchor(), anchor.der.as_slice());
        assert_eq!(path.signer_issuer(), anchor.der.as_slice());
    }

    #[test]
    fn signer_through_intermediate_builds_three_cert_path() {
        let anchor = root("Chancela Test Root", 1);
        let inter = intermediate("Chancela Test Intermediate", 2, &anchor);
        let signer = leaf("Chancela Signer", 7, &inter, T - DAY, T + DAY);

        let path = build_path(
            &signer,
            std::slice::from_ref(&inter.der),
            std::slice::from_ref(&anchor.der),
            &opts(),
        )
        .expect("path builds");

        assert_eq!(path.len(), 3);
        assert_eq!(path.certs_der[0], signer);
        assert_eq!(path.certs_der[1], inter.der);
        assert_eq!(path.certs_der[2], anchor.der);
        assert_eq!(path.signer_issuer(), inter.der.as_slice());
    }

    #[test]
    fn wrong_anchor_has_no_path() {
        let real_issuer = root("Chancela Test Root", 1);
        let unrelated = root("Some Other Root", 9);
        let signer = leaf("Chancela Signer", 7, &real_issuer, T - DAY, T + DAY);

        let err = build_path(&signer, &[], &[unrelated.der], &opts()).unwrap_err();
        assert!(matches!(err, TslError::CertPath(_)), "got {err:?}");
    }

    #[test]
    fn expired_signer_at_validation_time_errors() {
        let anchor = root("Chancela Test Root", 1);
        // notAfter one day before the validation instant.
        let signer = leaf("Chancela Signer", 7, &anchor, T - 2 * DAY, T - DAY);

        let err = build_path(&signer, &[], &[anchor.der], &opts()).unwrap_err();
        assert!(matches!(err, TslError::CertPath(_)), "got {err:?}");
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let anchor = root("Chancela Test Root", 1);
        // Signer whose signature was produced by a different (unrelated) key: the issuer names line
        // up, but the child-signature verification against the anchor's key must fail.
        let impostor = root("Chancela Test Root", 1);
        let signer = leaf("Chancela Signer", 7, &impostor, T - DAY, T + DAY);

        let err = build_path(&signer, &[], &[anchor.der], &opts()).unwrap_err();
        assert!(matches!(err, TslError::CertPath(_)), "got {err:?}");
    }

    #[test]
    fn empty_anchors_is_fail_closed_error() {
        let anchor = root("Chancela Test Root", 1);
        let signer = leaf("Chancela Signer", 7, &anchor, T - DAY, T + DAY);

        let err = build_path(&signer, &[], &[], &opts()).unwrap_err();
        match err {
            TslError::CertPath(msg) => assert!(msg.contains("no trust anchors")),
            other => panic!("expected CertPath error, got {other:?}"),
        }
    }

    #[test]
    fn unparseable_signer_der_errors() {
        let anchor = root("Chancela Test Root", 1);
        let err = build_path(b"not a certificate", &[], &[anchor.der], &opts()).unwrap_err();
        assert!(matches!(err, TslError::CertPath(_)), "got {err:?}");
    }
}
