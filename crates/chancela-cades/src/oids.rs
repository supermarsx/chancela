//! Object identifiers used across CAdES-B construction and validation.
//!
//! Centralised so the builder and validator agree byte-for-byte.

use der::asn1::ObjectIdentifier;

/// `id-data` (RFC 5652 §4) — the eContentType of a detached CAdES-B `SignedData`.
pub const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// `id-signedData` (RFC 5652 §5.1) — the outer `ContentInfo` content type.
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// `id-contentType` signed attribute (RFC 5652 §11.1).
pub const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// `id-messageDigest` signed attribute (RFC 5652 §11.2).
pub const ID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// `id-signingTime` signed attribute (RFC 5652 §11.3).
pub const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

/// `id-aa-signingCertificateV2` signed attribute (RFC 5035 §3) — the CAdES-B
/// `signing-certificate-v2` (ESSCertIDv2) attribute.
pub const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

/// `id-sha256` (NIST) — the digest algorithm for every profile this crate emits.
pub const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// `rsaEncryption` (PKCS#1) — the `SignerInfo.signatureAlgorithm` OID for the RSA profile
/// (RFC 5754 §3.2 recommends the plain `rsaEncryption` identifier for CMS).
pub const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// `sha256WithRSAEncryption` (PKCS#1) — accepted on validation as an alternate RSA identifier
/// (some producers emit it in place of `rsaEncryption`).
pub const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// `ecdsa-with-SHA256` (ANSI X9.62) — the `SignerInfo.signatureAlgorithm` OID for the ECDSA
/// P-256 profile.
pub const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
