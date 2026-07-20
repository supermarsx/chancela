//! Object identifiers used by the RFC 3161 / CMS wire format.
//!
//! `const-oid` 0.9 (the version behind `der` 0.7) predates the `rfc3161` OID database module, so
//! `id-ct-TSTInfo` is spelled out here alongside the CMS attribute OIDs we read.

use der::oid::ObjectIdentifier;

/// `id-signedData` — the CMS `SignedData` content type (RFC 5652 §5.1). A TimeStampToken is a
/// `ContentInfo` wrapping this.
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// `id-ct-TSTInfo` — the encapsulated content type of a timestamp token (RFC 3161 §2.4.2).
pub const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// `id-sha256` — the only message-imprint digest algorithm this client offers (SIG-22).
pub const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// `id-contentType` — the CMS `content-type` signed attribute (RFC 5652 §11.1).
pub const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// `id-messageDigest` — the CMS `message-digest` signed attribute (RFC 5652 §11.2).
pub const ID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// `rsaEncryption` (PKCS#1) — commonly used as the CMS `signatureAlgorithm` for RSA signatures.
pub const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// `sha256WithRSAEncryption` (PKCS#1) — accepted for RSA/SHA-256 timestamp signatures.
pub const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// `ecdsa-with-SHA256` (ANSI X9.62) — accepted for P-256/SHA-256 timestamp signatures.
pub const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
