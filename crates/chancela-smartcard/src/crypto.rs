//! Pure, hardware-free crypto helpers shared by the real token and the mock.
//!
//! Everything here is deterministic and offline so the card-generation branching
//! (spec 04, §1.2 / plan §3) is unit-tested without a reader:
//! - [`sha256_digest_info`] wraps a bare digest for `CKM_RSA_PKCS` (CC v1, RSA).
//! - [`ecdsa_signature_to_der`] normalises a `CKM_ECDSA` `r‖s` block to the
//!   DER `Ecdsa-Sig-Value` a CMS `SignerInfo` needs (CC v2, P-256).
//! - [`algorithm_from_cert_der`] detects RSA vs P-256 from a certificate's SPKI,
//!   which is how a [`SignatureAlgorithm`] is assigned to each token cert.

use chancela_cades::SignatureAlgorithm;
use der::{Encode, Length, asn1::UintRef, oid::ObjectIdentifier};

use crate::error::SmartcardError;

/// PKCS#1 v1.5 `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2), 19 bytes.
/// `SEQUENCE { SEQUENCE { OID sha-256, NULL }, OCTET STRING(32) }` header.
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// `rsaEncryption` (PKCS#1) — SPKI algorithm OID of a CC v1 RSA key.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// `id-ecPublicKey` — SPKI algorithm OID of a CC v2 EC (P-256) key.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `secp256r1` / `prime256v1` — the **only** EC curve the Cartão de Cidadão v2 carries.
/// Encoded as the EC parameters field of the SubjectPublicKeyInfo when the algorithm is
/// `id-ecPublicKey` (RFC 5480 §2.1.1). t41-e4 M10: any other curve MUST be rejected.
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// Build the SHA-256 `DigestInfo` to feed to `CKM_RSA_PKCS`.
///
/// The Cartão de Cidadão (v1) does raw RSA + PKCS#1 v1.5 padding on the card, so
/// the host must present the full `DigestInfo`, not the bare 32-byte hash
/// (plan §1.2). Result is a fixed 51 bytes (19-byte prefix + 32-byte digest).
#[must_use]
pub fn sha256_digest_info(digest: &[u8; 32]) -> [u8; 51] {
    let mut out = [0u8; 51];
    out[..19].copy_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    out[19..].copy_from_slice(digest);
    out
}

/// Normalise an ECDSA signature value to DER `Ecdsa-Sig-Value` for CMS.
///
/// `CKM_ECDSA` on the CC v2 card yields a fixed-width IEEE-P1363 `r‖s` block
/// (64 bytes for P-256), but CMS `SignerInfo` requires the DER
/// `SEQUENCE { INTEGER r, INTEGER s }` (RFC 5753). Some middleware builds
/// already return DER — this accepts either: a value that already parses as a
/// two-integer SEQUENCE is passed through unchanged, otherwise it is treated as
/// P1363 and re-encoded.
///
/// # Errors
/// [`SmartcardError::MalformedSignature`] if a non-DER value has an odd or empty
/// length; [`SmartcardError::DerEncoding`] if the resulting DER cannot be built.
pub fn ecdsa_signature_to_der(raw: &[u8]) -> Result<Vec<u8>, SmartcardError> {
    if is_der_ecdsa_sig_value(raw) {
        return Ok(raw.to_vec());
    }
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(SmartcardError::MalformedSignature(format!(
            "expected even-length IEEE-P1363 r‖s, got {} bytes",
            raw.len()
        )));
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    ecdsa_der_from_p1363(r, s)
}

/// True if `bytes` is a DER `SEQUENCE` of exactly two `INTEGER`s (an
/// `Ecdsa-Sig-Value`), so it can be passed to CMS as-is.
fn is_der_ecdsa_sig_value(bytes: &[u8]) -> bool {
    use der::{Reader, SliceReader, Tag};
    let Ok(mut outer) = SliceReader::new(bytes) else {
        return false;
    };
    let parsed_two_ints = outer.sequence(|reader| {
        // Two INTEGERs, then end-of-sequence.
        reader.decode::<UintRef<'_>>()?;
        reader.decode::<UintRef<'_>>()?;
        Ok(())
    });
    if parsed_two_ints.is_err() {
        return false;
    }
    // Reject trailing garbage after the SEQUENCE and confirm the outer tag.
    outer.is_finished() && matches!(bytes.first(), Some(&b) if b == u8::from(Tag::Sequence))
}

/// Encode two big-endian unsigned scalars as DER `SEQUENCE { INTEGER, INTEGER }`.
fn ecdsa_der_from_p1363(r: &[u8], s: &[u8]) -> Result<Vec<u8>, SmartcardError> {
    let der_err = |e: der::Error| SmartcardError::DerEncoding(e.to_string());
    // `UintRef` strips leading zeros and re-adds a sign byte when encoding, so
    // this yields canonical DER INTEGERs.
    let r_tlv = UintRef::new(r).and_then(|u| u.to_der()).map_err(der_err)?;
    let s_tlv = UintRef::new(s).and_then(|u| u.to_der()).map_err(der_err)?;

    let mut body = r_tlv;
    body.extend_from_slice(&s_tlv);

    let len = Length::try_from(body.len()).map_err(der_err)?;
    let mut out = Vec::with_capacity(1 + body.len() + 4);
    out.push(0x30); // universal, constructed, SEQUENCE
    out.extend_from_slice(&len.to_der().map_err(der_err)?);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Detect the signing algorithm from a certificate's SubjectPublicKeyInfo.
///
/// CC v1 cards carry RSA-2048 keys, CC v2 (June 2024+) carry P-256 EC keys; the
/// signer must branch on this (plan §1.2, risk #3). We map the SPKI algorithm
/// OID: `rsaEncryption` → [`SignatureAlgorithm::RsaPkcs1Sha256`],
/// `id-ecPublicKey` → [`SignatureAlgorithm::EcdsaP256Sha256`] **only after confirming
/// the curve is `secp256r1`** (t41-e4 M10). Previously any `id-ecPublicKey` key was
/// labelled P-256 without inspecting the EC parameters; a key on a different curve
/// (e.g. `secp384r1`, `secp521r1`, or a brainpool curve) would have been silently
/// signed/hashed as P-256, producing a signature the verifier rejects or — worse — a
/// mismatched digest that a downstream policy gate might not catch.
///
/// # Errors
/// [`SmartcardError::CertificateParse`] if the DER is not a valid certificate, or if an
/// EC key's `AlgorithmIdentifier.parameters` (the curve OID) is missing/malformed;
/// [`SmartcardError::UnsupportedKeyAlgorithm`] for any non-RSA/non-EC key, or an EC key
/// on a curve other than `secp256r1`.
pub fn algorithm_from_cert_der(cert_der: &[u8]) -> Result<SignatureAlgorithm, SmartcardError> {
    use der::Decode;
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| SmartcardError::CertificateParse(e.to_string()))?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let oid = spki.algorithm.oid;
    if oid == OID_RSA_ENCRYPTION {
        Ok(SignatureAlgorithm::RsaPkcs1Sha256)
    } else if oid == OID_EC_PUBLIC_KEY {
        // RFC 5480 §2.1.1: for id-ecPublicKey the AlgorithmIdentifier.parameters field
        // holds the named curve OID. Parse it and require secp256r1.
        let curve_oid = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| {
                SmartcardError::CertificateParse(
                    "EC key is missing its curve parameters (named curve OID)".to_string(),
                )
            })?
            .decode_as::<ObjectIdentifier>()
            .map_err(|e| SmartcardError::CertificateParse(format!("invalid EC curve OID: {e}")))?;
        if curve_oid != OID_SECP256R1 {
            return Err(SmartcardError::UnsupportedKeyAlgorithm(format!(
                "EC curve OID {curve_oid}; only secp256r1 (P-256) is supported"
            )));
        }
        Ok(SignatureAlgorithm::EcdsaP256Sha256)
    } else {
        Err(SmartcardError::UnsupportedKeyAlgorithm(oid.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Reader, SliceReader};

    const RSA_CERT: &[u8] = include_bytes!("../fixtures/cc_v1_signature_rsa2048.der");
    const EC_CERT: &[u8] = include_bytes!("../fixtures/cc_v2_authentication_p256.der");

    #[test]
    fn digest_info_has_sha256_prefix_and_digest() {
        let digest = [0xABu8; 32];
        let di = sha256_digest_info(&digest);
        assert_eq!(di.len(), 51);
        assert_eq!(&di[..19], &SHA256_DIGEST_INFO_PREFIX);
        assert_eq!(&di[19..], &digest);
    }

    /// A `SliceReader` that succeeds iff `bytes` is exactly `SEQUENCE { INTEGER, INTEGER }`.
    fn parse_ecdsa_der(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut reader = SliceReader::new(bytes).expect("valid slice");
        let (r, s) = reader
            .sequence(|r| {
                let a = r.decode::<UintRef<'_>>()?;
                let b = r.decode::<UintRef<'_>>()?;
                Ok((a.as_bytes().to_vec(), b.as_bytes().to_vec()))
            })
            .expect("two-integer sequence");
        assert!(reader.is_finished(), "no trailing bytes");
        (r, s)
    }

    #[test]
    fn ecdsa_p1363_reencodes_to_der() {
        // 64-byte r‖s; small values in the low bytes so leading zeros strip to
        // a one-byte magnitude (r = 1, s = 2).
        let mut raw = [0u8; 64];
        raw[31] = 0x01;
        raw[63] = 0x02;
        let der = ecdsa_signature_to_der(&raw).unwrap();
        assert_eq!(der[0], 0x30, "outer SEQUENCE");
        let (r, s) = parse_ecdsa_der(&der);
        assert_eq!(r, vec![0x01]);
        assert_eq!(s, vec![0x02]);
    }

    #[test]
    fn ecdsa_p1363_high_bit_gets_sign_byte() {
        // r has its top bit set -> DER INTEGER must gain a leading 0x00.
        let mut raw = [0u8; 64];
        raw[0] = 0x80;
        raw[63] = 0x7f;
        let der = ecdsa_signature_to_der(&raw).unwrap();
        // Re-decode and confirm canonical round-trip of the magnitudes.
        let (r, s) = parse_ecdsa_der(&der);
        // UintRef strips the DER sign byte, so the stripped magnitude starts 0x80.
        assert_eq!(r.first(), Some(&0x80));
        assert_eq!(s.last(), Some(&0x7f));
    }

    #[test]
    fn ecdsa_already_der_is_passed_through() {
        let mut raw = [0u8; 64];
        raw[0] = 0x11;
        raw[32] = 0x22;
        let der = ecdsa_signature_to_der(&raw).unwrap();
        let again = ecdsa_signature_to_der(&der).unwrap();
        assert_eq!(der, again, "a DER value is returned unchanged");
    }

    #[test]
    fn ecdsa_odd_length_rejected() {
        let raw = [0u8; 63];
        assert!(matches!(
            ecdsa_signature_to_der(&raw),
            Err(SmartcardError::MalformedSignature(_))
        ));
    }

    #[test]
    fn detects_rsa_from_cert() {
        assert_eq!(
            algorithm_from_cert_der(RSA_CERT).unwrap(),
            SignatureAlgorithm::RsaPkcs1Sha256
        );
    }

    #[test]
    fn detects_ec_from_cert() {
        assert_eq!(
            algorithm_from_cert_der(EC_CERT).unwrap(),
            SignatureAlgorithm::EcdsaP256Sha256
        );
    }

    #[test]
    fn rejects_garbage_cert() {
        assert!(matches!(
            algorithm_from_cert_der(&[0x00, 0x01, 0x02]),
            Err(SmartcardError::CertificateParse(_))
        ));
    }
}
