//! Provider-driven local ASiC signing: ASiC-S / ASiC-E lanes with CAdES and XAdES signatures,
//! multiple signers over one payload set, and an optional RFC 3161 archive manifest.
//!
//! These functions sit above [`crate::asic`] (which owns the container bytes and manifests) and the
//! [`SignerProvider`] seam (card / CMD / CSC / soft, all signing a digest). XAdES is layered on the
//! *same* two-phase seam as CAdES: [`chancela_xades::prepare_xades`] builds `<SignedInfo>` and
//! exposes its digest, the provider signs it exactly like a CAdES signed-attributes digest, and
//! [`chancela_xades::PreparedXades::assemble`] wraps the returned [`RawSignature`]. The XAdES
//! signature algorithm is inferred from the signer certificate's public key so `prepare_xades` can
//! declare the matching `SignatureMethod` before signing. These helpers assemble technical
//! containers and signature bytes only; they do not claim complete ASiC/XAdES conformance, trust
//! status, or legal qualification.

use der::Decode;
use time::OffsetDateTime;
use x509_cert::certificate::Certificate;

use chancela_cades::SignatureAlgorithm;
use chancela_xades::{
    DetachedRef, PreparedXades, SignaturePackaging, ValidationMaterial, XadesContext, XadesLevel,
    XadesSignRequest, prepare_xades,
};

use crate::SigningError;
use crate::asic::{
    ASICE_ARCHIVE_MANIFEST_PATH, ASICE_ARCHIVE_TIMESTAMP_PATH, AsicArchiveReference, AsicPayload,
    XADES_SIGNATURE_MIME_TYPE, assemble_asic_e_container, build_asic_archive_manifest,
    build_asic_e_manifest, create_asic_s_xades_container, sha256_content_digest,
};
use crate::pipeline::{TimestampProvider, sign_detached_cades};
use crate::provider::SignerProvider;

/// The XMLDSig/XAdES signature algorithm the signer will use, inferred from its certificate's
/// public-key algorithm (RSA → `RsaPkcs1Sha256`, EC P-256 → `EcdsaP256Sha256`).
///
/// `prepare_xades` needs the algorithm up front to write the `SignatureMethod`, before the
/// provider — which reveals its algorithm only in the produced [`RawSignature`] — has signed.
fn algorithm_for_cert(cert_der: &[u8]) -> Result<SignatureAlgorithm, SigningError> {
    // OIDs: rsaEncryption 1.2.840.113549.1.1.1, id-ecPublicKey 1.2.840.10045.2.1.
    const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

    let cert = Certificate::from_der(cert_der)
        .map_err(|_| SigningError::Xades("signer certificate is not valid DER".to_string()))?;
    let oid = cert
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid
        .to_string();
    match oid.as_str() {
        RSA_ENCRYPTION => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
        EC_PUBLIC_KEY => Ok(SignatureAlgorithm::EcdsaP256Sha256),
        other => Err(SigningError::Xades(format!(
            "unsupported XAdES signer public-key algorithm {other}"
        ))),
    }
}

/// Drive one detached XAdES signature over `payloads` through `provider`, returning the finished
/// XAdES XML at the requested level (B, T when `tsa` is supplied, or LT when `tsa` **and**
/// `material` are supplied). LT embeds the caller-collected `material` (chain + OCSP/CRL) — this
/// module never fetches revocation itself (that stays in `crate::revocation`).
fn produce_detached_xades(
    provider: &dyn SignerProvider,
    payloads: &[AsicPayload<'_>],
    signing_time: OffsetDateTime,
    signature_id: &str,
    level: XadesLevel,
    tsa: Option<&dyn TimestampProvider>,
    material: Option<&ValidationMaterial>,
) -> Result<Vec<u8>, SigningError> {
    let cert_der = provider.signing_certificate_der()?;
    let sig_alg = algorithm_for_cert(&cert_der)?;
    let detached = payloads
        .iter()
        .map(|p| DetachedRef {
            uri: p.name.to_string(),
            bytes: p.bytes.to_vec(),
        })
        .collect();

    let prepared: PreparedXades = prepare_xades(XadesSignRequest {
        signature_id: signature_id.to_string(),
        signing_cert_der: cert_der,
        sig_alg,
        level,
        context: XadesContext { signing_time },
        packaging: SignaturePackaging::Detached(detached),
    })
    .map_err(xades_err)?;

    // The provider signs the SignedInfo digest exactly as it signs a CAdES signed-attributes digest
    // (a raw signature over a 32-byte SHA-256): the XMLDSig SignatureValue encoding is handled by
    // `PreparedXades::assemble` (DER→r||s for ECDSA, passthrough for RSA). This lane infers RSA/P-256
    // from the signer cert, so the SignedInfo digest is always SHA-256 (32 bytes); a wider-curve
    // profile (SHA-384/512) would need a variable-length signer seam and is rejected here.
    let signed_info_digest: [u8; 32] = prepared
        .signed_info_digest()
        .as_slice()
        .try_into()
        .map_err(|_| {
            SigningError::Xades(
                "this signer lane only supports SHA-256 XAdES profiles (RSA/ECDSA-P256)"
                    .to_string(),
            )
        })?;
    let raw = provider.sign_signed_attributes(&signed_info_digest)?;
    let assembled = prepared.assemble(&raw).map_err(xades_err)?;

    match level {
        XadesLevel::B => assembled.into_bytes().map_err(xades_err),
        XadesLevel::T => {
            let tsa = tsa.ok_or_else(|| {
                SigningError::Xades(
                    "XAdES-T requires a timestamp provider for the signature timestamp".to_string(),
                )
            })?;
            let digest = assembled.signature_timestamp_digest().map_err(xades_err)?;
            let token = tsa.timestamp_digest(&digest)?;
            assembled
                .with_signature_timestamp(&token.token_der)
                .map_err(xades_err)
        }
        XadesLevel::LT => {
            let tsa = tsa.ok_or_else(|| {
                SigningError::Xades(
                    "XAdES-LT requires a timestamp provider for the signature timestamp"
                        .to_string(),
                )
            })?;
            let material = material.ok_or_else(|| {
                SigningError::Xades(
                    "XAdES-LT requires collected validation material (chain + OCSP/CRL)"
                        .to_string(),
                )
            })?;
            let digest = assembled.signature_timestamp_digest().map_err(xades_err)?;
            let token = tsa.timestamp_digest(&digest)?;
            assembled
                .with_lt(&token.token_der, material)
                .map_err(xades_err)
        }
        XadesLevel::LTA => Err(SigningError::Xades(
            "XAdES-LTA inside ASiC is deferred (archive timestamp)".to_string(),
        )),
    }
}

/// Produce a bounded ASiC-S container with a detached XAdES-B/T signature over one payload.
///
/// The XAdES `<ds:Reference URI="content_name">` digests the payload as-is; validation re-derives
/// that digest and checks the signed value (see [`crate::asic_validate::validate_asic_container`]).
/// `level` must be [`XadesLevel::B`] or [`XadesLevel::T`]; `tsa` is required for T.
pub fn sign_asic_s_xades(
    provider: &dyn SignerProvider,
    content_name: &str,
    content: &[u8],
    signing_time: OffsetDateTime,
    level: XadesLevel,
    tsa: Option<&dyn TimestampProvider>,
) -> Result<Vec<u8>, SigningError> {
    let payloads = [AsicPayload {
        name: content_name,
        bytes: content,
        mime_type: None,
    }];
    let xml = produce_detached_xades(
        provider,
        &payloads,
        signing_time,
        "asic-s-xades-sig",
        level,
        tsa,
        None,
    )?;
    create_asic_s_xades_container(content_name, content, &xml)
}

/// A request to produce a multi-signature ASiC-E container over one payload set.
///
/// Every CAdES signer gets its own `ASiCManifest{NNN}.xml` + `signature{NNN}.p7s`; every XAdES
/// signer gets its own detached `signatures{NNN}.xml` referencing the payloads directly (the ETSI
/// convention — XAdES carries its own `ds:Reference` digests, so it needs no `ASiCManifest`). When
/// `archive_tsa` is set, an `ASiCArchiveManifest` covering all payloads and signature members is
/// added, protected by an RFC 3161 archive-timestamp token.
pub struct AsicEMultiSignRequest<'a> {
    /// The shared payload set every signature covers.
    pub payloads: &'a [AsicPayload<'a>],
    /// CAdES signers (each produces an `ASiCManifest` + detached CAdES signature).
    pub cades_signers: &'a [&'a dyn SignerProvider],
    /// XAdES signers (each produces a detached XAdES signature over the payloads).
    pub xades_signers: &'a [&'a dyn SignerProvider],
    /// The signing time asserted by every signature.
    pub signing_time: OffsetDateTime,
    /// The XAdES level for the XAdES signers (B, or T with `xades_tsa`).
    pub xades_level: XadesLevel,
    /// The timestamp source for XAdES-T signature timestamps (required when `xades_level` is T).
    pub xades_tsa: Option<&'a dyn TimestampProvider>,
    /// When set, add an `ASiCArchiveManifest` protected by an archive timestamp from this source.
    pub archive_tsa: Option<&'a dyn TimestampProvider>,
}

/// Produce a multi-signature ASiC-E container (see [`AsicEMultiSignRequest`]).
pub fn sign_asic_e_multi(req: AsicEMultiSignRequest<'_>) -> Result<Vec<u8>, SigningError> {
    if req.cades_signers.is_empty() && req.xades_signers.is_empty() {
        return Err(SigningError::Asic(
            "ASiC-E multi-signature container requires at least one signer".to_string(),
        ));
    }

    // Own every produced member's bytes; borrow them into the assembler at the end.
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();

    for (index, provider) in req.cades_signers.iter().enumerate() {
        let n = index + 1;
        let manifest_path = format!("META-INF/ASiCManifest{n:03}.xml");
        let signature_path = format!("META-INF/signature{n:03}.p7s");
        let manifest = build_asic_e_manifest(req.payloads, &signature_path)?;
        let manifest_digest = sha256_content_digest(&manifest);
        let cades = sign_detached_cades(*provider, &manifest_digest, req.signing_time)?;
        members.push((manifest_path, manifest));
        members.push((signature_path, cades));
    }

    for (index, provider) in req.xades_signers.iter().enumerate() {
        let n = index + 1;
        let signature_path = format!("META-INF/signatures{n:03}.xml");
        let signature_id = format!("asic-e-xades-sig-{n:03}");
        let xml = produce_detached_xades(
            *provider,
            req.payloads,
            req.signing_time,
            &signature_id,
            req.xades_level,
            req.xades_tsa,
            None,
        )?;
        members.push((signature_path, xml));
    }

    if let Some(archive_tsa) = req.archive_tsa {
        // The archive manifest covers every payload and every signature/manifest member produced so
        // far; the archive timestamp then attests the manifest's own digest.
        let mut references: Vec<AsicArchiveReference<'_>> = req
            .payloads
            .iter()
            .map(|p| AsicArchiveReference {
                uri: p.name,
                bytes: p.bytes,
                mime_type: p.mime_type,
            })
            .collect();
        for (path, bytes) in &members {
            references.push(AsicArchiveReference {
                uri: path.as_str(),
                bytes: bytes.as_slice(),
                mime_type: None,
            });
        }
        let archive_manifest =
            build_asic_archive_manifest(ASICE_ARCHIVE_TIMESTAMP_PATH, &references)?;
        let archive_digest = sha256_content_digest(&archive_manifest);
        let token = archive_tsa.timestamp_digest(&archive_digest)?;
        members.push((ASICE_ARCHIVE_MANIFEST_PATH.to_string(), archive_manifest));
        members.push((ASICE_ARCHIVE_TIMESTAMP_PATH.to_string(), token.token_der));
    }

    let borrowed: Vec<(&str, &[u8])> = members
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    assemble_asic_e_container(req.payloads, &borrowed)
}

/// Produce a single-signer ASiC-E container carrying one detached **XAdES-LT** signature over
/// `payloads` (the ETSI-conventional long-term form for archived atas/documents).
///
/// LT requires the signature timestamp (`tsa`) **and** caller-collected validation material — the
/// signer chain plus its OCSP responses / CRLs, typically gathered through
/// [`crate::revocation::RevocationEvidenceProvider`]. This function only embeds that material as
/// `xades:CertificateValues`/`xades:RevocationValues`; it never fetches revocation itself, so it
/// composes with the revocation caching that lives in [`crate::revocation`].
pub fn sign_asic_e_xades_lt(
    provider: &dyn SignerProvider,
    payloads: &[AsicPayload<'_>],
    signing_time: OffsetDateTime,
    tsa: &dyn TimestampProvider,
    material: &ValidationMaterial,
) -> Result<Vec<u8>, SigningError> {
    if payloads.is_empty() {
        return Err(SigningError::Asic(
            "ASiC-E XAdES-LT requires at least one payload".to_string(),
        ));
    }
    let xml = produce_detached_xades(
        provider,
        payloads,
        signing_time,
        "asic-e-xades-lt-sig-001",
        XadesLevel::LT,
        Some(tsa),
        Some(material),
    )?;
    let members: Vec<(&str, &[u8])> = vec![("META-INF/signatures001.xml", xml.as_slice())];
    assemble_asic_e_container(payloads, &members)
}

/// The media type an ASiC-E XAdES signature member declares (exposed for callers assembling their
/// own manifests).
pub const fn xades_member_mime_type() -> &'static str {
    XADES_SIGNATURE_MIME_TYPE
}

fn xades_err(e: chancela_xades::XadesError) -> SigningError {
    SigningError::Xades(e.to_string())
}
