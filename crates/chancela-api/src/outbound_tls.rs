//! Operator-suppliable TLS **intermediate** CA certificates for outbound HTTPS fetches.
//!
//! # The fault this exists for
//!
//! A TLS server is required to send its whole certificate chain except the root ([RFC 8446 §4.4.2]:
//! "the sender's certificate MUST come first … each following certificate SHOULD directly certify
//! the one immediately preceding it"). Some do not. The Portuguese Trusted List endpoint
//! (`https://www.gns.gov.pt/media/TSLPT.xml`) is one: it presents **only** the leaf, and omits the
//! `Sectigo Public Server Authentication CA` intermediate that issued it. The root is in every trust
//! store; the middle link is simply never sent, so no verifier can join the two.
//!
//! Browsers and `curl` usually succeed against such a server anyway, because OpenSSL and the
//! platform verifiers chase the missing issuer through the leaf's Authority Information Access
//! extension, or reuse an intermediate they cached from an earlier connection to an unrelated site.
//! **rustls deliberately implements neither**, so `reqwest` reports
//! `invalid peer certificate: UnknownIssuer` where a browser on the same machine loads the page.
//! That asymmetry is why an operator's first conclusion is "Chancela is broken" — see
//! [`incomplete_chain_guidance`], which exists to say otherwise in the error itself.
//!
//! # Why supplying an intermediate is NOT "skip certificate verification"
//!
//! This is the distinction the whole module turns on, and it is not a matter of degree.
//!
//! A configured intermediate is added to the **pool of candidate chain links** that path building
//! may draw on. It is *not* added to the root store. Every check therefore still applies, unchanged:
//!
//! - the chain must still terminate at a root **already in the operating system's trust store**
//!   ([`native_root_store`]) — a configured intermediate that chains to nothing there fails exactly
//!   as it would have without the configuration;
//! - the intermediate must actually have **signed** the leaf, and the root must actually have signed
//!   the intermediate — the signatures are verified, not asserted;
//! - the requested **hostname** must still match the leaf's subject alternative names;
//! - **validity dates**, basic constraints, path length and EKU are still enforced, for every
//!   certificate in the path.
//!
//! An attacker gains nothing from a configured intermediate. To exploit one they would need a leaf
//! certificate genuinely issued under it — which is to say, they would need the intermediate's
//! private key, and holding that already lets them mint certificates that every browser on earth
//! accepts. Configuring the public certificate of a CA that a public root already vouches for adds
//! no authority that the root did not already delegate.
//!
//! Supplying an intermediate is therefore categorically **not** the same act as the second thing
//! this module offers, below. It supplies a fact the server failed to send and leaves the proof
//! intact; it should always be preferred, and the operator-facing copy says so.
//!
//! # The second thing: skipping verification for one configured source
//!
//! [`OutboundTls::for_tsl_source`] can build a client that does **not** verify the peer's
//! certificate, for one Trusted List source whose operator opted in. That is a real reduction in
//! posture and it is described honestly in [`UnverifiedPeer`], which is the only place it can be
//! reached from. Two things make it a defensible option rather than a hole:
//!
//! - **A Trusted List's authenticity does not rest on TLS.** It rests on the list's own XML-DSig
//!   signature, checked against the operator's configured trust anchors. That check is mandatory,
//!   has no off switch anywhere in this product, and nothing in this module can see or affect it.
//!   An attacker who intercepts the fetch and substitutes a forged list still fails it, and
//!   qualified signing still refuses. Disabling *signature* verification would be a different
//!   proposition entirely, and is not on offer.
//! - **The scope is one source.** Not a global switch, not an environment variable, not the EU LOTL
//!   fetch, not an ad-hoc refresh URL, and not any other outbound client in the product — the
//!   connectors, the registry, the CAE and law corpora and SMTP cannot reach this type at all.
//!
//! The residual risks are real and are named rather than glossed: an attacker on the path can serve
//! a **genuine but older** list (which authenticates perfectly, and on which a since-withdrawn trust
//! service still reads as granted), and can **deny service**. Every trust surface reports
//! [`crate::trust::TslUnverifiedTransportView`] beside the verdict for as long as the setting is on,
//! because a one-time confirmation on a settings page is read once, by one person, possibly months
//! before the result anyone is looking at.
//!
//! SSRF vetting and pinned-address resolution are untouched in every posture. They defend against a
//! different attack and are not part of this trade.
//!
//! # Not a Trusted List trust anchor
//!
//! `signing.tls_intermediate_certs` is **transport** trust: it concerns the TLS certificate of the
//! web server that happens to host a file. `signing.tsl_trust_anchor_certs` is **content** trust: it
//! pins the certificate that signed the Trusted List's own XML-DSig signature. They are different
//! certificates, issued by different authorities, protecting different things, and neither can
//! substitute for the other. Nothing in this module touches [`chancela_tsl::TslTrustAnchors`].
//!
//! [RFC 8446 §4.4.2]: https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2

use std::sync::Arc;

use tokio_rustls::rustls;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};

/// How many `source()`/`get_ref()` hops [`is_incomplete_chain_error`] will follow. Same bound and
/// same reason as [`chancela_tsl::describe_error_chain`]: this runs while an operator waits.
const MAX_ERROR_CHAIN_DEPTH: usize = 12;

/// Operator-supplied intermediate CA certificates, parsed and ready to hand to path building.
///
/// Empty is the ordinary state and means "behave exactly as before": [`is_empty`](Self::is_empty)
/// callers keep the stock `reqwest` client and never construct a `rustls` configuration at all, so
/// an install that configures nothing here cannot be affected by anything in this module.
#[derive(Debug, Clone, Default)]
pub(crate) struct TlsIntermediates {
    certs: Vec<CertificateDer<'static>>,
}

impl TlsIntermediates {
    /// The empty set, spelled out.
    ///
    /// `#[cfg(test)]` because **no production path constructs one**: every outbound fetch resolves
    /// this from the settings document, and an install that has configured nothing resolves it to
    /// the empty set through [`parse`](Self::parse) like any other value. A production caller
    /// reaching for a literal "no intermediates" would be a caller that had skipped the settings
    /// read, which is the bug this arrangement makes impossible to write by accident.
    #[cfg(test)]
    pub(crate) fn none() -> Self {
        Self::default()
    }

    /// Parse the operator's PEM entries, exactly as they are stored in
    /// `signing.tls_intermediate_certs`.
    ///
    /// Each entry may carry one or more `-----BEGIN CERTIFICATE-----` blocks, or a single raw DER
    /// certificate — the same shape [`chancela_tsl::parse_anchor_certs`] accepts for trust anchors,
    /// because the operator already knows that shape from the anchor fields next door.
    ///
    /// Unlike an anchor, an intermediate is **used**, not merely fingerprinted, so this goes one
    /// check further and requires the bytes to parse as an X.509 certificate. A blob that is only
    /// valid base64 would be accepted as an anchor (it can never match, so it is inert) but would
    /// reach path building here and be silently ignored — the operator would configure the fix,
    /// see no change, and have nothing to look at. Fail loudly at the boundary instead.
    pub(crate) fn parse(pem_entries: &[String]) -> Result<Self, String> {
        let mut certs = Vec::new();
        for (index, entry) in pem_entries.iter().enumerate() {
            for der in parse_intermediate_entry(entry)
                .map_err(|e| format!("signing.tls_intermediate_certs[{index}] {e}"))?
            {
                certs.push(CertificateDer::from(der));
            }
        }
        Ok(Self { certs })
    }

    /// `true` when no intermediate is configured — the default. The outbound client is then built
    /// exactly as it was before this module existed.
    pub(crate) fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// The parsed certificates, for the verifier.
    fn certs(&self) -> &[CertificateDer<'static>] {
        &self.certs
    }
}

/// Decode one settings entry into DER certificates, rejecting anything that is not a certificate.
///
/// Shared by [`TlsIntermediates::parse`] and by settings validation, so a document that saves
/// cannot then fail to load: the same bytes go through the same two steps (decode, then parse as
/// X.509) in both places.
pub(crate) fn parse_intermediate_entry(entry: &str) -> Result<Vec<Vec<u8>>, String> {
    if entry.trim().is_empty() {
        return Err("must be a non-empty PEM or DER certificate".to_owned());
    }
    let ders = chancela_tsl::parse_anchor_certs(entry.as_bytes())
        .map_err(|e| format!("must be a valid PEM/DER certificate: {e}"))?;
    for der in &ders {
        // The decode above only proves the base64 was well-formed. An intermediate has to be a real
        // certificate for path building to be able to use it at all.
        <x509_cert::Certificate as x509_cert::der::Decode>::from_der(der)
            .map_err(|e| format!("must be a valid X.509 certificate: {e}"))?;
    }
    Ok(ders)
}

/// The outbound TLS posture for **one** fetch.
///
/// It is a value passed per call rather than a global, because the second field must never become
/// process-wide. Every construction site names which of the two it is building, and only one
/// constructor can produce an unverified posture — see [`for_tsl_source`](Self::for_tsl_source).
#[derive(Debug, Clone)]
pub(crate) struct OutboundTls {
    intermediates: TlsIntermediates,
    /// `true` only for a configured TSL source whose operator set `tls_skip_verification`.
    skip_verification: bool,
}

impl OutboundTls {
    /// The ordinary posture: the peer's certificate is fully verified, optionally completing its
    /// chain with the operator's intermediates.
    ///
    /// Every outbound fetch that is **not** a configured TSL source uses this — the EU LOTL fetch,
    /// an ad-hoc URL handed to `POST /v1/trust/refresh`, and every client outside this module.
    pub(crate) fn verified(intermediates: TlsIntermediates) -> Self {
        Self {
            intermediates,
            skip_verification: false,
        }
    }

    /// The posture for one configured TSL source, which is the **only** thing that can ask for
    /// verification to be skipped.
    ///
    /// `skip_verification` comes from `signing.tsl_sources[i].tls_skip_verification`, which settings
    /// validation has already constrained to an https URL-backed source. Taking the bool through a
    /// distinctly-named constructor rather than a public field is what keeps the blast radius
    /// legible: a reader can enumerate every unverified fetch in the product by finding the callers
    /// of this function.
    pub(crate) fn for_tsl_source(intermediates: TlsIntermediates, skip_verification: bool) -> Self {
        Self {
            intermediates,
            skip_verification,
        }
    }

    /// `true` when this posture needs no `rustls` configuration at all, so the stock `reqwest`
    /// client is used exactly as it was before this module existed.
    pub(crate) fn is_stock(&self) -> bool {
        self.intermediates.is_empty() && !self.skip_verification
    }

    /// `true` when the peer's certificate will not be verified.
    pub(crate) fn skips_verification(&self) -> bool {
        self.skip_verification
    }
}

/// Build the outbound `rustls` client configuration for `posture`, anchored in `roots`.
///
/// The provider is named explicitly (`ring`) rather than taken from the process default, for the
/// same reason `smtp::tls_config` names it: this workspace links both `ring` and `aws-lc-rs`, so
/// `CryptoProvider::get_default()` is a coin flip that depends on what some other crate installed.
pub(crate) fn outbound_client_config(
    posture: &OutboundTls,
    roots: RootCertStore,
) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier: Arc<dyn ServerCertVerifier> = if posture.skips_verification() {
        // The operator's explicit, per-source, save-validated opt-in. `roots` is deliberately
        // consumed and dropped here: there is no half-measure where some checking still happens and
        // an operator might believe more is verified than is.
        drop(roots);
        Arc::new(UnverifiedPeer {
            provider: provider.clone(),
        })
    } else {
        // `WebPkiServerVerifier` is the ordinary rustls verifier: roots, signatures, validity, basic
        // constraints and hostname. The wrapper below changes exactly one input to it.
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| format!("outbound TLS verifier could not be built: {e}"))?;
        Arc::new(ChainCompletingVerifier {
            inner,
            extra: posture.intermediates.certs().to_vec(),
        })
    };
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("outbound TLS protocol versions are unusable: {e}"))?
        // `dangerous()` is rustls's name for "you are supplying the verifier". For
        // `ChainCompletingVerifier` that is all it means — it delegates every decision to the
        // `WebPkiServerVerifier` built above. For `UnverifiedPeer` it means what it says.
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // `reqwest` sets ALPN from its own HTTP version preference, and a preconfigured configuration
    // bypasses that. This crate's `reqwest` has no `http2` feature, so the stock client advertises
    // `http/1.1` alone; match it, or a preconfigured client would negotiate differently from every
    // other outbound request in the process.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The operating system trust store, as the root anchors for outbound HTTPS.
///
/// Same source and same tolerance as `smtp::tls_config`: one unparseable OS certificate must not
/// take the whole store down, but an **empty** store is a hard error rather than a verifier that
/// rejects everything with a misleading `UnknownIssuer`.
pub(crate) fn native_root_store() -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err(
            "no trusted root certificates could be loaded from the operating system, so no \
             outbound TLS certificate can be verified"
                .to_owned(),
        );
    }
    Ok(roots)
}

/// A [`ServerCertVerifier`] that adds operator-supplied intermediates to the certificate pool the
/// inner verifier builds a path from, and changes nothing else.
///
/// Every method other than [`verify_server_cert`](Self::verify_server_cert) delegates verbatim, and
/// that one differs from a plain delegation in a single expression: the `intermediates` slice it
/// passes down is the server's own chain **plus** the configured certificates. The verdict — roots,
/// signatures, hostname, validity — is entirely the inner verifier's.
#[derive(Debug)]
struct ChainCompletingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    extra: Vec<CertificateDer<'static>>,
}

impl ServerCertVerifier for ChainCompletingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Path building treats this slice as an unordered pool of candidate links, so appending is
        // sufficient and the server's own ordering is preserved. Owned copies keep one lifetime for
        // both halves; the chains involved are a handful of certificates per handshake.
        let mut pool: Vec<CertificateDer<'static>> = intermediates
            .iter()
            .map(|cert| cert.clone().into_owned())
            .collect();
        for cert in &self.extra {
            if !pool.contains(cert) {
                pool.push(cert.clone());
            }
        }
        self.inner
            .verify_server_cert(end_entity, &pool, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.inner.root_hint_subjects()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

/// A [`ServerCertVerifier`] that accepts any certificate chain, for a source whose operator
/// explicitly opted out of transport authentication.
///
/// # Why this is permitted here and nowhere else
///
/// A Trusted List's authenticity is established by **its own XML-DSig signature**, checked against
/// the operator's configured trust anchors. That check is mandatory, has no off switch anywhere in
/// this product, and is unaffected by anything in this file. TLS on this fetch is defence in depth:
/// an attacker who intercepts it and substitutes a forged list still fails the anchor check, and
/// qualified signing still refuses. Removing that second layer is a real reduction in posture, and
/// it is not the same act as removing the first.
///
/// **What an attacker on the path gains, stated plainly:** they can serve a *genuine but older*
/// list — which authenticates perfectly, because it is genuine, and on which a since-withdrawn trust
/// service still reads as granted — and they can block or corrupt the response. They cannot make a
/// forged list authenticate.
///
/// Handshake signatures are still verified against the presented key (via the crypto provider's
/// algorithms), so the connection is still confidential and integrity-protected with respect to
/// whoever answered; what is given up is any assurance about *who that is*.
///
/// This is reachable only through [`OutboundTls::for_tsl_source`], only for a configured source,
/// only after settings validation has confirmed an https URL, and only with `signing.configure`.
/// SSRF vetting and pinned-address resolution still apply — they are a different protection against
/// a different attack and are not relaxed alongside this.
#[derive(Debug)]
struct UnverifiedPeer {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for UnverifiedPeer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// `true` when this transport failure is a server that did not send its full certificate chain.
///
/// `UnknownIssuer` means path building ran out of links before it reached a root: either the server
/// omitted an intermediate, or the chain genuinely does not lead anywhere trusted. The two are
/// indistinguishable from the client side — which is exactly why the remedy the copy offers is
/// "supply the missing intermediate", a step that fails safely if the second case is the true one.
///
/// Detection is by **type**, not by matching the rendered sentence: `rustls::Error` is carried down
/// the chain inside a `std::io::Error`, whose `source()` skips over its own custom payload, so the
/// walk has to reach through [`std::io::Error::get_ref`] as well.
///
/// Platform note: on Windows and macOS the default (no-intermediates) client uses the OS verifier,
/// which reports its own failures as `CertificateError::Other`, and this returns `false` for them.
/// The configured path — the one an operator reaches after reading the copy — always runs
/// `WebPkiServerVerifier`, which reports `UnknownIssuer` on every platform.
pub(crate) fn is_incomplete_chain_error(err: &(dyn std::error::Error + 'static)) -> bool {
    matches!(
        rustls_error_in_chain(err),
        Some(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer
        ))
    )
}

/// The English sentence appended to a transport failure that looks like an incomplete chain.
///
/// Returned as a suffix rather than replacing the technical text: the `UnknownIssuer` chain is still
/// what an operator pastes into a support thread. The browser/`curl` clause is load-bearing — the
/// first thing an operator does is open the URL in a browser, succeed, and conclude the product is
/// at fault.
pub(crate) fn incomplete_chain_guidance() -> &'static str {
    "the server did not send the intermediate certificate that links its certificate to a trusted \
     root, which is a misconfiguration at that server rather than at this installation; a browser \
     or curl may load the same address successfully because they fetch missing intermediates \
     automatically and this client does not; supply the missing intermediate certificate in \
     signing.tls_intermediate_certs"
}

/// Walk an error chain for a `rustls::Error`, reaching through `io::Error` payloads.
fn rustls_error_in_chain<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a rustls::Error> {
    let mut current = Some(err);
    let mut depth = 0usize;
    while let Some(e) = current {
        if depth >= MAX_ERROR_CHAIN_DEPTH {
            break;
        }
        depth += 1;
        if let Some(found) = e.downcast_ref::<rustls::Error>() {
            return Some(found);
        }
        // `impl Error for io::Error` returns the *source of* its custom payload, skipping the
        // payload itself — which is precisely the `rustls::Error` being looked for. Step into it.
        current = match e
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
        {
            Some(inner) => Some(inner),
            None => e.source(),
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid PEM block whose body decodes but is not a certificate. Accepted by the
    /// *anchor* fields (an anchor is only ever fingerprinted, so a non-certificate is inert there)
    /// and rejected here, because an intermediate that is not a certificate cannot complete a chain
    /// and would fail silently.
    const NOT_A_CERTIFICATE_PEM: &str =
        "-----BEGIN CERTIFICATE-----\naGVsbG8gdHJ1c3QgYW5jaG9y\n-----END CERTIFICATE-----";

    #[test]
    fn no_configuration_parses_to_the_empty_set() {
        let parsed = TlsIntermediates::parse(&[]).expect("empty configuration is valid");
        assert!(parsed.is_empty());
        assert!(TlsIntermediates::none().is_empty());
    }

    #[test]
    fn a_blank_entry_is_refused() {
        let error = TlsIntermediates::parse(&["   ".to_owned()])
            .expect_err("a blank entry cannot be a certificate");
        assert!(
            error.contains("signing.tls_intermediate_certs[0]"),
            "{error}"
        );
    }

    #[test]
    fn malformed_pem_is_refused() {
        let error = TlsIntermediates::parse(&["-----BEGIN CERTIFICATE-----\nAAAA".to_owned()])
            .expect_err("PEM with no END marker cannot be a certificate");
        assert!(
            error.contains("signing.tls_intermediate_certs[0]"),
            "{error}"
        );
    }

    #[test]
    fn well_formed_base64_that_is_not_a_certificate_is_refused() {
        let error = TlsIntermediates::parse(&[NOT_A_CERTIFICATE_PEM.to_owned()])
            .expect_err("base64 alone does not make a certificate");
        assert!(error.contains("valid X.509 certificate"), "{error}");
    }

    #[test]
    fn unknown_issuer_is_recognised_through_an_io_error_payload() {
        // The shape `reqwest` produces: the rustls error is the custom payload of an `io::Error`,
        // which `source()` alone steps straight past.
        let wrapped = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        assert!(is_incomplete_chain_error(&wrapped));
    }

    #[test]
    fn other_certificate_failures_are_not_reported_as_an_incomplete_chain() {
        // A name mismatch and an expired certificate are real rejections with different remedies.
        // Offering "supply the missing intermediate" for either would send the operator nowhere.
        for error in [
            rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName),
            rustls::Error::InvalidCertificate(rustls::CertificateError::Expired),
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature),
        ] {
            let wrapped = std::io::Error::new(std::io::ErrorKind::InvalidData, error.clone());
            assert!(
                !is_incomplete_chain_error(&wrapped),
                "{error:?} must not be reported as an incomplete chain"
            );
        }
    }

    #[test]
    fn a_transport_failure_with_no_tls_error_is_not_an_incomplete_chain() {
        let timeout = std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out");
        assert!(!is_incomplete_chain_error(&timeout));
    }

    #[test]
    fn the_guidance_names_the_setting_and_pre_empts_but_it_works_in_my_browser() {
        let guidance = incomplete_chain_guidance();
        assert!(
            guidance.contains("signing.tls_intermediate_certs"),
            "{guidance}"
        );
        assert!(guidance.contains("browser"), "{guidance}");
        assert!(guidance.contains("curl"), "{guidance}");
    }
}

/// End-to-end proof against a **real TLS handshake**, over a throwaway PKI.
///
/// These do not stub the verifier, the chain or the transport: a `rustls` server presents a genuine
/// certificate chain over a loopback socket and the ordinary bounded outbound client dials it. That
/// is the only way the central claim of this module can actually be tested — that supplying an
/// intermediate completes a chain **and nothing else**. A test against a mock would prove that the
/// mock was written to agree with the documentation.
///
/// Every certificate here is generated in-process from fixed key material. No real certificate is
/// committed to this repository, and in particular not the Sectigo intermediate whose absence from
/// the Portuguese Trusted List endpoint prompted the work.
#[cfg(test)]
mod handshake_tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::str::FromStr;
    use std::time::Duration;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{RootCertStore, ServerConfig};

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(10);

    // --- A throwaway three-tier PKI --------------------------------------------------------------

    /// One issued certificate: its DER and the key that signs whatever it issues next.
    struct Issued {
        der: Vec<u8>,
        key: p256::ecdsa::SigningKey,
        subject: String,
    }

    impl Issued {
        fn pem(&self) -> String {
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                B64.encode(&self.der)
            )
        }
    }

    fn signing_key(seed: u8) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("valid scalar")
    }

    /// Issue one certificate, signed by `issuer` (or self-signed when `issuer` is `None`).
    ///
    /// `ca` selects between a CA certificate (`BasicConstraints` CA, with a path-length constraint)
    /// and a leaf (`serverAuth` EKU plus an IP subject alternative name). `valid_from_days_ago` /
    /// `valid_for_days` exist so an expired leaf can be issued for the expiry test.
    // Eight parameters, deliberately positional and deliberately not bundled into a builder: this
    // is a certificate, and every one of them is a field of it. A struct would add a layer between
    // the test that says "an expired leaf for 127.0.0.2" and the bytes that express it.
    #[allow(clippy::too_many_arguments)]
    fn issue(
        subject: &str,
        serial: u8,
        key: &p256::ecdsa::SigningKey,
        issuer: Option<&Issued>,
        ca_path_len: Option<u8>,
        san_ip: Option<[u8; 4]>,
        valid_from_days_ago: i64,
        valid_for_days: i64,
    ) -> Issued {
        use der::Encode;
        use der::asn1::{Any, BitString, OctetString};
        use der::oid::ObjectIdentifier;
        use p256::ecdsa::signature::Signer;
        use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
        use x509_cert::certificate::{Certificate, TbsCertificate, Version};
        use x509_cert::ext::Extension;
        use x509_cert::ext::pkix::name::GeneralName;
        use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, SubjectAltName};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::{Time, Validity};

        const ID_CE_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
        const ID_CE_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
        const ID_CE_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
        const ID_KP_SERVER_AUTH: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
        const ECDSA_WITH_SHA256: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

        fn extension(oid: ObjectIdentifier, critical: bool, value: Vec<u8>) -> Extension {
            Extension {
                extn_id: oid,
                critical,
                extn_value: OctetString::new(value).expect("extension value"),
            }
        }

        let mut extensions = vec![extension(
            ID_CE_BASIC_CONSTRAINTS,
            true,
            BasicConstraints {
                ca: ca_path_len.is_some(),
                path_len_constraint: ca_path_len,
            }
            .to_der()
            .expect("basic constraints"),
        )];
        if ca_path_len.is_none() {
            extensions.push(extension(
                ID_CE_EXT_KEY_USAGE,
                false,
                ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH])
                    .to_der()
                    .expect("eku"),
            ));
        }
        if let Some(ip) = san_ip {
            extensions.push(extension(
                ID_CE_SUBJECT_ALT_NAME,
                false,
                SubjectAltName(vec![GeneralName::IpAddress(
                    OctetString::new(ip.to_vec()).expect("ip san"),
                )])
                .to_der()
                .expect("san"),
            ));
        }

        let day: i64 = 24 * 3600;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let utc_time = |seconds: i64| {
            Time::UtcTime(
                der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(
                    u64::try_from(seconds).expect("test validity is after the epoch"),
                ))
                .expect("utc time"),
            )
        };
        let not_before = now - valid_from_days_ago * day;
        let validity = Validity {
            not_before: utc_time(not_before),
            not_after: utc_time(not_before + valid_for_days * day),
        };

        let sig_alg = AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None::<Any>,
        };
        let (issuer_name, issuer_key) = match issuer {
            Some(parent) => (parent.subject.clone(), &parent.key),
            None => (subject.to_owned(), key),
        };
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[serial]).expect("serial"),
            signature: sig_alg.clone(),
            issuer: Name::from_str(&format!("CN={issuer_name}")).expect("issuer"),
            validity,
            subject: Name::from_str(&format!("CN={subject}")).expect("subject"),
            subject_public_key_info: SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())
                .expect("spki"),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };
        let tbs_der = tbs.to_der().expect("tbs der");
        let signature: p256::ecdsa::Signature = issuer_key.sign(&tbs_der);
        let der = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(signature.to_der().as_bytes()).expect("signature"),
        }
        .to_der()
        .expect("certificate der");
        Issued {
            der,
            key: key.clone(),
            subject: subject.to_owned(),
        }
    }

    fn pkcs8(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
        use p256::pkcs8::EncodePrivateKey;
        p256::SecretKey::from(key.as_nonzero_scalar())
            .to_pkcs8_der()
            .expect("pkcs8")
            .as_bytes()
            .to_vec()
    }

    /// Root → intermediate → leaf, plus the variants each test needs.
    struct Pki {
        root: Issued,
        intermediate: Issued,
        leaf: Issued,
    }

    /// `seed` keys the whole hierarchy, so a "rogue" PKI is a genuinely independent one rather than
    /// the same certificates relabelled.
    fn pki(seed: u8, leaf_san: [u8; 4], leaf_from_days_ago: i64, leaf_valid_days: i64) -> Pki {
        let root = issue(
            &format!("Chancela Test Root {seed}"),
            1,
            &signing_key(seed),
            None,
            Some(1),
            None,
            1,
            365,
        );
        let intermediate = issue(
            &format!("Chancela Test Intermediate {seed}"),
            2,
            &signing_key(seed.wrapping_add(1)),
            Some(&root),
            Some(0),
            None,
            1,
            365,
        );
        let leaf = issue(
            "chancela-test-endpoint",
            3,
            &signing_key(seed.wrapping_add(2)),
            Some(&intermediate),
            None,
            Some(leaf_san),
            leaf_from_days_ago,
            leaf_valid_days,
        );
        Pki {
            root,
            intermediate,
            leaf,
        }
    }

    // --- A real TLS server -----------------------------------------------------------------------

    /// Serve one fixed HTTP response over TLS on loopback, presenting `chain` verbatim.
    ///
    /// `chain` is what makes the whole exercise meaningful: the leak this module addresses is a
    /// server whose chain is `[leaf]` when it should be `[leaf, intermediate]`, and that is
    /// expressible here exactly.
    fn serve(chain: Vec<Vec<u8>>, key: Vec<u8>) -> u16 {
        serve_body(chain, key, b"trusted-list")
    }

    /// [`serve`] with an explicit response body, so a test can put a real Trusted List on the wire.
    fn serve_body(chain: Vec<Vec<u8>>, key: Vec<u8>, body: &'static [u8]) -> u16 {
        let config = ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            chain.into_iter().map(CertificateDer::from).collect(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .expect("server certificate");
        let config = std::sync::Arc::new(config);

        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            for socket in listener.incoming().flatten() {
                let config = config.clone();
                // A rejected handshake is an expected outcome in most of these tests, so every
                // failure here is swallowed: the verdict under test is the client's.
                let _ = (|| -> std::io::Result<()> {
                    let conn = rustls::ServerConnection::new(config)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    let mut stream = rustls::StreamOwned::new(conn, socket);
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];
                    while !request.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte)? == 0 {
                            break;
                        }
                        request.push(byte[0]);
                    }
                    stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )?;
                    stream.write_all(body)?;
                    stream.flush()
                })();
            }
        });
        port
    }

    /// A root store holding exactly one certificate — the stand-in for "already in the operating
    /// system's trust store".
    fn roots_of(cert: &Issued) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert.der.clone()))
            .expect("test root");
        roots
    }

    /// Dial the loopback server through the ordinary vetted outbound client and return the body.
    fn fetch(
        port: u16,
        intermediates: &TlsIntermediates,
        roots: RootCertStore,
    ) -> Result<String, String> {
        fetch_with(
            port,
            &OutboundTls::verified(intermediates.clone()),
            roots,
            |bytes| String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    /// The same dial under an arbitrary posture, returning the raw body through `map`.
    fn fetch_with<T>(
        port: u16,
        posture: &OutboundTls,
        roots: RootCertStore,
        map: impl FnOnce(Vec<u8>) -> T,
    ) -> Result<T, String> {
        let url = format!("https://127.0.0.1:{port}/tsl.xml");
        // Loopback is refused by the SSRF policy; this is the same debug-only allowance every other
        // local-endpoint test in this crate uses, and it expires with the guard. Note that the
        // allowance is needed even in the skip-verification tests — that setting does not touch
        // SSRF vetting, which is exactly the separation being relied on here.
        let _allowance =
            crate::trust::allow_local_trust_url_for_tests(&url).expect("loopback test allowance");
        let vetted = crate::trust::validate_outbound_http_url(&url).map_err(|e| e.to_string())?;
        let client = vetted.client_with_tls_and_roots(TIMEOUT, posture, roots)?;
        let response = client
            .get(vetted.as_str())
            .send()
            .map_err(|e| format!("{e}: {:?}", std::error::Error::source(&e)))?;
        let bytes = response.bytes().map_err(|e| e.to_string())?;
        Ok(map(bytes.to_vec()))
    }

    fn intermediates_from(certs: &[&Issued]) -> TlsIntermediates {
        let pems: Vec<String> = certs.iter().map(|c| c.pem()).collect();
        TlsIntermediates::parse(&pems).expect("generated certificates parse")
    }

    // --- The tests -------------------------------------------------------------------------------

    /// The control. A correctly configured server — one that sends its intermediate, as RFC 8446
    /// requires — needs no configuration at all. Without this, a green result below could equally
    /// mean the harness accepts everything.
    #[test]
    fn a_server_that_sends_its_full_chain_needs_no_configuration() {
        let pki = pki(0x10, [127, 0, 0, 1], 1, 365);
        let port = serve(
            vec![pki.leaf.der.clone(), pki.intermediate.der.clone()],
            pkcs8(&pki.leaf.key),
        );
        let body = fetch(port, &TlsIntermediates::none(), roots_of(&pki.root))
            .expect("a complete chain verifies with no operator configuration");
        assert_eq!(body, "trusted-list");
    }

    /// The reported fault, reproduced: the server sends its leaf alone and the fetch fails. This is
    /// the "before" half of the pair — without it, the success below would not prove that the
    /// setting is what fixed anything.
    #[test]
    fn a_leaf_only_server_fails_when_no_intermediate_is_supplied() {
        let pki = pki(0x20, [127, 0, 0, 1], 1, 365);
        let port = serve(vec![pki.leaf.der.clone()], pkcs8(&pki.leaf.key));
        let error = fetch(port, &TlsIntermediates::none(), roots_of(&pki.root))
            .expect_err("a chain missing its middle link cannot be built");
        assert!(
            error.contains("UnknownIssuer"),
            "the failure must be the missing issuer, not something else: {error}"
        );
    }

    /// The fix. Same server, same missing link, and the operator supplies it in settings.
    #[test]
    fn a_leaf_only_server_succeeds_when_the_intermediate_is_supplied() {
        let pki = pki(0x30, [127, 0, 0, 1], 1, 365);
        let port = serve(vec![pki.leaf.der.clone()], pkcs8(&pki.leaf.key));
        let body = fetch(
            port,
            &intermediates_from(&[&pki.intermediate]),
            roots_of(&pki.root),
        )
        .expect("the supplied intermediate completes the chain");
        assert_eq!(body, "trusted-list");
    }

    /// **The test this whole design has to pass.**
    ///
    /// A configured intermediate is a chain link, not a trust root. Here the server presents a leaf
    /// issued by an intermediate the operator has configured — and that intermediate belongs to an
    /// entirely separate hierarchy whose root the trust store has never heard of. If configuring an
    /// intermediate were a bypass, or if it were quietly added to the root store, this handshake
    /// would succeed. It must not: the chain still has to reach a root that was already trusted.
    #[test]
    fn a_supplied_intermediate_that_reaches_no_trusted_root_is_still_refused() {
        let genuine = pki(0x40, [127, 0, 0, 1], 1, 365);
        let rogue = pki(0x50, [127, 0, 0, 1], 1, 365);
        let port = serve(vec![rogue.leaf.der.clone()], pkcs8(&rogue.leaf.key));

        let error = fetch(
            port,
            // The operator configures the rogue intermediate — the exact certificate that issued the
            // leaf being presented. Path building can now join leaf → intermediate, and then has
            // nowhere to go: the rogue root is not in the store.
            &intermediates_from(&[&rogue.intermediate]),
            roots_of(&genuine.root),
        )
        .expect_err("an intermediate is not a root and cannot terminate a chain");
        assert!(
            error.contains("UnknownIssuer"),
            "the chain must fail for want of a trusted root: {error}"
        );

        // And the same intermediate, supplied alongside the rogue ROOT, is still refused — proving
        // it is the trust store that decides, not the settings document. A configured certificate
        // never becomes an anchor, whatever it is.
        let error = fetch(
            port,
            &intermediates_from(&[&rogue.intermediate, &rogue.root]),
            roots_of(&genuine.root),
        )
        .expect_err("supplying the rogue root as an intermediate must not anchor it either");
        assert!(error.contains("UnknownIssuer"), "{error}");
    }

    /// The whole chain of custody for the operator-facing diagnosis, over a **real** rejected
    /// handshake: rustls refuses the connection, the classifier recognises it by type, the
    /// `TslError` variant survives into `SigningError`, and `code()` yields the stable code the
    /// client has copy for.
    ///
    /// Each of those hops is tested in isolation elsewhere. This is the one that would catch the
    /// hops being individually correct and not actually joined up — which is precisely what the
    /// original defect was: `UnknownIssuer` was accurately reported, all the way to an operator who
    /// could do nothing with it.
    #[test]
    fn a_real_incomplete_chain_reaches_the_stable_operator_facing_code() {
        let pki = pki(0x80, [127, 0, 0, 1], 1, 365);
        let port = serve(vec![pki.leaf.der.clone()], pkcs8(&pki.leaf.key));

        let url = format!("https://127.0.0.1:{port}/tsl.xml");
        let _allowance =
            crate::trust::allow_local_trust_url_for_tests(&url).expect("loopback test allowance");
        let vetted = crate::trust::validate_outbound_http_url(&url).expect("vetted loopback URL");
        let client = vetted
            .client_with_tls_and_roots(
                TIMEOUT,
                &OutboundTls::verified(TlsIntermediates::none()),
                roots_of(&pki.root),
            )
            .expect("client builds");
        let error = client
            .get(vetted.as_str())
            .send()
            .expect_err("the leaf-only chain is refused");

        let classified = crate::trust::classify_fetch_error(error);
        assert!(
            matches!(classified, chancela_tsl::TslError::TlsChainIncomplete(_)),
            "a real UnknownIssuer must classify as an incomplete chain, not a generic fetch \
             failure: {classified:?}"
        );

        // The message an operator actually reads: the technical cause, then what to do about it,
        // then the reason their browser disagrees.
        let message = classified.to_string();
        assert!(message.contains("UnknownIssuer"), "{message}");
        assert!(
            message.contains("signing.tls_intermediate_certs"),
            "{message}"
        );
        assert!(message.contains("browser"), "{message}");

        assert_eq!(
            chancela_signing::SigningError::from_tsl(classified).code(),
            chancela_signing::SIGNING_TRUSTED_LIST_TLS_CHAIN,
            "the signing path must report the dedicated code, not signing_trusted_list_unavailable"
        );
    }

    /// The complement of the test above, and the reason it is not merely a broken harness reporting
    /// a green refusal.
    ///
    /// The same rogue server, the same supplied intermediate — and this time the rogue root really is
    /// in the trust store. It succeeds. So the refusal above was decided by **the root store and
    /// nothing else**: identical chain, identical settings, one variable changed. An implementation
    /// that quietly added configured certificates to the root store would pass that test and fail
    /// this one's premise; an implementation that rejected everything would fail this one.
    #[test]
    fn the_same_rogue_chain_verifies_once_its_own_root_is_actually_trusted() {
        let rogue = pki(0x50, [127, 0, 0, 1], 1, 365);
        let port = serve(vec![rogue.leaf.der.clone()], pkcs8(&rogue.leaf.key));
        let body = fetch(
            port,
            &intermediates_from(&[&rogue.intermediate]),
            roots_of(&rogue.root),
        )
        .expect("the chain is well-formed; only the trusted root was missing before");
        assert_eq!(body, "trusted-list");
    }

    // --- The per-source opt-out ------------------------------------------------------------------

    /// The switch does what it says: a server whose certificate no verified client would accept —
    /// wrong root, and not even the right name — is reached.
    ///
    /// Both halves matter. The `expect_err` is what proves the posture is the only difference; a test
    /// that only showed the success would pass equally against a server the default client already
    /// trusted.
    #[test]
    fn skipping_verification_reaches_a_server_no_verified_client_would_accept() {
        let rogue = pki(0x90, [127, 0, 0, 2], 1, 365);
        let genuine = pki(0x91, [127, 0, 0, 1], 1, 365);
        let port = serve(vec![rogue.leaf.der.clone()], pkcs8(&rogue.leaf.key));

        let refused = fetch_with(
            port,
            &OutboundTls::verified(TlsIntermediates::none()),
            roots_of(&genuine.root),
            |_| (),
        )
        .expect_err("an untrusted, wrongly-named certificate is refused by default");
        assert!(refused.contains("UnknownIssuer"), "{refused}");

        let body = fetch_with(
            port,
            &OutboundTls::for_tsl_source(TlsIntermediates::none(), true),
            roots_of(&genuine.root),
            |bytes| String::from_utf8_lossy(&bytes).into_owned(),
        )
        .expect("the operator opted this source out of transport authentication");
        assert_eq!(body, "trusted-list");
    }

    /// **THE LINE.** There is no combination of settings that turns off both TLS verification and
    /// Trusted List anchor verification, and this is the test that goes looking for one.
    ///
    /// It configures the weakest state the product can be put into — `tls_skip_verification` on, and
    /// **no trust anchor at all** — then serves a real, well-formed, internally-consistent Trusted
    /// List over a certificate nothing trusts. The bytes arrive: that is the switch working. The list
    /// is then still refused, because the anchor check is mandatory and has no off switch anywhere in
    /// this product.
    ///
    /// The proof is in four parts, because "it errored" on its own would be worth very little — an
    /// empty response or a truncated body would error too, and would prove nothing about anchoring.
    #[test]
    fn the_anchor_check_still_refuses_when_tls_verification_is_off_and_no_anchor_is_configured() {
        let rogue = pki(0xa0, [127, 0, 0, 1], 1, 365);
        let genuine = pki(0xa1, [127, 0, 0, 1], 1, 365);
        let port = serve_body(
            vec![rogue.leaf.der.clone()],
            pkcs8(&rogue.leaf.key),
            crate::trust::BUNDLED_PT_TSL,
        );

        // 1. The switch really is on and really does work: a certificate nothing trusts is accepted
        //    and the body arrives. If this failed, everything below would be vacuous.
        let fetched = fetch_with(
            port,
            &OutboundTls::for_tsl_source(TlsIntermediates::none(), true),
            roots_of(&genuine.root),
            |bytes| bytes,
        )
        .expect("the switch is on, so the bytes arrive over an unauthenticated transport");
        assert_eq!(
            fetched.as_slice(),
            crate::trust::BUNDLED_PT_TSL,
            "the transport delivered the list intact"
        );

        // 2. What arrived is a real, parseable Trusted List with real content — not junk that would
        //    have been rejected by anything at all.
        let parsed = chancela_tsl::parse_tsl(&fetched).expect("a genuine Trusted List crossed");
        assert!(
            parsed.services().count() > 0,
            "the fixture must carry services, or 'it was refused' says nothing"
        );

        // 3. In the weakest configuration the product permits — TLS verification off AND no anchor
        //    configured anywhere — that list is still refused.
        let no_anchors = chancela_tsl::TslTrustAnchors::new();
        assert!(no_anchors.is_empty());
        assert!(
            chancela_tsl::validate_tsl_signature_with_anchors(&fetched, &no_anchors).is_err(),
            "a list obtained over an unverified transport must not authenticate for free"
        );

        // 4. And that refusal is not a property of this fixture. An empty anchor set anchors
        //    NOTHING, so no list — however perfectly signed, however genuine — can pass it. This is
        //    the structural half of the claim: the only settings that exist ADD anchors, so there is
        //    no configuration reachable from here in which this check is satisfied vacuously.
        for signer in [
            rogue.leaf.der.as_slice(),
            genuine.root.der.as_slice(),
            crate::trust::BUNDLED_PT_TSL,
        ] {
            assert!(
                !no_anchors.is_anchored(signer),
                "an empty anchor set must anchor nothing whatsoever"
            );
        }
    }

    /// SSRF vetting and pinned-address resolution are a separate protection and are **not** part of
    /// the trade. An operator who turns off certificate verification for a source has not thereby
    /// permitted this installation to be pointed at a cloud metadata endpoint or an internal host.
    #[test]
    fn skipping_verification_does_not_relax_ssrf_vetting() {
        // The canonical SSRF target, plus a private-range host. Neither is reachable in any posture,
        // and the refusal happens in `validate_outbound_http_url` — before a client exists at all,
        // which is why no posture can influence it.
        for url in [
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/tsl.xml",
            "https://127.0.0.1/tsl.xml",
        ] {
            let refused = crate::trust::validate_outbound_http_url(url)
                .expect_err("a disallowed address is refused whatever the TLS posture");
            assert!(refused.contains("unsafe outbound URL"), "{url}: {refused}");
        }
    }

    /// The two postures are distinct values and cannot be confused for one another; only
    /// [`OutboundTls::for_tsl_source`] can produce an unverified one, and only when asked.
    #[test]
    fn only_the_source_constructor_can_produce_an_unverified_posture() {
        assert!(!OutboundTls::verified(TlsIntermediates::none()).skips_verification());
        assert!(!OutboundTls::for_tsl_source(TlsIntermediates::none(), false).skips_verification());
        assert!(OutboundTls::for_tsl_source(TlsIntermediates::none(), true).skips_verification());
        // A posture that skips verification is never "stock", so it can never silently fall through
        // to the ordinary verifying `reqwest` client and appear to work while doing something else.
        assert!(OutboundTls::verified(TlsIntermediates::none()).is_stock());
        assert!(!OutboundTls::for_tsl_source(TlsIntermediates::none(), true).is_stock());
    }

    /// Hostname verification is untouched. The chain is complete and trusted, and the certificate is
    /// simply not for the address that was dialled.
    #[test]
    fn hostname_verification_still_applies_with_an_intermediate_supplied() {
        let pki = pki(0x60, [127, 0, 0, 2], 1, 365);
        let port = serve(vec![pki.leaf.der.clone()], pkcs8(&pki.leaf.key));
        let error = fetch(
            port,
            &intermediates_from(&[&pki.intermediate]),
            roots_of(&pki.root),
        )
        .expect_err("a certificate for 127.0.0.2 must not be accepted for 127.0.0.1");
        assert!(
            error.contains("NotValidForName"),
            "the failure must name the mismatch: {error}"
        );
        assert!(
            !error.contains("UnknownIssuer"),
            "a name mismatch must not be reported as an incomplete chain: {error}"
        );
    }

    /// Validity dates are untouched. The chain is complete and trusted, and the leaf expired
    /// yesterday.
    #[test]
    fn expiry_still_applies_with_an_intermediate_supplied() {
        let pki = pki(0x70, [127, 0, 0, 1], 30, 29);
        let port = serve(vec![pki.leaf.der.clone()], pkcs8(&pki.leaf.key));
        let error = fetch(
            port,
            &intermediates_from(&[&pki.intermediate]),
            roots_of(&pki.root),
        )
        .expect_err("an expired leaf must not be accepted");
        assert!(
            error.contains("Expired"),
            "the failure must name the expiry: {error}"
        );
    }
}
