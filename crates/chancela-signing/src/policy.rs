//! The trusted-list policy gate (SIG-11/23).
//!
//! Before a qualified signature is trusted, the signer's issuing CA must be a currently-granted
//! QTSP for e-signatures on the Portuguese Trusted List. [`TrustPolicy`] abstracts that decision so
//! the envelope engine stays testable offline: [`TslTrustPolicy`] resolves it against a live/parsed
//! TSL via `chancela-tsl`, while [`StaticTrustPolicy`] returns a fixed status in tests.

use std::fmt;

use time::OffsetDateTime;

use chancela_tsl::{TslClient, TslSource, TslTrustAnchors};

use crate::{SigningError, TrustedListStatus};

/// Where the trust anchors that authenticate the Trusted List's own XML-DSig signature came from.
///
/// Carried on [`SigningError::TrustAnchorNotConfigured`] and
/// [`SigningError::TrustedListNotAnchored`] so an operator can tell an **absent** anchor from a
/// **stale** one, and so a diagnostic can name the configuration surface they actually have to
/// edit rather than guessing between the settings document and the process environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TrustAnchorSource {
    /// The caller pinned an already-resolved anchor set onto the client
    /// ([`chancela_tsl::TslClient::with_anchors`]). In this application that set is the union of
    /// the `signing.tsl_trust_anchor_certs` / `signing.tsl_trust_anchor_sha256` settings fields
    /// with the environment anchors (t61-e1), so it is the operator's own configuration.
    ApplicationSettings,
    /// No anchor set was pinned, so the policy resolves anchors from the process environment
    /// alone (`CHANCELA_TSL_TRUST_ANCHOR` / `CHANCELA_TSL_TRUST_ANCHOR_SHA256`).
    Environment,
}

impl TrustAnchorSource {
    /// A stable machine token (`"application_settings"` / `"environment"`) for callers that map
    /// this onto user-facing copy without matching on the variant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApplicationSettings => "application_settings",
            Self::Environment => "environment",
        }
    }
}

impl fmt::Display for TrustAnchorSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ApplicationSettings => "application settings unioned with the environment",
            Self::Environment => "the process environment",
        })
    }
}

/// Resolves whether a signer's issuer is currently trusted for qualified e-signatures (SIG-11/23).
///
/// Object-safe: the envelope engine holds it as `&mut dyn TrustPolicy` (mutable because a real TSL
/// client refreshes its cache on lookup).
pub trait TrustPolicy {
    /// The trusted-list status of `issuer_cert_der` (the signer's issuing-CA certificate) as of
    /// `now`.
    fn issuer_status(
        &mut self,
        issuer_cert_der: &[u8],
        now: OffsetDateTime,
    ) -> Result<TrustedListStatus, SigningError>;
}

/// A [`TrustPolicy`] backed by the real Portuguese Trusted List via a `chancela-tsl`
/// [`TslClient`]. The `chancela-tsl` [`chancela_tsl::QualifiedStatus`] maps 1:1 onto
/// [`TrustedListStatus`] (t4-e5).
pub struct TslTrustPolicy<S: TslSource> {
    client: TslClient<S>,
}

impl<S: TslSource> TslTrustPolicy<S> {
    /// Build a policy over a TSL source (its own cache starts empty and is filled on first query).
    pub fn new(source: S) -> Self {
        Self {
            client: TslClient::new(source),
        }
    }

    /// Build a policy over an already-constructed [`TslClient`].
    pub fn from_client(client: TslClient<S>) -> Self {
        Self { client }
    }

    /// Borrow the underlying client.
    pub fn client(&self) -> &TslClient<S> {
        &self.client
    }

    /// The anchor set this policy authenticates the Trusted List against, and where it came from.
    ///
    /// Mirrors [`TslClient::refresh`]'s own resolution exactly — a pinned set is used as-is, an
    /// unpinned client reads the environment — so the answer describes the anchors that were
    /// actually applied. Consulted only on the failure path, to say *why* the list could not be
    /// authenticated.
    ///
    /// An anchor that is configured but unparseable is neither absent nor mismatched, so it
    /// surfaces as the underlying [`SigningError::TrustedList`] parse failure rather than being
    /// forced into one of the two answers.
    fn resolved_anchors(&self) -> Result<(TrustAnchorSource, usize), SigningError> {
        match self.client.anchors() {
            Some(anchors) => Ok((TrustAnchorSource::ApplicationSettings, anchors.len())),
            None => TslTrustAnchors::from_env()
                .map(|anchors| (TrustAnchorSource::Environment, anchors.len()))
                .map_err(|e| SigningError::TrustedList(e.to_string())),
        }
    }
}

impl<S: TslSource> TrustPolicy for TslTrustPolicy<S> {
    /// Resolve the issuer's trusted-list status, **discriminating the three distinct ways this
    /// gate fails** (t61-e2).
    ///
    /// Until this discriminator existed every caller collapsed all three into
    /// [`SigningError::UntrustedService`], whose message names the *signer's* trust service. That
    /// is true for exactly one of them:
    ///
    /// - **no anchor configured anywhere** → [`SigningError::TrustAnchorNotConfigured`]; the
    ///   operator has provisioned nothing, so no list can ever authenticate.
    /// - **anchors configured, list does not authenticate against them** →
    ///   [`SigningError::TrustedListNotAnchored`]; a wrong anchor, or a scheme-key rotation whose
    ///   new signing certificate is not anchored yet. This is the case that hits real operators,
    ///   and blaming the signer's service for it misdirects the diagnosis entirely.
    /// - **list authenticates, service genuinely not granted** → `Ok(status)`, which every caller
    ///   turns into [`SigningError::UntrustedService`] — now the only case that error describes.
    ///
    /// An unauthenticated list is not evidence about anybody: when the signature did not verify,
    /// the status resolved from it is discarded rather than reported, because
    /// [`TslClient::is_qualified_for_esig`] has already downgraded `Granted → Unknown` and a
    /// `Withdrawn` read off an unauthenticated list says nothing either. Fail-closed is unchanged
    /// throughout — every path that previously refused still refuses.
    fn issuer_status(
        &mut self,
        issuer_cert_der: &[u8],
        now: OffsetDateTime,
    ) -> Result<TrustedListStatus, SigningError> {
        let status: TrustedListStatus = self
            .client
            .is_qualified_for_esig(issuer_cert_der, now)
            .map_err(|e| SigningError::TrustedList(e.to_string()))?
            .into();

        if self
            .client
            .cached()
            .is_some_and(|cached| cached.signature_valid())
        {
            return Ok(status);
        }

        let (source, configured) = self.resolved_anchors()?;
        if configured == 0 {
            Err(SigningError::TrustAnchorNotConfigured { checked: source })
        } else {
            Err(SigningError::TrustedListNotAnchored {
                configured_in: source,
                anchor_count: configured,
            })
        }
    }
}

/// A [`TrustPolicy`] that always returns a fixed status, for offline tests and for callers that
/// resolve trust out-of-band.
#[derive(Debug, Clone, Copy)]
pub struct StaticTrustPolicy {
    status: TrustedListStatus,
}

impl StaticTrustPolicy {
    /// A policy that always reports `status`.
    pub fn new(status: TrustedListStatus) -> Self {
        Self { status }
    }

    /// A policy that always reports [`TrustedListStatus::Granted`].
    pub fn granted() -> Self {
        Self::new(TrustedListStatus::Granted)
    }

    /// A policy that always reports [`TrustedListStatus::Withdrawn`].
    pub fn withdrawn() -> Self {
        Self::new(TrustedListStatus::Withdrawn)
    }
}

impl TrustPolicy for StaticTrustPolicy {
    fn issuer_status(
        &mut self,
        _issuer_cert_der: &[u8],
        _now: OffsetDateTime,
    ) -> Result<TrustedListStatus, SigningError> {
        Ok(self.status)
    }
}

#[cfg(test)]
mod trust_anchor_discrimination_tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use chancela_tsl::BytesTslSource;

    use super::*;

    /// The DER standing in for the signer's issuing CA. The list below identifies its `CA/QC`
    /// service by certificate equality, so this need not be a real certificate.
    const ISSUER_DER: &[u8] = b"chancela-test-issuing-ca-der";

    /// A parseable Trusted List that grants [`ISSUER_DER`] for e-signatures and carries **no**
    /// XML-DSig signature at all, so it can never authenticate against any anchor.
    ///
    /// Granting the issuer is deliberate: it is the sharpest form of case A/B. The list *claims*
    /// the signer's service is granted, so any error naming that service as inactive is not merely
    /// unhelpful — it is false. The only real fault is the anchor configuration.
    fn unauthenticatable_list_granting_issuer() -> BytesTslSource {
        BytesTslSource::new(
            format!(
                concat!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>"#,
                    r#"<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">"#,
                    "<SchemeInformation>",
                    "<SchemeTerritory>PT</SchemeTerritory>",
                    "<ListIssueDateTime>2026-01-15T00:00:00Z</ListIssueDateTime>",
                    "<NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate>",
                    "</SchemeInformation>",
                    "<TrustServiceProviderList><TrustServiceProvider><TSPInformation>",
                    r#"<TSPName><Name xml:lang="en">Chancela Test QTSP</Name></TSPName>"#,
                    "</TSPInformation><TSPServices><TSPService><ServiceInformation>",
                    "<ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>",
                    r#"<ServiceName><Name xml:lang="en">Chancela Test CA</Name></ServiceName>"#,
                    "<ServiceDigitalIdentity><DigitalId><X509Certificate>{}</X509Certificate></DigitalId></ServiceDigitalIdentity>",
                    "<ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>",
                    "<StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime>",
                    r#"<ServiceInformationExtensions><Extension Critical="false"><AdditionalServiceInformation>"#,
                    r#"<URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</URI>"#,
                    "</AdditionalServiceInformation></Extension></ServiceInformationExtensions>",
                    "</ServiceInformation></TSPService></TSPServices>",
                    "</TrustServiceProvider></TrustServiceProviderList>",
                    "</TrustServiceStatusList>",
                ),
                BASE64_STANDARD.encode(ISSUER_DER)
            )
            .into_bytes(),
        )
    }

    fn now() -> OffsetDateTime {
        time::macros::datetime!(2026-07-28 12:00:00 UTC)
    }

    /// **Case A** — nothing configured anywhere. The pinned set is explicitly empty, which is what
    /// `build_trust_policy` resolves for an install with no `signing.tsl_trust_anchor_*` fields and
    /// no environment anchors, so this holds regardless of the test runner's environment.
    #[test]
    fn no_anchor_configured_reports_the_missing_configuration_not_the_signer() {
        let mut policy = TslTrustPolicy::from_client(
            TslClient::new(unauthenticatable_list_granting_issuer())
                .with_anchors(TslTrustAnchors::new()),
        );

        let err = policy
            .issuer_status(ISSUER_DER, now())
            .expect_err("an unauthenticatable list must never yield a trusted status");

        assert_eq!(
            err,
            SigningError::TrustAnchorNotConfigured {
                checked: TrustAnchorSource::ApplicationSettings,
            },
            "no anchor anywhere must be reported as the operator's missing configuration"
        );
    }

    /// **Case B** — an anchor *is* configured, it just does not authenticate this list. This is the
    /// mid-rotation state: the scheme published a list signed by a new certificate the operator has
    /// not provisioned yet.
    #[test]
    fn configured_but_non_matching_anchor_reports_a_stale_anchor_not_the_signer() {
        let mut policy = TslTrustPolicy::from_client(
            TslClient::new(unauthenticatable_list_granting_issuer())
                .with_anchors(TslTrustAnchors::new().with_cert_der(b"a previously-valid anchor")),
        );

        let err = policy
            .issuer_status(ISSUER_DER, now())
            .expect_err("a list that does not authenticate must never yield a trusted status");

        assert_eq!(
            err,
            SigningError::TrustedListNotAnchored {
                configured_in: TrustAnchorSource::ApplicationSettings,
                anchor_count: 1,
            },
            "a configured anchor that does not match must not be reported as no anchor at all"
        );
    }

    /// A and B must be **different errors**, and neither may be [`SigningError::UntrustedService`]
    /// — the error that names the signer's service, which is case C's and only case C's.
    #[test]
    fn the_three_trust_failures_are_mutually_distinguishable() {
        let source = unauthenticatable_list_granting_issuer();

        let mut absent = TslTrustPolicy::from_client(
            TslClient::new(source.clone()).with_anchors(TslTrustAnchors::new()),
        );
        let mut stale = TslTrustPolicy::from_client(
            TslClient::new(source).with_anchors(TslTrustAnchors::new().with_cert_der(b"stale")),
        );

        let absent = absent.issuer_status(ISSUER_DER, now()).expect_err("case A");
        let stale = stale.issuer_status(ISSUER_DER, now()).expect_err("case B");

        assert_ne!(absent, stale, "A and B must not collapse into one another");
        for err in [&absent, &stale] {
            assert!(
                !matches!(err, SigningError::UntrustedService { .. }),
                "an anchor-configuration fault must not be reported as the signer's service being \
                 untrusted: {err:?}"
            );
        }
        // Case C is the surviving `UntrustedService`: the discriminator returns `Ok(status)`
        // whenever the list authenticated, and every raise site (unchanged by t61-e2) turns a
        // non-`Granted` status into `UntrustedService { status }`. It is produced end to end,
        // through the real `build_trust_policy`, by `trust_anchor_failure_states_are_distinct` in
        // `chancela-api/src/signature.rs`.
    }

    /// An unpinned client resolves anchors from the environment, and must **say so** — an operator
    /// who configured the settings fields but is being served by the environment resolver can only
    /// tell from this. Deterministic either way: the runner's environment decides which of the two
    /// anchor errors applies, not which source is reported.
    #[test]
    fn an_unpinned_client_reports_the_environment_as_the_anchor_source() {
        let mut policy = TslTrustPolicy::new(unauthenticatable_list_granting_issuer());

        let err = policy
            .issuer_status(ISSUER_DER, now())
            .expect_err("an unauthenticatable list must never yield a trusted status");

        let env_anchors = TslTrustAnchors::from_env()
            .expect("CHANCELA_TSL_TRUST_ANCHOR[_SHA256] in this environment must parse");
        let reported = match &err {
            SigningError::TrustAnchorNotConfigured { checked } => *checked,
            SigningError::TrustedListNotAnchored { configured_in, .. } => *configured_in,
            other => panic!("expected a trust-anchor discriminator, got {other:?}"),
        };

        assert_eq!(reported, TrustAnchorSource::Environment);
        assert_eq!(reported.as_str(), "environment");
        assert_eq!(
            env_anchors.is_empty(),
            matches!(err, SigningError::TrustAnchorNotConfigured { .. }),
            "the empty/non-empty environment anchor set must decide A vs B: {err:?}"
        );
    }
}
