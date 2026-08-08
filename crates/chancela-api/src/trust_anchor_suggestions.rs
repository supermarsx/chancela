//! `GET /v1/trust/anchor-suggestions` — propose Trusted List trust anchors, without faking trust
//! (t118).
//!
//! # The problem
//!
//! Configuring `signing.tsl_trust_anchor_certs` / `_sha256` means pasting a PEM block or a 64-char
//! SHA-256 by hand, with nothing on the screen to say where the right value comes from. Operators
//! get it wrong in the direction that fails closed (no anchor, no qualified signing) and, worse, in
//! the direction that fails open — pasting whatever certificate the list they just fetched happened
//! to carry.
//!
//! # The hole this endpoint must NOT dig
//!
//! The obvious "assistant" is: fetch the configured list, read the certificate out of its own
//! `<ds:KeyInfo>`, offer it as that list's anchor. **That is circular.** The artefact being
//! authenticated would supply its own proof, so anyone who can serve a forged list also serves its
//! "anchor" and every subsequent verification passes. It is the same class of defect as a valid
//! signature over nothing.
//!
//! So the sound path is the only default:
//!
//! 1. Authenticate the **EU LOTL** against the operator's configured anchor. The LOTL's anchor is
//!    published out of band, in the Official Journal — it is the one value a human must establish,
//!    and no assistant can supply it. If the LOTL does not authenticate, this endpoint proposes
//!    **nothing at all**.
//! 2. Match each configured, enabled TSL source to a `PointersToOtherTSL` entry in that
//!    authenticated LOTL.
//! 3. Propose that pointer's `signer_certs` — **all** of them. Several usually means key rotation,
//!    and proposing only the first guarantees an outage the day the scheme operator rolls its key.
//!
//! # The fallback, and why it is shaped the way it is
//!
//! When the authenticated LOTL has no pointer for a source (a non-EU list, an internal mirror), the
//! endpoint may still show the certificate that list's own signature names — as an **identity to go
//! and check**, never as an anchor. Two structural decisions keep that from decaying into the hole
//! above:
//!
//! - the proposal's [`TrustAnchorProvenance`] is `list_self_asserted`, a required enum field, so no
//!   client can render it without having been told what it is; and
//! - it carries **no `certificate_pem`** — only the SHA-256 fingerprint. The operator's task is to
//!   compare that fingerprint against the value the scheme operator publishes, and the fingerprint
//!   is exactly what they then paste into `tsl_trust_anchor_sha256`. Handing over a PEM would invite
//!   a paste that skips the comparison, which is the whole risk.
//!
//! # What this endpoint never does
//!
//! It never writes. It reads settings under a read guard, fetches, and returns; there is no
//! settings mutation, no ledger append, and no cache promotion anywhere in this module. The
//! operator selects and saves through the existing settings write path, which is where
//! `signing.configure` authorisation, validation and the audit trail already live.

use axum::Json;
use axum::extract::State;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_authz::{Permission, Scope};
use chancela_tsl::{
    OtherTslPointer, TrustedList, TslTrustAnchors, extract_signer_cert, ingest_lotl,
    member_pointer_in,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;
use crate::settings::TslSourceSettings;
use crate::trust::{
    DEFAULT_TSL_FETCH_MAX_BYTES, DEFAULT_TSL_FETCH_TIMEOUT_SECONDS, cert_fingerprint,
    fetch_bounded_tsl_url, resolve_lotl_trust_anchors, resolve_lotl_url,
};
use crate::trust_anchor_suggestion_codes as codes;

/// Bound a distinguished name for display, on a character boundary so a multi-byte name cannot be
/// cut mid-codepoint. Same bound the AMA certificate inspection uses.
const NAME_MAX_CHARS: usize = 200;

/// Bound the machine `detail` that accompanies a failure code. It is the underlying library's own
/// error string; it is useful and it is not prose we translate, but it must not be unbounded.
const DETAIL_MAX_CHARS: usize = 400;

/// Where a proposed anchor came from. **Required on every proposal**, and an enum rather than a
/// boolean, so a client cannot render a candidate without having been told which kind it is, and a
/// third provenance later cannot be silently coerced into one of these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAnchorProvenance {
    /// The certificate the **authenticated EU LOTL** names as the expected signer of this list.
    /// Trust flows from the LOTL's own anchor, which the operator established out of band.
    EuLotl,
    /// The certificate the list's **own** XML signature carries. It proves nothing about the list:
    /// a forged list carries a forged one. It is shown only so the operator can compare its
    /// fingerprint against a value published by the scheme operator.
    ListSelfAsserted,
}

/// One proposed anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchorProposalView {
    /// Where this candidate came from. See [`TrustAnchorProvenance`].
    pub provenance: TrustAnchorProvenance,
    /// The certificate's subject distinguished name, for the operator to recognise.
    pub subject: String,
    /// The certificate's issuer distinguished name.
    pub issuer: String,
    /// Start of the validity window, RFC 3339, when parseable.
    pub not_before: Option<String>,
    /// End of the validity window, RFC 3339, when parseable.
    pub not_after: Option<String>,
    /// Lowercase-hex SHA-256 of the certificate DER — the value that goes in
    /// `signing.tsl_trust_anchor_sha256`, and the value to compare against a published fingerprint.
    pub sha256: String,
    /// PEM for `signing.tsl_trust_anchor_certs`. **`None` for a `list_self_asserted` candidate**:
    /// that one is not an anchor to paste, it is a fingerprint to verify first.
    pub certificate_pem: Option<String>,
    /// `true` when this certificate already matches a configured anchor (settings ∪ environment),
    /// compared by DER fingerprint rather than by PEM text — so re-encoded, re-wrapped or
    /// differently-whitespaced PEM of the same certificate is still recognised as present.
    pub already_configured: bool,
}

/// One configured Trusted List source and whatever could be proposed for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchorSourceSuggestionView {
    /// `signing.tsl_sources[].id`.
    pub source_id: String,
    /// `signing.tsl_sources[].name`, as the operator wrote it.
    pub source_name: String,
    /// The source's URL, when it has one.
    pub url: Option<String>,
    /// The source's configured territory, when it has one.
    pub territory: Option<String>,
    /// Stable outcome code from [`crate::trust_anchor_suggestion_codes`].
    pub code: String,
    /// The underlying library/transport error, verbatim, when the code names a failure. Machine
    /// detail rendered as the server's own words — never translated, never a substitute for `code`.
    pub detail: Option<String>,
    /// The proposals, possibly empty. Every entry carries its own provenance.
    pub proposals: Vec<TrustAnchorProposalView>,
}

/// The endpoint's response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchorSuggestionsView {
    /// When the proposal run happened, RFC 3339.
    pub checked_at: String,
    /// The LOTL location that was consulted.
    pub lotl_url: String,
    /// Whether the LOTL authenticated against a configured anchor. When `false`, `sources` carries
    /// no proposals at all — this endpoint fails closed.
    pub lotl_authenticated: bool,
    /// Stable outcome code for the LOTL step.
    pub lotl_code: String,
    /// The underlying error, verbatim, when the LOTL step failed.
    pub lotl_detail: Option<String>,
    /// How many anchors are configured today (settings ∪ environment), so the UI can say "already
    /// present" honestly without re-deriving the union client-side.
    pub configured_anchor_count: usize,
    /// One entry per configured, **enabled** TSL source, in configuration order.
    pub sources: Vec<TrustAnchorSourceSuggestionView>,
}

/// `GET /v1/trust/anchor-suggestions` — propose trust anchors for the configured Trusted List
/// sources. Read-only: it fetches and returns, and writes nothing anywhere.
///
/// Gated on `signing.configure`, the **same** permission that writes
/// `signing.tsl_trust_anchor_certs` / `_sha256`. Deliberately not the broader trust-catalog read
/// verb: this endpoint's whole output is material an operator is about to turn into a trust root,
/// and it performs outbound fetches on demand. Whoever may see the proposal is whoever may act on
/// it.
pub async fn trust_anchor_suggestions(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<TrustAnchorSuggestionsView>, ApiError> {
    require_permission(&state, &actor, Permission::SigningConfigure, Scope::Global).await?;

    let (sources, anchor_certs, anchor_fingerprints) = {
        let guard = state.settings.read().await;
        (
            guard.signing.tsl_sources.clone(),
            guard.signing.tsl_trust_anchor_certs.clone(),
            guard.signing.tsl_trust_anchor_sha256.clone(),
        )
    };

    // Blocking reqwest, exactly as the refresh path does it — never on the async runtime's threads.
    tokio::task::spawn_blocking(move || {
        // Settings ∪ environment, the same union the signing path anchors against — so "already
        // configured" means what an operator would mean by it, not "already in the settings
        // document". A configuration error is fail-closed: an anchor set that cannot be built
        // authenticates no LOTL, so the flow proposes nothing, which is the correct direction.
        let anchors = resolve_lotl_trust_anchors(&anchor_certs, &anchor_fingerprints)
            .unwrap_or_else(|_| TslTrustAnchors::new());
        build_suggestions(
            &sources,
            &anchors,
            &resolve_lotl_url(None),
            &|url, timeout, max_bytes| fetch_bounded_tsl_url(url, timeout, max_bytes),
            OffsetDateTime::now_utc(),
        )
    })
    .await
    .map_err(|e| ApiError::Internal(format!("trust-anchor suggestion worker failed: {e}")))
    .map(Json)
}

/// How this module reaches the network: a bounded, SSRF-vetted fetch of `(url, timeout, max_bytes)`.
///
/// Injected rather than called directly so the flow is testable without a network — and, just as
/// importantly, without the process environment, which `resolve_lotl_trust_anchors` reads and which
/// a sibling test in this crate legitimately mutates. A suggestion test that depended on either
/// would be a test whose verdict changed with the machine it ran on.
///
/// Production always passes [`fetch_bounded_tsl_url`]; there is no second fetch path.
type FetchTsl<'a> = &'a dyn Fn(&str, u16, u64) -> Result<Vec<u8>, String>;

/// Build one source's response row with everything but its outcome already filled in.
///
/// Passed down into [`self_asserted`] so that function decides the code and the proposals and
/// nothing else — it never gets to restate the source's identity, which is how the two would drift.
type BuildRow<'a> = &'a dyn Fn(
    &str,
    Option<String>,
    Vec<TrustAnchorProposalView>,
) -> TrustAnchorSourceSuggestionView;

/// The whole flow, with the network behind [`FetchTsl`] so a unit test can drive every branch.
fn build_suggestions(
    sources: &[TslSourceSettings],
    anchors: &TslTrustAnchors,
    lotl_url: &str,
    fetch: FetchTsl<'_>,
    now: OffsetDateTime,
) -> TrustAnchorSuggestionsView {
    let lotl_url = lotl_url.to_owned();
    let checked_at = now.format(&Rfc3339).unwrap_or_default();

    let enabled: Vec<&TslSourceSettings> = sources.iter().filter(|entry| entry.enabled).collect();

    // Step 1: the root of trust. No anchor means no assistant — the first anchor comes from the
    // Official Journal, by hand.
    if anchors.is_empty() {
        return refused(
            checked_at,
            lotl_url,
            codes::LOTL_ANCHOR_NOT_CONFIGURED,
            None,
            0,
            &enabled,
        );
    }

    let lotl_bytes = match fetch(
        &lotl_url,
        DEFAULT_TSL_FETCH_TIMEOUT_SECONDS,
        DEFAULT_TSL_FETCH_MAX_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            return refused(
                checked_at,
                lotl_url,
                codes::LOTL_FETCH_FAILED,
                Some(truncate(&e, DETAIL_MAX_CHARS)),
                anchors.len(),
                &enabled,
            );
        }
    };

    let lotl = match ingest_lotl(&lotl_bytes, anchors) {
        Ok(list) => list,
        Err(e) => {
            return refused(
                checked_at,
                lotl_url,
                codes::LOTL_NOT_AUTHENTICATED,
                Some(truncate(&e.to_string(), DETAIL_MAX_CHARS)),
                anchors.len(),
                &enabled,
            );
        }
    };

    if lotl.list.other_tsl_pointers.is_empty() {
        return refused(
            checked_at,
            lotl_url,
            codes::LOTL_NO_POINTERS,
            None,
            anchors.len(),
            &enabled,
        );
    }

    let sources = enabled
        .iter()
        .map(|entry| suggest_for_source(entry, &lotl.list, &lotl_url, anchors, fetch))
        .collect();

    TrustAnchorSuggestionsView {
        checked_at,
        lotl_url,
        lotl_authenticated: true,
        lotl_code: codes::LOTL_AUTHENTICATED.to_owned(),
        lotl_detail: None,
        configured_anchor_count: anchors.len(),
        sources,
    }
}

/// The fail-closed shape: every source listed so the operator can see it was considered, and not one
/// proposal anywhere. Used for **every** LOTL-step failure, including "no anchor configured".
///
/// The from-the-list-itself fallback deliberately does **not** run here. It exists to cover a source
/// the *authenticated* LOTL has no pointer for; letting an unauthenticated (and therefore
/// attacker-controllable) LOTL decide which sources get a fallback candidate would hand the attacker
/// that choice, and a run that proposed candidates for everything would look, at a glance, exactly
/// like a successful one.
fn refused(
    checked_at: String,
    lotl_url: String,
    code: &str,
    detail: Option<String>,
    configured_anchor_count: usize,
    enabled: &[&TslSourceSettings],
) -> TrustAnchorSuggestionsView {
    TrustAnchorSuggestionsView {
        checked_at,
        lotl_url,
        lotl_authenticated: false,
        lotl_code: code.to_owned(),
        lotl_detail: detail,
        configured_anchor_count,
        sources: enabled
            .iter()
            .map(|entry| TrustAnchorSourceSuggestionView {
                source_id: entry.id.clone(),
                source_name: entry.name.clone(),
                url: trimmed(entry.url.as_deref()),
                territory: trimmed(entry.country.as_deref()),
                code: code.to_owned(),
                detail: None,
                proposals: Vec::new(),
            })
            .collect(),
    }
}

fn suggest_for_source(
    entry: &TslSourceSettings,
    lotl: &TrustedList,
    lotl_url: &str,
    anchors: &TslTrustAnchors,
    fetch: FetchTsl<'_>,
) -> TrustAnchorSourceSuggestionView {
    let url = trimmed(entry.url.as_deref());
    let territory = trimmed(entry.country.as_deref());
    let row = |code: &str, detail: Option<String>, proposals: Vec<TrustAnchorProposalView>| {
        TrustAnchorSourceSuggestionView {
            source_id: entry.id.clone(),
            source_name: entry.name.clone(),
            url: url.clone(),
            territory: territory.clone(),
            code: code.to_owned(),
            detail,
            proposals,
        }
    };

    // The LOTL itself is not a member-state list and has no pointer to itself. Its anchor is the
    // Official Journal value the operator already holds; proposing one from the document would be
    // precisely the circularity this endpoint exists to avoid.
    if is_lotl_source(entry, lotl_url) {
        return row(codes::SOURCE_IS_LOTL, None, Vec::new());
    }

    let Some(url) = url.clone() else {
        return row(codes::SOURCE_LOCATION_UNSUPPORTED, None, Vec::new());
    };

    match match_pointer(lotl, &url, territory.as_deref()) {
        Some(pointer) if !pointer.signer_certs.is_empty() => {
            // ALL of them. A pointer carrying several is carrying a key rotation, and proposing only
            // the first schedules an outage for the day the scheme operator switches.
            let proposals = pointer
                .signer_certs
                .iter()
                .map(|der| proposal(der, TrustAnchorProvenance::EuLotl, anchors))
                .collect();
            row(codes::SOURCE_ANCHORS_FROM_LOTL, None, proposals)
        }
        // A pointer that names no signer certificate vouches for nothing, so this source is in the
        // same position as one the LOTL does not mention — but the operator should be told which of
        // the two it is, because the remedies differ.
        Some(_) => self_asserted(
            &url,
            entry,
            anchors,
            codes::SOURCE_POINTER_WITHOUT_SIGNER_CERT,
            &row,
            fetch,
        ),
        None => self_asserted(&url, entry, anchors, codes::SOURCE_NOT_IN_LOTL, &row, fetch),
    }
}

/// The fallback: fetch the list and show the identity of the certificate its own signature names.
///
/// `absent_code` is the caller's reason for being here (no pointer at all / a pointer with no
/// signer certificate) and is kept on success, because it is the fact the operator must act on. It
/// is replaced only when the fallback itself could produce nothing.
fn self_asserted(
    url: &str,
    entry: &TslSourceSettings,
    anchors: &TslTrustAnchors,
    absent_code: &str,
    row: BuildRow<'_>,
    fetch: FetchTsl<'_>,
) -> TrustAnchorSourceSuggestionView {
    // The entry's OWN fetch policy — its configured timeout and size bound, not this module's
    // defaults. A source the operator bounded tightly stays bounded tightly here.
    let bytes = match fetch(url, entry.timeout_seconds, entry.max_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            return row(
                codes::SOURCE_FETCH_FAILED,
                Some(truncate(&e, DETAIL_MAX_CHARS)),
                Vec::new(),
            );
        }
    };
    match extract_signer_cert(&bytes) {
        Ok(Some(der)) => row(
            absent_code,
            None,
            vec![proposal(
                &der,
                TrustAnchorProvenance::ListSelfAsserted,
                anchors,
            )],
        ),
        Ok(None) => row(codes::SOURCE_SIGNER_CERT_ABSENT, None, Vec::new()),
        Err(e) => row(
            codes::SOURCE_SIGNER_CERT_ABSENT,
            Some(truncate(&e.to_string(), DETAIL_MAX_CHARS)),
            Vec::new(),
        ),
    }
}

/// Build one proposal from a DER certificate.
///
/// The `certificate_pem` is withheld for a self-asserted candidate — see the module docs. Identity
/// fields fall back to an empty string / `None` when the DER does not parse as X.509, rather than
/// dropping the candidate: the fingerprint is still the thing to compare, and silently discarding a
/// certificate the LOTL pointer named would hide a real configuration problem.
fn proposal(
    der: &[u8],
    provenance: TrustAnchorProvenance,
    anchors: &TslTrustAnchors,
) -> TrustAnchorProposalView {
    let parsed = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(der).ok();
    let (subject, issuer) = parsed
        .as_ref()
        .map(|cert| {
            (
                truncate(&cert.tbs_certificate.subject.to_string(), NAME_MAX_CHARS),
                truncate(&cert.tbs_certificate.issuer.to_string(), NAME_MAX_CHARS),
            )
        })
        .unwrap_or_default();
    let (not_before, not_after) = parsed
        .as_ref()
        .map(|cert| {
            (
                rfc3339(&cert.tbs_certificate.validity.not_before),
                rfc3339(&cert.tbs_certificate.validity.not_after),
            )
        })
        .unwrap_or((None, None));

    TrustAnchorProposalView {
        provenance,
        subject,
        issuer,
        not_before,
        not_after,
        sha256: cert_fingerprint(der),
        certificate_pem: match provenance {
            TrustAnchorProvenance::EuLotl => Some(to_pem(der)),
            TrustAnchorProvenance::ListSelfAsserted => None,
        },
        // By fingerprint, never by PEM text: the same certificate re-encoded, re-wrapped or with
        // different trailing whitespace is the same anchor, and a string comparison would re-propose
        // it for ever.
        already_configured: anchors.is_anchored(der),
    }
}

/// Whether this configured source *is* the List of Trusted Lists rather than a member-state list.
fn is_lotl_source(entry: &TslSourceSettings, lotl_url: &str) -> bool {
    if entry
        .scheme
        .as_deref()
        .is_some_and(|scheme| scheme.trim().eq_ignore_ascii_case("lotl"))
    {
        return true;
    }
    entry
        .url
        .as_deref()
        .is_some_and(|url| same_location(url, lotl_url))
}

/// Match a source to a LOTL pointer: by location first, then by territory.
///
/// Location first because it is the precise answer — two pointers can share a territory. Territory
/// second because an operator legitimately points at a mirror of a member-state list, and its URL
/// then matches no pointer while the list it mirrors is unambiguous. [`member_pointer_in`] does the
/// territory half, so the XML-vs-PDF pointer preference is not reimplemented here.
fn match_pointer<'a>(
    lotl: &'a TrustedList,
    url: &str,
    territory: Option<&str>,
) -> Option<&'a OtherTslPointer> {
    if let Some(hit) = lotl
        .other_tsl_pointers
        .iter()
        .find(|pointer| same_location(&pointer.tsl_location, url))
    {
        return Some(hit);
    }
    territory.and_then(|territory| member_pointer_in(&lotl.other_tsl_pointers, territory))
}

/// Compare two list locations. Trimmed, case-insensitive, and tolerant of one trailing slash —
/// nothing more. Anything cleverer (percent-decoding, host normalisation) would start deciding that
/// two different URLs are the same, which is not a decision a trust-anchor matcher should make.
fn same_location(left: &str, right: &str) -> bool {
    let normalise = |value: &str| {
        value
            .trim()
            .trim_end_matches('/')
            .to_ascii_lowercase()
            .to_owned()
    };
    let (left, right) = (normalise(left), normalise(right));
    !left.is_empty() && left == right
}

fn trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let head: String = value.chars().take(max_chars).collect();
    format!("{head}…")
}

fn rfc3339(time: &x509_cert::time::Time) -> Option<String> {
    let seconds = i64::try_from(time.to_unix_duration().as_secs()).ok()?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn to_pem(der: &[u8]) -> String {
    let body = B64.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(id: &str, url: Option<&str>, country: Option<&str>) -> TslSourceSettings {
        TslSourceSettings {
            id: id.to_owned(),
            name: format!("{id} list"),
            enabled: true,
            url: url.map(str::to_owned),
            country: country.map(str::to_owned),
            ..TslSourceSettings::default()
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("fixed instant")
    }

    /// A fetch that always fails. The default for tests about a source the LOTL does not vouch for:
    /// the point there is the provenance, not the bytes.
    fn no_network(_: &str, _: u16, _: u64) -> Result<Vec<u8>, String> {
        Err("no network in this test".to_owned())
    }

    /// A fetch that serves fixed bytes for every URL.
    fn serving(bytes: Vec<u8>) -> impl Fn(&str, u16, u64) -> Result<Vec<u8>, String> {
        move |_, _, _| Ok(bytes.clone())
    }

    /// A synthesized DER certificate. Never a real one: a real anchor in a fixture is a value
    /// somebody will eventually paste into a settings document.
    fn synthetic_cert(serial: u8) -> Vec<u8> {
        // Not a parseable X.509 body — the identity fields degrade to empty, which is itself a case
        // worth pinning. The fingerprint and the provenance, which are what this module decides,
        // are exercised exactly as they would be by a real certificate.
        vec![0x30, 0x03, 0x02, 0x01, serial]
    }

    /// One synthetic `OtherTSLPointer` element.
    ///
    /// Built as XML and run through the real parser rather than constructed as a struct: `OtherTslPointer`
    /// is `#[non_exhaustive]`, and — more to the point — a fixture that skips the parser cannot catch a
    /// parser that stops populating `signer_certs`, which is the field every decision here hangs on.
    fn pointer(location: &str, territory: Option<&str>, certs: &[Vec<u8>]) -> String {
        let identities: String = certs
            .iter()
            .map(|der| {
                format!(
                    "<tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>{}                     </tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity>",
                    B64.encode(der)
                )
            })
            .collect();
        let territory = territory
            .map(|value| format!("<tsl:SchemeTerritory>{value}</tsl:SchemeTerritory>"))
            .unwrap_or_default();
        format!(
            "<tsl:OtherTSLPointer>             <tsl:ServiceDigitalIdentities>{identities}</tsl:ServiceDigitalIdentities>             <tsl:TSLLocation>{location}</tsl:TSLLocation>             <tsl:AdditionalInformation><tsl:OtherInformation>{territory}             <ns5:MimeType xmlns:ns5=\"http://uri.etsi.org/02231/v2/additionaltypes#\">             application/vnd.etsi.tsl+xml</ns5:MimeType>             </tsl:OtherInformation></tsl:AdditionalInformation>             </tsl:OtherTSLPointer>"
        )
    }

    /// A parsed LOTL carrying `pointers`. Never signed and never authenticated — every test here
    /// drives the code path that runs *after* `ingest_lotl` has already vouched for the document.
    fn lotl_with(pointers: &[String]) -> TrustedList {
        chancela_tsl::parse_tsl(&lotl_xml(pointers)).expect("synthetic LOTL parses")
    }

    /// The same document as bytes, for the tests that need it to travel through `ingest_lotl`.
    fn lotl_xml(pointers: &[String]) -> Vec<u8> {
        let body: String = pointers.concat();
        format!(
            "<tsl:TrustServiceStatusList xmlns:tsl=\"http://uri.etsi.org/02231/v2#\">             <tsl:SchemeInformation><tsl:SchemeTerritory>EU</tsl:SchemeTerritory>             <tsl:PointersToOtherTSL>{body}</tsl:PointersToOtherTSL>             </tsl:SchemeInformation></tsl:TrustServiceStatusList>"
        )
        .into_bytes()
    }

    #[test]
    fn a_lotl_pointer_proposes_every_signer_cert_it_carries_with_lotl_provenance() {
        let certs = vec![synthetic_cert(1), synthetic_cert(2), synthetic_cert(3)];
        let lotl = lotl_with(&[pointer("https://lists.example/xx.xml", Some("XX"), &certs)]);
        let entry = source("xx", Some("https://lists.example/xx.xml"), Some("XX"));

        let row = suggest_for_source(
            &entry,
            &lotl,
            "https://lotl.example/eu-lotl.xml",
            &TslTrustAnchors::new(),
            &no_network,
        );

        assert_eq!(row.code, codes::SOURCE_ANCHORS_FROM_LOTL);
        assert_eq!(
            row.proposals.len(),
            certs.len(),
            "a pointer carrying several certificates is carrying a key rotation; proposing a \
             subset schedules an outage"
        );
        for (proposal, der) in row.proposals.iter().zip(&certs) {
            assert_eq!(proposal.provenance, TrustAnchorProvenance::EuLotl);
            assert_eq!(proposal.sha256, cert_fingerprint(der));
            assert!(
                proposal.certificate_pem.is_some(),
                "a LOTL-derived anchor is meant to be pasted, so it carries its PEM"
            );
        }
    }

    #[test]
    fn a_source_the_lotl_does_not_mention_is_never_marked_lotl_derived() {
        // No network in this test, so the fallback fetch fails; what is pinned is that the outcome
        // is NOT a LOTL-derived proposal under any circumstance.
        let lotl = lotl_with(&[pointer(
            "https://lists.example/yy.xml",
            Some("YY"),
            &[synthetic_cert(9)],
        )]);
        let entry = source("zz", Some("https://127.0.0.1:1/zz.xml"), Some("ZZ"));

        let row = suggest_for_source(
            &entry,
            &lotl,
            "https://lotl.example/eu-lotl.xml",
            &TslTrustAnchors::new(),
            &no_network,
        );

        assert_ne!(row.code, codes::SOURCE_ANCHORS_FROM_LOTL);
        assert!(
            row.proposals
                .iter()
                .all(|p| p.provenance == TrustAnchorProvenance::ListSelfAsserted),
            "nothing outside a LOTL pointer may carry LOTL provenance"
        );
    }

    #[test]
    fn a_self_asserted_proposal_carries_no_pem_only_a_fingerprint_to_verify() {
        let der = synthetic_cert(7);
        let candidate = proposal(
            &der,
            TrustAnchorProvenance::ListSelfAsserted,
            &TslTrustAnchors::new(),
        );
        assert_eq!(
            candidate.provenance,
            TrustAnchorProvenance::ListSelfAsserted
        );
        assert_eq!(
            candidate.certificate_pem, None,
            "handing over a pasteable PEM invites the operator to skip the comparison that is the \
             entire point of the fallback"
        );
        assert_eq!(candidate.sha256.len(), 64);
    }

    #[test]
    fn an_already_configured_anchor_is_reported_present_and_matched_by_der_not_pem_text() {
        let der = synthetic_cert(4);
        let anchors = TslTrustAnchors::new().with_cert_der(&der);
        let lotl = lotl_with(&[pointer(
            "https://lists.example/xx.xml",
            Some("XX"),
            &[der.clone(), synthetic_cert(5)],
        )]);
        let entry = source("xx", Some("https://lists.example/XX.xml"), Some("XX"));

        let row = suggest_for_source(
            &entry,
            &lotl,
            "https://lotl.example/eu-lotl.xml",
            &anchors,
            &no_network,
        );

        assert_eq!(row.code, codes::SOURCE_ANCHORS_FROM_LOTL);
        assert_eq!(row.proposals.len(), 2);
        assert!(
            row.proposals[0].already_configured,
            "the configured anchor must be reported present, not offered again"
        );
        assert!(!row.proposals[1].already_configured);
    }

    #[test]
    fn without_an_anchor_the_lotl_step_refuses_and_nothing_at_all_is_proposed() {
        let sources = vec![
            source("xx", Some("https://lists.example/xx.xml"), Some("XX")),
            source("yy", Some("https://lists.example/yy.xml"), Some("YY")),
        ];

        let view = build_suggestions(
            &sources,
            &TslTrustAnchors::new(),
            "https://lotl.example/eu-lotl.xml",
            &no_network,
            now(),
        );

        assert!(!view.lotl_authenticated);
        assert_eq!(view.lotl_code, codes::LOTL_ANCHOR_NOT_CONFIGURED);
        assert_eq!(view.sources.len(), 2, "every source is still accounted for");
        assert!(
            view.sources.iter().all(|s| s.proposals.is_empty()),
            "an unauthenticated LOTL proposes nothing — not even a fallback candidate, which would \
             let an attacker-controlled document choose what the operator sees"
        );
    }

    /// A Trusted List whose XML signature names `cert_der` in its own `<ds:KeyInfo>` — the exact
    /// artefact the circular "assistant" would have mistaken for proof of itself.
    fn list_naming_its_own_signer(cert_der: &[u8]) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList>
  <SchemeInformation><SchemeTerritory>ZZ</SchemeTerritory></SchemeInformation>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AAAA</ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </ds:Signature>
</TrustServiceStatusList>"#,
            B64.encode(cert_der)
        )
        .into_bytes()
    }

    #[test]
    fn the_fallback_candidate_is_labelled_self_asserted_and_withholds_its_pem() {
        let der = synthetic_cert(42);
        let lotl = lotl_with(&[pointer(
            "https://lists.example/yy.xml",
            Some("YY"),
            &[synthetic_cert(1)],
        )]);
        let entry = source("zz", Some("https://lists.example/zz.xml"), Some("ZZ"));

        let row = suggest_for_source(
            &entry,
            &lotl,
            "https://lotl.example/eu-lotl.xml",
            &TslTrustAnchors::new(),
            &serving(list_naming_its_own_signer(&der)),
        );

        assert_eq!(
            row.code,
            codes::SOURCE_NOT_IN_LOTL,
            "the operator must be told the LOTL vouches for nothing here — that IS the finding"
        );
        assert_eq!(row.proposals.len(), 1);
        let candidate = &row.proposals[0];
        assert_eq!(
            candidate.provenance,
            TrustAnchorProvenance::ListSelfAsserted,
            "a certificate taken out of the list's own signature must never be marked LOTL-derived"
        );
        assert_eq!(candidate.sha256, cert_fingerprint(&der));
        assert_eq!(candidate.certificate_pem, None);
    }

    #[test]
    fn a_pointer_carrying_no_signer_cert_falls_back_and_says_so() {
        let der = synthetic_cert(43);
        let lotl = lotl_with(&[pointer("https://lists.example/zz.xml", Some("ZZ"), &[])]);
        let entry = source("zz", Some("https://lists.example/zz.xml"), Some("ZZ"));

        let row = suggest_for_source(
            &entry,
            &lotl,
            "https://lotl.example/eu-lotl.xml",
            &TslTrustAnchors::new(),
            &serving(list_naming_its_own_signer(&der)),
        );

        assert_eq!(row.code, codes::SOURCE_POINTER_WITHOUT_SIGNER_CERT);
        assert_eq!(
            row.proposals[0].provenance,
            TrustAnchorProvenance::ListSelfAsserted
        );
    }

    #[test]
    fn a_list_with_no_signature_yields_no_candidate_at_all() {
        let lotl = lotl_with(&[pointer(
            "https://lists.example/yy.xml",
            Some("YY"),
            &[synthetic_cert(1)],
        )]);
        let entry = source("zz", Some("https://lists.example/zz.xml"), Some("ZZ"));

        let row = suggest_for_source(
            &entry,
            &lotl,
            "https://lotl.example/eu-lotl.xml",
            &TslTrustAnchors::new(),
            &serving(b"<TrustServiceStatusList/>".to_vec()),
        );

        assert_eq!(row.code, codes::SOURCE_SIGNER_CERT_ABSENT);
        assert!(row.proposals.is_empty());
    }

    #[test]
    fn a_lotl_that_does_not_authenticate_proposes_nothing_even_though_it_parses() {
        // The adversarial case: a well-formed LOTL, served successfully, naming pointers with signer
        // certificates — and no signature this operator's anchor accepts. Every certificate in it is
        // attacker-chosen, so not one of them may reach the operator as a proposal.
        let forged = lotl_xml(&[pointer(
            "https://lists.example/xx.xml",
            Some("XX"),
            &[synthetic_cert(66)],
        )]);
        let anchors = TslTrustAnchors::new().with_cert_der(&synthetic_cert(99));
        let sources = vec![source(
            "xx",
            Some("https://lists.example/xx.xml"),
            Some("XX"),
        )];

        let view = build_suggestions(
            &sources,
            &anchors,
            "https://lotl.example/eu-lotl.xml",
            &serving(forged),
            now(),
        );

        assert!(!view.lotl_authenticated);
        assert_eq!(view.lotl_code, codes::LOTL_NOT_AUTHENTICATED);
        assert!(view.lotl_detail.is_some(), "the operator needs the reason");
        assert!(view.sources.iter().all(|s| s.proposals.is_empty()));
    }

    #[test]
    fn a_failed_lotl_fetch_proposes_nothing_and_carries_the_transport_error() {
        let anchors = TslTrustAnchors::new().with_cert_der(&synthetic_cert(99));
        let sources = vec![source(
            "xx",
            Some("https://lists.example/xx.xml"),
            Some("XX"),
        )];

        let view = build_suggestions(
            &sources,
            &anchors,
            "https://lotl.example/eu-lotl.xml",
            &no_network,
            now(),
        );

        assert!(!view.lotl_authenticated);
        assert_eq!(view.lotl_code, codes::LOTL_FETCH_FAILED);
        assert_eq!(view.lotl_detail.as_deref(), Some("no network in this test"));
        assert!(view.sources.iter().all(|s| s.proposals.is_empty()));
    }

    #[test]
    fn a_disabled_source_is_not_listed() {
        let mut disabled = source("off", Some("https://lists.example/off.xml"), Some("XX"));
        disabled.enabled = false;
        let view = build_suggestions(
            &[disabled],
            &TslTrustAnchors::new(),
            "https://lotl.example/eu-lotl.xml",
            &no_network,
            now(),
        );
        assert!(view.sources.is_empty());
    }

    #[test]
    fn the_lotl_source_itself_is_never_proposed_an_anchor_from_its_own_bytes() {
        let lotl = lotl_with(&[pointer(
            "https://lists.example/xx.xml",
            Some("XX"),
            &[synthetic_cert(1)],
        )]);
        let mut entry = source(
            "eu-lotl",
            Some("https://lotl.example/eu-lotl.xml"),
            Some("EU"),
        );
        entry.scheme = Some("lotl".to_owned());

        let row = suggest_for_source(
            &entry,
            &lotl,
            "https://lotl.example/eu-lotl.xml",
            &TslTrustAnchors::new(),
            &no_network,
        );

        assert_eq!(row.code, codes::SOURCE_IS_LOTL);
        assert!(row.proposals.is_empty());
    }

    #[test]
    fn a_source_without_a_url_is_reported_unsupported_rather_than_silently_dropped() {
        let lotl = lotl_with(&[pointer("https://lists.example/xx.xml", Some("XX"), &[])]);
        let mut entry = source("local", None, Some("XX"));
        entry.path = Some("/var/lib/chancela/tsl.xml".to_owned());

        let row = suggest_for_source(
            &entry,
            &lotl,
            "https://lotl.example/eu-lotl.xml",
            &TslTrustAnchors::new(),
            &no_network,
        );

        assert_eq!(row.code, codes::SOURCE_LOCATION_UNSUPPORTED);
        assert!(row.proposals.is_empty());
    }

    #[test]
    fn location_matching_ignores_case_and_one_trailing_slash_but_not_a_different_url() {
        assert!(same_location(
            "https://lists.example/xx.xml/",
            "https://LISTS.example/xx.xml"
        ));
        assert!(!same_location(
            "https://lists.example/xx.xml",
            "https://lists.example/yy.xml"
        ));
        assert!(!same_location("  ", ""));
    }

    #[test]
    fn territory_matching_is_the_fallback_when_no_location_matches() {
        let lotl = lotl_with(&[pointer(
            "https://official.example/xx.xml",
            Some("XX"),
            &[synthetic_cert(1)],
        )]);
        let entry = source("mirror", Some("https://mirror.internal/xx.xml"), Some("xx"));

        let row = suggest_for_source(
            &entry,
            &lotl,
            "https://lotl.example/eu-lotl.xml",
            &TslTrustAnchors::new(),
            &no_network,
        );

        assert_eq!(row.code, codes::SOURCE_ANCHORS_FROM_LOTL);
        assert_eq!(row.proposals.len(), 1);
    }

    #[test]
    fn every_code_this_module_emits_is_in_the_closed_list() {
        // The client's completeness test reads the closed list; a code emitted from here but never
        // listed there would render as a raw identifier in fourteen locales.
        for code in [
            codes::LOTL_AUTHENTICATED,
            codes::LOTL_ANCHOR_NOT_CONFIGURED,
            codes::LOTL_FETCH_FAILED,
            codes::LOTL_NOT_AUTHENTICATED,
            codes::LOTL_NO_POINTERS,
            codes::SOURCE_ANCHORS_FROM_LOTL,
            codes::SOURCE_IS_LOTL,
            codes::SOURCE_NOT_IN_LOTL,
            codes::SOURCE_POINTER_WITHOUT_SIGNER_CERT,
            codes::SOURCE_FETCH_FAILED,
            codes::SOURCE_SIGNER_CERT_ABSENT,
            codes::SOURCE_LOCATION_UNSUPPORTED,
        ] {
            assert!(
                codes::ALL_TRUST_ANCHOR_SUGGESTION_CODES.contains(&code),
                "{code} is emitted but not in the closed list"
            );
        }
    }

    #[test]
    fn pem_wraps_at_64_columns_with_the_standard_armour() {
        let pem = to_pem(&[0xABu8; 100]);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        for line in pem.lines().skip(1).take_while(|l| !l.starts_with("-----")) {
            assert!(line.len() <= 64);
        }
    }
}
