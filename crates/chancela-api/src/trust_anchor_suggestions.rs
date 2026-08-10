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
//! # The bootstrap case, and why it is opt-in
//!
//! Step 1 has a dead end. An operator with **no anchor at all** is told the first value comes from
//! the Official Journal and must be typed by hand — true, and useless to someone who does not have
//! that issue open. The one thing that can be shown in that state is the certificate the LOTL
//! document itself carries, and it is offered under [`bootstrap_self_asserted`], never by default:
//!
//! - a plain run in the unanchored state behaves **exactly** as before — it refuses, proposes
//!   nothing, and says why. The bootstrap candidate appears only when the operator asks a second,
//!   separately-labelled question, and accepting it is a further act in the settings draft;
//! - the candidate carries `TrustAnchorProvenance::ListSelfAsserted` — the same provenance, the
//!   same withheld PEM and the same "compare the fingerprint first" copy as a member-state list's
//!   own certificate. It is deliberately *not* a third, weaker-labelled kind;
//! - `lotl_authenticated` stays `false` and `lotl_code` stays `lotl_anchor_not_configured`. The
//!   verdict of the LOTL step does not change, because it has not changed: nothing authenticated.
//!
//! # …and what happens once that bootstrap anchor exists (t118/C2)
//!
//! Accepting the bootstrap candidate writes a fingerprint into `signing.tsl_trust_anchor_sha256`,
//! and from the next run onwards the LOTL **authenticates against it**: `is_anchored` is a pure
//! fingerprint pin, so a document that supplied its own anchor verifies against that anchor.
//! Left alone, step 1 would then report success, every member-state proposal would be built with
//! [`TrustAnchorProvenance::EuLotl`], and accepting one would store it unmarked — the whole anchor
//! set would descend from an unverified root with nothing in the deployment recording it. That is
//! precisely the "third provenance silently coerced into one of these two" the enum above exists to
//! prevent, arriving by the back door.
//!
//! So the run also reports [`TrustAnchorSuggestionsView::lotl_anchor_self_asserted`]: **at least one
//! of the configured anchors carries the `signing.tsl_trust_anchor_self_asserted_sha256`
//! annotation**. It is deliberately not "the LOTL authenticated against a self-asserted anchor",
//! because that is not knowable — `validate_tsl_signature_with_anchors` reports that *an* anchor
//! matched, never *which*. When any anchor in the set is unverified, the anchor that matched may
//! have been that one, and the mark says so. See [`intersects_annotation`] for the mixed case.
//!
//! What fetching over TLS did buy is worth stating precisely, because both overclaims are wrong.
//! TLS authenticated the **server**, which rules out a passive network attacker. It did not
//! authenticate the **list**: whoever served that document also chose the certificate inside it,
//! and a substituted list arrives with a matching certificate whose signature then verifies. So
//! this is trust on first use, and the verification that actually settles it is a human comparing
//! the SHA-256 fingerprint against the value published in the Official Journal. That is a normal
//! bootstrap step, not a reckless one — it just has to be labelled as what it is, and it has to
//! stay labelled after it is accepted (see `signing.tsl_trust_anchor_self_asserted_sha256`).
//!
//! # What this endpoint never does
//!
//! It never writes. It reads settings under a read guard, fetches, and returns; there is no
//! settings mutation, no ledger append, and no cache promotion anywhere in this module — the
//! bootstrap path included. The operator selects and saves through the existing settings write
//! path, which is where `signing.configure` authorisation, validation and the audit trail already
//! live.

use axum::Json;
use axum::extract::{Query, State};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_authz::{Permission, Scope};
use chancela_tsl::{
    OtherTslPointer, TrustedList, TslTrustAnchors, extract_signer_cert, ingest_lotl,
    member_pointer_in, parse_hex_sha256,
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
    ///
    /// The **LOTL bootstrap** candidate carries this same variant deliberately. A third value —
    /// "from the European list itself" — would read as a stronger claim than "from the list
    /// itself" while being exactly as unverified, and would need its own copy in fourteen
    /// locales to say the identical thing. The provenance of a certificate that vouches for
    /// itself does not depend on which list it came out of.
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
    /// **At least one configured anchor carries the self-asserted annotation** — it was accepted
    /// from a document that vouched for itself and no human has yet compared it against a published
    /// fingerprint. See [`intersects_annotation`] for why "at least one" and not "all".
    ///
    /// When this is `true` and [`lotl_authenticated`](Self::lotl_authenticated) is also `true`, the
    /// anchor the LOTL matched **may be** that unverified one: the verifier reports that an anchor
    /// matched, never which. Every `eu_lotl` proposal in the same response therefore descends from a
    /// root that might not be authentic, and the client must not present it as verified.
    ///
    /// Reported for a refused run too, because it is a fact about the deployment rather than about
    /// this run's outcome. It is `false` when no anchor is configured and when the configured
    /// anchors could not be read at all — in both of those states nothing has been annotated as
    /// belonging to a set that exists.
    pub lotl_anchor_self_asserted: bool,
    /// Stable outcome code for the LOTL step.
    pub lotl_code: String,
    /// The underlying error, verbatim, when the LOTL step failed.
    pub lotl_detail: Option<String>,
    /// Outcome of the **bootstrap** question, and `None` when it was not asked. A separate field
    /// from [`lotl_code`](Self::lotl_code) on purpose: asking it changes nothing about whether the
    /// LOTL authenticated, and folding the two would let a bootstrap answer overwrite the verdict.
    pub lotl_bootstrap_code: Option<String>,
    /// The underlying error, verbatim, when the bootstrap fetch failed.
    pub lotl_bootstrap_detail: Option<String>,
    /// The bootstrap candidate, or empty. At most one entry, and **always**
    /// `TrustAnchorProvenance::ListSelfAsserted` — this list is populated only in the unanchored
    /// state, where by definition nothing has authenticated anything.
    pub lotl_proposals: Vec<TrustAnchorProposalView>,
    /// How many anchors are configured today (settings ∪ environment), so the UI can say "already
    /// present" honestly without re-deriving the union client-side.
    ///
    /// `0` carries **two** meanings and must not be read on its own: no anchor is configured, or the
    /// configured anchors could not be resolved. [`lotl_code`](Self::lotl_code) discriminates them
    /// ([`codes::LOTL_ANCHOR_NOT_CONFIGURED`] against [`codes::LOTL_ANCHOR_CONFIG_INVALID`]), and it
    /// is the field a client must branch on.
    pub configured_anchor_count: usize,
    /// One entry per configured, **enabled** TSL source, in configuration order.
    pub sources: Vec<TrustAnchorSourceSuggestionView>,
}

/// Query string for [`trust_anchor_suggestions`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TrustAnchorSuggestionsQuery {
    /// Ask, **in addition**, for the certificate the EU LOTL document itself carries.
    ///
    /// Defaults to `false`, and a `false` run is byte-for-byte the endpoint's previous behaviour.
    /// It is a request parameter rather than something the server decides for the operator because
    /// the candidate is trust on first use: it has to be asked for, not encountered. Honoured only
    /// when no anchor is configured — with an anchor in place the answer is
    /// [`codes::LOTL_BOOTSTRAP_NOT_APPLICABLE`] and no candidate at all.
    pub bootstrap_self_asserted: bool,
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
    Query(query): Query<TrustAnchorSuggestionsQuery>,
) -> Result<Json<TrustAnchorSuggestionsView>, ApiError> {
    require_permission(&state, &actor, Permission::SigningConfigure, Scope::Global).await?;

    let (sources, anchor_certs, anchor_fingerprints, annotated) = {
        let guard = state.settings.read().await;
        (
            guard.signing.tsl_sources.clone(),
            guard.signing.tsl_trust_anchor_certs.clone(),
            guard.signing.tsl_trust_anchor_sha256.clone(),
            guard.signing.tsl_trust_anchor_self_asserted_sha256.clone(),
        )
    };

    // Blocking reqwest, exactly as the refresh path does it — never on the async runtime's threads.
    tokio::task::spawn_blocking(move || {
        build_suggestions(
            &sources,
            // Settings ∪ environment, the same union the signing path anchors against — so "already
            // configured" means what an operator would mean by it, not "already in the settings
            // document". Resolution can FAIL, and this is the one caller that must not treat that as
            // "unanchored": see [`AnchorConfig`].
            &AnchorConfig::resolve(&anchor_certs, &anchor_fingerprints, &annotated),
            &resolve_lotl_url(None),
            &|url, timeout, max_bytes| fetch_bounded_tsl_url(url, timeout, max_bytes),
            OffsetDateTime::now_utc(),
            query.bootstrap_self_asserted,
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

/// The resolved anchor set, together with what is known about where those anchors came from.
///
/// The two travel as one value because every decision this module makes about a proposal needs
/// both: `is_anchored` says whether a candidate is already present, and `self_asserted` says
/// whether the root the whole run hangs off is itself unverified. Splitting them into two
/// parameters is what let the second be forgotten at a call site (t118/C2).
struct ResolvedAnchors {
    anchors: TslTrustAnchors,
    /// See [`TrustAnchorSuggestionsView::lotl_anchor_self_asserted`].
    self_asserted: bool,
}

impl ResolvedAnchors {
    /// Pair an anchor set with the `signing.tsl_trust_anchor_self_asserted_sha256` annotation.
    fn new(anchors: TslTrustAnchors, annotated: &[String]) -> Self {
        let self_asserted = intersects_annotation(&anchors, annotated);
        Self {
            anchors,
            self_asserted,
        }
    }

    fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    fn len(&self) -> usize {
        self.anchors.len()
    }

    fn is_anchored(&self, der: &[u8]) -> bool {
        self.anchors.is_anchored(der)
    }
}

/// Whether **any** configured anchor also appears in the self-asserted annotation.
///
/// # Why "any", and not the "every anchor is annotated" rule that first suggests itself
///
/// The question the run actually needs answered is "could the anchor the LOTL matched be an
/// unverified one?", and `validate_tsl_signature_with_anchors` does not report *which* anchor
/// matched. So in the mixed set — one anchor transcribed from the Official Journal, one accepted on
/// first use — the LOTL may have authenticated against either, and the honest answer is that it
/// might have been the unverified one. "Every anchor is annotated" would go quiet on exactly that
/// case, which is the common one: it is what a deployment looks like the moment an operator adds a
/// real anchor beside a bootstrap one, or a bootstrap one beside a real one. Warning there is
/// over-warning by at most one screen of copy; going quiet is presenting a possibly-unverified root
/// as verified, which is the defect this module exists to prevent.
///
/// # Why the intersection, and not simply "the annotation is non-empty"
///
/// The annotation deliberately outlives its anchor: `validate_tsl_trust_anchors` neither prunes nor
/// rejects an entry that matches nothing, because pruning would erase the record. Reading the bare
/// list would therefore latch the warning on for ever the moment an operator deleted the
/// trust-on-first-use anchor they were warned about — and a mark that is always on is not a signal.
///
/// # How it is computed
///
/// [`TslTrustAnchors`] exposes no way to enumerate its fingerprints — only `len()` and a
/// DER-taking `is_anchored`. So the intersection is taken by cardinality:
/// `|A ∩ B| = |A| + |B| − |A ∪ B|`, where `A` is the anchor set, `B` the distinct annotated
/// fingerprints, and the union is `A` with every entry of `B` folded in (the fold deduplicates,
/// which is what makes the identity exact rather than an estimate).
fn intersects_annotation(anchors: &TslTrustAnchors, annotated: &[String]) -> bool {
    if anchors.is_empty() {
        return false;
    }
    let mut union = anchors.clone();
    let mut distinct: Vec<[u8; 32]> = Vec::new();
    for entry in annotated {
        // An entry that is not a fingerprint names no anchor and so cannot be one of them; settings
        // validation already refuses that shape on save. Skipping is the exact answer here, not a
        // lenient one.
        let Ok(fingerprint) = parse_hex_sha256(entry.trim()) else {
            continue;
        };
        if !distinct.contains(&fingerprint) {
            distinct.push(fingerprint);
        }
        union = union.with_fingerprint(fingerprint);
    }
    anchors.len() + distinct.len() > union.len()
}

/// The anchor configuration this run is judged against — **or the reason there isn't one**.
///
/// # Why this is an enum rather than a `TslTrustAnchors`
///
/// [`resolve_lotl_trust_anchors`] fails when `CHANCELA_TSL_TRUST_ANCHOR` points at a file that
/// cannot be read or at bytes that are not a certificate. This module used to discard that error
/// and carry on with an empty set, on the argument that an anchor set which cannot be built
/// authenticates no LOTL and therefore proposes nothing — fail-closed.
///
/// **That argument stopped holding when the bootstrap landed** (t118/C6). `anchors.is_empty()` is
/// now the *trigger* for the trust-on-first-use offer, so discarding the error told an operator
/// whose secret mount had gone missing "No trust anchor is configured, either here or in the
/// environment" — false about their deployment — and then showed them a button that walks them into
/// accepting an unverified root in place of the real anchor they already have. An error swallowed
/// into a sentinel value is only fail-closed for as long as nobody gives the sentinel a meaning.
///
/// Keeping the failure in the type is what makes that unforgettable: there is no way to obtain the
/// anchors without deciding what an unreadable configuration means.
enum AnchorConfig {
    Resolved(ResolvedAnchors),
    /// The configured anchors could not be built. Carries the library's own error, truncated.
    Invalid(String),
}

impl AnchorConfig {
    /// Resolve settings ∪ environment, keeping a resolution failure as a failure.
    fn resolve(certs: &[String], fingerprints: &[String], annotated: &[String]) -> Self {
        match resolve_lotl_trust_anchors(certs, fingerprints) {
            Ok(anchors) => Self::Resolved(ResolvedAnchors::new(anchors, annotated)),
            Err(e) => Self::Invalid(truncate(&e.to_string(), DETAIL_MAX_CHARS)),
        }
    }

    /// What to report as `configured_anchor_count`. Zero for an unreadable configuration — the
    /// count is genuinely unknown there, and `lotl_code` is what discriminates the two zeros.
    fn anchor_count(&self) -> usize {
        match self {
            Self::Resolved(anchors) => anchors.len(),
            Self::Invalid(_) => 0,
        }
    }

    fn self_asserted(&self) -> bool {
        match self {
            Self::Resolved(anchors) => anchors.self_asserted,
            Self::Invalid(_) => false,
        }
    }
}

/// The whole flow, with the network behind [`FetchTsl`] so a unit test can drive every branch.
///
/// `bootstrap` is the operator's explicit request for the from-the-document-itself LOTL candidate.
/// It is answered only in the unanchored state; with an anchor configured, the ordinary flow runs
/// untouched and the bootstrap question is answered "not applicable" without a second fetch.
fn build_suggestions(
    sources: &[TslSourceSettings],
    config: &AnchorConfig,
    lotl_url: &str,
    fetch: FetchTsl<'_>,
    now: OffsetDateTime,
    bootstrap: bool,
) -> TrustAnchorSuggestionsView {
    let mut view = suggest(sources, config, lotl_url, fetch, now, bootstrap);
    // "Not applicable" says an anchor is configured and the LOTL is authenticated against it. That
    // is true of a resolved, non-empty set and of nothing else — under `Invalid` it would be a claim
    // about a chain that does not exist, so that state answers the bootstrap question not at all and
    // lets `lotl_code` carry the whole verdict.
    if bootstrap && matches!(config, AnchorConfig::Resolved(anchors) if !anchors.is_empty()) {
        view.lotl_bootstrap_code = Some(codes::LOTL_BOOTSTRAP_NOT_APPLICABLE.to_owned());
    }
    view
}

fn suggest(
    sources: &[TslSourceSettings],
    config: &AnchorConfig,
    lotl_url: &str,
    fetch: FetchTsl<'_>,
    now: OffsetDateTime,
    bootstrap: bool,
) -> TrustAnchorSuggestionsView {
    let lotl_url = lotl_url.to_owned();
    let checked_at = now.format(&Rfc3339).unwrap_or_default();

    let enabled: Vec<&TslSourceSettings> = sources.iter().filter(|entry| entry.enabled).collect();

    // Step 0: is the anchor configuration even readable? Until that is settled, "no anchor is
    // configured" is not a statement this endpoint is entitled to make — and it is the statement
    // that unlocks the bootstrap offer. See [`AnchorConfig`].
    let anchors = match config {
        AnchorConfig::Resolved(anchors) => anchors,
        AnchorConfig::Invalid(detail) => {
            return refused(
                checked_at,
                lotl_url,
                codes::LOTL_ANCHOR_CONFIG_INVALID,
                Some(detail.clone()),
                config,
                &enabled,
                // Emphatically not the bootstrap path: this operator HAS an anchor.
                BootstrapOutcome::default(),
            );
        }
    };

    // Step 1: the root of trust. No anchor means no member-state proposal — every one of those
    // flows from the LOTL, and nothing has authenticated the LOTL.
    //
    // The bootstrap candidate is the single exception, and it does not weaken this: it is asked for
    // explicitly, it is about the LOTL and no other list, and it arrives labelled as unverified.
    // The verdict below is unchanged whether it was asked for or not.
    if anchors.is_empty() {
        return refused(
            checked_at,
            lotl_url.clone(),
            codes::LOTL_ANCHOR_NOT_CONFIGURED,
            None,
            config,
            &enabled,
            if bootstrap {
                lotl_self_asserted(&lotl_url, fetch)
            } else {
                BootstrapOutcome::default()
            },
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
                config,
                &enabled,
                BootstrapOutcome::default(),
            );
        }
    };

    let lotl = match ingest_lotl(&lotl_bytes, &anchors.anchors) {
        Ok(list) => list,
        Err(e) => {
            return refused(
                checked_at,
                lotl_url,
                codes::LOTL_NOT_AUTHENTICATED,
                Some(truncate(&e.to_string(), DETAIL_MAX_CHARS)),
                config,
                &enabled,
                BootstrapOutcome::default(),
            );
        }
    };

    if lotl.list.other_tsl_pointers.is_empty() {
        return refused(
            checked_at,
            lotl_url,
            codes::LOTL_NO_POINTERS,
            None,
            config,
            &enabled,
            BootstrapOutcome::default(),
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
        // The LOTL authenticated — against *an* anchor. When one of the configured anchors is a
        // trust-on-first-use fingerprint, this is what stops "authenticated" from laundering that
        // root into a verified one on the way to the operator's screen.
        lotl_anchor_self_asserted: anchors.self_asserted,
        lotl_code: codes::LOTL_AUTHENTICATED.to_owned(),
        lotl_detail: None,
        lotl_bootstrap_code: None,
        lotl_bootstrap_detail: None,
        lotl_proposals: Vec::new(),
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
    config: &AnchorConfig,
    enabled: &[&TslSourceSettings],
    bootstrap: BootstrapOutcome,
) -> TrustAnchorSuggestionsView {
    TrustAnchorSuggestionsView {
        checked_at,
        lotl_url,
        lotl_authenticated: false,
        // Still reported on a refusal: whether the deployment's anchors are annotated is a fact
        // about the deployment, not about whether this particular run reached the network.
        lotl_anchor_self_asserted: config.self_asserted(),
        lotl_code: code.to_owned(),
        lotl_detail: detail,
        lotl_bootstrap_code: bootstrap.code,
        lotl_bootstrap_detail: bootstrap.detail,
        lotl_proposals: bootstrap.proposals,
        configured_anchor_count: config.anchor_count(),
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

/// The answer to the bootstrap question: its outcome code, any transport detail, and the single
/// candidate — or none. Default is "not asked", which is what a plain run carries.
#[derive(Debug, Default)]
struct BootstrapOutcome {
    code: Option<String>,
    detail: Option<String>,
    proposals: Vec<TrustAnchorProposalView>,
}

/// Fetch the EU LOTL and offer the certificate its own signature names, as an unverified candidate.
///
/// Reached only when **no anchor is configured** and the operator explicitly asked. Three things are
/// load-bearing about how little this function does:
///
/// - it uses the same bounded, SSRF-vetted fetch, timeout and size ceiling as the authenticated
///   path — there is no second way out to the network, and the destination is the resolved LOTL URL,
///   not anything a caller supplied;
/// - it never touches `ingest_lotl`. Verifying the document against its own certificate would
///   produce a signature check that always passes and an "authenticated" that means nothing. The
///   XML is not even parsed as a Trusted List; only the certificate is lifted out; and
/// - the candidate is built against an **empty** anchor set, so `already_configured` is `false` by
///   construction. It cannot be otherwise: this branch runs only when there are no anchors.
fn lotl_self_asserted(lotl_url: &str, fetch: FetchTsl<'_>) -> BootstrapOutcome {
    let bytes = match fetch(
        lotl_url,
        DEFAULT_TSL_FETCH_TIMEOUT_SECONDS,
        DEFAULT_TSL_FETCH_MAX_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            return BootstrapOutcome {
                code: Some(codes::LOTL_BOOTSTRAP_FETCH_FAILED.to_owned()),
                detail: Some(truncate(&e, DETAIL_MAX_CHARS)),
                proposals: Vec::new(),
            };
        }
    };
    match extract_signer_cert(&bytes) {
        Ok(Some(der)) => BootstrapOutcome {
            code: Some(codes::LOTL_BOOTSTRAP_SELF_ASSERTED.to_owned()),
            detail: None,
            proposals: vec![proposal(
                &der,
                TrustAnchorProvenance::ListSelfAsserted,
                &ResolvedAnchors::new(TslTrustAnchors::new(), &[]),
            )],
        },
        Ok(None) => BootstrapOutcome {
            code: Some(codes::LOTL_BOOTSTRAP_SIGNER_CERT_ABSENT.to_owned()),
            detail: None,
            proposals: Vec::new(),
        },
        Err(e) => BootstrapOutcome {
            code: Some(codes::LOTL_BOOTSTRAP_SIGNER_CERT_ABSENT.to_owned()),
            detail: Some(truncate(&e.to_string(), DETAIL_MAX_CHARS)),
            proposals: Vec::new(),
        },
    }
}

fn suggest_for_source(
    entry: &TslSourceSettings,
    lotl: &TrustedList,
    lotl_url: &str,
    anchors: &ResolvedAnchors,
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
    anchors: &ResolvedAnchors,
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
    anchors: &ResolvedAnchors,
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
            // Withheld once the root is self-asserted, and for the same reason the fallback's PEM
            // is always withheld: a candidate this LOTL vouches for is only as verified as the LOTL,
            // and the LOTL may have authenticated against a trust-on-first-use anchor. Leaving the
            // "add as certificate" route open would be the one way to accept it while losing the
            // annotation, because the annotation is keyed by fingerprint and lives on the field the
            // other button writes.
            TrustAnchorProvenance::EuLotl if !anchors.self_asserted => Some(to_pem(der)),
            _ => None,
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

    /// An anchor set with **no** self-asserted annotation over it — the ordinary, verified case.
    fn resolved(anchors: TslTrustAnchors) -> ResolvedAnchors {
        ResolvedAnchors::new(anchors, &[])
    }

    /// The same, as the flow's entry-point argument.
    fn config(anchors: TslTrustAnchors) -> AnchorConfig {
        AnchorConfig::Resolved(resolved(anchors))
    }

    /// An anchor set every member of which the operator accepted on first use.
    fn config_annotated(anchors: TslTrustAnchors, annotated: &[String]) -> AnchorConfig {
        AnchorConfig::Resolved(ResolvedAnchors::new(anchors, annotated))
    }

    /// The lowercase-hex fingerprint of a synthetic certificate, as it would sit in
    /// `signing.tsl_trust_anchor_self_asserted_sha256`.
    fn fingerprint_of(der: &[u8]) -> String {
        cert_fingerprint(der)
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
            &resolved(TslTrustAnchors::new()),
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
            &resolved(TslTrustAnchors::new()),
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
            &resolved(TslTrustAnchors::new()),
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
            &resolved(anchors),
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
            &config(TslTrustAnchors::new()),
            "https://lotl.example/eu-lotl.xml",
            &no_network,
            now(),
            false,
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
            &resolved(TslTrustAnchors::new()),
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
            &resolved(TslTrustAnchors::new()),
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
            &resolved(TslTrustAnchors::new()),
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
            &config(anchors),
            "https://lotl.example/eu-lotl.xml",
            &serving(forged),
            now(),
            false,
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
            &config(anchors),
            "https://lotl.example/eu-lotl.xml",
            &no_network,
            now(),
            false,
        );

        assert!(!view.lotl_authenticated);
        assert_eq!(view.lotl_code, codes::LOTL_FETCH_FAILED);
        assert_eq!(view.lotl_detail.as_deref(), Some("no network in this test"));
        assert!(view.sources.iter().all(|s| s.proposals.is_empty()));
    }

    // --- The LOTL bootstrap -------------------------------------------------------------------
    //
    // Everything below drives `build_suggestions` with no configured anchor, which is the only
    // state in which the bootstrap candidate exists at all.

    #[test]
    fn without_asking_the_unanchored_run_is_byte_for_byte_what_it_always_was() {
        // The load-bearing negative. An operator who presses the ordinary button must reach the
        // ordinary refusal — no candidate, no bootstrap outcome, nothing to click past. The fetch
        // here would SUCCEED and would yield a certificate, so an accidental default-on would show
        // up as a proposal rather than as an absent one.
        let sources = vec![source(
            "xx",
            Some("https://lists.example/xx.xml"),
            Some("XX"),
        )];

        let view = build_suggestions(
            &sources,
            &config(TslTrustAnchors::new()),
            "https://lotl.example/eu-lotl.xml",
            &serving(list_naming_its_own_signer(&synthetic_cert(11))),
            now(),
            false,
        );

        assert!(!view.lotl_authenticated);
        assert_eq!(view.lotl_code, codes::LOTL_ANCHOR_NOT_CONFIGURED);
        assert_eq!(
            view.lotl_bootstrap_code, None,
            "a question that was not asked has no answer"
        );
        assert!(
            view.lotl_proposals.is_empty(),
            "the bootstrap candidate must never appear on a run that did not ask for it"
        );
        assert!(view.sources.iter().all(|s| s.proposals.is_empty()));
    }

    #[test]
    fn asking_for_the_bootstrap_candidate_yields_one_self_asserted_fingerprint_and_no_pem() {
        let der = synthetic_cert(21);
        let sources = vec![source(
            "xx",
            Some("https://lists.example/xx.xml"),
            Some("XX"),
        )];

        let view = build_suggestions(
            &sources,
            &config(TslTrustAnchors::new()),
            "https://lotl.example/eu-lotl.xml",
            &serving(list_naming_its_own_signer(&der)),
            now(),
            true,
        );

        assert_eq!(
            view.lotl_bootstrap_code.as_deref(),
            Some(codes::LOTL_BOOTSTRAP_SELF_ASSERTED)
        );
        assert_eq!(view.lotl_proposals.len(), 1);
        let candidate = &view.lotl_proposals[0];
        assert_eq!(
            candidate.provenance,
            TrustAnchorProvenance::ListSelfAsserted,
            "the LOTL's own certificate is exactly as self-asserted as a member-state list's; \
             marking it LOTL-derived would make the circularity invisible"
        );
        assert_eq!(candidate.sha256, cert_fingerprint(&der));
        assert_eq!(
            candidate.certificate_pem, None,
            "the fingerprint is the thing to compare against the Official Journal; a pasteable \
             PEM invites skipping that comparison"
        );
        assert!(!candidate.already_configured);

        // And the verdict is untouched: asking the question answered nothing about the list.
        assert!(
            !view.lotl_authenticated,
            "fetching a document over TLS authenticates the server, never the list"
        );
        assert_eq!(view.lotl_code, codes::LOTL_ANCHOR_NOT_CONFIGURED);
        assert_eq!(view.configured_anchor_count, 0);
        assert!(
            view.sources.iter().all(|s| s.proposals.is_empty()),
            "the bootstrap candidate is about the LOTL alone; it must not unlock member-state \
             proposals an unauthenticated LOTL cannot vouch for"
        );
    }

    #[test]
    fn once_an_anchor_exists_no_outcome_can_produce_a_self_asserted_lotl_candidate() {
        // Three ways the anchored flow can end short of success, each asked WITH the bootstrap
        // flag. None may answer it with a candidate: with an anchor configured the LOTL is
        // authenticated against it and every proposal flows from that chain. Asserting it across
        // all three is the point — a single case would leave the other two free to regress.
        let anchors = config(TslTrustAnchors::new().with_cert_der(&synthetic_cert(99)));
        let sources = vec![source(
            "xx",
            Some("https://lists.example/xx.xml"),
            Some("XX"),
        )];
        let forged = lotl_xml(&[pointer(
            "https://lists.example/xx.xml",
            Some("XX"),
            &[synthetic_cert(66)],
        )]);
        /// One boxed [`FetchTsl`] body, so the three cases can sit in one `Vec`.
        type BoxedFetch = Box<dyn Fn(&str, u16, u64) -> Result<Vec<u8>, String>>;
        let cases: Vec<(&str, BoxedFetch)> = vec![
            (codes::LOTL_FETCH_FAILED, Box::new(no_network)),
            (codes::LOTL_NOT_AUTHENTICATED, Box::new(serving(forged))),
            (
                codes::LOTL_NOT_AUTHENTICATED,
                Box::new(serving(list_naming_its_own_signer(&synthetic_cert(21)))),
            ),
        ];

        for (expected, fetch) in cases {
            let view = build_suggestions(
                &sources,
                &anchors,
                "https://lotl.example/eu-lotl.xml",
                &*fetch,
                now(),
                true,
            );

            assert_eq!(view.lotl_code, expected);
            assert_eq!(
                view.lotl_bootstrap_code.as_deref(),
                Some(codes::LOTL_BOOTSTRAP_NOT_APPLICABLE),
                "with an anchor configured there is nothing to bootstrap"
            );
            assert!(
                view.lotl_proposals.is_empty(),
                "a configured anchor must never be joined by a self-asserted one: the operator \
                 would have no way to tell which of the two the deployment is trusting"
            );
        }
    }

    #[test]
    fn a_failed_bootstrap_fetch_says_so_and_carries_the_transport_error() {
        let view = build_suggestions(
            &[],
            &config(TslTrustAnchors::new()),
            "https://lotl.example/eu-lotl.xml",
            &no_network,
            now(),
            true,
        );

        assert_eq!(
            view.lotl_bootstrap_code.as_deref(),
            Some(codes::LOTL_BOOTSTRAP_FETCH_FAILED)
        );
        assert_eq!(
            view.lotl_bootstrap_detail.as_deref(),
            Some("no network in this test"),
            "the operator needs the reason, in the server's own words"
        );
        assert!(view.lotl_proposals.is_empty());
        assert_eq!(
            view.lotl_code,
            codes::LOTL_ANCHOR_NOT_CONFIGURED,
            "a bootstrap answer never overwrites the LOTL step's verdict"
        );
    }

    #[test]
    fn a_lotl_carrying_no_signature_yields_no_bootstrap_candidate() {
        let view = build_suggestions(
            &[],
            &config(TslTrustAnchors::new()),
            "https://lotl.example/eu-lotl.xml",
            &serving(b"<TrustServiceStatusList/>".to_vec()),
            now(),
            true,
        );

        assert_eq!(
            view.lotl_bootstrap_code.as_deref(),
            Some(codes::LOTL_BOOTSTRAP_SIGNER_CERT_ABSENT)
        );
        assert!(view.lotl_proposals.is_empty());
    }

    #[test]
    fn the_bootstrap_fetch_honours_the_module_wide_timeout_and_size_bound() {
        // Not a new fetch path: the same bounded, SSRF-vetted call the authenticated flow makes,
        // at the same ceilings, to the resolved LOTL URL and nothing a caller supplied.
        use std::cell::RefCell;
        let seen: RefCell<Vec<(String, u16, u64)>> = RefCell::new(Vec::new());
        let recording = |url: &str, timeout: u16, max_bytes: u64| {
            seen.borrow_mut().push((url.to_owned(), timeout, max_bytes));
            Err("recorded".to_owned())
        };

        build_suggestions(
            &[],
            &config(TslTrustAnchors::new()),
            "https://lotl.example/eu-lotl.xml",
            &recording,
            now(),
            true,
        );

        assert_eq!(
            seen.into_inner(),
            vec![(
                "https://lotl.example/eu-lotl.xml".to_owned(),
                DEFAULT_TSL_FETCH_TIMEOUT_SECONDS,
                DEFAULT_TSL_FETCH_MAX_BYTES,
            )]
        );
    }

    #[test]
    fn a_disabled_source_is_not_listed() {
        let mut disabled = source("off", Some("https://lists.example/off.xml"), Some("XX"));
        disabled.enabled = false;
        let view = build_suggestions(
            &[disabled],
            &config(TslTrustAnchors::new()),
            "https://lotl.example/eu-lotl.xml",
            &no_network,
            now(),
            false,
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
            &resolved(TslTrustAnchors::new()),
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
            &resolved(TslTrustAnchors::new()),
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
            &resolved(TslTrustAnchors::new()),
            &no_network,
        );

        assert_eq!(row.code, codes::SOURCE_ANCHORS_FROM_LOTL);
        assert_eq!(row.proposals.len(), 1);
    }

    // --- The root of trust's own provenance (t118/C2) ------------------------------------------
    //
    // Everything above stops at `LOTL_NOT_AUTHENTICATED`, which is enough for those claims and not
    // for this one: the defect is what a *successful* authentication reports when the anchor it
    // succeeded against is one the operator accepted on first use. So these sign a LOTL in-process
    // and drive the whole flow through its success arm.

    /// A self-signed certificate carrying `spki`. Its own signature bytes are filler: anchoring
    /// matches on the SHA-256 of the DER and the XML-DSig verifier takes the public key from here,
    /// so nothing reads this certificate's own signature. Synthesized on every run — never a real
    /// certificate, which in a trust-anchor fixture is a value somebody eventually pastes.
    fn self_signed_cert(spki: spki::SubjectPublicKeyInfoOwned) -> Vec<u8> {
        use der::Encode as _;
        use der::asn1::{BitString, ObjectIdentifier};
        use std::str::FromStr as _;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;
        use x509_cert::{Certificate, TbsCertificate, Version};

        let sig_alg = spki::AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        let name = Name::from_str("CN=Anchor suggestion test signer").expect("name");
        let cert = Certificate {
            tbs_certificate: TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&[1]).expect("serial"),
                signature: sig_alg.clone(),
                issuer: name.clone(),
                validity: Validity::from_now(std::time::Duration::from_secs(365 * 24 * 3600))
                    .expect("validity"),
                subject: name,
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: None,
            },
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&[0u8; 64]).expect("signature bits"),
        };
        cert.to_der().expect("certificate DER")
    }

    /// A LOTL carrying `pointers`, signed in-process by a fresh P-256 key. Returns the document and
    /// the DER of the certificate an operator would have to anchor for it to authenticate.
    fn signed_lotl(pointers: &[String]) -> (Vec<u8>, Vec<u8>) {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer as _;
        use rsa::rand_core::OsRng;
        use sha2::{Digest as _, Sha256};

        const EXC_C14N_10: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
        const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
        const SHA256_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

        let unsigned = String::from_utf8(lotl_xml(pointers)).expect("synthetic LOTL is UTF-8");
        let key = SigningKey::random(&mut OsRng);
        let spki = spki::SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())
            .expect("p256 subject public key info");
        let cert_der = self_signed_cert(spki);

        // The reference is `URI=""`: the whole document with the `<ds:Signature>` element spliced
        // out, which is exactly the pre-insertion text.
        let digest = Sha256::digest(unsigned.as_bytes());
        let signed_info = format!(
            r#"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC_C14N_10}"/><ds:SignatureMethod Algorithm="{ECDSA_SHA256}"/><ds:Reference URI=""><ds:DigestMethod Algorithm="{SHA256_DIGEST}"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#,
            B64.encode(digest)
        );
        let signature: p256::ecdsa::Signature = key.sign(signed_info.as_bytes());
        let element = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
            B64.encode(signature.to_bytes()),
            B64.encode(&cert_der)
        );
        let insert_at = unsigned
            .find("</tsl:TrustServiceStatusList>")
            .expect("synthetic LOTL root close");
        let xml = format!(
            "{}{}{}",
            &unsigned[..insert_at],
            element,
            &unsigned[insert_at..]
        );
        (xml.into_bytes(), cert_der)
    }

    /// A signed LOTL naming one member-state list: the document, the certificate that authenticates
    /// it, and the certificate its pointer proposes. Each call mints a fresh key, so a fingerprint
    /// taken from one call names nothing in another.
    fn signed_lotl_with_one_member() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let member_cert = synthetic_cert(31);
        let (xml, signer) = signed_lotl(&[pointer(
            "https://lists.example/xx.xml",
            Some("XX"),
            std::slice::from_ref(&member_cert),
        )]);
        (xml, signer, member_cert)
    }

    /// One authenticated run over `xml`, against `anchors`, with `annotated` as the deployment's
    /// `signing.tsl_trust_anchor_self_asserted_sha256`.
    fn authenticated_run(
        xml: Vec<u8>,
        anchors: TslTrustAnchors,
        annotated: &[String],
    ) -> TrustAnchorSuggestionsView {
        let sources = vec![source(
            "xx",
            Some("https://lists.example/xx.xml"),
            Some("XX"),
        )];
        build_suggestions(
            &sources,
            &config_annotated(anchors, annotated),
            "https://lotl.example/eu-lotl.xml",
            &serving(xml),
            now(),
            false,
        )
    }

    #[test]
    fn a_clean_verified_root_authenticates_with_no_self_asserted_mark_and_a_pasteable_pem() {
        // The negative that makes the mark a signal rather than decoration, and the proof that the
        // signed fixture really does reach the success arm.
        let (xml, signer, _) = signed_lotl_with_one_member();
        let view = authenticated_run(xml, TslTrustAnchors::new().with_cert_der(&signer), &[]);

        assert!(
            view.lotl_authenticated,
            "the signed fixture must authenticate"
        );
        assert_eq!(view.lotl_code, codes::LOTL_AUTHENTICATED);
        assert!(
            !view.lotl_anchor_self_asserted,
            "an anchor nobody annotated is a verified anchor; marking it would make the warning \
             always-on and therefore worthless"
        );
        let proposals = &view.sources[0].proposals;
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].provenance, TrustAnchorProvenance::EuLotl);
        assert!(
            proposals[0].certificate_pem.is_some(),
            "a candidate under a verified root is still meant to be pasted"
        );
    }

    #[test]
    fn a_lotl_authenticated_against_an_annotated_anchor_reports_the_root_as_self_asserted() {
        // The laundering path in full: the bootstrap wrote a trust-on-first-use fingerprint, the
        // LOTL now authenticates against that very fingerprint, and every member-state candidate
        // below descends from a root nobody has checked.
        let (xml, signer, member_cert) = signed_lotl_with_one_member();
        let view = authenticated_run(
            xml,
            TslTrustAnchors::new().with_cert_der(&signer),
            &[fingerprint_of(&signer)],
        );

        assert!(
            view.lotl_authenticated,
            "it DOES authenticate — against the anchor it supplied itself, which is the whole \
             problem: the verdict is true and the trust it implies is not"
        );
        assert!(
            view.lotl_anchor_self_asserted,
            "an authenticated run whose only anchor was accepted on first use must say so, or the \
             deployment retains no record that its entire anchor set descends from an unverified \
             root"
        );
        let proposals = &view.sources[0].proposals;
        assert_eq!(
            proposals.len(),
            1,
            "the pointer's certificate is still shown"
        );
        assert_eq!(
            proposals[0].provenance,
            TrustAnchorProvenance::EuLotl,
            "the provenance is unchanged and honest: it DID come from the LOTL"
        );
        assert_eq!(
            proposals[0].certificate_pem, None,
            "the PEM is withheld so the only route to accepting this candidate is the fingerprint \
             button, which carries the annotation; a pasteable PEM lands in \
             tsl_trust_anchor_certs, where the fingerprint-keyed annotation cannot follow it"
        );
        assert_eq!(proposals[0].sha256, cert_fingerprint(&member_cert));
    }

    #[test]
    fn a_mixed_anchor_set_still_reports_a_self_asserted_root() {
        // The deliberate over-warn, asserted in BOTH directions. `validate_tsl_signature_with_anchors`
        // reports that an anchor matched and never which one, so with one verified and one
        // unverified anchor configured the root may be either. Warning when it might be unverified
        // costs a screen of copy; going quiet presents a possibly-unverified root as verified.
        let other = synthetic_cert(77);
        let mixed = |signer: &[u8]| {
            TslTrustAnchors::new()
                .with_cert_der(signer)
                .with_cert_der(&other)
        };

        // (a) neither of the two anchors is annotated — the ordinary verified deployment.
        let (xml, signer, _) = signed_lotl_with_one_member();
        let view = authenticated_run(xml, mixed(&signer), &[]);
        assert!(view.lotl_authenticated);
        assert!(!view.lotl_anchor_self_asserted);

        // (b) the annotated anchor is the one the LOTL did NOT match. Unknowable from here — the
        //     verifier reports that an anchor matched, never which — so the root is still marked.
        let (xml, signer, _) = signed_lotl_with_one_member();
        let view = authenticated_run(xml, mixed(&signer), &[fingerprint_of(&other)]);
        assert!(view.lotl_authenticated);
        assert!(
            view.lotl_anchor_self_asserted,
            "an unverified anchor anywhere in the set means the root MAY be unverified, and \
             'may be unverified' is not 'verified'"
        );

        // (c) the annotated anchor IS the one it matched, with a verified anchor also present.
        let (xml, signer, _) = signed_lotl_with_one_member();
        let annotated = vec![fingerprint_of(&signer)];
        let view = authenticated_run(xml, mixed(&signer), &annotated);
        assert!(view.lotl_anchor_self_asserted);
        assert_eq!(
            view.sources[0].proposals[0].certificate_pem, None,
            "a mixed set withholds the PEM too: the candidate is only as verified as the root"
        );
    }

    #[test]
    fn a_stale_annotation_whose_anchor_was_removed_does_not_mark_the_root() {
        // `validate_tsl_trust_anchors` deliberately neither prunes nor rejects an annotation that
        // matches no anchor — pruning would erase the record. Reading the bare list would therefore
        // latch the warning on for ever the moment the operator deleted the anchor they were warned
        // about, which is exactly when the warning should stop.
        let (xml, signer, _) = signed_lotl_with_one_member();
        let view = authenticated_run(
            xml,
            TslTrustAnchors::new().with_cert_der(&signer),
            &[fingerprint_of(&synthetic_cert(200))],
        );

        assert!(view.lotl_authenticated);
        assert!(!view.lotl_anchor_self_asserted);
        assert!(view.sources[0].proposals[0].certificate_pem.is_some());
    }

    #[test]
    fn the_self_asserted_mark_is_reported_on_a_refused_run_too() {
        // It is a fact about the deployment's anchors, not about whether this run reached the
        // network — so a failed fetch must not make it look as though the root became verified.
        let anchors = TslTrustAnchors::new().with_cert_der(&synthetic_cert(99));
        let annotated = vec![fingerprint_of(&synthetic_cert(99))];

        let view = build_suggestions(
            &[],
            &config_annotated(anchors, &annotated),
            "https://lotl.example/eu-lotl.xml",
            &no_network,
            now(),
            false,
        );

        assert_eq!(view.lotl_code, codes::LOTL_FETCH_FAILED);
        assert!(view.lotl_anchor_self_asserted);
    }

    #[test]
    fn the_annotation_is_intersected_with_the_anchor_set_not_read_on_its_own() {
        let der = synthetic_cert(5);
        let anchors = || TslTrustAnchors::new().with_cert_der(&der);
        let fingerprint = fingerprint_of(&der);

        assert!(intersects_annotation(&anchors(), std::slice::from_ref(&fingerprint)));
        assert!(
            !intersects_annotation(&anchors(), &[]),
            "no annotation, no mark"
        );
        assert!(
            !intersects_annotation(&TslTrustAnchors::new(), std::slice::from_ref(&fingerprint)),
            "an empty anchor set trusts nothing, so there is no root to mark"
        );
        assert!(
            !intersects_annotation(&anchors(), &[fingerprint_of(&synthetic_cert(6))]),
            "an annotation naming a different certificate is inert"
        );
        assert!(
            intersects_annotation(
                &anchors(),
                &[fingerprint.clone(), fingerprint.clone(), "  ".to_owned()]
            ),
            "duplicates and blanks must not confuse the cardinality identity the intersection is \
             computed with"
        );
        assert!(
            !intersects_annotation(&anchors(), &["not-a-fingerprint".to_owned()]),
            "an entry that is not a fingerprint names no anchor"
        );
        assert!(
            intersects_annotation(&anchors(), &[fingerprint.to_ascii_uppercase()]),
            "the same fingerprint retyped in upper case is the same anchor"
        );
    }

    // --- An unreadable anchor configuration (t118/C6) ------------------------------------------

    #[test]
    fn an_unreadable_anchor_configuration_gets_its_own_code_and_never_the_bootstrap_offer() {
        use std::cell::RefCell;
        // The fetch here would SUCCEED and would yield a certificate, so a flow that fell through
        // to the bootstrap would show up as a candidate rather than as an absent one. It also
        // records, because the right behaviour is not to reach the network at all.
        let fetched: RefCell<usize> = RefCell::new(0);
        let recording = |_: &str, _: u16, _: u64| {
            *fetched.borrow_mut() += 1;
            Ok(list_naming_its_own_signer(&synthetic_cert(11)))
        };
        let sources = vec![source(
            "xx",
            Some("https://lists.example/xx.xml"),
            Some("XX"),
        )];

        let view = build_suggestions(
            &sources,
            &AnchorConfig::Invalid("trust-anchor file is empty".to_owned()),
            "https://lotl.example/eu-lotl.xml",
            &recording,
            now(),
            true,
        );

        assert_eq!(
            view.lotl_code,
            codes::LOTL_ANCHOR_CONFIG_INVALID,
            "an operator whose anchor cannot be READ must not be told they have none: that \
             sentence is false about their deployment, and it is the sentence that unlocks the \
             trust-on-first-use offer"
        );
        assert_ne!(view.lotl_code, codes::LOTL_ANCHOR_NOT_CONFIGURED);
        assert_eq!(
            view.lotl_detail.as_deref(),
            Some("trust-anchor file is empty"),
            "the operator needs the reason, in the library's own words"
        );
        assert!(!view.lotl_authenticated);
        assert!(
            !view.lotl_anchor_self_asserted,
            "nothing is known about a set that could not be built"
        );
        assert_eq!(
            view.lotl_bootstrap_code, None,
            "'not applicable' claims the LOTL is authenticated against a configured anchor, which \
             is false here; the verdict code carries the whole answer instead"
        );
        assert!(
            view.lotl_proposals.is_empty(),
            "the bootstrap candidate would replace a real anchor with an unverified one"
        );
        assert_eq!(
            *fetched.borrow(),
            0,
            "nothing is fetched before the anchors resolve"
        );
        assert_eq!(view.sources.len(), 1, "the source is still accounted for");
        assert_eq!(view.sources[0].code, codes::LOTL_ANCHOR_CONFIG_INVALID);
        assert!(view.sources[0].proposals.is_empty());
    }

    #[test]
    fn a_resolution_failure_is_kept_as_a_failure_rather_than_degrading_to_unanchored() {
        // Through the real resolver, on the settings arm so no environment variable is touched: a
        // fingerprint that is not 64 hex characters cannot be parsed, and the old
        // `unwrap_or_else(|_| TslTrustAnchors::new())` turned exactly this into "no anchor".
        let config = AnchorConfig::resolve(&[], &["not-64-hex".to_owned()], &[]);

        assert!(
            matches!(config, AnchorConfig::Invalid(_)),
            "an anchor configuration that cannot be built is not an empty anchor configuration"
        );
        assert_eq!(config.anchor_count(), 0);
        assert!(!config.self_asserted());
    }

    #[test]
    fn every_code_this_module_emits_is_in_the_closed_list() {
        // The client's completeness test reads the closed list; a code emitted from here but never
        // listed there would render as a raw identifier in fourteen locales.
        for code in [
            codes::LOTL_AUTHENTICATED,
            codes::LOTL_ANCHOR_NOT_CONFIGURED,
            codes::LOTL_ANCHOR_CONFIG_INVALID,
            codes::LOTL_FETCH_FAILED,
            codes::LOTL_NOT_AUTHENTICATED,
            codes::LOTL_NO_POINTERS,
            codes::LOTL_BOOTSTRAP_SELF_ASSERTED,
            codes::LOTL_BOOTSTRAP_FETCH_FAILED,
            codes::LOTL_BOOTSTRAP_SIGNER_CERT_ABSENT,
            codes::LOTL_BOOTSTRAP_NOT_APPLICABLE,
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
