//! The stable machine vocabulary for **trust-anchor suggestions** (t118).
//!
//! # Why this module exists
//!
//! `GET /v1/trust/anchor-suggestions` answers a question that is mostly *bad news*: for each
//! configured Trusted List source it says either "the authenticated EU LOTL vouches for these
//! certificates" or one of several distinct reasons why it does not. Every one of those reasons is
//! a sentence an operator reads on the settings screen, and a sentence written in `chancela-api` is
//! invisible to both `noLiteralUiCopy` and `catalogLeakGate` — they inspect the web app and cannot
//! see prose that arrives over the wire.
//!
//! So the endpoint follows the convention `provider_probe_codes.rs` established: **the wire stays
//! English and stable, and the client maps a stable identifier to a catalog key.** Every outcome
//! carries a `code` from the closed list below, and the client renders the operator's language.
//!
//! Unlike the probe DTO, there is no English `detail` sentence riding alongside. That is deliberate
//! here: the codes below are *complete* outcomes, not summaries of a free-form diagnosis, and a
//! second English rendering of the same fact would be one more thing to keep in step. Where a
//! machine detail genuinely varies — a fetch error string — it travels as a separate `detail` field
//! that the client presents as the server's own words, exactly as the probe does.
//!
//! # The rules these constants obey
//!
//! - **English, snake_case, never translated.** They are machine identifiers.
//! - **One code per distinct sentence.** Two outcomes that say the same thing share a code.
//! - **A code is append-only.** Renaming one silently changes what a client renders; deleting one
//!   makes an older client's translation dead. Add, do not edit.
//!
//! # The guard
//!
//! [`ALL_TRUST_ANCHOR_SUGGESTION_CODES`] is the closed list, and
//! `apps/web/src/i18n/trustAnchorSuggestions.test.ts` reads **this file** to prove the client maps
//! every one of them to a catalog key in all fourteen locales.

// --- LOTL outcomes -------------------------------------------------------------------------------
//
// The whole endpoint hangs off one question: did the EU LOTL authenticate against the operator's
// own anchors? If it did not, NOTHING is proposed — not even the from-the-list-itself fallback,
// which exists to cover a source the *authenticated* LOTL has no pointer for. An unauthenticated
// LOTL is an attacker-controllable document, and letting it decide which lists get a fallback
// candidate would hand the attacker the choice.

/// The LOTL verified against a configured anchor. Proposals below are derived from it.
pub const LOTL_AUTHENTICATED: &str = "lotl_authenticated";

/// No LOTL trust anchor is configured, in settings or in the environment. The LOTL is the root of
/// trust and cannot authenticate itself, so nothing is proposed. This is the bootstrap case: the
/// first anchor must come from the Official Journal, by hand — no assistant can supply it.
pub const LOTL_ANCHOR_NOT_CONFIGURED: &str = "lotl_anchor_not_configured";

/// A trust anchor **is** configured, and the configured set could not be built: a certificate file
/// named by `CHANCELA_TSL_TRUST_ANCHOR` that cannot be read, a malformed PEM, a fingerprint that is
/// not 64 hex characters.
///
/// Distinct from [`LOTL_ANCHOR_NOT_CONFIGURED`] and never collapsed into it, for the same reason
/// `provider_credentials_write::CmdTrustAnchorPreflight` keeps `AnchorsInvalid` apart from
/// `Unanchored`: the two states call for opposite actions. "No anchor" invites the operator to
/// establish one, and the assistant offers a trust-on-first-use candidate to start from. "Anchor
/// unreadable" means they already have one and something in the deployment — most often an unmounted
/// secret — is hiding it, and offering them a self-asserted candidate would walk an operator who has
/// a real anchor into replacing it with an unverified one.
pub const LOTL_ANCHOR_CONFIG_INVALID: &str = "lotl_anchor_config_invalid";

/// The LOTL could not be fetched (network, timeout, size bound, or a blocked destination).
pub const LOTL_FETCH_FAILED: &str = "lotl_fetch_failed";

/// The LOTL was fetched but its own signature did not verify against a configured anchor, or it
/// could not be parsed. Fail-closed: an unauthenticated list proposes nothing.
pub const LOTL_NOT_AUTHENTICATED: &str = "lotl_not_authenticated";

/// The LOTL authenticated but carries no pointers to member-state lists — so it is not a List of
/// Trusted Lists at all, and vouches for nothing.
pub const LOTL_NO_POINTERS: &str = "lotl_no_pointers";

// --- LOTL bootstrap outcomes ---------------------------------------------------------------------
//
// [`LOTL_ANCHOR_NOT_CONFIGURED`] is a dead end for an operator who has no anchor and no copy of the
// Official Journal to hand: the assistant tells them the value must be entered by hand and offers
// nothing further. These codes cover the one thing that CAN be shown in that state — the certificate
// the LOTL document itself carries — and they exist as a **separate** field from `lotl_code` for a
// reason worth writing down: nothing about the LOTL step's verdict changes. It still did not
// authenticate, `lotl_authenticated` is still false, and no member-state proposal is produced. The
// bootstrap outcome is a strictly additional answer to a strictly additional question, asked only
// when the operator explicitly asks it.
//
// The candidate carries `TrustAnchorProvenance::ListSelfAsserted`, the same provenance a
// member-state list's own certificate carries, and for the same reason: fetching the document over
// TLS authenticated the *server*, not the list. That rules out a passive network observer and
// nothing else — whoever served that document also chose the certificate inside it. The value only
// becomes an anchor once a human has compared its SHA-256 fingerprint against the one published in
// the Official Journal of the European Union.

/// The operator asked for the bootstrap candidate, and the fetched LOTL carries a certificate in
/// its own signature. It is offered as an **unverified** candidate: it authenticates nothing by
/// itself and must be compared against the Official Journal fingerprint before it is relied on.
pub const LOTL_BOOTSTRAP_SELF_ASSERTED: &str = "lotl_bootstrap_self_asserted";

/// The operator asked for the bootstrap candidate, but the LOTL could not be fetched (network,
/// timeout, size bound, or a blocked destination), so there is nothing to show.
pub const LOTL_BOOTSTRAP_FETCH_FAILED: &str = "lotl_bootstrap_fetch_failed";

/// The operator asked for the bootstrap candidate and the LOTL was fetched, but it carries no
/// certificate in its XML signature, so there is no candidate at all.
pub const LOTL_BOOTSTRAP_SIGNER_CERT_ABSENT: &str = "lotl_bootstrap_signer_cert_absent";

/// The operator asked for the bootstrap candidate while an anchor **is** already configured. There
/// is nothing to bootstrap: the LOTL is authenticated against that anchor and proposals come from
/// the authenticated chain. Refusing here is not pedantry — offering a self-asserted candidate
/// beside verified ones is exactly the confusion this whole vocabulary exists to prevent.
pub const LOTL_BOOTSTRAP_NOT_APPLICABLE: &str = "lotl_bootstrap_not_applicable";

// --- Per-source outcomes -------------------------------------------------------------------------

/// The authenticated LOTL carries a pointer for this source, and the pointer names the
/// certificate(s) the list's signature is expected to verify against. These are real proposals.
pub const SOURCE_ANCHORS_FROM_LOTL: &str = "source_anchors_from_lotl";

/// This source IS the List of Trusted Lists. Its anchor is published out of band by the European
/// Commission and is never proposed from the list itself — that would be circular.
pub const SOURCE_IS_LOTL: &str = "source_is_lotl";

/// The authenticated LOTL has no pointer matching this source, so nothing vouches for it. Any
/// candidate shown for this source came out of the list's own signature and proves nothing.
pub const SOURCE_NOT_IN_LOTL: &str = "source_not_in_lotl";

/// The authenticated LOTL's pointer for this source carries no signer certificate, so the pointer
/// vouches for nothing. Any candidate shown came out of the list's own signature.
pub const SOURCE_POINTER_WITHOUT_SIGNER_CERT: &str = "source_pointer_without_signer_cert";

/// The list itself could not be fetched, so not even an unverified candidate could be shown.
pub const SOURCE_FETCH_FAILED: &str = "source_fetch_failed";

/// The list was fetched but carries no certificate in its XML signature, so there is no candidate
/// to show at all.
pub const SOURCE_SIGNER_CERT_ABSENT: &str = "source_signer_cert_absent";

/// The source has no URL this endpoint can fetch (it is file-backed, or its location is empty).
/// Nothing is proposed for it.
pub const SOURCE_LOCATION_UNSUPPORTED: &str = "source_location_unsupported";

/// The closed list every code above belongs to.
///
/// `apps/web/src/i18n/trustAnchorSuggestions.test.ts` reads both this list and the `pub const`
/// declarations, and cross-checks them — a constant declared but never listed here would otherwise
/// be invisible to a scan of the list alone.
pub const ALL_TRUST_ANCHOR_SUGGESTION_CODES: &[&str] = &[
    LOTL_AUTHENTICATED,
    LOTL_ANCHOR_NOT_CONFIGURED,
    LOTL_ANCHOR_CONFIG_INVALID,
    LOTL_FETCH_FAILED,
    LOTL_NOT_AUTHENTICATED,
    LOTL_NO_POINTERS,
    LOTL_BOOTSTRAP_SELF_ASSERTED,
    LOTL_BOOTSTRAP_FETCH_FAILED,
    LOTL_BOOTSTRAP_SIGNER_CERT_ABSENT,
    LOTL_BOOTSTRAP_NOT_APPLICABLE,
    SOURCE_ANCHORS_FROM_LOTL,
    SOURCE_IS_LOTL,
    SOURCE_NOT_IN_LOTL,
    SOURCE_POINTER_WITHOUT_SIGNER_CERT,
    SOURCE_FETCH_FAILED,
    SOURCE_SIGNER_CERT_ABSENT,
    SOURCE_LOCATION_UNSUPPORTED,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_code_is_unique_and_snake_case() {
        let unique: BTreeSet<&&str> = ALL_TRUST_ANCHOR_SUGGESTION_CODES.iter().collect();
        assert_eq!(
            unique.len(),
            ALL_TRUST_ANCHOR_SUGGESTION_CODES.len(),
            "a duplicated code makes two distinct outcomes render as one"
        );
        for code in ALL_TRUST_ANCHOR_SUGGESTION_CODES {
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{code} is not snake_case; the client's extraction regex would miss it"
            );
        }
    }
}
