//! A Trusted List cache keyed on the list's own validity window (`NextUpdate`).
//!
//! The Trusted List is large and changes rarely, so `chancela-tsl` caches the parsed list and
//! only re-fetches once the list's advertised `NextUpdate` has passed (SIG-10). A list without a
//! parseable `NextUpdate` is refreshed after a conservative fallback TTL.

use time::{Duration, OffsetDateTime};

use crate::parse::TrustedList;

/// Fallback maximum age for a cached list that advertises no parseable `NextUpdate`. EU trusted
/// lists are re-issued at least every 6 months; 24h keeps a defaulted entry from going stale
/// silently while staying cheap.
pub const FALLBACK_TTL: Duration = Duration::hours(24);

/// A parsed Trusted List together with when it was fetched, able to report its own staleness.
#[derive(Debug, Clone)]
pub struct CachedTsl {
    list: TrustedList,
    fetched_at: OffsetDateTime,
    /// Whether the list's own XML-DSig signature verified (SIG-11, audit t41/C2). When `false`,
    /// the parsed list is advisory and [`crate::query::TslClient`] MUST NOT report
    /// [`crate::query::QualifiedStatus::Granted`] — see `TslClient::is_qualified_for_esig`.
    signature_valid: bool,
}

impl CachedTsl {
    /// Wrap a freshly-parsed list fetched at `fetched_at`, marking the signature as unverified.
    /// Use [`Self::with_signature_valid`] to record the validation result.
    pub fn new(list: TrustedList, fetched_at: OffsetDateTime) -> Self {
        Self {
            list,
            fetched_at,
            signature_valid: false,
        }
    }

    /// Wrap a freshly-parsed list, recording whether its XML-DSig signature verified.
    pub fn with_signature_valid(
        list: TrustedList,
        fetched_at: OffsetDateTime,
        valid: bool,
    ) -> Self {
        Self {
            list,
            fetched_at,
            signature_valid: valid,
        }
    }

    /// The cached list.
    pub fn list(&self) -> &TrustedList {
        &self.list
    }

    /// When the list was fetched.
    pub fn fetched_at(&self) -> OffsetDateTime {
        self.fetched_at
    }

    /// Whether the list's XML-DSig signature was verified successfully at fetch time.
    pub fn signature_valid(&self) -> bool {
        self.signature_valid
    }

    /// The instant at which this cache entry becomes stale: the list's `NextUpdate`, or
    /// `fetched_at + `[`FALLBACK_TTL`] when the list carries no parseable `NextUpdate`.
    pub fn expires_at(&self) -> OffsetDateTime {
        self.list
            .next_update
            .unwrap_or(self.fetched_at + FALLBACK_TTL)
    }

    /// Whether the cache should be re-fetched as of `now` (its validity window has elapsed).
    pub fn is_stale(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at()
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::parse::TrustedList;

    fn list_with_next_update(next_update: Option<OffsetDateTime>) -> TrustedList {
        TrustedList {
            scheme_operator_name: String::new(),
            scheme_operator_names: Vec::new(),
            scheme_name: String::new(),
            scheme_names: Vec::new(),
            scheme_territory: "PT".to_owned(),
            sequence_number: None,
            issue_date_time: None,
            next_update,
            other_tsl_pointers: Vec::new(),
            providers: Vec::new(),
        }
    }

    #[test]
    fn staleness_follows_next_update() {
        let fetched = datetime!(2026-01-15 0:00 UTC);
        let next = datetime!(2026-07-15 0:00 UTC);
        let cache = CachedTsl::new(list_with_next_update(Some(next)), fetched);
        assert_eq!(cache.expires_at(), next);
        assert!(!cache.is_stale(datetime!(2026-07-06 0:00 UTC)));
        assert!(cache.is_stale(next));
        assert!(cache.is_stale(datetime!(2026-08-01 0:00 UTC)));
    }

    #[test]
    fn without_next_update_uses_fallback_ttl() {
        let fetched = datetime!(2026-01-15 0:00 UTC);
        let cache = CachedTsl::new(list_with_next_update(None), fetched);
        assert_eq!(cache.expires_at(), fetched + FALLBACK_TTL);
        assert!(!cache.is_stale(fetched + time::Duration::hours(1)));
        assert!(cache.is_stale(fetched + time::Duration::hours(25)));
    }
}
