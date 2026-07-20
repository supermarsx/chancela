//! Per-key rate limiting (t65 plan §3.1 / §3.3).
//!
//! A [`RateLimit`] is the persisted **policy** on a key (`rpm` sustained rate + `burst` capacity); a
//! [`RateLimitState`] is the in-memory token-bucket **state** the API keeps per `ApiKeyId`. The bucket
//! is a classic leaky/token bucket: it refills at `rpm/60` tokens per second up to a ceiling of
//! `burst`, and each request spends one token. This crate owns only the pure, deterministic
//! [`RateLimit::check`] transition — the caller (chancela-api, t65-E3) owns the `ApiKeyId → state` map
//! and enforces the outcome. Keeping the checker pure makes it exhaustively testable without a clock.

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

/// The per-key rate-limit **policy**. Persisted on the key (or defaulted from
/// `integration.rate_limit_default`). `rpm` is the sustained requests-per-minute refill rate; `burst`
/// is the bucket capacity (how many requests may arrive back-to-back before throttling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    /// Sustained requests per minute (token refill rate). `0` disables the key after its initial
    /// burst is spent (no tokens ever refill).
    pub rpm: u32,
    /// Bucket capacity — the maximum burst of back-to-back requests.
    pub burst: u32,
}

impl Default for RateLimit {
    /// The plan §3.3 default: 60 rpm, 20 burst.
    fn default() -> Self {
        RateLimit { rpm: 60, burst: 20 }
    }
}

impl RateLimit {
    /// A policy with an explicit rate and burst.
    #[must_use]
    pub fn new(rpm: u32, burst: u32) -> Self {
        RateLimit { rpm, burst }
    }

    /// Tokens added per second (the sustained rate).
    fn refill_per_second(&self) -> f64 {
        f64::from(self.rpm) / 60.0
    }

    /// The state a fresh bucket starts in: full (a new key may immediately burst).
    #[must_use]
    pub fn initial_state(&self, now: OffsetDateTime) -> RateLimitState {
        RateLimitState {
            tokens: f64::from(self.burst),
            last_refill: now,
        }
    }

    /// Attempt to spend one token at `now`, mutating `state`. Refills first (capped at `burst`), then
    /// either consumes a token ([`RateLimitOutcome::Allowed`]) or reports how long until one token is
    /// available ([`RateLimitOutcome::Limited`]). Deterministic given `state` and `now`.
    pub fn check(&self, state: &mut RateLimitState, now: OffsetDateTime) -> RateLimitOutcome {
        // Refill for the elapsed time (clamp negative clock-skew to zero), capped at capacity.
        let elapsed = (now - state.last_refill).as_seconds_f64().max(0.0);
        let capacity = f64::from(self.burst);
        state.tokens = (state.tokens + elapsed * self.refill_per_second()).min(capacity);
        state.last_refill = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            RateLimitOutcome::Allowed
        } else {
            let rate = self.refill_per_second();
            let retry_after = if rate > 0.0 {
                Duration::seconds_f64((1.0 - state.tokens) / rate)
            } else {
                // rpm == 0: no refill ever — the key is spent for good.
                Duration::seconds(i64::from(u32::MAX))
            };
            RateLimitOutcome::Limited { retry_after }
        }
    }
}

/// The in-memory token-bucket state for one key. Not persisted — the API rebuilds it on demand
/// (a restart simply resets a key's bucket to full, which is safe).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitState {
    tokens: f64,
    last_refill: OffsetDateTime,
}

/// The result of a [`RateLimit::check`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RateLimitOutcome {
    /// A token was available and consumed; the request may proceed.
    Allowed,
    /// The bucket is empty; the request should be rejected (HTTP 429) and may be retried after
    /// `retry_after`.
    Limited { retry_after: Duration },
}

impl RateLimitOutcome {
    /// Whether the request may proceed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitOutcome::Allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    #[test]
    fn burst_is_allowed_then_throttled() {
        let rl = RateLimit::new(60, 5);
        let mut st = rl.initial_state(t0());
        // Five back-to-back requests at the same instant: all allowed (full bucket).
        for _ in 0..5 {
            assert!(rl.check(&mut st, t0()).is_allowed());
        }
        // Sixth at the same instant: throttled.
        assert!(!rl.check(&mut st, t0()).is_allowed());
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimit::new(60, 1); // 1 token/sec, capacity 1
        let mut st = rl.initial_state(t0());
        assert!(rl.check(&mut st, t0()).is_allowed()); // spend the one token
        assert!(!rl.check(&mut st, t0()).is_allowed()); // empty
        // After 1s exactly one token has refilled.
        assert!(rl.check(&mut st, t0() + Duration::seconds(1)).is_allowed());
    }

    #[test]
    fn reports_retry_after_when_limited() {
        let rl = RateLimit::new(60, 1); // 1 token/sec
        let mut st = rl.initial_state(t0());
        assert!(rl.check(&mut st, t0()).is_allowed());
        match rl.check(&mut st, t0()) {
            RateLimitOutcome::Limited { retry_after } => {
                // ~1s until the next token.
                assert!((retry_after.as_seconds_f64() - 1.0).abs() < 1e-6);
            }
            RateLimitOutcome::Allowed => panic!("expected Limited"),
        }
    }

    #[test]
    fn does_not_exceed_capacity_after_long_idle() {
        let rl = RateLimit::new(600, 3);
        let mut st = rl.initial_state(t0());
        // Idle an hour: tokens must cap at burst (3), not accumulate unbounded.
        let later = t0() + Duration::hours(1);
        for _ in 0..3 {
            assert!(rl.check(&mut st, later).is_allowed());
        }
        assert!(!rl.check(&mut st, later).is_allowed());
    }

    #[test]
    fn zero_rpm_key_is_spent_after_burst() {
        let rl = RateLimit::new(0, 2);
        let mut st = rl.initial_state(t0());
        assert!(rl.check(&mut st, t0()).is_allowed());
        assert!(rl.check(&mut st, t0()).is_allowed());
        // No refill ever, even far in the future.
        let outcome = rl.check(&mut st, t0() + Duration::days(365));
        assert!(!outcome.is_allowed());
    }

    #[test]
    fn clock_skew_backwards_does_not_grant_tokens() {
        let rl = RateLimit::new(60, 1);
        let mut st = rl.initial_state(t0());
        assert!(rl.check(&mut st, t0()).is_allowed());
        // now earlier than last_refill (skew) must not refill.
        assert!(!rl.check(&mut st, t0() - Duration::seconds(10)).is_allowed());
    }
}
