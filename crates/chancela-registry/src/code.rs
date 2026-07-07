//! The [`AccessCode`] — a validated, secret certidão permanente access code.

use crate::error::RegistryError;

/// A validated certidão permanente access code (12 digits, canonical `XXXX-XXXX-XXXX`).
///
/// The value is a **secret**: possession of the code grants full access to the entity's registry
/// record, so `Debug` renders it masked and there is no `Display` / `Serialize` that leaks the full
/// code. The full digits are reachable only via [`AccessCode::expose_secret`], used solely by the
/// transport when building the request URL (LEG-22 / GDPR — see plan t11 §2.6).
#[derive(Clone, PartialEq, Eq)]
pub struct AccessCode {
    /// Canonical `XXXX-XXXX-XXXX` form (12 digits, grouped in threes-of-four by hyphens).
    canonical: String,
}

impl AccessCode {
    /// Parse & normalize: strip every non-digit, require **exactly 12** digits, store the canonical
    /// `XXXX-XXXX-XXXX` form.
    ///
    /// Returns [`RegistryError::InvalidCode`] on failure. The message NEVER echoes the raw code —
    /// it reports only the (mismatched) digit count, so a mistyped secret cannot leak through logs.
    pub fn parse(raw: &str) -> Result<Self, RegistryError> {
        let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() != 12 {
            return Err(RegistryError::InvalidCode(format!(
                "expected exactly 12 digits, found {}",
                digits.len()
            )));
        }
        let canonical = format!("{}-{}-{}", &digits[0..4], &digits[4..8], &digits[8..12]);
        Ok(Self { canonical })
    }

    /// `****-****-NNNN` — safe for logs, provenance, ledger payloads and error messages. Reveals
    /// only the last four digits (enough to distinguish two codes at a glance, not to consult one).
    pub fn masked(&self) -> String {
        // `canonical` is always exactly `XXXX-XXXX-XXXX`; the last group is the final 4 chars.
        let last4 = &self.canonical[self.canonical.len() - 4..];
        format!("****-****-{last4}")
    }

    /// The full `XXXX-XXXX-XXXX` — ONLY for building the live request. Never logged or stored.
    pub fn expose_secret(&self) -> String {
        self.canonical.clone()
    }
}

/// `Debug` prints the **masked** form so the secret never leaks into logs or panic messages.
impl std::fmt::Debug for AccessCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AccessCode").field(&self.masked()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_canonicalizes_grouped_input() {
        let c = AccessCode::parse("7110-6727-7477").unwrap();
        assert_eq!(c.expose_secret(), "7110-6727-7477");
    }

    #[test]
    fn strips_arbitrary_separators_and_whitespace() {
        let c = AccessCode::parse("  7110 6727.7477  ").unwrap();
        assert_eq!(c.expose_secret(), "7110-6727-7477");
        let bare = AccessCode::parse("711067277477").unwrap();
        assert_eq!(bare.expose_secret(), "7110-6727-7477");
    }

    #[test]
    fn rejects_wrong_length_without_echoing_the_code() {
        let err = AccessCode::parse("7110-6727-74").unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, RegistryError::InvalidCode(_)));
        // The message must never contain the raw digits that were supplied.
        assert!(!msg.contains("7110"));
        assert!(msg.contains("10")); // reports the found digit count (10)
    }

    #[test]
    fn non_ascii_digits_do_not_count_as_digits() {
        // Full-width and other Unicode "digit" characters are not `is_ascii_digit`, so they are
        // stripped like any other non-digit — a code typed with them fails the 12-digit check
        // rather than being silently accepted. Twelve full-width digits fold to zero ASCII digits.
        let fullwidth = "７１１０６７２７７４７７"; // U+FF10..U+FF19, 12 chars
        assert_eq!(fullwidth.chars().count(), 12);
        let err = AccessCode::parse(fullwidth).unwrap_err();
        assert!(matches!(err, RegistryError::InvalidCode(_)));
        // None of the 12 characters were counted as digits.
        assert!(err.to_string().contains('0'));
    }

    #[test]
    fn strips_interspersed_letters_leaving_exactly_the_digits() {
        // `parse` strips every non-digit (not just separators), so letters mixed into the input are
        // removed and only the twelve ASCII digits are retained and canonicalized.
        let c = AccessCode::parse("AB7110cd6727EF7477").unwrap();
        assert_eq!(c.expose_secret(), "7110-6727-7477");
    }

    #[test]
    fn masks_all_but_the_last_four() {
        let c = AccessCode::parse("7110-6727-7477").unwrap();
        assert_eq!(c.masked(), "****-****-7477");
    }

    #[test]
    fn debug_renders_masked_never_the_full_code() {
        let c = AccessCode::parse("7110-6727-7477").unwrap();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("****-****-7477"));
        assert!(!dbg.contains("7110"));
        assert!(!dbg.contains("6727"));
    }
}
