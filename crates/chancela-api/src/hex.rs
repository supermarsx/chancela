//! Hand-rolled lowercase hex for the 32-byte digests the ledger and acts carry.
//!
//! The domain models digests as `[u8; 32]` (sha-256), which serde would otherwise emit as a
//! JSON array of integers. The pinned API contract (§2.1) requires **lowercase hex strings**,
//! so the DTO layer converts every digest through [`hex`] on the way out and [`parse_hex32`]
//! on the way in. This is a couple of lines, so we do it here rather than pull in a crate.

/// Encode a 32-byte digest as a 64-character lowercase hex string.
pub fn hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &b in bytes {
        // `from_digit(_, 16)` yields lowercase `a`–`f`; the nibbles are always < 16.
        s.push(char::from_digit((b >> 4) as u32, 16).expect("high nibble < 16"));
        s.push(char::from_digit((b & 0x0f) as u32, 16).expect("low nibble < 16"));
    }
    s
}

/// Parse a 64-character lowercase/uppercase hex string back into a 32-byte digest.
///
/// Returns `None` on any length or character error so callers can map it to a `422`.
pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        *slot = (hi * 16 + lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_digest() {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = i as u8;
        }
        let s = hex(&d);
        assert_eq!(s.len(), 64);
        assert!(s.starts_with("000102030405"));
        assert_eq!(parse_hex32(&s), Some(d));
    }

    #[test]
    fn rejects_malformed_hex() {
        assert_eq!(parse_hex32("abc"), None);
        assert_eq!(parse_hex32(&"z".repeat(64)), None);
    }
}
