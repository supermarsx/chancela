//! Minimal, dependency-free hex encoding/decoding for key material and digests.
//!
//! Keys and their sha256 digests are stored/transmitted as lowercase hex so the on-disk form is
//! human-auditable and header-safe (no base64 padding / URL-unsafe characters), without pulling a
//! `hex`/`base64` crate into this security leaf.

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase-hex encode arbitrary bytes.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode exactly 64 hex chars into a 32-byte digest. Returns `None` for any wrong length or
/// non-hex input — **fail-closed** (a malformed stored hash can never verify).
pub(crate) fn decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, chunk) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        *slot = (nibble(chunk[0])? << 4) | nibble(chunk[1])?;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_a_digest() {
        let bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
        let hex = encode(&bytes);
        assert_eq!(hex.len(), 64);
        assert_eq!(decode_32(&hex), Some(bytes));
    }

    #[test]
    fn rejects_wrong_length_and_non_hex() {
        assert_eq!(decode_32("abcd"), None);
        assert_eq!(decode_32(&"z".repeat(64)), None);
    }
}
