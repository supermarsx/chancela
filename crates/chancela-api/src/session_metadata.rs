//! Best-effort, privacy-minded metadata for the "active sign-ins" feature (t95 session backend):
//! a short human device label derived from the `User-Agent`, and a **truncated** client IP.
//!
//! Both are *recognition aids* — enough for an operator to tell "my laptop" from "a session I don't
//! recognise" — not forensic identifiers, and both are optional (`None` when there is nothing to
//! derive). They are personal data in a mutable store, so they are erasable with the session record
//! (see the module note in `session.rs`).
//!
//! ## Why the IP is truncated
//!
//! A full client IP is precise personal data — it can single out an individual and their location.
//! For *recognising your own sessions* a network-level hint is enough: you know your home network's
//! prefix and can spot a foreign one. So the last octet of an IPv4 (`/24`) and everything past the
//! first 48 bits of an IPv6 (`/48`) are zeroed before storage. The stored value is a network, not a
//! host — it still says "a different place signed in" without pinning the exact device. This is a
//! deliberate default; the exact granularity is a decision surfaced to the product owner.

use std::net::IpAddr;

/// The longest device label we keep. A `User-Agent` can be arbitrarily long; the label is a
/// recognition aid, not the raw header.
const MAX_DEVICE_LABEL: usize = 80;

/// Derive a short `"Browser on OS"` label from a `User-Agent`, or `None` when the header is absent or
/// empty. Deliberately a small heuristic over the common families rather than a full UA parser: the
/// label only has to be recognisable to its owner, and an unknown UA degrades to a bounded, sanitised
/// slice of the raw string rather than a wrong guess.
#[must_use]
pub fn device_label(user_agent: Option<&str>) -> Option<String> {
    let ua = user_agent.map(str::trim).filter(|s| !s.is_empty())?;

    let browser = browser_family(ua);
    let os = os_family(ua);
    let label = match (browser, os) {
        (Some(b), Some(o)) => format!("{b} on {o}"),
        (Some(b), None) => b.to_owned(),
        (None, Some(o)) => o.to_owned(),
        // Nothing recognised: keep a bounded, control-char-free slice of the raw UA so the row still
        // says *something* the owner might recognise, rather than a fabricated family.
        (None, None) => sanitise(ua),
    };
    Some(truncate(&label))
}

/// Order matters: Edge and Opera and Brave all also contain `"Chrome"`, so the more specific brands
/// are checked first. This is intentionally not exhaustive — it names the families an operator is
/// likely to actually be using.
fn browser_family(ua: &str) -> Option<&'static str> {
    let u = ua.to_ascii_lowercase();
    if u.contains("edg/") || u.contains("edga/") || u.contains("edgios/") {
        Some("Edge")
    } else if u.contains("opr/") || u.contains("opera") {
        Some("Opera")
    } else if u.contains("firefox") {
        Some("Firefox")
    } else if u.contains("chrome") || u.contains("crios") {
        Some("Chrome")
    } else if u.contains("safari") {
        Some("Safari")
    } else if u.contains("curl") {
        Some("curl")
    } else {
        None
    }
}

fn os_family(ua: &str) -> Option<&'static str> {
    let u = ua.to_ascii_lowercase();
    if u.contains("windows") {
        Some("Windows")
    } else if u.contains("iphone") || u.contains("ipad") || u.contains("ios") {
        Some("iOS")
    } else if u.contains("mac os x") || u.contains("macintosh") {
        Some("macOS")
    } else if u.contains("android") {
        Some("Android")
    } else if u.contains("linux") {
        Some("Linux")
    } else {
        None
    }
}

fn sanitise(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .take(MAX_DEVICE_LABEL)
        .collect()
}

fn truncate(label: &str) -> String {
    if label.chars().count() <= MAX_DEVICE_LABEL {
        label.to_owned()
    } else {
        label.chars().take(MAX_DEVICE_LABEL).collect()
    }
}

/// Truncate a client IP to a **network** for storage: IPv4 to its `/24`, IPv6 to its `/48`. The
/// result is rendered as the zeroed network address so it reads as a place, not a host
/// (`198.51.100.0`, `2001:db8:1::`). `None` in, `None` out.
#[must_use]
pub fn truncate_ip(ip: Option<IpAddr>) -> Option<String> {
    match ip? {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            Some(std::net::Ipv4Addr::new(a, b, c, 0).to_string())
        }
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            // Keep the first 48 bits (three 16-bit groups); zero the rest.
            for seg in segments.iter_mut().skip(3) {
                *seg = 0;
            }
            Some(std::net::Ipv6Addr::from(segments).to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_user_agents_get_a_recognisable_label() {
        let cases = [
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Chrome on Windows",
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Safari on macOS",
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Firefox on Linux",
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
                "Safari on iOS",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36 Edg/120.0.0.0",
                "Edge on Windows",
            ),
        ];
        for (ua, expected) in cases {
            assert_eq!(device_label(Some(ua)).as_deref(), Some(expected), "{ua}");
        }
    }

    #[test]
    fn an_absent_or_empty_user_agent_is_none() {
        assert_eq!(device_label(None), None);
        assert_eq!(device_label(Some("   ")), None);
    }

    #[test]
    fn an_unrecognised_user_agent_degrades_to_a_bounded_sanitised_slice() {
        let label = device_label(Some("SomeCustomClient/9.9")).expect("a label");
        assert_eq!(label, "SomeCustomClient/9.9");
        // Control characters are stripped and the length is bounded.
        let noisy = format!("weird\u{7}client{}", "x".repeat(200));
        let label = device_label(Some(&noisy)).expect("a label");
        assert!(!label.contains('\u{7}'));
        assert!(label.chars().count() <= MAX_DEVICE_LABEL);
    }

    #[test]
    fn ipv4_is_truncated_to_its_slash_24() {
        let ip: IpAddr = "198.51.100.37".parse().unwrap();
        assert_eq!(truncate_ip(Some(ip)).as_deref(), Some("198.51.100.0"));
    }

    #[test]
    fn ipv6_is_truncated_to_its_slash_48() {
        let ip: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        assert_eq!(truncate_ip(Some(ip)).as_deref(), Some("2001:db8:1::"));
    }

    #[test]
    fn a_missing_ip_is_none() {
        assert_eq!(truncate_ip(None), None);
    }

    /// The truncated form must not be the original host — that is the whole point.
    #[test]
    fn truncation_actually_drops_host_bits() {
        let ip: IpAddr = "203.0.113.254".parse().unwrap();
        let truncated = truncate_ip(Some(ip)).unwrap();
        assert_ne!(truncated, "203.0.113.254");
        assert_eq!(truncated, "203.0.113.0");
    }
}
