//! Operator-controlled outbound-network policy for connector targets.
//!
//! A connector is never an open URL fetcher. Network targets must name an exact host in the
//! effective allowlist; private, loopback, link-local, and otherwise non-public addresses
//! additionally require an explicit IP/CIDR entry. DNS is resolved at validation time and every
//! returned address is checked, which also makes provider-supplied upload-session URLs pass
//! through the same boundary before source bytes are sent.
//!
//! ## Two sources, one boundary (precedence)
//!
//! The allowlist has a deployment source and a runtime source:
//!
//! * `CHANCELA_CONNECTOR_ALLOWED_HOSTS` — the **deployment ceiling**. Owned by whoever controls
//!   the container/unit file, changeable only by redeploying.
//! * `<CHANCELA_DATA_DIR>/connector-allowed-hosts.json` — the **runtime allowlist**, written by
//!   the API when a Global `settings.manage` holder saves the connector egress setting.
//!
//! The rule is *intersection, never union*: when the ceiling is set, every runtime entry must be
//! covered by it, so an administrator can only ever **narrow** what the deployment permits. When
//! the ceiling is unset, the runtime allowlist is the sole boundary — that is the case this
//! feature exists to serve, and it is why [`NetworkPolicy::parse_administrative`] applies stricter
//! rules than the environment parser: loopback, link-local/cloud-metadata, multicast and
//! over-broad prefixes are rejected outright from the runtime source, whatever the deployment
//! itself is willing to permit.
//!
//! Both sources are read at each validation (with an mtime/env-keyed cache), so a saved change
//! takes effect on the next connector operation in both the API and the worker process without a
//! restart.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::ConnectorError;

pub const ALLOWED_HOSTS_ENV: &str = "CHANCELA_CONNECTOR_ALLOWED_HOSTS";
/// Data directory that holds the runtime allowlist document. Shared by the API and the worker.
pub const DATA_DIR_ENV: &str = "CHANCELA_DATA_DIR";
/// File name of the runtime allowlist document beneath [`DATA_DIR_ENV`].
pub const RUNTIME_ALLOWLIST_FILE: &str = "connector-allowed-hosts.json";
/// Schema discriminator for [`RuntimeAllowlist`].
pub const RUNTIME_ALLOWLIST_SCHEMA_VERSION: u32 = 1;
/// Hard cap on runtime entries. A boundary an operator cannot read in one screen is not a boundary.
pub const MAX_RUNTIME_ALLOWLIST_ENTRIES: usize = 64;
/// Narrowest IPv4 prefix an administrator may add at runtime (`/16` ≈ 65k addresses).
const MIN_ADMIN_V4_PREFIX: u8 = 16;
/// Narrowest IPv6 prefix an administrator may add at runtime.
const MIN_ADMIN_V6_PREFIX: u8 = 32;
/// Cap on the runtime document so a corrupt/hostile file cannot be read unboundedly.
const MAX_RUNTIME_ALLOWLIST_BYTES: u64 = 64 * 1024;

/// The on-disk runtime allowlist document.
///
/// It carries provenance (`updated_at`/`updated_by`) purely so an operator reading the data
/// directory can see who last moved the boundary; the authoritative record is the ledger event
/// the API appends, not this file.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct RuntimeAllowlist {
    pub schema_version: u32,
    pub entries: Vec<String>,
    pub updated_at: String,
    pub updated_by: String,
}

impl RuntimeAllowlist {
    #[must_use]
    pub fn new(entries: Vec<String>, updated_at: String, updated_by: String) -> Self {
        Self {
            schema_version: RUNTIME_ALLOWLIST_SCHEMA_VERSION,
            entries,
            updated_at,
            updated_by,
        }
    }

    /// Path of the runtime document beneath a data directory.
    #[must_use]
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(RUNTIME_ALLOWLIST_FILE)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum AllowEntry {
    Host(String),
    Network(IpAddr, u8),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPolicy {
    entries: Vec<AllowEntry>,
}

impl NetworkPolicy {
    /// The deployment ceiling alone. Prefer [`NetworkPolicy::effective`] at call sites; this
    /// remains for callers that specifically mean "what does the deployment permit?".
    pub fn from_env() -> Result<Self, ConnectorError> {
        let raw = std::env::var(ALLOWED_HOSTS_ENV).map_err(|_| {
            ConnectorError::configuration(format!(
                "{ALLOWED_HOSTS_ENV} is required for network connectors"
            ))
        })?;
        Self::parse(&raw)
    }

    /// The policy every connector operation is actually validated against: the deployment ceiling
    /// intersected with the runtime allowlist. See the module docs for the precedence rule.
    ///
    /// Both sources are re-read on change (cached on env value + file mtime/len), so a saved
    /// setting applies to the next operation without restarting the API or the worker.
    pub fn effective() -> Result<Self, ConnectorError> {
        let ceiling_raw = std::env::var(ALLOWED_HOSTS_ENV)
            .ok()
            .filter(|raw| !raw.trim().is_empty());
        let runtime_path = std::env::var(DATA_DIR_ENV)
            .ok()
            .filter(|dir| !dir.trim().is_empty())
            .map(|dir| RuntimeAllowlist::path_in(Path::new(dir.trim())));
        resolve_effective(ceiling_raw.as_deref(), runtime_path.as_deref())
    }

    /// Resolve an effective policy from explicit sources. Exposed for the API, which knows its own
    /// data directory without consulting the environment, and for tests.
    pub fn resolve(
        environment_ceiling: Option<&str>,
        runtime: Option<&RuntimeAllowlist>,
    ) -> Result<Self, ConnectorError> {
        let ceiling = match environment_ceiling.filter(|raw| !raw.trim().is_empty()) {
            Some(raw) => Some(Self::parse(raw)?),
            None => None,
        };
        let runtime = match runtime.filter(|doc| !doc.entries.is_empty()) {
            Some(doc) => Some(Self::parse_administrative(&doc.entries)?),
            None => None,
        };
        match (ceiling, runtime) {
            (Some(ceiling), Some(runtime)) => {
                runtime.require_within(&ceiling)?;
                Ok(runtime)
            }
            (Some(ceiling), None) => Ok(ceiling),
            (None, Some(runtime)) => Ok(runtime),
            (None, None) => Err(ConnectorError::configuration(format!(
                "{ALLOWED_HOSTS_ENV} is required for network connectors, or an administrator must configure the connector egress allowlist in Settings"
            ))),
        }
    }

    /// Parse entries supplied by an administrator at runtime.
    ///
    /// Deliberately stricter than [`NetworkPolicy::parse`]: this is the path an attacker holding
    /// an admin session would use, so it refuses the destinations that make connector egress a
    /// useful exfiltration or SSRF primitive even when no deployment ceiling is pinned.
    pub fn parse_administrative<S: AsRef<str>>(entries: &[S]) -> Result<Self, ConnectorError> {
        if entries.len() > MAX_RUNTIME_ALLOWLIST_ENTRIES {
            return Err(ConnectorError::configuration(format!(
                "connector allowlist accepts at most {MAX_RUNTIME_ALLOWLIST_ENTRIES} entries"
            )));
        }
        let mut parsed = Vec::new();
        for entry in entries {
            let entry = entry.as_ref().trim();
            if entry.is_empty() {
                return Err(ConnectorError::configuration(
                    "connector allowlist contains a blank entry",
                ));
            }
            parsed.push(parse_administrative_entry(entry)?);
        }
        if parsed.is_empty() {
            return Err(ConnectorError::configuration(
                "connector outbound host allowlist is empty",
            ));
        }
        parsed.sort();
        parsed.dedup();
        Ok(Self { entries: parsed })
    }

    /// Fail unless every entry of `self` is covered by `ceiling` — the check that makes the
    /// environment variable a ceiling rather than merely a default.
    pub fn require_within(&self, ceiling: &Self) -> Result<(), ConnectorError> {
        for entry in &self.entries {
            if !ceiling.covers(entry) {
                return Err(ConnectorError::configuration(format!(
                    "{} is not permitted by {ALLOWED_HOSTS_ENV}; the deployment allowlist is a ceiling that Settings can only narrow",
                    describe_entry(entry)
                )));
            }
        }
        Ok(())
    }

    fn covers(&self, candidate: &AllowEntry) -> bool {
        self.entries
            .iter()
            .any(|allowed| match (allowed, candidate) {
                (AllowEntry::Host(allowed), AllowEntry::Host(candidate)) => allowed == candidate,
                (
                    AllowEntry::Network(network, prefix),
                    AllowEntry::Network(candidate, candidate_prefix),
                ) => candidate_prefix >= prefix && network_contains(*network, *prefix, *candidate),
                // A hostname entry never covers a literal and vice versa: the ceiling's hostname may
                // resolve anywhere, so treating it as covering an IP range would widen the boundary.
                (AllowEntry::Host(_), AllowEntry::Network(a, p)) => *p == if a.is_ipv4() {32} else {128},
                _ => false,
            })
    }

    pub fn parse(raw: &str) -> Result<Self, ConnectorError> {
        let mut entries = Vec::new();
        for raw_entry in raw.split(',') {
            let entry = raw_entry.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some((address, prefix)) = entry.split_once('/') {
                let address: IpAddr = address.parse().map_err(|_| {
                    ConnectorError::configuration("connector allowlist contains an invalid CIDR")
                })?;
                let prefix: u8 = prefix.parse().map_err(|_| {
                    ConnectorError::configuration("connector allowlist contains an invalid CIDR")
                })?;
                let maximum = if address.is_ipv4() { 32 } else { 128 };
                if prefix > maximum {
                    return Err(ConnectorError::configuration(
                        "connector allowlist contains an invalid CIDR prefix",
                    ));
                }
                entries.push(AllowEntry::Network(address, prefix));
            } else if let Ok(address) = entry.parse::<IpAddr>() {
                entries.push(AllowEntry::Network(
                    address,
                    if address.is_ipv4() { 32 } else { 128 },
                ));
            } else {
                let host = normalize_host(entry)?;
                entries.push(AllowEntry::Host(host));
            }
        }
        if entries.is_empty() {
            return Err(ConnectorError::configuration(
                "connector outbound host allowlist is empty",
            ));
        }
        Ok(Self { entries })
    }

    pub async fn validate_url(&self, value: &str, label: &str) -> Result<(), ConnectorError> {
        let url = reqwest::Url::parse(value)
            .map_err(|_| ConnectorError::configuration(format!("invalid {label} URL")))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ConnectorError::configuration(format!(
                "{label} URL must not contain user information"
            )));
        }
        let host = url
            .host_str()
            .ok_or_else(|| ConnectorError::configuration(format!("{label} URL has no host")))?;
        let port = url.port_or_known_default().ok_or_else(|| {
            ConnectorError::configuration(format!("{label} URL has no usable port"))
        })?;
        self.validate_host(host, port, label).await
    }

    pub async fn validate_host(
        &self,
        host: &str,
        port: u16,
        label: &str,
    ) -> Result<(), ConnectorError> {
        let normalized = normalize_host(host)?;
        let literal = normalized.parse::<IpAddr>().ok();
        let host_explicit = self.entries.iter().any(|entry| match entry {
            AllowEntry::Host(allowed) => allowed == &normalized,
            AllowEntry::Network(network, prefix) => {
                literal.is_some_and(|address| network_contains(*network, *prefix, address))
            }
        });
        if !host_explicit {
            return Err(ConnectorError::configuration(format!(
                "{label} host is not in {ALLOWED_HOSTS_ENV}"
            )));
        }

        let addresses = tokio::net::lookup_host((normalized.as_str(), port))
            .await
            .map_err(|_| ConnectorError::configuration(format!("{label} host did not resolve")))?
            .map(|address| address.ip())
            .collect::<std::collections::BTreeSet<_>>();
        if addresses.is_empty() {
            return Err(ConnectorError::configuration(format!(
                "{label} host did not resolve"
            )));
        }
        for address in addresses {
            if !is_public_address(address) && !self.ip_explicit(address) {
                return Err(ConnectorError::configuration(format!(
                    "{label} resolved to a non-public address that is not explicitly allowlisted by IP/CIDR"
                )));
            }
        }
        Ok(())
    }

    fn ip_explicit(&self, address: IpAddr) -> bool {
        self.entries.iter().any(|entry| match entry {
            AllowEntry::Host(_) => false,
            AllowEntry::Network(network, prefix) => network_contains(*network, *prefix, address),
        })
    }
}

/// Cache key for a resolved policy: the ceiling text plus the runtime file's identity. Any change
/// to either invalidates it, which is what lets a saved setting apply without a restart while
/// still not re-reading the file on every chunked upload.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolutionKey {
    ceiling: Option<String>,
    runtime: Option<PathBuf>,
    stamp: Option<(SystemTime, u64)>,
}

static RESOLVED: RwLock<Option<(ResolutionKey, NetworkPolicy)>> = RwLock::new(None);

fn resolve_effective(
    ceiling: Option<&str>,
    runtime_path: Option<&Path>,
) -> Result<NetworkPolicy, ConnectorError> {
    let stamp = runtime_path.and_then(|path| {
        let metadata = std::fs::metadata(path).ok()?;
        Some((metadata.modified().ok()?, metadata.len()))
    });
    let key = ResolutionKey {
        ceiling: ceiling.map(str::to_owned),
        runtime: runtime_path.map(Path::to_path_buf),
        stamp,
    };
    if let Ok(cached) = RESOLVED.read()
        && let Some((cached_key, policy)) = cached.as_ref()
        && cached_key == &key
    {
        return Ok(policy.clone());
    }
    let runtime = match runtime_path {
        Some(path) => load_runtime_allowlist(path)?,
        None => None,
    };
    let policy = NetworkPolicy::resolve(ceiling, runtime.as_ref())?;
    if let Ok(mut cached) = RESOLVED.write() {
        *cached = Some((key, policy.clone()));
    }
    Ok(policy)
}

/// Read the runtime allowlist document. A missing file simply means "not configured"; a present
/// but unreadable or malformed one is an error, because silently continuing on the deployment
/// ceiling alone would widen the boundary an administrator believed they had narrowed.
pub fn load_runtime_allowlist(path: &Path) -> Result<Option<RuntimeAllowlist>, ConnectorError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(ConnectorError::configuration(
                "connector allowlist document is unreadable",
            ));
        }
    };
    if metadata.len() > MAX_RUNTIME_ALLOWLIST_BYTES {
        return Err(ConnectorError::configuration(
            "connector allowlist document is too large",
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|_| ConnectorError::configuration("connector allowlist document is unreadable"))?;
    let document: RuntimeAllowlist = serde_json::from_slice(&bytes)
        .map_err(|_| ConnectorError::configuration("connector allowlist document is malformed"))?;
    Ok(Some(document))
}

fn parse_administrative_entry(entry: &str) -> Result<AllowEntry, ConnectorError> {
    for (needle, reason) in [
        ("://", "must not include a URL scheme"),
        ("@", "must not include user information"),
        ("?", "must not include a query string"),
        ("#", "must not include a fragment"),
        ("*", "must not use wildcards"),
        ("[", "must not be bracketed"),
        (" ", "must not contain spaces"),
        (",", "must be entered one per line"),
    ] {
        if entry.contains(needle) {
            return Err(ConnectorError::configuration(format!(
                "connector allowlist entry {reason}"
            )));
        }
    }

    if let Some((address, prefix)) = entry.split_once('/') {
        let address: IpAddr = address.parse().map_err(|_| {
            ConnectorError::configuration(
                "connector allowlist entry must be a hostname or an IP/CIDR, with no path",
            )
        })?;
        let prefix: u8 = prefix.parse().map_err(|_| {
            ConnectorError::configuration("connector allowlist contains an invalid CIDR")
        })?;
        let (maximum, minimum) = if address.is_ipv4() {
            (32, MIN_ADMIN_V4_PREFIX)
        } else {
            (128, MIN_ADMIN_V6_PREFIX)
        };
        if prefix > maximum {
            return Err(ConnectorError::configuration(
                "connector allowlist contains an invalid CIDR prefix",
            ));
        }
        if prefix < minimum {
            return Err(ConnectorError::configuration(format!(
                "connector allowlist CIDR is too broad; use a prefix of at least /{minimum}"
            )));
        }
        reject_forbidden_network(address, prefix)?;
        return Ok(AllowEntry::Network(address, prefix));
    }

    if let Ok(address) = entry.parse::<IpAddr>() {
        let prefix = if address.is_ipv4() { 32 } else { 128 };
        reject_forbidden_network(address, prefix)?;
        return Ok(AllowEntry::Network(address, prefix));
    }

    // Hostnames only past this point: a stray ':' here is a port or an unbracketed IPv6 literal.
    if entry.contains(':') {
        return Err(ConnectorError::configuration(
            "connector allowlist entry must not include a port",
        ));
    }
    if entry.contains('/') {
        return Err(ConnectorError::configuration(
            "connector allowlist entry must not include a path",
        ));
    }
    let host = normalize_host(entry)?;
    if host == "localhost" || host.ends_with(".localhost") {
        return Err(ConnectorError::configuration(
            "connector allowlist may not target the host running Chancela",
        ));
    }
    Ok(AllowEntry::Host(host))
}

/// Ranges an administrator may never open from Settings, whatever the deployment permits.
///
/// `169.254.0.0/16` carries the cloud instance-metadata endpoint (`169.254.169.254`) — the single
/// most valuable SSRF destination in a hosted deployment. Loopback would point a connector back at
/// Chancela's own API. Multicast and the unspecified address are never legitimate targets.
fn reject_forbidden_network(address: IpAddr, prefix: u8) -> Result<(), ConnectorError> {
    let canonical = match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        v4 => v4,
    };
    let forbidden: &[(&str, &str, u8)] = &[
        ("the loopback range", "127.0.0.0", 8),
        ("the unspecified range", "0.0.0.0", 8),
        ("the link-local / cloud-metadata range", "169.254.0.0", 16),
        ("the multicast range", "224.0.0.0", 4),
    ];
    for (label, network, network_prefix) in forbidden {
        let network: IpAddr = network.parse().expect("static network literal");
        // Reject both "inside a forbidden range" and "a range that contains one".
        if network_contains(network, (*network_prefix).min(prefix), canonical) {
            return Err(ConnectorError::configuration(format!(
                "connector allowlist may not include {label}"
            )));
        }
    }
    if let IpAddr::V6(v6) = canonical {
        let segments = v6.segments();
        let forbidden_v6 = v6.is_loopback()
            || v6.is_unspecified()
            || v6.is_multicast()
            || (segments[0] & 0xffc0) == 0xfe80
            || (prefix < 16 && segments[0] == 0);
        if forbidden_v6 {
            return Err(ConnectorError::configuration(
                "connector allowlist may not include loopback, link-local, or multicast addresses",
            ));
        }
    }
    Ok(())
}

fn describe_entry(entry: &AllowEntry) -> String {
    match entry {
        AllowEntry::Host(host) => host.clone(),
        AllowEntry::Network(address, prefix) => format!("{address}/{prefix}"),
    }
}

fn normalize_host(value: &str) -> Result<String, ConnectorError> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !value.is_empty()
        && value.len() <= 253
        && !value.contains('*')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'));
    if valid {
        Ok(value)
    } else {
        Err(ConnectorError::configuration(
            "connector allowlist contains an invalid host",
        ))
    }
}

fn network_contains(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => is_public_v6(address),
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_v4(mapped);
    }
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matching_is_exact_for_both_address_families() {
        assert!(network_contains(
            "10.20.0.0".parse().unwrap(),
            16,
            "10.20.8.9".parse().unwrap()
        ));
        assert!(!network_contains(
            "10.20.0.0".parse().unwrap(),
            16,
            "10.21.8.9".parse().unwrap()
        ));
        assert!(network_contains(
            "fd00::".parse().unwrap(),
            8,
            "fd42::1".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn allowlist_rejects_wildcards_empty_values_and_url_userinfo() {
        assert!(NetworkPolicy::parse("").is_err());
        assert!(NetworkPolicy::parse("*.example.com").is_err());
        let policy = NetworkPolicy::parse("example.com").unwrap();
        assert!(
            policy
                .validate_url("https://user:password@example.com/path", "test")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn localhost_requires_both_host_and_ip_allowlisting() {
        let host_only = NetworkPolicy::parse("localhost").unwrap();
        assert!(
            host_only
                .validate_host("localhost", 443, "test")
                .await
                .is_err()
        );
        let explicit = NetworkPolicy::parse("localhost,127.0.0.0/8,::1/128").unwrap();
        explicit
            .validate_host("localhost", 443, "test")
            .await
            .unwrap();
    }

    /// The precedence rule, stated as a test: the environment ceiling can only be narrowed.
    #[test]
    fn runtime_allowlist_may_narrow_the_environment_ceiling_but_never_exceed_it() {
        let ceiling = Some("backup.example.com,archive.example.com,10.42.0.0/16");

        let narrowed = NetworkPolicy::resolve(
            ceiling,
            Some(&RuntimeAllowlist::new(
                vec!["backup.example.com".into(), "10.42.8.15/32".into()],
                String::new(),
                String::new(),
            )),
        )
        .expect("narrowing within the ceiling is allowed");
        assert_eq!(narrowed.entries.len(), 2);
        assert!(
            !narrowed
                .entries
                .contains(&AllowEntry::Host("archive.example.com".into()))
        );

        let widened = NetworkPolicy::resolve(
            ceiling,
            Some(&RuntimeAllowlist::new(
                vec!["backup.example.com".into(), "attacker.example.net".into()],
                String::new(),
                String::new(),
            )),
        );
        assert!(
            widened.is_err(),
            "a host outside the ceiling must be refused"
        );

        // A broader CIDR than the ceiling grants is a widening too, not a narrowing.
        assert!(
            NetworkPolicy::resolve(
                ceiling,
                Some(&RuntimeAllowlist::new(
                    vec!["10.0.0.0/16".into()],
                    String::new(),
                    String::new()
                )),
            )
            .is_err()
        );
    }

    #[test]
    fn resolution_falls_back_to_each_single_source_and_fails_closed_with_neither() {
        let environment_only =
            NetworkPolicy::resolve(Some("backup.example.com"), None).expect("ceiling alone");
        assert_eq!(
            environment_only.entries,
            vec![AllowEntry::Host("backup.example.com".into())]
        );

        let runtime_only = NetworkPolicy::resolve(
            None,
            Some(&RuntimeAllowlist::new(
                vec!["backup.example.com".into()],
                String::new(),
                String::new(),
            )),
        )
        .expect("runtime allowlist alone is the boundary when no ceiling is pinned");
        assert_eq!(
            runtime_only.entries,
            vec![AllowEntry::Host("backup.example.com".into())]
        );

        assert!(NetworkPolicy::resolve(None, None).is_err());
        assert!(NetworkPolicy::resolve(Some("   "), None).is_err());
    }

    /// What an administrator may never add from Settings, whatever the deployment permits.
    #[test]
    fn administrative_parsing_rejects_dangerous_entries() {
        for rejected in [
            "*",
            "*.example.com",
            "example.*",
            "",
            "   ",
            "https://backup.example.com",
            "backup.example.com/path",
            "backup.example.com:443",
            "user@backup.example.com",
            "backup.example.com?x=1",
            "a.example.com,b.example.com",
            "[2001:db8::1]",
            "localhost",
            "api.localhost",
            // Cloud instance metadata and the link-local range that carries it.
            "169.254.169.254",
            "169.254.0.0/16",
            "169.254.169.0/24",
            // Loopback: a connector pointed back at Chancela's own API.
            "127.0.0.1",
            "127.0.0.0/8",
            "::1",
            "fe80::1",
            // Unspecified, multicast, and everything-matching prefixes.
            "0.0.0.0",
            "0.0.0.0/0",
            "224.0.0.1",
            "::/0",
            // Bounded prefixes only.
            "10.0.0.0/8",
            "2001:db8::/16",
        ] {
            assert!(
                NetworkPolicy::parse_administrative(&[rejected]).is_err(),
                "{rejected} should be rejected from the runtime allowlist"
            );
        }

        for accepted in [
            "backup.example.com",
            "BACKUP.example.com",
            "nas.internal",
            "10.42.8.15",
            "10.42.0.0/16",
            "2001:db8:1234::/48",
        ] {
            NetworkPolicy::parse_administrative(&[accepted])
                .unwrap_or_else(|error| panic!("{accepted} should be accepted: {error}"));
        }

        let too_many: Vec<String> = (0..=MAX_RUNTIME_ALLOWLIST_ENTRIES)
            .map(|i| format!("host{i}.example.com"))
            .collect();
        assert!(NetworkPolicy::parse_administrative(&too_many).is_err());
    }

    /// End to end: the resolved policy actually admits and refuses hosts.
    #[tokio::test]
    async fn runtime_allowlist_permits_listed_hosts_and_blocks_unlisted_ones() {
        let policy = NetworkPolicy::resolve(
            None,
            Some(&RuntimeAllowlist::new(
                vec!["example.com".into()],
                String::new(),
                String::new(),
            )),
        )
        .expect("runtime allowlist resolves");

        policy
            .validate_url("https://example.com/backups", "target")
            .await
            .expect("a listed host is permitted");
        assert!(
            policy
                .validate_url("https://exfil.example.net/drop", "target")
                .await
                .is_err(),
            "an unlisted host must be blocked"
        );
        assert!(
            policy
                .validate_host("169.254.169.254", 80, "target")
                .await
                .is_err()
        );
    }

    #[test]
    fn a_present_but_malformed_runtime_document_fails_closed() {
        let dir = std::env::temp_dir().join(format!("chancela-allowlist-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = RuntimeAllowlist::path_in(&dir);

        assert!(load_runtime_allowlist(&path).unwrap().is_none());

        std::fs::write(&path, b"{ not json").unwrap();
        assert!(
            resolve_effective(Some("example.com"), Some(&path)).is_err(),
            "a malformed document must not silently fall back to the wider ceiling"
        );

        std::fs::write(
            &path,
            serde_json::to_vec(&RuntimeAllowlist::new(
                vec!["example.com".into()],
                "2026-07-19T00:00:00Z".into(),
                "amelia.marques".into(),
            ))
            .unwrap(),
        )
        .unwrap();
        let policy = resolve_effective(Some("example.com,other.example.com"), Some(&path)).unwrap();
        assert_eq!(policy.entries, vec![AllowEntry::Host("example.com".into())]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn metadata_address_is_rejected_without_exact_network_entry() {
        let policy = NetworkPolicy::parse("metadata.internal").unwrap();
        assert!(
            policy
                .validate_host("169.254.169.254", 80, "metadata")
                .await
                .is_err()
        );
    }
}
