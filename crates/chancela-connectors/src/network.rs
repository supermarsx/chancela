//! Operator-controlled outbound-network policy for connector targets.
//!
//! A connector is never an open URL fetcher. Network targets must name an exact host in
//! `CHANCELA_CONNECTOR_ALLOWED_HOSTS`; private, loopback, link-local, and otherwise non-public
//! addresses additionally require an explicit IP/CIDR entry. DNS is resolved at validation time
//! and every returned address is checked, which also makes provider-supplied upload-session URLs
//! pass through the same boundary before source bytes are sent.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ConnectorError;

pub const ALLOWED_HOSTS_ENV: &str = "CHANCELA_CONNECTOR_ALLOWED_HOSTS";

#[derive(Clone, Debug, Eq, PartialEq)]
enum AllowEntry {
    Host(String),
    Network(IpAddr, u8),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPolicy {
    entries: Vec<AllowEntry>,
}

impl NetworkPolicy {
    pub fn from_env() -> Result<Self, ConnectorError> {
        let raw = std::env::var(ALLOWED_HOSTS_ENV).map_err(|_| {
            ConnectorError::configuration(format!(
                "{ALLOWED_HOSTS_ENV} is required for network connectors"
            ))
        })?;
        Self::parse(&raw)
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
