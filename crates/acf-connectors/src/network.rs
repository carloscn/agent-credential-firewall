//! Destination address policy and the validating DNS resolver.
//!
//! The HTTP client resolves names only through [`ValidatingResolver`], which
//! returns the addresses it validated; the client connects to exactly those.
//! A name that resolves to any forbidden address is rejected as a whole, so a
//! rebinding answer mixing public and internal addresses fails loudly.
//!
//! IP-literal hosts never reach a resolver, so the connector checks them with
//! [`NetworkPolicy::check_ip`] before sending.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Gateway-level network policy. Not configurable from connector profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkPolicy {
    /// Allow loopback destinations (local test upstreams only).
    pub allow_loopback: bool,
    /// Allow private, unique-local, and carrier-grade NAT destinations.
    pub allow_private: bool,
    /// Allow `http://` origins.
    pub allow_plaintext_http: bool,
}

impl NetworkPolicy {
    /// Public destinations over HTTPS only.
    #[must_use]
    pub fn production() -> Self {
        Self {
            allow_loopback: false,
            allow_private: false,
            allow_plaintext_http: false,
        }
    }

    /// Adds loopback and plaintext HTTP, for a local development upstream.
    #[must_use]
    pub fn development_loopback() -> Self {
        Self {
            allow_loopback: true,
            allow_private: false,
            allow_plaintext_http: true,
        }
    }

    /// Checks one destination address.
    ///
    /// # Errors
    ///
    /// Returns the [`ForbiddenAddress`] category.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), ForbiddenAddress> {
        match classify(ip) {
            AddressClass::Public => Ok(()),
            AddressClass::Loopback if self.allow_loopback => Ok(()),
            AddressClass::Private if self.allow_private => Ok(()),
            AddressClass::Loopback => Err(ForbiddenAddress::Loopback),
            AddressClass::Private => Err(ForbiddenAddress::Private),
            AddressClass::AlwaysForbidden => Err(ForbiddenAddress::Reserved),
        }
    }
}

/// Why a destination address was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ForbiddenAddress {
    /// Loopback.
    #[error("destination resolves to a loopback address")]
    Loopback,
    /// Private, unique-local, or carrier-grade NAT.
    #[error("destination resolves to a private address")]
    Private,
    /// Link-local (including cloud metadata), unspecified, multicast,
    /// broadcast, or reserved. Never allowed.
    #[error("destination resolves to a link-local, metadata, or reserved address")]
    Reserved,
    /// The name resolved to no address.
    #[error("destination did not resolve")]
    Unresolved,
}

enum AddressClass {
    Public,
    Loopback,
    Private,
    AlwaysForbidden,
}

fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            // `::ffff:a.b.c.d` reaches the IPv4 address.
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    let [a, b, ..] = ip.octets();
    if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_unspecified()
        || ip.is_link_local() // 169.254.0.0/16, including 169.254.169.254
        || ip.is_multicast()
        || ip.is_broadcast()
        || a == 0 // "this network"
        || a >= 240
    // reserved
    {
        AddressClass::AlwaysForbidden
    } else if ip.is_private()
        || (a == 100 && (64..128).contains(&b)) // 100.64.0.0/10, carrier-grade NAT
        || (a == 198 && (b == 18 || b == 19))
    // 198.18.0.0/15, benchmarking
    {
        AddressClass::Private
    } else {
        AddressClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    let first = ip.segments()[0];
    if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_unspecified() || ip.is_multicast() || (first & 0xffc0) == 0xfe80
    // fe80::/10 link-local
    {
        AddressClass::AlwaysForbidden
    } else if (first & 0xfe00) == 0xfc00 {
        // fc00::/7 unique-local, including fd00:ec2::254 metadata.
        AddressClass::Private
    } else {
        AddressClass::Public
    }
}

/// Resolves host names to addresses. Swappable for tests.
#[async_trait]
pub trait HostResolver: Send + Sync {
    /// Resolves `host`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when resolution fails.
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// The operating system resolver.
pub struct SystemResolver;

#[async_trait]
impl HostResolver for SystemResolver {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(tokio::net::lookup_host((host, 0))
            .await?
            .map(|a| a.ip())
            .collect())
    }
}

/// Validates every resolved address against a [`NetworkPolicy`].
pub(crate) struct ValidatingResolver {
    pub(crate) inner: Arc<dyn HostResolver>,
    pub(crate) policy: NetworkPolicy,
}

impl Resolve for ValidatingResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let inner = Arc::clone(&self.inner);
        let policy = self.policy;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let ips = inner.resolve(&host).await?;
            if ips.is_empty() {
                return Err(Box::new(ForbiddenAddress::Unresolved) as _);
            }
            for ip in &ips {
                // `?` boxes the error once, so callers can downcast it.
                policy.check_ip(*ip)?;
            }
            // Port 0 is replaced by the URL's port.
            let addrs: Addrs = Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(policy: NetworkPolicy, ip: &str) -> Result<(), ForbiddenAddress> {
        policy.check_ip(ip.parse().unwrap())
    }

    #[test]
    fn production_allows_only_public_addresses() {
        let p = NetworkPolicy::production();
        for ok in ["203.0.113.10", "1.1.1.1", "2606:4700::1111"] {
            assert_eq!(check(p, ok), Ok(()), "{ok}");
        }
        for (ip, expected) in [
            ("127.0.0.1", ForbiddenAddress::Loopback),
            ("127.255.0.9", ForbiddenAddress::Loopback),
            ("::1", ForbiddenAddress::Loopback),
            ("::ffff:127.0.0.1", ForbiddenAddress::Loopback),
            ("10.1.2.3", ForbiddenAddress::Private),
            ("172.16.0.1", ForbiddenAddress::Private),
            ("192.168.1.1", ForbiddenAddress::Private),
            ("100.100.100.200", ForbiddenAddress::Private),
            ("fd00:ec2::254", ForbiddenAddress::Private),
            ("::ffff:10.0.0.1", ForbiddenAddress::Private),
            ("169.254.169.254", ForbiddenAddress::Reserved),
            ("169.254.170.2", ForbiddenAddress::Reserved),
            ("fe80::1", ForbiddenAddress::Reserved),
            ("0.0.0.0", ForbiddenAddress::Reserved),
            ("::", ForbiddenAddress::Reserved),
            ("224.0.0.1", ForbiddenAddress::Reserved),
            ("255.255.255.255", ForbiddenAddress::Reserved),
            ("240.0.0.1", ForbiddenAddress::Reserved),
            ("::ffff:169.254.169.254", ForbiddenAddress::Reserved),
        ] {
            assert_eq!(check(p, ip), Err(expected), "{ip}");
        }
    }

    #[test]
    fn development_allows_loopback_but_never_metadata() {
        let p = NetworkPolicy::development_loopback();
        assert_eq!(check(p, "127.0.0.1"), Ok(()));
        assert_eq!(check(p, "169.254.169.254"), Err(ForbiddenAddress::Reserved));
        assert_eq!(check(p, "10.0.0.1"), Err(ForbiddenAddress::Private));
    }
}
