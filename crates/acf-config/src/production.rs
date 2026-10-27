//! `production` profile rules that depend only on configuration
//! (design §13.4, ADR 0004). Startup facts such as listeners and audit
//! sinks are checked by the gateway.

use std::net::IpAddr;

use acf_secrets::Origin;

use crate::bundle::{ConfigIssue, KeySourceKind, SecretProviderConfig, ValidatedConfig};

/// Reserved names that only ever point at test or documentation hosts
/// (RFC 2606, RFC 6761, RFC 6762).
const TEST_SUFFIXES: &[&str] = &["test", "example", "invalid", "localhost", "local"];
const TEST_DOMAINS: &[&str] = &["example.com", "example.net", "example.org"];

/// Why an origin is not a production destination, if it is not.
#[must_use]
pub fn destination_problem(origin: &Origin) -> Option<String> {
    let text = origin.as_str();
    let (scheme, rest) = text.split_once("://")?;
    if scheme != "https" {
        return Some(format!("`{text}` is not https"));
    }
    let host = if let Some(bracketed) = rest.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or_default()
    } else {
        rest.rsplit_once(':').map_or(rest, |(host, _)| host)
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = host.parse::<IpAddr>() {
        let internal = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
                    || v6.to_ipv4_mapped().is_some()
            }
        };
        return internal.then(|| format!("`{text}` is a loopback, private, or reserved address"));
    }
    let reserved = host == "localhost"
        || TEST_SUFFIXES
            .iter()
            .any(|suffix| host.ends_with(&format!(".{suffix}")))
        || TEST_DOMAINS
            .iter()
            .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")));
    reserved.then(|| format!("`{text}` is a local or reserved test name"))
}

/// Every configuration-level reason `config` may not run under the
/// `production` profile. Empty means none.
#[must_use]
pub fn production_issues(config: &ValidatedConfig) -> Vec<ConfigIssue> {
    let mut issues = Vec::new();
    let mut push = |location: String, problem: String| {
        issues.push(ConfigIssue { location, problem });
    };
    for (namespace, provider) in config.providers() {
        let location = format!("secret_providers.{namespace}");
        match provider {
            SecretProviderConfig::InMemory => {
                push(
                    location,
                    "the in-memory provider is for development only".to_owned(),
                );
            }
            SecretProviderConfig::EncryptedLocal {
                key_source,
                rollback_anchor,
                rollback_resistance,
                ..
            } => {
                if *key_source == KeySourceKind::InsecureDevelopment {
                    push(
                        location.clone(),
                        "`key_source: insecure-development` is for development only".to_owned(),
                    );
                }
                if rollback_anchor.is_none() && rollback_resistance.is_none() {
                    push(
                        location,
                        "set a `rollback_anchor` or acknowledge `rollback_resistance: none`"
                            .to_owned(),
                    );
                }
            }
            SecretProviderConfig::External { .. } => {}
        }
    }
    for (connector, profile) in config.profiles() {
        if let Some(problem) = destination_problem(profile.base_url.origin()) {
            push(format!("profiles[{connector}].base_url"), problem);
        }
    }
    for (reference, registration) in config.secrets() {
        for origin in registration.use_binding.origins() {
            if let Some(problem) = destination_problem(origin) {
                push(format!("secrets.{reference}.use_binding.origins"), problem);
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem(origin: &str) -> Option<String> {
        destination_problem(&Origin::parse(origin).unwrap())
    }

    #[test]
    fn production_destinations_are_public_https_names() {
        for good in [
            "https://api.cloudflare.com",
            "https://api.github.com:8443",
            "https://8.8.8.8",
            "https://[2606:4700::1111]",
            "https://example.company.com",
        ] {
            assert_eq!(problem(good), None, "{good}");
        }
        for bad in [
            "http://api.cloudflare.com",
            "https://localhost",
            "https://api.localhost",
            "https://127.0.0.1:8443",
            "https://10.0.0.5",
            "https://192.168.1.1",
            "https://169.254.169.254",
            "https://100.64.0.1",
            "https://0.0.0.0",
            "https://[::1]",
            "https://[fd00::1]",
            "https://[::ffff:127.0.0.1]",
            "https://upstream.test",
            "https://api.example",
            "https://printer.local",
            "https://example.com",
            "https://api.example.org",
            "https://host.invalid",
        ] {
            assert!(problem(bad).is_some(), "{bad}");
        }
    }
}
