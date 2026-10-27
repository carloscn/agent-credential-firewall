//! Startup facts the `production` profile checks beyond the configuration
//! itself (design §13.4, ADR 0004).

use acf_config::{ValidatedConfig, production_issues};

/// `development` when built with the `development` feature, else `release`.
pub const BUILD_FLAVOR: &str = if cfg!(feature = "development") {
    "development"
} else {
    "release"
};

/// What the gateway is about to start with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one independent startup fact per field"
)]
pub struct StartupFacts {
    /// Built with the `development` feature.
    pub development_build: bool,
    /// A trust anchor was given and every document was admitted.
    pub config_admitted: bool,
    /// The trust anchor file is writable by group or others.
    pub trust_anchor_writable: bool,
    /// TLS 1.3 with client certificates; otherwise plaintext with the
    /// development identity.
    pub mtls: bool,
    /// Every request needs a capability (`--authority-keys`).
    pub capabilities_required: bool,
    /// An explicit audit sink rather than standard error.
    pub audit_sink: bool,
    /// Audit checkpoints go to an external collector (`--checkpoint-url`).
    pub audit_anchored: bool,
}

/// Every reason the gateway may not start under `production`. Empty means
/// it may.
#[must_use]
pub fn production_refusals(facts: &StartupFacts, config: &ValidatedConfig) -> Vec<String> {
    let mut refusals = Vec::new();
    if facts.development_build {
        refusals.push("this binary was built with the `development` feature".to_owned());
    }
    if !facts.config_admitted {
        refusals.push(
            "configuration must be admitted: pass --config-trust and sign or pin every document"
                .to_owned(),
        );
    }
    if facts.trust_anchor_writable {
        refusals.push("the configuration trust anchor is writable by group or others".to_owned());
    }
    if config.inline_profile_count() > 0 {
        refusals.push(
            "profiles must come from admitted files in --profiles, not inline in the bundle"
                .to_owned(),
        );
    }
    if !facts.mtls {
        refusals.push(
            "plaintext listener and development identity: pass --tls-cert, --tls-key, --client-ca, and --devices"
                .to_owned(),
        );
    }
    if !facts.capabilities_required {
        refusals.push(
            "requests must carry certificate-bound capabilities: pass --authority-keys".to_owned(),
        );
    }
    if !facts.audit_sink {
        refusals.push("an explicit audit sink is required: pass --audit-log".to_owned());
    }
    if !facts.audit_anchored {
        refusals.push(
            "the audit chain must be anchored externally: pass --audit-key, --audit-kid, and --checkpoint-url with its client certificate"
                .to_owned(),
        );
    }
    refusals.extend(production_issues(config).into_iter().map(|i| i.to_string()));
    refusals
}
