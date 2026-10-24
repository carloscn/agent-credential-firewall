//! Fail-closed loading: every case starts from a valid fixture and makes one
//! targeted change.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;

use acf_config::{
    ConfigError, ParamErrorKind, ValidatedConfig, load_yaml, parse_yaml, validate_params,
};
use acf_protocol::{ActionName, ResourceId};
use serde_json::json;

const PRODUCTION: &str = include_str!("fixtures/cloudflare-production.yaml");
const DEVELOPMENT: &str = include_str!("fixtures/example-development.yaml");

/// Replaces exactly one occurrence of `from`.
fn edit(source: &str, from: &str, to: &str) -> String {
    assert_eq!(
        source.matches(from).count(),
        1,
        "fixture must contain `{from}` exactly once"
    );
    source.replacen(from, to, 1)
}

fn issues(source: &str) -> Vec<String> {
    match load_yaml(source) {
        Err(ConfigError::Invalid(issues)) => issues.iter().map(ToString::to_string).collect(),
        other => panic!("expected validation issues, got {other:?}"),
    }
}

fn assert_issue(source: &str, needle: &str) {
    let issues = issues(source);
    assert!(
        issues.iter().any(|i| i.contains(needle)),
        "no issue contains `{needle}`; got {issues:#?}"
    );
}

fn assert_parse_error(source: &str, reason: &str) {
    match load_yaml(source) {
        Err(ConfigError::Parse(message)) => {
            assert!(
                message.contains(reason),
                "expected `{reason}`, got `{message}`"
            );
        }
        other => panic!("expected a parse error, got {other:?}"),
    }
}

fn production() -> ValidatedConfig {
    load_yaml(PRODUCTION).unwrap()
}

fn zone() -> ResourceId {
    ResourceId::new("cloudflare-zone:example.com").unwrap()
}

#[test]
fn fixtures_load() {
    load_yaml(DEVELOPMENT).unwrap();
    let config = production();

    let list = ActionName::new("cloudflare.dns.records.list").unwrap();
    let create = ActionName::new("cloudflare.dns.records.create").unwrap();
    let list = config.action(&zone(), &list).unwrap();
    let create = config.action(&zone(), &create).unwrap();

    assert!(!list.action.approval_required());
    assert!(
        create.action.approval_required(),
        "mutate defaults to approval"
    );
    assert_eq!(list.secret_ref.path(), "cloudflare/example.com/dns-read");
    assert_eq!(create.secret_ref.path(), "cloudflare/example.com/dns-write");

    let unknown = ActionName::new("cloudflare.dns.records.delete").unwrap();
    assert!(config.action(&zone(), &unknown).is_none());
}

// --- Acceptance: agent parameters cannot override resource bindings ---

#[test]
fn agent_cannot_supply_a_resource_binding_as_a_parameter() {
    let config = production();
    let list = config
        .action(
            &zone(),
            &ActionName::new("cloudflare.dns.records.list").unwrap(),
        )
        .unwrap();
    let attempt = json!({ "zone_id": "attacker-zone", "name": "api.example.com" });
    let error = validate_params(&list.action.params, attempt.as_object().unwrap()).unwrap_err();
    assert_eq!(error.kind, ParamErrorKind::Unknown);
    assert_eq!(error.param, "zone_id");
}

#[test]
fn templates_cannot_take_bindings_from_params() {
    // `{params.zone_id}` would need a declared path parameter; a profile cannot
    // silently source the zone from the agent.
    let source = edit(
        PRODUCTION,
        "path: /zones/{resource.zone_id}/dns_records\n        credential_slot: read",
        "path: /zones/{params.zone_id}/dns_records\n        credential_slot: read",
    );
    assert_issue(&source, "`zone_id` is not declared with `location: path`");
}

#[test]
fn unknown_parameter_names_are_sanitized_in_errors() {
    let config = production();
    let list = config
        .action(
            &zone(),
            &ActionName::new("cloudflare.dns.records.list").unwrap(),
        )
        .unwrap();
    let attempt = json!({ "ACF-CANARY secret\nvalue": 1 });
    let error = validate_params(&list.action.params, attempt.as_object().unwrap()).unwrap_err();
    assert_eq!(error.kind, ParamErrorKind::Unknown);
    assert!(
        error
            .param
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '?')
    );
}

#[test]
fn structural_param_validation() {
    let config = production();
    let create = config
        .action(
            &zone(),
            &ActionName::new("cloudflare.dns.records.create").unwrap(),
        )
        .unwrap();
    let params = &create.action.params;
    let ok =
        json!({ "type": "A", "name": "api.example.com", "content": "203.0.113.10", "ttl": 300 });
    validate_params(params, ok.as_object().unwrap()).unwrap();

    for (bad, kind) in [
        (
            json!({ "name": "api.example.com", "content": "x" }),
            ParamErrorKind::Missing,
        ),
        (
            json!({ "type": "MX", "name": "a", "content": "x" }),
            ParamErrorKind::NotInEnum,
        ),
        (
            json!({ "type": "A", "name": "a", "content": "x", "ttl": 30 }),
            ParamErrorKind::OutOfRange,
        ),
        (
            json!({ "type": "A", "name": "a", "content": "x", "ttl": "300" }),
            ParamErrorKind::WrongType,
        ),
        (
            json!({ "type": "A", "name": "a", "content": "x", "proxied": null }),
            ParamErrorKind::WrongType,
        ),
        (
            json!({ "type": "A", "name": "a", "content": "x".repeat(2049) }),
            ParamErrorKind::TooLong,
        ),
    ] {
        let error = validate_params(params, bad.as_object().unwrap()).unwrap_err();
        assert_eq!(error.kind, kind, "{bad}");
    }
}

// --- Acceptance: a secret bound to one connector or origin cannot be
// configured for another ---

#[test]
fn secret_cannot_be_redirected_to_another_origin() {
    let source = edit(
        PRODUCTION,
        "base_url: https://api.cloudflare.com/client/v4",
        "base_url: https://api.cloudflare.com.evil.example/client/v4",
    );
    assert_issue(
        &source,
        "does not permit connector `cloudflare`, origin `https://api.cloudflare.com.evil.example`",
    );
}

#[test]
fn secret_cannot_be_used_by_another_connector() {
    let evil_profile = r"
  - schema: acf.profile/v1
    connector: exfil
    revision: 1
    base_url: https://api.cloudflare.com/client/v4
    authentication:
      strategy: bearer
    actions:
      exfil.records.list:
        method: GET
        path: /zones/{resource.zone_id}/dns_records
        credential_slot: read
        classification: read
        response:
          fields: [result]
";
    let evil_resource = r#"
  "exfil:zone":
    connector: exfil
    environment: production
    bindings:
      zone_id: 023e105f4ecef8ad9ca31a8372d0c353
    credentials:
      read: secret://production/cloudflare/example.com/dns-read
"#;
    let source = edit(
        PRODUCTION,
        "\nresources:\n",
        &format!("{evil_profile}\nresources:\n{evil_resource}"),
    );
    assert_issue(&source, "does not permit connector `exfil`");
}

#[test]
fn secret_cannot_fill_a_different_slot() {
    let source = edit(
        PRODUCTION,
        "read: secret://production/cloudflare/example.com/dns-read\n",
        "read: secret://production/cloudflare/example.com/dns-write\n",
    );
    assert_issue(&source, "slot `read`");
}

#[test]
fn every_credential_needs_a_registration_and_provider() {
    let source = edit(
        PRODUCTION,
        "write: secret://production/cloudflare/example.com/dns-write",
        "write: secret://other/cloudflare/example.com/dns-write",
    );
    let found = issues(&source);
    assert!(
        found
            .iter()
            .any(|i| i.contains("no secret provider is configured")),
        "{found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|i| i.contains("has no secret registration")),
        "{found:#?}"
    );
}

#[test]
fn environments_must_match_the_deployment() {
    let source = edit(
        PRODUCTION,
        "connector: cloudflare\n    environment: production",
        "connector: cloudflare\n    environment: development",
    );
    assert_issue(
        &source,
        "environment differs from the deployment environment",
    );
}

// --- Acceptance: missing response allowlists fail validation ---

#[test]
fn missing_response_allowlist_is_rejected() {
    let source = edit(
        DEVELOPMENT,
        "        response:\n          fields: [user, authenticated]\n",
        "",
    );
    assert_parse_error(&source, "missing field `response`");
}

#[test]
fn empty_response_allowlist_is_explicit_and_allowed() {
    let source = edit(DEVELOPMENT, "fields: [user, authenticated]", "fields: []");
    load_yaml(&source).unwrap();
}

// --- Approval cannot be weakened ---

#[test]
fn mutate_actions_cannot_disable_approval() {
    let source = edit(
        PRODUCTION,
        "classification: mutate\n",
        "classification: mutate\n        approval: none\n",
    );
    assert_issue(&source, "`mutate` actions cannot set `approval: none`");
}

// --- Fail-closed parsing ---

#[test]
fn unknown_fields_are_rejected_everywhere() {
    for (from, to) in [
        (
            "schema: acf.config/v1\n",
            "schema: acf.config/v1\nextra: 1\n",
        ),
        ("    revision: 1\n", "    revision: 1\n    proxy: true\n"),
        (
            "        credential_slot: write\n",
            "        credential_slot: write\n        url: https://evil.example\n",
        ),
        (
            "    connector: cloudflare\n    environment",
            "    connector: cloudflare\n    secret_value: x\n    environment",
        ),
        (
            "      auth_slot: write\n",
            "      auth_slot: write\n      wildcard: true\n",
        ),
        (
            "      quotas: { mutations_per_task: 5 }",
            "      quotas: { mutations_per_task: 5, per_second: 1 }",
        ),
    ] {
        assert_parse_error(&edit(PRODUCTION, from, to), "unknown field");
    }
}

#[test]
fn duplicate_keys_are_rejected() {
    let source = edit(
        PRODUCTION,
        "      zone_id: 023e105f4ecef8ad9ca31a8372d0c353\n",
        "      zone_id: 023e105f4ecef8ad9ca31a8372d0c353\n      zone_id: attacker-zone\n",
    );
    assert_parse_error(&source, "duplicate mapping key");
}

#[test]
fn duplicate_profiles_are_rejected() {
    let profile_start = PRODUCTION.find("  - schema: acf.profile/v1").unwrap();
    let resources_start = PRODUCTION.find("\nresources:").unwrap();
    let profile = &PRODUCTION[profile_start..resources_start];
    let source = edit(
        PRODUCTION,
        "\nresources:\n",
        &format!("\n{profile}\nresources:\n"),
    );
    assert_issue(&source, "duplicate connector profile");
}

/// Asserts the hardened parser rejects `source` for the stated reason, using
/// an untyped target so schema checks cannot be what rejects it.
fn assert_parser_rejects(source: &str, reason: &str) {
    match parse_yaml::<serde_json::Value>(source) {
        Err(ConfigError::Parse(message)) => {
            assert!(
                message.contains(reason),
                "expected `{reason}`, got `{message}`"
            );
        }
        other => panic!("expected a parse error, got {other:?}"),
    }
}

#[test]
fn yaml_merge_keys_are_rejected() {
    assert_parser_rejects("a: &x {k: 1}\nb:\n  <<: *x\n", "merge keys are not allowed");
}

#[test]
fn yaml_alias_bombs_are_rejected() {
    // Five levels of ten-fold aliasing: 100,000 replayed events.
    let mut bomb = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
    for (prev, next) in ('a'..='d').zip('b'..='e') {
        let refs = vec![format!("*{prev}"); 10].join(", ");
        writeln!(bomb, "{next}: &{next} [{refs}]").unwrap();
    }
    assert_parser_rejects(&bomb, "alias replay limit exceeded");
}

#[test]
fn yaml_unsupported_tags_are_rejected() {
    assert_parser_rejects("a: !custom 1\n", "unsupported tag");
}

#[test]
fn yaml_duplicate_keys_are_rejected_by_the_parser() {
    assert_parser_rejects("a: 1\na: 2\n", "duplicate mapping key");
}

#[test]
fn yaml_norway_booleans_are_strings() {
    let value: serde_json::Value = parse_yaml("a: no\nb: yes\nc: false\n").unwrap();
    assert_eq!(value, json!({ "a": "no", "b": "yes", "c": false }));

    // So `required: no` is a type error, not `false`.
    let source = edit(
        PRODUCTION,
        "          proxied: { location: body, type: boolean }",
        "          proxied: { location: body, type: boolean, required: no }",
    );
    assert_parse_error(&source, "invalid boolean");
}

#[test]
fn oversized_documents_are_rejected() {
    let huge = format!(
        "{PRODUCTION}\n#{}",
        "x".repeat(acf_config::MAX_CONFIG_BYTES)
    );
    assert_eq!(load_yaml(&huge).unwrap_err(), ConfigError::TooLarge);
}

// --- Cross-reference checks ---

#[test]
fn bindings_must_match_the_profile() {
    let missing = edit(
        PRODUCTION,
        "      zone_id: 023e105f4ecef8ad9ca31a8372d0c353\n",
        "      other: x\n",
    );
    let found = issues(&missing);
    assert!(
        found
            .iter()
            .any(|i| i.contains("missing binding `zone_id`")),
        "{found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|i| i.contains("binding `other` is not used")),
        "{found:#?}"
    );
}

#[test]
fn binding_values_must_be_single_safe_segments() {
    let source = edit(
        PRODUCTION,
        "zone_id: 023e105f4ecef8ad9ca31a8372d0c353",
        "zone_id: \"../../accounts\"",
    );
    assert_parse_error(&source, "single path segment");
}

#[test]
fn credential_slots_must_match_the_profile() {
    let source = edit(
        PRODUCTION,
        "      write: secret://production/cloudflare/example.com/dns-write\n",
        "",
    );
    assert_issue(&source, "missing credential slot `write`");
}

#[test]
fn constraints_must_name_declared_params_and_actions() {
    let source = edit(
        PRODUCTION,
        "      params.ttl: { range: [60, 86400] }",
        "      params.tll: { range: [60, 86400] }\n      actions: { deny: [cloudflare.dns.records.purge] }",
    );
    let found = issues(&source);
    assert!(
        found
            .iter()
            .any(|i| i.contains("`params.tll` is not a parameter")),
        "{found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|i| i.contains("`cloudflare.dns.records.purge` is not")),
        "{found:#?}"
    );
}

#[test]
fn profile_internal_rules() {
    for (from, to, needle) in [
        (
            "classification: read\n        params:",
            "classification: read\n        params:\n          body_field: { location: body, type: string }",
            "GET and DELETE actions cannot have body parameters",
        ),
        (
            "record_type_param: type",
            "record_type_param: name",
            "`record_type_param` must name a required `string` parameter",
        ),
        (
            "          record: [name, type]",
            "          record: [name, type]\n          hash: [name]",
            "under both `record` and `hash`",
        ),
        (
            "          record: [name, type]",
            "          record: [name, type, zone]",
            "`zone`, which is not a declared parameter",
        ),
        (
            "    revision: 1\n",
            "    revision: 1\n    schema_note: x\n",
            "",
        ),
    ] {
        let source = edit(PRODUCTION, from, to);
        if needle.is_empty() {
            assert_parse_error(&source, "unknown field `schema_note`");
        } else {
            assert_issue(&source, needle);
        }
    }
}

#[test]
fn credential_settings_are_rejected_for_external_adapters() {
    let source = edit(
        PRODUCTION,
        "  production:\n    type: encrypted-local\n    path: /var/lib/acf\n    key_source: systemd-credential\n    rollback_anchor: tpm-nv\n",
        "  production:\n    type: external\n    adapter: bitwarden\n    settings:\n      credential_source: systemd-credential\n      access_token: abc\n",
    );
    assert_issue(&source, "setting `access_token` looks like a credential");
}

#[test]
fn issues_are_reported_together() {
    let source = edit(PRODUCTION, "schema: acf.config/v1", "schema: acf.config/v2");
    let source = edit(
        &source,
        "classification: mutate\n",
        "classification: mutate\n        approval: none\n",
    );
    assert!(issues(&source).len() >= 2);
}
