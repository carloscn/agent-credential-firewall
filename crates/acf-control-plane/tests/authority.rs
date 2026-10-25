//! Capability issuance: scope intersection, authorization bases, and
//! compatibility with the gateway-side verifier (ADR 0003).

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use acf_config::{ValidatedConfig, load_yaml, parse_yaml};
use acf_control_plane::{
    Authority, AuthorityConfig, AuthorityConfigError, AuthorityPolicy, CapabilitySigner, JobFile,
    generate_pem, parse_key_pair, public_key, sha256, sign_detached,
};
use acf_identity::{
    AUTHORITY_KEYS_SCHEMA, AuthorityKeys, CapabilityVerifier, IdentityAssurance, IdentityContext,
};
use acf_protocol::{
    AuthorityErrorCode, AuthorizationBasis, BasisRequest, CertificateThumbprint, Grant, IssuerId,
    JobId, KeyId, ParamName, PrincipalId, TaskCapabilityClaims, TaskId, TaskProposal,
};
use ring::signature::Ed25519KeyPair;
use serde_json::{Map, Value, json};

const NOW: i64 = 1_800_000_000;
const THUMBPRINT: &str = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
const PROFILE: &str = "example.profile.get";
const CREATE: &str = "example.records.create";
const RESOURCE: &str = "example-api:development";

const BUNDLE: &str = r#"
schema: acf.config/v1
deployment: { profile: development, environment: development }
secret_providers:
  development: { type: in-memory }
profiles:
  - schema: acf.profile/v1
    connector: example-api
    revision: 1
    base_url: http://127.0.0.1:9
    authentication: { strategy: bearer }
    actions:
      example.profile.get:
        method: GET
        path: /profile
        credential_slot: read
        classification: read
        params:
          view: { location: query, type: string, enum: [summary, full] }
        response: { fields: [user] }
      example.records.create:
        method: POST
        path: /records
        credential_slot: write
        classification: mutate
        params:
          name: { location: body, type: string, required: true }
        response: { fields: [id] }
resources:
  "example-api:development":
    connector: example-api
    environment: development
    credentials:
      read: secret://development/example-api/read
      write: secret://development/example-api/write
secrets:
  "secret://development/example-api/read":
    use_binding: { connectors: [example-api], origins: ["http://127.0.0.1:9"], auth_slot: read, environment: development }
  "secret://development/example-api/write":
    use_binding: { connectors: [example-api], origins: ["http://127.0.0.1:9"], auth_slot: write, environment: development }
"#;

fn bundle() -> ValidatedConfig {
    load_yaml(BUNDLE).unwrap()
}

fn authority_config(job_signer: &str) -> AuthorityConfig {
    parse_yaml(&format!(
        r#"
schema: acf.authority/v1
issuer: acf-authority-test
audience: acf-gateway-test
default_ttl_secs: 900
max_ttl_secs: 3600
entitlements:
  - principal: "workload:vps-17"
    grants:
      - {{ action: {PROFILE}, resource: "{RESOURCE}" }}
  - principal: "workload:ci"
    grants:
      - {{ action: {PROFILE}, resource: "{RESOURCE}", constraints: {{ params.view: {{ in: [summary] }} }} }}
      - {{ action: {CREATE}, resource: "{RESOURCE}" }}
schedulers:
  - principal: "workload:ci"
    max_ttl_secs: 300
    limits: {{ maxRequests: 5 }}
    grants:
      - {{ action: {PROFILE}, resource: "{RESOURCE}" }}
job_signers:
  - kid: admin-1
    public_key: {job_signer}
"#
    ))
    .unwrap()
}

const JOB: &str = r#"schema: acf.job/v1
id: nightly-profile
principals: ["workload:vps-17"]
ttl_secs: 600
limits: { maxRequests: 10 }
grants:
  - { action: example.profile.get, resource: "example-api:development" }
  - { action: example.records.create, resource: "example-api:development" }
"#;

struct Fixture {
    admin: Ed25519KeyPair,
    signing_pem: String,
}

impl Fixture {
    fn new() -> Self {
        Self {
            admin: parse_key_pair(&generate_pem().unwrap()).unwrap(),
            signing_pem: generate_pem().unwrap(),
        }
    }

    fn signed_job(&self, bytes: &str) -> JobFile {
        let signature = sign_detached(
            KeyId::new("admin-1").unwrap(),
            &self.admin,
            bytes.as_bytes(),
        );
        JobFile {
            name: "nightly.yaml".to_owned(),
            bytes: bytes.as_bytes().to_vec(),
            signature: serde_json::to_vec(&signature).unwrap(),
        }
    }

    fn policy(&self, jobs: &[JobFile]) -> Result<AuthorityPolicy, AuthorityConfigError> {
        AuthorityPolicy::new(authority_config(&public_key(&self.admin)), &bundle(), jobs)
    }

    fn signer(&self) -> CapabilitySigner {
        CapabilitySigner::new(
            IssuerId::new("acf-authority-test").unwrap(),
            KeyId::new("authority-1").unwrap(),
            parse_key_pair(&self.signing_pem).unwrap(),
        )
    }

    fn authority(&self) -> Authority {
        let policy = self.policy(&[self.signed_job(JOB)]).unwrap();
        Authority::new(policy, bundle(), self.signer()).unwrap()
    }

    fn verifier(&self) -> CapabilityVerifier {
        CapabilityVerifier::new(AuthorityKeys {
            schema: AUTHORITY_KEYS_SCHEMA.to_owned(),
            keys: vec![self.signer().trust_entry()],
        })
        .unwrap()
    }
}

fn caller(principal: &str) -> IdentityContext {
    IdentityContext {
        principal: PrincipalId::new(principal).unwrap(),
        device: None,
        labels: std::collections::BTreeSet::new(),
        certificate: Some(CertificateThumbprint::parse(THUMBPRINT).unwrap()),
        issuer: IssuerId::new("test-mtls").unwrap(),
        assurance: IdentityAssurance::Production,
    }
}

fn proposal(basis: BasisRequest, grants: Value) -> TaskProposal {
    TaskProposal {
        task_id: TaskId::new("task-1").unwrap(),
        basis,
        grants: serde_json::from_value(grants).unwrap(),
        ttl_secs: None,
    }
}

fn job() -> BasisRequest {
    BasisRequest::Job {
        job: JobId::new("nightly-profile").unwrap(),
    }
}

fn pairs(grants: &[Grant]) -> Vec<String> {
    grants
        .iter()
        .map(|g| format!("{} {}", g.action, g.resource))
        .collect()
}

fn allows_view(grant: &Grant, view: &str) -> bool {
    let mut params = Map::new();
    params.insert("view".to_owned(), json!(view));
    grant
        .constraints
        .check_params(|p: &ParamName| p.as_str() == "view", &params)
        .is_ok()
}

#[test]
fn a_job_basis_yields_a_verifiable_certificate_bound_capability() {
    let fixture = Fixture::new();
    let issuance = fixture
        .authority()
        .issue(&caller("workload:vps-17"), &proposal(job(), json!([])), NOW)
        .unwrap();

    let claims: TaskCapabilityClaims = fixture
        .verifier()
        .verify(&issuance.issued.capability)
        .unwrap();
    assert_eq!(claims.iss.as_str(), "acf-authority-test");
    assert_eq!(claims.aud.as_str(), "acf-gateway-test");
    assert_eq!(claims.sub.as_str(), "workload:vps-17");
    assert_eq!(claims.cnf.x5t_s256.as_str(), THUMBPRINT);
    assert_eq!(claims.jti, issuance.jti);
    assert_eq!(claims.task.id.as_str(), "task-1");
    assert_eq!(
        claims.task.basis,
        AuthorizationBasis::JobDefinition {
            definition_digest: sha256(JOB.as_bytes())
        }
    );
    // The job allows create, but vps-17 is not entitled to it.
    assert_eq!(pairs(&claims.grants), [format!("{PROFILE} {RESOURCE}")]);
    assert_eq!(claims.grants, issuance.issued.grants);
    assert_eq!(claims.limits.max_requests, Some(10));
    assert_eq!((claims.iat, claims.nbf, claims.exp), (NOW, NOW, NOW + 600));
    assert_eq!(issuance.issued.expires_at.unix_timestamp(), NOW + 600);
}

#[test]
fn a_proposal_can_only_narrow() {
    let fixture = Fixture::new();
    let authority = fixture.authority();
    let ci = caller("workload:ci");

    // The scheduler scope has no create, so proposing it adds nothing.
    let issued = authority
        .issue(
            &ci,
            &proposal(
                BasisRequest::Scheduler,
                json!([
                    { "action": PROFILE, "resource": RESOURCE },
                    { "action": CREATE, "resource": RESOURCE },
                ]),
            ),
            NOW,
        )
        .unwrap()
        .issued;
    assert_eq!(pairs(&issued.grants), [format!("{PROFILE} {RESOURCE}")]);
    // The entitlement's `view in [summary]` survives even though neither the
    // proposal nor the scheduler scope mentions it.
    assert!(allows_view(&issued.grants[0], "summary"));
    assert!(!allows_view(&issued.grants[0], "full"));

    // A proposal constraint narrows further; it cannot loosen the others.
    let issued = authority
        .issue(
            &ci,
            &proposal(
                BasisRequest::Scheduler,
                json!([{ "action": PROFILE, "resource": RESOURCE,
                         "constraints": { "params.view": { "in": ["summary", "full"] } } }]),
            ),
            NOW,
        )
        .unwrap()
        .issued;
    assert!(!allows_view(&issued.grants[0], "full"));

    // Nothing left: denied, not an empty capability.
    assert_eq!(
        authority
            .issue(
                &ci,
                &proposal(
                    BasisRequest::Scheduler,
                    json!([{ "action": CREATE, "resource": RESOURCE }]),
                ),
                NOW,
            )
            .unwrap_err(),
        AuthorityErrorCode::ScopeEmpty
    );
    // Repeating a pair is malformed.
    assert_eq!(
        authority
            .issue(
                &ci,
                &proposal(
                    BasisRequest::Scheduler,
                    json!([
                        { "action": PROFILE, "resource": RESOURCE },
                        { "action": PROFILE, "resource": RESOURCE },
                    ]),
                ),
                NOW,
            )
            .unwrap_err(),
        AuthorityErrorCode::InvalidRequest
    );
}

#[test]
fn ttl_is_capped_by_the_basis_and_the_authority() {
    let fixture = Fixture::new();
    let authority = fixture.authority();
    let mut scheduled = proposal(BasisRequest::Scheduler, json!([]));
    scheduled.ttl_secs = Some(3000);
    let issued = authority
        .issue(&caller("workload:ci"), &scheduled, NOW)
        .unwrap()
        .issued;
    assert_eq!(
        issued.expires_at.unix_timestamp(),
        NOW + 300,
        "scheduler max"
    );
    assert_eq!(issued.limits.max_requests, Some(5));

    let mut short = proposal(job(), json!([]));
    short.ttl_secs = Some(60);
    let issued = authority
        .issue(&caller("workload:vps-17"), &short, NOW)
        .unwrap()
        .issued;
    assert_eq!(
        issued.expires_at.unix_timestamp(),
        NOW + 60,
        "proposal is shorter"
    );
}

#[test]
fn bases_are_available_only_to_their_principals() {
    let fixture = Fixture::new();
    let authority = fixture.authority();
    for (who, basis) in [
        ("workload:ci", job()),
        ("workload:vps-17", BasisRequest::Scheduler),
        (
            "workload:vps-17",
            BasisRequest::Job {
                job: JobId::new("no-such-job").unwrap(),
            },
        ),
    ] {
        assert_eq!(
            authority
                .issue(&caller(who), &proposal(basis, json!([])), NOW)
                .unwrap_err(),
            AuthorityErrorCode::BasisRejected,
            "{who}"
        );
    }
    let mut anonymous = caller("workload:vps-17");
    anonymous.certificate = None;
    assert_eq!(
        authority
            .issue(&anonymous, &proposal(job(), json!([])), NOW)
            .unwrap_err(),
        AuthorityErrorCode::Unauthenticated
    );
}

#[test]
fn unsigned_tampered_and_foreign_jobs_are_refused_at_load() {
    let fixture = Fixture::new();
    let tampered = {
        let mut job = fixture.signed_job(JOB);
        job.bytes = JOB.replace("ttl_secs: 600", "ttl_secs: 3600").into_bytes();
        job
    };
    let foreign = {
        let other = parse_key_pair(&generate_pem().unwrap()).unwrap();
        let signature = sign_detached(KeyId::new("admin-1").unwrap(), &other, JOB.as_bytes());
        JobFile {
            signature: serde_json::to_vec(&signature).unwrap(),
            ..fixture.signed_job(JOB)
        }
    };
    let unsigned = JobFile {
        signature: b"{}".to_vec(),
        ..fixture.signed_job(JOB)
    };
    for (name, job) in [
        ("tampered", tampered),
        ("foreign", foreign),
        ("unsigned", unsigned),
    ] {
        assert!(
            matches!(
                fixture.policy(&[job]),
                Err(AuthorityConfigError::Unsigned(_))
            ),
            "{name}"
        );
    }
    let unknown_action = fixture.signed_job(&JOB.replace(CREATE, "example.records.delete"));
    assert!(matches!(
        fixture.policy(&[unknown_action]),
        Err(AuthorityConfigError::UnknownGrant(..))
    ));
}

#[test]
fn the_signer_must_match_the_configured_issuer() {
    let fixture = Fixture::new();
    let other = CapabilitySigner::new(
        IssuerId::new("someone-else").unwrap(),
        KeyId::new("authority-1").unwrap(),
        parse_key_pair(&fixture.signing_pem).unwrap(),
    );
    assert!(Authority::new(fixture.policy(&[]).unwrap(), bundle(), other).is_err());
}
