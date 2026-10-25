//! Authority configuration (`acf.authority/v1`) and signed job definitions
//! (`acf.job/v1`, ADR 0003).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use acf_config::{ValidatedConfig, parse_yaml};
use acf_protocol::{
    ActionName, AudienceId, Grant, IssuerId, JobId, KeyId, Limits, PrincipalId, ResourceId,
    Sha256Digest,
};
use serde::Deserialize;

use crate::keys::{DetachedSignature, verify_detached};

/// Schema identifier for the authority configuration.
pub const AUTHORITY_SCHEMA: &str = "acf.authority/v1";
/// Schema identifier for job definitions.
pub const JOB_SCHEMA: &str = "acf.job/v1";
/// Longest lifetime the authority will ever issue, in seconds. Gateways
/// accept at most 24 hours.
pub const MAX_TTL_SECS: u32 = 24 * 60 * 60;

/// What one principal may ever be granted.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entitlement {
    /// The principal.
    pub principal: PrincipalId,
    /// Grants; each action/resource pair at most once.
    pub grants: Vec<Grant>,
}

/// A trusted scheduler and the scope it may request for itself.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scheduler {
    /// The scheduler's principal (its mTLS identity).
    pub principal: PrincipalId,
    /// Preconfigured scope.
    pub grants: Vec<Grant>,
    /// Longest lifetime for its tasks.
    #[serde(default)]
    pub max_ttl_secs: Option<u32>,
    /// Usage limits for its tasks.
    #[serde(default)]
    pub limits: Limits,
}

/// A public key trusted to sign job definitions.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSigner {
    /// Key identifier.
    pub kid: KeyId,
    /// Raw Ed25519 public key, unpadded base64url.
    pub public_key: String,
}

/// The `acf.authority/v1` document.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    /// Must be [`AUTHORITY_SCHEMA`].
    pub schema: String,
    /// `iss` of issued capabilities.
    pub issuer: IssuerId,
    /// `aud` of issued capabilities: the gateway security domain.
    pub audience: AudienceId,
    /// Lifetime when a proposal names none.
    pub default_ttl_secs: u32,
    /// Longest lifetime for any capability.
    pub max_ttl_secs: u32,
    /// Per-principal entitlements.
    #[serde(default)]
    pub entitlements: Vec<Entitlement>,
    /// Trusted schedulers.
    #[serde(default)]
    pub schedulers: Vec<Scheduler>,
    /// Keys trusted to sign job definitions.
    #[serde(default)]
    pub job_signers: Vec<JobSigner>,
}

/// An administrator-approved job definition.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobDefinition {
    /// Must be [`JOB_SCHEMA`].
    pub schema: String,
    /// Job identifier.
    pub id: JobId,
    /// Principals that may run the job.
    pub principals: BTreeSet<PrincipalId>,
    /// Approved scope.
    pub grants: Vec<Grant>,
    /// Longest lifetime for its tasks.
    #[serde(default)]
    pub ttl_secs: Option<u32>,
    /// Usage limits for its tasks.
    #[serde(default)]
    pub limits: Limits,
}

/// A job definition whose signature verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedJob {
    /// The definition.
    pub definition: JobDefinition,
    /// SHA-256 of the signed bytes.
    pub digest: Sha256Digest,
}

/// Why configuration was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityConfigError {
    /// Malformed YAML or schema.
    #[error("{0}")]
    Parse(String),
    /// A TTL is zero, inconsistent, or above [`MAX_TTL_SECS`].
    #[error("TTLs must satisfy 0 < default_ttl_secs <= max_ttl_secs <= {MAX_TTL_SECS}")]
    Ttl,
    /// Something is defined twice.
    #[error("{0} is defined twice")]
    Duplicate(String),
    /// A grant names a resource or action the bundle does not register.
    #[error("grant `{0}` on `{1}` is not a registered action")]
    UnknownGrant(ActionName, ResourceId),
    /// A job definition has no valid signature.
    #[error("job definition {0} is not signed by a trusted key")]
    Unsigned(String),
}

fn check_grants(
    owner: &str,
    grants: &[Grant],
    bundle: &ValidatedConfig,
) -> Result<(), AuthorityConfigError> {
    let mut seen = BTreeSet::new();
    for grant in grants {
        if bundle.action(&grant.resource, &grant.action).is_none() {
            return Err(AuthorityConfigError::UnknownGrant(
                grant.action.clone(),
                grant.resource.clone(),
            ));
        }
        if !seen.insert((&grant.action, &grant.resource)) {
            return Err(AuthorityConfigError::Duplicate(format!(
                "grant `{}` on `{}` for {owner}",
                grant.action, grant.resource
            )));
        }
    }
    Ok(())
}

/// A job definition file and its detached signature, as read from disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobFile {
    /// Name for error messages, usually the path.
    pub name: String,
    /// Exact file bytes.
    pub bytes: Vec<u8>,
    /// Contents of the `.sig` file.
    pub signature: Vec<u8>,
}

/// The authority's validated policy.
#[derive(Clone, Debug)]
pub struct AuthorityPolicy {
    /// The configuration.
    pub config: AuthorityConfig,
    /// Entitlements by principal.
    pub entitlements: BTreeMap<PrincipalId, Vec<Grant>>,
    /// Schedulers by principal.
    pub schedulers: BTreeMap<PrincipalId, Scheduler>,
    /// Verified jobs by identifier.
    pub jobs: BTreeMap<JobId, SignedJob>,
}

impl AuthorityPolicy {
    /// Validates `config` against `bundle` and verifies each job file.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityConfigError`] for anything inconsistent or
    /// unsigned. Nothing is skipped: one bad job fails the whole load.
    pub fn new(
        config: AuthorityConfig,
        bundle: &ValidatedConfig,
        jobs: &[JobFile],
    ) -> Result<Self, AuthorityConfigError> {
        if config.schema != AUTHORITY_SCHEMA {
            return Err(AuthorityConfigError::Parse(format!(
                "authority schema must be `{AUTHORITY_SCHEMA}`"
            )));
        }
        if config.default_ttl_secs == 0
            || config.default_ttl_secs > config.max_ttl_secs
            || config.max_ttl_secs > MAX_TTL_SECS
        {
            return Err(AuthorityConfigError::Ttl);
        }
        let mut entitlements = BTreeMap::new();
        for entry in &config.entitlements {
            check_grants(entry.principal.as_str(), &entry.grants, bundle)?;
            if entitlements
                .insert(entry.principal.clone(), entry.grants.clone())
                .is_some()
            {
                return Err(AuthorityConfigError::Duplicate(format!(
                    "entitlement for `{}`",
                    entry.principal
                )));
            }
        }
        let mut schedulers = BTreeMap::new();
        for scheduler in &config.schedulers {
            check_grants(scheduler.principal.as_str(), &scheduler.grants, bundle)?;
            if scheduler.max_ttl_secs == Some(0) {
                return Err(AuthorityConfigError::Ttl);
            }
            if schedulers
                .insert(scheduler.principal.clone(), scheduler.clone())
                .is_some()
            {
                return Err(AuthorityConfigError::Duplicate(format!(
                    "scheduler `{}`",
                    scheduler.principal
                )));
            }
        }
        let mut signers = BTreeMap::new();
        for signer in &config.job_signers {
            if signers
                .insert(signer.kid.clone(), signer.public_key.clone())
                .is_some()
            {
                return Err(AuthorityConfigError::Duplicate(format!(
                    "job signer `{}`",
                    signer.kid
                )));
            }
        }
        let mut verified = BTreeMap::new();
        for file in jobs {
            let job = verify_job(&file.name, &file.bytes, &file.signature, &signers)?;
            check_grants(job.definition.id.as_str(), &job.definition.grants, bundle)?;
            if job.definition.ttl_secs == Some(0) {
                return Err(AuthorityConfigError::Ttl);
            }
            if verified
                .insert(job.definition.id.clone(), job.clone())
                .is_some()
            {
                return Err(AuthorityConfigError::Duplicate(format!(
                    "job `{}`",
                    job.definition.id
                )));
            }
        }
        Ok(Self {
            config,
            entitlements,
            schedulers,
            jobs: verified,
        })
    }
}

fn verify_job(
    name: &str,
    bytes: &[u8],
    signature: &[u8],
    signers: &BTreeMap<KeyId, String>,
) -> Result<SignedJob, AuthorityConfigError> {
    let unsigned = || AuthorityConfigError::Unsigned(name.to_owned());
    let signature: DetachedSignature = serde_json::from_slice(signature).map_err(|_| unsigned())?;
    let public_key = signers.get(&signature.kid).ok_or_else(unsigned)?;
    if !verify_detached(public_key, bytes, &signature) {
        return Err(unsigned());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| unsigned())?;
    let definition: JobDefinition =
        parse_yaml(text).map_err(|e| AuthorityConfigError::Parse(format!("{name}: {e}")))?;
    if definition.schema != JOB_SCHEMA {
        return Err(AuthorityConfigError::Parse(format!(
            "{name}: job schema must be `{JOB_SCHEMA}`"
        )));
    }
    Ok(SignedJob {
        definition,
        digest: sha256(bytes),
    })
}

/// The `sha256:<hex>` digest of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> Sha256Digest {
    use std::fmt::Write as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut text = String::from("sha256:");
    for byte in digest.as_ref() {
        let _ = write!(text, "{byte:02x}");
    }
    // 32 bytes always format as a well-formed digest.
    Sha256Digest::parse(text).unwrap_or_else(|_| unreachable!())
}

/// Reads every `*.yaml` job in `dir` with its `*.yaml.sig`.
///
/// # Errors
///
/// Returns a message if the directory or a file cannot be read, or a job has
/// no signature file.
pub fn read_jobs(dir: &Path) -> Result<Vec<JobFile>, String> {
    let mut jobs = Vec::new();
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut paths: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    paths.sort();
    for path in paths {
        let name = path.display().to_string();
        let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {name}: {e}"))?;
        let signature_path = path.with_extension("yaml.sig");
        let signature = std::fs::read(&signature_path)
            .map_err(|_| format!("{name} has no signature file {}", signature_path.display()))?;
        jobs.push(JobFile {
            name,
            bytes,
            signature,
        });
    }
    Ok(jobs)
}
