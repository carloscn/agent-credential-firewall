//! Redacted audit events (design §15).
//!
//! Every request produces a `decision` event; allowed requests also produce
//! an `outcome` event after execution. Events carry identities, the logical
//! action and resource, the decision and its reason code, the policy version,
//! the connector and logical secret reference, and the downstream status.
//! They never carry secret values, authorization headers, raw request bodies,
//! or unfiltered responses: this crate does not depend on `acf-secrets`, and
//! parameter values enter only through [`AuditParam`], which the gateway fills
//! according to each parameter's audit classification.
//!
//! Tamper evidence (hash chain and external checkpoints) arrives with WP-12.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Mutex;

use acf_protocol::{
    ActionName, CapabilityId, DeviceId, PrincipalId, RequestId, ResourceId, TaskId,
};
use async_trait::async_trait;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

/// Audit event schema version.
pub const AUDIT_SCHEMA_VERSION: u32 = 1;

/// Which stage of a request an event describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// The authorization decision, emitted before any secret is retrieved.
    Decision,
    /// The execution outcome of an allowed request.
    Outcome,
}

/// Decision or outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Authorization allowed the request.
    Allowed,
    /// Authorization denied the request.
    Denied,
    /// The allowed request completed downstream.
    Completed,
    /// The allowed request failed during execution.
    Failed,
}

/// The emitting gateway.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GatewayInfo {
    /// Gateway instance identifier.
    pub id: String,
    /// `development` or `release` build.
    pub build: String,
    /// Deployment profile.
    pub deployment_profile: String,
}

/// A parameter as it appears in an event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditParam {
    /// The normalized value (classification `record`).
    Value(Value),
    /// A keyed hash of the normalized value (classification `hash`).
    Hmac(String),
}

/// Policy that allowed a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyRef {
    /// Policy version.
    pub version: String,
    /// Matching allow rules.
    pub rules: Vec<String>,
}

/// Downstream call result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Downstream {
    /// HTTP status, when a response arrived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Wall-clock latency of the connector call.
    pub latency_ms: u64,
}

/// One audit event.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AuditEvent {
    /// [`AUDIT_SCHEMA_VERSION`].
    pub schema: u32,
    /// Random event identifier.
    pub event_id: String,
    /// Emission time.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Decision or outcome.
    pub kind: EventKind,
    /// Emitting gateway.
    pub gateway: GatewayInfo,
    /// Request identifier from the agent.
    pub request_id: RequestId,
    /// Task identifier from the agent.
    pub task_id: TaskId,
    /// Authenticated principal; absent when authentication failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalId>,
    /// Device, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceId>,
    /// Capability `jti`, for capability-scoped tasks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<CapabilityId>,
    /// Requested action.
    pub action: ActionName,
    /// Requested resource.
    pub resource: ResourceId,
    /// Verdict.
    pub verdict: Verdict,
    /// Stable reason code for denials and failures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Policy that allowed the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyRef>,
    /// Whether approval was required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_required: Option<bool>,
    /// Connector that executes the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector: Option<String>,
    /// Logical secret reference (never the value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,
    /// Parameters, filtered by audit classification.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, AuditParam>,
    /// Downstream result, on outcome events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downstream: Option<Downstream>,
}

impl AuditEvent {
    /// Starts an event with the fields every event carries.
    #[must_use]
    pub fn new(
        kind: EventKind,
        gateway: GatewayInfo,
        request_id: RequestId,
        task_id: TaskId,
        action: ActionName,
        resource: ResourceId,
        verdict: Verdict,
    ) -> Self {
        Self {
            schema: AUDIT_SCHEMA_VERSION,
            event_id: random_id(),
            timestamp: OffsetDateTime::now_utc(),
            kind,
            gateway,
            request_id,
            task_id,
            principal: None,
            device: None,
            capability: None,
            action,
            resource,
            verdict,
            reason: None,
            policy: None,
            approval_required: None,
            connector: None,
            secret_ref: None,
            params: BTreeMap::new(),
            downstream: None,
        }
    }
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    // An all-zero id on RNG failure is still a valid (if non-unique) id;
    // event ids are for correlation, not security.
    let _ = SystemRandom::new().fill(&mut bytes);
    bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
        s
    })
}

/// Keyed hashing for `hash`-classified parameters: HMAC-SHA256 over the
/// parameter name and the value's JSON encoding. The key never leaves the
/// gateway, so hashes correlate equal values without revealing them.
pub struct AuditHasher {
    key: hmac::Key,
}

impl AuditHasher {
    /// Creates a hasher with a fresh random key. Hashes then correlate only
    /// within one gateway process.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Random`] if the OS random source fails.
    pub fn random() -> Result<Self, AuditError> {
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new())
            .map_err(|_| AuditError::Random)?;
        Ok(Self { key })
    }

    /// Hashes one parameter value.
    #[must_use]
    pub fn hash(&self, param: &str, value: &Value) -> String {
        let mut context = hmac::Context::with_key(&self.key);
        context.update(param.as_bytes());
        context.update(&[0]);
        context.update(value.to_string().as_bytes());
        let tag = context.sign();
        tag.as_ref()
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
                s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
                s
            })
    }
}

/// Audit failures.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The sink could not record the event.
    #[error("audit sink unavailable")]
    Unavailable,
    /// No secure random source.
    #[error("no secure random source available")]
    Random,
}

/// Where events go.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Records one event durably before returning.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Unavailable`] if the event was not recorded.
    async fn emit(&self, event: &AuditEvent) -> Result<(), AuditError>;
}

/// Writes one JSON object per line and flushes after each event.
pub struct JsonLinesSink {
    writer: Mutex<Box<dyn Write + Send>>,
}

impl JsonLinesSink {
    /// Wraps a writer, for example an append-mode file or stderr.
    #[must_use]
    pub fn new(writer: Box<dyn Write + Send>) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }
}

#[async_trait]
impl AuditSink for JsonLinesSink {
    async fn emit(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut line = serde_json::to_vec(event).map_err(|_| AuditError::Unavailable)?;
        line.push(b'\n');
        let mut writer = self.writer.lock().map_err(|_| AuditError::Unavailable)?;
        writer
            .write_all(&line)
            .map_err(|_| AuditError::Unavailable)?;
        writer.flush().map_err(|_| AuditError::Unavailable)
    }
}

/// Keeps events in memory, for tests.
#[derive(Default)]
pub struct MemorySink {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemorySink {
    /// A copy of the recorded events.
    #[must_use]
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl AuditSink for MemorySink {
    async fn emit(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.events
            .lock()
            .map_err(|_| AuditError::Unavailable)?
            .push(event.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event() -> AuditEvent {
        AuditEvent::new(
            EventKind::Decision,
            GatewayInfo {
                id: "gw".to_owned(),
                build: "development".to_owned(),
                deployment_profile: "development".to_owned(),
            },
            RequestId::new("req-1").unwrap(),
            TaskId::new("task-1").unwrap(),
            ActionName::new("example.profile.get").unwrap(),
            ResourceId::new("example-api:development").unwrap(),
            Verdict::Allowed,
        )
    }

    #[test]
    fn hashes_are_keyed_and_deterministic_per_key() {
        let a = AuditHasher::random().unwrap();
        let b = AuditHasher::random().unwrap();
        let value = json!("api.example.com");
        assert_eq!(a.hash("name", &value), a.hash("name", &value));
        assert_ne!(
            a.hash("name", &value),
            b.hash("name", &value),
            "different keys"
        );
        assert_ne!(
            a.hash("name", &value),
            a.hash("other", &value),
            "bound to the parameter"
        );
        assert_eq!(a.hash("name", &value).len(), 64);
        assert!(!a.hash("name", &value).contains("example"));
    }

    #[tokio::test]
    async fn json_lines_sink_writes_one_line_per_event() {
        #[derive(Clone, Default)]
        struct Shared(std::sync::Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Shared::default();
        let sink = JsonLinesSink::new(Box::new(buffer.clone()));
        sink.emit(&event()).await.unwrap();
        sink.emit(&event()).await.unwrap();
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["schema"], 1);
        assert_eq!(lines[0]["kind"], "decision");
        assert_eq!(lines[0]["verdict"], "allowed");
        assert_ne!(lines[0]["event_id"], lines[1]["event_id"]);
        assert!(lines[0].get("params").is_none(), "empty params are omitted");
    }
}
