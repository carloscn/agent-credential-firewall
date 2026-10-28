//! Append-only checkpoint collector (ADR 0005): the external anchor for
//! gateway audit logs.
//!
//! Each log gets `<dir>/<log>.jsonl`, one envelope per line, appended and
//! synced, never rewritten. A checkpoint is accepted only if its signature
//! verifies, its key belongs to the calling principal, and it extends the
//! log's stored history.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use acf_audit::{AuditKeys, CheckpointEnvelope, CheckpointError, CheckpointStatement};
use acf_identity::{ConnectionInfo, IdentityContextProvider};
use acf_protocol::{PrincipalId, base64url_decode};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Router};
use serde_json::json;

/// Largest accepted checkpoint envelope.
pub const MAX_CHECKPOINT_BYTES: usize = 8 * 1024;

/// How the collector answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepted {
    /// Appended as a new checkpoint.
    Created,
    /// The same checkpoint was already stored.
    Duplicate,
}

/// Why a checkpoint was refused.
#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    /// Bad signature, unknown key, or malformed.
    #[error("{0}")]
    Invalid(CheckpointError),
    /// The caller is not the principal this key belongs to, or the log
    /// belongs to another gateway.
    #[error("caller may not submit this checkpoint")]
    Forbidden,
    /// It contradicts or precedes the stored history.
    #[error("checkpoint conflicts with the stored history")]
    Conflict,
    /// The store could not be written.
    #[error("checkpoint store unavailable: {0}")]
    Store(String),
}

/// Log identifiers are `log-` plus 32 lowercase hex digits, so they are safe
/// file names.
fn valid_log_id(log: &str) -> bool {
    log.strip_prefix("log-").is_some_and(|hex| {
        hex.len() == 32
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Decodes a stored or received envelope's statement without checking its
/// signature.
///
/// # Errors
///
/// Returns [`CheckpointError::Malformed`] if it does not decode.
pub fn statement_of(envelope: &CheckpointEnvelope) -> Result<CheckpointStatement, CheckpointError> {
    let payload = base64url_decode(&envelope.payload).map_err(|_| CheckpointError::Malformed)?;
    serde_json::from_slice(&payload).map_err(|_| CheckpointError::Malformed)
}

/// Reads every envelope stored for `log` in `dir`.
///
/// # Errors
///
/// Returns a message if the file exists but cannot be read or parsed.
pub fn read_stored(dir: &Path, log: &str) -> Result<Vec<CheckpointEnvelope>, String> {
    if !valid_log_id(log) {
        return Err(format!("`{log}` is not a log identifier"));
    }
    let path = dir.join(format!("{log}.jsonl"));
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    text.lines()
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|_| format!("{} has a malformed line", path.display()))
        })
        .collect()
}

/// The newest stored checkpoint of one log.
#[derive(Clone, Debug)]
struct Newest {
    seq: u64,
    head: String,
    /// The gateway whose key signed the log's first checkpoint. Only it may
    /// extend the log.
    gateway: String,
}

/// The collector's store.
pub struct CheckpointStore {
    dir: PathBuf,
    keys: AuditKeys,
    /// Newest stored checkpoint per log, and the gateway that owns the log.
    newest: Mutex<BTreeMap<String, Newest>>,
}

impl std::fmt::Debug for CheckpointStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointStore")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl CheckpointStore {
    /// Opens `dir`, creating it if needed, and learns each stored log's
    /// newest checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a message if the directory or a stored file cannot be read.
    pub fn open(dir: &Path, keys: AuditKeys) -> Result<Self, String> {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let mut newest = BTreeMap::new();
        let entries =
            std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(log) = name.strip_suffix(".jsonl").filter(|log| valid_log_id(log)) else {
                continue;
            };
            if let Some(last) = read_stored(dir, log)?.last() {
                let statement = statement_of(last).map_err(|e| format!("{name}: {e}"))?;
                newest.insert(
                    log.to_owned(),
                    Newest {
                        seq: statement.seq,
                        head: statement.head,
                        gateway: statement.gateway,
                    },
                );
            }
        }
        Ok(Self {
            dir: dir.to_owned(),
            keys,
            newest: Mutex::new(newest),
        })
    }

    /// Accepts or refuses one checkpoint from `caller`.
    ///
    /// # Errors
    ///
    /// Returns [`CollectorError`] as described in ADR 0005.
    pub fn accept(
        &self,
        caller: &PrincipalId,
        envelope: &CheckpointEnvelope,
    ) -> Result<Accepted, CollectorError> {
        let (statement, entry) = self
            .keys
            .verify(envelope)
            .map_err(CollectorError::Invalid)?;
        if &entry.principal != caller {
            return Err(CollectorError::Forbidden);
        }
        if !valid_log_id(&statement.log) {
            return Err(CollectorError::Invalid(CheckpointError::Malformed));
        }
        let mut newest = self
            .newest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match newest.get(&statement.log) {
            // Another gateway cannot extend, or wedge, this log.
            Some(stored) if stored.gateway != statement.gateway => {
                return Err(CollectorError::Forbidden);
            }
            Some(stored) if statement.seq == stored.seq && statement.head == stored.head => {
                return Ok(Accepted::Duplicate);
            }
            Some(stored) if statement.seq <= stored.seq => return Err(CollectorError::Conflict),
            _ => {}
        }
        let mut line =
            serde_json::to_vec(envelope).map_err(|e| CollectorError::Store(e.to_string()))?;
        line.push(b'\n');
        let path = self.dir.join(format!("{}.jsonl", statement.log));
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| CollectorError::Store(e.to_string()))?;
        file.write_all(&line)
            .and_then(|()| file.sync_data())
            .map_err(|e| CollectorError::Store(e.to_string()))?;
        newest.insert(
            statement.log,
            Newest {
                seq: statement.seq,
                head: statement.head,
                gateway: statement.gateway,
            },
        );
        Ok(Accepted::Created)
    }
}

struct AppState {
    store: Arc<CheckpointStore>,
    identity: Arc<dyn IdentityContextProvider>,
}

fn answer(status: StatusCode, body: &serde_json::Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

#[expect(clippy::print_stderr, reason = "collector decision log")]
fn log(event: &serde_json::Value) {
    eprintln!("{event}");
}

async fn submit(
    State(state): State<Arc<AppState>>,
    connection: Option<Extension<ConnectionInfo>>,
    body: Bytes,
) -> Response {
    let connection = connection.map(|Extension(c)| c).unwrap_or_default();
    let Ok(caller) = state.identity.resolve(&connection).await else {
        return answer(
            StatusCode::UNAUTHORIZED,
            &json!({ "error": "unauthenticated" }),
        );
    };
    let Ok(envelope) = serde_json::from_slice::<CheckpointEnvelope>(&body) else {
        return answer(
            StatusCode::BAD_REQUEST,
            &json!({ "error": "invalid_request" }),
        );
    };
    let statement = statement_of(&envelope).ok();
    let describe = |outcome: &str| {
        json!({
            "event": outcome,
            "caller": caller.principal,
            "log": statement.as_ref().map(|s| &s.log),
            "seq": statement.as_ref().map(|s| s.seq),
        })
    };
    match state.store.accept(&caller.principal, &envelope) {
        Ok(Accepted::Created) => {
            log(&describe("checkpoint_accepted"));
            answer(StatusCode::CREATED, &json!({ "status": "accepted" }))
        }
        Ok(Accepted::Duplicate) => answer(StatusCode::OK, &json!({ "status": "duplicate" })),
        Err(CollectorError::Conflict) => {
            // A gateway presenting a different history than it committed to.
            log(&describe("checkpoint_conflict"));
            answer(
                StatusCode::CONFLICT,
                &json!({ "error": "checkpoint_conflict" }),
            )
        }
        Err(CollectorError::Forbidden) => {
            log(&describe("checkpoint_forbidden"));
            answer(StatusCode::FORBIDDEN, &json!({ "error": "forbidden" }))
        }
        Err(CollectorError::Invalid(_)) => {
            log(&describe("checkpoint_invalid"));
            answer(
                StatusCode::BAD_REQUEST,
                &json!({ "error": "checkpoint_invalid" }),
            )
        }
        Err(CollectorError::Store(_)) => answer(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({ "error": "unavailable" }),
        ),
    }
}

/// `POST /v1/audit/checkpoints`. Merge it into the authority's mTLS router.
pub fn checkpoint_router(
    store: Arc<CheckpointStore>,
    identity: Arc<dyn IdentityContextProvider>,
) -> Router {
    Router::new()
        .route("/v1/audit/checkpoints", post(submit))
        .layer(DefaultBodyLimit::max(MAX_CHECKPOINT_BYTES))
        .with_state(Arc::new(AppState { store, identity }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use acf_audit::{
        AUDIT_KEYS_SCHEMA, AuditKeyEntry, AuditKeysDocument, ChainHead, CheckpointSigner,
    };
    use acf_identity::{generate_pem, parse_key_pair, public_key};
    use acf_protocol::KeyId;
    use time::OffsetDateTime;

    const LOG: &str = "log-0123456789abcdef0123456789abcdef";

    struct Fixture {
        dir: PathBuf,
        pem: String,
        signer: CheckpointSigner,
        keys: AuditKeys,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "acf-collector-{}-{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos()
            ));
            let pem = generate_pem().unwrap();
            let keys = AuditKeys::new(AuditKeysDocument {
                schema: AUDIT_KEYS_SCHEMA.to_owned(),
                keys: vec![AuditKeyEntry {
                    kid: KeyId::new("gw-audit").unwrap(),
                    gateway: "gw-1".to_owned(),
                    principal: PrincipalId::new("gateway:gw-1").unwrap(),
                    public_key: public_key(&parse_key_pair(&pem).unwrap()),
                }],
            })
            .unwrap();
            let signer = CheckpointSigner::new(
                KeyId::new("gw-audit").unwrap(),
                "gw-1".to_owned(),
                parse_key_pair(&pem).unwrap(),
            );
            Self {
                dir,
                pem,
                signer,
                keys,
            }
        }

        fn envelope(&self, seq: u64, hash: &str) -> CheckpointEnvelope {
            self.signer.sign(
                &ChainHead {
                    log: LOG.to_owned(),
                    seq,
                    hash: hash.to_owned(),
                },
                OffsetDateTime::now_utc(),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn gateway() -> PrincipalId {
        PrincipalId::new("gateway:gw-1").unwrap()
    }

    #[test]
    fn history_only_moves_forward() {
        let fixture = Fixture::new();
        let store = CheckpointStore::open(&fixture.dir, fixture.keys.clone()).unwrap();
        let first = fixture.envelope(3, "sha256:aa");
        assert_eq!(store.accept(&gateway(), &first).unwrap(), Accepted::Created);
        assert_eq!(
            store.accept(&gateway(), &first).unwrap(),
            Accepted::Duplicate
        );
        assert_eq!(
            store
                .accept(&gateway(), &fixture.envelope(7, "sha256:bb"))
                .unwrap(),
            Accepted::Created
        );
        for (seq, hash) in [(7, "sha256:cc"), (5, "sha256:dd"), (3, "sha256:aa")] {
            assert!(
                matches!(
                    store.accept(&gateway(), &fixture.envelope(seq, hash)),
                    Err(CollectorError::Conflict)
                ),
                "{seq}"
            );
        }
        assert_eq!(read_stored(&fixture.dir, LOG).unwrap().len(), 2);

        // A reopened store remembers where each log stands.
        let reopened = CheckpointStore::open(&fixture.dir, fixture.keys.clone()).unwrap();
        assert!(matches!(
            reopened.accept(&gateway(), &fixture.envelope(6, "sha256:ee")),
            Err(CollectorError::Conflict)
        ));
    }

    #[test]
    fn a_log_belongs_to_the_gateway_that_first_checkpointed_it() {
        let fixture = Fixture::new();
        let other_pem = generate_pem().unwrap();
        let keys = AuditKeys::new(AuditKeysDocument {
            schema: AUDIT_KEYS_SCHEMA.to_owned(),
            keys: vec![
                AuditKeyEntry {
                    kid: KeyId::new("gw-audit").unwrap(),
                    gateway: "gw-1".to_owned(),
                    principal: gateway(),
                    public_key: public_key(&parse_key_pair(&fixture.pem).unwrap()),
                },
                AuditKeyEntry {
                    kid: KeyId::new("gw2-audit").unwrap(),
                    gateway: "gw-2".to_owned(),
                    principal: PrincipalId::new("gateway:gw-2").unwrap(),
                    public_key: public_key(&parse_key_pair(&other_pem).unwrap()),
                },
            ],
        })
        .unwrap();
        let store = CheckpointStore::open(&fixture.dir, keys.clone()).unwrap();
        store
            .accept(&gateway(), &fixture.envelope(3, "sha256:aa"))
            .unwrap();
        let intruder = CheckpointSigner::new(
            KeyId::new("gw2-audit").unwrap(),
            "gw-2".to_owned(),
            parse_key_pair(&other_pem).unwrap(),
        );
        let wedge = intruder.sign(
            &ChainHead {
                log: LOG.to_owned(),
                seq: 1_000_000,
                hash: "sha256:ff".to_owned(),
            },
            OffsetDateTime::now_utc(),
        );
        let gw2 = PrincipalId::new("gateway:gw-2").unwrap();
        assert!(matches!(
            store.accept(&gw2, &wedge),
            Err(CollectorError::Forbidden)
        ));
        // Still enforced after a restart.
        let reopened = CheckpointStore::open(&fixture.dir, keys).unwrap();
        assert!(matches!(
            reopened.accept(&gw2, &wedge),
            Err(CollectorError::Forbidden)
        ));
        assert_eq!(
            reopened
                .accept(&gateway(), &fixture.envelope(4, "sha256:bb"))
                .unwrap(),
            Accepted::Created
        );
    }

    #[test]
    fn only_the_keys_principal_may_submit_valid_checkpoints() {
        let fixture = Fixture::new();
        let store = CheckpointStore::open(&fixture.dir, fixture.keys.clone()).unwrap();
        let envelope = fixture.envelope(1, "sha256:aa");
        assert!(matches!(
            store.accept(&PrincipalId::new("workload:vps-17").unwrap(), &envelope),
            Err(CollectorError::Forbidden)
        ));
        let tampered = CheckpointEnvelope {
            signature: fixture.envelope(2, "sha256:bb").signature,
            ..envelope
        };
        assert!(matches!(
            store.accept(&gateway(), &tampered),
            Err(CollectorError::Invalid(_))
        ));
        assert!(read_stored(&fixture.dir, LOG).unwrap().is_empty());
        assert!(read_stored(&fixture.dir, "../etc/passwd").is_err());
    }
}
