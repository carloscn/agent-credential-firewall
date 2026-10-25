//! Embedded durable state store on SQLite.
//!
//! WAL mode with `synchronous=FULL`: a recorded request identifier,
//! revocation, or charge is on disk before the call returns. Each operation
//! is one transaction, and charges use `BEGIN IMMEDIATE`, so concurrent
//! writers (other gateway workers or an admin process) serialize.

use std::path::Path;
use std::sync::{Arc, Mutex};

use acf_protocol::{PrincipalId, RequestId};
use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{
    Charge, Revocation, RevocationQuery, RevocationRecord, RevocationTarget, StateError, StateStore,
};

const SCHEMA_VERSION: i64 = 1;
/// Expired request identifiers are swept once every this many inserts.
const SWEEP_EVERY: u64 = 1024;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS requests (
    principal  TEXT    NOT NULL,
    request_id TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (principal, request_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS requests_expiry ON requests (expires_at);
CREATE TABLE IF NOT EXISTS revocations (
    sequence   INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT    NOT NULL,
    target     TEXT    NOT NULL,
    revoked_at INTEGER NOT NULL,
    expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS revocations_target ON revocations (kind, target);
CREATE TABLE IF NOT EXISTS counters (
    key          TEXT    NOT NULL,
    window_start INTEGER NOT NULL,
    count        INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    PRIMARY KEY (key, window_start)
) WITHOUT ROWID;
";

/// Durable single-node state store.
#[derive(Clone)]
pub struct SqliteStateStore {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteStateStore {
    /// Opens or creates the store at `path`.
    ///
    /// # Errors
    ///
    /// [`StateError::Unavailable`] if the file cannot be opened, the schema
    /// cannot be created, or it was created by an incompatible version.
    pub fn open(path: &Path) -> Result<Self, StateError> {
        let connection = Connection::open(path).map_err(|_| StateError::Unavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;",
            )
            .map_err(|_| StateError::Unavailable)?;
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|_| StateError::Unavailable)?;
        match version {
            0 => {
                connection
                    .execute_batch(SCHEMA)
                    .map_err(|_| StateError::Unavailable)?;
                connection
                    .execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))
                    .map_err(|_| StateError::Unavailable)?;
            }
            SCHEMA_VERSION => {}
            _ => return Err(StateError::Unavailable),
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Runs `operation` on a blocking thread with the connection locked.
    async fn with<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, StateError> + Send + 'static,
    ) -> Result<T, StateError> {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let mut guard = connection.lock().map_err(|_| StateError::Unavailable)?;
            operation(&mut guard)
        })
        .await
        .map_err(|_| StateError::Unavailable)?
    }
}

fn unavailable(_: rusqlite::Error) -> StateError {
    StateError::Unavailable
}

fn to_sequence(value: i64) -> Result<u64, StateError> {
    u64::try_from(value).map_err(|_| StateError::Unavailable)
}

#[async_trait]
impl StateStore for SqliteStateStore {
    fn replay_is_durable(&self) -> bool {
        true
    }

    async fn record_request(
        &self,
        principal: &PrincipalId,
        request: &RequestId,
        expires_at: i64,
        now: i64,
    ) -> Result<(), StateError> {
        let principal = principal.as_str().to_owned();
        let request = request.as_str().to_owned();
        self.with(move |connection| {
            let tx = connection.transaction().map_err(unavailable)?;
            // An expired entry no longer protects anything; replace it.
            tx.execute(
                "DELETE FROM requests WHERE principal = ?1 AND request_id = ?2 AND expires_at <= ?3",
                params![principal, request, now],
            )
            .map_err(unavailable)?;
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO requests (principal, request_id, expires_at) VALUES (?1, ?2, ?3)",
                    params![principal, request, expires_at],
                )
                .map_err(unavailable)?;
            if inserted == 0 {
                return Err(StateError::Replay);
            }
            sweep_expired_requests(&tx, now)?;
            tx.commit().map_err(unavailable)
        })
        .await
    }

    async fn revoke(&self, revocation: Revocation) -> Result<u64, StateError> {
        self.with(move |connection| {
            connection
                .execute(
                    "INSERT INTO revocations (kind, target, revoked_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        revocation.target.kind(),
                        revocation.target.value(),
                        revocation.revoked_at,
                        revocation.expires_at
                    ],
                )
                .map_err(unavailable)?;
            to_sequence(connection.last_insert_rowid())
        })
        .await
    }

    async fn is_revoked(&self, query: &RevocationQuery<'_>) -> Result<bool, StateError> {
        let candidates = [
            query
                .capability
                .map(|(jti, _)| ("capability", jti.as_str().to_owned())),
            Some(("task", query.task.as_str().to_owned())),
            Some(("principal", query.principal.as_str().to_owned())),
            query.device.map(|d| ("device", d.as_str().to_owned())),
        ];
        let candidates: Vec<(&'static str, String)> = candidates.into_iter().flatten().collect();
        let rows = self
            .with(move |connection| {
                let mut statement = connection
                    .prepare_cached(
                        "SELECT kind, target, revoked_at, expires_at FROM revocations WHERE kind = ?1 AND target = ?2",
                    )
                    .map_err(unavailable)?;
                let mut rows = Vec::new();
                for (kind, target) in candidates {
                    let found = statement
                        .query_map(params![kind, target], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get(2)?, row.get(3)?))
                        })
                        .map_err(unavailable)?;
                    for row in found {
                        rows.push(row.map_err(unavailable)?);
                    }
                }
                Ok(rows)
            })
            .await?;
        for (kind, target, revoked_at, expires_at) in rows {
            // A row we cannot parse is treated as an applicable revocation.
            let Some(target) = RevocationTarget::from_parts(&kind, &target) else {
                return Ok(true);
            };
            let revocation = Revocation {
                target,
                revoked_at,
                expires_at,
            };
            if revocation.applies_to(query) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn revocations_since(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<RevocationRecord>, StateError> {
        let after = i64::try_from(after).map_err(|_| StateError::Unavailable)?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with(move |connection| {
            let mut statement = connection
                .prepare_cached(
                    "SELECT sequence, kind, target, revoked_at, expires_at FROM revocations
                     WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
                )
                .map_err(unavailable)?;
            let rows = statement
                .query_map(params![after, limit], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })
                .map_err(unavailable)?;
            let mut records = Vec::new();
            for row in rows {
                let (sequence, kind, target, revoked_at, expires_at) = row.map_err(unavailable)?;
                let target =
                    RevocationTarget::from_parts(&kind, &target).ok_or(StateError::Unavailable)?;
                records.push(RevocationRecord {
                    sequence: to_sequence(sequence)?,
                    revocation: Revocation {
                        target,
                        revoked_at,
                        expires_at,
                    },
                });
            }
            Ok(records)
        })
        .await
    }

    async fn charge(&self, charges: &[Charge], now: i64) -> Result<(), StateError> {
        let charges = charges.to_vec();
        self.with(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(unavailable)?;
            tx.execute("DELETE FROM counters WHERE expires_at <= ?1", params![now])
                .map_err(unavailable)?;
            for charge in &charges {
                let (start, expiry) = charge.window.bounds(now);
                let key = charge.key.storage_key();
                let count: i64 = tx
                    .query_row(
                        "SELECT count FROM counters WHERE key = ?1 AND window_start = ?2",
                        params![key, start],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(unavailable)?
                    .unwrap_or(0);
                if count >= i64::from(charge.limit) {
                    // Dropping `tx` rolls back every increment made so far.
                    return Err(StateError::Exceeded(charge.key.kind()));
                }
                tx.execute(
                    "INSERT INTO counters (key, window_start, count, expires_at) VALUES (?1, ?2, 1, ?3)
                     ON CONFLICT (key, window_start) DO UPDATE SET count = count + 1",
                    params![key, start, expiry],
                )
                .map_err(unavailable)?;
            }
            tx.commit().map_err(unavailable)
        })
        .await
    }
}

/// Sweeps expired request identifiers occasionally.
fn sweep_expired_requests(tx: &rusqlite::Transaction<'_>, now: i64) -> Result<(), StateError> {
    // `random() % N == 0` amortizes the sweep without shared counters.
    let sweep: bool = tx
        .query_row(
            &format!("SELECT abs(random()) % {SWEEP_EVERY} = 0"),
            [],
            |row| row.get(0),
        )
        .map_err(unavailable)?;
    if sweep {
        tx.execute("DELETE FROM requests WHERE expires_at <= ?1", params![now])
            .map_err(unavailable)?;
    }
    Ok(())
}
