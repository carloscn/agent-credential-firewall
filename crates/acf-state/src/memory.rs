//! Per-process state store, for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use acf_protocol::{PrincipalId, RequestId};
use async_trait::async_trait;

use crate::{Charge, Revocation, RevocationQuery, RevocationRecord, StateError, StateStore};

/// Largest number of unexpired request identifiers kept. Past it the store
/// fails closed rather than evicting entries that could then be replayed.
const MAX_REQUESTS: usize = 1_000_000;

#[derive(Default)]
struct Inner {
    requests: HashMap<(PrincipalId, RequestId), i64>,
    revocations: Vec<RevocationRecord>,
    counters: HashMap<(String, i64), (u32, i64)>,
}

/// Keeps all state in process memory. Nothing survives a restart.
#[derive(Default)]
pub struct MemoryStateStore {
    inner: Mutex<Inner>,
}

impl MemoryStateStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl StateStore for MemoryStateStore {
    fn replay_is_durable(&self) -> bool {
        false
    }

    async fn record_request(
        &self,
        principal: &PrincipalId,
        request: &RequestId,
        expires_at: i64,
        now: i64,
    ) -> Result<(), StateError> {
        let mut inner = self.inner.lock().map_err(|_| StateError::Unavailable)?;
        let key = (principal.clone(), request.clone());
        if inner.requests.get(&key).is_some_and(|expiry| now < *expiry) {
            return Err(StateError::Replay);
        }
        if inner.requests.len() >= MAX_REQUESTS {
            inner.requests.retain(|_, expiry| now < *expiry);
            if inner.requests.len() >= MAX_REQUESTS {
                return Err(StateError::Unavailable);
            }
        }
        inner.requests.insert(key, expires_at);
        Ok(())
    }

    async fn revoke(&self, revocation: Revocation) -> Result<u64, StateError> {
        let mut inner = self.inner.lock().map_err(|_| StateError::Unavailable)?;
        let sequence = inner.revocations.last().map_or(1, |r| r.sequence + 1);
        inner.revocations.push(RevocationRecord {
            sequence,
            revocation,
        });
        Ok(sequence)
    }

    async fn is_revoked(&self, query: &RevocationQuery<'_>) -> Result<bool, StateError> {
        let inner = self.inner.lock().map_err(|_| StateError::Unavailable)?;
        Ok(inner
            .revocations
            .iter()
            .any(|r| r.revocation.applies_to(query)))
    }

    async fn revocations_since(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<RevocationRecord>, StateError> {
        let inner = self.inner.lock().map_err(|_| StateError::Unavailable)?;
        Ok(inner
            .revocations
            .iter()
            .filter(|r| r.sequence > after)
            .take(limit)
            .cloned()
            .collect())
    }

    async fn charge(&self, charges: &[Charge], now: i64) -> Result<(), StateError> {
        let mut inner = self.inner.lock().map_err(|_| StateError::Unavailable)?;
        inner.counters.retain(|_, (_, expiry)| now < *expiry);
        let keys: Vec<((String, i64), i64)> = charges
            .iter()
            .map(|c| {
                let (start, expiry) = c.window.bounds(now);
                ((c.key.storage_key(), start), expiry)
            })
            .collect();
        for (charge, (key, _)) in charges.iter().zip(&keys) {
            let count = inner.counters.get(key).map_or(0, |(count, _)| *count);
            if count >= charge.limit {
                return Err(StateError::Exceeded(charge.key.kind()));
            }
        }
        for (key, expiry) in keys {
            inner.counters.entry(key).or_insert((0, expiry)).0 += 1;
        }
        Ok(())
    }
}
