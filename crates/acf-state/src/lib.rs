//! Security state: replay cache, revocation, quotas, and rate limits.
//!
//! [`StateStore`] is the interface the gateway uses; it is designed so a
//! shared, strongly consistent backend can replace the embedded ones for
//! high availability (M3). Two implementations ship here:
//!
//! - [`MemoryStateStore`]: per-process, for tests. Its replay cache does not
//!   survive a restart ([`StateStore::replay_is_durable`] is false).
//! - [`SqliteStateStore`]: embedded and durable (WAL, `synchronous=FULL`).
//!   Other local processes, such as an admin tool, can write revocations
//!   while the gateway runs; the gateway sees them on its next request.
//!
//! Timestamps are seconds since the Unix epoch.

mod memory;
mod sqlite;

use acf_protocol::{
    ActionName, CapabilityId, DeviceId, PrincipalId, RequestId, ResourceId, TaskId,
};
use async_trait::async_trait;

pub use memory::MemoryStateStore;
pub use sqlite::SqliteStateStore;

/// What a revocation applies to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RevocationTarget {
    /// One capability, by `jti`.
    Capability(CapabilityId),
    /// Every capability for one task issued before the revocation.
    Task(TaskId),
    /// Every capability for one principal issued before the revocation.
    Principal(PrincipalId),
    /// Every capability used from one device issued before the revocation.
    Device(DeviceId),
}

impl RevocationTarget {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Capability(_) => "capability",
            Self::Task(_) => "task",
            Self::Principal(_) => "principal",
            Self::Device(_) => "device",
        }
    }

    pub(crate) fn value(&self) -> &str {
        match self {
            Self::Capability(id) => id.as_str(),
            Self::Task(id) => id.as_str(),
            Self::Principal(id) => id.as_str(),
            Self::Device(id) => id.as_str(),
        }
    }

    pub(crate) fn from_parts(kind: &str, value: &str) -> Option<Self> {
        match kind {
            "capability" => CapabilityId::new(value).ok().map(Self::Capability),
            "task" => TaskId::new(value).ok().map(Self::Task),
            "principal" => PrincipalId::new(value).ok().map(Self::Principal),
            "device" => DeviceId::new(value).ok().map(Self::Device),
            _ => None,
        }
    }
}

/// A revocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revocation {
    /// What is revoked.
    pub target: RevocationTarget,
    /// When it took effect.
    pub revoked_at: i64,
    /// When it lapses; `None` means until removed.
    pub expires_at: Option<i64>,
}

/// A revocation with its position in the revocation feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationRecord {
    /// Monotonically increasing feed position.
    pub sequence: u64,
    /// The revocation.
    pub revocation: Revocation,
}

/// The request being checked against revocations.
#[derive(Clone, Copy, Debug)]
pub struct RevocationQuery<'a> {
    /// Authenticated principal.
    pub principal: &'a PrincipalId,
    /// Device, when known.
    pub device: Option<&'a DeviceId>,
    /// Task named in the request.
    pub task: &'a TaskId,
    /// Capability `jti` and `iat`, for capability-scoped tasks.
    pub capability: Option<(&'a CapabilityId, i64)>,
    /// Current time.
    pub now: i64,
}

impl Revocation {
    /// Whether this revocation denies `query`.
    ///
    /// Task, principal, and device revocations cover capabilities issued at
    /// or before the revocation, so a capability issued afterwards is
    /// unaffected. Requests without a capability are always covered while
    /// the revocation is active.
    #[must_use]
    pub fn applies_to(&self, query: &RevocationQuery<'_>) -> bool {
        let active =
            self.revoked_at <= query.now && self.expires_at.is_none_or(|end| query.now < end);
        if !active {
            return false;
        }
        let issued_before = query
            .capability
            .is_none_or(|(_, iat)| iat <= self.revoked_at);
        match &self.target {
            RevocationTarget::Capability(jti) => query.capability.is_some_and(|(id, _)| id == jti),
            RevocationTarget::Task(task) => task == query.task && issued_before,
            RevocationTarget::Principal(principal) => principal == query.principal && issued_before,
            RevocationTarget::Device(device) => query.device == Some(device) && issued_before,
        }
    }
}

/// A usage counter.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CounterKey {
    /// Requests by one principal under one task.
    TaskRequests(PrincipalId, TaskId),
    /// Mutations by one principal under one task.
    TaskMutations(PrincipalId, TaskId),
    /// Requests under one capability.
    CapabilityRequests(CapabilityId),
    /// Mutations under one capability.
    CapabilityMutations(CapabilityId),
    /// Requests by one principal (rate limit).
    PrincipalRate(PrincipalId),
    /// Requests to one resource (rate limit).
    ResourceRate(ResourceId),
    /// Requests for one action (rate limit).
    ActionRate(ActionName),
}

impl CounterKey {
    /// A stable code naming the counter kind, for audit reasons.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::TaskRequests(..) => "task_requests",
            Self::TaskMutations(..) => "task_mutations",
            Self::CapabilityRequests(_) => "capability_requests",
            Self::CapabilityMutations(_) => "capability_mutations",
            Self::PrincipalRate(_) => "principal_rate",
            Self::ResourceRate(_) => "resource_rate",
            Self::ActionRate(_) => "action_rate",
        }
    }

    pub(crate) fn storage_key(&self) -> String {
        // `|` never appears in an identifier, so composite keys cannot collide.
        let value = match self {
            Self::TaskRequests(principal, task) | Self::TaskMutations(principal, task) => {
                format!("{principal}|{task}")
            }
            Self::CapabilityRequests(id) | Self::CapabilityMutations(id) => id.to_string(),
            Self::PrincipalRate(id) => id.to_string(),
            Self::ResourceRate(id) => id.to_string(),
            Self::ActionRate(id) => id.to_string(),
        };
        format!("{}|{value}", self.kind())
    }
}

/// How long a counter accumulates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Window {
    /// One counter until `expires_at` (task and capability quotas).
    Until {
        /// When the counter and its limit lapse.
        expires_at: i64,
    },
    /// Fixed windows of `seconds`, aligned to the epoch (rate limits).
    Fixed {
        /// Window length.
        seconds: u32,
    },
}

impl Window {
    /// `(window_start, expires_at)` for `now`.
    pub(crate) fn bounds(self, now: i64) -> (i64, i64) {
        match self {
            Self::Until { expires_at } => (0, expires_at),
            Self::Fixed { seconds } => {
                let length = i64::from(seconds.max(1));
                let start = now - now.rem_euclid(length);
                (start, start + length)
            }
        }
    }
}

/// One counter to increment, with its limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Charge {
    /// Counter.
    pub key: CounterKey,
    /// Largest allowed count after this charge.
    pub limit: u32,
    /// Accumulation window.
    pub window: Window,
}

/// State failures.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    /// The request identifier was already recorded.
    #[error("request identifier already used")]
    Replay,
    /// A charge would exceed its limit; nothing was charged.
    #[error("limit exceeded for {0}")]
    Exceeded(&'static str),
    /// The store cannot answer; callers must fail closed.
    #[error("state store unavailable")]
    Unavailable,
}

/// Shared security state.
#[async_trait]
pub trait StateStore: Send + Sync {
    /// Whether recorded request identifiers survive a restart. When false,
    /// the gateway must refuse requests that could have been accepted before
    /// the restart.
    fn replay_is_durable(&self) -> bool;

    /// Records `request` for `principal`, retained until `expires_at`.
    ///
    /// # Errors
    ///
    /// [`StateError::Replay`] if it was already recorded and has not expired.
    async fn record_request(
        &self,
        principal: &PrincipalId,
        request: &RequestId,
        expires_at: i64,
        now: i64,
    ) -> Result<(), StateError>;

    /// Adds a revocation and returns its feed position.
    ///
    /// # Errors
    ///
    /// [`StateError::Unavailable`] if it was not stored.
    async fn revoke(&self, revocation: Revocation) -> Result<u64, StateError>;

    /// Whether any active revocation applies.
    ///
    /// # Errors
    ///
    /// [`StateError::Unavailable`]; callers must treat it as revoked.
    async fn is_revoked(&self, query: &RevocationQuery<'_>) -> Result<bool, StateError>;

    /// Revocations after feed position `after`, oldest first, at most `limit`.
    ///
    /// # Errors
    ///
    /// [`StateError::Unavailable`].
    async fn revocations_since(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<RevocationRecord>, StateError>;

    /// Increments every counter in `charges` atomically: all of them, or none
    /// if any would exceed its limit.
    ///
    /// # Errors
    ///
    /// [`StateError::Exceeded`] naming the first counter over its limit, or
    /// [`StateError::Unavailable`].
    async fn charge(&self, charges: &[Charge], now: i64) -> Result<(), StateError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query<'a>(
        principal: &'a PrincipalId,
        task: &'a TaskId,
        capability: Option<(&'a CapabilityId, i64)>,
    ) -> RevocationQuery<'a> {
        RevocationQuery {
            principal,
            device: None,
            task,
            capability,
            now: 1000,
        }
    }

    #[test]
    fn principal_revocation_covers_earlier_capabilities_only() {
        let alice = PrincipalId::new("alice").unwrap();
        let task = TaskId::new("t").unwrap();
        let jti = CapabilityId::new("cap").unwrap();
        let revocation = Revocation {
            target: RevocationTarget::Principal(alice.clone()),
            revoked_at: 900,
            expires_at: None,
        };
        assert!(revocation.applies_to(&query(&alice, &task, None)));
        assert!(revocation.applies_to(&query(&alice, &task, Some((&jti, 900)))));
        assert!(
            !revocation.applies_to(&query(&alice, &task, Some((&jti, 901)))),
            "issued after"
        );
        let bob = PrincipalId::new("bob").unwrap();
        assert!(!revocation.applies_to(&query(&bob, &task, None)));
    }

    #[test]
    fn revocations_have_an_active_window() {
        let alice = PrincipalId::new("alice").unwrap();
        let task = TaskId::new("t").unwrap();
        let pending = Revocation {
            target: RevocationTarget::Task(task.clone()),
            revoked_at: 1001,
            expires_at: None,
        };
        assert!(!pending.applies_to(&query(&alice, &task, None)));
        let lapsed = Revocation {
            revoked_at: 0,
            expires_at: Some(1000),
            ..pending
        };
        assert!(!lapsed.applies_to(&query(&alice, &task, None)));
    }

    #[test]
    fn capability_revocation_matches_the_jti_only() {
        let alice = PrincipalId::new("alice").unwrap();
        let task = TaskId::new("t").unwrap();
        let jti = CapabilityId::new("cap").unwrap();
        let revocation = Revocation {
            target: RevocationTarget::Capability(jti.clone()),
            revoked_at: 0,
            expires_at: None,
        };
        assert!(revocation.applies_to(&query(&alice, &task, Some((&jti, 5000)))));
        assert!(!revocation.applies_to(&query(&alice, &task, None)));
    }

    #[test]
    fn fixed_windows_align_to_the_epoch() {
        assert_eq!(Window::Fixed { seconds: 60 }.bounds(125), (120, 180));
        assert_eq!(Window::Until { expires_at: 9 }.bounds(5), (0, 9));
    }
}
