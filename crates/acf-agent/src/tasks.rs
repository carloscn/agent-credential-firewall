//! Opaque task handles, bound to the caller's UID and optionally a PID.
//!
//! Each handle may hold the task's capability (ADR 0003). The capability
//! stays here: it is attached to gateway requests and never returned
//! through the local API.

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::sync::Mutex;

use acf_protocol::{Grant, Limits, TaskHandle, TaskId, TaskIssued, TaskState, TaskStatus};
use time::{Duration, OffsetDateTime};

/// Most open tasks one UID may hold.
pub const MAX_TASKS_PER_UID: usize = 256;

/// How long a handle stays valid; shorter when its capability expires first.
pub const TASK_TTL: Duration = Duration::hours(12);

/// Kernel-reported credentials of the process on the other end of the socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Peer {
    /// Effective UID.
    pub uid: u32,
    /// Effective GID.
    pub gid: u32,
    /// PID, where the platform reports one.
    pub pid: Option<u32>,
}

/// A capability token. Its `Debug` output is redacted.
#[derive(Clone)]
struct Capability(String);

impl fmt::Debug for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Capability(<redacted>)")
    }
}

#[derive(Clone, Debug)]
struct Entry {
    task_id: TaskId,
    uid: u32,
    pid: Option<u32>,
    expires: OffsetDateTime,
    capability: Option<Capability>,
    grants: Vec<Grant>,
    limits: Option<Limits>,
}

impl Entry {
    fn usable_by(&self, peer: Peer, now: OffsetDateTime) -> bool {
        now < self.expires
            && self.uid == peer.uid
            && self.pid.is_none_or(|pid| peer.pid == Some(pid))
    }

    fn status(&self, handle: &TaskHandle) -> TaskStatus {
        TaskStatus {
            task_handle: handle.clone(),
            task_id: self.task_id.clone(),
            state: TaskState::Active,
            expires_at: self.expires,
            grants: self.grants.clone(),
            limits: self.limits,
        }
    }
}

/// What the daemon needs to forward a request for a task.
#[derive(Clone, Debug)]
pub struct ResolvedTask {
    /// The task identifier.
    pub task_id: TaskId,
    capability: Option<Capability>,
}

impl ResolvedTask {
    /// The capability token, if the task is scoped.
    #[must_use]
    pub fn capability(&self) -> Option<&str> {
        self.capability.as_ref().map(|c| c.0.as_str())
    }
}

/// Why a task could not be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TaskError {
    /// The caller holds [`MAX_TASKS_PER_UID`] tasks already.
    #[error("too many open tasks")]
    TooMany,
    /// No random source for the handle.
    #[error("no secure random source available")]
    Random,
}

/// In-memory handle table. Handles do not survive a daemon restart.
#[derive(Debug, Default)]
pub struct TaskRegistry {
    entries: Mutex<HashMap<TaskHandle, Entry>>,
}

fn new_handle() -> Result<TaskHandle, TaskError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| TaskError::Random)?;
    let mut text = String::with_capacity(67);
    text.push_str("th-");
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    TaskHandle::new(text).map_err(|_| TaskError::Random)
}

impl TaskRegistry {
    /// Opens a task for `peer`, restricted to `pid` if given. `issued` is
    /// the authority's capability; `None` opens an unscoped development task.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError`] if the caller has too many tasks or randomness
    /// fails.
    pub fn create(
        &self,
        peer: Peer,
        task_id: TaskId,
        pid: Option<u32>,
        issued: Option<TaskIssued>,
    ) -> Result<TaskStatus, TaskError> {
        let now = OffsetDateTime::now_utc();
        let handle = new_handle()?;
        let mut entry = Entry {
            task_id,
            uid: peer.uid,
            pid,
            expires: now + TASK_TTL,
            capability: None,
            grants: Vec::new(),
            limits: None,
        };
        if let Some(issued) = issued {
            entry.expires = entry.expires.min(issued.expires_at);
            entry.capability = Some(Capability(issued.capability));
            entry.grants = issued.grants;
            entry.limits = Some(issued.limits);
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, entry| now < entry.expires);
        if entries.values().filter(|e| e.uid == peer.uid).count() >= MAX_TASKS_PER_UID {
            return Err(TaskError::TooMany);
        }
        let status = entry.status(&handle);
        entries.insert(handle, entry);
        Ok(status)
    }

    fn find<T>(&self, peer: Peer, handle: &TaskHandle, f: impl FnOnce(&Entry) -> T) -> Option<T> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries
            .get(handle)
            .filter(|entry| entry.usable_by(peer, OffsetDateTime::now_utc()))
            .map(f)
    }

    /// The task behind `handle`, if `peer` may use it. Unknown, expired, and
    /// foreign handles are indistinguishable.
    #[must_use]
    pub fn get(&self, peer: Peer, handle: &TaskHandle) -> Option<TaskStatus> {
        self.find(peer, handle, |entry| entry.status(handle))
    }

    /// Like [`Self::get`], but returns what forwarding needs, including the
    /// capability.
    #[must_use]
    pub fn resolve(&self, peer: Peer, handle: &TaskHandle) -> Option<ResolvedTask> {
        self.find(peer, handle, |entry| ResolvedTask {
            task_id: entry.task_id.clone(),
            capability: entry.capability.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: Peer = Peer {
        uid: 1000,
        gid: 1000,
        pid: Some(42),
    };

    fn task() -> TaskId {
        TaskId::new("t-1").unwrap()
    }

    #[test]
    fn handles_are_bound_to_the_uid() {
        let registry = TaskRegistry::default();
        let status = registry.create(ALICE, task(), None, None).unwrap();
        assert!(status.task_handle.as_str().starts_with("th-"));
        assert_eq!(status.task_handle.as_str().len(), 67);
        assert_eq!(
            registry.get(ALICE, &status.task_handle),
            Some(status.clone())
        );
        let other_pid = Peer {
            pid: Some(7),
            ..ALICE
        };
        assert!(registry.get(other_pid, &status.task_handle).is_some());
        let bob = Peer { uid: 1001, ..ALICE };
        assert_eq!(registry.get(bob, &status.task_handle), None);
    }

    #[test]
    fn pid_bound_handles_reject_other_processes() {
        let registry = TaskRegistry::default();
        let status = registry.create(ALICE, task(), Some(4242), None).unwrap();
        assert_eq!(registry.get(ALICE, &status.task_handle), None);
        let agent = Peer {
            pid: Some(4242),
            ..ALICE
        };
        assert!(registry.get(agent, &status.task_handle).is_some());
        let unknown_pid = Peer { pid: None, ..agent };
        assert_eq!(registry.get(unknown_pid, &status.task_handle), None);
    }

    #[test]
    fn open_tasks_are_capped_per_uid() {
        let registry = TaskRegistry::default();
        for _ in 0..MAX_TASKS_PER_UID {
            registry.create(ALICE, task(), None, None).unwrap();
        }
        assert_eq!(
            registry.create(ALICE, task(), None, None),
            Err(TaskError::TooMany)
        );
        let bob = Peer { uid: 1001, ..ALICE };
        assert!(registry.create(bob, task(), None, None).is_ok());
    }

    #[test]
    fn capabilities_stay_inside_the_registry() {
        let registry = TaskRegistry::default();
        let issued = TaskIssued {
            task_id: task(),
            capability: "eyJ.secret.token".to_owned(),
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
            grants: Vec::new(),
            limits: Limits::default(),
        };
        let status = registry.create(ALICE, task(), None, Some(issued)).unwrap();
        assert!(
            status.expires_at < OffsetDateTime::now_utc() + TASK_TTL,
            "capability expiry wins"
        );
        assert!(!serde_json::to_string(&status).unwrap().contains("eyJ"));
        assert!(!format!("{registry:?}").contains("eyJ"));
        let resolved = registry.resolve(ALICE, &status.task_handle).unwrap();
        assert_eq!(resolved.capability(), Some("eyJ.secret.token"));
        assert!(!format!("{resolved:?}").contains("eyJ"));
    }

    #[test]
    fn expired_handles_are_unknown() {
        let registry = TaskRegistry::default();
        let status = registry.create(ALICE, task(), None, None).unwrap();
        registry
            .entries
            .lock()
            .unwrap()
            .get_mut(&status.task_handle)
            .unwrap()
            .expires = OffsetDateTime::now_utc();
        assert_eq!(registry.get(ALICE, &status.task_handle), None);
    }
}
