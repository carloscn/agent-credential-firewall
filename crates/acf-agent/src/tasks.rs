//! Opaque task handles, bound to the caller's UID and optionally a PID.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use acf_protocol::{TaskHandle, TaskId, TaskState, TaskStatus};

/// Most open tasks one UID may hold.
pub const MAX_TASKS_PER_UID: usize = 256;

/// How long a handle stays valid.
pub const TASK_TTL: Duration = Duration::from_secs(12 * 60 * 60);

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

#[derive(Clone, Debug)]
struct Entry {
    task_id: TaskId,
    uid: u32,
    pid: Option<u32>,
    expires: Instant,
}

impl Entry {
    fn usable_by(&self, peer: Peer, now: Instant) -> bool {
        now < self.expires
            && self.uid == peer.uid
            && self.pid.is_none_or(|pid| peer.pid == Some(pid))
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
    /// Opens a task for `peer`, restricted to `pid` if given.
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
    ) -> Result<TaskStatus, TaskError> {
        let now = Instant::now();
        let handle = new_handle()?;
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, entry| now < entry.expires);
        if entries.values().filter(|e| e.uid == peer.uid).count() >= MAX_TASKS_PER_UID {
            return Err(TaskError::TooMany);
        }
        entries.insert(
            handle.clone(),
            Entry {
                task_id: task_id.clone(),
                uid: peer.uid,
                pid,
                expires: now + TASK_TTL,
            },
        );
        Ok(TaskStatus {
            task_handle: handle,
            task_id,
            state: TaskState::Active,
        })
    }

    /// The task behind `handle`, if `peer` may use it. Unknown, expired, and
    /// foreign handles are indistinguishable.
    #[must_use]
    pub fn get(&self, peer: Peer, handle: &TaskHandle) -> Option<TaskStatus> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries
            .get(handle)
            .filter(|entry| entry.usable_by(peer, Instant::now()))
            .map(|entry| TaskStatus {
                task_handle: handle.clone(),
                task_id: entry.task_id.clone(),
                state: TaskState::Active,
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
        let status = registry.create(ALICE, task(), None).unwrap();
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
        let status = registry.create(ALICE, task(), Some(4242)).unwrap();
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
            registry.create(ALICE, task(), None).unwrap();
        }
        assert_eq!(
            registry.create(ALICE, task(), None),
            Err(TaskError::TooMany)
        );
        let bob = Peer { uid: 1001, ..ALICE };
        assert!(registry.create(bob, task(), None).is_ok());
    }

    #[test]
    fn expired_handles_are_unknown() {
        let registry = TaskRegistry::default();
        let status = registry.create(ALICE, task(), None).unwrap();
        registry
            .entries
            .lock()
            .unwrap()
            .get_mut(&status.task_handle)
            .unwrap()
            .expires = Instant::now();
        assert_eq!(registry.get(ALICE, &status.task_handle), None);
    }
}
