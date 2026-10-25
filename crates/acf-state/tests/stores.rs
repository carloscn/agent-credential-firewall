//! Behavior shared by every state store, plus SQLite durability.

// Fixture helpers outside `#[test]` functions build known-valid test values.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use acf_protocol::{CapabilityId, PrincipalId, RequestId, ResourceId, TaskId};
use acf_state::{
    Charge, CounterKey, MemoryStateStore, Revocation, RevocationQuery, RevocationTarget,
    SqliteStateStore, StateError, StateStore, Window,
};

fn temp_db() -> PathBuf {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).unwrap();
    let name = bytes.iter().fold(String::from("acf-state-"), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    std::env::temp_dir().join(format!("{name}.sqlite"))
}

fn principal(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

fn request(id: &str) -> RequestId {
    RequestId::new(id).unwrap()
}

fn stores() -> Vec<(&'static str, Arc<dyn StateStore>)> {
    vec![
        ("memory", Arc::new(MemoryStateStore::new())),
        (
            "sqlite",
            Arc::new(SqliteStateStore::open(&temp_db()).unwrap()),
        ),
    ]
}

#[tokio::test]
async fn request_ids_are_single_use_until_they_expire() {
    for (name, store) in stores() {
        let alice = principal("alice");
        store
            .record_request(&alice, &request("r1"), 100, 10)
            .await
            .unwrap();
        assert_eq!(
            store.record_request(&alice, &request("r1"), 100, 20).await,
            Err(StateError::Replay),
            "{name}"
        );
        // Scoped by principal: another caller cannot burn alice's identifiers.
        store
            .record_request(&principal("bob"), &request("r1"), 100, 20)
            .await
            .unwrap();
        // After expiry the entry protects nothing and may be reused.
        store
            .record_request(&alice, &request("r1"), 300, 100)
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_duplicates_admit_exactly_one() {
    for (name, store) in stores() {
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let store = Arc::clone(&store);
            tasks.push(tokio::spawn(async move {
                store
                    .record_request(&principal("alice"), &request("dup"), 100, 10)
                    .await
            }));
        }
        let mut admitted = 0;
        for task in tasks {
            if task.await.unwrap().is_ok() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 1, "{name}");
    }
}

#[tokio::test]
async fn charges_are_all_or_nothing() {
    for (name, store) in stores() {
        let task = TaskId::new("t").unwrap();
        let resource = ResourceId::new("r").unwrap();
        let a = Charge {
            key: CounterKey::TaskRequests(principal("alice"), task.clone()),
            limit: 5,
            window: Window::Until { expires_at: 1000 },
        };
        let b = Charge {
            key: CounterKey::ResourceRate(resource),
            limit: 1,
            window: Window::Fixed { seconds: 60 },
        };

        store.charge(&[a.clone(), b.clone()], 10).await.unwrap();
        assert_eq!(
            store.charge(&[a.clone(), b.clone()], 11).await,
            Err(StateError::Exceeded("resource_rate")),
            "{name}"
        );

        // The failed charge did not increment `a`: it is still at 1 of 2.
        let a2 = Charge {
            limit: 2,
            ..a.clone()
        };
        store.charge(std::slice::from_ref(&a2), 12).await.unwrap();
        assert_eq!(
            store.charge(&[a2], 13).await,
            Err(StateError::Exceeded("task_requests")),
            "{name}"
        );

        // The rate window resets in the next minute.
        store.charge(&[b], 61).await.unwrap();
    }
}

#[tokio::test]
async fn revocations_apply_and_feed_in_order() {
    for (name, store) in stores() {
        let alice = principal("alice");
        let task = TaskId::new("t").unwrap();
        let jti = CapabilityId::new("cap-1").unwrap();
        let query = RevocationQuery {
            principal: &alice,
            device: None,
            task: &task,
            capability: Some((&jti, 50)),
            now: 100,
        };
        assert!(!store.is_revoked(&query).await.unwrap(), "{name}");

        let first = store
            .revoke(Revocation {
                target: RevocationTarget::Capability(CapabilityId::new("other").unwrap()),
                revoked_at: 90,
                expires_at: None,
            })
            .await
            .unwrap();
        assert!(
            !store.is_revoked(&query).await.unwrap(),
            "{name}: other capability"
        );
        let second = store
            .revoke(Revocation {
                target: RevocationTarget::Principal(alice.clone()),
                revoked_at: 90,
                expires_at: Some(200),
            })
            .await
            .unwrap();
        assert!(second > first);
        assert!(
            store.is_revoked(&query).await.unwrap(),
            "{name}: principal revoked"
        );
        assert!(
            !store
                .is_revoked(&RevocationQuery { now: 200, ..query })
                .await
                .unwrap(),
            "{name}: lapsed"
        );

        let feed = store.revocations_since(0, 10).await.unwrap();
        assert_eq!(
            feed.iter().map(|r| r.sequence).collect::<Vec<_>>(),
            [first, second],
            "{name}"
        );
        assert_eq!(
            store.revocations_since(first, 10).await.unwrap().len(),
            1,
            "{name}"
        );
    }
}

#[tokio::test]
async fn sqlite_state_survives_reopening() {
    let path = temp_db();
    let alice = principal("alice");
    let task = TaskId::new("t").unwrap();
    {
        let store = SqliteStateStore::open(&path).unwrap();
        assert!(store.replay_is_durable());
        store
            .record_request(&alice, &request("r1"), 1000, 10)
            .await
            .unwrap();
        store
            .revoke(Revocation {
                target: RevocationTarget::Task(task.clone()),
                revoked_at: 0,
                expires_at: None,
            })
            .await
            .unwrap();
        let charge = Charge {
            key: CounterKey::TaskRequests(principal("alice"), task.clone()),
            limit: 1,
            window: Window::Until { expires_at: 1000 },
        };
        store.charge(&[charge], 10).await.unwrap();
    }
    let store = SqliteStateStore::open(&path).unwrap();
    assert_eq!(
        store.record_request(&alice, &request("r1"), 1000, 20).await,
        Err(StateError::Replay)
    );
    let query = RevocationQuery {
        principal: &alice,
        device: None,
        task: &task,
        capability: None,
        now: 20,
    };
    assert!(store.is_revoked(&query).await.unwrap());
    let charge = Charge {
        key: CounterKey::TaskRequests(principal("alice"), task),
        limit: 1,
        window: Window::Until { expires_at: 1000 },
    };
    assert_eq!(
        store.charge(&[charge], 20).await,
        Err(StateError::Exceeded("task_requests"))
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn another_process_revocation_is_seen_on_the_next_check() {
    // Two independent handles stand in for the gateway and an admin process.
    let path = temp_db();
    let gateway = SqliteStateStore::open(&path).unwrap();
    let admin = SqliteStateStore::open(&path).unwrap();
    let alice = principal("alice");
    let task = TaskId::new("t").unwrap();
    let query = RevocationQuery {
        principal: &alice,
        device: None,
        task: &task,
        capability: None,
        now: 10,
    };
    assert!(!gateway.is_revoked(&query).await.unwrap());
    admin
        .revoke(Revocation {
            target: RevocationTarget::Principal(alice.clone()),
            revoked_at: 5,
            expires_at: None,
        })
        .await
        .unwrap();
    assert!(gateway.is_revoked(&query).await.unwrap());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn memory_replay_is_not_durable() {
    assert!(!MemoryStateStore::new().replay_is_durable());
}
