//! Request freshness, replay, revocation, quotas, and rate limits.
//!
//! Every check runs before the credential is retrieved, and a state store
//! failure denies the request.
//!
//! Freshness: a request's timestamp must lie within
//! `[now − freshness, now + clock_skew]`. Its identifier is then recorded for
//! `freshness + clock_skew` after the timestamp, which covers every moment the
//! same request could still pass the freshness check.
//!
//! Restart rule: a store whose replay cache does not survive a restart cannot
//! know which identifiers the previous process accepted. Those requests had
//! timestamps of at most the previous process's last moment plus the clock
//! skew, which is before `started_at + clock_skew`, so such requests are
//! refused.

use std::sync::Arc;

use acf_identity::IdentityContext;
use acf_policy::Permit;
use acf_protocol::{ActionRequest, CapabilityId, DenialReason};
use acf_state::{Charge, CounterKey, RevocationQuery, StateError, StateStore, Window};

/// Default request freshness window, in seconds.
pub const DEFAULT_FRESHNESS_SECS: i64 = 300;
/// Default allowed clock skew, in seconds.
pub const DEFAULT_CLOCK_SKEW_SECS: i64 = 30;
/// How long per-task counters live when the task has no capability expiry.
pub const DEFAULT_TASK_COUNTER_TTL_SECS: i64 = 86_400;

/// Per-minute rate limits. `None` means no limit for that dimension.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateLimits {
    /// Requests per principal per minute.
    pub per_principal_per_minute: Option<u32>,
    /// Requests per resource per minute.
    pub per_resource_per_minute: Option<u32>,
    /// Requests per action per minute.
    pub per_action_per_minute: Option<u32>,
}

/// State wiring.
pub struct StateSettings {
    /// Replay cache, revocations, and counters.
    pub store: Arc<dyn StateStore>,
    /// Oldest accepted request age, in seconds.
    pub freshness_secs: i64,
    /// Allowed clock skew, in seconds.
    pub clock_skew_secs: i64,
    /// When this process started, in seconds since the Unix epoch.
    pub started_at: i64,
    /// Rate limits.
    pub rate_limits: RateLimits,
}

impl StateSettings {
    /// Default windows and no rate limits.
    #[must_use]
    pub fn new(store: Arc<dyn StateStore>, started_at: i64) -> Self {
        Self {
            store,
            freshness_secs: DEFAULT_FRESHNESS_SECS,
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            started_at,
            rate_limits: RateLimits::default(),
        }
    }
}

/// A denial: the agent-facing reason and the audit code.
pub(crate) type Refusal = (DenialReason, String);

fn unavailable() -> Refusal {
    (DenialReason::Unavailable, "state_unavailable".to_owned())
}

/// Freshness, replay, and revocation checks for an authenticated caller.
pub(crate) async fn admit(
    settings: &StateSettings,
    identity: &IdentityContext,
    request: &ActionRequest,
    capability: Option<(&CapabilityId, i64)>,
    now: i64,
) -> Result<(), Refusal> {
    let timestamp = request.timestamp.unix_timestamp();
    let skew = settings.clock_skew_secs;
    if timestamp > now + skew || timestamp < now - settings.freshness_secs {
        return Err((DenialReason::Replay, "stale_request".to_owned()));
    }
    if !settings.store.replay_is_durable() && timestamp <= settings.started_at + skew {
        return Err((DenialReason::Replay, "request_predates_restart".to_owned()));
    }
    let retain_until = timestamp + settings.freshness_secs + skew;
    match settings
        .store
        .record_request(&identity.principal, &request.request_id, retain_until, now)
        .await
    {
        Ok(()) => {}
        Err(StateError::Replay) => {
            return Err((DenialReason::Replay, "replayed_request".to_owned()));
        }
        Err(_) => return Err(unavailable()),
    }
    let query = RevocationQuery {
        principal: &identity.principal,
        device: identity.device.as_ref(),
        task: &request.task_id,
        capability,
        now,
    };
    match settings.store.is_revoked(&query).await {
        Ok(false) => Ok(()),
        Ok(true) => Err((DenialReason::CapabilityRevoked, "revoked".to_owned())),
        Err(_) => Err(unavailable()),
    }
}

/// Charges quotas and rate limits for an allowed request, all or nothing.
pub(crate) async fn charge(
    settings: &StateSettings,
    identity: &IdentityContext,
    request: &ActionRequest,
    capability: Option<(&CapabilityId, i64)>,
    mutating: bool,
    permit: &Permit,
    now: i64,
) -> Result<(), Refusal> {
    let principal = &identity.principal;
    let task_window = Window::Until {
        expires_at: capability.map_or(now + DEFAULT_TASK_COUNTER_TTL_SECS, |(_, exp)| exp),
    };
    let minute = Window::Fixed { seconds: 60 };
    let mut charges = Vec::new();
    let mut push = |key, limit: Option<u32>, window| {
        if let Some(limit) = limit {
            charges.push(Charge { key, limit, window });
        }
    };
    push(
        CounterKey::TaskRequests(principal.clone(), request.task_id.clone()),
        permit.quotas.requests_per_task,
        task_window,
    );
    if mutating {
        push(
            CounterKey::TaskMutations(principal.clone(), request.task_id.clone()),
            permit.quotas.mutations_per_task,
            task_window,
        );
    }
    if let Some((jti, _)) = capability {
        push(
            CounterKey::CapabilityRequests(jti.clone()),
            permit.capability_limits.max_requests,
            task_window,
        );
        if mutating {
            push(
                CounterKey::CapabilityMutations(jti.clone()),
                permit.capability_limits.max_mutations,
                task_window,
            );
        }
    }
    let limits = settings.rate_limits;
    push(
        CounterKey::PrincipalRate(principal.clone()),
        limits.per_principal_per_minute,
        minute,
    );
    push(
        CounterKey::ResourceRate(request.resource.clone()),
        limits.per_resource_per_minute,
        minute,
    );
    push(
        CounterKey::ActionRate(request.action.clone()),
        limits.per_action_per_minute,
        minute,
    );
    if charges.is_empty() {
        return Ok(());
    }
    match settings.store.charge(&charges, now).await {
        Ok(()) => Ok(()),
        Err(StateError::Exceeded(kind)) => Err((
            DenialReason::QuotaExceeded,
            format!("quota_exceeded:{kind}"),
        )),
        Err(_) => Err(unavailable()),
    }
}
