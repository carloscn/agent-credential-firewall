//! Mutation operation states (design §9.2).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ids::OperationId;

/// State of one journaled mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Validated and recorded; not yet waiting for approval or sent.
    Prepared,
    /// Waiting for a human approval decision.
    AwaitingApproval,
    /// A valid receipt exists; not yet sent downstream.
    Approved,
    /// The approver declined.
    Rejected,
    /// The approval or receipt expired before execution.
    Expired,
    /// Durably journaled as sent before the downstream call.
    Sent,
    /// The downstream service confirmed the change.
    Confirmed,
    /// The downstream service reported failure.
    Failed,
    /// The downstream outcome is ambiguous and needs reconciliation.
    Unknown,
}

impl OperationState {
    /// Returns whether `self → next` is a permitted transition.
    ///
    /// There is no transition out of `Unknown` except reconciliation to
    /// `Confirmed` or `Failed`; in particular, `Unknown → Sent` (an automatic
    /// retry) is never permitted.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        use OperationState::{
            Approved, AwaitingApproval, Confirmed, Expired, Failed, Prepared, Rejected, Sent,
            Unknown,
        };
        matches!(
            (self, next),
            (Prepared, AwaitingApproval | Sent)
                | (AwaitingApproval, Approved | Rejected | Expired)
                | (Approved, Sent | Expired)
                | (Sent | Unknown, Confirmed | Failed)
                | (Sent, Unknown)
        )
    }

    /// Returns whether no further transition is possible.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Rejected | Self::Expired | Self::Confirmed | Self::Failed
        )
    }
}

/// Current status of an operation, as returned to the daemon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationStatus {
    /// Operation identifier.
    pub operation_id: OperationId,
    /// Current state.
    pub state: OperationState,
    /// Time of the most recent state change.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::OperationState::{self, *};

    const ALL: [OperationState; 9] = [
        Prepared,
        AwaitingApproval,
        Approved,
        Rejected,
        Expired,
        Sent,
        Confirmed,
        Failed,
        Unknown,
    ];

    #[test]
    fn unknown_is_never_retried() {
        assert!(!Unknown.can_transition_to(Sent));
        assert!(Unknown.can_transition_to(Confirmed));
        assert!(Unknown.can_transition_to(Failed));
    }

    #[test]
    fn mutations_cannot_skip_approval_once_awaiting() {
        assert!(!AwaitingApproval.can_transition_to(Sent));
    }

    #[test]
    fn terminal_states_have_no_successors() {
        for from in ALL.into_iter().filter(|s| s.is_terminal()) {
            for to in ALL {
                assert!(!from.can_transition_to(to), "{from:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&AwaitingApproval).unwrap(),
            "\"awaiting_approval\""
        );
    }
}
