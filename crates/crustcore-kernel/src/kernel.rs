// SPDX-License-Identifier: Apache-2.0
//! The kernel state machine itself.

use crustcore_policy::PolicySnapshot;
use crustcore_types::EventSeq;

use crate::action::Action;
use crate::event::{Event, EventKind};

/// The CrustCore nanokernel.
///
/// Owns task/job/approval/budget state (added in Phase 1) and an immutable
/// policy snapshot, and turns each [`Event`] into a bounded list of [`Action`]s.
///
/// Properties of [`Kernel::step`]: synchronous, deterministic, allocation-light;
/// no async runtime, network, database, or tool execution.
#[derive(Debug)]
pub struct Kernel {
    next_seq: EventSeq,
    policy: PolicySnapshot,
    // TODO(P1.1): tasks: TaskArena, jobs: JobArena, approvals: ApprovalArena,
    // budgets: BudgetState, ready: VecDeque<JobId>.
}

impl Kernel {
    /// Creates a kernel with the given policy snapshot.
    #[must_use]
    pub fn new(policy: PolicySnapshot) -> Self {
        Kernel {
            next_seq: EventSeq::FIRST,
            policy,
        }
    }

    /// The policy this kernel evaluates against.
    #[must_use]
    pub fn policy(&self) -> &PolicySnapshot {
        &self.policy
    }

    /// The sequence number that will be assigned to the next appended event.
    #[must_use]
    pub fn next_seq(&self) -> EventSeq {
        self.next_seq
    }

    /// Advances the state machine by one event, returning a bounded list of
    /// actions for adapters to execute.
    ///
    /// TODO(P1.3): implement the full transition table and property tests for
    /// impossible transitions (`ROADMAP.md` Phase 1 acceptance). The scaffold
    /// records the event and emits a single `AppendEvent` so the contract shape
    /// is exercised end to end.
    pub fn step(&mut self, event: Event) -> Vec<Action> {
        self.next_seq = self.next_seq.next();

        let mut actions = Vec::new();
        actions.push(Action::AppendEvent {
            task_id: event.task_id,
        });

        match event.kind {
            EventKind::TaskCompleted | EventKind::TaskFailed | EventKind::TaskKilled => {
                if let Some(task_id) = event.task_id {
                    actions.push(Action::TaskFinished { task_id });
                }
            }
            EventKind::ApprovalRequested => {
                // Approval routing is wired in Phase 1; for now the event is
                // logged and the adapter layer surfaces it.
            }
            _ => {}
        }

        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_policy::RiskProfile;

    #[test]
    fn step_is_deterministic_and_appends() {
        let mut k = Kernel::new(PolicySnapshot::new(RiskProfile::Supervised));
        let before = k.next_seq();
        let actions = k.step(Event::internal(EventKind::TaskCreated));
        assert!(matches!(actions[0], Action::AppendEvent { .. }));
        assert_eq!(k.next_seq(), before.next());
    }
}
