// SPDX-License-Identifier: Apache-2.0
//! The kernel state machine itself.

use crustcore_policy::{PolicyDecision, PolicySnapshot};
use crustcore_types::{
    ApprovalId, ApprovalResolution, ApprovalStatus, Budget, BudgetCheck, EventSeq, JobId,
    JobStatus, Reversibility, TaskId, TaskStatus, Timestamp,
};

use crate::action::Action;
use crate::event::{Actor, Event, EventKind};
use crate::state::{
    job_next, task_next, ApprovalEntry, ApprovalOp, BlockReason, JobEntry, JobTransition,
    TaskEntry, TaskTransition, READY_DRAIN_MAX,
};
use crate::ActionVec;
use std::collections::VecDeque;

const APPROVAL_TTL_MS: u64 = 300_000;

#[derive(Debug)]
pub struct Kernel {
    next_seq: EventSeq,
    applied_through: EventSeq,
    policy: PolicySnapshot,
    next_approval: u128,
    tasks: Vec<TaskEntry>,
    jobs: Vec<JobEntry>,
    approvals: Vec<ApprovalEntry>,
    ready: VecDeque<JobId>,
}

impl Kernel {
    #[must_use]
    pub fn new(policy: PolicySnapshot) -> Self {
        Kernel {
            next_seq: EventSeq::FIRST,
            applied_through: EventSeq::FIRST,
            policy,
            next_approval: 1,
            tasks: Vec::new(),
            jobs: Vec::new(),
            approvals: Vec::new(),
            ready: VecDeque::new(),
        }
    }

    #[must_use]
    pub fn policy(&self) -> &PolicySnapshot {
        &self.policy
    }

    #[must_use]
    pub fn next_seq(&self) -> EventSeq {
        self.next_seq
    }

    #[must_use]
    pub fn task_status(&self, id: TaskId) -> Option<TaskStatus> {
        self.task(id).map(|t| t.status)
    }

    #[must_use]
    pub fn block_reason(&self, id: TaskId) -> Option<BlockReason> {
        self.task(id).and_then(|t| t.block_reason)
    }

    #[must_use]
    pub fn task_awaiting(&self, id: TaskId) -> Option<ApprovalId> {
        self.task(id).and_then(|t| t.awaiting)
    }

    #[must_use]
    pub fn budget(&self, id: TaskId) -> Option<Budget> {
        self.task(id).map(|t| t.budget)
    }

    #[must_use]
    pub fn job_status(&self, id: JobId) -> Option<JobStatus> {
        self.job(id).map(|j| j.status)
    }

    #[must_use]
    pub fn approval_status(&self, id: ApprovalId) -> Option<ApprovalStatus> {
        self.approval(id).map(|a| a.status)
    }

    pub fn step(&mut self, event: Event) -> ActionVec {
        let mut actions = ActionVec::new();

        if event.seq != EventSeq::FIRST && event.seq <= self.applied_through {
            return actions;
        }

        actions.push(Action::AppendEvent {
            task_id: event.task_id,
        });

        self.process(&event, &mut actions);

        self.next_seq = self.next_seq.next_saturating();
        if event.seq != EventSeq::FIRST && event.seq > self.applied_through {
            self.applied_through = event.seq;
        }
        actions
    }

    fn process(&mut self, event: &Event, actions: &mut ActionVec) {
        if event.kind == EventKind::TaskCreated {
            if let Some(tid) = event.task_id {
                if self.task_index(tid).is_none() {
                    let budget = event.budget.unwrap_or_else(Budget::unlimited);
                    self.tasks.push(TaskEntry::new(tid, budget, event.seq));
                }
            }
            return;
        }

        let Some(tid) = event.task_id else {
            return;
        };
        let Some(idx) = self.task_index(tid) else {
            return;
        };

        if self.tasks[idx].status.is_terminal() {
            self.tasks[idx].last_event = event.seq;
            return;
        }

        // Approval-expiry sweep: an `AwaitingApproval` task whose pending approval
        // has passed its deadline pauses to `Blocked` (resumable) on the next
        // event from ANY source. This makes the TTL meaningful without a wall
        // clock and without depending on a well-formed user resolution — an
        // absent or lost approval can never wedge a task forever (liveness;
        // invariant 14 deadline). A valid, in-time resolution arrives with
        // `timestamp <= expires_at`, so this never pre-empts it.
        if self.tasks[idx].status == TaskStatus::AwaitingApproval {
            if let Some(aid) = self.tasks[idx].awaiting {
                if let Some(aidx) = self.approval_index(aid) {
                    if event.timestamp > self.approvals[aidx].expires_at {
                        self.approvals[aidx].status = ApprovalStatus::Expired;
                        self.set_blocked(idx, BlockReason::ApprovalExpired);
                        self.tasks[idx].last_event = event.seq;
                        return;
                    }
                }
            }
        }

        if let Some(delta) = event.budget_delta {
            if let BudgetCheck::Exhausted(axis) = self.tasks[idx].budget.record(&delta) {
                self.set_blocked(idx, BlockReason::BudgetExhausted(axis));
                self.tasks[idx].last_event = event.seq;
                return;
            }
        }

        self.apply_job(event);

        // Source-state gate: a side-effecting request is classified only from a
        // status where that effect is legitimate. A paused (`Blocked`/
        // `AwaitingApproval`), denied, not-yet-started, or terminal task absorbs
        // the request to audit-only — this is what makes the budget pause and the
        // approval/denial states truly *absorbing* (invariants 8, 11, 14). Tool
        // calls belong to the work phase (`Running`); GitHub operations also run
        // during integration (`Integrating`, ROADMAP.md §12.7–§12.8).
        let status = self.tasks[idx].status;
        match event.kind {
            EventKind::ApprovalResolved => self.resolve_approval(event, idx, actions),
            EventKind::ToolCallRequested => {
                if status == TaskStatus::Running {
                    self.classify_request(event, idx, actions);
                }
            }
            EventKind::GitHubOperationRequested => {
                if matches!(status, TaskStatus::Running | TaskStatus::Integrating) {
                    self.classify_request(event, idx, actions);
                }
            }
            _ => {
                if let TaskTransition::Move(to) = task_next(status, event.kind) {
                    self.set_task_status(idx, to);
                }
            }
        }

        if self.tasks[idx].status.is_terminal() {
            actions.push(Action::TaskFinished { task_id: tid });
        }

        self.tasks[idx].last_event = event.seq;
        self.drain_ready(actions);
    }

    fn classify_request(&mut self, event: &Event, idx: usize, actions: &mut ActionVec) {
        // Reached only from a `Running` task (source-state gate in `process`). A
        // request with no reversibility is fail-safe: treated as irreversible so
        // it can never be auto-allowed.
        let reversibility = event.reversibility.unwrap_or(Reversibility::Irreversible);
        match self.policy.classify(reversibility) {
            PolicyDecision::Allow => {
                // Emit only for a real, runnable job belonging to this task — never
                // for an unknown, foreign, or terminal job (invariants 8, 12; no
                // effect on hostile/contradictory input).
                if let Some(job_id) = event.job_id {
                    if self.is_runnable_job(job_id, self.tasks[idx].id) {
                        actions.push(Action::RunTool { job_id });
                    }
                }
            }
            PolicyDecision::RequireApproval { .. } => {
                // At most one pending approval per task: a second request while
                // already awaiting is ignored, so no orphaned approval can later
                // release an effect (invariant 14).
                if self.tasks[idx].awaiting.is_some() {
                    return;
                }
                // An approval must bind to a concrete operation id. An untagged
                // side-effecting request cannot be safely approved, so it is
                // blocked rather than minting a `None`-bound (unbindable, and thus
                // forgeable) approval (invariant 14; defeats wrong-operation
                // replay even on the fail-safe path).
                let Some(tool_call_id) = event.tool_call_id else {
                    self.set_blocked(idx, BlockReason::RiskDetected);
                    return;
                };
                let approval_id = self.mint_approval();
                let task = self.tasks[idx].id;
                let expires_at = Timestamp::from_millis(
                    event.timestamp.as_millis().saturating_add(APPROVAL_TTL_MS),
                );
                self.approvals.push(ApprovalEntry {
                    id: approval_id,
                    task,
                    job: event.job_id,
                    status: ApprovalStatus::Pending,
                    op: ApprovalOp {
                        tool_call_id: Some(tool_call_id),
                    },
                    expires_at,
                });
                self.tasks[idx].awaiting = Some(approval_id);
                self.tasks[idx].status = TaskStatus::AwaitingApproval;
                actions.push(Action::RequestApproval { approval_id });
            }
            PolicyDecision::Deny { .. } => {
                self.set_blocked(idx, BlockReason::PolicyDenied);
            }
        }
    }

    fn resolve_approval(&mut self, event: &Event, idx: usize, actions: &mut ActionVec) {
        // Guard 1 (invariant 4): only an authorized *user* can resolve. A
        // model/subagent/worker/adapter resolution is inert.
        if event.actor != Actor::User {
            return;
        }
        let Some(approval_id) = event.approval_id else {
            return;
        };
        // Guard 1b: only the task's *current* pending approval is resolvable, so a
        // stale/orphaned approval can never release an effect (invariant 14).
        if self.tasks[idx].awaiting != Some(approval_id) {
            return;
        }
        let Some(aidx) = self.approval_index(approval_id) else {
            return;
        };
        if self.approvals[aidx].status != ApprovalStatus::Pending {
            return;
        }
        // Guard 2 (operation binding, invariant 14): the resolution must name the
        // exact bound operation. A mismatched/unbound tool call cannot retarget it.
        if !self.approvals[aidx].op.matches(event.tool_call_id) {
            return;
        }
        // Guard 3 (expiry at use time, docs/policy.md §4.1). An expired approval
        // pauses the task (resumable via user steer) instead of stranding it in
        // `AwaitingApproval`.
        if event.timestamp > self.approvals[aidx].expires_at {
            self.approvals[aidx].status = ApprovalStatus::Expired;
            self.set_blocked(idx, BlockReason::ApprovalExpired);
            return;
        }

        match event.resolution {
            Some(ApprovalResolution::Approve) => {
                self.approvals[aidx].status = ApprovalStatus::Approved;
                let job = self.approvals[aidx].job;
                let task = self.tasks[idx].id;
                self.tasks[idx].status = TaskStatus::Running;
                self.tasks[idx].block_reason = None;
                self.tasks[idx].awaiting = None;
                // Release the withheld effect only for a runnable job.
                if let Some(job_id) = job {
                    if self.is_runnable_job(job_id, task) {
                        actions.push(Action::RunTool { job_id });
                    }
                }
            }
            Some(ApprovalResolution::Deny) => {
                self.approvals[aidx].status = ApprovalStatus::Denied;
                self.set_blocked(idx, BlockReason::ApprovalDenied);
            }
            None => {}
        }
    }

    /// Whether `job_id` is a real, non-terminal, runnable job belonging to
    /// `task_id`. The effect-emitting paths require this before emitting `RunTool`
    /// so a request can never run an unknown, foreign, or terminal job.
    fn is_runnable_job(&self, job_id: JobId, task_id: TaskId) -> bool {
        self.jobs.iter().any(|j| {
            j.id == job_id
                && j.task == task_id
                && matches!(j.status, JobStatus::Leased | JobStatus::Running)
        })
    }

    fn apply_job(&mut self, event: &Event) {
        if event.kind == EventKind::JobQueued {
            if let (Some(jid), Some(tid)) = (event.job_id, event.task_id) {
                match self.job_index(jid) {
                    None => self.jobs.push(JobEntry::new(jid, tid, event.seq)),
                    Some(jidx) => {
                        if self.jobs[jidx].status == JobStatus::Retrying {
                            self.jobs[jidx].status = JobStatus::Queued;
                        }
                    }
                }
            }
            return;
        }

        if matches!(event.kind, EventKind::TaskKilled | EventKind::TaskFailed) {
            let to = if event.kind == EventKind::TaskKilled {
                JobStatus::Killed
            } else {
                JobStatus::Failed
            };
            if let Some(tid) = event.task_id {
                for job in self
                    .jobs
                    .iter_mut()
                    .filter(|j| j.task == tid && !j.status.is_terminal())
                {
                    job.status = to;
                }
            }
            return;
        }

        let Some(jid) = event.job_id else {
            return;
        };
        let Some(jidx) = self.job_index(jid) else {
            return;
        };
        if self.jobs[jidx].status.is_terminal() {
            return;
        }

        let active = matches!(
            self.jobs[jidx].status,
            JobStatus::Leased | JobStatus::Running | JobStatus::HeartbeatMissing
        );
        if active {
            if let (Some(owner), Some(ev_owner)) = (self.jobs[jidx].lease.owner, event.lease_owner)
            {
                if owner != ev_owner {
                    return;
                }
            }
            if self.jobs[jidx].lease.is_expired_at(event.timestamp) {
                self.jobs[jidx].status = JobStatus::Expired;
                return;
            }
        }

        if let JobTransition::Move(to) = job_next(self.jobs[jidx].status, event.kind) {
            self.jobs[jidx].status = to;
        }

        let is_activity = matches!(
            event.kind,
            EventKind::ModelRequestStarted
                | EventKind::ToolCallStarted
                | EventKind::CommandStarted
                | EventKind::SandboxStarted
                | EventKind::CommandOutputCaptured
                | EventKind::CommandCompleted
                | EventKind::ToolCallCompleted
        );
        if event.kind == EventKind::JobLeased {
            self.jobs[jidx]
                .lease
                .refresh(event.lease_owner, event.timestamp);
            self.ready.push_back(jid);
        } else if is_activity && self.jobs[jidx].lease.owner.is_some() {
            let owner = self.jobs[jidx].lease.owner;
            self.jobs[jidx].lease.refresh(owner, event.timestamp);
        }

        self.jobs[jidx].last_event = event.seq;
    }

    fn drain_ready(&mut self, actions: &mut ActionVec) {
        for _ in 0..READY_DRAIN_MAX {
            let Some(jid) = self.ready.pop_front() else {
                break;
            };
            if let Some(jidx) = self.job_index(jid) {
                let job_status = self.jobs[jidx].status;
                // A model request is a side effect (it consumes the token / model-
                // cost / wall budget axes), so it must obey the same source-state
                // gate as a tool call: emit only for a runnable job whose task is
                // `Running`. A paused (budget-`Blocked` / `AwaitingApproval`) task
                // does not drive the model (invariants 8, 11).
                let task_running =
                    self.task_status(self.jobs[jidx].task) == Some(TaskStatus::Running);
                if task_running && matches!(job_status, JobStatus::Leased | JobStatus::Running) {
                    actions.push(Action::RequestModel { job_id: jid });
                }
            }
        }
    }

    fn set_blocked(&mut self, idx: usize, reason: BlockReason) {
        self.tasks[idx].status = TaskStatus::Blocked;
        self.tasks[idx].block_reason = Some(reason);
        // Blocking supersedes any pending approval: with `awaiting` cleared, an
        // orphaned approval can never be resolved into an effect (so e.g. a
        // `RiskDetected` on an `AwaitingApproval` task cannot be overridden by a
        // late user approve — invariant 14).
        self.tasks[idx].awaiting = None;
    }

    /// Applies a pure-table status transition, keeping the invariant that only
    /// `Blocked` carries a `block_reason` and only `AwaitingApproval` carries an
    /// `awaiting` approval (the kernel sets `AwaitingApproval` directly in
    /// `classify_request`, never through this path).
    fn set_task_status(&mut self, idx: usize, to: TaskStatus) {
        if to == TaskStatus::Blocked {
            self.set_blocked(idx, BlockReason::RiskDetected);
            return;
        }
        self.tasks[idx].status = to;
        self.tasks[idx].block_reason = None;
        self.tasks[idx].awaiting = None;
    }

    fn mint_approval(&mut self) -> ApprovalId {
        let id = ApprovalId(self.next_approval);
        self.next_approval = self.next_approval.saturating_add(1);
        id
    }

    fn task(&self, id: TaskId) -> Option<&TaskEntry> {
        self.tasks.iter().find(|t| t.id == id)
    }

    fn task_index(&self, id: TaskId) -> Option<usize> {
        self.tasks.iter().position(|t| t.id == id)
    }

    fn job(&self, id: JobId) -> Option<&JobEntry> {
        self.jobs.iter().find(|j| j.id == id)
    }

    fn job_index(&self, id: JobId) -> Option<usize> {
        self.jobs.iter().position(|j| j.id == id)
    }

    fn approval(&self, id: ApprovalId) -> Option<&ApprovalEntry> {
        self.approvals.iter().find(|a| a.id == id)
    }

    fn approval_index(&self, id: ApprovalId) -> Option<usize> {
        self.approvals.iter().position(|a| a.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_policy::RiskProfile;
    use crustcore_types::{BudgetAxis, BudgetDelta, LeaseOwner, ToolCallId};

    fn kernel() -> Kernel {
        Kernel::new(PolicySnapshot::new(RiskProfile::Supervised))
    }

    fn running_task(seed_budget: Option<Budget>) -> (Kernel, TaskId, u64) {
        let mut k = kernel();
        let tid = TaskId(1);
        let mut seq = 1u64;
        let mut created =
            Event::inbound(EventKind::TaskCreated, EventSeq(seq), Actor::Adapter).with_task(tid);
        if let Some(b) = seed_budget {
            created = created.with_budget(b);
        }
        k.step(created);
        seq += 1;
        let jid = JobId(1);
        k.step(
            Event::inbound(EventKind::JobQueued, EventSeq(seq), Actor::Adapter)
                .with_task(tid)
                .with_job(jid),
        );
        seq += 1;
        k.step(
            Event::inbound(EventKind::JobLeased, EventSeq(seq), Actor::Adapter)
                .with_task(tid)
                .with_job(jid)
                .with_lease_owner(LeaseOwner(1)),
        );
        seq += 1;
        assert_eq!(k.task_status(tid), Some(TaskStatus::Running));
        (k, tid, seq)
    }

    fn has_effect(actions: &[Action]) -> bool {
        actions.iter().any(|a| {
            matches!(
                a,
                Action::RunTool { .. }
                    | Action::RequestModel { .. }
                    | Action::RequestApproval { .. }
            )
        })
    }

    /// Drives a `Running` task to `AwaitingApproval` via an irreversible request,
    /// returning the pending approval id and the next sequence number.
    fn request_irreversible(
        k: &mut Kernel,
        tid: TaskId,
        jid: JobId,
        seq: u64,
    ) -> (ApprovalId, u64) {
        k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
                .with_task(tid)
                .with_job(jid)
                .with_tool_call(ToolCallId(1))
                .with_reversibility(Reversibility::Irreversible),
        );
        let approval = k.task_awaiting(tid).expect("approval pending");
        assert_eq!(k.task_status(tid), Some(TaskStatus::AwaitingApproval));
        (approval, seq + 1)
    }

    #[test]
    fn step_is_deterministic_and_appends() {
        let mut k = kernel();
        let before = k.next_seq();
        let actions = k.step(Event::internal(EventKind::TaskCreated));
        assert!(matches!(actions[0], Action::AppendEvent { .. }));
        assert_eq!(k.next_seq(), before.next());
    }

    // AC2: a terminal task absorbs every event and emits no tool actions.
    #[test]
    fn terminal_tasks_emit_no_tool_actions() {
        for terminal_kind in [
            EventKind::TaskCompleted,
            EventKind::TaskFailed,
            EventKind::TaskKilled,
        ] {
            for kind in EventKind::ALL {
                let (mut k, tid, mut seq) = running_task(None);
                k.step(Event::inbound(terminal_kind, EventSeq(seq), Actor::Adapter).with_task(tid));
                seq += 1;
                assert!(k.task_status(tid).unwrap().is_terminal());
                let actions = k.step(
                    Event::inbound(kind, EventSeq(seq), Actor::Adapter)
                        .with_task(tid)
                        .with_job(JobId(1))
                        .with_reversibility(Reversibility::Reversible)
                        .with_tool_call(ToolCallId(1)),
                );
                assert!(
                    !has_effect(&actions),
                    "terminal task ({terminal_kind:?}) emitted an effect on {kind:?}: {actions:?}"
                );
            }
        }
    }

    // AC3a: an irreversible request never produces an effect — only an approval
    // request — under both supervised and full profiles.
    #[test]
    fn irreversible_request_requires_approval_path() {
        for profile in [RiskProfile::Supervised, RiskProfile::Full] {
            for reversibility in [Reversibility::Irreversible, Reversibility::Destructive] {
                let mut k = Kernel::new(PolicySnapshot::new(profile));
                let tid = TaskId(1);
                k.step(
                    Event::inbound(EventKind::TaskCreated, EventSeq(1), Actor::Adapter)
                        .with_task(tid),
                );
                k.step(
                    Event::inbound(EventKind::JobQueued, EventSeq(2), Actor::Adapter)
                        .with_task(tid)
                        .with_job(JobId(1)),
                );
                k.step(
                    Event::inbound(EventKind::JobLeased, EventSeq(3), Actor::Adapter)
                        .with_task(tid)
                        .with_job(JobId(1))
                        .with_lease_owner(LeaseOwner(1)),
                );
                let actions = k.step(
                    Event::inbound(EventKind::ToolCallRequested, EventSeq(4), Actor::Model)
                        .with_task(tid)
                        .with_job(JobId(1))
                        .with_tool_call(ToolCallId(1))
                        .with_reversibility(reversibility),
                );
                assert!(actions
                    .iter()
                    .any(|a| matches!(a, Action::RequestApproval { .. })));
                assert!(!actions.iter().any(|a| matches!(a, Action::RunTool { .. })));
                assert_eq!(k.task_status(tid), Some(TaskStatus::AwaitingApproval));
            }
        }
    }

    // AC3a (allow path): a reversible request runs immediately under supervised.
    #[test]
    fn reversible_request_runs_without_approval() {
        let (mut k, tid, seq) = running_task(None);
        let actions = k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
                .with_task(tid)
                .with_job(JobId(1))
                .with_tool_call(ToolCallId(1))
                .with_reversibility(Reversibility::Reversible),
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::RunTool { job_id } if *job_id == JobId(1))));
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::RequestApproval { .. })));
    }

    // Fail-safe: an irreversible request with no operation id cannot be bound to
    // an approval, so it is blocked rather than minting an unbindable approval.
    #[test]
    fn untagged_irreversible_request_is_blocked() {
        let (mut k, tid, seq) = running_task(None);
        let actions = k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
                .with_task(tid)
                .with_job(JobId(1)),
        );
        assert!(
            !has_effect(&actions),
            "untagged request emitted {actions:?}"
        );
        assert_eq!(k.task_status(tid), Some(TaskStatus::Blocked));
        assert_eq!(k.block_reason(tid), Some(BlockReason::RiskDetected));
        assert_eq!(k.task_awaiting(tid), None);
    }

    // AC3b (invariant 4): no non-user actor can resolve an approval into an
    // effect; an authorized user can.
    #[test]
    fn model_cannot_self_approve() {
        for actor in [
            Actor::Model,
            Actor::Subagent,
            Actor::ExternalWorker,
            Actor::Adapter,
            Actor::Kernel,
        ] {
            let (mut k, tid, seq) = running_task(None);
            let (approval, seq) = request_irreversible(&mut k, tid, JobId(1), seq);
            let actions = k.step(
                Event::inbound(EventKind::ApprovalResolved, EventSeq(seq), actor)
                    .with_task(tid)
                    .with_approval(approval)
                    .with_tool_call(ToolCallId(1))
                    .with_resolution(ApprovalResolution::Approve),
            );
            assert!(!has_effect(&actions), "{actor:?} produced an effect");
            assert_eq!(k.approval_status(approval), Some(ApprovalStatus::Pending));
            assert_eq!(k.task_status(tid), Some(TaskStatus::AwaitingApproval));
        }
    }

    #[test]
    fn authorized_user_approval_releases_the_effect() {
        let (mut k, tid, seq) = running_task(None);
        let (approval, seq) = request_irreversible(&mut k, tid, JobId(1), seq);
        let actions = k.step(
            Event::inbound(EventKind::ApprovalResolved, EventSeq(seq), Actor::User)
                .with_task(tid)
                .with_approval(approval)
                .with_tool_call(ToolCallId(1))
                .with_resolution(ApprovalResolution::Approve),
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::RunTool { job_id } if *job_id == JobId(1))));
        assert_eq!(k.approval_status(approval), Some(ApprovalStatus::Approved));
        assert_eq!(k.task_status(tid), Some(TaskStatus::Running));
    }

    #[test]
    fn wrong_operation_resolution_is_rejected() {
        let (mut k, tid, seq) = running_task(None);
        let (approval, seq) = request_irreversible(&mut k, tid, JobId(1), seq);
        // Resolve referencing a different tool call than the bound operation.
        let actions = k.step(
            Event::inbound(EventKind::ApprovalResolved, EventSeq(seq), Actor::User)
                .with_task(tid)
                .with_approval(approval)
                .with_tool_call(ToolCallId(999))
                .with_resolution(ApprovalResolution::Approve),
        );
        assert!(!has_effect(&actions));
        assert_eq!(k.approval_status(approval), Some(ApprovalStatus::Pending));
    }

    // An approval resolution must positively name the operation: omitting the id
    // cannot satisfy the bound op (defense in depth for the op binding).
    #[test]
    fn untagged_resolution_cannot_release_effect() {
        let (mut k, tid, seq) = running_task(None);
        let (approval, seq) = request_irreversible(&mut k, tid, JobId(1), seq);
        let actions = k.step(
            Event::inbound(EventKind::ApprovalResolved, EventSeq(seq), Actor::User)
                .with_task(tid)
                .with_approval(approval)
                .with_resolution(ApprovalResolution::Approve),
        );
        assert!(!has_effect(&actions));
        assert_eq!(k.approval_status(approval), Some(ApprovalStatus::Pending));
    }

    #[test]
    fn expired_approval_is_rejected_at_use_time() {
        let (mut k, tid, mut seq) = running_task(None);
        k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
                .with_task(tid)
                .with_job(JobId(1))
                .with_tool_call(ToolCallId(1))
                .with_timestamp(Timestamp::from_millis(0))
                .with_reversibility(Reversibility::Irreversible),
        );
        seq += 1;
        let approval = k.task_awaiting(tid).unwrap();
        let actions = k.step(
            Event::inbound(EventKind::ApprovalResolved, EventSeq(seq), Actor::User)
                .with_task(tid)
                .with_approval(approval)
                .with_tool_call(ToolCallId(1))
                .with_timestamp(Timestamp::from_millis(APPROVAL_TTL_MS + 1))
                .with_resolution(ApprovalResolution::Approve),
        );
        assert!(!has_effect(&actions));
        assert_eq!(k.approval_status(approval), Some(ApprovalStatus::Expired));
        // Expiry pauses (resumable), it does not strand the task.
        assert_eq!(k.task_status(tid), Some(TaskStatus::Blocked));
        assert_eq!(k.block_reason(tid), Some(BlockReason::ApprovalExpired));
    }

    #[test]
    fn denied_approval_blocks_the_task() {
        let (mut k, tid, seq) = running_task(None);
        let (approval, seq) = request_irreversible(&mut k, tid, JobId(1), seq);
        k.step(
            Event::inbound(EventKind::ApprovalResolved, EventSeq(seq), Actor::User)
                .with_task(tid)
                .with_approval(approval)
                .with_tool_call(ToolCallId(1))
                .with_resolution(ApprovalResolution::Deny),
        );
        assert_eq!(k.task_status(tid), Some(TaskStatus::Blocked));
        assert_eq!(k.block_reason(tid), Some(BlockReason::ApprovalDenied));
        assert_eq!(k.approval_status(approval), Some(ApprovalStatus::Denied));
    }

    // A second request while already awaiting is ignored — no orphan approval is
    // created that could later release an effect (invariant 14).
    #[test]
    fn second_request_while_awaiting_is_ignored() {
        let (mut k, tid, seq) = running_task(None);
        let (approval, seq) = request_irreversible(&mut k, tid, JobId(1), seq);
        let actions = k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
                .with_task(tid)
                .with_job(JobId(1))
                .with_tool_call(ToolCallId(2))
                .with_reversibility(Reversibility::Irreversible),
        );
        assert!(!has_effect(&actions));
        // Still the same single pending approval.
        assert_eq!(k.task_awaiting(tid), Some(approval));
        assert_eq!(k.task_status(tid), Some(TaskStatus::AwaitingApproval));
    }

    // AC4: budget exhaustion pauses the task on every axis, and a user steer
    // resumes it.
    #[test]
    fn budget_exhaustion_blocks_then_resumes() {
        for axis in BudgetAxis::ALL {
            let budget = Budget::unlimited().with_limit(axis, 10);
            let (mut k, tid, mut seq) = running_task(Some(budget));
            let actions = k.step(
                Event::inbound(
                    EventKind::CommandOutputCaptured,
                    EventSeq(seq),
                    Actor::Adapter,
                )
                .with_task(tid)
                .with_job(JobId(1))
                .with_lease_owner(LeaseOwner(1))
                .with_budget_delta(BudgetDelta::of(axis, 11)),
            );
            seq += 1;
            assert_eq!(
                k.task_status(tid),
                Some(TaskStatus::Blocked),
                "axis {axis:?}"
            );
            assert_eq!(
                k.block_reason(tid),
                Some(BlockReason::BudgetExhausted(axis))
            );
            assert!(!has_effect(&actions));

            k.step(
                Event::inbound(EventKind::UserSteerReceived, EventSeq(seq), Actor::User)
                    .with_task(tid),
            );
            assert_eq!(
                k.task_status(tid),
                Some(TaskStatus::Running),
                "axis {axis:?}"
            );
        }
    }

    // The budget pause is *absorbing*: a blocked task emits no effects on a
    // subsequent request until a user steer resumes it (the critical fix).
    #[test]
    fn budget_pause_is_durable() {
        let budget = Budget::unlimited().with_limit(BudgetAxis::Tokens, 10);
        let (mut k, tid, mut seq) = running_task(Some(budget));
        k.step(
            Event::inbound(
                EventKind::CommandOutputCaptured,
                EventSeq(seq),
                Actor::Adapter,
            )
            .with_task(tid)
            .with_job(JobId(1))
            .with_lease_owner(LeaseOwner(1))
            .with_budget_delta(BudgetDelta::of(BudgetAxis::Tokens, 11)),
        );
        seq += 1;
        assert_eq!(k.task_status(tid), Some(TaskStatus::Blocked));

        // A reversible request carrying NO budget delta must not slip past the
        // pause (it previously did — invariant 11 / AC4).
        for kind in [
            EventKind::ToolCallRequested,
            EventKind::GitHubOperationRequested,
        ] {
            let actions = k.step(
                Event::inbound(kind, EventSeq(seq), Actor::Model)
                    .with_task(tid)
                    .with_job(JobId(1))
                    .with_tool_call(ToolCallId(1))
                    .with_reversibility(Reversibility::Reversible),
            );
            seq += 1;
            assert!(
                !has_effect(&actions),
                "{kind:?} slipped past the pause: {actions:?}"
            );
            assert_eq!(
                k.task_status(tid),
                Some(TaskStatus::Blocked),
                "pause cleared by {kind:?}"
            );
        }

        // After a user steer, work resumes and effects flow again.
        k.step(
            Event::inbound(EventKind::UserSteerReceived, EventSeq(seq), Actor::User).with_task(tid),
        );
        seq += 1;
        let actions = k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
                .with_task(tid)
                .with_job(JobId(1))
                .with_tool_call(ToolCallId(1))
                .with_reversibility(Reversibility::Reversible),
        );
        assert!(actions.iter().any(|a| matches!(a, Action::RunTool { .. })));
    }

    // An untrusted request cannot silently clear a block by re-classifying.
    #[test]
    fn request_does_not_clear_a_block() {
        let budget = Budget::unlimited().with_limit(BudgetAxis::Tokens, 10);
        let (mut k, tid, mut seq) = running_task(Some(budget));
        k.step(
            Event::inbound(
                EventKind::CommandOutputCaptured,
                EventSeq(seq),
                Actor::Adapter,
            )
            .with_task(tid)
            .with_job(JobId(1))
            .with_lease_owner(LeaseOwner(1))
            .with_budget_delta(BudgetDelta::of(BudgetAxis::Tokens, 11)),
        );
        seq += 1;
        let actions = k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
                .with_task(tid)
                .with_job(JobId(1))
                .with_tool_call(ToolCallId(1))
                .with_reversibility(Reversibility::Irreversible),
        );
        assert!(!has_effect(&actions));
        // It must NOT have moved to AwaitingApproval (which would lift the pause).
        assert_eq!(k.task_status(tid), Some(TaskStatus::Blocked));
        assert_eq!(k.task_awaiting(tid), None);
    }

    // No RunTool for an unknown job id.
    #[test]
    fn unknown_job_request_emits_no_runtool() {
        let (mut k, tid, seq) = running_task(None);
        let actions = k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
                .with_task(tid)
                .with_job(JobId(999))
                .with_tool_call(ToolCallId(1))
                .with_reversibility(Reversibility::Reversible),
        );
        assert!(!actions.iter().any(|a| matches!(a, Action::RunTool { .. })));
    }

    // No RunTool for a terminal job.
    #[test]
    fn terminal_job_request_emits_no_runtool() {
        let (mut k, tid, mut seq) = running_task(None);
        k.step(
            Event::inbound(EventKind::ToolCallCompleted, EventSeq(seq), Actor::Adapter)
                .with_task(tid)
                .with_job(JobId(1))
                .with_lease_owner(LeaseOwner(1)),
        );
        seq += 1;
        assert_eq!(k.job_status(JobId(1)), Some(JobStatus::Completed));
        let actions = k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
                .with_task(tid)
                .with_job(JobId(1))
                .with_tool_call(ToolCallId(1))
                .with_reversibility(Reversibility::Reversible),
        );
        assert!(!actions.iter().any(|a| matches!(a, Action::RunTool { .. })));
    }

    // Invariant 8 / AC3: the policy deny outcome blocks the task.
    #[test]
    fn policy_deny_blocks_the_task() {
        let mut k = Kernel::new(PolicySnapshot::new(RiskProfile::ReadOnly));
        let tid = TaskId(1);
        k.step(Event::inbound(EventKind::TaskCreated, EventSeq(1), Actor::Adapter).with_task(tid));
        k.step(
            Event::inbound(EventKind::JobQueued, EventSeq(2), Actor::Adapter)
                .with_task(tid)
                .with_job(JobId(1)),
        );
        k.step(
            Event::inbound(EventKind::JobLeased, EventSeq(3), Actor::Adapter)
                .with_task(tid)
                .with_job(JobId(1))
                .with_lease_owner(LeaseOwner(1)),
        );
        let actions = k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(4), Actor::Model)
                .with_task(tid)
                .with_job(JobId(1))
                .with_tool_call(ToolCallId(1))
                .with_reversibility(Reversibility::Reversible),
        );
        assert!(!has_effect(&actions));
        assert_eq!(k.task_status(tid), Some(TaskStatus::Blocked));
        assert_eq!(k.block_reason(tid), Some(BlockReason::PolicyDenied));
    }

    // Invariant 14: an irreversible GitHub operation also gates on approval.
    #[test]
    fn github_irreversible_requires_approval() {
        let (mut k, tid, seq) = running_task(None);
        let actions = k.step(
            Event::inbound(
                EventKind::GitHubOperationRequested,
                EventSeq(seq),
                Actor::Model,
            )
            .with_task(tid)
            .with_job(JobId(1))
            .with_tool_call(ToolCallId(1))
            .with_reversibility(Reversibility::Irreversible),
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::RequestApproval { .. })));
        assert!(!actions.iter().any(|a| matches!(a, Action::RunTool { .. })));
        assert_eq!(k.task_status(tid), Some(TaskStatus::AwaitingApproval));
    }

    // Invariant 12: killing/failing a task cascades to its live jobs.
    #[test]
    fn task_termination_cascades_to_jobs() {
        for (terminal_kind, job_terminal) in [
            (EventKind::TaskKilled, JobStatus::Killed),
            (EventKind::TaskFailed, JobStatus::Failed),
        ] {
            let mut k = kernel();
            let tid = TaskId(1);
            k.step(
                Event::inbound(EventKind::TaskCreated, EventSeq(1), Actor::Adapter).with_task(tid),
            );
            for (i, jid) in [JobId(1), JobId(2)].into_iter().enumerate() {
                let base = 2 + (i as u64) * 2;
                k.step(
                    Event::inbound(EventKind::JobQueued, EventSeq(base), Actor::Adapter)
                        .with_task(tid)
                        .with_job(jid),
                );
                k.step(
                    Event::inbound(EventKind::JobLeased, EventSeq(base + 1), Actor::Adapter)
                        .with_task(tid)
                        .with_job(jid)
                        .with_lease_owner(LeaseOwner(1)),
                );
            }
            k.step(Event::inbound(terminal_kind, EventSeq(99), Actor::Adapter).with_task(tid));
            assert_eq!(
                k.job_status(JobId(1)),
                Some(job_terminal),
                "{terminal_kind:?}"
            );
            assert_eq!(
                k.job_status(JobId(2)),
                Some(job_terminal),
                "{terminal_kind:?}"
            );
        }
    }

    // Determinism: the same event stream through two fresh kernels yields
    // identical per-step action lists (replay/golden-test foundation).
    #[test]
    fn step_is_deterministic_across_kernels() {
        let script = |k: &mut Kernel| -> Vec<ActionVec> {
            let tid = TaskId(1);
            let jid = JobId(1);
            let events = [
                Event::inbound(EventKind::TaskCreated, EventSeq(1), Actor::Adapter).with_task(tid),
                Event::inbound(EventKind::JobQueued, EventSeq(2), Actor::Adapter)
                    .with_task(tid)
                    .with_job(jid),
                Event::inbound(EventKind::JobLeased, EventSeq(3), Actor::Adapter)
                    .with_task(tid)
                    .with_job(jid)
                    .with_lease_owner(LeaseOwner(1)),
                Event::inbound(EventKind::ToolCallRequested, EventSeq(4), Actor::Model)
                    .with_task(tid)
                    .with_job(jid)
                    .with_tool_call(ToolCallId(1))
                    .with_reversibility(Reversibility::Reversible),
                Event::inbound(EventKind::PatchVerified, EventSeq(5), Actor::Adapter)
                    .with_task(tid),
                Event::inbound(EventKind::TaskCompleted, EventSeq(6), Actor::Adapter)
                    .with_task(tid),
            ];
            events.into_iter().map(|e| k.step(e)).collect()
        };
        let mut a = kernel();
        let mut b = kernel();
        assert_eq!(script(&mut a), script(&mut b));
    }

    #[test]
    fn redelivered_event_is_a_noop() {
        let (mut k, tid, seq) = running_task(None);
        let ev =
            Event::inbound(EventKind::PatchVerified, EventSeq(seq), Actor::Adapter).with_task(tid);
        let first = k.step(ev.clone());
        assert!(!first.is_empty());
        assert_eq!(k.task_status(tid), Some(TaskStatus::Integrating));
        let second = k.step(ev);
        assert!(second.is_empty());
        assert_eq!(k.task_status(tid), Some(TaskStatus::Integrating));
    }

    // Re-delivering an *effect-bearing* event does not duplicate the effect.
    #[test]
    fn redelivered_effect_event_does_not_duplicate() {
        let (mut k, tid, seq) = running_task(None);
        let ev = Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
            .with_task(tid)
            .with_job(JobId(1))
            .with_tool_call(ToolCallId(1))
            .with_reversibility(Reversibility::Reversible);
        let first = k.step(ev.clone());
        assert!(first.iter().any(|a| matches!(a, Action::RunTool { .. })));
        let second = k.step(ev);
        assert!(
            second.is_empty(),
            "duplicate delivery re-emitted: {second:?}"
        );
    }

    #[test]
    fn fan_out_is_bounded() {
        let mut k = kernel();
        let tid = TaskId(1);
        for (i, kind) in EventKind::ALL.into_iter().enumerate() {
            let seq = i as u64 + 1;
            let actions = k.step(
                Event::inbound(kind, EventSeq(seq), Actor::Adapter)
                    .with_task(tid)
                    .with_job(JobId(1))
                    .with_lease_owner(LeaseOwner(1))
                    .with_reversibility(Reversibility::Reversible)
                    .with_tool_call(ToolCallId(1)),
            );
            assert!(
                actions.len() <= READY_DRAIN_MAX + 3,
                "{kind:?} -> {actions:?}"
            );
        }
    }

    #[test]
    fn stale_worker_event_is_ignored() {
        let (mut k, tid, seq) = running_task(None);
        k.step(
            Event::inbound(EventKind::CommandCompleted, EventSeq(seq), Actor::Adapter)
                .with_task(tid)
                .with_job(JobId(1))
                .with_lease_owner(LeaseOwner(999)),
        );
        assert_ne!(k.job_status(JobId(1)), Some(JobStatus::Completed));
    }

    #[test]
    fn lease_expiry_marks_job_expired() {
        let (mut k, tid, seq) = running_task(None);
        k.step(
            Event::inbound(EventKind::CommandStarted, EventSeq(seq), Actor::Adapter)
                .with_task(tid)
                .with_job(JobId(1))
                .with_lease_owner(LeaseOwner(1))
                .with_timestamp(Timestamp::from_millis(u64::MAX)),
        );
        assert_eq!(k.job_status(JobId(1)), Some(JobStatus::Expired));
    }

    // The model-request (drain) path must obey the source-state gate too: a
    // paused task does not drive the model by leasing a new job.
    #[test]
    fn paused_task_does_not_drive_the_model() {
        // (a) budget-Blocked task: leasing a second job emits no RequestModel.
        let budget = Budget::unlimited().with_limit(BudgetAxis::Tokens, 10);
        let (mut k, tid, mut seq) = running_task(Some(budget));
        k.step(
            Event::inbound(
                EventKind::CommandOutputCaptured,
                EventSeq(seq),
                Actor::Adapter,
            )
            .with_task(tid)
            .with_job(JobId(1))
            .with_lease_owner(LeaseOwner(1))
            .with_budget_delta(BudgetDelta::of(BudgetAxis::Tokens, 11)),
        );
        seq += 1;
        assert_eq!(k.task_status(tid), Some(TaskStatus::Blocked));
        k.step(
            Event::inbound(EventKind::JobQueued, EventSeq(seq), Actor::Adapter)
                .with_task(tid)
                .with_job(JobId(2)),
        );
        seq += 1;
        let actions = k.step(
            Event::inbound(EventKind::JobLeased, EventSeq(seq), Actor::Adapter)
                .with_task(tid)
                .with_job(JobId(2))
                .with_lease_owner(LeaseOwner(2)),
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::RequestModel { .. })),
            "blocked task drove the model: {actions:?}"
        );

        // (b) AwaitingApproval task: same.
        let (mut k, tid, seq) = running_task(None);
        let (_approval, mut seq) = request_irreversible(&mut k, tid, JobId(1), seq);
        k.step(
            Event::inbound(EventKind::JobQueued, EventSeq(seq), Actor::Adapter)
                .with_task(tid)
                .with_job(JobId(2)),
        );
        seq += 1;
        let actions = k.step(
            Event::inbound(EventKind::JobLeased, EventSeq(seq), Actor::Adapter)
                .with_task(tid)
                .with_job(JobId(2))
                .with_lease_owner(LeaseOwner(2)),
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::RequestModel { .. })),
            "awaiting-approval task drove the model: {actions:?}"
        );
    }

    // A detected risk on an AwaitingApproval task drops the pending approval, so a
    // late user approve cannot override the risk block (invariant 14).
    #[test]
    fn risk_block_supersedes_a_pending_approval() {
        let (mut k, tid, seq) = running_task(None);
        let (approval, mut seq) = request_irreversible(&mut k, tid, JobId(1), seq);
        k.step(
            Event::inbound(EventKind::RiskDetected, EventSeq(seq), Actor::Adapter).with_task(tid),
        );
        seq += 1;
        assert_eq!(k.task_status(tid), Some(TaskStatus::Blocked));
        assert_eq!(k.task_awaiting(tid), None);
        // A user approve of the now-orphaned approval must not run the tool.
        let actions = k.step(
            Event::inbound(EventKind::ApprovalResolved, EventSeq(seq), Actor::User)
                .with_task(tid)
                .with_approval(approval)
                .with_tool_call(ToolCallId(1))
                .with_resolution(ApprovalResolution::Approve),
        );
        assert!(!has_effect(&actions));
        assert_eq!(k.task_status(tid), Some(TaskStatus::Blocked));
    }

    // `block_reason` is set iff the task is `Blocked`: a transition out of Blocked
    // clears it (no stale reason on a non-Blocked task).
    #[test]
    fn block_reason_is_cleared_when_leaving_blocked() {
        let mut k = Kernel::new(PolicySnapshot::new(RiskProfile::ReadOnly));
        let tid = TaskId(1);
        k.step(Event::inbound(EventKind::TaskCreated, EventSeq(1), Actor::Adapter).with_task(tid));
        k.step(
            Event::inbound(EventKind::JobQueued, EventSeq(2), Actor::Adapter)
                .with_task(tid)
                .with_job(JobId(1)),
        );
        k.step(
            Event::inbound(EventKind::JobLeased, EventSeq(3), Actor::Adapter)
                .with_task(tid)
                .with_job(JobId(1))
                .with_lease_owner(LeaseOwner(1)),
        );
        // ReadOnly denies the request -> Blocked(PolicyDenied).
        k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(4), Actor::Model)
                .with_task(tid)
                .with_job(JobId(1))
                .with_tool_call(ToolCallId(1))
                .with_reversibility(Reversibility::Reversible),
        );
        assert_eq!(k.block_reason(tid), Some(BlockReason::PolicyDenied));
        // Blocked --PatchRejected--> Retrying must clear the stale reason.
        k.step(
            Event::inbound(EventKind::PatchRejected, EventSeq(5), Actor::Adapter).with_task(tid),
        );
        assert_eq!(k.task_status(tid), Some(TaskStatus::Retrying));
        assert_eq!(k.block_reason(tid), None);
    }

    // Liveness: an AwaitingApproval task is not wedged forever when no valid
    // resolution arrives — any event past the approval TTL pauses it (resumable),
    // and a user steer then resumes it.
    #[test]
    fn awaiting_approval_recovers_after_ttl() {
        let (mut k, tid, mut seq) = running_task(None);
        // Request at t=0 -> AwaitingApproval, approval expires at APPROVAL_TTL_MS.
        k.step(
            Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
                .with_task(tid)
                .with_job(JobId(1))
                .with_tool_call(ToolCallId(1))
                .with_timestamp(Timestamp::from_millis(0))
                .with_reversibility(Reversibility::Irreversible),
        );
        seq += 1;
        let approval = k.task_awaiting(tid).expect("pending");
        assert_eq!(k.task_status(tid), Some(TaskStatus::AwaitingApproval));

        // An UNRELATED event (not a resolution) arrives past the TTL: the sweep
        // expires the approval and pauses the task — it is no longer wedged.
        k.step(
            Event::inbound(EventKind::ModelOutputReceived, EventSeq(seq), Actor::Model)
                .with_task(tid)
                .with_job(JobId(1))
                .with_timestamp(Timestamp::from_millis(APPROVAL_TTL_MS + 1)),
        );
        seq += 1;
        assert_eq!(k.task_status(tid), Some(TaskStatus::Blocked));
        assert_eq!(k.block_reason(tid), Some(BlockReason::ApprovalExpired));
        assert_eq!(k.approval_status(approval), Some(ApprovalStatus::Expired));
        assert_eq!(k.task_awaiting(tid), None);

        // And it is resumable.
        k.step(
            Event::inbound(EventKind::UserSteerReceived, EventSeq(seq), Actor::User).with_task(tid),
        );
        assert_eq!(k.task_status(tid), Some(TaskStatus::Running));
    }

    // GitHub operations are legitimate during integration; the source-state gate
    // must not drop them (otherwise the task wedges in `Integrating`).
    #[test]
    fn github_op_during_integration_is_classified() {
        let (mut k, tid, mut seq) = running_task(None);
        k.step(
            Event::inbound(EventKind::PatchVerified, EventSeq(seq), Actor::Adapter).with_task(tid),
        );
        seq += 1;
        assert_eq!(k.task_status(tid), Some(TaskStatus::Integrating));
        let actions = k.step(
            Event::inbound(
                EventKind::GitHubOperationRequested,
                EventSeq(seq),
                Actor::Model,
            )
            .with_task(tid)
            .with_job(JobId(1))
            .with_tool_call(ToolCallId(1))
            .with_reversibility(Reversibility::Irreversible),
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::RequestApproval { .. })),
            "GitHub op during Integrating was dropped: {actions:?}"
        );
        assert_eq!(k.task_status(tid), Some(TaskStatus::AwaitingApproval));
    }

    // No-panic guarantee: a deterministic LCG fuzz of hostile/contradictory
    // events (incl. sequences near u64::MAX, huge timestamps/deltas, finite
    // budgets, unknown ids) never panics and keeps the action list bounded.
    #[test]
    fn step_never_panics_on_hostile_input() {
        let mut k = kernel();
        // Seed a few tasks with finite budgets so the exhaustion path is fuzzed.
        for t in 0..3u128 {
            k.step(
                Event::inbound(
                    EventKind::TaskCreated,
                    EventSeq(t as u64 + 1),
                    Actor::Adapter,
                )
                .with_task(TaskId(t))
                .with_budget(Budget::unlimited().with_limit(BudgetAxis::Tokens, 1_000)),
            );
        }
        let mut lcg: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            lcg
        };
        for _ in 0..50_000 {
            let r = next();
            let kind = EventKind::ALL[(r % EventKind::ALL.len() as u64) as usize];
            let actor = Actor::ALL[((r >> 8) % Actor::ALL.len() as u64) as usize];
            // Mix small seqs (replays) with values near u64::MAX (saturation).
            let seq = match (r >> 13) % 4 {
                0 => EventSeq((r >> 16) % 7),
                1 => EventSeq(u64::MAX - (r % 3)),
                _ => EventSeq(r.rotate_left(7)),
            };
            let ts = Timestamp::from_millis(r.rotate_left(3));
            let tid = TaskId((r % 4) as u128);
            // Reversibility varies so the approval-mint path is reached, not just
            // the deny/allow extremes.
            let reversibility = match (r >> 5) % 3 {
                0 => Reversibility::Reversible,
                1 => Reversibility::Irreversible,
                _ => Reversibility::Destructive,
            };
            let mut event = Event::inbound(kind, seq, actor)
                .with_task(tid)
                .with_job(JobId((r % 4) as u128))
                .with_timestamp(ts)
                .with_approval(ApprovalId((r % 4) as u128))
                .with_tool_call(ToolCallId((r % 4) as u128))
                .with_reversibility(reversibility)
                .with_resolution(ApprovalResolution::Approve)
                .with_lease_owner(LeaseOwner(r % 3));
            // Attach a *bounded* budget delta on only some events, so tasks stay
            // Running long enough to mint and resolve approvals (and occasionally
            // exhaust). Periodically inject a user steer to resume blocked tasks.
            if r % 5 == 0 {
                event = event.with_budget_delta(BudgetDelta::of(BudgetAxis::Tokens, r % 64));
            }
            let actions = k.step(event);
            assert!(actions.len() <= READY_DRAIN_MAX + 3);
            if r % 11 == 0 {
                let steer = Event::inbound(
                    EventKind::UserSteerReceived,
                    EventSeq(seq.0.saturating_add(1)),
                    Actor::User,
                )
                .with_task(tid);
                let a2 = k.step(steer);
                assert!(a2.len() <= READY_DRAIN_MAX + 3);
            }
        }
    }
}
