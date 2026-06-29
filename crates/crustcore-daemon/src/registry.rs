// SPDX-License-Identifier: Apache-2.0
//! The **multi-task supervised registry** — the bounded-concurrency, lease/heartbeat
//! lifecycle brain for chat-launched tasks (`P10-net`, invariant 12).
//!
//! The runtime used to run **one** chat task at a time (`active: Option<TaskHandle>`). This
//! module replaces that with a deterministic, CI-tested registry that supervises **several**
//! tasks at once with the four semantics invariant 12 requires of every long-running job:
//!
//! - **Lease** — each task holds a lease with an expiry ([`Lease::expires_at`]).
//! - **Heartbeat** — proof-of-life ([`TaskRegistry::heartbeat`], also via
//!   [`TaskRegistry::observe_progress`]) refreshes the lease. The runtime heartbeats every
//!   running handle each tick, so a healthy task — even one running a long *silent* verify —
//!   never falsely expires; the lease reflects "the supervisor still holds the live thread."
//! - **Cancellation** — cooperative ([`TaskRegistry::request_cancel`]) and hard
//!   ([`TaskRegistry::request_kill`]).
//! - **Recovery** — [`TaskRegistry::tick`] reclaims a slot two ways: an **expired lease**
//!   (the supervisor lost the thread — an orphaned slot, or the future cross-process case) is
//!   finalized as [`TaskDone::Expired`] and its concurrency slot freed; a **runaway** task is
//!   killed when its wall budget breaches (invariant 11). Either way the operator is told,
//!   rather than a task hanging forever.
//!
//! ## Pure brain, live hands (the repo's core/live split)
//!
//! The registry is a **pure** state machine: every method takes an injected `now:
//! Timestamp` (no wall clock), owns no threads or sockets, and `tick` returns a bounded list
//! of [`RegistryAction`]s for the live runtime loop to perform (send a line, cancel/kill a
//! handle, finalize). This mirrors `Kernel::step` and `dispatch_event` — it is fully
//! unit-tested with built slots and stepped timestamps, no I/O. The live
//! [`run_serve_loop`](crate::runtime) holds the un-pure [`TaskHandle`](crate::task::TaskHandle)s
//! the actions name and merely executes them.
//!
//! It **reuses** the existing supervision primitives verbatim — the bounded-concurrency
//! [`Scheduler`](crate::supervisor::Scheduler) and the per-task
//! [`AgentBudget`](crate::supervisor::AgentBudget)/[`AgentUsage`](crate::supervisor::AgentUsage)
//! (invariant 11) — and restates the kernel's lease/heartbeat model in-process. Tasks never
//! talk to the user: the registry emits [`RegistryAction::SendLine`] as **data**, and only
//! the runtime loop renders it through the redactor and sends it (invariants 2, 5).
//!
//! **Cross-process recovery (roadmap-v0.6 F.1):** [`TaskRegistry::snapshot_all`] +
//! [`TaskRegistry::adopt_from_snapshot`] now realize the recovery half of invariant 12 —
//! a restarting daemon re-adopts its running tasks (stable ids), re-leasing under the new
//! [`LeaseOwner`] and marking each **`Pending`** so a fresh worker resumes from the log
//! (an `mpsc` channel cannot survive a restart). These are **pure** state-machine steps;
//! the actual dump/load file I/O + the SIGTERM hook + a kill-and-restart cycle are the
//! `TODO(daemon-recover-xproc-live)` seam. A remote operator [`admin`](crate::admin) socket
//! (`TODO(daemon-admin)`) lands the control plane beyond the chat verbs.
//!
//! The module is **pure** (no `TaskHandle`/socket/thread), so it is always compiled and
//! CI-tested in every build; only the live loop that drives it is `live`-gated.

use std::collections::BTreeMap;

use crustcore_types::Timestamp;

use crate::supervisor::{AgentBudget, AgentUsage, BudgetError, Scheduler};
use crate::telegram::ChatId;

/// How long a task's lease is valid without proof-of-life before it is presumed dead and
/// reclaimed (mirrors the kernel's `LEASE_TTL_MS`; invariant 12). Far larger than the poll
/// interval so a slow tick never falsely expires a healthy task.
pub const LEASE_TTL_MS: u64 = 60_000;

/// The default per-task resource budget (invariant 11). Bounds wall time and streamed output
/// so a runaway task is killed mid-run. Tokens are not metered for these worktree tasks.
#[must_use]
pub fn default_task_budget() -> AgentBudget {
    AgentBudget {
        max_wall_ms: 30 * 60 * 1000, // 30 minutes
        max_output_bytes: 1 << 20,   // 1 MiB of streamed status
        max_tokens: u64::MAX,
    }
}

/// A registry-assigned task id (distinct from [`ChatId`] — several tasks can share a chat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

/// The single supervising runtime instance that owns a task's lease. Reserved for a future
/// cross-process recovery protocol (`TODO(daemon-recover-xproc)`); today there is exactly one
/// supervisor (the maintainer/runtime model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseOwner(pub u64);

/// A task lease: who owns it, when it expires, and the last proof-of-life. A healthy task
/// refreshes this on every progress report; an unrefreshed lease past [`Lease::expires_at`]
/// is presumed dead (invariant 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    /// The supervising instance that holds the lease.
    pub owner: LeaseOwner,
    /// When the lease expires (no proof-of-life by then ⇒ presumed dead).
    pub expires_at: Timestamp,
    /// The last proof-of-life timestamp (informational; drives `expires_at`).
    pub heartbeat_at: Timestamp,
}

impl Lease {
    fn granted(owner: LeaseOwner, now: Timestamp) -> Self {
        Lease {
            owner,
            expires_at: Timestamp::from_millis(now.as_millis().saturating_add(LEASE_TTL_MS)),
            heartbeat_at: now,
        }
    }

    /// Refresh on proof-of-life: bump the heartbeat and push the expiry out by the TTL.
    fn refresh(&mut self, now: Timestamp) {
        self.heartbeat_at = now;
        self.expires_at = Timestamp::from_millis(now.as_millis().saturating_add(LEASE_TTL_MS));
    }

    /// Whether the lease has expired at `now` (no proof-of-life within the TTL).
    #[must_use]
    pub fn expired_at(&self, now: Timestamp) -> bool {
        now.as_millis() > self.expires_at.as_millis()
    }
}

/// How a task ended (a terminal [`TaskPhase`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskDone {
    /// The worker thread finished (its verifier-owned result is in the final status line).
    Completed,
    /// Cooperatively cancelled by the operator (`/cancel`).
    Cancelled,
    /// Hard-killed by the operator (`/kill`).
    Killed,
    /// Lease expired (presumed dead) and reclaimed by the supervisor (invariant 12 recovery).
    Expired,
    /// A budget axis was exhausted mid-run; the task was killed (invariant 11).
    BudgetExhausted(BudgetError),
}

impl TaskDone {
    /// A short, non-sensitive label for status rendering.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            TaskDone::Completed => "completed",
            TaskDone::Cancelled => "cancelled",
            TaskDone::Killed => "killed",
            TaskDone::Expired => "expired (stalled, reclaimed)",
            TaskDone::BudgetExhausted(_) => "killed (budget exhausted)",
        }
    }
}

/// A task's lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskPhase {
    /// Admitted (slot reserved, lease granted) but the worker has not been marked running.
    Pending,
    /// The worker thread is running.
    Running,
    /// A cooperative cancel was requested; awaiting the worker to stop.
    Cancelling,
    /// Terminal.
    Done(TaskDone),
}

impl TaskPhase {
    /// Whether this phase is terminal (the task is finished).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, TaskPhase::Done(_))
    }

    /// Whether this phase is active (occupies a concurrency slot, accrues budget).
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(
            self,
            TaskPhase::Pending | TaskPhase::Running | TaskPhase::Cancelling
        )
    }
}

/// One supervised task's record.
#[derive(Debug, Clone)]
pub struct TaskSlot {
    /// The task id.
    pub id: TaskId,
    /// The chat that launched it (where progress is reported).
    pub chat: ChatId,
    /// The lifecycle phase.
    pub phase: TaskPhase,
    /// The lease (owner + expiry + heartbeat).
    pub lease: Lease,
    /// The per-task resource budget.
    pub budget: AgentBudget,
    /// Accumulated usage.
    pub usage: AgentUsage,
    /// When the task was admitted.
    pub started_at: Timestamp,
    /// The last time wall-ms/output was charged (so a charge never double-counts).
    last_charge_at: Timestamp,
}

/// A bounded action the live runtime loop must perform after a registry step. The registry
/// owns no threads/sockets, so it only *names* what to do; the loop holds the
/// [`TaskHandle`](crate::task::TaskHandle)s and performs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryAction {
    /// Send a (to-be-redacted) status line to a chat.
    SendLine {
        /// The chat to report to.
        chat: ChatId,
        /// The raw line (the loop renders it through the redactor before sending).
        line: String,
    },
    /// Cooperatively cancel a task's worker (`TaskHandle::cancel`).
    RequestCancel {
        /// The task to cancel.
        id: TaskId,
    },
    /// Hard-stop a task: drop its handle (Drop joins the thread + tears down the worktree).
    HardKill {
        /// The task to kill.
        id: TaskId,
    },
    /// The task is terminal: the loop drops its handle and forgets it (the registry has
    /// already freed the concurrency slot).
    Finalize {
        /// The finalized task.
        id: TaskId,
        /// How it ended.
        done: TaskDone,
    },
}

/// Why an admission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitError {
    /// The concurrency cap is reached (bounded fan-out; invariant 11).
    ConcurrencyCap,
}

/// A read-only, bounded snapshot of the registry for the `/tasks` and `/task` commands and
/// the status report. Cloned cheaply (rows are bounded by the concurrency cap).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistrySnapshot {
    /// One row per active task, in id order.
    pub rows: Vec<TaskRow>,
}

/// One row of [`RegistrySnapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRow {
    /// The task id.
    pub id: TaskId,
    /// The chat that launched it.
    pub chat: ChatId,
    /// The phase label.
    pub phase: TaskPhase,
    /// Wall-ms used.
    pub wall_ms: u64,
    /// Output bytes streamed.
    pub output_bytes: u64,
    /// Milliseconds until the lease expires (0 if already past).
    pub lease_ttl_ms: u64,
}

impl RegistrySnapshot {
    /// Look up one task's row.
    #[must_use]
    pub fn get(&self, id: TaskId) -> Option<&TaskRow> {
        self.rows.iter().find(|r| r.id == id)
    }
}

/// The bounded-concurrency, lease-supervised registry of chat-launched tasks.
#[derive(Debug)]
pub struct TaskRegistry {
    slots: BTreeMap<TaskId, TaskSlot>,
    sched: Scheduler,
    owner: LeaseOwner,
    next_id: u64,
}

impl TaskRegistry {
    /// A registry allowing at most `max_concurrent` active tasks, supervised by `owner`.
    #[must_use]
    pub fn new(max_concurrent: usize, owner: LeaseOwner) -> Self {
        TaskRegistry {
            slots: BTreeMap::new(),
            sched: Scheduler::new(max_concurrent),
            owner,
            next_id: 1,
        }
    }

    /// Admit a new task: reserve a concurrency slot (invariant 11) and grant a lease
    /// (invariant 12). Returns the assigned [`TaskId`], or [`AdmitError::ConcurrencyCap`] if
    /// already at the limit. The task starts [`TaskPhase::Pending`]; the loop spawns the
    /// worker and calls [`mark_running`](Self::mark_running).
    ///
    /// # Errors
    /// [`AdmitError::ConcurrencyCap`] when the concurrency cap is reached.
    pub fn admit(
        &mut self,
        chat: ChatId,
        budget: AgentBudget,
        now: Timestamp,
    ) -> Result<TaskId, AdmitError> {
        if self.sched.try_spawn().is_err() {
            return Err(AdmitError::ConcurrencyCap);
        }
        let id = TaskId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        self.slots.insert(
            id,
            TaskSlot {
                id,
                chat,
                phase: TaskPhase::Pending,
                lease: Lease::granted(self.owner, now),
                budget,
                usage: AgentUsage::default(),
                started_at: now,
                last_charge_at: now,
            },
        );
        Ok(id)
    }

    /// Mark an admitted task's worker as running.
    pub fn mark_running(&mut self, id: TaskId, now: Timestamp) {
        if let Some(slot) = self.slots.get_mut(&id) {
            if slot.phase == TaskPhase::Pending {
                slot.phase = TaskPhase::Running;
                slot.lease.refresh(now);
            }
        }
    }

    /// Proof-of-life: a task streamed `output_bytes` of status. Refreshes the lease and
    /// charges the budget (output + the wall-ms since the last charge). If a budget axis
    /// would breach, the task is marked [`TaskDone::BudgetExhausted`] (invariant 11) — the
    /// caller should stop sending its lines; [`tick`](Self::tick) emits the kill.
    pub fn observe_progress(&mut self, id: TaskId, output_bytes: u64, now: Timestamp) {
        if let Some(slot) = self.slots.get_mut(&id) {
            if slot.phase.is_terminal() {
                return;
            }
            slot.lease.refresh(now);
            let delta = AgentUsage {
                wall_ms: now
                    .as_millis()
                    .saturating_sub(slot.last_charge_at.as_millis()),
                output_bytes,
                tokens: 0,
            };
            match slot.usage.charge(delta, &slot.budget) {
                Ok(next) => {
                    slot.usage = next;
                    slot.last_charge_at = now;
                }
                Err(e) => slot.phase = TaskPhase::Done(TaskDone::BudgetExhausted(e)),
            }
        }
    }

    /// Proof-of-life **without** output: the supervisor still holds the task's live worker
    /// thread, so refresh the lease (invariant 12 heartbeat). The runtime calls this every
    /// tick for every running handle, so a healthy but *quiet* task (e.g. a long verify that
    /// streams nothing) never falsely expires — a lease only expires when the supervisor has
    /// lost the thread (an orphaned slot / the future cross-process case). Runaway work is
    /// bounded separately by the wall budget (invariant 11), not the lease.
    pub fn heartbeat(&mut self, id: TaskId, now: Timestamp) {
        if let Some(slot) = self.slots.get_mut(&id) {
            if !slot.phase.is_terminal() {
                slot.lease.refresh(now);
            }
        }
    }

    /// The worker thread finished — the task completed (its verifier-owned result is in the
    /// final status line; the registry never asserts completion from a model claim,
    /// invariant 13). Idempotent and ignored if already terminal.
    pub fn observe_finished(&mut self, id: TaskId) {
        if let Some(slot) = self.slots.get_mut(&id) {
            if !slot.phase.is_terminal() {
                slot.phase = TaskPhase::Done(TaskDone::Completed);
            }
        }
    }

    /// Request a cooperative cancel (`/cancel`): move a running task to
    /// [`TaskPhase::Cancelling`]; [`tick`](Self::tick) emits the [`RegistryAction::RequestCancel`].
    /// **Owner-scoped** — acts only if `chat` launched the task (so one allowlisted operator
    /// cannot cancel another's task; least authority). Returns whether it acted.
    pub fn request_cancel(&mut self, id: TaskId, chat: ChatId) -> bool {
        if let Some(slot) = self.slots.get_mut(&id) {
            if slot.chat == chat && slot.phase.is_active() {
                slot.phase = TaskPhase::Cancelling;
                return true;
            }
        }
        false
    }

    /// Request a hard kill (`/kill`): mark the task [`TaskDone::Killed`]; [`tick`](Self::tick)
    /// emits the [`RegistryAction::HardKill`] and finalizes the slot. **Owner-scoped** (as
    /// [`request_cancel`](Self::request_cancel)). Returns whether it acted.
    pub fn request_kill(&mut self, id: TaskId, chat: ChatId) -> bool {
        if let Some(slot) = self.slots.get_mut(&id) {
            if slot.chat == chat && !slot.phase.is_terminal() {
                slot.phase = TaskPhase::Done(TaskDone::Killed);
                return true;
            }
        }
        false
    }

    /// Step the supervisor at `now`. **The only place lifecycle decisions are made.** It is
    /// deterministic and bounded (at most a handful of actions per active task):
    /// - charges wall-ms to each running task (kills it if the wall budget breaches),
    /// - expires a lease past its TTL and reclaims the slot ([`TaskDone::Expired`]),
    /// - emits the cancel/kill/finalize actions for tasks the operator acted on,
    /// - finalizes terminal tasks (frees their concurrency slot) and removes them.
    #[must_use]
    pub fn tick(&mut self, now: Timestamp) -> Vec<RegistryAction> {
        let mut actions = Vec::new();

        // 1. Per-active-task lifecycle: charge wall-ms, expire stale leases, surface kills.
        for slot in self.slots.values_mut() {
            match slot.phase {
                TaskPhase::Running | TaskPhase::Pending => {
                    // Charge the wall-ms accrued since the last charge.
                    let delta = AgentUsage {
                        wall_ms: now
                            .as_millis()
                            .saturating_sub(slot.last_charge_at.as_millis()),
                        output_bytes: 0,
                        tokens: 0,
                    };
                    match slot.usage.charge(delta, &slot.budget) {
                        Ok(next) => {
                            slot.usage = next;
                            slot.last_charge_at = now;
                        }
                        Err(e) => {
                            slot.phase = TaskPhase::Done(TaskDone::BudgetExhausted(e));
                            continue;
                        }
                    }
                    // Lease expiry (presumed dead) — reclaim (invariant 12 recovery).
                    if slot.lease.expired_at(now) {
                        slot.phase = TaskPhase::Done(TaskDone::Expired);
                    }
                }
                TaskPhase::Cancelling => {
                    actions.push(RegistryAction::RequestCancel { id: slot.id });
                    // A cancel that is not honored within the lease TTL escalates to reclaim.
                    if slot.lease.expired_at(now) {
                        slot.phase = TaskPhase::Done(TaskDone::Killed);
                    }
                }
                TaskPhase::Done(_) => {}
            }
        }

        // 2. Finalize terminal tasks: surface the outcome, emit kill if needed, free the slot.
        let terminal: Vec<(TaskId, ChatId, TaskDone)> = self
            .slots
            .values()
            .filter_map(|s| match s.phase {
                TaskPhase::Done(done) => Some((s.id, s.chat, done)),
                _ => None,
            })
            .collect();

        for (id, chat, done) in terminal {
            // A budget-kill or operator-kill needs the worker hard-stopped before we forget it.
            if matches!(done, TaskDone::Killed | TaskDone::BudgetExhausted(_)) {
                actions.push(RegistryAction::HardKill { id });
            }
            actions.push(RegistryAction::SendLine {
                chat,
                line: format!("task #{} {}.", id.0, done.label()),
            });
            actions.push(RegistryAction::Finalize { id, done });
            self.slots.remove(&id);
            self.sched.finish();
        }

        actions
    }

    /// Number of active (non-terminal) tasks.
    #[must_use]
    pub fn len_active(&self) -> usize {
        self.slots.values().filter(|s| s.phase.is_active()).count()
    }

    /// A bounded, read-only snapshot for `/tasks`, `/task`, and status.
    #[must_use]
    pub fn snapshot(&self, now: Timestamp) -> RegistrySnapshot {
        let rows = self
            .slots
            .values()
            .map(|s| TaskRow {
                id: s.id,
                chat: s.chat,
                phase: s.phase,
                wall_ms: s.usage.wall_ms,
                output_bytes: s.usage.output_bytes,
                lease_ttl_ms: s
                    .lease
                    .expires_at
                    .as_millis()
                    .saturating_sub(now.as_millis()),
            })
            .collect();
        RegistrySnapshot { rows }
    }

    /// The single active task for `chat`, if exactly one is active (so `/cancel` with no id
    /// is unambiguous). Returns `None` if zero or more than one.
    #[must_use]
    pub fn sole_active_for(&self, chat: ChatId) -> Option<TaskId> {
        let mut found = None;
        for s in self.slots.values() {
            if s.chat == chat && s.phase.is_active() {
                if found.is_some() {
                    return None; // ambiguous
                }
                found = Some(s.id);
            }
        }
        found
    }

    // --- cross-process recovery (roadmap-v0.6 F.1) ---------------------------

    /// Snapshots every **non-terminal** task for a cross-process dump (F.1). Pure — no
    /// I/O; the caller persists the returned `Vec` (the live dump/load is the seam). A
    /// terminal task has nothing to recover and is skipped. The live channel is **not**
    /// captured: an `mpsc` pair cannot survive a restart, so a re-adopted task resumes
    /// from its log, not by reconnecting a channel.
    #[must_use]
    pub fn snapshot_all(&self, now: Timestamp) -> Vec<TaskSnapshot> {
        self.slots
            .values()
            .filter(|s| !s.phase.is_terminal())
            .map(|s| TaskSnapshot {
                id: s.id,
                chat: s.chat,
                phase: s.phase,
                lease_remaining_ms: s
                    .lease
                    .expires_at
                    .as_millis()
                    .saturating_sub(now.as_millis()),
                budget: s.budget,
                usage: s.usage,
                worktree_path: None,
            })
            .collect()
    }

    /// Re-adopts a task from a [`TaskSnapshot`] after a daemon restart (F.1; closes the
    /// recovery half of invariant 12). Re-leases under **this** instance's `LeaseOwner`
    /// and marks the task **`Pending`** so the loop spawns a *fresh* worker that resumes
    /// from the log. Carried `usage` is preserved so budgets are re-charged, not reset
    /// (invariant 11); a re-adopted task still completes only on a `VerifiedPatch`
    /// (invariant 13 — adoption restores supervision, never completion).
    ///
    /// - **Absent worktree** (`worktree_present == false`) → [`AdoptError::WorktreeGone`].
    /// - **Already over budget** (carried usage breaches the budget) → adopted **terminal**
    ///   `Done(BudgetExhausted)` so `tick` finalizes it (never resumed).
    /// - **Duplicate id** already live → [`AdoptError::Duplicate`].
    ///
    /// # Errors
    /// [`AdoptError`] for a gone worktree or a duplicate id.
    pub fn adopt_from_snapshot(
        &mut self,
        snap: &TaskSnapshot,
        worktree_present: bool,
        now: Timestamp,
    ) -> Result<TaskId, AdoptError> {
        if self.slots.contains_key(&snap.id) {
            return Err(AdoptError::Duplicate);
        }
        if !worktree_present {
            return Err(AdoptError::WorktreeGone);
        }
        // A task whose carried usage already breaches its budget is adopted terminal.
        let phase = match snap.usage.charge(AgentUsage::default(), &snap.budget) {
            Err(axis) => TaskPhase::Done(TaskDone::BudgetExhausted(axis)),
            Ok(_) => TaskPhase::Pending,
        };
        self.slots.insert(
            snap.id,
            TaskSlot {
                id: snap.id,
                chat: snap.chat,
                phase,
                lease: Lease::granted(self.owner, now), // re-leased under THIS instance
                budget: snap.budget,
                usage: snap.usage, // carried — budgets re-charge, not reset
                started_at: now,
                last_charge_at: now,
            },
        );
        if self.next_id <= snap.id.0 {
            self.next_id = snap.id.0.wrapping_add(1); // never re-issue an adopted id
        }
        Ok(snap.id)
    }
}

/// A serializable snapshot of one task for cross-process recovery (F.1). Carries what is
/// needed to re-adopt the task after a restart — **not** the live channel (an `mpsc`
/// pair cannot survive a restart; a re-adopted task resumes from its log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSnapshot {
    /// The task id (stable across the restart).
    pub id: TaskId,
    /// The chat that launched it.
    pub chat: ChatId,
    /// The phase at dump time.
    pub phase: TaskPhase,
    /// Lease time remaining at dump (informational; adoption re-leases fresh).
    pub lease_remaining_ms: u64,
    /// The per-task budget.
    pub budget: AgentBudget,
    /// Carried usage (so budgets re-charge, not reset).
    pub usage: AgentUsage,
    /// The worktree path (set by the dumper; checked for existence on adopt).
    pub worktree_path: Option<String>,
}

/// Why a task could not be re-adopted from a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptError {
    /// The task's worktree no longer exists — the work is unrecoverable.
    WorktreeGone,
    /// A task with that id is already live in this instance.
    Duplicate,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> TaskRegistry {
        TaskRegistry::new(2, LeaseOwner(1))
    }

    fn at(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    // --- cross-process recovery (F.1) ---

    #[test]
    fn snapshot_and_adopt_round_trip_preserves_id_and_usage() {
        let mut old = reg();
        let id = old
            .admit(ChatId(7), default_task_budget(), at(1000))
            .unwrap();
        let snaps = old.snapshot_all(at(1000));
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].id, id);

        // A fresh instance (new owner) adopts the snapshot.
        let mut fresh = TaskRegistry::new(2, LeaseOwner(99));
        let adopted = fresh
            .adopt_from_snapshot(&snaps[0], true, at(5000))
            .unwrap();
        assert_eq!(adopted, id, "id is stable across the restart");
        let snap2 = fresh.snapshot(at(5000));
        let row = snap2.get(id).unwrap();
        // Re-adopted as Pending (a fresh worker resumes from the log), re-leased fresh.
        assert_eq!(row.phase, TaskPhase::Pending);
        assert_eq!(row.lease_ttl_ms, LEASE_TTL_MS);
        // A re-issued id can never collide with the adopted one.
        let next = fresh
            .admit(ChatId(7), default_task_budget(), at(5000))
            .unwrap();
        assert_ne!(next, id);
    }

    #[test]
    fn an_absent_worktree_cannot_be_adopted() {
        let mut old = reg();
        old.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        let snap = old.snapshot_all(at(0)).remove(0);
        let mut fresh = TaskRegistry::new(2, LeaseOwner(2));
        assert_eq!(
            fresh.adopt_from_snapshot(&snap, false, at(1)),
            Err(AdoptError::WorktreeGone)
        );
    }

    #[test]
    fn an_over_budget_task_is_adopted_terminal() {
        let mut old = reg();
        let id = old.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        let mut snap = old.snapshot_all(at(0)).remove(0);
        // Carry usage past the wall budget.
        snap.usage.wall_ms = snap.budget.max_wall_ms + 1;

        let mut fresh = TaskRegistry::new(2, LeaseOwner(2));
        fresh.adopt_from_snapshot(&snap, true, at(1)).unwrap();
        let row = fresh.snapshot(at(1)).get(id).unwrap().phase;
        assert!(
            matches!(row, TaskPhase::Done(TaskDone::BudgetExhausted(_))),
            "an over-budget task must adopt terminal, got {row:?}"
        );
    }

    #[test]
    fn a_duplicate_id_is_rejected() {
        let mut r = reg();
        let id = r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        let snap = TaskSnapshot {
            id,
            chat: ChatId(7),
            phase: TaskPhase::Pending,
            lease_remaining_ms: LEASE_TTL_MS,
            budget: default_task_budget(),
            usage: AgentUsage::default(),
            worktree_path: None,
        };
        assert_eq!(
            r.adopt_from_snapshot(&snap, true, at(1)),
            Err(AdoptError::Duplicate)
        );
    }

    // Live seam: the real dump/load file I/O, the SIGTERM hook, and a kill-and-restart smoke.
    #[test]
    #[ignore = "live: dump on SIGTERM, reload + re-adopt after a process restart (TODO(daemon-recover-xproc-live))"]
    fn daemon_recover_xproc_live_smoke() {
        // See docs/live-socket-validation.md §F.6. Needs file I/O + a process restart.
        panic!("live seam: run manually with a kill-and-restart cycle (see runbook §F.6)");
    }

    #[test]
    fn admit_reserves_slot_and_grants_lease() {
        let mut r = reg();
        let id = r.admit(ChatId(7), default_task_budget(), at(1000)).unwrap();
        assert_eq!(id, TaskId(1));
        let snap = r.snapshot(at(1000));
        let row = snap.get(id).unwrap();
        assert_eq!(row.phase, TaskPhase::Pending);
        assert_eq!(row.lease_ttl_ms, LEASE_TTL_MS);
        assert_eq!(r.len_active(), 1);
    }

    #[test]
    fn admit_refuses_at_concurrency_cap() {
        let mut r = reg(); // cap 2
        r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        assert_eq!(
            r.admit(ChatId(7), default_task_budget(), at(0)),
            Err(AdmitError::ConcurrencyCap)
        );
    }

    #[test]
    fn finishing_a_task_frees_the_slot_for_a_new_admit() {
        let mut r = reg(); // cap 2
        let a = r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        assert_eq!(
            r.admit(ChatId(7), default_task_budget(), at(0)),
            Err(AdmitError::ConcurrencyCap)
        );
        // Finish one and tick to finalize it → a slot frees up.
        r.observe_finished(a);
        let _ = r.tick(at(10));
        assert!(r.admit(ChatId(7), default_task_budget(), at(10)).is_ok());
    }

    #[test]
    fn progress_refreshes_the_lease_so_a_healthy_task_never_expires() {
        let mut r = reg();
        let id = r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        r.mark_running(id, at(0));
        // Heartbeat just before each expiry — the task stays alive well past one TTL.
        for t in (LEASE_TTL_MS - 1000..LEASE_TTL_MS * 3).step_by((LEASE_TTL_MS - 1000) as usize) {
            r.observe_progress(id, 10, at(t));
            let acts = r.tick(at(t));
            assert!(
                !acts
                    .iter()
                    .any(|a| matches!(a, RegistryAction::Finalize { .. })),
                "a heartbeating task must not be reclaimed at t={t}"
            );
        }
        assert_eq!(r.len_active(), 1);
    }

    #[test]
    fn a_quiet_heartbeat_keeps_a_silent_task_alive() {
        // A task that streams NOTHING (a long quiet verify) must not expire as long as the
        // supervisor heartbeats it — proof-of-life is "the thread is held", not "it printed".
        let mut r = reg();
        let id = r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        r.mark_running(id, at(0));
        for t in (LEASE_TTL_MS / 2..LEASE_TTL_MS * 4).step_by((LEASE_TTL_MS / 2) as usize) {
            r.heartbeat(id, at(t)); // no output, just proof-of-life
            let acts = r.tick(at(t));
            assert!(
                !acts
                    .iter()
                    .any(|a| matches!(a, RegistryAction::Finalize { .. })),
                "a heartbeated task must not be reclaimed at t={t}"
            );
        }
        assert_eq!(r.len_active(), 1);
    }

    #[test]
    fn tick_expires_a_stale_lease_and_reclaims_the_slot() {
        let mut r = reg();
        let id = r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        r.mark_running(id, at(0));
        // No proof-of-life past the TTL → expired + reclaimed (invariant 12 recovery).
        let acts = r.tick(at(LEASE_TTL_MS + 1));
        assert!(acts.iter().any(|a| matches!(
            a,
            RegistryAction::Finalize { id: i, done: TaskDone::Expired } if *i == id
        )));
        assert_eq!(r.len_active(), 0);
    }

    #[test]
    fn output_over_budget_kills_the_task() {
        let mut r = reg();
        let tiny = AgentBudget {
            max_wall_ms: u64::MAX,
            max_output_bytes: 100,
            max_tokens: u64::MAX,
        };
        let id = r.admit(ChatId(7), tiny, at(0)).unwrap();
        r.mark_running(id, at(0));
        r.observe_progress(id, 50, at(1));
        r.observe_progress(id, 60, at(2)); // 110 > 100 → breach, not applied
        let acts = r.tick(at(3));
        assert!(acts
            .iter()
            .any(|a| matches!(a, RegistryAction::HardKill { id: i } if *i == id)));
        assert!(acts.iter().any(|a| matches!(
            a,
            RegistryAction::Finalize {
                done: TaskDone::BudgetExhausted(BudgetError::Output),
                ..
            }
        )));
    }

    #[test]
    fn wall_budget_breach_kills_the_task_on_tick() {
        let mut r = reg();
        let tiny = AgentBudget {
            max_wall_ms: 500,
            max_output_bytes: u64::MAX,
            max_tokens: u64::MAX,
        };
        let id = r.admit(ChatId(7), tiny, at(0)).unwrap();
        r.mark_running(id, at(0));
        let acts = r.tick(at(600)); // 600ms wall > 500 cap
        assert!(acts.iter().any(|a| matches!(
            a,
            RegistryAction::Finalize {
                done: TaskDone::BudgetExhausted(BudgetError::Wall),
                ..
            }
        )));
    }

    #[test]
    fn request_cancel_moves_to_cancelling_and_emits_a_cancel() {
        let mut r = reg();
        let id = r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        r.mark_running(id, at(0));
        assert!(r.request_cancel(id, ChatId(7)));
        let acts = r.tick(at(10));
        assert!(acts
            .iter()
            .any(|a| matches!(a, RegistryAction::RequestCancel { id: i } if *i == id)));
        // Still active (cancel is cooperative — the worker stops next).
        assert_eq!(
            r.snapshot(at(10)).get(id).unwrap().phase,
            TaskPhase::Cancelling
        );
    }

    #[test]
    fn request_kill_hard_kills_and_finalizes() {
        let mut r = reg();
        let id = r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        r.mark_running(id, at(0));
        assert!(r.request_kill(id, ChatId(7)));
        let acts = r.tick(at(10));
        assert!(acts
            .iter()
            .any(|a| matches!(a, RegistryAction::HardKill { id: i } if *i == id)));
        assert!(acts.iter().any(|a| matches!(
            a,
            RegistryAction::Finalize {
                done: TaskDone::Killed,
                ..
            }
        )));
        assert_eq!(r.len_active(), 0);
    }

    #[test]
    fn cancel_kill_are_owner_scoped() {
        // A task launched by chat 7 cannot be cancelled or killed by chat 99 (least authority
        // across allowlisted operators).
        let mut r = reg();
        let id = r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        r.mark_running(id, at(0));
        assert!(
            !r.request_cancel(id, ChatId(99)),
            "another chat must not cancel"
        );
        assert!(
            !r.request_kill(id, ChatId(99)),
            "another chat must not kill"
        );
        assert!(r.snapshot(at(1)).get(id).unwrap().phase.is_active());
        assert!(r.request_cancel(id, ChatId(7)), "the owner can cancel");
    }

    #[test]
    fn sole_active_for_disambiguates() {
        let mut r = reg();
        assert_eq!(r.sole_active_for(ChatId(7)), None); // none
        let a = r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        assert_eq!(r.sole_active_for(ChatId(7)), Some(a)); // exactly one
        r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        assert_eq!(r.sole_active_for(ChatId(7)), None); // ambiguous
    }

    #[test]
    fn tick_is_deterministic() {
        let build = || {
            let mut r = reg();
            let id = r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
            r.mark_running(id, at(0));
            r
        };
        let a = build().tick(at(LEASE_TTL_MS + 5));
        let b = build().tick(at(LEASE_TTL_MS + 5));
        assert_eq!(a, b);
    }

    #[test]
    fn completed_task_is_surfaced_and_finalized() {
        let mut r = reg();
        let id = r.admit(ChatId(7), default_task_budget(), at(0)).unwrap();
        r.mark_running(id, at(0));
        r.observe_finished(id);
        let acts = r.tick(at(10));
        assert!(acts.iter().any(|a| matches!(
            a,
            RegistryAction::Finalize {
                done: TaskDone::Completed,
                ..
            }
        )));
        assert!(acts.iter().any(|a| matches!(
            a,
            RegistryAction::SendLine { chat, line } if *chat == ChatId(7) && line.contains("completed")
        )));
        assert_eq!(r.len_active(), 0);
    }
}
