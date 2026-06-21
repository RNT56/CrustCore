// SPDX-License-Identifier: Apache-2.0
//! Run inspector + session list (`C7.3`). Read-only over the hash-chained event log.
//!
//! Renders the task/job/budget summary exactly as `EventLog::inspect` rolls it up — the
//! same streamed-to-user set as `docs/telegram.md` §7, never raw chain-of-thought. It
//! **mints nothing, writes nothing, appends no frame**, and reaches no verifier.

use crate::backend::{RunInspectorView, SessionListView, TaskRow};
use crustcore_eventlog::EventLog;
use crustcore_secrets::Redactor;
use crustcore_session::{SessionId, SessionService};

/// Render the run inspector over the live log. Pure: `&EventLog` in, view model out.
#[must_use]
pub fn render(log: &EventLog) -> RunInspectorView {
    // `inspect` verifies the chain and rolls up per-task; only verified frames count.
    let report = log.inspect();
    let tasks = report
        .tasks
        .iter()
        .map(|t| TaskRow {
            task_id: t.task_id,
            frames: t.frames,
            first_seq: t.first_seq,
            last_seq: t.last_seq,
            // The terminal kind is a closed-enum name, never untrusted text.
            terminal: t.terminal.map(|k| format!("{k:?}")),
        })
        .collect();

    RunInspectorView {
        chain: report.status,
        total_frames: report.total_frames,
        tasks,
    }
}

/// Render the session list (read-only) via the `crustcore-session` service. The service
/// is a verify-or-refuse VIEW over the same log; listing mints/writes nothing.
#[must_use]
pub fn sessions(log: &EventLog, redactor: &Redactor) -> SessionListView {
    let service = SessionService::new(log, redactor);
    let sessions = service.list().into_iter().map(SessionId::task_id).collect();
    SessionListView { sessions }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_eventlog::{ChainStatus, FrameMeta};
    use crustcore_kernel::event::EventKind;
    use crustcore_types::TaskId;

    fn log_with_one_task() -> EventLog {
        let mut log = EventLog::new();
        log.append(
            &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(1)),
            b"created",
        );
        log.append(
            &FrameMeta::new(2, EventKind::TaskCompleted).task(TaskId(1)),
            b"done",
        );
        log
    }

    #[test]
    fn renders_intact_task_rollup() {
        let log = log_with_one_task();
        let view = render(&log);
        assert!(matches!(view.chain, ChainStatus::Intact { frames: 2 }));
        assert_eq!(view.total_frames, 2);
        assert_eq!(view.tasks.len(), 1);
        let t = &view.tasks[0];
        assert_eq!(t.task_id, TaskId(1));
        assert_eq!(t.frames, 2);
        assert_eq!(t.terminal.as_deref(), Some("TaskCompleted"));
    }

    #[test]
    fn render_does_not_mutate_the_log() {
        let log = log_with_one_task();
        let before = log.bytes().to_vec();
        let before_head = log.head_hash();
        let _ = render(&log);
        // Pure read: bytes and head unchanged.
        assert_eq!(log.bytes(), before.as_slice());
        assert_eq!(log.head_hash(), before_head);
    }

    #[test]
    fn session_list_is_read_only() {
        let log = log_with_one_task();
        let redactor = Redactor::new();
        let before = log.bytes().to_vec();
        let list = sessions(&log, &redactor);
        assert_eq!(log.bytes(), before.as_slice());
        // One task -> one session.
        assert!(list.sessions.contains(&TaskId(1)));
    }
}
