// SPDX-License-Identifier: Apache-2.0
//! Shared fixtures for the `crustcore-session` integration + red-team tests.
//!
//! Everything is deterministic and built via the public `crustcore-eventlog` /
//! `crustcore-receipts` APIs — no net, no secrets, no live binaries.
//!
//! Each integration test binary compiles this module independently and uses a
//! different subset of the helpers, so unused-in-one-binary items are expected.
#![allow(dead_code)]

use crustcore_eventlog::{EventLog, FrameMeta};
use crustcore_kernel::{Actor, EventKind, Visibility};
use crustcore_receipts::{MacKey, ReceiptChain, ReceiptParams, ToolReceipt};
use crustcore_types::{EventSeq, JobId, LeaseOwner, TaskId, ToolCallId};

/// The sentinel secret threaded through fixtures so a leak is detectable verbatim.
pub const SECRET: &str = "sk-SESSIONSENTINEL";

/// The task/job a fixture run uses.
pub const TASK: u128 = 1;
pub const JOB: u128 = 10;

/// A redactor that scrubs [`SECRET`].
pub fn redactor() -> crustcore_secrets::Redactor {
    let mut r = crustcore_secrets::Redactor::new();
    r.register("sentinel", SECRET.as_bytes());
    r
}

/// Builds a clean session log:
/// - seq 1: TaskCreated (Internal)
/// - seq 2: JobLeased  (owner 7, Internal)
/// - seq 3: UserMessageQueued  (ModelVisible)
/// - seq 4: ToolCallCompleted  (Internal)
/// - seq 5: ModelOutputReceived containing the SECRET (ModelVisible)
///
/// A receipt anchored at seq 4 joins this log cleanly.
pub fn clean_log() -> EventLog {
    let mut log = EventLog::new();
    log.append(
        &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(TASK)),
        b"created",
    );
    log.append(
        &FrameMeta::new(2, EventKind::JobLeased)
            .task(TaskId(TASK))
            .job(JobId(JOB))
            .actor(Actor::Adapter),
        &LeaseOwner(7).0.to_le_bytes(),
    );
    log.append(
        &FrameMeta::new(3, EventKind::UserMessageQueued)
            .task(TaskId(TASK))
            .job(JobId(JOB))
            .actor(Actor::User)
            .visibility(Visibility::ModelVisible),
        b"please run the tests",
    );
    log.append(
        &FrameMeta::new(4, EventKind::ToolCallCompleted)
            .task(TaskId(TASK))
            .job(JobId(JOB))
            .actor(Actor::Adapter),
        b"tool result",
    );
    log.append(
        &FrameMeta::new(5, EventKind::ModelOutputReceived)
            .task(TaskId(TASK))
            .job(JobId(JOB))
            .actor(Actor::Model)
            .visibility(Visibility::ModelVisible),
        format!("done; the deploy key was {SECRET} (do not share)").as_bytes(),
    );
    log
}

/// A receipt anchored at seq 4 (the ToolCallCompleted frame) of [`clean_log`].
pub fn clean_receipt() -> ToolReceipt {
    receipt_at(4, TASK, JOB)
}

/// Mints a receipt anchored at `seq` for `task`/`job` via the public API.
pub fn receipt_at(seq: u64, task: u128, job: u128) -> ToolReceipt {
    let mut chain = ReceiptChain::new(MacKey::new([5u8; 32]));
    chain.mint(&ReceiptParams {
        task_id: TaskId(task),
        job_id: JobId(job),
        tool_call_id: ToolCallId(u128::from(seq)),
        tool_name: b"run_command",
        args: b"cargo test",
        result: b"tool result",
        artifacts: &[],
        event_seq: EventSeq(seq),
    })
}

/// The byte-length of each frame of [`clean_log`], in order, so tests can splice
/// raw bytes (the eventlog does not expose frame offsets).
pub fn frame_lengths() -> Vec<usize> {
    let metas: Vec<(FrameMeta, Vec<u8>)> = vec![
        (
            FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(TASK)),
            b"created".to_vec(),
        ),
        (
            FrameMeta::new(2, EventKind::JobLeased)
                .task(TaskId(TASK))
                .job(JobId(JOB))
                .actor(Actor::Adapter),
            LeaseOwner(7).0.to_le_bytes().to_vec(),
        ),
        (
            FrameMeta::new(3, EventKind::UserMessageQueued)
                .task(TaskId(TASK))
                .job(JobId(JOB))
                .actor(Actor::User)
                .visibility(Visibility::ModelVisible),
            b"please run the tests".to_vec(),
        ),
        (
            FrameMeta::new(4, EventKind::ToolCallCompleted)
                .task(TaskId(TASK))
                .job(JobId(JOB))
                .actor(Actor::Adapter),
            b"tool result".to_vec(),
        ),
        (
            FrameMeta::new(5, EventKind::ModelOutputReceived)
                .task(TaskId(TASK))
                .job(JobId(JOB))
                .actor(Actor::Model)
                .visibility(Visibility::ModelVisible),
            format!("done; the deploy key was {SECRET} (do not share)").into_bytes(),
        ),
    ];
    metas
        .into_iter()
        .map(|(m, p)| {
            let mut single = EventLog::new();
            single.append(&m, &p);
            single.bytes().len()
        })
        .collect()
}
