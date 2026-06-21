// SPDX-License-Identifier: Apache-2.0
//! Regenerates the committed on-disk event-log fixture used by the session tests.
//!
//! Run with: `cargo run -p crustcore-session --example gen_fixture`. The output is
//! a hash-chained `crustcore-eventlog` byte stream representing a small clean run
//! (the same shape the daemon produces). The fixture is committed so the tests can
//! load a real on-disk log rather than only synthesizing one in memory.

use crustcore_eventlog::{EventLog, FrameMeta};
use crustcore_kernel::{Actor, EventKind, Visibility};
use crustcore_types::{JobId, LeaseOwner, TaskId};

fn main() {
    let mut log = EventLog::new();
    log.append(
        &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(1)),
        b"created",
    );
    log.append(
        &FrameMeta::new(2, EventKind::JobLeased)
            .task(TaskId(1))
            .job(JobId(10))
            .actor(Actor::Adapter),
        &LeaseOwner(7).0.to_le_bytes(),
    );
    log.append(
        &FrameMeta::new(3, EventKind::UserMessageQueued)
            .task(TaskId(1))
            .job(JobId(10))
            .actor(Actor::User)
            .visibility(Visibility::ModelVisible),
        b"please run the tests",
    );
    log.append(
        &FrameMeta::new(4, EventKind::ToolCallCompleted)
            .task(TaskId(1))
            .job(JobId(10))
            .actor(Actor::Adapter),
        b"tool result",
    );
    log.append(
        &FrameMeta::new(5, EventKind::ModelOutputReceived)
            .task(TaskId(1))
            .job(JobId(10))
            .actor(Actor::Model)
            .visibility(Visibility::ModelVisible),
        b"done; verify passed",
    );

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures");
    std::fs::create_dir_all(dir).unwrap();
    let path = format!("{dir}/clean_session.cclog");
    std::fs::write(&path, log.bytes()).unwrap();
    println!(
        "wrote {} ({} frames, {} bytes)",
        path,
        log.len(),
        log.bytes().len()
    );
}
