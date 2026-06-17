// SPDX-License-Identifier: Apache-2.0
//! Writes a small demo event log to the path in `argv[1]`, so you can try the
//! Phase 2 CLI:
//!
//! ```bash
//! cargo run -p crustcore --example write_demo_log -- /tmp/demo.cclog
//! cargo run -p crustcore -- inspect /tmp/demo.cclog
//! cargo run -p crustcore -- export  /tmp/demo.cclog
//! ```

use crustcore_eventlog::{EventLog, FrameMeta, RedactionState};
use crustcore_kernel::{Actor, EventKind, Visibility};
use crustcore_types::TaskId;

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: write_demo_log <path>");
            std::process::exit(2);
        }
    };

    let task = TaskId(1);
    let mut log = EventLog::new();
    log.append(
        &FrameMeta::new(1, EventKind::TaskCreated)
            .actor(Actor::Adapter)
            .task(task),
        b"goal: fix the failing test",
    );
    log.append(
        &FrameMeta::new(2, EventKind::JobQueued)
            .actor(Actor::Adapter)
            .task(task),
        b"job 1 queued",
    );
    log.append(
        &FrameMeta::new(3, EventKind::ModelOutputReceived)
            .actor(Actor::Model)
            .visibility(Visibility::ModelVisible)
            .redaction(RedactionState::Redacted)
            .task(task),
        b"(model output - redacted in export)",
    );
    log.append(
        &FrameMeta::new(4, EventKind::TaskCompleted)
            .actor(Actor::Kernel)
            .task(task),
        b"verified",
    );

    if let Err(e) = std::fs::write(&path, log.bytes()) {
        eprintln!("write_demo_log: cannot write {path}: {e}");
        std::process::exit(1);
    }
    eprintln!("wrote {} frame(s) to {path}", log.len());
}
