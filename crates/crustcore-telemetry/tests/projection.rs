// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the C6 read-only projection over synthetic
//! `EventLog` + receipt fixtures: mapping, bounding, visibility/redaction gating,
//! receipt binding (P5-join), and read-only behavior. (C6T.1–C6T.6, dims (c)–(f).)

use crustcore_eventlog::{EventLog, FrameMeta, RedactionState};
use crustcore_kernel::{Actor, EventKind, Visibility};
use crustcore_receipts::{MacKey, ReceiptChain, ReceiptParams, ToolReceipt};
use crustcore_secrets::Redactor;
use crustcore_telemetry::{run_log, Config, Emitted, InMemoryExporter};
use crustcore_types::{EventSeq, JobId, TaskId, Timestamp, ToolCallId};

/// Builds a small, realistic log: a model request/response, a tool start/complete,
/// and a patch verification — and the matching receipt for the tool completion.
fn fixture() -> (EventLog, Vec<ToolReceipt>) {
    let mut log = EventLog::new();
    let mv = |seq, kind| {
        FrameMeta::new(seq, kind)
            .task(TaskId(1))
            .job(JobId(2))
            .actor(Actor::Adapter)
            .visibility(Visibility::ModelVisible)
            .timestamp(Timestamp::from_millis(seq * 100))
    };
    log.append(&mv(1, EventKind::ModelRequestStarted), b"req");
    log.append(&mv(2, EventKind::ModelOutputReceived), b"resp");
    log.append(&mv(3, EventKind::ToolCallStarted), b"start");
    log.append(&mv(4, EventKind::ToolCallCompleted), b"done");
    log.append(&mv(5, EventKind::PatchVerified), b"verified");

    // Receipt anchored to the ToolCallCompleted frame at seq 4.
    let mut chain = ReceiptChain::new(MacKey::new([3u8; 32]));
    let r = chain.mint(&ReceiptParams {
        task_id: TaskId(1),
        job_id: JobId(2),
        tool_call_id: ToolCallId(77),
        tool_name: b"run_command",
        args: b"cargo test",
        result: b"done",
        artifacts: &[],
        event_seq: EventSeq(4),
    });
    (log, vec![r])
}

fn drive(log: &EventLog, receipts: &[ToolReceipt]) -> InMemoryExporter {
    let mut exp = InMemoryExporter::new();
    let report = run_log(
        log,
        receipts,
        0,
        u64::MAX,
        &Config::enabled_in_memory(),
        &Redactor::new(),
        &mut exp,
    );
    assert_eq!(report.frames_seen, 5);
    exp
}

#[test]
fn each_kind_maps_to_its_expected_span_name() {
    let (log, receipts) = fixture();
    let exp = drive(&log, &receipts);
    let names: Vec<&str> = exp.spans().iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "gen_ai.model_request",
            "gen_ai.model_response",
            "crustcore.tool.started",
            "crustcore.tool.completed",
            "crustcore.verify.verified",
        ]
    );
}

#[test]
fn model_spans_carry_genai_attributes() {
    let (log, receipts) = fixture();
    let exp = drive(&log, &receipts);
    let req = exp
        .spans()
        .into_iter()
        .find(|s| s.name == "gen_ai.model_request")
        .unwrap();
    assert!(req
        .attrs
        .iter()
        .any(|(k, v)| k == "gen_ai.system" && v == "crustcore"));
    assert!(req.attrs.iter().any(|(k, _)| k == "gen_ai.operation.name"));
}

#[test]
fn tool_completed_span_is_receipt_bound_via_join() {
    let (log, receipts) = fixture();
    let exp = drive(&log, &receipts);
    let tool = exp
        .spans()
        .into_iter()
        .find(|s| s.name == "crustcore.tool.completed")
        .unwrap();
    // Receipt MAC/hashes bound; the receipt's event_seq is recorded.
    assert!(tool.attrs.iter().any(|(k, _)| k == "crustcore.tool.mac"));
    assert!(tool
        .attrs
        .iter()
        .any(|(k, v)| k == "crustcore.tool.receipt_event_seq" && v == "4"));
    // The raw tool name/result/args are NOT present (only hashes; invariant 10).
    assert!(!tool.attrs.iter().any(|(_, v)| v == "run_command"));
    assert!(!tool.attrs.iter().any(|(_, v)| v == "cargo test"));
}

#[test]
fn forged_receipt_seq_does_not_bind_to_an_unrelated_span() {
    // A receipt that anchors to a NON-tool frame (seq 1 = ModelRequestStarted) must
    // not join, so no span is receipt-bound (dimension (c)/(f): a forged seq cannot
    // inject receipt attributes).
    let (log, _good) = fixture();
    let mut chain = ReceiptChain::new(MacKey::new([3u8; 32]));
    let forged = chain.mint(&ReceiptParams {
        task_id: TaskId(1),
        job_id: JobId(2),
        tool_call_id: ToolCallId(1),
        tool_name: b"x",
        args: b"y",
        result: b"z",
        artifacts: &[],
        event_seq: EventSeq(1), // not a ToolCallCompleted frame
    });
    let mut exp = InMemoryExporter::new();
    run_log(
        &log,
        &[forged],
        0,
        u64::MAX,
        &Config::enabled_in_memory(),
        &Redactor::new(),
        &mut exp,
    );
    // The join fails, so the tool span records the receipt as absent.
    let tool = exp
        .spans()
        .into_iter()
        .find(|s| s.name == "crustcore.tool.completed")
        .unwrap();
    assert!(tool
        .attrs
        .iter()
        .any(|(k, v)| k == "crustcore.tool.receipt" && v == "absent"));
}

#[test]
fn internal_visibility_frame_emits_only_kind_and_seq() {
    let mut log = EventLog::new();
    log.append(
        &FrameMeta::new(1, EventKind::ModelOutputReceived)
            .task(TaskId(1))
            .visibility(Visibility::Internal),
        b"internal-secret-bearing",
    );
    let mut exp = InMemoryExporter::new();
    run_log(
        &log,
        &[],
        0,
        u64::MAX,
        &Config::enabled_in_memory(),
        &Redactor::new(),
        &mut exp,
    );
    let s = exp.spans();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].attrs.len(), 2);
    assert!(!s[0].attrs.iter().any(|(k, _)| k == "gen_ai.system"));
    assert!(!s[0].attrs.iter().any(|(k, _)| k == "crustcore.task_id"));
}

#[test]
fn redacted_state_frame_emits_no_payload_derived_attributes() {
    let mut log = EventLog::new();
    log.append(
        &FrameMeta::new(1, EventKind::ToolCallCompleted)
            .task(TaskId(1))
            .visibility(Visibility::ModelVisible)
            .redaction(RedactionState::Redacted),
        b"x",
    );
    // Even with a matching receipt, a Redacted frame suppresses receipt attrs.
    let mut chain = ReceiptChain::new(MacKey::new([3u8; 32]));
    let r = chain.mint(&ReceiptParams {
        task_id: TaskId(1),
        job_id: JobId(1),
        tool_call_id: ToolCallId(1),
        tool_name: b"t",
        args: b"a",
        result: b"r",
        artifacts: &[],
        event_seq: EventSeq(1),
    });
    let mut exp = InMemoryExporter::new();
    run_log(
        &log,
        &[r],
        0,
        u64::MAX,
        &Config::enabled_in_memory(),
        &Redactor::new(),
        &mut exp,
    );
    let s = exp.spans();
    assert_eq!(s[0].attrs.len(), 2);
    assert!(!s[0].attrs.iter().any(|(k, _)| k == "crustcore.tool.mac"));
}

#[test]
fn range_filter_bounds_the_frames_projected() {
    let (log, receipts) = fixture();
    let mut exp = InMemoryExporter::new();
    // Only seqs 3..=4 (tool start + complete).
    run_log(
        &log,
        &receipts,
        3,
        4,
        &Config::enabled_in_memory(),
        &Redactor::new(),
        &mut exp,
    );
    let names: Vec<&str> = exp.spans().iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["crustcore.tool.started", "crustcore.tool.completed"]
    );
}

#[test]
fn projection_is_read_only_log_and_receipts_unchanged() {
    // Dimension (f): the run mints nothing and mutates nothing.
    let (log, receipts) = fixture();
    let bytes_before = log.bytes().to_vec();
    let head_before = log.head_hash();
    let receipts_before = receipts.clone();

    let mut exp = InMemoryExporter::new();
    run_log(
        &log,
        &receipts,
        0,
        u64::MAX,
        &Config::enabled_in_memory(),
        &Redactor::new(),
        &mut exp,
    );

    // The log is byte-for-byte identical and still verifies; receipts unchanged.
    assert_eq!(log.bytes(), bytes_before.as_slice());
    assert_eq!(log.head_hash(), head_before);
    assert!(log.verify().is_intact());
    assert_eq!(receipts, receipts_before);
    // And a second identical run produces identical output (idempotent).
    let mut exp2 = InMemoryExporter::new();
    run_log(
        &log,
        &receipts,
        0,
        u64::MAX,
        &Config::enabled_in_memory(),
        &Redactor::new(),
        &mut exp2,
    );
    assert_eq!(exp.emitted(), exp2.emitted());
}

#[test]
fn disabled_by_default_emits_nothing_fail_closed() {
    // Dimension (g): fail-closed when unconfigured.
    let (log, receipts) = fixture();
    let mut exp = InMemoryExporter::new();
    let report = run_log(
        &log,
        &receipts,
        0,
        u64::MAX,
        &Config::default(), // enabled = false
        &Redactor::new(),
        &mut exp,
    );
    assert_eq!(report.frames_seen, 0);
    assert!(exp.emitted().is_empty());
}

#[test]
fn span_count_is_bounded_against_an_adversarially_large_log() {
    // Dimension (e): batch_bound caps work regardless of log size.
    let mut log = EventLog::new();
    for seq in 1..=5000u64 {
        log.append(
            &FrameMeta::new(seq, EventKind::ModelRequestStarted)
                .task(TaskId(1))
                .visibility(Visibility::ModelVisible),
            b"x",
        );
    }
    let cfg = Config {
        batch_bound: 100,
        ..Config::enabled_in_memory()
    };
    let mut exp = InMemoryExporter::new();
    let report = run_log(&log, &[], 0, u64::MAX, &cfg, &Redactor::new(), &mut exp);
    assert_eq!(report.frames_seen, 100);
    assert!(matches!(exp.emitted()[0], Emitted::Span(_)));
    assert_eq!(exp.spans().len(), 100);
}
