// SPDX-License-Identifier: Apache-2.0
//! The chat-launched verified task runner (the "do the work" half of the chat
//! front door). When the conversational front door decides a turn is a *task*
//! (not chatter), the runtime spawns a [`TaskHandle`] here: it runs the SAME
//! verifier-owned flow as `crustcore run` — a disposable worktree, the worker (or
//! native HEAD), then a sandboxed rerun of the verify command — and completes the
//! task **only** on a verifier-minted `VerifiedPatch` (invariant 13). Nothing here
//! authorizes, integrates, or talks to the user directly; it streams bounded status
//! lines back to the runtime over an `mpsc` channel, and the runtime renders them
//! through the redactor before they reach any channel (invariants 2, 5, 15).
//!
//! The whole module is compiled only under the `live` feature (it links the
//! sandbox/worktree/backend/receipt stack). The threading core ([`TaskHandle`] +
//! [`TaskHandle::spawn_with`]) is generic over the work closure, so the
//! channel/cancel/done/join mechanics are unit-tested with a fake closure — no real
//! I/O, no sandbox backend, no git repo. The real verified flow ([`run_one_task`])
//! gets one `#[ignore]`d end-to-end test (it needs a sandbox backend + a git repo).
#![cfg(feature = "live")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use crustcore_policy::{Approved, GitHubWriteCap};

use crate::telegram::ChatId;

/// Maximum verify output we fold into a final status line (bounded — invariant 11,
/// §6.5). Verify output is untrusted (invariant 7); the runtime redacts before send.
const MAX_VERIFY_TAIL: usize = 1500;

/// The coding backend for a chat-launched task. `Native` verifies the worktree as it
/// stands (its HEAD is the verified state); the others run an external worker that
/// proposes a change first, which the verifier alone may accept (invariants 6, 13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskBackend {
    /// No external worker: verify the worktree as-is.
    Native,
    /// Codex CLI worker.
    Codex,
    /// Claude Code worker.
    ClaudeCode,
    /// A generic external worker: `program` + literal `args` (no shell).
    Cmd(String, Vec<String>),
}

/// Where a verified chat task may open a **draft** PR (`--open-pr`/`--repo`/`--base`/
/// `--branch-prefix`). Present only when the operator enabled PR mode; the daemon gates
/// every launch on a human approval (invariant 14) and mints the `Approved<GitHubWriteCap>`
/// the verified task consumes. The strings are config (not model/comment input;
/// invariant 17): `repo` is `owner/name`, `base_branch` the PR target, `branch_prefix`
/// the prefix the head branch is confined under.
#[derive(Debug, Clone)]
pub struct PrTarget {
    /// `owner/name` of the repository to open the PR against.
    pub repo: String,
    /// The base branch the PR targets (e.g. `main`).
    pub base_branch: String,
    /// The branch prefix the head branch is confined under (e.g. `crustcore`).
    pub branch_prefix: String,
}

/// What a chat-launched task runs against: the repo, the verify command (split into
/// program + literal args, **no shell** — invariant 7; empty means "detect from the
/// repo shape"), the coding backend, and (optionally) the draft-PR target. Bound at
/// runtime startup from `--dir` / `--verify` / `--backend` / `--open-pr`, then cloned
/// per launch.
#[derive(Debug, Clone)]
pub struct TaskSpec {
    /// The repository root the task operates on.
    pub repo_root: std::path::PathBuf,
    /// The verify command: program + args, already split (no shell). Empty = detect.
    pub verify: Vec<String>,
    /// The coding backend that produces the candidate change.
    pub backend: TaskBackend,
    /// Where a verified task may open a draft PR. `None` = verify-and-complete only (no
    /// PR, no approval gate). `Some` = the launch is gated on approval and a verified
    /// patch opens a draft PR.
    pub pr: Option<PrTarget>,
}

/// A running chat-launched task: one OS thread streaming bounded status lines back to
/// the runtime. The handle is non-blocking to poll ([`drain`](Self::drain),
/// [`finished`](Self::finished)) and cooperatively cancellable
/// ([`cancel`](Self::cancel)). It owns a cancel flag and a done flag shared with the
/// thread; [`Drop`] sets cancel and **joins** the thread, so no task thread is ever
/// detached.
pub struct TaskHandle {
    chat: ChatId,
    rx: Receiver<String>,
    cancel: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl TaskHandle {
    /// Spawns the real verified flow for `goal` in `spec.repo_root`, addressed to
    /// `chat`. Runs [`run_one_task`] on a dedicated thread, streaming bounded status
    /// lines over the channel. The thread is the generic [`spawn_with`](Self::spawn_with)
    /// core; the work closure simply runs the verified flow.
    ///
    /// `pr_cap` is the human-approved GitHub write authority (`Some` only when the
    /// operator enabled PR mode and the launch was approved — invariant 14). It moves
    /// into the task thread (it is `Send` data), so the `VerifiedPatch` is produced and
    /// consumed by `open_pr` in the same place — it never has to outlive the approval or
    /// cross a thread boundary.
    #[must_use]
    pub fn spawn(
        spec: TaskSpec,
        goal: String,
        chat: ChatId,
        pr_cap: Option<Approved<GitHubWriteCap>>,
    ) -> TaskHandle {
        Self::spawn_with(chat, move |cancel, tx| {
            run_one_task(&spec, &goal, cancel, tx, pr_cap.as_ref())
        })
    }

    /// The generic threading core, testable without any real I/O. Spawns a thread that
    /// runs `work(&cancel, &tx)`; the returned `String` is sent as the final status
    /// line, then the done flag is set. The cancel flag is shared with the caller so
    /// [`cancel`](Self::cancel) (and [`Drop`]) can ask a cooperating `work` to stop.
    ///
    /// `work` receives the cancel flag and the status sender; it does **not** redact —
    /// the runtime renders every line through the redactor before it leaves the process
    /// (invariants 2, 15).
    #[must_use]
    pub fn spawn_with<F>(chat: ChatId, work: F) -> TaskHandle
    where
        F: FnOnce(&AtomicBool, &Sender<String>) -> String + Send + 'static,
    {
        let (tx, rx) = mpsc::channel::<String>();
        let cancel = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));

        let thread_cancel = Arc::clone(&cancel);
        let thread_done = Arc::clone(&done);
        let join = std::thread::spawn(move || {
            let final_line = work(&thread_cancel, &tx);
            // Best-effort: the receiver may already be gone if the handle was dropped.
            let _ = tx.send(final_line);
            // Publish "done" only after the final line is queued, so a reader that sees
            // `finished()` true is guaranteed the last `drain()` includes the summary.
            thread_done.store(true, Ordering::SeqCst);
        });

        TaskHandle {
            chat,
            rx,
            cancel,
            done,
            join: Some(join),
        }
    }

    /// Non-blocking: returns the status lines produced since the last call, in order.
    /// Never blocks on the worker thread.
    #[must_use]
    pub fn drain(&self) -> Vec<String> {
        self.rx.try_iter().collect()
    }

    /// Whether the worker thread has finished (its final line is already queued for the
    /// next [`drain`](Self::drain)). Non-blocking.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    /// Requests cooperative cancellation. A cooperating worker checks the flag at safe
    /// points and tears down cleanly; this never force-kills the thread.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// The chat this task reports to. The runtime addresses every streamed line here.
    #[must_use]
    pub fn chat(&self) -> ChatId {
        self.chat
    }
}

impl Drop for TaskHandle {
    /// Signals cancellation and joins the worker thread — no task thread is ever left
    /// detached. A cooperating worker observes the flag and tears its worktree down;
    /// the join then waits for that teardown to finish.
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Runs one chat-launched task through the SAME verifier-owned flow as `crustcore run`
/// (`crates/crustcore/src/main.rs`): create a disposable worktree, produce a candidate
/// `PatchRef` (native = worktree HEAD; worker = run it sandboxed and take its re-derived
/// patch), then rerun the verify command in a clean sandbox and complete the task
/// **only** on a verifier-minted `VerifiedPatch` (invariant 13). The disposable worktree
/// is **removed on every path**. Cancellation is honored at the safe points (before the
/// worker runs and before verify) — cooperative, never a force-kill.
///
/// Returns a single bounded summary line. Progress lines are streamed over `tx` as the
/// flow advances. This function never redacts; the runtime renders each line through the
/// redactor before it leaves the process (invariants 2, 15).
fn run_one_task(
    spec: &TaskSpec,
    goal: &str,
    cancel: &AtomicBool,
    tx: &Sender<String>,
    pr_cap: Option<&Approved<GitHubWriteCap>>,
) -> String {
    use crustcore_backend::verify::{run_verify, VerifyIds, VerifyOutcome};
    use crustcore_backend::{complete_task, PatchRef};
    use crustcore_policy::SandboxExecCap;
    use crustcore_receipts::{MacKey, ReceiptChain};
    use crustcore_sandbox::SandboxProfile;
    use crustcore_types::hash::sha256;
    use crustcore_types::{EventSeq, JobId, ScopeId, TaskId, ToolCallId};
    use crustcore_worktree::WorktreeManager;

    // Resolve the verify spec up front (before any side effect): explicit program+args,
    // or detection from the repo shape. No shell — an untrusted value can't smuggle a
    // second command (invariant 7).
    let verify_spec = match resolve_verify(spec) {
        Ok(s) => s,
        Err(e) => return format!("⛔ {e}"),
    };

    let task = TaskId(1);
    let manager = WorktreeManager::new(&spec.repo_root);
    let worktree = match manager.create_for(task) {
        Ok(w) => w,
        Err(e) => return format!("❌ could not create worktree: {e}"),
    };
    let _ = tx.send("📂 worktree ready…".to_string());

    let cap = SandboxExecCap {
        profile: ScopeId(1),
        scope: ScopeId(1),
    };
    let profile = SandboxProfile::default_sandboxed();

    // Cancel before producing the patch — cheapest abort point (worktree only).
    if cancel.load(Ordering::SeqCst) {
        let _ = manager.remove(&worktree);
        return "⛔ CANCELLED before work started.".to_string();
    }

    // Produce the candidate patch reference. Native = the worktree HEAD (the canonical
    // repo is untouched). A worker runs sandboxed with no secrets; CrustCore re-derives
    // the real diff and takes only the (unverified) patch reference — the worker's
    // self-claim is never authority (invariants 6, 7).
    let patch: PatchRef = match &spec.backend {
        TaskBackend::Native => {
            let head = manager.head_commit(&worktree).unwrap_or_default();
            PatchRef {
                diff_hash: sha256(head.as_bytes()),
            }
        }
        TaskBackend::Codex | TaskBackend::ClaudeCode | TaskBackend::Cmd(_, _) => {
            use crustcore_backend::worker::{run_external_worker, WorkerInput};
            let _ = tx.send("🛠️ running worker (sandboxed)…".to_string());
            let coding = backend_for(&spec.backend);
            let input = WorkerInput::for_task(task, goal, &worktree);
            match run_external_worker(coding.as_ref(), &input, &worktree, &cap, &profile) {
                Ok(product) => product.patch.0,
                Err(e) => {
                    let _ = manager.remove(&worktree);
                    return format!("❌ WORKER REJECTED: {}", bound_tail(&e.to_string()));
                }
            }
        }
    };

    // Cancel before the (expensive) verify run.
    if cancel.load(Ordering::SeqCst) {
        let _ = manager.remove(&worktree);
        return "⛔ CANCELLED before verify.".to_string();
    }

    let _ = tx.send(format!("🔬 verifying: {}…", verify_spec.display()));

    let mut receipts = ReceiptChain::new(MacKey::new(run_key()));
    let ids = VerifyIds {
        task_id: task,
        job_id: JobId(1),
        tool_call_id: ToolCallId(1),
        event_seq: EventSeq(1),
        now: now_ts(),
    };

    // Capture the outcome BEFORE teardown so a teardown failure cannot mask it; the
    // worktree is then removed unconditionally (every path).
    let outcome = run_verify(
        &cap,
        &profile,
        &worktree,
        &verify_spec,
        patch,
        &mut receipts,
        &ids,
    );

    let summary = match outcome {
        VerifyOutcome::Verified(verified) => {
            // A verifier-minted patch (invariant 13). Two terminal paths:
            //  - PR mode (an approved cap): mint a *draft* PR intent from the verifier
            //    evidence under the human-approved capability (invariant 14). The intent
            //    is the completion for this task; the actual git push + GitHub REST POST
            //    are the reduced live socket (`TODO(P10-net-live)`).
            //  - otherwise: complete the task from the evidence (the original behavior).
            match pr_cap {
                Some(cap) => open_draft_pr(cap, *verified, spec, &verify_spec),
                None => {
                    let _completion = complete_task(*verified);
                    format!(
                        "✅ VERIFIED — '{}' passed; task completed.",
                        verify_spec.display()
                    )
                }
            }
        }
        VerifyOutcome::Failed { status, output } => {
            format!(
                "❌ VERIFY FAILED ({status:?}): {}",
                bound_tail(output.as_str())
            )
        }
        VerifyOutcome::Refused(reason) => {
            format!("⛔ VERIFY REFUSED: {}", bound_tail(&reason))
        }
    };

    // Tear down the disposable worktree on every path (best-effort).
    let _ = manager.remove(&worktree);
    summary
}

/// Opens a **draft** PR intent from a verifier-minted [`VerifiedPatch`] under the
/// human-approved `GitHubWriteCap` (invariants 13 + 14). The head branch is confined to
/// the cap's branch prefix; [`open_pr`](crustcore_backend::integrate::open_pr) re-checks
/// that and the approval expiry (defense-in-depth). The returned line reports the prepared
/// draft PR (title + branches); the actual git push of the head branch and the GitHub REST
/// `create_pull` are the reduced live socket (`TODO(P10-net-live)`) — they need real
/// credentials and a pushed branch, so they cannot run in CI.
fn open_draft_pr(
    cap: &Approved<GitHubWriteCap>,
    verified: crustcore_backend::VerifiedPatch,
    spec: &TaskSpec,
    verify_spec: &crustcore_backend::verify::VerifySpec,
) -> String {
    use crustcore_backend::integrate::open_pr;

    // Head branch is confined under the approved cap's prefix (open_pr re-checks it).
    let prefix = cap.value().branch_prefix.0.as_str();
    let head_branch = format!("{prefix}/chat-task");
    let base_branch = spec
        .pr
        .as_ref()
        .map(|p| p.base_branch.clone())
        .unwrap_or_else(|| "main".to_string());

    match open_pr(cap, verified, &head_branch, &base_branch, now_ts()) {
        Ok(intent) => format!(
            "✅ VERIFIED — '{}' passed. 📝 Draft PR prepared: {} → {} (\"{}\"). \
             The push + GitHub REST open is the live socket.",
            verify_spec.display(),
            intent.head_branch,
            intent.base_branch,
            intent.title
        ),
        Err(e) => format!("⛔ verified, but PR refused: {e}"),
    }
}

/// Resolves the verify spec for a task: explicit program + literal args (no shell —
/// invariant 7), or detection from the repo shape when empty.
fn resolve_verify(spec: &TaskSpec) -> Result<crustcore_backend::verify::VerifySpec, String> {
    use crustcore_backend::verify::VerifySpec;
    if let Some((program, args)) = spec.verify.split_first() {
        return Ok(VerifySpec::new(program.clone(), args.to_vec()));
    }
    VerifySpec::detect(&spec.repo_root).ok_or_else(|| {
        "no verify command given and none could be detected \
         (no Cargo.toml/package.json/Makefile)"
            .to_string()
    })
}

/// Builds the coding backend for an external-worker task. `Native` has no worker (the
/// caller never reaches here for it), but the match is total to keep the helper
/// standalone — and the fallback still cannot escape the sandbox.
fn backend_for(b: &TaskBackend) -> Box<dyn crustcore_backend::worker::CodingBackend> {
    use crustcore_backend::worker::{ClaudeCodeBackend, CodexBackend, ExternalCommandBackend};
    match b {
        TaskBackend::Codex => Box::new(CodexBackend::default()),
        TaskBackend::ClaudeCode => Box::new(ClaudeCodeBackend::default()),
        TaskBackend::Cmd(p, a) => Box::new(ExternalCommandBackend::new(p.clone(), a.clone())),
        TaskBackend::Native => Box::new(ExternalCommandBackend::new("true".to_string(), vec![])),
    }
}

/// A fresh per-run MAC key for the receipt chain. CrustCore holds this key; the model
/// never does, so receipts are unforgeable (invariant 10). Drawn from the OS RNG with a
/// clearly-marked dev fallback (mirrors `crustcore run`).
fn run_key() -> [u8; 32] {
    use std::io::Read as _;
    let mut key = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut key).is_ok() {
            return key;
        }
    }
    for (i, b) in key.iter_mut().enumerate() {
        *b = 0xC0u8 ^ (i as u8);
    }
    key
}

/// Wall-clock timestamp for stamping the verify run. Time enters at the adapter layer,
/// never inside the kernel.
fn now_ts() -> crustcore_types::Timestamp {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    crustcore_types::Timestamp::from_millis(ms)
}

/// Bounds an untrusted string to [`MAX_VERIFY_TAIL`] bytes for a status line, on a char
/// boundary, with an explicit truncation marker. Verify output is untrusted (invariant 7)
/// and must never balloon a status line.
fn bound_tail(s: &str) -> String {
    let s = s.trim();
    if s.len() <= MAX_VERIFY_TAIL {
        return s.to_string();
    }
    let mut end = MAX_VERIFY_TAIL;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… (truncated)", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Polls until `f()` is true or the deadline passes — keeps the threading tests from
    /// racing without an unbounded wait.
    fn wait_until(deadline: Duration, mut f: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if f() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        f()
    }

    #[test]
    fn spawn_with_streams_status_then_final_line_and_carries_chat() {
        let handle = TaskHandle::spawn_with(ChatId(42), |_cancel, tx| {
            tx.send("step one".to_string()).unwrap();
            tx.send("step two".to_string()).unwrap();
            "✅ done".to_string()
        });

        // chat() is preserved verbatim.
        assert_eq!(handle.chat(), ChatId(42));

        // The thread finishes; finished() flips true only after the final line is queued.
        assert!(
            wait_until(Duration::from_secs(5), || handle.finished()),
            "task should finish"
        );

        // drain() returns the streamed lines AND the final summary, in order.
        let lines = handle.drain();
        assert_eq!(lines, vec!["step one", "step two", "✅ done"]);
    }

    #[test]
    fn drain_is_incremental_between_calls() {
        // A closure that streams one line, waits to be cancelled, then streams a second.
        let handle = TaskHandle::spawn_with(ChatId(7), |cancel, tx| {
            tx.send("before".to_string()).unwrap();
            while !cancel.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            tx.send("after".to_string()).unwrap();
            "fin".to_string()
        });

        // First drain sees only what's been produced so far (not the post-cancel line).
        assert!(wait_until(Duration::from_secs(5), || {
            !handle.drain().is_empty() || handle.finished()
        }));
        // Now release the closure and let it finish.
        handle.cancel();
        assert!(wait_until(Duration::from_secs(5), || handle.finished()));
        let rest = handle.drain();
        assert!(
            rest.contains(&"fin".to_string()),
            "final line must arrive: {rest:?}"
        );
    }

    #[test]
    fn cancel_is_observed_by_a_spinning_worker_and_the_handle_finishes() {
        // A worker that spins on the cancel flag — proves cancel() is actually seen.
        let handle = TaskHandle::spawn_with(ChatId(1), |cancel, _tx| {
            while !cancel.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            "⛔ cancelled".to_string()
        });

        // Not finished while the worker spins.
        assert!(!handle.finished());
        handle.cancel();
        assert!(
            wait_until(Duration::from_secs(5), || handle.finished()),
            "cancel must be observed and the worker must exit"
        );
        assert_eq!(handle.drain(), vec!["⛔ cancelled".to_string()]);
    }

    #[test]
    fn drop_signals_cancel_and_joins_without_hanging() {
        // A worker that only exits when cancelled. Dropping the handle must set cancel
        // and join — if Drop didn't cancel, this would hang the test thread forever.
        let observed = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&observed);
        let handle = TaskHandle::spawn_with(ChatId(3), move |cancel, _tx| {
            while !cancel.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            seen.store(true, Ordering::SeqCst);
            "stopped".to_string()
        });
        drop(handle);
        // After drop returns, the worker observed cancellation and ran to completion.
        assert!(observed.load(Ordering::SeqCst));
    }

    #[test]
    fn bound_tail_clamps_untrusted_output() {
        let big = "x".repeat(MAX_VERIFY_TAIL * 3);
        let bounded = bound_tail(&big);
        assert!(bounded.len() <= MAX_VERIFY_TAIL + "… (truncated)".len());
        assert!(bounded.ends_with("… (truncated)"));
        // Short output is passed through (trimmed) untouched.
        assert_eq!(bound_tail("  ok  "), "ok");
    }

    #[test]
    fn task_spec_and_backend_derives_hold() {
        // Cheap guard on the public contract runtime.rs depends on (Clone/Eq).
        let spec = TaskSpec {
            repo_root: std::path::PathBuf::from("/tmp/repo"),
            verify: vec!["cargo".to_string(), "test".to_string()],
            backend: TaskBackend::Cmd("worker".to_string(), vec!["--go".to_string()]),
            pr: None,
        };
        let clone = spec.clone();
        assert_eq!(clone.verify, spec.verify);
        assert_eq!(clone.backend, spec.backend);
        assert_eq!(TaskBackend::Native, TaskBackend::Native);
        assert_ne!(TaskBackend::Native, TaskBackend::Codex);
    }

    // The real `run_one_task` needs a sandbox backend + a git repo worktree; it is
    // `#[ignore]`d (the reduced live seam). The threading core above is the CI-tested
    // part; this asserts the verified flow end to end on a host with a sandbox backend.
    #[test]
    #[ignore = "live: requires a sandbox backend + git repo worktree"]
    fn run_one_task_completes_only_on_verifier_evidence() {
        // On a host with a sandbox backend, in a git repo: a `true` verify passes (native
        // HEAD), a `false` verify fails — and only the pass yields a ✅ line.
        let repo = std::env::var("CRUSTCORE_TEST_REPO").unwrap_or_else(|_| ".".to_string());
        let (tx, _rx) = mpsc::channel();
        let cancel = AtomicBool::new(false);

        let pass = TaskSpec {
            repo_root: std::path::PathBuf::from(&repo),
            verify: vec!["true".to_string()],
            backend: TaskBackend::Native,
            pr: None,
        };
        let line = run_one_task(&pass, "goal", &cancel, &tx, None);
        assert!(line.starts_with("✅ VERIFIED"), "got: {line}");

        let fail = TaskSpec {
            repo_root: std::path::PathBuf::from(&repo),
            verify: vec!["false".to_string()],
            backend: TaskBackend::Native,
            pr: None,
        };
        let line = run_one_task(&fail, "goal", &cancel, &tx, None);
        assert!(line.starts_with("❌ VERIFY FAILED"), "got: {line}");
    }
}
