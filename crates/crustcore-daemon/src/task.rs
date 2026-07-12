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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use crustcore_policy::{Approved, GitHubWriteCap};

use crate::telegram::ChatId;

/// Maximum verify output we fold into a final status line (bounded — invariant 11,
/// §6.5). Verify output is untrusted (invariant 7); the runtime redacts before send.
const MAX_VERIFY_TAIL: usize = 1500;
static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

fn next_task_id() -> crustcore_types::TaskId {
    let counter = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
    let high = now_ts().as_millis() as u128;
    let low = ((std::process::id() as u128) << 32) | counter as u128;
    crustcore_types::TaskId((high << 64) | low)
}

fn task_state_root() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("CRUSTCORE_STATE") {
        return path.into();
    }
    if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        return std::path::PathBuf::from(path).join("crustcore");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home).join(".local/state/crustcore");
    }
    std::env::temp_dir().join("crustcore-state")
}

struct TaskAudit {
    log: crustcore_eventlog::EventLog,
    path: std::path::PathBuf,
}

impl TaskAudit {
    fn new(task: crustcore_types::TaskId) -> Self {
        TaskAudit {
            log: crustcore_eventlog::EventLog::new(),
            path: task_state_root()
                .join("runs")
                .join(format!("task-{:032x}.cclog", task.0)),
        }
    }

    fn append(
        &mut self,
        seq: u64,
        kind: crustcore_kernel::EventKind,
        task: crustcore_types::TaskId,
        job: Option<crustcore_types::JobId>,
        payload: &[u8],
    ) {
        let mut meta = crustcore_eventlog::FrameMeta::new(seq, kind)
            .actor(crustcore_kernel::Actor::Adapter)
            .visibility(crustcore_kernel::Visibility::Internal)
            .timestamp(now_ts())
            .task(task);
        if let Some(job) = job {
            meta = meta.job(job);
        }
        self.log.append(&meta, payload);
    }
}

fn read_owner_only_token(path: &std::path::Path) -> Result<zeroize::Zeroizing<String>, String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect GitHub token file: {error}"))?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > 16 * 1024 {
        return Err("GitHub token file must be a small regular file, not a symlink".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("GitHub token file permissions must be owner-only (0600)".into());
        }
    }
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(path).map_err(|error| format!("cannot read GitHub token file: {error}"))?,
    );
    let token = std::str::from_utf8(&bytes)
        .map_err(|_| "GitHub token file is not valid UTF-8".to_string())?;
    let token = token
        .strip_suffix("\r\n")
        .or_else(|| token.strip_suffix('\n'))
        .unwrap_or(token);
    if token.is_empty()
        || token.trim() != token
        || token.chars().any(|ch| matches!(ch, '\r' | '\n'))
    {
        return Err("GitHub token file must contain exactly one non-empty token".into());
    }
    Ok(zeroize::Zeroizing::new(token.to_string()))
}

fn valid_repo_slug(repo: &str) -> bool {
    if repo.is_empty() || repo.len() > 200 {
        return false;
    }
    let Some((owner, name)) = repo.split_once('/') else {
        return false;
    };
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && !matches!(segment, "." | "..")
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    };
    !name.contains('/') && valid_segment(owner) && valid_segment(name)
}

fn valid_git_branch(branch: &str) -> bool {
    !branch.is_empty()
        && branch.len() <= 255
        && branch != "@"
        && !branch.starts_with(['/', '.'])
        && !branch.ends_with(['/', '.'])
        && !branch.contains("..")
        && !branch.contains("//")
        && !branch.contains("@{")
        && branch.split('/').all(|segment| {
            !segment.is_empty()
                && !matches!(segment, "." | "..")
                && !segment.ends_with(".lock")
                && segment.bytes().all(|byte| {
                    byte.is_ascii_graphic()
                        && !matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
                })
        })
}

fn validate_pr_target(target: &PrTarget) -> Result<(), String> {
    if !valid_repo_slug(&target.repo) {
        return Err("PR repo must be a safe owner/name GitHub slug".into());
    }
    if !valid_git_branch(&target.base_branch) {
        return Err("PR base must be a valid Git branch name".into());
    }
    if !valid_git_branch(&format!(
        "{}/probe",
        target.branch_prefix.trim_end_matches('/')
    )) {
        return Err("PR branch prefix must be a valid Git branch prefix".into());
    }
    Ok(())
}

struct CredentialHelperLease {
    dir: std::path::PathBuf,
    helper_command: String,
}

impl CredentialHelperLease {
    fn create(task: crustcore_types::TaskId, repo: &str, token: &str) -> Result<Self, String> {
        use std::io::Write as _;

        let dir = std::path::PathBuf::from(format!(
            "/tmp/crustcore-credential-{}-{:032x}",
            std::process::id(),
            task.0
        ));
        let _ = std::fs::remove_dir_all(&dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(&dir)
                .map_err(|error| format!("cannot create credential-helper dir: {error}"))?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&dir)
            .map_err(|error| format!("cannot create credential-helper dir: {error}"))?;
        let helper = dir.join("helper");
        let executable = std::env::current_exe()
            .map_err(|error| format!("cannot locate daemon executable: {error}"))?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&executable, &helper)
            .map_err(|error| format!("cannot link credential helper: {error}"))?;
        #[cfg(not(unix))]
        std::fs::copy(&executable, &helper)
            .map_err(|error| format!("cannot copy credential helper: {error}"))?;

        let config = dir.join("config");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&config)
            .map_err(|error| format!("cannot create credential config: {error}"))?;
        let payload = zeroize::Zeroizing::new(format!("CCGH1\n{repo}\n{token}"));
        file.write_all(payload.as_bytes())
            .map_err(|error| format!("cannot write credential config: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync credential config: {error}"))?;
        Ok(CredentialHelperLease {
            helper_command: format!(
                "{} credential-helper {}",
                helper.display(),
                config.display()
            ),
            dir,
        })
    }
}

impl Drop for CredentialHelperLease {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn trusted_git(worktree: &crustcore_path::WorktreeRoot) -> std::process::Command {
    let mut command = std::process::Command::new("git");
    command
        .env_clear()
        .env(
            "PATH",
            "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
        )
        .env("HOME", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-C")
        .arg(worktree.as_path())
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(["-c", "commit.gpgSign=false"])
        .args(["-c", "core.fsmonitor=false"]);
    command
}

fn prepare_pr_commit(
    worktree: &crustcore_path::WorktreeRoot,
) -> Result<crustcore_backend::PatchRef, String> {
    let add = trusted_git(worktree)
        .args(["add", "-A", "--", "."])
        .output()
        .map_err(|error| format!("cannot stage verified candidate: {error}"))?;
    if !add.status.success() {
        return Err(format!(
            "staging verified candidate failed: {}",
            bound_tail(&String::from_utf8_lossy(&add.stderr))
        ));
    }
    let commit = trusted_git(worktree)
        .args([
            "-c",
            "user.name=CrustCore",
            "-c",
            "user.email=crustcore@localhost",
            "commit",
            "-q",
            "-m",
            "CrustCore verified candidate",
        ])
        .output()
        .map_err(|error| format!("cannot commit candidate: {error}"))?;
    if !commit.status.success() {
        return Err(format!(
            "candidate commit failed: {}",
            bound_tail(&String::from_utf8_lossy(&commit.stderr))
        ));
    }
    let head = trusted_git(worktree)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("cannot resolve candidate commit: {error}"))?;
    if !head.status.success() {
        return Err("cannot resolve candidate commit".into());
    }
    Ok(crustcore_backend::PatchRef {
        diff_hash: crustcore_types::hash::sha256(&head.stdout),
    })
}

fn push_and_create_pr(
    cap: &Approved<GitHubWriteCap>,
    intent: &crustcore_backend::integrate::PrIntent,
    worktree: &crustcore_path::WorktreeRoot,
    target: &PrTarget,
    task: crustcore_types::TaskId,
) -> Result<crustcore_net::github::PrCreated, String> {
    use crustcore_net::github::{GitHubApi as _, RestGitHub, GITHUB_API};
    use std::rc::Rc;

    let push = crate::github::PushRequest::new(
        target.repo.clone(),
        crate::github::GITHUB_HOST,
        false,
        vec![format!("HEAD:refs/heads/{}", intent.head_branch)],
    );
    crate::github::validate_push(cap.value(), &push)
        .map_err(|error| format!("push policy refused: {error:?}"))?;

    let token = read_owner_only_token(&target.credential_file)?;
    let helper = CredentialHelperLease::create(task, &target.repo, token.as_str())?;
    let mut command = trusted_git(worktree);
    command.args(crate::github::confining_git_config(&helper.helper_command));
    let remote = format!("https://github.com/{}.git", target.repo);
    let pushed = command
        .args([
            "push",
            "--porcelain",
            "--",
            &remote,
            &format!("HEAD:refs/heads/{}", intent.head_branch),
        ])
        .output()
        .map_err(|error| format!("cannot launch confined git push: {error}"))?;
    if !pushed.status.success() {
        return Err(format!(
            "git push failed: {}",
            bound_tail(&String::from_utf8_lossy(&pushed.stderr))
        ));
    }

    let credentials =
        Rc::new(crustcore_net::credsource::StaticCredentials::new().with("github", token.as_str()));
    let api = RestGitHub::new(
        GITHUB_API,
        "github",
        Rc::new(crustcore_net::transport::UreqClient::new()),
        credentials,
    );
    api.create_pull(&crate::github::pr_intent_to_create_request(intent))
        .map_err(|error| format!("GitHub draft PR creation failed: {error}"))
}

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
    /// Owner-only file containing a fine-grained PAT or short-lived installation
    /// token. The path is operator configuration; bytes never enter a model,
    /// sandbox environment, argv, log, or worktree.
    pub credential_file: std::path::PathBuf,
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
    use crustcore_kernel::EventKind;
    use crustcore_policy::{PolicySnapshot, RiskProfile};
    use crustcore_receipts::join::{verify_against_log, FrameRef};
    use crustcore_receipts::{MacKey, ReceiptChain};
    use crustcore_sandbox::SandboxProfile;
    use crustcore_types::hash::sha256;
    use crustcore_types::{EventSeq, JobId, ScopeId, ToolCallId};
    use crustcore_worktree::WorktreeManager;

    // Resolve the verify spec up front (before any side effect): explicit program+args,
    // or detection from the repo shape. No shell — an untrusted value can't smuggle a
    // second command (invariant 7).
    let verify_spec = match resolve_verify(spec) {
        Ok(s) => s,
        Err(e) => return format!("⛔ {e}"),
    };
    if matches!(spec.backend, TaskBackend::Native) && !goal.trim().is_empty() {
        return "⛔ native is verify-only; configure codex, claude, or cmd for coding tasks."
            .to_string();
    }
    if let Some(target) = &spec.pr {
        if let Err(error) = validate_pr_target(target) {
            return format!("⛔ invalid PR configuration: {error}");
        }
    }

    let task = next_task_id();
    let job = JobId(task.0);
    let mut audit = TaskAudit::new(task);
    audit.append(1, EventKind::TaskCreated, task, None, b"task created");
    audit.append(2, EventKind::JobQueued, task, Some(job), b"job queued");
    let key = match MacKey::load_or_create(&task_state_root().join("receipt.key")) {
        Ok(key) => key,
        Err(error) => return format!("⛔ receipt key unavailable: {error}"),
    };
    let manager = WorktreeManager::new(&spec.repo_root);
    let worktree = match manager.create_for(task) {
        Ok(w) => w,
        Err(e) => {
            audit.append(3, EventKind::TaskFailed, task, None, b"task failed");
            let _ = audit.log.store_atomic(&audit.path);
            return format!("❌ could not create worktree: {e}");
        }
    };
    audit.append(3, EventKind::JobLeased, task, Some(job), b"job leased");
    let _ = tx.send("📂 worktree ready…".to_string());

    let profile = SandboxProfile::default_sandboxed();
    let cap = PolicySnapshot::new(RiskProfile::Supervised)
        .authorize_reversible(ScopeId(1))
        .expect("supervised policy permits sandboxed task execution")
        .sandbox_exec(profile.id);

    // Cancel before producing the patch — cheapest abort point (worktree only).
    if cancel.load(Ordering::SeqCst) {
        audit.append(4, EventKind::TaskKilled, task, None, b"task cancelled");
        let _ = audit.log.store_atomic(&audit.path);
        let _ = manager.remove(&worktree);
        return "⛔ CANCELLED before work started.".to_string();
    }

    // Produce the candidate patch reference. Native = the worktree HEAD (the canonical
    // repo is untouched). A worker runs sandboxed with no secrets; CrustCore re-derives
    // the real diff and takes only the (unverified) patch reference — the worker's
    // self-claim is never authority (invariants 6, 7).
    let mut patch: PatchRef = match &spec.backend {
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
                    audit.append(4, EventKind::TaskFailed, task, Some(job), b"task failed");
                    let _ = audit.log.store_atomic(&audit.path);
                    let _ = manager.remove(&worktree);
                    return format!("❌ WORKER REJECTED: {}", bound_tail(&e.to_string()));
                }
            }
        }
    };

    let prepared_branch = if let Some(cap) = pr_cap {
        let prefix = cap.value().branch_prefix().0.as_str();
        let branch = format!("{prefix}/chat-{:032x}", task.0);
        match prepare_pr_commit(&worktree) {
            Ok(committed) => patch = committed,
            Err(error) => {
                audit.append(4, EventKind::TaskFailed, task, Some(job), b"commit failed");
                let _ = audit.log.store_atomic(&audit.path);
                let _ = manager.remove(&worktree);
                return format!("⛔ PR candidate preparation failed: {error}");
            }
        }
        Some(branch)
    } else {
        None
    };

    // Cancel before the (expensive) verify run.
    if cancel.load(Ordering::SeqCst) {
        audit.append(
            4,
            EventKind::PatchProposed,
            task,
            Some(job),
            b"patch proposed",
        );
        audit.append(5, EventKind::TaskKilled, task, None, b"task cancelled");
        let _ = audit.log.store_atomic(&audit.path);
        let _ = manager.remove(&worktree);
        return "⛔ CANCELLED before verify.".to_string();
    }

    let _ = tx.send(format!("🔬 verifying: {}…", verify_spec.display()));

    audit.append(
        4,
        EventKind::PatchProposed,
        task,
        Some(job),
        b"patch proposed",
    );
    audit.append(
        5,
        EventKind::ToolCallStarted,
        task,
        Some(job),
        b"verify started",
    );
    let mut receipts = ReceiptChain::new(key);
    let ids = VerifyIds {
        task_id: task,
        job_id: job,
        tool_call_id: ToolCallId(1),
        event_seq: EventSeq(6),
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
            let receipt = verified.receipt().clone();
            audit.append(
                6,
                EventKind::ToolCallCompleted,
                task,
                Some(job),
                &receipt.to_bytes(),
            );
            audit.append(
                7,
                EventKind::PatchVerified,
                task,
                Some(job),
                b"patch verified",
            );
            let frames: Vec<FrameRef> = audit
                .log
                .iter()
                .map(|decoded| FrameRef {
                    seq: decoded.frame.seq,
                    tool_completed: decoded.frame.kind == EventKind::ToolCallCompleted,
                    task_id: decoded.frame.task_id,
                    job_id: decoded.frame.job_id,
                })
                .collect();
            if !receipts.verify(std::slice::from_ref(&receipt)).is_intact()
                || !verify_against_log(&[receipt], &frames).is_joined()
            {
                let _ = manager.remove(&worktree);
                return "⛔ audit receipt/event-log join failed; task not completed.".to_string();
            }
            if let Err(error) = audit.log.store_atomic(&audit.path) {
                let _ = manager.remove(&worktree);
                return format!("⛔ audit persistence failed; task not completed: {error}");
            }
            match pr_cap {
                Some(cap) => {
                    let branch = prepared_branch
                        .as_deref()
                        .expect("PR authority always prepares a branch before verify");
                    match open_draft_pr(cap, *verified, spec, &verify_spec, &worktree, branch, task)
                    {
                        Ok(message) => {
                            audit.append(
                                8,
                                EventKind::GitHubOperationCompleted,
                                task,
                                Some(job),
                                b"draft PR opened",
                            );
                            audit.append(
                                9,
                                EventKind::TaskCompleted,
                                task,
                                None,
                                b"task completed",
                            );
                            if let Err(error) = audit.log.store_atomic(&audit.path) {
                                format!(
                                    "⛔ draft PR opened but final audit persistence failed: {error}"
                                )
                            } else {
                                message
                            }
                        }
                        Err(error) => {
                            audit.append(
                                8,
                                EventKind::TaskFailed,
                                task,
                                None,
                                b"integration failed",
                            );
                            let _ = audit.log.store_atomic(&audit.path);
                            format!("⛔ verified, but draft PR integration failed: {error}")
                        }
                    }
                }
                None => {
                    audit.append(8, EventKind::TaskCompleted, task, None, b"task completed");
                    if let Err(error) = audit.log.store_atomic(&audit.path) {
                        return format!("⛔ audit persistence failed; task not completed: {error}");
                    }
                    let _completion = complete_task(*verified);
                    format!(
                        "✅ VERIFIED — '{}' passed; task completed.",
                        verify_spec.display()
                    )
                }
            }
        }
        VerifyOutcome::Failed { status, output } => {
            audit.append(
                6,
                EventKind::CommandCompleted,
                task,
                Some(job),
                b"verify failed",
            );
            audit.append(
                7,
                EventKind::PatchRejected,
                task,
                Some(job),
                b"patch rejected",
            );
            audit.append(8, EventKind::TaskFailed, task, None, b"task failed");
            let _ = audit.log.store_atomic(&audit.path);
            format!(
                "❌ VERIFY FAILED ({status:?}): {}",
                bound_tail(output.as_str())
            )
        }
        VerifyOutcome::Refused(reason) => {
            audit.append(6, EventKind::TaskFailed, task, None, b"verify refused");
            let _ = audit.log.store_atomic(&audit.path);
            format!("⛔ VERIFY REFUSED: {}", bound_tail(&reason))
        }
    };

    // Tear down the disposable worktree on every path (best-effort).
    let _ = manager.remove(&worktree);
    summary
}

/// Consumes verifier evidence, pushes the exact committed candidate through the
/// confined credential helper, and opens a real draft PR. No raw token enters the
/// sandbox, worktree, argv, environment, log, or returned status.
fn open_draft_pr(
    cap: &Approved<GitHubWriteCap>,
    verified: crustcore_backend::VerifiedPatch,
    spec: &TaskSpec,
    verify_spec: &crustcore_backend::verify::VerifySpec,
    worktree: &crustcore_path::WorktreeRoot,
    head_branch: &str,
    task: crustcore_types::TaskId,
) -> Result<String, String> {
    use crustcore_backend::integrate::open_pr;

    let target = spec
        .pr
        .as_ref()
        .ok_or_else(|| "PR target disappeared before integration".to_string())?;
    let intent = open_pr(cap, verified, head_branch, &target.base_branch, now_ts())
        .map_err(|error| format!("PR policy refused: {error}"))?;
    let created = push_and_create_pr(cap, &intent, worktree, target, task)?;
    Ok(format!(
        "✅ VERIFIED — '{}' passed. Draft PR #{} opened: {}",
        verify_spec.display(),
        created.number,
        bound_tail(&created.html_url)
    ))
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

    #[test]
    fn pr_candidate_is_committed_before_verification() {
        let dir = std::env::temp_dir().join(format!("cc-pr-commit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .current_dir(&dir)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .args(args)
                .status()
                .unwrap()
                .success()
        };
        assert!(git(&["init", "-q"]));
        std::fs::write(dir.join("file.txt"), b"before\n").unwrap();
        assert!(git(&["add", "."]));
        assert!(git(&[
            "-c",
            "user.name=ci",
            "-c",
            "user.email=ci@localhost",
            "commit",
            "-q",
            "-m",
            "init",
        ]));
        std::fs::write(dir.join("file.txt"), b"after\n").unwrap();
        let root = crustcore_path::WorktreeRoot::open(&dir).unwrap();
        let patch = prepare_pr_commit(&root).unwrap();
        assert_ne!(patch.diff_hash, [0u8; 32]);
        let status = trusted_git(&root)
            .args(["status", "--porcelain"])
            .output()
            .unwrap();
        assert!(status.status.success());
        assert!(status.stdout.is_empty(), "committed tree must be clean");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_file_must_be_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("cc-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, b"github_pat_TEST").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_owner_only_token(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_owner_only_token(&path).unwrap().as_str(),
            "github_pat_TEST"
        );
        std::fs::write(&path, b" github_pat_TEST\n").unwrap();
        assert!(read_owner_only_token(&path).is_err());
        std::fs::write(&path, b"github_pat_TEST\nextra\n").unwrap();
        assert!(read_owner_only_token(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pr_configuration_rejects_slug_and_ref_injection() {
        assert!(valid_repo_slug("owner/name"));
        assert!(!valid_repo_slug("owner/name\nTOKEN"));
        assert!(!valid_repo_slug("owner/name/extra"));
        assert!(valid_git_branch("release/next"));
        assert!(!valid_git_branch("main\ncredential.helper=evil"));
        assert!(!valid_git_branch("refs/../main"));
        let target = PrTarget {
            repo: "owner/name".to_string(),
            base_branch: "main".to_string(),
            branch_prefix: "crustcore".to_string(),
            credential_file: "/tmp/token".into(),
        };
        assert!(validate_pr_target(&target).is_ok());
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
        let line = run_one_task(&pass, "", &cancel, &tx, None);
        assert!(line.starts_with("✅ VERIFIED"), "got: {line}");

        let fail = TaskSpec {
            repo_root: std::path::PathBuf::from(&repo),
            verify: vec!["false".to_string()],
            backend: TaskBackend::Native,
            pr: None,
        };
        let line = run_one_task(&fail, "", &cancel, &tx, None);
        assert!(line.starts_with("❌ VERIFY FAILED"), "got: {line}");
    }
}
