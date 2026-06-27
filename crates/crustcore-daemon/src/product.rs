// SPDX-License-Identifier: Apache-2.0
//! Product-layer contracts for the GitHub PR Supervisor.
//!
//! This module is deliberately **non-kernel** and always compiled in the daemon:
//! it gives the product surfaces stable, pure data contracts for repo onboarding,
//! task lifecycle rendering, executor capability metadata, and evidence bundles.
//! It mints no authority, opens no sockets, runs no tools, and constructs no
//! `VerifiedPatch`; the verifier-owned completion boundary remains in
//! `crustcore-backend`.

/// The repo-level profile file CrustCore looks for during onboarding.
pub const PROFILE_FILE: &str = "crustcore.yml";

/// The default branch prefix for machine-created branches.
pub const DEFAULT_BRANCH_PREFIX: &str = "crustcore";

/// The default base branch for draft PRs.
pub const DEFAULT_BASE_BRANCH: &str = "main";

/// Product policy posture selected by trusted setup, never by repo text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyMode {
    /// Read-only exploration; no writes.
    ReadOnly,
    /// Reversible local work may run; irreversible work asks.
    #[default]
    Supervised,
    /// Completion requires verifier evidence.
    Verified,
    /// Draft PR creation requires approval.
    Approved,
    /// Release-sensitive mode: strongest gates and human review.
    Release,
}

impl PolicyMode {
    /// Parses a profile token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match normalize_token(value).as_str() {
            "readonly" | "read_only" => Some(PolicyMode::ReadOnly),
            "supervised" => Some(PolicyMode::Supervised),
            "verified" => Some(PolicyMode::Verified),
            "approved" => Some(PolicyMode::Approved),
            "release" => Some(PolicyMode::Release),
            _ => None,
        }
    }
}

/// Risk tier for route budgets and review posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RiskTier {
    /// Low-risk docs or small local changes.
    Low,
    /// Normal small-team default.
    #[default]
    Standard,
    /// Security, auth, dependency, workflow, or broad refactor changes.
    High,
    /// Release, credential, branch-protection, or production-impacting changes.
    Critical,
}

impl RiskTier {
    /// Parses a profile token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match normalize_token(value).as_str() {
            "low" => Some(RiskTier::Low),
            "standard" | "normal" => Some(RiskTier::Standard),
            "high" => Some(RiskTier::High),
            "critical" => Some(RiskTier::Critical),
            _ => None,
        }
    }
}

/// Pluggable executor identities. These are capability descriptions, not authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutorKind {
    /// Built-in local verifier/native path.
    Native,
    /// Codex CLI or Codex-compatible worker.
    Codex,
    /// Claude Code worker.
    ClaudeCode,
    /// A local model loop controlled by CrustCore.
    LocalModel,
    /// A generic command worker.
    ExternalCommand,
    /// A curated MCP tool executor.
    McpTool,
}

impl ExecutorKind {
    /// Parses a profile token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match normalize_token(value).as_str() {
            "native" => Some(ExecutorKind::Native),
            "codex" => Some(ExecutorKind::Codex),
            "claude" | "claude_code" | "claudecode" => Some(ExecutorKind::ClaudeCode),
            "local" | "local_model" => Some(ExecutorKind::LocalModel),
            "cmd" | "external" | "external_command" => Some(ExecutorKind::ExternalCommand),
            "mcp" | "mcp_tool" => Some(ExecutorKind::McpTool),
            _ => None,
        }
    }

    /// Stable display label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ExecutorKind::Native => "native",
            ExecutorKind::Codex => "codex",
            ExecutorKind::ClaudeCode => "claude-code",
            ExecutorKind::LocalModel => "local-model",
            ExecutorKind::ExternalCommand => "external-command",
            ExecutorKind::McpTool => "mcp-tool",
        }
    }
}

/// Cost class for product routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostClass {
    /// Free or already-local.
    Local,
    /// Cheap remote/default route.
    Standard,
    /// Premium route for hard problems.
    Premium,
}

/// Context mode an executor can tolerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextMode {
    /// Small targeted context.
    Targeted,
    /// Large repo context.
    RepoScale,
    /// Whole project plus memory/RAG context.
    ProjectScale,
}

/// Trust posture of an executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPosture {
    /// In-process or local deterministic helper.
    LocalOnly,
    /// External worker; patch producer only.
    ExternalWorker,
    /// Tool gateway; calls are still policy/receipt gated.
    ToolGateway,
}

/// Product-facing executor metadata used by routing and UX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorCapability {
    /// Executor kind.
    pub kind: ExecutorKind,
    /// Languages or stacks this executor is preferred for.
    pub languages: Vec<String>,
    /// Relative cost class.
    pub cost: CostClass,
    /// Context capacity.
    pub context: ContextMode,
    /// Whether execution must happen under the sandbox boundary.
    pub sandbox_required: bool,
    /// Trust posture.
    pub trust: TrustPosture,
}

impl ExecutorCapability {
    /// Conservative default metadata for a configured executor.
    #[must_use]
    pub fn for_kind(kind: ExecutorKind) -> Self {
        match kind {
            ExecutorKind::Native => ExecutorCapability {
                kind,
                languages: vec!["any".to_string()],
                cost: CostClass::Local,
                context: ContextMode::Targeted,
                sandbox_required: true,
                trust: TrustPosture::LocalOnly,
            },
            ExecutorKind::Codex => ExecutorCapability {
                kind,
                languages: vec![
                    "rust".to_string(),
                    "typescript".to_string(),
                    "python".to_string(),
                ],
                cost: CostClass::Premium,
                context: ContextMode::RepoScale,
                sandbox_required: true,
                trust: TrustPosture::ExternalWorker,
            },
            ExecutorKind::ClaudeCode => ExecutorCapability {
                kind,
                languages: vec![
                    "rust".to_string(),
                    "typescript".to_string(),
                    "python".to_string(),
                ],
                cost: CostClass::Premium,
                context: ContextMode::ProjectScale,
                sandbox_required: true,
                trust: TrustPosture::ExternalWorker,
            },
            ExecutorKind::LocalModel => ExecutorCapability {
                kind,
                languages: vec!["any".to_string()],
                cost: CostClass::Local,
                context: ContextMode::Targeted,
                sandbox_required: true,
                trust: TrustPosture::ExternalWorker,
            },
            ExecutorKind::ExternalCommand => ExecutorCapability {
                kind,
                languages: vec!["any".to_string()],
                cost: CostClass::Standard,
                context: ContextMode::Targeted,
                sandbox_required: true,
                trust: TrustPosture::ExternalWorker,
            },
            ExecutorKind::McpTool => ExecutorCapability {
                kind,
                languages: vec!["any".to_string()],
                cost: CostClass::Standard,
                context: ContextMode::Targeted,
                sandbox_required: true,
                trust: TrustPosture::ToolGateway,
            },
        }
    }
}

/// Bounded product budget defaults for one supervised task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorBudgetProfile {
    /// Wall-clock cap in milliseconds.
    pub max_wall_ms: u64,
    /// Output cap in bytes.
    pub max_output_bytes: u64,
    /// Token cap.
    pub max_tokens: u64,
    /// Max bounded CI repair attempts.
    pub repair_attempts: u8,
}

impl Default for SupervisorBudgetProfile {
    fn default() -> Self {
        SupervisorBudgetProfile {
            max_wall_ms: 30 * 60 * 1000,
            max_output_bytes: 1 << 20,
            max_tokens: u64::MAX,
            repair_attempts: 2,
        }
    }
}

/// GitHub-facing product profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubProductProfile {
    /// Bound repo in `owner/name` form, if configured.
    pub repo: Option<String>,
    /// Base branch for draft PRs.
    pub base_branch: String,
    /// Whether verified tasks may open draft PRs after approval.
    pub open_draft_pr: bool,
    /// Labels CrustCore may apply to its own PRs/issues.
    pub labels: Vec<String>,
}

impl Default for GitHubProductProfile {
    fn default() -> Self {
        GitHubProductProfile {
            repo: None,
            base_branch: DEFAULT_BASE_BRANCH.to_string(),
            open_draft_pr: true,
            labels: vec!["crustcore".to_string(), "needs-human-review".to_string()],
        }
    }
}

/// UX surface toggles. These do not grant authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiProductProfile {
    /// Enable the local cockpit/dev UI.
    pub cockpit: bool,
    /// Enable Telegram as an operator channel.
    pub telegram: bool,
}

impl Default for UiProductProfile {
    fn default() -> Self {
        UiProductProfile {
            cockpit: true,
            telegram: false,
        }
    }
}

/// Repo-level `crustcore.yml` profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoProfile {
    /// Policy mode.
    pub policy_mode: PolicyMode,
    /// Risk tier.
    pub risk_tier: RiskTier,
    /// Branch prefix for machine branches.
    pub branch_prefix: String,
    /// Verification commands, in priority order.
    pub verify: Vec<String>,
    /// Allowed executors.
    pub executors: Vec<ExecutorKind>,
    /// Budget profile.
    pub budget: SupervisorBudgetProfile,
    /// GitHub profile.
    pub github: GitHubProductProfile,
    /// UI profile.
    pub ui: UiProductProfile,
}

impl Default for RepoProfile {
    fn default() -> Self {
        RepoProfile {
            policy_mode: PolicyMode::Supervised,
            risk_tier: RiskTier::Standard,
            branch_prefix: DEFAULT_BRANCH_PREFIX.to_string(),
            verify: Vec::new(),
            executors: vec![ExecutorKind::Native],
            budget: SupervisorBudgetProfile::default(),
            github: GitHubProductProfile::default(),
            ui: UiProductProfile::default(),
        }
    }
}

impl RepoProfile {
    /// Parses the conservative YAML subset used by `crustcore.yml`.
    ///
    /// Supported shapes:
    /// - top-level scalars: `policy_mode`, `risk_tier`, `branch_prefix`
    /// - top-level lists: `verify`, `executors`, `labels`
    /// - nested scalars under `budget`, `github`, and `ui`
    ///
    /// Unknown keys fail closed so a misspelled policy field cannot look active.
    ///
    /// # Errors
    /// Returns a line-addressed parse error for unknown keys, bad values, or
    /// malformed entries.
    pub fn parse(input: &str) -> Result<Self, ProfileError> {
        let mut out = RepoProfile::default();
        let mut section = Section::Top;

        for (idx, raw) in input.lines().enumerate() {
            let line_no = idx + 1;
            let without_comment = raw.split_once('#').map_or(raw, |(before, _)| before);
            if without_comment.trim().is_empty() {
                continue;
            }
            let indented = without_comment.starts_with(' ') || without_comment.starts_with('\t');
            let line = without_comment.trim();

            if let Some(item) = line.strip_prefix("- ") {
                match section {
                    Section::Verify => push_nonempty(&mut out.verify, item, line_no)?,
                    Section::Executors => out.executors.push(parse_executor(item, line_no)?),
                    Section::Labels => push_nonempty(&mut out.github.labels, item, line_no)?,
                    _ => {
                        return Err(ProfileError::new(
                            line_no,
                            "list item is not inside verify/executors/labels",
                        ))
                    }
                }
                continue;
            }

            let (key, value) = split_key_value(line, line_no)?;
            if value.is_empty() {
                section = Section::parse(key).ok_or_else(|| {
                    ProfileError::new(line_no, format!("unknown section '{key}'"))
                })?;
                if section == Section::Labels {
                    out.github.labels.clear();
                }
                if section == Section::Executors {
                    out.executors.clear();
                }
                continue;
            }

            if indented {
                apply_section_scalar(&mut out, section, key, value, line_no)?;
            } else {
                section = Section::Top;
                apply_top_scalar(&mut out, key, value, line_no)?;
            }
        }

        Ok(out)
    }

    /// Returns executor capability metadata for every configured executor.
    #[must_use]
    pub fn executor_capabilities(&self) -> Vec<ExecutorCapability> {
        self.executors
            .iter()
            .copied()
            .map(ExecutorCapability::for_kind)
            .collect()
    }
}

/// Parse failure for `crustcore.yml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError {
    /// 1-based line number.
    pub line: usize,
    /// Human-readable reason.
    pub reason: String,
}

impl ProfileError {
    fn new(line: usize, reason: impl Into<String>) -> Self {
        ProfileError {
            line,
            reason: reason.into(),
        }
    }
}

impl core::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}: {}", PROFILE_FILE, self.line, self.reason)
    }
}

impl std::error::Error for ProfileError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Top,
    Verify,
    Executors,
    Budget,
    Github,
    Ui,
    Labels,
}

impl Section {
    fn parse(value: &str) -> Option<Self> {
        match normalize_token(value).as_str() {
            "verify" => Some(Section::Verify),
            "executors" => Some(Section::Executors),
            "budget" | "budgets" => Some(Section::Budget),
            "github" => Some(Section::Github),
            "ui" => Some(Section::Ui),
            "labels" => Some(Section::Labels),
            _ => None,
        }
    }
}

fn apply_top_scalar(
    out: &mut RepoProfile,
    key: &str,
    value: &str,
    line: usize,
) -> Result<(), ProfileError> {
    match normalize_token(key).as_str() {
        "policy_mode" | "policy" => {
            out.policy_mode = PolicyMode::parse(value)
                .ok_or_else(|| ProfileError::new(line, format!("unknown policy_mode '{value}'")))?;
        }
        "risk_tier" | "risk" => {
            out.risk_tier = RiskTier::parse(value)
                .ok_or_else(|| ProfileError::new(line, format!("unknown risk_tier '{value}'")))?;
        }
        "branch_prefix" => {
            out.branch_prefix = clean_scalar(value).to_string();
            if out.branch_prefix.is_empty() {
                return Err(ProfileError::new(line, "branch_prefix cannot be empty"));
            }
        }
        "verify" => {
            out.verify.clear();
            for item in split_csv(value) {
                push_nonempty(&mut out.verify, item, line)?;
            }
        }
        "executors" => {
            out.executors.clear();
            for item in split_csv(value) {
                out.executors.push(parse_executor(item, line)?);
            }
        }
        "labels" => {
            out.github.labels.clear();
            for item in split_csv(value) {
                push_nonempty(&mut out.github.labels, item, line)?;
            }
        }
        "repo" => out.github.repo = Some(clean_scalar(value).to_string()),
        "base_branch" => out.github.base_branch = clean_scalar(value).to_string(),
        other => return Err(ProfileError::new(line, format!("unknown key '{other}'"))),
    }
    Ok(())
}

fn apply_section_scalar(
    out: &mut RepoProfile,
    section: Section,
    key: &str,
    value: &str,
    line: usize,
) -> Result<(), ProfileError> {
    match section {
        Section::Budget => match normalize_token(key).as_str() {
            "max_wall_ms" => out.budget.max_wall_ms = parse_u64(value, line, key)?,
            "max_output_bytes" => out.budget.max_output_bytes = parse_u64(value, line, key)?,
            "max_tokens" => out.budget.max_tokens = parse_u64(value, line, key)?,
            "repair_attempts" => {
                let attempts = parse_u64(value, line, key)?;
                out.budget.repair_attempts = u8::try_from(attempts)
                    .map_err(|_| ProfileError::new(line, "repair_attempts must fit in u8"))?;
            }
            other => {
                return Err(ProfileError::new(
                    line,
                    format!("unknown budget key '{other}'"),
                ))
            }
        },
        Section::Github => match normalize_token(key).as_str() {
            "repo" => out.github.repo = Some(clean_scalar(value).to_string()),
            "base_branch" => out.github.base_branch = clean_scalar(value).to_string(),
            "open_draft_pr" => out.github.open_draft_pr = parse_bool(value, line, key)?,
            "labels" => {
                out.github.labels.clear();
                for item in split_csv(value) {
                    push_nonempty(&mut out.github.labels, item, line)?;
                }
            }
            other => {
                return Err(ProfileError::new(
                    line,
                    format!("unknown github key '{other}'"),
                ))
            }
        },
        Section::Ui => match normalize_token(key).as_str() {
            "cockpit" => out.ui.cockpit = parse_bool(value, line, key)?,
            "telegram" => out.ui.telegram = parse_bool(value, line, key)?,
            other => return Err(ProfileError::new(line, format!("unknown ui key '{other}'"))),
        },
        Section::Verify => push_nonempty(&mut out.verify, value, line)?,
        Section::Executors => out.executors.push(parse_executor(value, line)?),
        Section::Labels => push_nonempty(&mut out.github.labels, value, line)?,
        Section::Top => apply_top_scalar(out, key, value, line)?,
    }
    Ok(())
}

fn split_key_value(line: &str, line_no: usize) -> Result<(&str, &str), ProfileError> {
    let Some((key, value)) = line.split_once(':') else {
        return Err(ProfileError::new(line_no, "expected key: value"));
    };
    let key = key.trim();
    if key.is_empty() {
        return Err(ProfileError::new(line_no, "empty key"));
    }
    Ok((key, value.trim()))
}

fn split_csv(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn parse_executor(value: &str, line: usize) -> Result<ExecutorKind, ProfileError> {
    ExecutorKind::parse(value)
        .ok_or_else(|| ProfileError::new(line, format!("unknown executor '{value}'")))
}

fn parse_u64(value: &str, line: usize, key: &str) -> Result<u64, ProfileError> {
    clean_scalar(value)
        .parse::<u64>()
        .map_err(|_| ProfileError::new(line, format!("{key} must be an unsigned integer")))
}

fn parse_bool(value: &str, line: usize, key: &str) -> Result<bool, ProfileError> {
    match normalize_token(value).as_str() {
        "true" | "yes" | "on" => Ok(true),
        "false" | "no" | "off" => Ok(false),
        _ => Err(ProfileError::new(line, format!("{key} must be true/false"))),
    }
}

fn push_nonempty(vec: &mut Vec<String>, value: &str, line: usize) -> Result<(), ProfileError> {
    let cleaned = clean_scalar(value);
    if cleaned.is_empty() {
        return Err(ProfileError::new(line, "list value cannot be empty"));
    }
    vec.push(cleaned.to_string());
    Ok(())
}

fn clean_scalar(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        if (bytes[0] == b'"' && bytes[trimmed.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[trimmed.len() - 1] == b'\'')
        {
            return &trimmed[1..trimmed.len() - 1];
        }
    }
    trimmed
}

fn normalize_token(value: &str) -> String {
    clean_scalar(value)
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
}

/// Product lifecycle states used by the cockpit, GitHub comments, and chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskLifecycle {
    /// Accepted but not started.
    Queued,
    /// Planning/verifier selection.
    Planning,
    /// Worker/model/tool execution.
    Executing,
    /// Verifier command is running.
    Verifying,
    /// Verified patch is being pushed/opened as a draft PR.
    OpeningPr,
    /// Draft PR checks are being watched.
    MonitoringCi,
    /// Bounded repair loop is running after CI failed.
    Repairing,
    /// Work stopped and needs operator action.
    Blocked,
    /// Completed with evidence.
    Completed,
}

impl TaskLifecycle {
    /// Stable label for UX and PR evidence.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            TaskLifecycle::Queued => "queued",
            TaskLifecycle::Planning => "planning",
            TaskLifecycle::Executing => "executing",
            TaskLifecycle::Verifying => "verifying",
            TaskLifecycle::OpeningPr => "opening-pr",
            TaskLifecycle::MonitoringCi => "monitoring-ci",
            TaskLifecycle::Repairing => "repairing",
            TaskLifecycle::Blocked => "blocked",
            TaskLifecycle::Completed => "completed",
        }
    }

    /// Whether this state is terminal.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, TaskLifecycle::Blocked | TaskLifecycle::Completed)
    }
}

/// CI/check state included in an evidence bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiState {
    /// No CI state recorded.
    Unknown,
    /// Checks are still running.
    Pending,
    /// Checks passed.
    Passed,
    /// Checks failed.
    Failed,
    /// Checks were intentionally not applicable.
    Skipped,
}

impl CiState {
    /// Stable label for UX and PR evidence.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            CiState::Unknown => "unknown",
            CiState::Pending => "pending",
            CiState::Passed => "passed",
            CiState::Failed => "failed",
            CiState::Skipped => "skipped",
        }
    }
}

/// One verifier command's evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandEvidenceLine {
    /// Command line shown to humans.
    pub command: String,
    /// Whether it passed.
    pub passed: bool,
    /// Bounded, redacted excerpt or short note.
    pub note: Option<String>,
}

impl CommandEvidenceLine {
    /// Creates a command evidence line.
    #[must_use]
    pub fn new(command: impl Into<String>, passed: bool) -> Self {
        CommandEvidenceLine {
            command: command.into(),
            passed,
            note: None,
        }
    }

    /// Attaches a bounded note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(bound(note.into(), 512));
        self
    }
}

/// Stable evidence artifact for one supervised task attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBundle {
    /// Stable run id.
    pub run_id: String,
    /// Current product lifecycle.
    pub lifecycle: TaskLifecycle,
    /// Verification plan label.
    pub verifier_plan: String,
    /// Verifier command evidence.
    pub commands: Vec<CommandEvidenceLine>,
    /// Verified patch hash, if a patch was verified.
    pub patch_hash: Option<String>,
    /// CI/check state.
    pub ci: CiState,
    /// Unresolved risks, redacted/bounded.
    pub risks: Vec<String>,
    /// Receipt/event-log references.
    pub receipts: Vec<String>,
    /// Event-log frame refs or external evidence refs.
    pub event_refs: Vec<String>,
}

impl EvidenceBundle {
    /// Creates an empty bundle for a run.
    #[must_use]
    pub fn new(run_id: impl Into<String>) -> Self {
        EvidenceBundle {
            run_id: run_id.into(),
            lifecycle: TaskLifecycle::Queued,
            verifier_plan: "not selected".to_string(),
            commands: Vec::new(),
            patch_hash: None,
            ci: CiState::Unknown,
            risks: Vec::new(),
            receipts: Vec::new(),
            event_refs: Vec::new(),
        }
    }

    /// Evaluates whether this bundle is strong enough to present as complete.
    #[must_use]
    pub fn verdict(&self) -> EvidenceVerdict {
        if self.lifecycle == TaskLifecycle::Blocked {
            return EvidenceVerdict::Blocked;
        }
        if self.commands.is_empty() {
            return EvidenceVerdict::NoVerifierEvidence;
        }
        if self.commands.iter().any(|c| !c.passed) {
            return EvidenceVerdict::FailedVerifier;
        }
        if self.patch_hash.as_deref().unwrap_or_default().is_empty() {
            return EvidenceVerdict::MissingPatch;
        }
        if self.ci == CiState::Failed {
            return EvidenceVerdict::CiFailed;
        }
        if self.receipts.is_empty() {
            return EvidenceVerdict::MissingReceipts;
        }
        EvidenceVerdict::Sufficient
    }

    /// Whether the bundle can be treated as complete product evidence.
    #[must_use]
    pub fn is_sufficient(&self) -> bool {
        self.verdict() == EvidenceVerdict::Sufficient
    }

    /// Renders the evidence block intended for a draft PR body.
    #[must_use]
    pub fn draft_pr_body(&self) -> String {
        let mut body = String::new();
        body.push_str("## CrustCore evidence-backed draft PR\n\n");
        body.push_str("Machine-produced change. Human review required before merge.\n\n");
        body.push_str(&format!("- Run: `{}`\n", bound(&self.run_id, 160)));
        body.push_str(&format!("- State: `{}`\n", self.lifecycle.label()));
        body.push_str(&format!(
            "- Evidence verdict: `{}`\n",
            self.verdict().label()
        ));
        body.push_str(&format!(
            "- Verifier plan: `{}`\n",
            bound(&self.verifier_plan, 240)
        ));
        body.push_str(&format!("- CI: `{}`\n", self.ci.label()));
        if let Some(hash) = &self.patch_hash {
            body.push_str(&format!("- Patch: `{}`\n", bound(hash, 128)));
        }
        body.push_str("\n### Verifier Commands\n");
        if self.commands.is_empty() {
            body.push_str("- none recorded\n");
        } else {
            for command in &self.commands {
                body.push_str(&format!(
                    "- `{}` - {}\n",
                    bound(&command.command, 240),
                    if command.passed { "passed" } else { "failed" }
                ));
            }
        }
        body.push_str("\n### Receipts\n");
        if self.receipts.is_empty() {
            body.push_str("- none recorded\n");
        } else {
            for receipt in &self.receipts {
                body.push_str(&format!("- `{}`\n", bound(receipt, 160)));
            }
        }
        if !self.risks.is_empty() {
            body.push_str("\n### Unresolved Risks\n");
            for risk in &self.risks {
                body.push_str(&format!("- {}\n", bound(risk, 240)));
            }
        }
        body
    }
}

/// Evidence completeness verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceVerdict {
    /// Strong enough for a completed task/draft PR.
    Sufficient,
    /// No verifier command evidence exists.
    NoVerifierEvidence,
    /// A verifier command failed.
    FailedVerifier,
    /// No verified patch hash was recorded.
    MissingPatch,
    /// No receipt/event-log evidence was recorded.
    MissingReceipts,
    /// CI failed and repair/attention is needed.
    CiFailed,
    /// The task is blocked.
    Blocked,
}

impl EvidenceVerdict {
    /// Stable label for UX and PR bodies.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            EvidenceVerdict::Sufficient => "sufficient",
            EvidenceVerdict::NoVerifierEvidence => "no-verifier-evidence",
            EvidenceVerdict::FailedVerifier => "failed-verifier",
            EvidenceVerdict::MissingPatch => "missing-patch",
            EvidenceVerdict::MissingReceipts => "missing-receipts",
            EvidenceVerdict::CiFailed => "ci-failed",
            EvidenceVerdict::Blocked => "blocked",
        }
    }
}

fn bound(value: impl AsRef<str>, max: usize) -> String {
    let s = value.as_ref();
    if s.len() <= max {
        return s.to_string();
    }
    let mut out = String::new();
    for ch in s.chars() {
        if out.len() + ch.len_utf8() > max {
            break;
        }
        out.push(ch);
    }
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_is_team_safe() {
        let profile = RepoProfile::default();
        assert_eq!(profile.policy_mode, PolicyMode::Supervised);
        assert_eq!(profile.risk_tier, RiskTier::Standard);
        assert_eq!(profile.branch_prefix, DEFAULT_BRANCH_PREFIX);
        assert_eq!(profile.github.base_branch, DEFAULT_BASE_BRANCH);
        assert_eq!(profile.executors, vec![ExecutorKind::Native]);
        assert_eq!(profile.budget.repair_attempts, 2);
    }

    #[test]
    fn parses_crustcore_yml_subset() {
        let parsed = RepoProfile::parse(
            r#"
policy_mode: verified
risk_tier: high
branch_prefix: crustcore/team
verify:
  - cargo test --workspace
  - cargo clippy --workspace -- -D warnings
executors:
  - codex
  - claude-code
budget:
  max_wall_ms: 900000
  max_output_bytes: 262144
  max_tokens: 200000
  repair_attempts: 3
github:
  repo: RNT56/CrustCore
  base_branch: main
  open_draft_pr: true
  labels: crustcore, evidence-backed
ui:
  cockpit: true
  telegram: false
"#,
        )
        .unwrap();

        assert_eq!(parsed.policy_mode, PolicyMode::Verified);
        assert_eq!(parsed.risk_tier, RiskTier::High);
        assert_eq!(parsed.branch_prefix, "crustcore/team");
        assert_eq!(
            parsed.verify,
            vec![
                "cargo test --workspace".to_string(),
                "cargo clippy --workspace -- -D warnings".to_string()
            ]
        );
        assert_eq!(
            parsed.executors,
            vec![ExecutorKind::Codex, ExecutorKind::ClaudeCode]
        );
        assert_eq!(parsed.budget.max_wall_ms, 900_000);
        assert_eq!(parsed.budget.repair_attempts, 3);
        assert_eq!(parsed.github.repo.as_deref(), Some("RNT56/CrustCore"));
        assert_eq!(
            parsed.github.labels,
            vec!["crustcore".to_string(), "evidence-backed".to_string()]
        );
        assert!(parsed.ui.cockpit);
        assert!(!parsed.ui.telegram);
    }

    #[test]
    fn profile_parser_fails_closed_on_unknown_keys_and_values() {
        let err = RepoProfile::parse("policy_mode: YOLO").unwrap_err();
        assert_eq!(err.line, 1);
        assert!(err.reason.contains("policy_mode"));

        let err = RepoProfile::parse("surprise: true").unwrap_err();
        assert_eq!(err.line, 1);
        assert!(err.reason.contains("unknown key"));

        let err = RepoProfile::parse("executors:\n  - unknown-agent\n").unwrap_err();
        assert_eq!(err.line, 2);
        assert!(err.reason.contains("unknown executor"));
    }

    #[test]
    fn executor_capabilities_are_metadata_not_authority() {
        let profile = RepoProfile {
            executors: vec![ExecutorKind::Codex, ExecutorKind::McpTool],
            ..RepoProfile::default()
        };
        let caps = profile.executor_capabilities();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].kind, ExecutorKind::Codex);
        assert_eq!(caps[0].trust, TrustPosture::ExternalWorker);
        assert!(caps[0].sandbox_required);
        assert_eq!(caps[1].trust, TrustPosture::ToolGateway);
    }

    #[test]
    fn lifecycle_labels_and_terminal_states_are_stable() {
        assert_eq!(TaskLifecycle::MonitoringCi.label(), "monitoring-ci");
        assert!(!TaskLifecycle::Verifying.is_terminal());
        assert!(TaskLifecycle::Blocked.is_terminal());
        assert!(TaskLifecycle::Completed.is_terminal());
    }

    #[test]
    fn evidence_requires_verifier_patch_and_receipts() {
        let mut bundle = EvidenceBundle::new("run-1");
        assert_eq!(bundle.verdict(), EvidenceVerdict::NoVerifierEvidence);

        bundle
            .commands
            .push(CommandEvidenceLine::new("cargo test", true));
        assert_eq!(bundle.verdict(), EvidenceVerdict::MissingPatch);

        bundle.patch_hash = Some("abc123".to_string());
        assert_eq!(bundle.verdict(), EvidenceVerdict::MissingReceipts);

        bundle.receipts.push("receipt:verify:1".to_string());
        assert_eq!(bundle.verdict(), EvidenceVerdict::Sufficient);
    }

    #[test]
    fn evidence_failed_verifier_ci_and_blocked_are_not_sufficient() {
        let mut failed = EvidenceBundle::new("run-failed");
        failed
            .commands
            .push(CommandEvidenceLine::new("cargo test", false));
        failed.patch_hash = Some("abc".to_string());
        failed.receipts.push("receipt".to_string());
        assert_eq!(failed.verdict(), EvidenceVerdict::FailedVerifier);

        let mut ci_failed = EvidenceBundle::new("run-ci");
        ci_failed
            .commands
            .push(CommandEvidenceLine::new("cargo test", true));
        ci_failed.patch_hash = Some("abc".to_string());
        ci_failed.receipts.push("receipt".to_string());
        ci_failed.ci = CiState::Failed;
        assert_eq!(ci_failed.verdict(), EvidenceVerdict::CiFailed);

        let mut blocked = ci_failed;
        blocked.lifecycle = TaskLifecycle::Blocked;
        assert_eq!(blocked.verdict(), EvidenceVerdict::Blocked);
    }

    #[test]
    fn draft_pr_body_is_evidence_first_and_review_gated() {
        let mut bundle = EvidenceBundle::new("run-42");
        bundle.lifecycle = TaskLifecycle::Completed;
        bundle.verifier_plan = "rust full gate".to_string();
        bundle.commands.push(
            CommandEvidenceLine::new("cargo test --workspace", true).with_note("all tests passed"),
        );
        bundle.patch_hash = Some("patch-deadbeef".to_string());
        bundle.ci = CiState::Passed;
        bundle.receipts.push("receipt:verify:42".to_string());
        bundle.event_refs.push("event:1..9".to_string());
        bundle
            .risks
            .push("No browser smoke for UI paths.".to_string());

        assert!(bundle.is_sufficient());
        let body = bundle.draft_pr_body();
        assert!(body.contains("Human review required before merge"));
        assert!(body.contains("cargo test --workspace"));
        assert!(body.contains("receipt:verify:42"));
        assert!(body.contains("No browser smoke"));
    }
}
