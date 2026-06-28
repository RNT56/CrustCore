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

/// Stable evidence bundle export schema id.
pub const EVIDENCE_BUNDLE_SCHEMA: &str = "crustcore.evidence_bundle.v1";

const MAX_EVIDENCE_EXPORT_COMMANDS: usize = 32;
const MAX_EVIDENCE_EXPORT_RISKS: usize = 32;
const MAX_EVIDENCE_EXPORT_REFS: usize = 64;

// `crustcore.yml` is repo-controlled, **untrusted** input (invariant 7); its lists are
// bounded so a hostile profile cannot exhaust memory (invariant 11). A profile that exceeds
// any cap is *rejected*, never allocated past it.
const MAX_VERIFY_COMMANDS: usize = 32;
const MAX_EXECUTORS: usize = 8;
const MAX_LABELS: usize = 32;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
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
                    Section::Verify => {
                        push_nonempty(&mut out.verify, item, line_no, MAX_VERIFY_COMMANDS)?
                    }
                    Section::Executors => {
                        ensure_capacity(&out.executors, line_no, MAX_EXECUTORS)?;
                        out.executors.push(parse_executor(item, line_no)?);
                    }
                    Section::Labels => {
                        push_nonempty(&mut out.github.labels, item, line_no, MAX_LABELS)?
                    }
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

    /// Builds a deterministic verifier plan from trusted setup and repo signals.
    ///
    /// This is product guidance, not proof: executors may use the plan, but only
    /// the backend verifier can mint a `VerifiedPatch` after actually running
    /// commands in the sandbox.
    #[must_use]
    pub fn plan_verification(&self, signals: &RepoSignals, task: TaskShape) -> VerifierPlan {
        VerifierPlan::build(self, signals, task)
    }
}

/// Adapter-supplied repo facts used by verifier planning.
///
/// These facts are observations, not authority. They let the planner choose
/// conservative default commands and explain weak evidence before any task is
/// marked complete.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepoSignals {
    /// A Cargo manifest was detected.
    pub cargo_manifest: bool,
    /// A Node package manifest was detected.
    pub package_json: bool,
    /// A Python project manifest or pytest layout was detected.
    pub python_project: bool,
    /// A Makefile was detected.
    pub makefile: bool,
    /// A concrete browser/UI smoke command was detected.
    pub browser_smoke_command: Option<String>,
    /// A concrete dependency audit/security command was detected.
    pub dependency_audit_command: Option<String>,
    /// A concrete docs/lint command was detected.
    pub docs_check_command: Option<String>,
    /// Sanitized targeted verifier commands inferred from changed paths.
    pub targeted_commands: Vec<String>,
    /// A lockfile was detected for dependency-sensitive changes.
    pub lockfile: bool,
}

impl RepoSignals {
    /// Derives repo signals from adapter-provided path observations.
    ///
    /// This does not read the filesystem and does not trust repo content. It is
    /// a deterministic classifier over bounded path strings so live adapters,
    /// tests, and GitHub diffs can all feed the same product planner.
    #[must_use]
    pub fn from_paths<I, P>(paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let mut signals = RepoSignals::default();

        for raw_path in paths {
            let path = normalize_path(raw_path.as_ref());
            if path.is_empty() {
                continue;
            }
            let file = path.rsplit('/').next().unwrap_or(path.as_str());

            if file == "Cargo.toml" {
                signals.cargo_manifest = true;
            }
            if file == "package.json" {
                signals.package_json = true;
            }
            if is_python_project_marker(file) {
                signals.python_project = true;
            }
            if file == "Makefile" || file == "makefile" {
                signals.makefile = true;
            }
            if is_lockfile(file) {
                signals.lockfile = true;
            }
            if is_playwright_marker(&path, file) {
                signals.browser_smoke_command = Some("npx playwright test".to_string());
            } else if is_cypress_marker(&path, file) && signals.browser_smoke_command.is_none() {
                signals.browser_smoke_command = Some("npx cypress run".to_string());
            }
            if is_cargo_deny_marker(&path, file) {
                signals.dependency_audit_command = Some("cargo deny check".to_string());
            }
            if is_mdbook_marker(file) {
                signals.docs_check_command = Some("mdbook test".to_string());
            } else if is_markdownlint_marker(file) && signals.docs_check_command.is_none() {
                signals.docs_check_command = Some("markdownlint .".to_string());
            }
        }

        signals
    }

    /// Derives repo signals from repo-marker paths plus changed-file paths.
    ///
    /// Changed paths only contribute sanitized targeted verifier hints. They do
    /// not replace the full-suite gate and cannot by themselves prove a task.
    #[must_use]
    pub fn from_repo_and_changed_paths<RI, RP, CI, CP>(repo_paths: RI, changed_paths: CI) -> Self
    where
        RI: IntoIterator<Item = RP>,
        RP: AsRef<str>,
        CI: IntoIterator<Item = CP>,
        CP: AsRef<str>,
    {
        RepoSignals::from_paths(repo_paths).with_changed_path_hints(changed_paths)
    }

    /// Adds sanitized targeted verifier hints inferred from changed paths.
    #[must_use]
    pub fn with_changed_path_hints<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let mut commands = Vec::new();
        for raw_path in paths {
            add_changed_path_targeted_command(&self, raw_path.as_ref(), &mut commands);
        }
        for command in commands {
            push_unique_string(&mut self.targeted_commands, command);
        }
        self
    }

    /// Whether no useful repo signal was observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.cargo_manifest
            && !self.package_json
            && !self.python_project
            && !self.makefile
            && self.browser_smoke_command.is_none()
            && self.dependency_audit_command.is_none()
            && self.docs_check_command.is_none()
            && self.targeted_commands.is_empty()
            && !self.lockfile
    }
}

/// Product-level task shape used to decide task-specific verification gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaskShape {
    /// The task has not been classified yet.
    #[default]
    Unknown,
    /// A bug fix, expected to include or run a regression test.
    BugFix,
    /// A non-UI feature.
    Feature,
    /// A UI/browser-visible change.
    UiChange,
    /// A dependency or lockfile change.
    DependencyChange,
    /// Documentation-only change.
    DocsOnly,
    /// CI/workflow/policy automation change.
    WorkflowChange,
    /// Auth, secrets, sandbox, policy, or security-sensitive change.
    SecuritySensitive,
}

impl TaskShape {
    /// Classifies a task from changed paths when no stronger issue/intent signal
    /// is available.
    ///
    /// Path classification is intentionally conservative: sensitive and workflow
    /// paths win over UI/docs heuristics, and bug fixes are not inferred from
    /// filenames because that requires trusted task intent.
    #[must_use]
    pub fn from_changed_paths<I, P>(paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let mut saw_path = false;
        let mut all_docs = true;
        let mut saw_dependency = false;
        let mut saw_ui = false;

        for raw_path in paths {
            let path = normalize_path(raw_path.as_ref());
            if path.is_empty() {
                continue;
            }
            saw_path = true;

            if is_security_sensitive_path(&path) {
                return TaskShape::SecuritySensitive;
            }
            if is_workflow_path(&path) {
                return TaskShape::WorkflowChange;
            }
            if is_dependency_path(&path) {
                saw_dependency = true;
            }
            if is_ui_path(&path) {
                saw_ui = true;
            }
            if !is_docs_path(&path) {
                all_docs = false;
            }
        }

        if !saw_path {
            TaskShape::Unknown
        } else if saw_dependency {
            TaskShape::DependencyChange
        } else if saw_ui {
            TaskShape::UiChange
        } else if all_docs {
            TaskShape::DocsOnly
        } else {
            TaskShape::Feature
        }
    }

    /// Stable label for evidence and cockpit views.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            TaskShape::Unknown => "unknown",
            TaskShape::BugFix => "bug-fix",
            TaskShape::Feature => "feature",
            TaskShape::UiChange => "ui-change",
            TaskShape::DependencyChange => "dependency-change",
            TaskShape::DocsOnly => "docs-only",
            TaskShape::WorkflowChange => "workflow-change",
            TaskShape::SecuritySensitive => "security-sensitive",
        }
    }
}

/// A verifier gate the product expects for a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaskGate {
    /// Bug fixes should prove the regression path.
    RegressionTest,
    /// UI changes should have browser-visible smoke coverage when applicable.
    BrowserSmoke,
    /// Dependency changes should cover lockfile and security posture.
    DependencySafety,
    /// Docs-only changes may use a lighter docs/lint gate.
    DocsCheck,
    /// Non-doc changes should include a full-suite gate before completion.
    FullSuite,
    /// Workflow changes require typed approval and human review.
    WorkflowReview,
    /// Security-sensitive changes require stronger review.
    SecurityReview,
}

impl TaskGate {
    /// Stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            TaskGate::RegressionTest => "regression-test",
            TaskGate::BrowserSmoke => "browser-smoke",
            TaskGate::DependencySafety => "dependency-safety",
            TaskGate::DocsCheck => "docs-check",
            TaskGate::FullSuite => "full-suite",
            TaskGate::WorkflowReview => "workflow-review",
            TaskGate::SecurityReview => "security-review",
        }
    }
}

/// Planned command stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierCommandStage {
    /// Narrow command intended to fail fast before the full suite.
    Targeted,
    /// Completion gate command.
    Full,
    /// Human/operator review step represented in product UX.
    Review,
}

impl VerifierCommandStage {
    /// Stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            VerifierCommandStage::Targeted => "targeted",
            VerifierCommandStage::Full => "full",
            VerifierCommandStage::Review => "review",
        }
    }
}

/// One planned verifier command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedVerifierCommand {
    /// Command line to run later through the sandboxed verifier path.
    pub command: String,
    /// Why this command is ordered where it is.
    pub stage: VerifierCommandStage,
}

impl PlannedVerifierCommand {
    fn new(command: impl Into<String>, stage: VerifierCommandStage) -> Self {
        PlannedVerifierCommand {
            command: command.into(),
            stage,
        }
    }
}

/// Product-level evidence strength for a verifier plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceStrength {
    /// Missing or shallow evidence; cannot support completion language.
    Weak,
    /// Useful evidence, but with caveats or inferred defaults.
    Standard,
    /// Configured, task-appropriate evidence with no planner caveats.
    Strong,
}

impl EvidenceStrength {
    /// Stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            EvidenceStrength::Weak => "weak",
            EvidenceStrength::Standard => "standard",
            EvidenceStrength::Strong => "strong",
        }
    }
}

/// Deterministic verifier plan for a task attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierPlan {
    /// Human-readable plan label.
    pub label: String,
    /// Classified task shape.
    pub task: TaskShape,
    /// Commands ranked in the order they should be attempted.
    pub commands: Vec<PlannedVerifierCommand>,
    /// Gates expected for this task.
    pub gates: Vec<TaskGate>,
    /// Weak-evidence or approval warnings.
    pub warnings: Vec<String>,
    /// Planner assessment before commands actually run.
    pub strength: EvidenceStrength,
}

impl VerifierPlan {
    fn build(profile: &RepoProfile, signals: &RepoSignals, task: TaskShape) -> Self {
        let mut commands = Vec::new();
        let mut gates = Vec::new();
        let mut warnings = Vec::new();
        let mut weak_evidence = false;

        add_task_gates(task, &mut gates);
        if profile.risk_tier >= RiskTier::High {
            push_gate(&mut gates, TaskGate::SecurityReview);
        }
        if !matches!(task, TaskShape::DocsOnly) {
            push_gate(&mut gates, TaskGate::FullSuite);
        }

        add_signal_commands(signals, task, &mut commands);
        for command in &profile.verify {
            add_unique_command(&mut commands, command, classify_verifier_command(command));
        }
        if profile.verify.is_empty() {
            add_inferred_full_commands(signals, &mut commands);
        }

        if signals.is_empty() && profile.verify.is_empty() {
            warnings.push(
                "No repo stack or verifier command was detected; evidence is weak.".to_string(),
            );
            weak_evidence = true;
        }
        if commands.is_empty() {
            warnings.push(
                "No verifier command is configured or inferred; completion cannot be evidenced."
                    .to_string(),
            );
            weak_evidence = true;
        }
        if !matches!(task, TaskShape::DocsOnly) && !has_full_command(&commands) {
            warnings
                .push("No full-suite verifier command is planned before completion.".to_string());
            weak_evidence = true;
        }

        match task {
            TaskShape::BugFix => {
                if !has_test_command(&commands) {
                    warnings.push(
                        "Bug fixes need regression-test evidence; no test command is planned."
                            .to_string(),
                    );
                    weak_evidence = true;
                }
            }
            TaskShape::UiChange => {
                if signals.browser_smoke_command.is_none() && !has_browser_command(&commands) {
                    warnings.push(
                        "UI changes need browser smoke evidence; no browser smoke command is planned."
                            .to_string(),
                    );
                    weak_evidence = true;
                }
            }
            TaskShape::DependencyChange => {
                if !signals.lockfile {
                    warnings.push(
                        "Dependency changes need lockfile evidence; no lockfile signal was detected."
                            .to_string(),
                    );
                    weak_evidence = true;
                }
                if signals.dependency_audit_command.is_none() && !has_dependency_audit(&commands) {
                    warnings.push(
                        "Dependency changes need audit/security evidence; no audit command is planned."
                            .to_string(),
                    );
                    weak_evidence = true;
                }
            }
            TaskShape::DocsOnly => {
                if signals.docs_check_command.is_none()
                    && !commands.is_empty()
                    && !has_docs_command(&commands)
                {
                    warnings.push(
                        "Docs-only changes are using general verifier evidence; docs-specific checks were not detected."
                            .to_string(),
                    );
                }
            }
            TaskShape::WorkflowChange => warnings.push(
                "Workflow changes require typed approval and human review before integration."
                    .to_string(),
            ),
            TaskShape::SecuritySensitive => warnings.push(
                "Security-sensitive changes require stronger human review before integration."
                    .to_string(),
            ),
            TaskShape::Feature | TaskShape::Unknown => {}
        }

        let strength = if weak_evidence {
            EvidenceStrength::Weak
        } else if profile.verify.is_empty() || !warnings.is_empty() {
            EvidenceStrength::Standard
        } else {
            EvidenceStrength::Strong
        };

        VerifierPlan {
            label: format!("{} verifier plan ({})", task.label(), strength.label()),
            task,
            commands,
            gates,
            warnings,
            strength,
        }
    }

    /// Returns planned command lines for callers that do not need stage data.
    #[must_use]
    pub fn command_lines(&self) -> Vec<&str> {
        self.commands
            .iter()
            .map(|command| command.command.as_str())
            .collect()
    }
}

fn add_task_gates(task: TaskShape, gates: &mut Vec<TaskGate>) {
    match task {
        TaskShape::BugFix => push_gate(gates, TaskGate::RegressionTest),
        TaskShape::UiChange => push_gate(gates, TaskGate::BrowserSmoke),
        TaskShape::DependencyChange => push_gate(gates, TaskGate::DependencySafety),
        TaskShape::DocsOnly => push_gate(gates, TaskGate::DocsCheck),
        TaskShape::WorkflowChange => push_gate(gates, TaskGate::WorkflowReview),
        TaskShape::SecuritySensitive => push_gate(gates, TaskGate::SecurityReview),
        TaskShape::Feature | TaskShape::Unknown => {}
    }
}

fn push_gate(gates: &mut Vec<TaskGate>, gate: TaskGate) {
    if !gates.contains(&gate) {
        gates.push(gate);
    }
}

fn add_signal_commands(
    signals: &RepoSignals,
    task: TaskShape,
    commands: &mut Vec<PlannedVerifierCommand>,
) {
    for command in &signals.targeted_commands {
        add_unique_command(commands, command, VerifierCommandStage::Targeted);
    }
    if let Some(command) = &signals.browser_smoke_command {
        if matches!(task, TaskShape::UiChange) {
            add_unique_command(commands, command, VerifierCommandStage::Targeted);
        }
    }
    if let Some(command) = &signals.dependency_audit_command {
        if matches!(task, TaskShape::DependencyChange) {
            add_unique_command(commands, command, VerifierCommandStage::Targeted);
        }
    }
    if let Some(command) = &signals.docs_check_command {
        if matches!(task, TaskShape::DocsOnly) {
            add_unique_command(commands, command, VerifierCommandStage::Targeted);
        }
    }
}

fn add_inferred_full_commands(signals: &RepoSignals, commands: &mut Vec<PlannedVerifierCommand>) {
    if signals.cargo_manifest {
        add_unique_command(
            commands,
            "cargo test --workspace",
            VerifierCommandStage::Full,
        );
    }
    if signals.package_json {
        add_unique_command(commands, "npm test", VerifierCommandStage::Full);
    }
    if signals.python_project {
        add_unique_command(commands, "python -m pytest", VerifierCommandStage::Full);
    }
    if signals.makefile {
        add_unique_command(commands, "make test", VerifierCommandStage::Full);
    }
}

fn add_unique_command(
    commands: &mut Vec<PlannedVerifierCommand>,
    command: &str,
    stage: VerifierCommandStage,
) {
    let cleaned = clean_scalar(command);
    if cleaned.is_empty()
        || commands
            .iter()
            .any(|existing| existing.command.as_str() == cleaned)
    {
        return;
    }
    commands.push(PlannedVerifierCommand::new(cleaned, stage));
}

fn classify_verifier_command(command: &str) -> VerifierCommandStage {
    let normalized = normalize_command(command);
    if normalized.contains("manual review")
        || normalized.contains("manual_review")
        || normalized.contains("human review")
        || normalized.contains("human_review")
    {
        return VerifierCommandStage::Review;
    }
    if looks_full_command(&normalized) {
        VerifierCommandStage::Full
    } else {
        VerifierCommandStage::Targeted
    }
}

fn has_full_command(commands: &[PlannedVerifierCommand]) -> bool {
    commands
        .iter()
        .any(|command| command.stage == VerifierCommandStage::Full)
}

fn has_test_command(commands: &[PlannedVerifierCommand]) -> bool {
    commands
        .iter()
        .any(|command| normalize_command(&command.command).contains("test"))
}

fn has_browser_command(commands: &[PlannedVerifierCommand]) -> bool {
    commands.iter().any(|command| {
        let normalized = normalize_command(&command.command);
        normalized.contains("playwright")
            || normalized.contains("cypress")
            || normalized.contains("browser")
            || normalized.contains("e2e")
    })
}

fn has_dependency_audit(commands: &[PlannedVerifierCommand]) -> bool {
    commands.iter().any(|command| {
        let normalized = normalize_command(&command.command);
        normalized.contains("audit")
            || normalized.contains("cargo_deny")
            || normalized.contains("cargo-deny")
            || normalized.contains("cargo deny")
            || normalized.contains("pip_audit")
            || normalized.contains("pip-audit")
            || normalized.contains("safety")
    })
}

fn has_docs_command(commands: &[PlannedVerifierCommand]) -> bool {
    commands.iter().any(|command| {
        let normalized = normalize_command(&command.command);
        normalized.contains("docs") || normalized.contains("doc") || normalized.contains("md")
    })
}

fn looks_full_command(normalized: &str) -> bool {
    normalized.contains("xtask verify")
        || normalized.contains("test --workspace")
        || normalized.contains("cargo test")
        || normalized.contains("cargo nextest")
        || normalized.contains("pytest")
        || normalized.contains("npm test")
        || normalized.contains("pnpm test")
        || normalized.contains("yarn test")
        || normalized.contains("make test")
        || normalized.contains("clippy --workspace")
}

fn normalize_command(value: &str) -> String {
    clean_scalar(value).trim().to_ascii_lowercase()
}

fn normalize_path(value: &str) -> String {
    let normalized = clean_scalar(value).trim().replace('\\', "/");
    bound(normalized.trim_start_matches("./"), 512)
}

fn add_changed_path_targeted_command(
    signals: &RepoSignals,
    raw_path: &str,
    commands: &mut Vec<String>,
) {
    let path = normalize_path(raw_path);
    if path.is_empty() {
        return;
    }
    let Some(safe_path) = safe_command_path(&path) else {
        return;
    };
    let file = safe_path.rsplit('/').next().unwrap_or(safe_path.as_str());

    if signals.cargo_manifest && is_rust_changed_path(&safe_path, file) {
        if let Some(package) = safe_crates_package_name(&safe_path) {
            push_unique_string(commands, format!("cargo test -p {package}"));
        } else {
            push_unique_string(commands, "cargo test".to_string());
        }
    }

    if signals.python_project && is_python_test_path(&safe_path, file) {
        push_unique_string(commands, format!("python -m pytest {safe_path}"));
    }

    if signals.package_json && is_javascript_test_path(file) {
        push_unique_string(commands, format!("npm test -- {safe_path}"));
    }
}

fn push_unique_string(values: &mut Vec<String>, value: String) {
    let cleaned = clean_scalar(&value);
    if cleaned.is_empty() || values.iter().any(|existing| existing == cleaned) {
        return;
    }
    values.push(cleaned.to_string());
}

fn safe_command_path(path: &str) -> Option<String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('-')
        || path.contains("//")
        || path.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.starts_with('-')
                || !segment
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
        })
    {
        return None;
    }
    Some(path.to_string())
}

fn safe_crates_package_name(path: &str) -> Option<&str> {
    let mut segments = path.split('/');
    if segments.next()? != "crates" {
        return None;
    }
    let package = segments.next()?;
    if package.is_empty()
        || package.starts_with('-')
        || !package
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return None;
    }
    Some(package)
}

fn is_rust_changed_path(path: &str, file: &str) -> bool {
    file.ends_with(".rs") || path == "Cargo.toml" || file == "Cargo.toml"
}

fn is_python_test_path(path: &str, file: &str) -> bool {
    file.ends_with(".py")
        && (path.starts_with("tests/") || file.starts_with("test_") || file.ends_with("_test.py"))
}

fn is_javascript_test_path(file: &str) -> bool {
    file.ends_with(".test.js")
        || file.ends_with(".test.jsx")
        || file.ends_with(".test.ts")
        || file.ends_with(".test.tsx")
        || file.ends_with(".spec.js")
        || file.ends_with(".spec.jsx")
        || file.ends_with(".spec.ts")
        || file.ends_with(".spec.tsx")
}

fn is_python_project_marker(file: &str) -> bool {
    matches!(
        file,
        "pyproject.toml" | "setup.py" | "setup.cfg" | "requirements.txt" | "pytest.ini" | "tox.ini"
    )
}

fn is_lockfile(file: &str) -> bool {
    matches!(
        file,
        "Cargo.lock"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "poetry.lock"
            | "uv.lock"
            | "Pipfile.lock"
    )
}

fn is_playwright_marker(path: &str, file: &str) -> bool {
    file.starts_with("playwright.config.") || path.starts_with("tests/e2e/")
}

fn is_cypress_marker(path: &str, file: &str) -> bool {
    file.starts_with("cypress.config.") || path.starts_with("cypress/")
}

fn is_cargo_deny_marker(path: &str, file: &str) -> bool {
    file == "deny.toml" || file == "cargo-deny.toml" || path == ".cargo/deny.toml"
}

fn is_mdbook_marker(file: &str) -> bool {
    file == "book.toml"
}

fn is_markdownlint_marker(file: &str) -> bool {
    file == ".markdownlint.json" || file == ".markdownlint.yaml" || file == ".markdownlint.yml"
}

fn is_security_sensitive_path(path: &str) -> bool {
    path == "CLAUDE.md"
        || path == "AGENTS.md"
        || path == "INVARIANTS.md"
        || path == "SECURITY.md"
        || path == "THREAT_MODEL.md"
        || path.starts_with("docs/policy")
        || path.starts_with("docs/secrets")
        || path.starts_with("docs/sandbox")
        || path.starts_with("docs/backend-contract")
        || path.starts_with("crates/crustcore-kernel/")
        || path.starts_with("crates/crustcore-policy/")
        || path.starts_with("crates/crustcore-sandbox/")
        || path.starts_with("crates/crustcore-secrets/")
}

fn is_workflow_path(path: &str) -> bool {
    path.starts_with(".github/workflows/")
}

fn is_dependency_path(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    matches!(
        file,
        "Cargo.toml"
            | "Cargo.lock"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "pyproject.toml"
            | "poetry.lock"
            | "uv.lock"
            | "requirements.txt"
            | "Pipfile.lock"
    )
}

fn is_ui_path(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    path.starts_with("crates/crustcore-dev/")
        || path.starts_with("ui/")
        || path.starts_with("web/")
        || path.starts_with("frontend/")
        || file.ends_with(".tsx")
        || file.ends_with(".jsx")
        || file.ends_with(".css")
        || file.ends_with(".scss")
        || file.ends_with(".sass")
}

fn is_docs_path(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    path.starts_with("docs/")
        || matches!(
            file,
            "README.md" | "CHANGELOG.md" | "CONTRIBUTING.md" | "LICENSE" | "NOTICE"
        )
        || file.ends_with(".md")
        || file.ends_with(".mdx")
        || file.ends_with(".rst")
        || file.ends_with(".txt")
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
                push_nonempty(&mut out.verify, item, line, MAX_VERIFY_COMMANDS)?;
            }
        }
        "executors" => {
            out.executors.clear();
            for item in split_csv(value) {
                ensure_capacity(&out.executors, line, MAX_EXECUTORS)?;
                out.executors.push(parse_executor(item, line)?);
            }
        }
        "labels" => {
            out.github.labels.clear();
            for item in split_csv(value) {
                push_nonempty(&mut out.github.labels, item, line, MAX_LABELS)?;
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
                    push_nonempty(&mut out.github.labels, item, line, MAX_LABELS)?;
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
        Section::Verify => push_nonempty(&mut out.verify, value, line, MAX_VERIFY_COMMANDS)?,
        Section::Executors => {
            ensure_capacity(&out.executors, line, MAX_EXECUTORS)?;
            out.executors.push(parse_executor(value, line)?);
        }
        Section::Labels => push_nonempty(&mut out.github.labels, value, line, MAX_LABELS)?,
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

fn push_nonempty(
    vec: &mut Vec<String>,
    value: &str,
    line: usize,
    max: usize,
) -> Result<(), ProfileError> {
    if vec.len() >= max {
        return Err(ProfileError::new(
            line,
            format!("too many list entries (max {max})"),
        ));
    }
    let cleaned = clean_scalar(value);
    if cleaned.is_empty() {
        return Err(ProfileError::new(line, "list value cannot be empty"));
    }
    vec.push(cleaned.to_string());
    Ok(())
}

/// Bound an untrusted list before a `push` of a non-string element (e.g. an executor).
fn ensure_capacity<T>(vec: &[T], line: usize, max: usize) -> Result<(), ProfileError> {
    if vec.len() >= max {
        Err(ProfileError::new(
            line,
            format!("too many list entries (max {max})"),
        ))
    } else {
        Ok(())
    }
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

    /// Creates a planning-stage bundle from a verifier plan.
    ///
    /// Planned commands are not command evidence. The bundle stays
    /// `NoVerifierEvidence` until actual verifier command results are attached.
    #[must_use]
    pub fn from_verifier_plan(run_id: impl Into<String>, plan: &VerifierPlan) -> Self {
        let mut bundle = EvidenceBundle::new(run_id);
        bundle.lifecycle = TaskLifecycle::Planning;
        bundle.verifier_plan = plan.label.clone();
        bundle
            .risks
            .extend(plan.warnings.iter().map(|warning| bound(warning, 240)));
        bundle
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

    /// Whether JSON export had to cap list lengths.
    #[must_use]
    pub fn export_is_truncated(&self) -> bool {
        self.commands.len() > MAX_EVIDENCE_EXPORT_COMMANDS
            || self.risks.len() > MAX_EVIDENCE_EXPORT_RISKS
            || self.receipts.len() > MAX_EVIDENCE_EXPORT_REFS
            || self.event_refs.len() > MAX_EVIDENCE_EXPORT_REFS
    }

    /// Exports this bundle as stable bounded JSON for audit/cockpit storage.
    ///
    /// This avoids adding a serialization dependency to the product contract
    /// layer. The output is data only; it does not grant completion authority.
    #[must_use]
    pub fn export_json(&self) -> String {
        let mut out = String::new();
        out.push('{');
        out.push_str("\"schema\":");
        out.push_str(&json_string(EVIDENCE_BUNDLE_SCHEMA, 64));
        out.push_str(",\"run_id\":");
        out.push_str(&json_string(&self.run_id, 160));
        out.push_str(",\"lifecycle\":");
        out.push_str(&json_string(self.lifecycle.label(), 32));
        out.push_str(",\"verdict\":");
        out.push_str(&json_string(self.verdict().label(), 64));
        out.push_str(",\"verifier_plan\":");
        out.push_str(&json_string(&self.verifier_plan, 240));
        out.push_str(",\"ci\":");
        out.push_str(&json_string(self.ci.label(), 32));
        out.push_str(",\"human_review_required\":true");
        out.push_str(",\"truncated\":");
        out.push_str(if self.export_is_truncated() {
            "true"
        } else {
            "false"
        });
        out.push_str(",\"patch_hash\":");
        match &self.patch_hash {
            Some(hash) => out.push_str(&json_string(hash, 128)),
            None => out.push_str("null"),
        }

        out.push_str(",\"commands\":[");
        for (idx, command) in self
            .commands
            .iter()
            .take(MAX_EVIDENCE_EXPORT_COMMANDS)
            .enumerate()
        {
            if idx > 0 {
                out.push(',');
            }
            out.push('{');
            out.push_str("\"command\":");
            out.push_str(&json_string(&command.command, 240));
            out.push_str(",\"passed\":");
            out.push_str(if command.passed { "true" } else { "false" });
            out.push_str(",\"note\":");
            match &command.note {
                Some(note) => out.push_str(&json_string(note, 512)),
                None => out.push_str("null"),
            }
            out.push('}');
        }
        out.push(']');

        out.push_str(",\"risks\":");
        push_json_string_array(
            &mut out,
            self.risks.iter().map(String::as_str),
            MAX_EVIDENCE_EXPORT_RISKS,
            240,
        );
        out.push_str(",\"receipts\":");
        push_json_string_array(
            &mut out,
            self.receipts.iter().map(String::as_str),
            MAX_EVIDENCE_EXPORT_REFS,
            160,
        );
        out.push_str(",\"event_refs\":");
        push_json_string_array(
            &mut out,
            self.event_refs.iter().map(String::as_str),
            MAX_EVIDENCE_EXPORT_REFS,
            160,
        );
        out.push('}');
        out
    }

    /// Exports this bundle as one JSONL line.
    #[must_use]
    pub fn export_jsonl_line(&self) -> String {
        let mut line = self.export_json();
        line.push('\n');
        line
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

/// JSON-escaped byte length of `ch` — so the **escaped** output can be bounded (a control
/// char escapes to `\u00xx` = 6 bytes; bounding the *input* would let escaping blow the size
/// up ~6×, breaking the "bounded JSON" contract).
fn escaped_len(ch: char) -> usize {
    match ch {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
        c if c.is_control() => 6, // \u00xx
        c => c.len_utf8(),
    }
}

/// A JSON string literal whose **escaped** body is bounded to `max` bytes (so a hostile,
/// all-control-character value cannot 6×-explode the export — invariant 11). Truncation is
/// marked with a trailing `...` inside the quotes.
fn json_string(value: impl AsRef<str>, max: usize) -> String {
    let s = value.as_ref();
    let mut out = String::with_capacity(max + 8);
    out.push('"');
    let mut body = 0usize;
    let mut truncated = false;
    for ch in s.chars() {
        if body + escaped_len(ch) > max {
            truncated = true;
            break;
        }
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ch if ch.is_control() => {
                out.push_str("\\u");
                out.push_str(&format!("{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
        body += escaped_len(ch);
    }
    if truncated {
        out.push_str("...");
    }
    out.push('"');
    out
}

fn push_json_string_array<'a>(
    out: &mut String,
    values: impl Iterator<Item = &'a str>,
    max_items: usize,
    max_value_len: usize,
) {
    out.push('[');
    for (idx, value) in values.take(max_items).enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&json_string(value, max_value_len));
    }
    out.push(']');
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
    fn profile_parser_rejects_oversized_untrusted_lists() {
        // crustcore.yml is untrusted repo input (invariant 7); a hostile list is rejected,
        // never allocated past the cap (invariant 11) — whether inline-CSV or block style.
        let many = (0..MAX_VERIFY_COMMANDS + 5)
            .map(|i| format!("cmd{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let err = RepoProfile::parse(&format!("verify: {many}")).unwrap_err();
        assert!(err.reason.contains("too many"), "got: {}", err.reason);

        let block = std::iter::once("labels:".to_string())
            .chain((0..MAX_LABELS + 5).map(|i| format!("  - l{i}")))
            .collect::<Vec<_>>()
            .join("\n");
        let err = RepoProfile::parse(&block).unwrap_err();
        assert!(err.reason.contains("too many"), "got: {}", err.reason);

        // A within-cap profile still parses.
        assert!(RepoProfile::parse("verify: a,b,c").is_ok());
    }

    #[test]
    fn json_string_bounds_the_escaped_output_not_the_input() {
        // A value of all control characters escapes ~6x; the *escaped* output must stay within
        // the byte bound (the bug was bounding the input, letting escaping explode it).
        let hostile = "\u{1}".repeat(1000);
        let out = json_string(&hostile, 64);
        assert!(
            out.len() <= 64 + 5, // 64-byte escaped body + `...` marker + two quotes
            "escaped json must be bounded, got {} bytes",
            out.len()
        );
        // Still valid: opens/closes with a quote, contains only \u escapes + the marker.
        assert!(out.starts_with('"') && out.ends_with('"'));
        assert!(out.contains("\\u0001"));
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
    fn verifier_plan_infers_rust_full_gate_from_repo_signals() {
        let profile = RepoProfile::default();
        let signals = RepoSignals {
            cargo_manifest: true,
            ..RepoSignals::default()
        };

        let plan = profile.plan_verification(&signals, TaskShape::Feature);

        assert_eq!(plan.command_lines(), vec!["cargo test --workspace"]);
        assert_eq!(plan.commands[0].stage, VerifierCommandStage::Full);
        assert!(plan.gates.contains(&TaskGate::FullSuite));
        assert_eq!(plan.strength, EvidenceStrength::Standard);
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn repo_signals_are_detected_from_path_observations() {
        let signals = RepoSignals::from_paths([
            "./Cargo.toml",
            "Cargo.lock",
            "package.json",
            "playwright.config.ts",
            "deny.toml",
            "book.toml",
        ]);

        assert!(signals.cargo_manifest);
        assert!(signals.package_json);
        assert!(signals.lockfile);
        assert_eq!(
            signals.browser_smoke_command.as_deref(),
            Some("npx playwright test")
        );
        assert_eq!(
            signals.dependency_audit_command.as_deref(),
            Some("cargo deny check")
        );
        assert_eq!(signals.docs_check_command.as_deref(), Some("mdbook test"));
    }

    #[test]
    fn repo_signals_detect_python_make_and_cypress_markers() {
        let signals = RepoSignals::from_paths([
            "pyproject.toml",
            "Makefile",
            "poetry.lock",
            "cypress.config.ts",
        ]);

        assert!(signals.python_project);
        assert!(signals.makefile);
        assert!(signals.lockfile);
        assert_eq!(
            signals.browser_smoke_command.as_deref(),
            Some("npx cypress run")
        );
    }

    #[test]
    fn repo_signals_add_sanitized_targeted_hints_from_changed_paths() {
        let signals = RepoSignals::from_repo_and_changed_paths(
            ["Cargo.toml", "package.json", "pyproject.toml"],
            [
                "crates/crustcore-daemon/src/product.rs",
                "tests/test_smoke.py",
                "web/app.test.tsx",
            ],
        );

        assert_eq!(
            signals.targeted_commands,
            vec![
                "cargo test -p crustcore-daemon".to_string(),
                "python -m pytest tests/test_smoke.py".to_string(),
                "npm test -- web/app.test.tsx".to_string(),
            ]
        );

        let plan = RepoProfile::default().plan_verification(&signals, TaskShape::Feature);
        assert_eq!(plan.commands[0].stage, VerifierCommandStage::Targeted);
        assert_eq!(plan.commands[0].command, "cargo test -p crustcore-daemon");
        assert!(plan.command_lines().contains(&"cargo test --workspace"));
    }

    #[test]
    fn changed_path_hints_reject_unsafe_path_fragments() {
        let signals = RepoSignals::from_repo_and_changed_paths(
            ["Cargo.toml", "package.json", "pyproject.toml"],
            [
                "crates/crustcore-daemon/src/product.rs;rm",
                "tests/../../secret_test.py",
                "web/$(touch-pwned).test.ts",
                "-leading-dash.test.ts",
            ],
        );

        assert!(signals.targeted_commands.is_empty());
    }

    #[test]
    fn changed_paths_classify_docs_ui_dependency_and_feature_shapes() {
        assert_eq!(
            TaskShape::from_changed_paths(["docs/product-stack.md", "CHANGELOG.md"]),
            TaskShape::DocsOnly
        );
        assert_eq!(
            TaskShape::from_changed_paths(["crates/crustcore-dev/src/app.tsx"]),
            TaskShape::UiChange
        );
        assert_eq!(
            TaskShape::from_changed_paths(["Cargo.toml", "Cargo.lock"]),
            TaskShape::DependencyChange
        );
        assert_eq!(
            TaskShape::from_changed_paths(["crates/crustcore-daemon/src/product.rs"]),
            TaskShape::Feature
        );
        assert_eq!(
            TaskShape::from_changed_paths(["", "   "]),
            TaskShape::Unknown
        );
    }

    #[test]
    fn changed_paths_fail_closed_for_sensitive_and_workflow_paths() {
        assert_eq!(
            TaskShape::from_changed_paths([
                "docs/product-stack.md",
                "crates/crustcore-secrets/src/lib.rs"
            ]),
            TaskShape::SecuritySensitive
        );
        assert_eq!(
            TaskShape::from_changed_paths([".github/workflows/ci.yml", "README.md"]),
            TaskShape::WorkflowChange
        );
    }

    #[test]
    fn verifier_plan_ranks_targeted_task_checks_before_full_profile_checks() {
        let profile = RepoProfile {
            verify: vec!["cargo xtask verify".to_string()],
            ..RepoProfile::default()
        };
        let signals = RepoSignals {
            package_json: true,
            browser_smoke_command: Some("npm run test:e2e".to_string()),
            ..RepoSignals::default()
        };

        let plan = profile.plan_verification(&signals, TaskShape::UiChange);

        assert_eq!(
            plan.command_lines(),
            vec!["npm run test:e2e", "cargo xtask verify"]
        );
        assert_eq!(plan.commands[0].stage, VerifierCommandStage::Targeted);
        assert_eq!(plan.commands[1].stage, VerifierCommandStage::Full);
        assert!(plan.gates.contains(&TaskGate::BrowserSmoke));
        assert_eq!(plan.strength, EvidenceStrength::Strong);
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn bugfix_without_test_or_full_suite_is_weak_evidence() {
        let profile = RepoProfile {
            verify: vec!["cargo check --workspace".to_string()],
            ..RepoProfile::default()
        };
        let signals = RepoSignals {
            cargo_manifest: true,
            ..RepoSignals::default()
        };

        let plan = profile.plan_verification(&signals, TaskShape::BugFix);

        assert_eq!(plan.strength, EvidenceStrength::Weak);
        assert!(plan.gates.contains(&TaskGate::RegressionTest));
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("regression-test")));
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("full-suite")));
    }

    #[test]
    fn dependency_change_requires_lockfile_and_audit_evidence() {
        let profile = RepoProfile {
            verify: vec!["cargo test --workspace".to_string()],
            ..RepoProfile::default()
        };
        let weak = profile.plan_verification(
            &RepoSignals {
                cargo_manifest: true,
                ..RepoSignals::default()
            },
            TaskShape::DependencyChange,
        );

        assert_eq!(weak.strength, EvidenceStrength::Weak);
        assert!(weak.gates.contains(&TaskGate::DependencySafety));
        assert!(weak
            .warnings
            .iter()
            .any(|warning| warning.contains("lockfile")));
        assert!(weak
            .warnings
            .iter()
            .any(|warning| warning.contains("audit")));

        let strong = profile.plan_verification(
            &RepoSignals {
                cargo_manifest: true,
                dependency_audit_command: Some("cargo audit".to_string()),
                lockfile: true,
                ..RepoSignals::default()
            },
            TaskShape::DependencyChange,
        );

        assert_eq!(
            strong.command_lines(),
            vec!["cargo audit", "cargo test --workspace"]
        );
        assert_eq!(strong.strength, EvidenceStrength::Strong);
        assert!(strong.warnings.is_empty());
    }

    #[test]
    fn docs_only_plan_allows_lighter_docs_gate() {
        let profile = RepoProfile::default();
        let signals = RepoSignals {
            docs_check_command: Some("cargo doc --no-deps".to_string()),
            ..RepoSignals::default()
        };

        let plan = profile.plan_verification(&signals, TaskShape::DocsOnly);

        assert_eq!(plan.command_lines(), vec!["cargo doc --no-deps"]);
        assert!(plan.gates.contains(&TaskGate::DocsCheck));
        assert!(!plan.gates.contains(&TaskGate::FullSuite));
        assert_eq!(plan.strength, EvidenceStrength::Standard);
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn unknown_repo_without_verifier_is_weak_and_blocking() {
        let profile = RepoProfile::default();
        let plan = profile.plan_verification(&RepoSignals::default(), TaskShape::Unknown);

        assert!(plan.commands.is_empty());
        assert_eq!(plan.strength, EvidenceStrength::Weak);
        assert!(plan.gates.contains(&TaskGate::FullSuite));
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("No verifier command")));
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
    fn evidence_bundle_from_verifier_plan_preserves_weak_evidence_without_results() {
        let profile = RepoProfile {
            verify: vec!["cargo check --workspace".to_string()],
            ..RepoProfile::default()
        };
        let signals = RepoSignals {
            cargo_manifest: true,
            ..RepoSignals::default()
        };
        let plan = profile.plan_verification(&signals, TaskShape::BugFix);

        let bundle = EvidenceBundle::from_verifier_plan("run-plan", &plan);

        assert_eq!(bundle.lifecycle, TaskLifecycle::Planning);
        assert_eq!(bundle.verifier_plan, plan.label);
        assert!(bundle.commands.is_empty());
        assert_eq!(bundle.verdict(), EvidenceVerdict::NoVerifierEvidence);
        assert!(bundle
            .risks
            .iter()
            .any(|risk| risk.contains("regression-test")));
    }

    #[test]
    fn evidence_export_json_is_stable_escaped_and_review_gated() {
        let mut bundle = EvidenceBundle::new("run-\"quoted\"");
        bundle.lifecycle = TaskLifecycle::Completed;
        bundle.verifier_plan = "rust full gate".to_string();
        bundle.commands.push(
            CommandEvidenceLine::new("cargo test --workspace", true)
                .with_note("line one\nline \"two\""),
        );
        bundle.patch_hash = Some("patch\\hash".to_string());
        bundle.ci = CiState::Passed;
        bundle.receipts.push("receipt:verify:1".to_string());
        bundle.event_refs.push("event:1..3".to_string());
        bundle.risks.push("review auth-sensitive path".to_string());

        let json = bundle.export_json();

        assert!(json.starts_with("{\"schema\":\"crustcore.evidence_bundle.v1\""));
        assert!(json.contains("\"human_review_required\":true"));
        assert!(json.contains("\"verdict\":\"sufficient\""));
        assert!(json.contains("run-\\\"quoted\\\""));
        assert!(json.contains("line one\\nline \\\"two\\\""));
        assert!(json.contains("patch\\\\hash"));
        assert!(!json.contains("line one\nline"));

        let jsonl = bundle.export_jsonl_line();
        assert!(jsonl.ends_with('\n'));
        assert_eq!(&jsonl[..jsonl.len() - 1], json);
    }

    #[test]
    fn evidence_export_caps_arrays_and_marks_truncated() {
        let mut bundle = EvidenceBundle::new("run-large");
        for idx in 0..40 {
            bundle
                .commands
                .push(CommandEvidenceLine::new(format!("cmd-{idx}"), true));
            bundle.risks.push(format!("risk-{idx}"));
            bundle.receipts.push(format!("receipt-{idx}"));
            bundle.event_refs.push(format!("event-{idx}"));
        }

        let json = bundle.export_json();

        assert!(bundle.export_is_truncated());
        assert!(json.contains("\"truncated\":true"));
        assert!(json.contains("cmd-31"));
        assert!(!json.contains("cmd-32"));
        assert!(json.contains("risk-31"));
        assert!(!json.contains("risk-32"));
        assert!(json.contains("receipt-39"));
        assert!(json.contains("event-39"));
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
