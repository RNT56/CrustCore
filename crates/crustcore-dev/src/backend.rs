// SPDX-License-Identifier: Apache-2.0
//! The [`DevBackend`] decoupling boundary + view models + [`MockDevBackend`] (`C7.1`).
//!
//! Every handler reads its data through a backend trait, never a live transport, so the
//! whole handler surface is CI-testable over [`MockDevBackend`] with no net/secrets.
//!
//! ## The read-only / mutating type split (dimension (c))
//!
//! Data access is split into **two disjoint traits**:
//!
//! - [`ReadOnlyBackend`] — inspect/replay/provider/MCP/flow/session view models. Every
//!   method borrows; none mints, writes, appends a frame, or reaches the verifier.
//! - [`MutatingBackend`] — the *single* side-effecting capability: dispatching an
//!   operation-bound approval resolution into the existing approval engine.
//!
//! A [`RouteClass::ReadOnly`](crate::route_class::RouteClass) handler is handed
//! `&dyn ReadOnlyBackend` and there is **no** method on it that returns a
//! `MutatingBackend` — so a read handler cannot reach a side effect; it is a compile
//! error, not a runtime guard. A [`MutatingBackend`] is obtained only via
//! [`DevBackend::mutating`], which the router calls solely for the one mutating route,
//! behind the launch flag and the approval gate.

use crustcore_eventlog::{ChainStatus, EventLog, RedactionState};
use crustcore_receipts::join::JoinStatus;
use crustcore_receipts::ToolReceipt;
use crustcore_secrets::Redactor;
use crustcore_types::{ArtifactId, EventSeq, TaskId, Timestamp};

// ---------------------------------------------------------------------------
// View models — already redacted, already bounded. Carry NO live/secret types.
// ---------------------------------------------------------------------------

/// One per-frame row of the replay view. Carries no payload bytes — only the
/// visibility/redaction metadata and the artifact handle (by id). The actual payload is
/// never inlined (invariant 7 / bounded everything).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRow {
    /// The frame's sequence number.
    pub seq: EventSeq,
    /// The event kind name (a closed-enum name, never untrusted text).
    pub kind: String,
    /// `true` if the payload was model-visible (vs internal).
    pub model_visible: bool,
    /// `true` if the payload was redacted (secret-bearing).
    pub redacted: bool,
    /// The artifact this frame references, if any — by id only, never inlined.
    pub artifact: Option<ArtifactId>,
}

/// The replay viewer's read-only result over the hash-chained log (`C7.3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayView {
    /// The hash-chain verification status (`Intact`/`Broken` + where).
    pub chain: ChainStatus,
    /// The receipt↔log join status (P5-join), if receipts were present.
    pub join: Option<JoinStatus>,
    /// Per-frame rows (bounded). Redacted/internal payloads are flagged, never shown.
    pub rows: Vec<ReplayRow>,
}

/// The run inspector's read-only summary (`C7.3`): the per-task rollup + chain status,
/// exactly the streamed-to-user set (never raw chain-of-thought).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInspectorView {
    /// The chain verification status.
    pub chain: ChainStatus,
    /// Total verified frames.
    pub total_frames: u64,
    /// Per-task rollups (id, frame count, seq range, terminal kind if any).
    pub tasks: Vec<TaskRow>,
}

/// One task row in the run inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRow {
    /// The task id.
    pub task_id: TaskId,
    /// Frames seen for this task.
    pub frames: u64,
    /// First sequence number.
    pub first_seq: EventSeq,
    /// Last sequence number.
    pub last_seq: EventSeq,
    /// The terminal event kind, if the task ended.
    pub terminal: Option<String>,
}

/// A provider/model card for the provider tester (`C7.4`). Renders metadata only — never
/// a credential. Mirrors `crustcore_netproto::ModelInfo` / `crustcore_net::ModelCard`,
/// but is a flat redacted view model so the UI process never touches the live types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCardView {
    /// Provider id.
    pub provider: String,
    /// Model name.
    pub model: String,
    /// Whether the last probe reported the model healthy.
    pub healthy: bool,
    /// Context window size.
    pub context: u32,
    /// Whether tools are supported.
    pub tools: bool,
    /// Cost per 1k tokens, in micros (metadata, not a secret).
    pub cost_per_1k_micros: u64,
}

/// The MCP registry view (`C7.5`): a registered server plus its `tool_policies`-derived
/// gate decisions and manifest-drift state. The gate decisions come from the registry's
/// policies, **never** the server's self-description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerView {
    /// The server id.
    pub server_id: u64,
    /// A redacted, bounded source description.
    pub source: String,
    /// Whether the live manifest hash matches the registered one (no drift).
    pub manifest_intact: bool,
    /// Per-tool gate decisions, each `(tool, decision)`, decision from `tool_policies`.
    pub tool_decisions: Vec<(String, String)>,
}

/// A flow graph rendering for the workflow debugger (`C7.5`): nodes + edges only. No live
/// driver, no execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowGraphView {
    /// `(node_id, kind_label)` for each node.
    pub nodes: Vec<(u32, String)>,
    /// `(from, to)` directed edges.
    pub edges: Vec<(u32, u32)>,
    /// The entry node id.
    pub entry: u32,
}

/// One simulated step of the flow debugger (`C7.5`). Produced by a *no-op driver*: it
/// dispatches no kernel `Action`, appends no frame, never reaches `verify::run_verify`,
/// and mints no `VerifiedPatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStepView {
    /// The node that was (simulated) stepped.
    pub node_id: u32,
    /// Its kind label.
    pub kind: String,
    /// A bounded, redacted human note about what the simulated step did.
    pub note: String,
    /// `true` once the simulation reached an `End`/terminal node. Never `Completed` —
    /// the no-op driver cannot mint a `VerifiedPatch`.
    pub finished: bool,
}

/// A session list row for the read-only session inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionListView {
    /// Session ids (as their backing task ids), in deterministic order.
    pub sessions: Vec<TaskId>,
}

/// A pending-approval view (`C7.6`): what the UI surfaces *before* a resolution. It shows
/// the operation summary and its binding (approval id + op-hash) so the user resolves the
/// exact operation shown — and so the resolution can be operation-bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalView {
    /// The approval id.
    pub approval_id: u128,
    /// The op-hash this approval is bound to (hex; binds the resolution to this op).
    pub op_hash_hex: String,
    /// A redacted, bounded human summary of the operation awaiting approval.
    pub summary: String,
    /// When the approval expires (millis).
    pub expires_at_millis: u64,
}

// ---------------------------------------------------------------------------
// The read-only capability surface
// ---------------------------------------------------------------------------

/// The **read-only** data surface. Every method borrows and is side-effect-free: none
/// mints, writes, appends a frame, advances a budget, or reaches the verifier. A
/// [`RouteClass::ReadOnly`](crate::route_class::RouteClass) handler is handed
/// `&dyn ReadOnlyBackend`; there is no method here that yields a [`MutatingBackend`], so a
/// read handler structurally cannot cause a side effect (dimension (c)).
///
/// The split is enforced by the type system — a read handler holding `&dyn ReadOnlyBackend`
/// cannot call the mutating method; it does not exist on this trait:
///
/// ```compile_fail
/// use crustcore_dev::backend::{MockDevBackend, DevBackend, ReadOnlyBackend};
/// let backend = MockDevBackend::new();
/// let ro: &dyn ReadOnlyBackend = backend.read_only();
/// // error[E0599]: no method named `dispatch_resolution` found for `&dyn ReadOnlyBackend`
/// let _ = ro.dispatch_resolution(1, true, "00");
/// ```
pub trait ReadOnlyBackend {
    /// The run inspector summary over the live event log.
    fn run_inspector(&self) -> RunInspectorView;

    /// The replay view over the hash-chained log + receipt join.
    fn replay(&self) -> ReplayView;

    /// The provider/model cards (metadata only; renders no credential).
    fn provider_cards(&self) -> Vec<ModelCardView>;

    /// The MCP registry view (gate decisions from `tool_policies`).
    fn mcp_servers(&self) -> Vec<McpServerView>;

    /// The loaded flow graph rendering (nodes/edges only).
    fn flow_graph(&self) -> FlowGraphView;

    /// Simulate stepping the flow graph from `from_node` with a no-op driver. Returns
    /// the next step; never executes, never mints a `VerifiedPatch`.
    fn flow_step(&self, from_node: u32) -> Option<FlowStepView>;

    /// The list of known sessions (read-only).
    fn sessions(&self) -> SessionListView;

    /// The currently pending approvals (the *view* the UI surfaces before a resolution).
    fn pending_approvals(&self) -> Vec<ApprovalView>;
}

/// The result of dispatching an approval resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchResult {
    /// The resolution was approved by an authorized user (the engine minted an
    /// `Approved<T>` internally — the UI never sees or constructs it).
    Approved {
        /// The approval id that was resolved.
        approval_id: u128,
    },
    /// The resolution denied the operation.
    Denied {
        /// The approval id that was resolved.
        approval_id: u128,
    },
    /// The resolution was rejected (unknown nonce, expired, op-hash mismatch, or the
    /// resolving identity was not authorized). The UI surfaces this; it mints nothing.
    Rejected {
        /// A short, non-sensitive reason.
        reason: String,
    },
}

/// The **mutating** capability surface — the *only* side-effecting operation the UI can
/// trigger. It does not mint an `Approved<T>`: it forwards an operation-bound resolution
/// into the existing approval engine ([`crustcore_daemon::telegram::ApprovalEngine`]),
/// where `AuthorizedUser::approve` is the sole minter (dimension (d)). Obtainable only
/// via [`DevBackend::mutating`], which the router calls solely for the one mutating route,
/// behind the launch flag and the approval gate.
pub trait MutatingBackend {
    /// Dispatch an operation-bound approval resolution. `op_hash_hex` binds the
    /// resolution to a specific pending operation; a mismatch is rejected by the engine,
    /// so a resolution can never approve a different operation than the one shown.
    fn dispatch_resolution(
        &mut self,
        approval_id: u128,
        approve: bool,
        op_hash_hex: &str,
    ) -> DispatchResult;
}

/// The full backend: a read-only surface plus a gated path to the mutating surface. The
/// read-only and mutating capabilities are *separate traits*; only the router (for the
/// one mutating route, behind the launch flag + approval gate) calls [`DevBackend::mutating`].
pub trait DevBackend {
    /// Borrow the read-only surface (all that a [`RouteClass::ReadOnly`] handler gets).
    fn read_only(&self) -> &dyn ReadOnlyBackend;

    /// Borrow the mutating surface. The router only reaches this for the single mutating
    /// route, after the launch flag and the operation-bound approval gate admit it.
    fn mutating(&mut self) -> &mut dyn MutatingBackend;
}

// ---------------------------------------------------------------------------
// MockDevBackend — the CI fake. No net, no secrets, no live transport.
// ---------------------------------------------------------------------------

/// The CI fake backend. Holds an in-memory event log, receipts, a flow graph, an MCP
/// registry, provider cards, and a pending-approval table — all the read views are
/// derived from these deterministically, and the single mutating operation is forwarded
/// to a real [`crustcore_daemon::telegram::ApprovalEngine`] so the dispatch path is the
/// genuine one (the engine, not a stand-in, mints `Approved<T>`).
pub struct MockDevBackend {
    log: EventLog,
    receipts: Vec<ToolReceipt>,
    redactor: Redactor,
    provider_cards: Vec<ModelCardView>,
    mcp_servers: Vec<McpServerView>,
    flow: Option<crustcore_flow::graph::Flow>,
    pending: Vec<ApprovalView>,
    // The genuine approval engine + allowlist used by the mutating path, so the dispatch
    // is the real operation-bound resolution (dimension (d)).
    engine: crustcore_daemon::telegram::ApprovalEngine,
    allowlist: crustcore_daemon::telegram::ChatAllowlist,
    resolving_chat: crustcore_daemon::telegram::ChatId,
    now: Timestamp,
}

impl Default for MockDevBackend {
    fn default() -> Self {
        MockDevBackend::new()
    }
}

impl MockDevBackend {
    /// An empty mock with a deny-all allowlist (no chat can resolve approvals until one
    /// is bound — the fail-safe default mirrors Telegram).
    #[must_use]
    pub fn new() -> Self {
        MockDevBackend {
            log: EventLog::new(),
            receipts: Vec::new(),
            redactor: Redactor::new(),
            provider_cards: Vec::new(),
            mcp_servers: Vec::new(),
            flow: None,
            pending: Vec::new(),
            engine: crustcore_daemon::telegram::ApprovalEngine::new(),
            allowlist: crustcore_daemon::telegram::ChatAllowlist::deny_all(),
            resolving_chat: crustcore_daemon::telegram::ChatId(0),
            now: Timestamp::from_millis(0),
        }
    }

    /// Replace the in-memory log (e.g. with a tamper fixture).
    #[must_use]
    pub fn with_log(mut self, log: EventLog) -> Self {
        self.log = log;
        self
    }

    /// Provide receipts for the replay view's join.
    #[must_use]
    pub fn with_receipts(mut self, receipts: Vec<ToolReceipt>) -> Self {
        self.receipts = receipts;
        self
    }

    /// Provide a redactor (e.g. one carrying a sentinel secret for the leak canary).
    #[must_use]
    pub fn with_redactor(mut self, redactor: Redactor) -> Self {
        self.redactor = redactor;
        self
    }

    /// Provide provider cards for the provider tester.
    #[must_use]
    pub fn with_provider_cards(mut self, cards: Vec<ModelCardView>) -> Self {
        self.provider_cards = cards;
        self
    }

    /// Provide MCP server views.
    #[must_use]
    pub fn with_mcp_servers(mut self, servers: Vec<McpServerView>) -> Self {
        self.mcp_servers = servers;
        self
    }

    /// Provide a flow graph for the workflow debugger.
    #[must_use]
    pub fn with_flow(mut self, flow: crustcore_flow::graph::Flow) -> Self {
        self.flow = Some(flow);
        self
    }

    /// Bind an allowlisted resolving chat (the trusted setup path), so the mutating
    /// dispatch can reach an [`crustcore_policy::AuthorizedUser`]. Without this, every
    /// resolution is rejected as not-allowlisted (fail-safe default).
    #[must_use]
    pub fn with_allowlisted_chat(mut self, chat_id: i64) -> Self {
        self.allowlist = crustcore_daemon::telegram::ChatAllowlist::of(&[chat_id]);
        self.resolving_chat = crustcore_daemon::telegram::ChatId(chat_id);
        self
    }

    /// The current time used for approval-expiry checks.
    #[must_use]
    pub fn now(&self) -> Timestamp {
        self.now
    }

    /// Set the current time (for expiry tests).
    #[must_use]
    pub fn at_time(mut self, now: Timestamp) -> Self {
        self.now = now;
        self
    }

    /// Register a pending approval in the genuine engine and the surfaced view. Returns
    /// the op-hash (hex) the resolution must carry — this is exactly what the
    /// [`ApprovalView`] shows, so a user resolves the operation they see.
    pub fn request_approval(
        &mut self,
        approval_id: u128,
        operation: &str,
        summary: &str,
        expires_at: Timestamp,
    ) -> String {
        let nonce = self
            .engine
            .request(approval_id, operation, summary, expires_at);
        let op_hash_hex = hex(&nonce.op_hash);
        self.pending.push(ApprovalView {
            approval_id,
            op_hash_hex: op_hash_hex.clone(),
            summary: self.redactor.redact(summary),
            expires_at_millis: expires_at.as_millis(),
        });
        op_hash_hex
    }

    /// Read access to the in-memory log (for tests that inspect the fixture directly).
    #[must_use]
    pub fn log(&self) -> &EventLog {
        &self.log
    }
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl ReadOnlyBackend for MockDevBackend {
    fn run_inspector(&self) -> RunInspectorView {
        crate::views::inspector::render(&self.log)
    }

    fn replay(&self) -> ReplayView {
        crate::views::replay::render(&self.log, &self.receipts)
    }

    fn provider_cards(&self) -> Vec<ModelCardView> {
        // Already redacted/flat view models; pass through the redactor defensively so a
        // sentinel needle in any field is scrubbed before render (dimension (e)).
        crate::views::provider::render(&self.provider_cards, &self.redactor)
    }

    fn mcp_servers(&self) -> Vec<McpServerView> {
        crate::views::mcp::render(&self.mcp_servers, &self.redactor)
    }

    fn flow_graph(&self) -> FlowGraphView {
        match &self.flow {
            Some(flow) => crate::views::flow::render_graph(flow),
            None => FlowGraphView {
                nodes: Vec::new(),
                edges: Vec::new(),
                entry: 0,
            },
        }
    }

    fn flow_step(&self, from_node: u32) -> Option<FlowStepView> {
        let flow = self.flow.as_ref()?;
        crate::views::flow::simulate_step(flow, from_node, &self.redactor)
    }

    fn sessions(&self) -> SessionListView {
        crate::views::inspector::sessions(&self.log, &self.redactor)
    }

    fn pending_approvals(&self) -> Vec<ApprovalView> {
        self.pending.clone()
    }
}

impl MutatingBackend for MockDevBackend {
    fn dispatch_resolution(
        &mut self,
        approval_id: u128,
        approve: bool,
        op_hash_hex: &str,
    ) -> DispatchResult {
        use crustcore_daemon::telegram::ApprovalOutcome;
        use crustcore_types::ApprovalResolution;

        // The op-hash binds the resolution to the operation shown. A malformed/wrong
        // hash never reaches the engine as a match — it is rejected (dimension (d)).
        let callback_op_hash = decode_hex32(op_hash_hex);
        let decision = if approve {
            ApprovalResolution::Approve
        } else {
            ApprovalResolution::Deny
        };

        // Forward into the GENUINE engine. We never construct an Approved<T> here; the
        // engine does, and only for an allowlisted chat (-> AuthorizedUser). The UI
        // discards the token: the token is the engine's authority object, not the UI's.
        let outcome = self.engine.resolve(
            approval_id,
            decision,
            self.resolving_chat,
            &self.allowlist,
            self.now,
            callback_op_hash,
        );

        // Drop the resolved approval from the surfaced view (single-use).
        self.pending.retain(|a| a.approval_id != approval_id);

        match outcome {
            ApprovalOutcome::Approved(_token) => DispatchResult::Approved { approval_id },
            ApprovalOutcome::Denied { approval_id } => DispatchResult::Denied { approval_id },
            ApprovalOutcome::RejectedNotAllowlisted => DispatchResult::Rejected {
                reason: "not allowlisted".to_string(),
            },
            ApprovalOutcome::RejectedUnknownNonce => DispatchResult::Rejected {
                reason: "unknown approval".to_string(),
            },
            ApprovalOutcome::RejectedExpired => DispatchResult::Rejected {
                reason: "approval expired".to_string(),
            },
            ApprovalOutcome::RejectedOpMismatch => DispatchResult::Rejected {
                reason: "operation mismatch".to_string(),
            },
        }
    }
}

impl DevBackend for MockDevBackend {
    fn read_only(&self) -> &dyn ReadOnlyBackend {
        self
    }

    fn mutating(&mut self) -> &mut dyn MutatingBackend {
        self
    }
}

/// Whether a frame's redaction byte marks it secret-bearing (helper re-export for views).
#[must_use]
pub fn is_redacted(state: RedactionState) -> bool {
    state == RedactionState::Redacted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips_32() {
        let bytes = [0xABu8; 32];
        let h = hex(&bytes);
        assert_eq!(h.len(), 64);
        assert_eq!(decode_hex32(&h), Some(bytes));
        assert_eq!(decode_hex32("zz"), None);
        assert_eq!(decode_hex32(&"a".repeat(63)), None);
    }

    #[test]
    fn empty_mock_yields_empty_views() {
        let mock = MockDevBackend::new();
        let ro = mock.read_only();
        assert!(ro.provider_cards().is_empty());
        assert!(ro.mcp_servers().is_empty());
        assert!(ro.pending_approvals().is_empty());
        assert_eq!(ro.flow_graph().nodes.len(), 0);
        assert!(ro.flow_step(0).is_none());
    }
}
