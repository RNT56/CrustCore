// SPDX-License-Identifier: Apache-2.0
//! MCP gateway + registry + code-mode (`ROADMAP.md` §14, §18 Phase 13;
//! `docs/mcp.md`). A **capability pack**, not a kernel concern — it is **not in
//! nano** (invariants 19, 20): a nano build links no MCP stack.
//!
//! The trust model (`docs/mcp.md` §2): everything an MCP server produces — tool
//! **output**, fetched **resources**, and even tool **descriptions** — is
//! **untrusted data** (invariant 7). It never controls policy, secrets, approvals,
//! or user comms. CrustCore turns the whole MCP universe into small, policy-checked
//! ([`gateway_check`], invariant 8), receipted ([`filter_result`], invariant 10),
//! redacted typed APIs, with **credentials injected at the gateway** (never in the
//! model context or the sandbox — invariants 1–3) and only the **used** tool stubs
//! ever entering model context (invariant 20).
//!
//! This module is the std-only trust/policy/redaction/receipt core. The gateway call
//! flow ([`call_tool`]) resolves a server's `McpAuthMode::BrokerSecret` via the broker
//! → [`crustcore_secrets::CredentialProxy`] and injects it at the transport boundary
//! (P13-net), fully tested with an in-process `MockMcp`. The live network transport that
//! carries the injected header on the wire is [`transport::HttpMcp`] (P13-net-http, the
//! `http` feature); its envelope build + response parse are CI-tested and the live POST
//! is `#[ignore]`d. What remains is only sandboxed stub execution (it needs the Phase-4
//! sandbox); the trust-critical gateway and credential-resolution logic are fully tested.
#![forbid(unsafe_code)]

pub mod server;
pub mod transport;

use crustcore_receipts::{ReceiptChain, ReceiptParams, ToolReceipt};
use crustcore_secrets::{
    CredentialProxy, HeaderInjection, ModelVisibleText, Redactor, SecretBroker, SecretStore,
};
use crustcore_types::hash::sha256;
use crustcore_types::{
    ApprovalId, ArtifactId, BoundedText, EventSeq, JobId, RepoRef, SecretId, TaskId, Timestamp,
    ToolCallId,
};

/// Cap on a model-visible MCP result summary (bounded; not megabytes — invariant
/// 11; `docs/mcp.md` §4 step 7).
pub const MAX_MCP_SUMMARY: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// Trust + registry (P13.1)
// ---------------------------------------------------------------------------

/// Trust posture for a registered MCP server (`docs/mcp.md` §3). Maps to a default
/// risk posture: a lower-trust server gets tighter tool policies and more
/// aggressive redaction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// Unknown/untrusted (the default) — never trusted with secrets.
    #[default]
    Untrusted,
    /// Registered and version/manifest-pinned, but still semi-trusted.
    SemiTrusted,
    /// Explicitly trusted (e.g. a first-party local server).
    Trusted,
}

/// A stable MCP server identity (for receipts, events, policy lookups).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct McpServerId(pub u64);

/// Where a server came from — provenance for trust decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpServerSource {
    /// A local binary path.
    LocalBinary(String),
    /// A remote URL.
    RemoteUrl(String),
    /// A package reference.
    Package(String),
}

/// The transport (determines sandbox + network posture).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTransport {
    /// stdio JSON-RPC (local subprocess).
    Stdio,
    /// HTTP transport (remote).
    Http,
}

/// How a server's credential is obtained — **always broker-mediated, never
/// model-visible** (invariants 1–3). The model sees an availability state, never
/// the bytes; the secret is injected at the gateway (`docs/mcp.md` §2, §4 step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpAuthMode {
    /// No credential needed.
    None,
    /// A secret resolved by the broker at the gateway (a `secret://` handle).
    BrokerSecret(SecretId),
}

/// The ask/deny/allow decision a tool policy encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolDecision {
    /// Allowed to run (reversible/low-risk).
    Allow,
    /// Requires an approval (routes a nonce-bound approval; `docs/telegram.md` §6).
    Ask,
    /// Denied.
    Deny,
}

/// A per-tool policy — fine-grained, not all-or-nothing (`docs/mcp.md` §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolPolicy {
    /// The tool name this policy governs.
    pub tool: String,
    /// The decision.
    pub decision: ToolDecision,
}

/// A registered MCP server record (`docs/mcp.md` §3).
#[derive(Debug, Clone)]
pub struct McpServerRecord {
    /// Stable identity.
    pub id: McpServerId,
    /// Provenance.
    pub source: McpServerSource,
    /// Transport.
    pub transport: McpTransport,
    /// Optional version pin.
    pub version: Option<String>,
    /// Hash of the declared tool surface at admission (drift detection).
    pub manifest_hash: Option<[u8; 32]>,
    /// How the credential is obtained (broker-mediated).
    pub auth: McpAuthMode,
    /// Trust posture.
    pub trust_level: TrustLevel,
    /// Repos this server is scoped to (not globally ambient).
    pub allowed_repos: Vec<RepoRef>,
    /// Per-tool policies.
    pub tool_policies: Vec<McpToolPolicy>,
}

impl McpServerRecord {
    /// The policy decision for `tool`, or `None` if the tool has no policy (an
    /// unpoliced tool is **denied by default**, never implicitly allowed).
    #[must_use]
    pub fn tool_decision(&self, tool: &str) -> Option<ToolDecision> {
        self.tool_policies
            .iter()
            .find(|p| p.tool == tool)
            .map(|p| p.decision)
    }

    /// Whether this server is scoped to `repo`.
    #[must_use]
    pub fn allows_repo(&self, repo: &str) -> bool {
        self.allowed_repos.iter().any(|r| r.0.as_str() == repo)
    }
}

/// The registry of admitted MCP servers. Empty = no MCP surface at all (a server
/// is never ambient until registered through the trusted admin path).
#[derive(Default)]
pub struct McpRegistry {
    servers: std::collections::BTreeMap<u64, McpServerRecord>,
}

impl McpRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        McpRegistry {
            servers: std::collections::BTreeMap::new(),
        }
    }

    /// Registers a server.
    pub fn register(&mut self, record: McpServerRecord) {
        self.servers.insert(record.id.0, record);
    }

    /// The record for a server id.
    #[must_use]
    pub fn get(&self, id: McpServerId) -> Option<&McpServerRecord> {
        self.servers.get(&id.0)
    }
}

// ---------------------------------------------------------------------------
// Gateway policy check (P13.2) — invariant 8
// ---------------------------------------------------------------------------

/// The gateway's decision for an MCP tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayDecision {
    /// Allowed — perform the call (then redact + receipt the result).
    Allow,
    /// Requires a human approval first (the policy is `Ask`).
    Ask,
    /// Denied, with a typed reason.
    Deny(GatewayDeny),
}

/// Why the gateway refused an MCP call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayDeny {
    /// The server is not registered.
    UnknownServer,
    /// The server's declared tool surface changed since admission (supply-chain /
    /// tamper drift; `docs/mcp.md` §3) — re-gate required.
    ManifestDrift,
    /// The server is not scoped to this repo.
    RepoNotAllowed,
    /// The tool has no allow/ask policy (default deny — invariant 8).
    ToolNotAllowed,
    /// The tool's policy is explicitly `Deny`.
    ToolDenied,
}

/// Decides whether an MCP tool call may proceed (`docs/mcp.md` §4 step 3,
/// invariant 8). Order: unknown server → deny; manifest drift (the live tool
/// surface differs from what was admitted) → deny; repo not allowed → deny; tool
/// policy missing → deny (default-deny); else the tool's decision (Allow/Ask/Deny).
/// **The server's own tool descriptions/output are never consulted** — they are
/// untrusted data and cannot influence the gate.
#[must_use]
pub fn gateway_check(
    registry: &McpRegistry,
    server: McpServerId,
    tool: &str,
    repo: &str,
    live_manifest_hash: Option<[u8; 32]>,
) -> GatewayDecision {
    let Some(record) = registry.get(server) else {
        return GatewayDecision::Deny(GatewayDeny::UnknownServer);
    };
    // Drift: if a manifest was pinned and the live surface differs, re-gate.
    if let (Some(pinned), Some(live)) = (record.manifest_hash, live_manifest_hash) {
        if pinned != live {
            return GatewayDecision::Deny(GatewayDeny::ManifestDrift);
        }
    }
    if !record.allows_repo(repo) {
        return GatewayDecision::Deny(GatewayDeny::RepoNotAllowed);
    }
    match record.tool_decision(tool) {
        None => GatewayDecision::Deny(GatewayDeny::ToolNotAllowed),
        Some(ToolDecision::Deny) => GatewayDecision::Deny(GatewayDeny::ToolDenied),
        Some(ToolDecision::Ask) => GatewayDecision::Ask,
        Some(ToolDecision::Allow) => GatewayDecision::Allow,
    }
}

// ---------------------------------------------------------------------------
// Result redaction + receipting (P13.3) — invariants 2, 7, 10
// ---------------------------------------------------------------------------

/// A bounded, redacted, receipted MCP result — what the **model** sees (a summary
/// plus an artifact handle and a receipt), never megabytes of raw, possibly
/// secret-bearing output (`docs/mcp.md` §4 step 6–7).
#[derive(Debug, Clone)]
pub struct McpResult {
    /// The redacted, bounded, model-visible summary (untrusted data, scrubbed).
    pub summary: ModelVisibleText,
    /// Content hash of the full (untruncated) raw output — the artifact handle.
    pub artifact_hash: [u8; 32],
    /// The receipt tying this result to a real, MAC-verified call (invariant 10).
    pub receipt: ToolReceipt,
}

/// Ids anchoring an MCP result's receipt to the event log.
#[derive(Debug, Clone, Copy)]
pub struct McpCallIds {
    /// The task the call ran under.
    pub task_id: TaskId,
    /// The job the call ran under.
    pub job_id: JobId,
    /// The tool-call id.
    pub tool_call_id: ToolCallId,
    /// The event-log seq this receipt anchors to.
    pub event_seq: EventSeq,
}

/// Turns raw (untrusted) MCP output into a model-visible [`McpResult`]: **redact**
/// known secrets out (invariant 2; `docs/mcp.md` §4 step 6 — the result may contain
/// the server's credential or echoed secrets), **bound** it to a summary (not
/// megabytes), hash the full output into an **artifact handle**, and **mint a
/// receipt** over the redacted, shown bytes (invariant 10 — no receipt, no
/// model-visible claim that the tool ran). MCP output is untrusted data: nothing
/// here interprets it as a command (invariant 7).
///
/// `call_args` is the **canonicalized** argument bytes the tool was actually called
/// with; the receipt's `args_hash` binds them (`docs/mcp.md` §5), so the result is
/// tied to a specific call's inputs — two calls to the same tool with different args
/// produce distinguishable receipts. Pass already-redacted, non-secret arg bytes:
/// the receipt covers redacted data only (invariants 1–2).
pub fn filter_result(
    server: McpServerId,
    tool: &str,
    call_args: &[u8],
    raw_output: &[u8],
    redactor: &Redactor,
    receipts: &mut ReceiptChain,
    ids: &McpCallIds,
) -> McpResult {
    // Artifact handle over the FULL raw bytes (content address of the real output).
    let artifact_hash = sha256(raw_output);

    // Redact, then bound to a summary. Redaction runs before any model visibility.
    let redacted = redactor.to_model_visible(&String::from_utf8_lossy(raw_output));
    let summary = ModelVisibleTextExt::bounded(&redacted, MAX_MCP_SUMMARY);

    // Receipt over exactly the bytes the model is shown (the redacted summary), and
    // bound to the canonicalized call args so the receipt commits to a specific call.
    let tool_name = format!("mcp:{}:{}", server.0, tool);
    let receipt = receipts.mint(&ReceiptParams {
        task_id: ids.task_id,
        job_id: ids.job_id,
        tool_call_id: ids.tool_call_id,
        tool_name: tool_name.as_bytes(),
        args: call_args,
        result: summary.as_str().as_bytes(),
        artifacts: &[ArtifactId(artifact_hash)],
        event_seq: ids.event_seq,
    });

    McpResult {
        summary,
        artifact_hash,
        receipt,
    }
}

// ---------------------------------------------------------------------------
// The gated call flow (P13-net): gateway_check → JSON-RPC tools/call → filter_result
// ---------------------------------------------------------------------------

/// The outcome of a gated MCP tool call.
#[derive(Debug)]
pub enum CallOutcome {
    /// Authorized, performed, and turned into a redacted, bounded, receipted result.
    /// Boxed: [`McpResult`] (its receipt) dwarfs the other variants, so an unboxed
    /// `Done` would bloat every `CallOutcome` (`clippy::large_enum_variant`).
    Done(Box<McpResult>),
    /// The gateway denied the call (the typed reason) — no call was made.
    Denied(GatewayDeny),
    /// The tool's policy is `Ask` — an approval must be obtained before calling.
    NeedsApproval,
    /// The gateway allowed the call, but the server's `McpAuthMode::BrokerSecret`
    /// credential could **not** be resolved (missing/expired/no broker provided) — so
    /// the call **fails closed**: it is never issued *unauthenticated* (invariant 1).
    /// No transport call was made.
    CredentialUnavailable(SecretId),
}

/// The trusted context [`call_tool`] needs to **resolve** a server's
/// `McpAuthMode::BrokerSecret` into an injectable credential at call time (P13-net;
/// `docs/mcp.md` §4 step 4). It carries the [`SecretBroker`] (the only thing that can
/// materialize a secret), the **approval** that authorizes this use, the current time
/// (for the broker's one-shot/expiry checks), and the TTL of the minted view.
///
/// The model never sees any of this: the broker hands back a non-model-visible
/// [`HeaderInjection`] via [`CredentialProxy::bearer`], whose bytes flow only to the
/// transport (invariants 1–3). A server with `McpAuthMode::None` ignores this context
/// entirely; a `BrokerSecret` server with no context (or an unresolvable secret) fails
/// closed ([`CallOutcome::CredentialUnavailable`]) — never an unauthenticated call.
pub struct McpAuthContext<'b, S: SecretStore> {
    /// The broker that materializes the credential (the only authority on secret bytes).
    pub broker: &'b SecretBroker<S>,
    /// The approval authorizing this credential use (binds the minted view).
    pub approval_id: ApprovalId,
    /// The current time, for the broker's one-shot view expiry checks.
    pub now: Timestamp,
    /// How long (ms) the minted view stays valid — bounded blast radius.
    pub ttl_millis: u64,
    /// The non-sensitive label used in the redaction marker (e.g. the secret's handle
    /// label). Never the value.
    pub label: &'b str,
}

/// A convenience "no broker context" for [`call_tool`] when every involved server is
/// `McpAuthMode::None`. Spelling the absent context's store type once here keeps the
/// common unauthenticated call site free of a turbofish: pass [`NO_AUTH`]. A
/// `BrokerSecret` server reached with `NO_AUTH` correctly fails closed
/// ([`CallOutcome::CredentialUnavailable`]).
pub type NoAuth<'b> = McpAuthContext<'b, crustcore_secrets::InMemoryStore>;

/// The "no broker context" value to pass to [`call_tool`] for unauthenticated
/// (`McpAuthMode::None`) servers. See [`NoAuth`].
pub const NO_AUTH: Option<&'static NoAuth<'static>> = None;

/// Resolves a server's [`McpAuthMode`] into an optional injectable credential for the
/// transport. `None` auth (or — defensively — a missing context) yields `Ok(None)`: an
/// unauthenticated call is correct for a `None` server. A `BrokerSecret` server with no
/// context or an unresolvable/expired secret yields `Err(secret_id)` so the caller can
/// **fail closed** rather than call unauthenticated (invariant 1). The minted
/// [`HeaderInjection`] holds the secret bytes off the model path (invariants 1–3).
fn resolve_auth<S: SecretStore>(
    auth: McpAuthMode,
    ctx: Option<&McpAuthContext<'_, S>>,
) -> Result<Option<HeaderInjection>, SecretId> {
    let McpAuthMode::BrokerSecret(secret_id) = auth else {
        // `McpAuthMode::None`: no credential is needed; the call goes unauthenticated.
        return Ok(None);
    };
    // From here a credential is REQUIRED; any failure must fail closed, not fall back.
    let ctx = ctx.ok_or(secret_id)?;
    let view = ctx
        .broker
        .authorize(secret_id, ctx.approval_id, ctx.now, ctx.ttl_millis)
        .map_err(|_| secret_id)?;
    let injection = CredentialProxy::bearer(&view, ctx.now, ctx.label).map_err(|_| secret_id)?;
    Ok(Some(injection))
}

/// A request to call one MCP tool: the target server/tool, the repo context the call
/// runs under, the (already-redacted, non-secret) arguments, and the live tool-surface
/// hash for drift detection. Grouping these keeps [`call_tool`] to one request value
/// instead of a long positional argument list.
pub struct ToolCall<'a> {
    /// The target server (must be registered).
    pub server: McpServerId,
    /// The tool name — the gateway keys policy on this.
    pub tool: &'a str,
    /// The repo the call runs under (checked against the record's `allowed_repos`).
    pub repo: &'a str,
    /// The tool arguments — already redacted, non-secret (the receipt binds these).
    pub args: &'a serde_json::Value,
    /// The live tool-surface hash, or `None` to skip drift detection (`docs/mcp.md` §4).
    pub live_manifest_hash: Option<[u8; 32]>,
}

/// Performs a **gated** MCP tool call end to end (`docs/mcp.md` §4): check the gateway
/// (the decision comes from the registry's `tool_policies`, **never** the server's
/// self-description), and only on `Allow` issue the JSON-RPC `tools/call`, then turn
/// the (untrusted) response into a redacted, bounded, receipted [`McpResult`] via
/// [`filter_result`]. `Ask` and `Deny` short-circuit **before** any call is made — a
/// denied or approval-needing tool never reaches the server.
///
/// The model is shown the **whole** response — redacted, then bounded — and the
/// artifact handle commits to the **full canonical response**, never a lossy
/// projection, so the receipt's artifact anchors exactly what the (untrusted) server
/// returned (invariant 10). The response is never interpreted as a command (invariant
/// 7); redaction runs over every field before anything is model-visible (invariant 2).
///
/// **Credential handling (P13-net):** on `Allow`, the server's [`McpAuthMode`] is
/// resolved via [`resolve_auth`] (`docs/mcp.md` §4 step 4) **after** the gateway and
/// **before** the transport call. A `McpAuthMode::BrokerSecret` is materialized through
/// the [`McpAuthContext`]'s [`SecretBroker`] → [`CredentialProxy::bearer`] into a
/// non-model-visible [`HeaderInjection`] that is handed to the transport, never placed
/// in `args`, the response, the model context, or a log (invariants 1–3). If the
/// credential cannot be resolved (no context, missing/expired secret) the call **fails
/// closed** as [`CallOutcome::CredentialUnavailable`] — it is never issued
/// unauthenticated (invariant 1). A `McpAuthMode::None` server passes `auth = None` and
/// calls unauthenticated, as before. The stdio transport ignores the header by
/// construction (it has no header channel; see [`transport::StdioMcp::call`]).
///
/// # Errors
/// [`transport::McpError`] if an *authorized* call fails at the transport/RPC layer.
pub fn call_tool<S: SecretStore>(
    registry: &McpRegistry,
    call: &ToolCall,
    transport: &dyn transport::McpTransport,
    auth_ctx: Option<&McpAuthContext<'_, S>>,
    redactor: &Redactor,
    receipts: &mut ReceiptChain,
    ids: &McpCallIds,
) -> Result<CallOutcome, transport::McpError> {
    match gateway_check(
        registry,
        call.server,
        call.tool,
        call.repo,
        call.live_manifest_hash,
    ) {
        GatewayDecision::Deny(reason) => return Ok(CallOutcome::Denied(reason)),
        GatewayDecision::Ask => return Ok(CallOutcome::NeedsApproval),
        GatewayDecision::Allow => {}
    }
    // The gateway already proved the server is registered; read its auth mode. (A
    // BrokerSecret server reached here only because the gate allowed *this tool* — the
    // credential is what the call needs to actually authenticate to the server.)
    let auth_mode = registry
        .get(call.server)
        .map_or(McpAuthMode::None, |r| r.auth);
    // Resolve the credential via the broker → CredentialProxy at call time. Fail CLOSED
    // if a required credential cannot be minted — never an unauthenticated call. The
    // resolved header holds the secret bytes off the model path (invariants 1–3); it is
    // injected at the transport boundary below, after the gateway Allow.
    let injection = match resolve_auth(auth_mode, auth_ctx) {
        Ok(maybe) => maybe,
        Err(secret_id) => return Ok(CallOutcome::CredentialUnavailable(secret_id)),
    };
    let raw = transport.call(
        "tools/call",
        serde_json::json!({ "name": call.tool, "arguments": call.args.clone() }),
        injection.as_ref(),
    )?;
    // Hash + show the FULL canonical response (not a lossy text projection): the model
    // sees the complete result redacted then bounded, and the artifact handle commits to
    // the whole untrusted response — `filter_result`'s artifact hash is then honestly the
    // full output it documents.
    let raw_bytes = serde_json::to_vec(&raw).unwrap_or_default();
    let args_bytes = serde_json::to_vec(call.args).unwrap_or_default();
    let result = filter_result(
        call.server,
        call.tool,
        &args_bytes,
        &raw_bytes,
        redactor,
        receipts,
        ids,
    );
    Ok(CallOutcome::Done(Box::new(result)))
}

/// A small helper to bound a [`ModelVisibleText`] to a byte cap (the redactor
/// already produced model-visible text; this enforces the result-size bound).
struct ModelVisibleTextExt;
impl ModelVisibleTextExt {
    fn bounded(mvt: &ModelVisibleText, max: usize) -> ModelVisibleText {
        // Re-bound through an (empty) redactor: truncation only, no secret in it.
        let bounded = BoundedText::truncated(mvt.as_str(), max);
        Redactor::new().to_model_visible(bounded.as_str())
    }
}

/// Wraps untrusted MCP-supplied text (a tool **description**, prompt, or resource)
/// for model context — redacted, **bounded**, and clearly *data*. Tool descriptions
/// are untrusted too (`docs/mcp.md` §2): an MCP server cannot smuggle an instruction
/// into the model through its self-description, because that text never controls the
/// gateway and is redacted before it is shown. It is bounded for the same reason
/// [`filter_result`] bounds tool output: a hostile server's description/resource is
/// attacker-controlled and could otherwise flood model context with megabytes of
/// (redacted but unbounded) text — "bounded everything" (CLAUDE.md §6.5). Redaction
/// runs first, then the already-redacted text is truncated, so no raw is reintroduced.
#[must_use]
pub fn wrap_untrusted(text: &str, redactor: &Redactor) -> ModelVisibleText {
    let redacted = redactor.to_model_visible(text);
    ModelVisibleTextExt::bounded(&redacted, MAX_MCP_SUMMARY)
}

// ---------------------------------------------------------------------------
// Code-mode stubs (P13.4) — invariant 20
// ---------------------------------------------------------------------------

/// A generated code-mode stub descriptor: a small typed API the model calls
/// programmatically, instead of seeing the whole MCP universe (`docs/mcp.md` §4).
/// Only stubs for **used** tools enter model context (invariant 20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StubDescriptor {
    /// The server this stub calls.
    pub server: McpServerId,
    /// The tool name.
    pub tool: String,
    /// A typed signature (the small API surface the model sees).
    pub signature: String,
}

/// Generates stub descriptors for exactly the `used_tools` of `record` — never the
/// server's full tool list — so unused tools cost zero model context (invariant
/// 20). A tool with no allow/ask policy is skipped (it could never be called).
#[must_use]
pub fn generate_stubs(record: &McpServerRecord, used_tools: &[&str]) -> Vec<StubDescriptor> {
    used_tools
        .iter()
        .filter(|t| {
            matches!(
                record.tool_decision(t),
                Some(ToolDecision::Allow | ToolDecision::Ask)
            )
        })
        .map(|t| StubDescriptor {
            server: record.id,
            tool: (*t).to_string(),
            signature: format!("fn {t}(args: Json) -> McpResult"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_receipts::MacKey;

    fn record() -> McpServerRecord {
        McpServerRecord {
            id: McpServerId(1),
            source: McpServerSource::LocalBinary("/usr/bin/some-mcp".into()),
            transport: McpTransport::Stdio,
            version: Some("1.0".into()),
            manifest_hash: Some(sha256(b"tool surface v1")),
            auth: McpAuthMode::BrokerSecret(SecretId(9)),
            trust_level: TrustLevel::SemiTrusted,
            allowed_repos: vec![RepoRef(BoundedText::truncated("RNT56/CrustCore", 64))],
            tool_policies: vec![
                McpToolPolicy {
                    tool: "search".into(),
                    decision: ToolDecision::Allow,
                },
                McpToolPolicy {
                    tool: "write_file".into(),
                    decision: ToolDecision::Ask,
                },
                McpToolPolicy {
                    tool: "rm_rf".into(),
                    decision: ToolDecision::Deny,
                },
            ],
        }
    }

    fn registry() -> McpRegistry {
        let mut r = McpRegistry::new();
        r.register(record());
        r
    }

    // --- gateway policy check (P13.2, invariant 8) ---

    #[test]
    fn gateway_allows_ask_denies_per_policy() {
        let reg = registry();
        let h = record().manifest_hash;
        assert_eq!(
            gateway_check(&reg, McpServerId(1), "search", "RNT56/CrustCore", h),
            GatewayDecision::Allow
        );
        assert_eq!(
            gateway_check(&reg, McpServerId(1), "write_file", "RNT56/CrustCore", h),
            GatewayDecision::Ask
        );
        assert_eq!(
            gateway_check(&reg, McpServerId(1), "rm_rf", "RNT56/CrustCore", h),
            GatewayDecision::Deny(GatewayDeny::ToolDenied)
        );
        // An unpoliced tool is denied by default (invariant 8).
        assert_eq!(
            gateway_check(&reg, McpServerId(1), "exfiltrate", "RNT56/CrustCore", h),
            GatewayDecision::Deny(GatewayDeny::ToolNotAllowed)
        );
    }

    #[test]
    fn gateway_denies_unknown_server_repo_mismatch_and_drift() {
        let reg = registry();
        let h = record().manifest_hash;
        assert_eq!(
            gateway_check(&reg, McpServerId(99), "search", "RNT56/CrustCore", h),
            GatewayDecision::Deny(GatewayDeny::UnknownServer)
        );
        assert_eq!(
            gateway_check(&reg, McpServerId(1), "search", "other/repo", h),
            GatewayDecision::Deny(GatewayDeny::RepoNotAllowed)
        );
        // Live manifest differs from the pinned one → drift → deny (re-gate).
        assert_eq!(
            gateway_check(
                &reg,
                McpServerId(1),
                "search",
                "RNT56/CrustCore",
                Some(sha256(b"tool surface v2"))
            ),
            GatewayDecision::Deny(GatewayDeny::ManifestDrift)
        );
    }

    // --- result redaction + receipting (P13.3, invariants 2/10) ---

    #[test]
    fn filter_result_redacts_bounds_and_receipts() {
        let mut redactor = Redactor::new();
        redactor.register("mcp-token", b"sk-MCPSENTINEL");
        let mut receipts = ReceiptChain::new(MacKey::new([0x31; 32]));
        let ids = McpCallIds {
            task_id: TaskId(1),
            job_id: JobId(1),
            tool_call_id: ToolCallId(1),
            event_seq: EventSeq(1),
        };
        let raw = b"result with secret sk-MCPSENTINEL and lots of data";
        let call_args = br#"{"query":"needle"}"#;
        let out = filter_result(
            McpServerId(1),
            "search",
            call_args,
            raw,
            &redactor,
            &mut receipts,
            &ids,
        );
        // The secret is redacted before model visibility (invariant 2).
        assert!(!out.summary.as_str().contains("MCPSENTINEL"));
        assert!(out.summary.as_str().contains("[REDACTED:mcp-token]"));
        // The artifact handle is the hash of the FULL raw output.
        assert_eq!(out.artifact_hash, sha256(raw));
        // The receipt binds to exactly the shown (redacted) summary (invariant 10).
        assert!(out.receipt.result_matches(out.summary.as_str().as_bytes()));
        // The receipt binds the real call args, not just the tool name: a receipt
        // minted for the same tool with different args must not match these args.
        assert!(out.receipt.args_matches(call_args));
        assert!(!out.receipt.args_matches(b"search"));
    }

    // --- code-mode stubs (P13.4, invariant 20) ---

    #[test]
    fn only_used_and_policied_tools_get_stubs() {
        let rec = record();
        // Ask for two tools, one of which is denied (rm_rf) and one unpoliced (x).
        let stubs = generate_stubs(&rec, &["search", "rm_rf", "x"]);
        // Only the allow/ask tool ("search") yields a stub; denied/unpoliced skipped.
        assert_eq!(stubs.len(), 1);
        assert_eq!(stubs[0].tool, "search");
        // Unused tools (write_file) cost zero context — not generated.
        assert!(!stubs.iter().any(|s| s.tool == "write_file"));
    }
}
