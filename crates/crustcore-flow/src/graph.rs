// SPDX-License-Identifier: Apache-2.0
//! The typed graph (C3.1): [`Node`], [`NodeId`], [`FlowState`], [`FlowError`], and
//! [`Flow`].
//!
//! Everything here is pure data describing a *plan*. No node carries an authority
//! object: there is no `Approved<T>` field on any node, no `VerifiedPatch`, no
//! capability. Authority lives only in [`FlowState`] (the externally-minted approval
//! set) and is produced only by `crustcore-policy` — never by this crate.

use std::collections::BTreeMap;

use crustcore_policy::caps::Approved;
use crustcore_types::Reversibility;

use crate::predicate::Predicate;

/// A stable identifier for a node within one [`Flow`]. Opaque, comparable, ordered —
/// so scheduling is deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u32);

/// What a `Tool` node intends to do, as pure data. The reversibility classification
/// is what `crustcore_policy::PolicySnapshot::classify` reads; the builder defaults
/// it to the most restrictive [`Reversibility::Destructive`] so a forgotten field
/// fails closed (invariants 8, 14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSpec {
    /// The tool's name (audit/diagnostic only — never used as authority).
    pub name: String,
    /// How reversible the tool's effect is. Drives policy classification. Defaults to
    /// `Destructive` in the builder (fail closed).
    pub reversibility: Reversibility,
    /// Whether the tool is execution-capable and therefore requires a sandbox profile
    /// when run live (invariant 9). Defaults to `true` (fail closed): an unclassified
    /// tool is treated as needing the sandbox.
    pub execution_capable: bool,
}

impl ToolSpec {
    /// A tool spec with the **most restrictive** posture: destructive (so policy
    /// requires approval / denies), execution-capable (so it needs a sandbox). The
    /// builder uses this; callers loosen explicitly.
    #[must_use]
    pub fn fail_closed(name: impl Into<String>) -> Self {
        ToolSpec {
            name: name.into(),
            reversibility: Reversibility::Destructive,
            execution_capable: true,
        }
    }

    /// Whether running this tool requires an approval token to be present in
    /// [`FlowState`] before the engine will let it proceed (invariant 14).
    #[must_use]
    pub fn requires_approval(&self) -> bool {
        self.reversibility.requires_approval()
    }
}

/// A node in the flow graph. Effectful nodes name *what to attempt*; the engine runs
/// them only through an injected driver. No variant carries an authority object.
pub enum Node {
    /// Consult a model role (advisory data only — never authority, never user-facing).
    /// Runs through the injected [`ModelDriver`](crate::drivers::ModelDriver). Stores
    /// its (tainted, redacted, bounded) output under `out_key` in [`FlowState`].
    Model {
        /// A bounded prompt/decision handed to the model driver.
        prompt: String,
        /// Where the redacted output is recorded in [`FlowState`].
        out_key: String,
        /// The node to run next.
        next: NodeId,
    },
    /// Invoke a policy-gated tool. Classified through `crustcore-policy` before it can
    /// run (invariant 8); irreversible tools require an approval token in
    /// [`FlowState`] (invariant 14); execution-capable tools pass a sandbox profile
    /// when run live (invariant 9). Records its redacted output under `out_key`.
    Tool {
        /// What the tool does (classification + sandbox posture).
        spec: ToolSpec,
        /// A bounded argument string for the tool driver.
        args: String,
        /// Where the redacted output is recorded in [`FlowState`].
        out_key: String,
        /// The node to run next.
        next: NodeId,
    },
    /// Rerun the user verify command via the injected
    /// [`VerifyDriver`](crate::drivers::VerifyDriver) (→ public
    /// `crustcore_backend::verify::run_verify`). **The sole completion path**
    /// (invariant 13): only a `Verified` outcome completes the flow. A `Failed`/
    /// `Refused` outcome continues to `on_fail` (e.g. a loop or a terminal).
    Verify {
        /// Where to go if verification did **not** pass (it never completes the flow).
        on_fail: NodeId,
    },
    /// An advisory `crustcore-daemon::advisor` check. Its note is engine-internal
    /// advisory data: it never authorizes, never reaches the user, never completes a
    /// flow (invariants 4, 5, 6). Records its redacted rationale under `out_key`.
    Review {
        /// Where the redacted rationale is recorded in [`FlowState`].
        out_key: String,
        /// The node to run next.
        next: NodeId,
    },
    /// Bounded fan-out: run each child, honoring `max_concurrency` (invariant 11).
    /// Children must be `Join`-free terminals or lead into a single `join`.
    Parallel {
        /// The child nodes to run.
        children: Vec<NodeId>,
        /// Hard cap on how many children run "concurrently" (the deterministic engine
        /// schedules them in bounded waves of this width).
        max_concurrency: usize,
        /// The join node that merges the children.
        join: NodeId,
    },
    /// Bounded iteration: run `body` until `until` holds over typed [`FlowState`], or
    /// until `max_iterations` is reached (invariant 11). The predicate reads only
    /// typed state — never raw model/tool text (invariant 7).
    LoopUntil {
        /// The node that begins one loop body.
        body: NodeId,
        /// The exit predicate, evaluated over typed [`FlowState`] only.
        until: Predicate,
        /// Hard cap on iterations (fail closed: a missing predicate exits at the cap,
        /// it never loops forever).
        max_iterations: u32,
        /// Where to go once the loop exits (predicate true or cap reached).
        next: NodeId,
    },
    /// Branch over typed [`FlowState`] only (invariant 7). Hostile model/tool text
    /// cannot reach a predicate un-tainted, so it cannot steer the branch.
    Route {
        /// The predicate over typed state.
        predicate: Predicate,
        /// Where to go when the predicate is true.
        if_true: NodeId,
        /// Where to go when the predicate is false.
        if_false: NodeId,
    },
    /// Merge child results (a structural rendezvous point; merging is recording that
    /// children completed). Continues to `next`.
    Join {
        /// The node to run after the join.
        next: NodeId,
    },
    /// A terminal node: the flow ends here without completing (no `VerifiedPatch`).
    /// Used as the failure sink and as `LoopUntil`/`Route` dead ends.
    End,
}

impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A diagnostic shape only — no node carries secret/authority data, but we keep
        // Debug terse and stable for test assertions.
        match self {
            Node::Model { out_key, next, .. } => f
                .debug_struct("Model")
                .field("out_key", out_key)
                .field("next", next)
                .finish(),
            Node::Tool {
                spec,
                out_key,
                next,
                ..
            } => f
                .debug_struct("Tool")
                .field("spec", spec)
                .field("out_key", out_key)
                .field("next", next)
                .finish(),
            Node::Verify { on_fail } => f.debug_struct("Verify").field("on_fail", on_fail).finish(),
            Node::Review { out_key, next } => f
                .debug_struct("Review")
                .field("out_key", out_key)
                .field("next", next)
                .finish(),
            Node::Parallel {
                children,
                max_concurrency,
                join,
            } => f
                .debug_struct("Parallel")
                .field("children", children)
                .field("max_concurrency", max_concurrency)
                .field("join", join)
                .finish(),
            Node::LoopUntil {
                body,
                max_iterations,
                next,
                ..
            } => f
                .debug_struct("LoopUntil")
                .field("body", body)
                .field("max_iterations", max_iterations)
                .field("next", next)
                .finish(),
            Node::Route {
                if_true, if_false, ..
            } => f
                .debug_struct("Route")
                .field("if_true", if_true)
                .field("if_false", if_false)
                .finish(),
            Node::Join { next } => f.debug_struct("Join").field("next", next).finish(),
            Node::End => f.write_str("End"),
        }
    }
}

/// The typed, evolving state of a running flow. **Predicates read this and only
/// this** — never raw model/tool text (invariant 7).
///
/// `outputs` holds **already-redacted, bounded** strings keyed by name (set by the
/// engine after passing each effectful node's untrusted output through `Tainted` +
/// `Redactor` + bounding — see [`crate::predicate`]). `flags`/`counters` are typed
/// scalars a predicate can branch on.
///
/// `approvals` carries **externally-minted** [`Approved`] tokens (e.g. for an
/// irreversible tool node). It is deliberately **not** `Serialize`, `Clone`, or
/// `Default`-constructible with content: an `Approved<()>` can come only from
/// `AuthorizedUser::approve`, and no node ever writes to this field — the engine only
/// *reads* it (invariants 4, 14).
#[derive(Default)]
pub struct FlowState {
    /// Redacted, bounded outputs recorded by effectful nodes, keyed by `out_key`.
    outputs: BTreeMap<String, String>,
    /// Typed boolean flags a predicate may branch on.
    flags: BTreeMap<String, bool>,
    /// Typed integer counters a predicate may branch on.
    counters: BTreeMap<String, i64>,
    /// Externally-minted approval tokens for irreversible nodes. The engine reads, but
    /// never writes, this field; it is non-`Serialize`/non-forgeable by construction
    /// (the `Approved<()>` type-seal).
    approvals: Vec<Approved<()>>,
}

impl FlowState {
    /// An empty state.
    #[must_use]
    pub fn new() -> Self {
        FlowState::default()
    }

    /// Records a **redacted, bounded** output under `key`. Called by the engine after
    /// it declassifies an effectful node's untrusted output — never with raw text.
    pub fn set_output(&mut self, key: impl Into<String>, redacted: impl Into<String>) {
        self.outputs.insert(key.into(), redacted.into());
    }

    /// The redacted output recorded under `key`, if any.
    #[must_use]
    pub fn output(&self, key: &str) -> Option<&str> {
        self.outputs.get(key).map(String::as_str)
    }

    /// Sets a typed boolean flag a predicate may branch on.
    pub fn set_flag(&mut self, key: impl Into<String>, value: bool) {
        self.flags.insert(key.into(), value);
    }

    /// Reads a typed boolean flag (absent ⇒ `false`, fail closed).
    #[must_use]
    pub fn flag(&self, key: &str) -> bool {
        self.flags.get(key).copied().unwrap_or(false)
    }

    /// Sets a typed integer counter a predicate may branch on.
    pub fn set_counter(&mut self, key: impl Into<String>, value: i64) {
        self.counters.insert(key.into(), value);
    }

    /// Reads a typed integer counter (absent ⇒ `0`).
    #[must_use]
    pub fn counter(&self, key: &str) -> i64 {
        self.counters.get(key).copied().unwrap_or(0)
    }

    /// Adds an externally-minted approval token. Called **only** at the trusted setup
    /// boundary by the supervisor that built the flow — never by a node. An
    /// `Approved<()>` argument can come only from `AuthorizedUser::approve`.
    pub fn add_approval(&mut self, approval: Approved<()>) {
        self.approvals.push(approval);
    }

    /// Whether a valid (unexpired-at-`now_millis`) approval is present — the gate an
    /// irreversible node must pass (invariant 14). The engine consults this; no node
    /// can synthesize an entry here.
    #[must_use]
    pub fn has_valid_approval(&self, now_millis: u64) -> bool {
        let now = crustcore_types::Timestamp::from_millis(now_millis);
        self.approvals.iter().any(|a| a.is_valid_at(now))
    }
}

/// Why a flow is structurally invalid or could not run to a meaningful end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// A node referenced an id that is not in the graph.
    UnknownNode(NodeId),
    /// The flow has no node registered at its declared entry.
    NoEntry,
    /// An irreversible node was reached without a valid approval token in state
    /// (invariant 14). Carries the offending node.
    ApprovalRequired(NodeId),
    /// A tool node was denied by policy (invariant 8). Carries the reason.
    PolicyDenied {
        /// The node policy denied.
        node: NodeId,
        /// Non-sensitive reason from `crustcore-policy`.
        reason: String,
    },
    /// A driver failed to run an effectful node. Carries a bounded reason.
    Driver(String),
    /// The flow's [`FlowBudget`](crate::budget::FlowBudget) was breached
    /// (invariant 11). Carries the breached axis description.
    BudgetExceeded(String),
    /// The engine took more node steps than the flow's hard step cap allows — a
    /// structural backstop against a cyclic non-loop graph (invariant 11).
    StepCapExceeded,
}

impl core::fmt::Display for FlowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FlowError::UnknownNode(n) => write!(f, "unknown node {}", n.0),
            FlowError::NoEntry => write!(f, "flow has no entry node"),
            FlowError::ApprovalRequired(n) => {
                write!(f, "node {} requires an approval token", n.0)
            }
            FlowError::PolicyDenied { node, reason } => {
                write!(f, "node {} denied by policy: {reason}", node.0)
            }
            FlowError::Driver(e) => write!(f, "driver error: {e}"),
            FlowError::BudgetExceeded(a) => write!(f, "flow budget exceeded: {a}"),
            FlowError::StepCapExceeded => write!(f, "flow exceeded its step cap"),
        }
    }
}

impl std::error::Error for FlowError {}

/// A flow graph: a map of [`NodeId`] → [`Node`] plus the entry node. Built via
/// [`FlowBuilder`](crate::builder::FlowBuilder).
pub struct Flow {
    pub(crate) nodes: BTreeMap<NodeId, Node>,
    pub(crate) entry: NodeId,
}

impl Flow {
    /// The node registered at `id`, if any.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(&id)
    }

    /// The entry node id.
    #[must_use]
    pub fn entry(&self) -> NodeId {
        self.entry
    }

    /// How many nodes the flow has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the flow has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Validates that every referenced node exists and the entry is present. A flow
    /// that points at a missing node is rejected before it runs (fail closed).
    ///
    /// # Errors
    /// [`FlowError::NoEntry`] / [`FlowError::UnknownNode`].
    pub fn validate(&self) -> Result<(), FlowError> {
        if !self.nodes.contains_key(&self.entry) {
            return Err(FlowError::NoEntry);
        }
        for node in self.nodes.values() {
            for referenced in node_targets(node) {
                if !self.nodes.contains_key(&referenced) {
                    return Err(FlowError::UnknownNode(referenced));
                }
            }
        }
        Ok(())
    }
}

/// Every node id a node points at (for validation + diagnostics).
fn node_targets(node: &Node) -> Vec<NodeId> {
    match node {
        Node::Model { next, .. } | Node::Review { next, .. } | Node::Join { next } => vec![*next],
        Node::Tool { next, .. } => vec![*next],
        Node::Verify { on_fail } => vec![*on_fail],
        Node::Parallel { children, join, .. } => {
            let mut v = children.clone();
            v.push(*join);
            v
        }
        Node::LoopUntil { body, next, .. } => vec![*body, *next],
        Node::Route {
            if_true, if_false, ..
        } => vec![*if_true, *if_false],
        Node::End => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_policy::caps::AuthorizedUser;
    use crustcore_types::{ApprovalId, Timestamp};

    #[test]
    fn tool_spec_fail_closed_is_most_restrictive() {
        let s = ToolSpec::fail_closed("rm");
        assert_eq!(s.reversibility, Reversibility::Destructive);
        assert!(s.execution_capable);
        assert!(s.requires_approval());
    }

    #[test]
    fn state_defaults_fail_closed() {
        let st = FlowState::new();
        // Absent flag is false; absent counter is zero; no approval present.
        assert!(!st.flag("missing"));
        assert_eq!(st.counter("missing"), 0);
        assert!(!st.has_valid_approval(0));
        assert!(st.output("missing").is_none());
    }

    #[test]
    fn approval_is_read_only_and_externally_minted() {
        let mut st = FlowState::new();
        // The only way to get an Approved<()> is AuthorizedUser::approve — there is no
        // node-reachable constructor. The supervisor adds it at setup.
        let user = AuthorizedUser::bind(7);
        let approval = user.approve((), ApprovalId(1), Timestamp::from_millis(1_000));
        st.add_approval(approval);
        assert!(st.has_valid_approval(1_000));
        assert!(st.has_valid_approval(500));
        // Expired approvals do not count.
        assert!(!st.has_valid_approval(1_001));
    }
}
