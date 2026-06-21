// SPDX-License-Identifier: Apache-2.0
//! The flow builder (C3.1).
//!
//! [`FlowBuilder`] constructs a [`Flow`] node-by-node. Its constructors default every
//! classification to the **most restrictive** posture so a forgotten field fails
//! closed (Track C P2):
//! - a `tool` node defaults to [`ToolSpec::fail_closed`] — `Destructive` reversibility
//!   (policy requires approval / denies) and execution-capable (needs a sandbox);
//! - untrusted output is always redacted + bounded by the engine (there is no
//!   "redact-off" knob);
//! - the recommended budget is [`FlowBudget::fail_closed`] (tight caps).
//!
//! The builder hands back typed [`NodeId`]s so a flow is wired by id, not by string —
//! and validates structurally before it runs.

use std::collections::BTreeMap;

use crate::budget::FlowBudget;
use crate::graph::{Flow, FlowError, Node, NodeId, ToolSpec};
use crate::predicate::Predicate;

/// Builds a [`Flow`]. Reserve node ids up front with [`FlowBuilder::reserve`], then
/// define each with the typed constructors; finish with [`FlowBuilder::build`].
#[derive(Default)]
pub struct FlowBuilder {
    nodes: BTreeMap<NodeId, Node>,
    next_id: u32,
    entry: Option<NodeId>,
}

impl FlowBuilder {
    /// A new, empty builder.
    #[must_use]
    pub fn new() -> Self {
        FlowBuilder::default()
    }

    /// Reserves a fresh [`NodeId`] so forward references (loops, joins, branches) can
    /// be wired before the target is defined.
    pub fn reserve(&mut self) -> NodeId {
        let id = NodeId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Sets the entry node.
    pub fn entry(&mut self, id: NodeId) -> &mut Self {
        self.entry = Some(id);
        self
    }

    /// Defines a `model` node at `id`: consult a model with `prompt`, record the
    /// redacted output under `out_key`, then go to `next`.
    pub fn model(
        &mut self,
        id: NodeId,
        prompt: impl Into<String>,
        out_key: impl Into<String>,
        next: NodeId,
    ) -> &mut Self {
        self.nodes.insert(
            id,
            Node::Model {
                prompt: prompt.into(),
                out_key: out_key.into(),
                next,
            },
        );
        self
    }

    /// Defines a `tool` node at `id` with an **explicit** [`ToolSpec`]. Prefer
    /// [`FlowBuilder::tool_fail_closed`] unless you have deliberately classified the
    /// tool as less restrictive.
    pub fn tool(
        &mut self,
        id: NodeId,
        spec: ToolSpec,
        args: impl Into<String>,
        out_key: impl Into<String>,
        next: NodeId,
    ) -> &mut Self {
        self.nodes.insert(
            id,
            Node::Tool {
                spec,
                args: args.into(),
                out_key: out_key.into(),
                next,
            },
        );
        self
    }

    /// Defines a `tool` node at `id` with the **fail-closed** spec (`Destructive`,
    /// execution-capable). This is the safe default: such a tool needs both a
    /// non-read-only policy profile *and* a valid approval token to run.
    pub fn tool_fail_closed(
        &mut self,
        id: NodeId,
        name: impl Into<String>,
        args: impl Into<String>,
        out_key: impl Into<String>,
        next: NodeId,
    ) -> &mut Self {
        self.tool(id, ToolSpec::fail_closed(name), args, out_key, next)
    }

    /// Defines a `verify` node at `id`: the sole completion path. On a non-pass it
    /// continues to `on_fail` (a loop, a route, or `End`).
    pub fn verify(&mut self, id: NodeId, on_fail: NodeId) -> &mut Self {
        self.nodes.insert(id, Node::Verify { on_fail });
        self
    }

    /// Defines a `review` node at `id`: an advisory check; record the redacted
    /// rationale under `out_key`, then go to `next`.
    pub fn review(&mut self, id: NodeId, out_key: impl Into<String>, next: NodeId) -> &mut Self {
        self.nodes.insert(
            id,
            Node::Review {
                out_key: out_key.into(),
                next,
            },
        );
        self
    }

    /// Defines a `parallel` node at `id` with a hard `max_concurrency` cap, then a
    /// `join`.
    pub fn parallel(
        &mut self,
        id: NodeId,
        children: Vec<NodeId>,
        max_concurrency: usize,
        join: NodeId,
    ) -> &mut Self {
        self.nodes.insert(
            id,
            Node::Parallel {
                children,
                max_concurrency: max_concurrency.max(1),
                join,
            },
        );
        self
    }

    /// Defines a `loop_until` node at `id`: run `body` until `until` (over typed state)
    /// holds or `max_iterations` is reached, then go to `next`.
    pub fn loop_until(
        &mut self,
        id: NodeId,
        body: NodeId,
        until: Predicate,
        max_iterations: u32,
        next: NodeId,
    ) -> &mut Self {
        self.nodes.insert(
            id,
            Node::LoopUntil {
                body,
                until,
                max_iterations,
                next,
            },
        );
        self
    }

    /// Defines a `route` node at `id`: branch on a typed-state predicate.
    pub fn route(
        &mut self,
        id: NodeId,
        predicate: Predicate,
        if_true: NodeId,
        if_false: NodeId,
    ) -> &mut Self {
        self.nodes.insert(
            id,
            Node::Route {
                predicate,
                if_true,
                if_false,
            },
        );
        self
    }

    /// Defines a `join` node at `id` that continues to `next`.
    pub fn join(&mut self, id: NodeId, next: NodeId) -> &mut Self {
        self.nodes.insert(id, Node::Join { next });
        self
    }

    /// Defines an `End` terminal at `id` (the flow ends without completing).
    pub fn end(&mut self, id: NodeId) -> &mut Self {
        self.nodes.insert(id, Node::End);
        self
    }

    /// The recommended starting budget: the tight, fail-closed one. Callers raise its
    /// caps explicitly for larger plans.
    #[must_use]
    pub fn default_budget() -> FlowBudget {
        FlowBudget::fail_closed()
    }

    /// Finishes the build, validating structure (entry present, all references exist).
    ///
    /// # Errors
    /// [`FlowError::NoEntry`] / [`FlowError::UnknownNode`].
    pub fn build(self) -> Result<Flow, FlowError> {
        let entry = self.entry.ok_or(FlowError::NoEntry)?;
        let flow = Flow {
            nodes: self.nodes,
            entry,
        };
        flow.validate()?;
        Ok(flow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_types::Reversibility;

    #[test]
    fn tool_fail_closed_default_is_destructive_and_execution_capable() {
        let mut b = FlowBuilder::new();
        let t = b.reserve();
        let e = b.reserve();
        b.entry(t)
            .tool_fail_closed(t, "rm", "-rf /", "out", e)
            .end(e);
        let flow = b.build().unwrap();
        match flow.node(t).unwrap() {
            Node::Tool { spec, .. } => {
                assert_eq!(spec.reversibility, Reversibility::Destructive);
                assert!(spec.execution_capable);
            }
            other => panic!("expected a tool node, got {other:?}"),
        }
    }

    #[test]
    fn build_rejects_dangling_reference() {
        let mut b = FlowBuilder::new();
        let m = b.reserve();
        let missing = NodeId(999);
        b.entry(m).model(m, "p", "out", missing);
        assert_eq!(b.build().err(), Some(FlowError::UnknownNode(missing)));
    }

    #[test]
    fn build_rejects_missing_entry() {
        let b = FlowBuilder::new();
        assert_eq!(b.build().err(), Some(FlowError::NoEntry));
    }

    #[test]
    fn default_budget_is_fail_closed() {
        assert_eq!(FlowBuilder::default_budget(), FlowBudget::fail_closed());
    }
}
