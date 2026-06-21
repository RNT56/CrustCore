// SPDX-License-Identifier: Apache-2.0
//! Workflow debugger (`C7.5`). Load + *simulate* single-stepping a `crustcore-flow`
//! (C3) graph with a **no-op driver**.
//!
//! The simulation is pure structural traversal of the graph: it dispatches **no kernel
//! `Action`**, appends **no frame** to any live log, spawns no sandbox/`ExecutionDriver`,
//! and never reaches `verify::run_verify`. It therefore cannot complete a task or mint a
//! `VerifiedPatch` — a `Verify` node simulates as "would run verify" and a `Route`/`Loop`
//! node simulates the *structure* (it shows both branches as the next candidates), never
//! evaluating an untrusted predicate against live model/tool output.
//!
//! The graph file is untrusted; the C3 [`Flow`](crustcore_flow::graph::Flow) is already
//! built with bounds (node count, fan-out caps), so we render and step over it inertly.

use crate::backend::{FlowGraphView, FlowStepView};
use crustcore_flow::graph::{Flow, Node, NodeId};
use crustcore_secrets::Redactor;

/// Render the graph as nodes + edges for visualization. Pure read over the C3 graph.
#[must_use]
pub fn render_graph(flow: &Flow) -> FlowGraphView {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // Walk node ids densely from 0; the C3 builder assigns ids from a counter.
    for raw in 0..(flow.len() as u32) {
        let id = NodeId(raw);
        let Some(node) = flow.node(id) else {
            continue;
        };
        nodes.push((raw, kind_label(node).to_string()));
        for to in successors(node) {
            edges.push((raw, to.0));
        }
    }

    FlowGraphView {
        nodes,
        edges,
        entry: flow.entry().0,
    }
}

/// Simulate one step from `from_node` with a no-op driver. Returns the rendered step (the
/// node's kind + a redacted note) and whether the simulation reached a terminal node. It
/// executes nothing: no driver runs, no `Action` is dispatched, no `VerifiedPatch` is
/// minted (the `finished` flag is reached only at an `End`/terminal node).
#[must_use]
pub fn simulate_step(flow: &Flow, from_node: u32, redactor: &Redactor) -> Option<FlowStepView> {
    let node = flow.node(NodeId(from_node))?;
    // The note describes what a *live* run WOULD do — it is a closed-form description
    // (never untrusted text); redacted defensively before render.
    let note = redactor.redact(&simulated_note(node));
    let finished = matches!(node, Node::Verify { .. } | Node::End);
    Some(FlowStepView {
        node_id: from_node,
        kind: kind_label(node).to_string(),
        note,
        // A `Verify` node simulates as "would run verify" and terminates the simulation
        // WITHOUT minting a VerifiedPatch (the no-op driver returns no `Verified`). `End`
        // is the natural terminus.
        finished,
    })
}

/// The structural successors of a node (for edge rendering). A `Route`/`LoopUntil`
/// surfaces *both* branches; we never evaluate a predicate over untrusted output.
fn successors(node: &Node) -> Vec<NodeId> {
    match node {
        Node::Model { next, .. }
        | Node::Tool { next, .. }
        | Node::Review { next, .. }
        | Node::Join { next, .. } => vec![*next],
        Node::Verify { on_fail } => vec![*on_fail],
        Node::Parallel { children, join, .. } => {
            let mut s = children.clone();
            s.push(*join);
            s
        }
        Node::LoopUntil { body, next, .. } => vec![*body, *next],
        Node::Route {
            if_true, if_false, ..
        } => vec![*if_true, *if_false],
        Node::End => Vec::new(),
    }
}

fn kind_label(node: &Node) -> &'static str {
    match node {
        Node::Model { .. } => "model",
        Node::Tool { .. } => "tool",
        Node::Verify { .. } => "verify",
        Node::Review { .. } => "review",
        Node::Parallel { .. } => "parallel",
        Node::LoopUntil { .. } => "loop_until",
        Node::Route { .. } => "route",
        Node::Join { .. } => "join",
        Node::End => "end",
    }
}

fn simulated_note(node: &Node) -> String {
    match node {
        Node::Model { out_key, .. } => format!("would call model -> {out_key} (no-op driver)"),
        Node::Tool { spec, out_key, .. } => {
            format!("would run tool {} -> {out_key} (no-op driver)", spec.name)
        }
        Node::Verify { .. } => {
            "would run verify (no-op: mints no VerifiedPatch, completes no task)".to_string()
        }
        Node::Review { out_key, .. } => format!("would request review -> {out_key} (no-op)"),
        Node::Parallel {
            max_concurrency, ..
        } => format!("would fan out (max_concurrency={max_concurrency})"),
        Node::LoopUntil { max_iterations, .. } => {
            format!("would loop (max_iterations={max_iterations})")
        }
        Node::Route { .. } => "would branch (both successors shown; predicate not run)".to_string(),
        Node::Join { .. } => "would join parallel branches".to_string(),
        Node::End => "end of flow".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_flow::builder::FlowBuilder;

    fn small_flow() -> Flow {
        let mut b = FlowBuilder::new();
        let model = b.reserve();
        let verify = b.reserve();
        let end = b.reserve();
        b.entry(model)
            .model(model, "analyze", "analysis", verify)
            .verify(verify, end)
            .end(end);
        b.build().unwrap()
    }

    #[test]
    fn renders_nodes_and_edges() {
        let flow = small_flow();
        let view = render_graph(&flow);
        assert_eq!(view.nodes.len(), 3);
        assert_eq!(view.entry, 0);
        let labels: Vec<&str> = view.nodes.iter().map(|(_, l)| l.as_str()).collect();
        assert!(labels.contains(&"model"));
        assert!(labels.contains(&"verify"));
        assert!(labels.contains(&"end"));
    }

    #[test]
    fn simulating_a_verify_node_never_completes() {
        let flow = small_flow();
        let redactor = Redactor::new();
        // Step the verify node (id 1). It must finish the simulation but mint nothing.
        let step = simulate_step(&flow, 1, &redactor).unwrap();
        assert_eq!(step.kind, "verify");
        assert!(step.finished);
        // The note explicitly states no VerifiedPatch is minted.
        assert!(step.note.contains("mints no VerifiedPatch"));
    }

    #[test]
    fn simulating_a_model_node_is_inert() {
        let flow = small_flow();
        let redactor = Redactor::new();
        let step = simulate_step(&flow, 0, &redactor).unwrap();
        assert_eq!(step.kind, "model");
        assert!(!step.finished);
        assert!(step.note.contains("no-op driver"));
    }

    #[test]
    fn note_is_redacted() {
        // A sentinel in a (hypothetical) out_key would be scrubbed. We register a needle
        // matching part of the closed-form note's content to prove the redactor runs.
        let flow = small_flow();
        let mut redactor = Redactor::new();
        redactor.register("kw", b"analysis");
        let step = simulate_step(&flow, 0, &redactor).unwrap();
        assert!(
            !step.note.contains("analysis"),
            "redactor must run on the note"
        );
    }

    #[test]
    fn out_of_range_node_is_none() {
        let flow = small_flow();
        let redactor = Redactor::new();
        assert!(simulate_step(&flow, 999, &redactor).is_none());
    }
}
