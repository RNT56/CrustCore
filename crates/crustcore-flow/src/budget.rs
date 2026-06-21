// SPDX-License-Identifier: Apache-2.0
//! Per-flow budget (C3.6, invariant 11).
//!
//! A [`FlowBudget`] caps the total work a flow may attempt: wall time, node steps,
//! cumulative fan-out (children spawned by `Parallel` nodes), and model cost. The
//! engine charges each axis as it runs and **halts on the first breach** — runaway
//! fan-out or iteration cannot exhaust resources (red-team dimension (f)).
//!
//! The irreversibility/approval gate (an irreversible node halting unless an
//! `Approved<T>` is present in `FlowState`) lives next to the budget conceptually but
//! is enforced in the engine against [`FlowState`](crate::graph::FlowState), whose
//! approval field is non-forgeable (see `graph.rs`).

/// Caps on the total work one flow may attempt (invariant 11). Each is a hard ceiling
/// the engine enforces; a forgotten budget should be built via
/// [`FlowBudget::fail_closed`] (tight defaults), not left unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowBudget {
    /// Max cumulative model "cost" units the flow may charge (model nodes).
    pub max_model_cost: u64,
    /// Max wall-clock milliseconds the flow may charge across all nodes.
    pub max_wall_ms: u64,
    /// Max node steps the engine may take (a backstop against a cyclic non-loop graph
    /// even before a loop's own `max_iterations` applies).
    pub max_steps: u32,
    /// Max cumulative fan-out: total children scheduled across all `Parallel` nodes.
    pub max_total_fanout: u32,
}

impl FlowBudget {
    /// A **tight, fail-closed** budget — the builder's default. Small enough that an
    /// unconfigured flow halts quickly rather than running away. Callers raise the
    /// caps explicitly for larger plans.
    #[must_use]
    pub const fn fail_closed() -> Self {
        FlowBudget {
            max_model_cost: 0,
            max_wall_ms: 0,
            max_steps: 64,
            max_total_fanout: 0,
        }
    }

    /// A convenience budget with explicit caps.
    #[must_use]
    pub const fn new(
        max_model_cost: u64,
        max_wall_ms: u64,
        max_steps: u32,
        max_total_fanout: u32,
    ) -> Self {
        FlowBudget {
            max_model_cost,
            max_wall_ms,
            max_steps,
            max_total_fanout,
        }
    }
}

/// Which axis a charge would breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetBreach {
    /// Model cost cap exceeded.
    ModelCost,
    /// Wall-clock cap exceeded.
    Wall,
    /// Step cap exceeded.
    Steps,
    /// Total fan-out cap exceeded.
    Fanout,
}

impl BudgetBreach {
    /// A short non-sensitive description for [`FlowError`](crate::graph::FlowError).
    #[must_use]
    pub fn axis(self) -> &'static str {
        match self {
            BudgetBreach::ModelCost => "model cost",
            BudgetBreach::Wall => "wall time",
            BudgetBreach::Steps => "steps",
            BudgetBreach::Fanout => "total fan-out",
        }
    }
}

/// Running totals charged against a [`FlowBudget`]. The engine threads one of these
/// through the run and charges before doing the work, so a breach halts **before** the
/// over-limit work happens (invariant 11).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowUsage {
    /// Model cost charged so far.
    pub model_cost: u64,
    /// Wall-clock ms charged so far.
    pub wall_ms: u64,
    /// Node steps taken so far.
    pub steps: u32,
    /// Total fan-out scheduled so far.
    pub fanout: u32,
}

impl FlowUsage {
    /// Charges one node step. Returns the breach if the step cap would be exceeded;
    /// the step is **not** applied on breach.
    ///
    /// # Errors
    /// [`BudgetBreach::Steps`].
    pub fn charge_step(&mut self, budget: &FlowBudget) -> Result<(), BudgetBreach> {
        let next = self.steps.saturating_add(1);
        if next > budget.max_steps {
            return Err(BudgetBreach::Steps);
        }
        self.steps = next;
        Ok(())
    }

    /// Charges model cost. Not applied on breach.
    ///
    /// # Errors
    /// [`BudgetBreach::ModelCost`].
    pub fn charge_model(&mut self, cost: u64, budget: &FlowBudget) -> Result<(), BudgetBreach> {
        let next = self.model_cost.saturating_add(cost);
        if next > budget.max_model_cost {
            return Err(BudgetBreach::ModelCost);
        }
        self.model_cost = next;
        Ok(())
    }

    /// Charges wall-clock time. Not applied on breach.
    ///
    /// # Errors
    /// [`BudgetBreach::Wall`].
    pub fn charge_wall(&mut self, ms: u64, budget: &FlowBudget) -> Result<(), BudgetBreach> {
        let next = self.wall_ms.saturating_add(ms);
        if next > budget.max_wall_ms {
            return Err(BudgetBreach::Wall);
        }
        self.wall_ms = next;
        Ok(())
    }

    /// Charges fan-out (children scheduled). Not applied on breach.
    ///
    /// # Errors
    /// [`BudgetBreach::Fanout`].
    pub fn charge_fanout(&mut self, n: u32, budget: &FlowBudget) -> Result<(), BudgetBreach> {
        let next = self.fanout.saturating_add(n);
        if next > budget.max_total_fanout {
            return Err(BudgetBreach::Fanout);
        }
        self.fanout = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_budget_is_tight() {
        let b = FlowBudget::fail_closed();
        assert_eq!(b.max_model_cost, 0);
        assert_eq!(b.max_wall_ms, 0);
        assert_eq!(b.max_total_fanout, 0);
        // A non-zero step cap so a trivial flow can still finish a couple of steps,
        // but small enough to halt a runaway.
        assert!(b.max_steps > 0 && b.max_steps <= 128);
    }

    #[test]
    fn charges_halt_on_breach_and_do_not_apply() {
        let b = FlowBudget::new(10, 10, 3, 2);
        let mut u = FlowUsage::default();
        assert!(u.charge_step(&b).is_ok());
        assert!(u.charge_step(&b).is_ok());
        assert!(u.charge_step(&b).is_ok());
        assert_eq!(u.charge_step(&b), Err(BudgetBreach::Steps));
        assert_eq!(u.steps, 3, "breached step is not applied");

        assert!(u.charge_model(10, &b).is_ok());
        assert_eq!(u.charge_model(1, &b), Err(BudgetBreach::ModelCost));
        assert_eq!(u.model_cost, 10);

        assert!(u.charge_fanout(2, &b).is_ok());
        assert_eq!(u.charge_fanout(1, &b), Err(BudgetBreach::Fanout));
        assert_eq!(u.fanout, 2);
    }
}
