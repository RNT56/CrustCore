// SPDX-License-Identifier: Apache-2.0
//! Task budgets (`ROADMAP.md` §7.2, invariant 11).
//!
//! Every task carries a [`Budget`]: one metered axis per resource the runtime can
//! exhaust (wall time, CPU, memory, disk, output bytes, tokens, model cost,
//! subagent count). The kernel folds a per-event [`BudgetDelta`] into the budget
//! and asks it for a [`BudgetCheck`]; exhaustion **pauses** the task (the kernel
//! moves it to `Blocked` — `ROADMAP.md` §18 Phase 1 acceptance), it never silently
//! drops work.
//!
//! Everything here is integer-only and `Copy` so the kernel stays deterministic
//! (no floats, no clock) and allocation-light. Model cost is measured in **micro
//! units** (e.g. micro-USD) so it needs no floating point.

/// A resource axis a task budget meters (invariant 11).
///
/// The variant order is stable and is the index order used internally; do not
/// reorder without updating [`BudgetAxis::ALL`] and the meter array layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetAxis {
    /// Wall-clock time, milliseconds.
    WallMillis,
    /// CPU time, milliseconds.
    CpuMillis,
    /// Peak resident memory, bytes.
    MemoryBytes,
    /// Disk written, bytes.
    DiskBytes,
    /// Captured tool/command output, bytes.
    OutputBytes,
    /// Model tokens consumed.
    Tokens,
    /// Model cost, micro-units (e.g. micro-USD) to stay integer/deterministic.
    ModelCostMicros,
    /// Number of subagents spawned.
    SubagentCount,
}

/// The number of budget axes. Kept in sync with [`BudgetAxis::ALL`] by the
/// `axis_count_matches_all` test.
pub const BUDGET_AXIS_COUNT: usize = 8;

impl BudgetAxis {
    /// Every axis, in stable index order. Used for exhaustive iteration in the
    /// kernel's budget tests and for generic folding.
    pub const ALL: [BudgetAxis; BUDGET_AXIS_COUNT] = [
        BudgetAxis::WallMillis,
        BudgetAxis::CpuMillis,
        BudgetAxis::MemoryBytes,
        BudgetAxis::DiskBytes,
        BudgetAxis::OutputBytes,
        BudgetAxis::Tokens,
        BudgetAxis::ModelCostMicros,
        BudgetAxis::SubagentCount,
    ];

    /// The dense array index for this axis (always `< BUDGET_AXIS_COUNT`).
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// A single metered axis: how much has been used against the limit.
///
/// `limit == u64::MAX` means "unlimited on this axis". `used` saturates on add so
/// a hostile/overflowing delta can never panic or wrap (the no-panic guarantee,
/// `docs/architecture.md` §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meter {
    /// Amount consumed so far.
    pub used: u64,
    /// The ceiling; `u64::MAX` is unlimited.
    pub limit: u64,
}

impl Meter {
    /// An unlimited, unused meter.
    pub const UNLIMITED: Meter = Meter {
        used: 0,
        limit: u64::MAX,
    };

    /// A meter with `used = 0` and the given limit.
    #[must_use]
    pub const fn with_limit(limit: u64) -> Self {
        Meter { used: 0, limit }
    }

    /// Whether the meter is still within budget (`used <= limit`).
    #[must_use]
    pub const fn within(self) -> bool {
        self.used <= self.limit
    }

    /// Adds `delta` to `used`, saturating (never panics/wraps).
    pub fn add(&mut self, delta: u64) {
        self.used = self.used.saturating_add(delta);
    }
}

impl Default for Meter {
    fn default() -> Self {
        Meter::UNLIMITED
    }
}

/// The amount a single event consumed across one or more axes. Adapters build
/// this from a real tool/command/model result; the kernel folds it into the
/// task's [`Budget`]. Additive and saturating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetDelta {
    amounts: [u64; BUDGET_AXIS_COUNT],
}

impl Default for BudgetDelta {
    fn default() -> Self {
        BudgetDelta {
            amounts: [0; BUDGET_AXIS_COUNT],
        }
    }
}

impl BudgetDelta {
    /// An empty delta (consumes nothing).
    #[must_use]
    pub const fn none() -> Self {
        BudgetDelta {
            amounts: [0; BUDGET_AXIS_COUNT],
        }
    }

    /// A delta consuming `amount` on a single `axis`.
    #[must_use]
    pub fn of(axis: BudgetAxis, amount: u64) -> Self {
        BudgetDelta::none().with(axis, amount)
    }

    /// Returns a copy with `amount` added (saturating) on `axis`.
    #[must_use]
    pub fn with(mut self, axis: BudgetAxis, amount: u64) -> Self {
        let slot = &mut self.amounts[axis.index()];
        *slot = slot.saturating_add(amount);
        self
    }

    /// The amount this delta consumes on `axis`.
    #[must_use]
    pub fn amount(&self, axis: BudgetAxis) -> u64 {
        self.amounts[axis.index()]
    }

    /// Whether this delta consumes nothing on any axis.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.amounts.iter().all(|&a| a == 0)
    }
}

/// The result of checking a [`Budget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetCheck {
    /// Every axis is within its limit.
    WithinBudget,
    /// The named axis has exceeded its limit; the task must pause (invariant 11).
    Exhausted(BudgetAxis),
}

impl BudgetCheck {
    /// Whether any axis is exhausted.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        matches!(self, BudgetCheck::Exhausted(_))
    }

    /// The exhausted axis, if any.
    #[must_use]
    pub const fn exhausted_axis(self) -> Option<BudgetAxis> {
        match self {
            BudgetCheck::Exhausted(a) => Some(a),
            BudgetCheck::WithinBudget => None,
        }
    }
}

/// A task's budget: one [`Meter`] per [`BudgetAxis`] (invariant 11).
///
/// Constructed unlimited and tightened per-axis by the adapter that creates the
/// task. The kernel only ever *reads* limits and *folds* deltas — it never sets a
/// limit from model-controlled input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    meters: [Meter; BUDGET_AXIS_COUNT],
}

impl Default for Budget {
    fn default() -> Self {
        Budget::unlimited()
    }
}

impl Budget {
    /// A budget with no limit on any axis.
    #[must_use]
    pub const fn unlimited() -> Self {
        Budget {
            meters: [Meter::UNLIMITED; BUDGET_AXIS_COUNT],
        }
    }

    /// The meter for `axis`.
    #[must_use]
    pub fn meter(&self, axis: BudgetAxis) -> Meter {
        self.meters[axis.index()]
    }

    /// Sets the limit on `axis`, returning the updated budget (builder style).
    #[must_use]
    pub fn with_limit(mut self, axis: BudgetAxis, limit: u64) -> Self {
        self.meters[axis.index()].limit = limit;
        self
    }

    /// Folds a single event's [`BudgetDelta`] into every axis (saturating) and
    /// returns the resulting [`BudgetCheck`]. The first axis (in stable order)
    /// found over its limit is the one reported, so the result is deterministic.
    pub fn record(&mut self, delta: &BudgetDelta) -> BudgetCheck {
        for axis in BudgetAxis::ALL {
            self.meters[axis.index()].add(delta.amount(axis));
        }
        self.check()
    }

    /// Checks every axis without mutating, returning the first exhausted one.
    #[must_use]
    pub fn check(&self) -> BudgetCheck {
        for axis in BudgetAxis::ALL {
            if !self.meters[axis.index()].within() {
                return BudgetCheck::Exhausted(axis);
            }
        }
        BudgetCheck::WithinBudget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn axis_count_matches_all() {
        assert_eq!(BudgetAxis::ALL.len(), BUDGET_AXIS_COUNT);
        // Indices are dense and unique.
        for (i, axis) in BudgetAxis::ALL.iter().enumerate() {
            assert_eq!(axis.index(), i);
        }
    }

    #[test]
    fn unlimited_budget_is_always_within() {
        let mut b = Budget::unlimited();
        assert_eq!(b.check(), BudgetCheck::WithinBudget);
        let check = b.record(&BudgetDelta::of(BudgetAxis::Tokens, u64::MAX));
        assert_eq!(check, BudgetCheck::WithinBudget);
    }

    #[test]
    fn record_exhausts_the_limited_axis() {
        let mut b = Budget::unlimited().with_limit(BudgetAxis::OutputBytes, 100);
        assert_eq!(
            b.record(&BudgetDelta::of(BudgetAxis::OutputBytes, 60)),
            BudgetCheck::WithinBudget
        );
        assert_eq!(
            b.record(&BudgetDelta::of(BudgetAxis::OutputBytes, 60)),
            BudgetCheck::Exhausted(BudgetAxis::OutputBytes)
        );
        assert_eq!(b.meter(BudgetAxis::OutputBytes).used, 120);
    }

    #[test]
    fn add_saturates_rather_than_panicking() {
        let mut m = Meter::with_limit(10);
        m.add(u64::MAX);
        m.add(u64::MAX);
        assert_eq!(m.used, u64::MAX);
        assert!(!m.within());
    }

    #[test]
    fn first_exhausted_axis_is_deterministic() {
        // Two axes over limit; the earlier axis in stable order wins.
        let mut b = Budget::unlimited()
            .with_limit(BudgetAxis::CpuMillis, 1)
            .with_limit(BudgetAxis::Tokens, 1);
        let delta = BudgetDelta::of(BudgetAxis::CpuMillis, 5).with(BudgetAxis::Tokens, 5);
        assert_eq!(
            b.record(&delta),
            BudgetCheck::Exhausted(BudgetAxis::CpuMillis)
        );
    }
}
