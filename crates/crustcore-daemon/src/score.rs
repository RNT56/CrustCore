// SPDX-License-Identifier: Apache-2.0
//! Verified-candidate scoring (roadmap-v0.6 B.2).
//!
//! When a fan-out produces several candidates, the supervisor should integrate the
//! **best verifier-accepted** one — not merely the first accepted. This module scores a
//! candidate from bounded metadata (verification, diff size, gates passed, security
//! review) and picks the winner.
//!
//! Trust boundary: **scoring never bypasses verifier acceptance** (invariants 6, 13). A
//! verified candidate *always* outranks an unverified one regardless of every other
//! term — correctness dominates by construction (the verified bonus exceeds the sum of
//! all other contributions). Scoring is a tie-break *among* verifier-accepted
//! candidates, never a path to ship an unverified patch. The metadata is extracted from
//! a real `VerifiedPatch` by the live executor (the existing `P11-exec-live` seam); the
//! scorer here is **pure** and defaults missing fields to zero — it never fails.

use crate::product::RiskTier;

/// Bounded metadata about one fan-out candidate. Pure scoring input; the live
/// `SubagentExecutor` fills it from the candidate's `VerifiedPatch` (missing fields
/// default to 0/false — the scorer never fails on absent metadata).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PatchMetadata {
    /// Whether the supervisor's verifier accepted this candidate (the only completion
    /// authority — invariants 6, 13).
    pub verified: bool,
    /// Size of the candidate's diff in bytes (smaller is preferred).
    pub diff_bytes: u64,
    /// How many task gates the candidate satisfied (more is preferred).
    pub gates_passed: u32,
    /// Whether a security review passed (a boost for sensitive work).
    pub security_review_passed: bool,
}

/// A candidate's score — higher is better. Constructed only by [`score_candidate`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PatchScore(pub f32);

/// The fixed correctness bonus for a verified candidate. It exceeds the maximum sum of
/// every other term (diff penalty is in `[0, 50]`, gates in `[0, 20]`, security in
/// `[0, 8]` → at most `28` of swing), so a verified candidate's score (`≥ 50`) can
/// never be overtaken by an unverified one (`≤ 28`). This is what makes scoring safe:
/// it can reorder accepted candidates but never promote an unverified one (invariant 13).
pub const VERIFIED_BONUS: f32 = 100.0;

/// Scores a candidate from its metadata at the given risk tier. **Pure and total.**
///
/// Correctness dominates (`+VERIFIED_BONUS` when verified); then a smaller diff ranks
/// higher (a bounded penalty), more gates passed ranks higher, and a passing security
/// review is a small boost (a touch larger at `High`+ risk).
#[must_use]
pub fn score_candidate(meta: &PatchMetadata, risk: RiskTier) -> PatchScore {
    let mut s = 0.0_f32;
    if meta.verified {
        s += VERIFIED_BONUS;
    }
    // Smaller diff is better: a bounded penalty in [0, 50] (1 point per KiB, capped).
    s -= (meta.diff_bytes as f32 / 1024.0).min(50.0);
    // More gates passed is better: capped contribution in [0, 20].
    s += f32::from(u16::try_from(meta.gates_passed.min(10)).unwrap_or(10)) * 2.0;
    if meta.security_review_passed {
        s += 5.0;
        if risk >= RiskTier::High {
            s += 3.0;
        }
    }
    PatchScore(s)
}

/// Picks the highest-scored candidate, with a **deterministic tie-break: the first
/// proposed wins** (a strict improvement is required to displace the incumbent). Returns
/// `None` for an empty set.
///
/// Because the verified bonus dominates, this returns a verified candidate whenever one
/// exists — an unverified candidate can only win when *no* candidate verified (and even
/// then it is advisory; nothing completes without verifier evidence — invariant 13).
#[must_use]
pub fn pick_best<T: Copy>(candidates: &[(T, PatchMetadata)], risk: RiskTier) -> Option<T> {
    let mut best: Option<(T, f32)> = None;
    for (id, meta) in candidates {
        let s = score_candidate(meta, risk).0;
        let displaces = match best {
            None => true,
            Some((_, best_score)) => s > best_score, // strict → ties keep the earlier proposer
        };
        if displaces {
            best = Some((*id, s));
        }
    }
    best.map(|(id, _)| id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(verified: bool, diff_bytes: u64, gates: u32, sec: bool) -> PatchMetadata {
        PatchMetadata {
            verified,
            diff_bytes,
            gates_passed: gates,
            security_review_passed: sec,
        }
    }

    #[test]
    fn verified_always_outranks_unverified_however_good() {
        // A verified, large-diff, no-gates candidate vs an unverified candidate maxed
        // out on every other term — verified must still win (invariant 13).
        let v = score_candidate(&meta(true, 1_000_000, 0, false), RiskTier::Standard).0;
        let u = score_candidate(&meta(false, 0, 1000, true), RiskTier::High).0;
        assert!(v > u, "verified {v} must outrank unverified {u}");
    }

    #[test]
    fn among_verified_smaller_diff_ranks_higher() {
        let small = score_candidate(&meta(true, 1024, 2, false), RiskTier::Standard).0;
        let large = score_candidate(&meta(true, 50 * 1024, 2, false), RiskTier::Standard).0;
        assert!(
            small > large,
            "smaller diff should rank higher: {small} vs {large}"
        );
    }

    #[test]
    fn a_passing_security_review_boosts() {
        let with = score_candidate(&meta(true, 1024, 2, true), RiskTier::High).0;
        let without = score_candidate(&meta(true, 1024, 2, false), RiskTier::High).0;
        assert!(with > without);
    }

    #[test]
    fn golden_three_proposers_ranks_the_small_passing_one() {
        // fail (unverified) / pass-large (verified, big diff) / pass-small (verified, small diff).
        let candidates = [
            (0u32, meta(false, 2048, 1, false)),     // fail
            (1u32, meta(true, 80 * 1024, 2, false)), // pass, large
            (2u32, meta(true, 2 * 1024, 2, false)),  // pass, small
        ];
        assert_eq!(pick_best(&candidates, RiskTier::Standard), Some(2));
    }

    #[test]
    fn ties_keep_the_first_proposer() {
        let candidates = [
            (10u32, meta(true, 4096, 3, true)),
            (11u32, meta(true, 4096, 3, true)), // identical score
        ];
        assert_eq!(pick_best(&candidates, RiskTier::High), Some(10));
    }

    #[test]
    fn empty_set_has_no_winner() {
        let none: [(u32, PatchMetadata); 0] = [];
        assert_eq!(pick_best(&none, RiskTier::Standard), None);
    }

    #[test]
    fn missing_metadata_defaults_and_never_panics() {
        // An all-default (unverified, zero) candidate scores without panicking.
        let s = score_candidate(&PatchMetadata::default(), RiskTier::Low).0;
        assert!(s <= 0.0);
    }
}
