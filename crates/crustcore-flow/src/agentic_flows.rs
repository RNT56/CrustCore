// SPDX-License-Identifier: Apache-2.0
//! Optional `agentic-flows` contract adapter.
//!
//! CrustCore remains an independent project. This module maps required gates from a
//! selected `agentic-flows` definition into CrustCore-owned verifier completion
//! criteria. Imported flow metadata never completes a patch by itself: callers must
//! prove the required verifier evidence before accepting completion.

use std::collections::{BTreeMap, BTreeSet};

/// A gate declared by a selected `agentic-flows` flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgenticFlowGate {
    pub id: String,
    pub title: String,
    pub required: bool,
    pub evidence_refs: Vec<String>,
}

impl AgenticFlowGate {
    #[must_use]
    pub fn required(
        id: impl Into<String>,
        title: impl Into<String>,
        evidence_refs: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            required: true,
            evidence_refs: evidence_refs.into_iter().map(Into::into).collect(),
        }
    }

    #[must_use]
    pub fn optional(id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            required: false,
            evidence_refs: Vec::new(),
        }
    }
}

/// CrustCore-owned criterion that must be satisfied before accepting completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierCompletionCriterion {
    pub gate_id: String,
    pub title: String,
    pub required_evidence_refs: Vec<String>,
}

/// Evidence produced by CrustCore's verifier side of the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateEvidence {
    pub gate_id: String,
    pub evidence_refs: Vec<String>,
}

impl GateEvidence {
    #[must_use]
    pub fn new(
        gate_id: impl Into<String>,
        evidence_refs: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            gate_id: gate_id.into(),
            evidence_refs: evidence_refs.into_iter().map(Into::into).collect(),
        }
    }
}

/// Why an imported flow cannot be treated as complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionEvidenceError {
    MissingRequiredGate {
        gate_id: String,
    },
    MissingEvidenceRef {
        gate_id: String,
        evidence_ref: String,
    },
}

/// Maps required `agentic-flows` gates to deterministic verifier criteria.
#[must_use]
pub fn verifier_completion_criteria(gates: &[AgenticFlowGate]) -> Vec<VerifierCompletionCriterion> {
    let mut criteria: Vec<_> = gates
        .iter()
        .filter(|gate| gate.required)
        .map(|gate| VerifierCompletionCriterion {
            gate_id: gate.id.clone(),
            title: gate.title.clone(),
            required_evidence_refs: normalized_refs(&gate.evidence_refs),
        })
        .collect();
    criteria.sort_by(|left, right| left.gate_id.cmp(&right.gate_id));
    criteria
}

/// Returns every missing verifier-owned evidence item for the imported flow.
#[must_use]
pub fn completion_evidence_errors(
    criteria: &[VerifierCompletionCriterion],
    evidence: &[GateEvidence],
) -> Vec<CompletionEvidenceError> {
    let mut by_gate: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for item in evidence {
        by_gate
            .entry(item.gate_id.clone())
            .or_default()
            .extend(item.evidence_refs.iter().cloned());
    }

    let mut errors = Vec::new();
    for criterion in criteria {
        let Some(refs) = by_gate.get(&criterion.gate_id) else {
            errors.push(CompletionEvidenceError::MissingRequiredGate {
                gate_id: criterion.gate_id.clone(),
            });
            continue;
        };
        for evidence_ref in &criterion.required_evidence_refs {
            if !refs.contains(evidence_ref) {
                errors.push(CompletionEvidenceError::MissingEvidenceRef {
                    gate_id: criterion.gate_id.clone(),
                    evidence_ref: evidence_ref.clone(),
                });
            }
        }
    }
    errors
}

/// Accepts imported-flow completion only when every required verifier criterion has
/// matching evidence.
pub fn validate_patch_completion_evidence(
    criteria: &[VerifierCompletionCriterion],
    evidence: &[GateEvidence],
) -> Result<(), Vec<CompletionEvidenceError>> {
    let errors = completion_evidence_errors(criteria, evidence);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn normalized_refs(refs: &[String]) -> Vec<String> {
    refs.iter()
        .filter(|reference| !reference.is_empty())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_required_gates_to_verifier_criteria() {
        let criteria = verifier_completion_criteria(&[
            AgenticFlowGate::optional("advisory-review", "Advisory review"),
            AgenticFlowGate::required(
                "verify-tests",
                "Tests pass",
                ["tests-pass", "tests-pass", "patch-diff-reviewed"],
            ),
        ]);

        assert_eq!(
            criteria,
            vec![VerifierCompletionCriterion {
                gate_id: "verify-tests".into(),
                title: "Tests pass".into(),
                required_evidence_refs: vec!["patch-diff-reviewed".into(), "tests-pass".into()],
            }]
        );
    }

    #[test]
    fn rejects_missing_required_gate_evidence() {
        let criteria = verifier_completion_criteria(&[AgenticFlowGate::required(
            "verify-tests",
            "Tests pass",
            ["tests-pass"],
        )]);

        let errors = completion_evidence_errors(&criteria, &[]);

        assert_eq!(
            errors,
            vec![CompletionEvidenceError::MissingRequiredGate {
                gate_id: "verify-tests".into(),
            }]
        );
    }

    #[test]
    fn rejects_incomplete_evidence_refs() {
        let criteria = verifier_completion_criteria(&[AgenticFlowGate::required(
            "verify-tests",
            "Tests pass",
            ["tests-pass", "lint-pass"],
        )]);

        let errors = completion_evidence_errors(
            &criteria,
            &[GateEvidence::new("verify-tests", ["tests-pass"])],
        );

        assert_eq!(
            errors,
            vec![CompletionEvidenceError::MissingEvidenceRef {
                gate_id: "verify-tests".into(),
                evidence_ref: "lint-pass".into(),
            }]
        );
    }

    #[test]
    fn accepts_complete_verifier_evidence() {
        let criteria = verifier_completion_criteria(&[AgenticFlowGate::required(
            "verify-tests",
            "Tests pass",
            ["tests-pass", "lint-pass"],
        )]);
        let evidence = [GateEvidence::new(
            "verify-tests",
            ["lint-pass", "tests-pass", "extra-diagnostic"],
        )];

        assert!(validate_patch_completion_evidence(&criteria, &evidence).is_ok());
    }
}
