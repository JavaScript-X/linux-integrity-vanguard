//! Conservative policy evaluation for verified evidence.

use crate::protocol::{EvidenceItem, Observation};

/// The action recommended by a policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Review,
    Deny,
}

/// Stable reason codes suitable for audit events and user-facing explanations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReasonCode {
    EvidenceMatched,
    EvidenceMismatch,
    EvidenceIncomplete,
    EvidenceMissing,
}

/// An explainable policy result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evaluation {
    pub decision: Decision,
    pub reasons: Vec<ReasonCode>,
}

/// Evaluate an already authenticated collection of evidence.
///
/// A mismatch is a strong negative signal in this initial policy. Missing,
/// unsupported, or unavailable evidence is never treated as a match and requires
/// review. Authentication and freshness checks belong to the verifier layer.
#[must_use]
pub fn evaluate(evidence: &[EvidenceItem]) -> Evaluation {
    if evidence.is_empty() {
        return Evaluation {
            decision: Decision::Review,
            reasons: vec![ReasonCode::EvidenceMissing],
        };
    }

    let has_mismatch = evidence
        .iter()
        .any(|item| item.observation == Observation::Mismatch);
    let has_incomplete = evidence.iter().any(|item| {
        matches!(
            item.observation,
            Observation::Unsupported | Observation::Unavailable(_)
        )
    });

    if has_mismatch {
        Evaluation {
            decision: Decision::Deny,
            reasons: vec![ReasonCode::EvidenceMismatch],
        }
    } else if has_incomplete {
        Evaluation {
            decision: Decision::Review,
            reasons: vec![ReasonCode::EvidenceIncomplete],
        }
    } else {
        Evaluation {
            decision: Decision::Allow,
            reasons: vec![ReasonCode::EvidenceMatched],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Check, UnavailableReason};

    fn item(observation: Observation) -> EvidenceItem {
        EvidenceItem {
            check: Check::GameExecutable,
            observation,
        }
    }

    #[test]
    fn allows_complete_matching_evidence() {
        let result = evaluate(&[item(Observation::Match), item(Observation::Match)]);

        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.reasons, [ReasonCode::EvidenceMatched]);
    }

    #[test]
    fn denies_when_any_verified_observation_mismatches() {
        let result = evaluate(&[item(Observation::Match), item(Observation::Mismatch)]);

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.reasons, [ReasonCode::EvidenceMismatch]);
    }

    #[test]
    fn reviews_unsupported_evidence() {
        let result = evaluate(&[item(Observation::Unsupported)]);

        assert_eq!(result.decision, Decision::Review);
        assert_eq!(result.reasons, [ReasonCode::EvidenceIncomplete]);
    }

    #[test]
    fn reviews_unavailable_evidence() {
        let result = evaluate(&[item(Observation::Unavailable(
            UnavailableReason::PermissionDenied,
        ))]);

        assert_eq!(result.decision, Decision::Review);
        assert_eq!(result.reasons, [ReasonCode::EvidenceIncomplete]);
    }

    #[test]
    fn reviews_an_empty_report() {
        let result = evaluate(&[]);

        assert_eq!(result.decision, Decision::Review);
        assert_eq!(result.reasons, [ReasonCode::EvidenceMissing]);
    }
}
