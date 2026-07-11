//! Version-independent domain types used before wire encoding is selected.

use std::fmt;

pub const PROTOCOL_VERSION: u16 = 1;
pub const NONCE_LENGTH: usize = 32;
pub const MAX_KEY_ID_LENGTH: usize = 64;
pub const MAX_EVIDENCE_ITEMS: usize = 256;

pub type Nonce = [u8; NONCE_LENGTH];

/// The result of collecting one explicitly requested integrity fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Observation {
    /// The observed value matches the server's expected value.
    Match,
    /// The collector completed and found a different value.
    Mismatch,
    /// This agent does not implement the requested check.
    Unsupported,
    /// The check is supported but could not be completed.
    Unavailable(UnavailableReason),
}

/// A non-sensitive, machine-readable reason why evidence could not be collected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnavailableReason {
    PermissionDenied,
    TargetExited,
    InputChanged,
    InternalError,
}

/// An allowlisted integrity fact and its collection result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceItem {
    pub check: Check,
    pub observation: Observation,
}

/// Checks supported by the initial evidence profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Check {
    GameExecutable,
    GameArtifact,
    GameProcess,
    ParentProcess,
    PlatformCompatibility,
}

/// A server-issued, single-use request for integrity evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Challenge {
    pub protocol_version: u16,
    pub nonce: Nonce,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub requested_checks: Vec<Check>,
}

impl Challenge {
    /// Construct a validated version 1 challenge.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidValidityWindow`] if expiry is not after
    /// issue time, or an evidence-profile error if checks are empty, duplicated,
    /// or exceed [`MAX_EVIDENCE_ITEMS`].
    pub fn new(
        nonce: Nonce,
        issued_at_ms: i64,
        expires_at_ms: i64,
        requested_checks: Vec<Check>,
    ) -> Result<Self, ProtocolError> {
        if expires_at_ms <= issued_at_ms {
            return Err(ProtocolError::InvalidValidityWindow);
        }
        validate_checks(&requested_checks)?;

        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            nonce,
            issued_at_ms,
            expires_at_ms,
            requested_checks,
        })
    }

    /// Ensure a report answers this exact challenge before policy evaluation.
    ///
    /// # Errors
    ///
    /// Returns an error when the protocol version or nonce differs, or when the
    /// report does not contain exactly the checks requested by this challenge.
    pub fn validate_report(&self, report: &EvidenceReport) -> Result<(), ProtocolError> {
        if report.protocol_version != self.protocol_version {
            return Err(ProtocolError::UnsupportedVersion(report.protocol_version));
        }
        if report.nonce != self.nonce {
            return Err(ProtocolError::NonceMismatch);
        }
        if report.evidence.len() != self.requested_checks.len()
            || self
                .requested_checks
                .iter()
                .any(|requested| !report.evidence.iter().any(|item| item.check == *requested))
        {
            return Err(ProtocolError::EvidenceProfileMismatch);
        }

        Ok(())
    }
}

/// The unsigned, policy-independent contents of an integrity report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceReport {
    pub protocol_version: u16,
    pub nonce: Nonce,
    pub key_id: String,
    pub evidence: Vec<EvidenceItem>,
}

impl EvidenceReport {
    /// Construct a validated version 1 evidence report.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidKeyId`] for an empty, oversized, or
    /// non-ASCII-safe key identifier, or an evidence-profile error if checks are
    /// empty, duplicated, or exceed [`MAX_EVIDENCE_ITEMS`].
    pub fn new(
        nonce: Nonce,
        key_id: String,
        evidence: Vec<EvidenceItem>,
    ) -> Result<Self, ProtocolError> {
        validate_key_id(&key_id)?;
        validate_checks(&evidence.iter().map(|item| item.check).collect::<Vec<_>>())?;

        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            nonce,
            key_id,
            evidence,
        })
    }
}

/// A validation failure that must stop report processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidValidityWindow,
    EmptyEvidenceProfile,
    TooManyEvidenceItems,
    DuplicateCheck(Check),
    InvalidKeyId,
    UnsupportedVersion(u16),
    NonceMismatch,
    EvidenceProfileMismatch,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message())
    }
}

impl std::error::Error for ProtocolError {}

impl ProtocolError {
    const fn message(&self) -> &'static str {
        match self {
            Self::InvalidValidityWindow => "challenge expiry must be after issue time",
            Self::EmptyEvidenceProfile => "evidence profile must not be empty",
            Self::TooManyEvidenceItems => "evidence profile exceeds the item limit",
            Self::DuplicateCheck(_) => "evidence profile contains a duplicate check",
            Self::InvalidKeyId => "key identifier is invalid",
            Self::UnsupportedVersion(_) => "protocol version is unsupported",
            Self::NonceMismatch => "report nonce does not match the challenge",
            Self::EvidenceProfileMismatch => {
                "report does not answer the requested evidence profile"
            }
        }
    }
}

fn validate_checks(checks: &[Check]) -> Result<(), ProtocolError> {
    if checks.is_empty() {
        return Err(ProtocolError::EmptyEvidenceProfile);
    }
    if checks.len() > MAX_EVIDENCE_ITEMS {
        return Err(ProtocolError::TooManyEvidenceItems);
    }
    for (index, check) in checks.iter().enumerate() {
        if checks[..index].contains(check) {
            return Err(ProtocolError::DuplicateCheck(*check));
        }
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<(), ProtocolError> {
    let valid = !key_id.is_empty()
        && key_id.len() <= MAX_KEY_ID_LENGTH
        && key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));

    if valid {
        Ok(())
    } else {
        Err(ProtocolError::InvalidKeyId)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: Nonce = [7; NONCE_LENGTH];

    fn evidence(check: Check) -> EvidenceItem {
        EvidenceItem {
            check,
            observation: Observation::Match,
        }
    }

    #[test]
    fn constructs_a_valid_challenge_and_matching_report() {
        let challenge = Challenge::new(
            NONCE,
            1_000,
            2_000,
            vec![Check::GameExecutable, Check::GameProcess],
        )
        .expect("valid challenge");
        let report = EvidenceReport::new(
            NONCE,
            "device-key_1".to_owned(),
            vec![
                evidence(Check::GameProcess),
                evidence(Check::GameExecutable),
            ],
        )
        .expect("valid report");

        assert_eq!(challenge.validate_report(&report), Ok(()));
    }

    #[test]
    fn rejects_non_positive_validity_windows() {
        let result = Challenge::new(NONCE, 2_000, 2_000, vec![Check::GameExecutable]);

        assert_eq!(result, Err(ProtocolError::InvalidValidityWindow));
    }

    #[test]
    fn rejects_duplicate_requested_checks() {
        let result = Challenge::new(
            NONCE,
            1_000,
            2_000,
            vec![Check::GameExecutable, Check::GameExecutable],
        );

        assert_eq!(
            result,
            Err(ProtocolError::DuplicateCheck(Check::GameExecutable))
        );
    }

    #[test]
    fn rejects_invalid_key_identifiers() {
        let result = EvidenceReport::new(
            NONCE,
            "contains spaces".to_owned(),
            vec![evidence(Check::GameExecutable)],
        );

        assert_eq!(result, Err(ProtocolError::InvalidKeyId));
    }

    #[test]
    fn rejects_a_report_for_another_challenge() {
        let challenge = Challenge::new(NONCE, 1_000, 2_000, vec![Check::GameExecutable])
            .expect("valid challenge");
        let report = EvidenceReport::new(
            [9; NONCE_LENGTH],
            "device-key".to_owned(),
            vec![evidence(Check::GameExecutable)],
        )
        .expect("valid report");

        assert_eq!(
            challenge.validate_report(&report),
            Err(ProtocolError::NonceMismatch)
        );
    }

    #[test]
    fn rejects_an_incomplete_report() {
        let challenge = Challenge::new(
            NONCE,
            1_000,
            2_000,
            vec![Check::GameExecutable, Check::GameProcess],
        )
        .expect("valid challenge");
        let report = EvidenceReport::new(
            NONCE,
            "device-key".to_owned(),
            vec![evidence(Check::GameExecutable)],
        )
        .expect("valid report");

        assert_eq!(
            challenge.validate_report(&report),
            Err(ProtocolError::EvidenceProfileMismatch)
        );
    }
}
