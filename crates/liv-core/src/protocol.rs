//! Version-independent domain types used before wire encoding is selected.

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
