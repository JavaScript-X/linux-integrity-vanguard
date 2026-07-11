//! Server-side orchestration for authenticated, fresh, single-use reports.

use std::{collections::HashSet, fmt};

use ed25519_dalek::VerifyingKey;

use crate::{
    crypto::{SignedReport, VerificationError, verify_report},
    protocol::{Challenge, EvidenceReport, Nonce, ProtocolError},
};

/// Storage that atomically marks a nonce as consumed.
pub trait NonceStore {
    /// Return `true` only for the first successful consumption of this nonce.
    fn consume(&mut self, nonce: Nonce) -> bool;
}

/// An in-memory nonce store for tests and single-process development.
#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
    consumed: HashSet<Nonce>,
}

impl NonceStore for InMemoryNonceStore {
    fn consume(&mut self, nonce: Nonce) -> bool {
        self.consumed.insert(nonce)
    }
}

/// Authenticate and validate a report before it reaches policy evaluation.
///
/// Checks run in this order: signature, wire decoding, server-clock freshness,
/// challenge binding, then atomic nonce consumption. Invalid reports never consume
/// a nonce, allowing a client to retry after transport corruption.
///
/// # Errors
///
/// Returns [`VerifierError`] when authentication, decoding, freshness, challenge
/// binding, or replay protection fails.
pub fn verify_challenge_response(
    challenge: &Challenge,
    signed: &SignedReport,
    verifying_key: &VerifyingKey,
    now_ms: i64,
    nonce_store: &mut impl NonceStore,
) -> Result<EvidenceReport, VerifierError> {
    let report = verify_report(signed, verifying_key).map_err(VerifierError::Authentication)?;

    if now_ms < challenge.issued_at_ms {
        return Err(VerifierError::ChallengeNotYetValid);
    }
    if now_ms >= challenge.expires_at_ms {
        return Err(VerifierError::ChallengeExpired);
    }
    challenge
        .validate_report(&report)
        .map_err(VerifierError::ChallengeBinding)?;
    if !nonce_store.consume(challenge.nonce) {
        return Err(VerifierError::ReplayDetected);
    }

    Ok(report)
}

/// A reason a signed challenge response was rejected before policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifierError {
    Authentication(VerificationError),
    ChallengeNotYetValid,
    ChallengeExpired,
    ChallengeBinding(ProtocolError),
    ReplayDetected,
}

impl fmt::Display for VerifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(error) => write!(formatter, "authentication failed: {error}"),
            Self::ChallengeNotYetValid => write!(formatter, "challenge is not yet valid"),
            Self::ChallengeExpired => write!(formatter, "challenge has expired"),
            Self::ChallengeBinding(error) => {
                write!(formatter, "report does not answer the challenge: {error}")
            }
            Self::ReplayDetected => write!(formatter, "challenge nonce was already consumed"),
        }
    }
}

impl std::error::Error for VerifierError {}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{
        crypto::sign_report,
        protocol::{Check, EvidenceItem, NONCE_LENGTH, Observation},
    };

    const NONCE: Nonce = [0x11; NONCE_LENGTH];

    fn challenge() -> Challenge {
        Challenge::new(NONCE, 1_000, 2_000, vec![Check::GameExecutable]).expect("valid fixture")
    }

    fn signed_report(signing_key: &SigningKey, nonce: Nonce) -> SignedReport {
        let report = EvidenceReport::new(
            nonce,
            "test-key".to_owned(),
            vec![EvidenceItem {
                check: Check::GameExecutable,
                observation: Observation::Match,
            }],
        )
        .expect("valid fixture");
        sign_report(&report, signing_key).expect("signable fixture")
    }

    #[test]
    fn accepts_a_fresh_authenticated_response_once() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let challenge = challenge();
        let signed = signed_report(&signing_key, NONCE);
        let mut nonces = InMemoryNonceStore::default();

        let result = verify_challenge_response(
            &challenge,
            &signed,
            &signing_key.verifying_key(),
            1_500,
            &mut nonces,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn rejects_an_expired_challenge() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut nonces = InMemoryNonceStore::default();

        let result = verify_challenge_response(
            &challenge(),
            &signed_report(&signing_key, NONCE),
            &signing_key.verifying_key(),
            2_000,
            &mut nonces,
        );

        assert_eq!(result, Err(VerifierError::ChallengeExpired));
    }

    #[test]
    fn rejects_a_challenge_from_the_future() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut nonces = InMemoryNonceStore::default();

        let result = verify_challenge_response(
            &challenge(),
            &signed_report(&signing_key, NONCE),
            &signing_key.verifying_key(),
            999,
            &mut nonces,
        );

        assert_eq!(result, Err(VerifierError::ChallengeNotYetValid));
    }

    #[test]
    fn rejects_a_replayed_response() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let challenge = challenge();
        let signed = signed_report(&signing_key, NONCE);
        let mut nonces = InMemoryNonceStore::default();
        verify_challenge_response(
            &challenge,
            &signed,
            &signing_key.verifying_key(),
            1_500,
            &mut nonces,
        )
        .expect("first use succeeds");

        let replay = verify_challenge_response(
            &challenge,
            &signed,
            &signing_key.verifying_key(),
            1_500,
            &mut nonces,
        );

        assert_eq!(replay, Err(VerifierError::ReplayDetected));
    }

    #[test]
    fn invalid_binding_does_not_consume_the_nonce() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let challenge = challenge();
        let mut nonces = InMemoryNonceStore::default();
        let wrong = signed_report(&signing_key, [0x22; NONCE_LENGTH]);

        assert!(
            verify_challenge_response(
                &challenge,
                &wrong,
                &signing_key.verifying_key(),
                1_500,
                &mut nonces,
            )
            .is_err()
        );
        assert!(
            verify_challenge_response(
                &challenge,
                &signed_report(&signing_key, NONCE),
                &signing_key.verifying_key(),
                1_500,
                &mut nonces,
            )
            .is_ok()
        );
    }
}
