//! Report signing and verification using Ed25519.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{
    protocol::EvidenceReport,
    wire::{WireError, decode_report, encode_report},
};

pub const SIGNATURE_LENGTH: usize = 64;
pub const REPORT_DOMAIN: &[u8] = b"linux-integrity-vanguard/report/v1\0";

/// An encoded report and its detached Ed25519 signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedReport {
    pub report_bytes: Vec<u8>,
    pub signature: [u8; SIGNATURE_LENGTH],
}

/// Encode and sign a validated report.
///
/// # Errors
///
/// Returns a [`WireError`] if the report cannot be encoded within protocol limits.
pub fn sign_report(
    report: &EvidenceReport,
    signing_key: &SigningKey,
) -> Result<SignedReport, WireError> {
    let report_bytes = encode_report(report)?;
    let signature = signing_key
        .sign(&signature_message(&report_bytes))
        .to_bytes();
    Ok(SignedReport {
        report_bytes,
        signature,
    })
}

/// Authenticate raw report bytes before decoding them into domain data.
///
/// # Errors
///
/// Returns [`VerificationError::InvalidSignature`] if authentication fails, or
/// [`VerificationError::Wire`] if authenticated bytes violate the wire contract.
pub fn verify_report(
    signed: &SignedReport,
    verifying_key: &VerifyingKey,
) -> Result<EvidenceReport, VerificationError> {
    let signature = Signature::from_bytes(&signed.signature);
    verifying_key
        .verify_strict(&signature_message(&signed.report_bytes), &signature)
        .map_err(|_| VerificationError::InvalidSignature)?;
    decode_report(&signed.report_bytes).map_err(VerificationError::Wire)
}

fn signature_message(report_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(REPORT_DOMAIN.len() + report_bytes.len());
    message.extend_from_slice(REPORT_DOMAIN);
    message.extend_from_slice(report_bytes);
    message
}

/// A failure to authenticate or decode a signed report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    InvalidSignature,
    Wire(WireError),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(formatter, "report signature is invalid"),
            Self::Wire(error) => write!(formatter, "authenticated report is invalid: {error}"),
        }
    }
}

impl std::error::Error for VerificationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Check, EvidenceItem, NONCE_LENGTH, Observation};

    fn report() -> EvidenceReport {
        EvidenceReport::new(
            [0x42; NONCE_LENGTH],
            "test-key".to_owned(),
            vec![EvidenceItem {
                check: Check::GameExecutable,
                observation: Observation::Match,
            }],
        )
        .expect("valid fixture")
    }

    #[test]
    fn signs_and_verifies_a_report() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let expected = report();
        let signed = sign_report(&expected, &signing_key).expect("signable fixture");

        assert_eq!(
            verify_report(&signed, &signing_key.verifying_key()),
            Ok(expected)
        );
    }

    #[test]
    fn rejects_modified_report_bytes() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut signed = sign_report(&report(), &signing_key).expect("signable fixture");
        *signed.report_bytes.last_mut().expect("non-empty report") ^= 1;

        assert_eq!(
            verify_report(&signed, &signing_key.verifying_key()),
            Err(VerificationError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_a_signature_from_another_key() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let other_key = SigningKey::from_bytes(&[9; 32]);
        let signed = sign_report(&report(), &signing_key).expect("signable fixture");

        assert_eq!(
            verify_report(&signed, &other_key.verifying_key()),
            Err(VerificationError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_a_signature_for_a_different_domain() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let report_bytes = encode_report(&report()).expect("encodable fixture");
        let signature = signing_key.sign(&report_bytes).to_bytes();
        let signed = SignedReport {
            report_bytes,
            signature,
        };

        assert_eq!(
            verify_report(&signed, &signing_key.verifying_key()),
            Err(VerificationError::InvalidSignature)
        );
    }
}
