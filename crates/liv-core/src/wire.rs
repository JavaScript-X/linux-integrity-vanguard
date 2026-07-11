//! Deterministic, bounded version 1 wire encoding.

use std::fmt;

use crate::protocol::{Challenge, Check, NONCE_LENGTH, PROTOCOL_VERSION, ProtocolError};

const MAGIC: &[u8; 4] = b"LIV1";
const CHALLENGE_KIND: u8 = 1;
const HEADER_LENGTH: usize = 11;
pub const MAX_CHALLENGE_BYTES: usize = 4 * 1024;

/// Encode a challenge using the version 1 binary framing contract.
///
/// # Errors
///
/// Returns [`WireError::MessageTooLarge`] if the encoded frame exceeds
/// [`MAX_CHALLENGE_BYTES`]. Validated domain values cannot produce other errors.
pub fn encode_challenge(challenge: &Challenge) -> Result<Vec<u8>, WireError> {
    let payload_length = NONCE_LENGTH + 8 + 8 + 2 + challenge.requested_checks.len();
    let frame_length = HEADER_LENGTH + payload_length;
    if frame_length > MAX_CHALLENGE_BYTES {
        return Err(WireError::MessageTooLarge);
    }

    let payload_length = u32::try_from(payload_length).map_err(|_| WireError::MessageTooLarge)?;
    let check_count =
        u16::try_from(challenge.requested_checks.len()).map_err(|_| WireError::MessageTooLarge)?;

    let mut output = Vec::with_capacity(frame_length);
    output.extend_from_slice(MAGIC);
    output.push(CHALLENGE_KIND);
    output.extend_from_slice(&challenge.protocol_version.to_be_bytes());
    output.extend_from_slice(&payload_length.to_be_bytes());
    output.extend_from_slice(&challenge.nonce);
    output.extend_from_slice(&challenge.issued_at_ms.to_be_bytes());
    output.extend_from_slice(&challenge.expires_at_ms.to_be_bytes());
    output.extend_from_slice(&check_count.to_be_bytes());
    output.extend(
        challenge
            .requested_checks
            .iter()
            .map(|check| check.to_wire()),
    );
    Ok(output)
}

/// Decode and validate an exact version 1 challenge frame.
///
/// # Errors
///
/// Returns a typed [`WireError`] for oversized, truncated, malformed, unsupported,
/// or semantically invalid frames. Trailing bytes are rejected.
pub fn decode_challenge(input: &[u8]) -> Result<Challenge, WireError> {
    if input.len() > MAX_CHALLENGE_BYTES {
        return Err(WireError::MessageTooLarge);
    }
    if input.len() < HEADER_LENGTH {
        return Err(WireError::Truncated);
    }
    if &input[..4] != MAGIC {
        return Err(WireError::InvalidMagic);
    }
    if input[4] != CHALLENGE_KIND {
        return Err(WireError::UnexpectedMessageKind(input[4]));
    }

    let version = u16::from_be_bytes([input[5], input[6]]);
    if version != PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }

    let declared_payload = u32::from_be_bytes([input[7], input[8], input[9], input[10]]);
    let declared_payload =
        usize::try_from(declared_payload).map_err(|_| WireError::MessageTooLarge)?;
    if declared_payload != input.len() - HEADER_LENGTH {
        return Err(WireError::LengthMismatch);
    }

    let mut cursor = Cursor::new(&input[HEADER_LENGTH..]);
    let nonce = cursor.take_array::<NONCE_LENGTH>()?;
    let issued_at_ms = i64::from_be_bytes(cursor.take_array::<8>()?);
    let expires_at_ms = i64::from_be_bytes(cursor.take_array::<8>()?);
    let check_count = usize::from(u16::from_be_bytes(cursor.take_array::<2>()?));
    let mut requested_checks = Vec::with_capacity(check_count);
    for _ in 0..check_count {
        requested_checks.push(Check::from_wire(cursor.take_byte()?)?);
    }
    if !cursor.is_empty() {
        return Err(WireError::TrailingBytes);
    }

    Challenge::new(nonce, issued_at_ms, expires_at_ms, requested_checks).map_err(WireError::Domain)
}

impl Check {
    const fn to_wire(self) -> u8 {
        match self {
            Self::GameExecutable => 1,
            Self::GameArtifact => 2,
            Self::GameProcess => 3,
            Self::ParentProcess => 4,
            Self::PlatformCompatibility => 5,
        }
    }

    fn from_wire(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::GameExecutable),
            2 => Ok(Self::GameArtifact),
            3 => Ok(Self::GameProcess),
            4 => Ok(Self::ParentProcess),
            5 => Ok(Self::PlatformCompatibility),
            value => Err(WireError::UnknownCheck(value)),
        }
    }
}

/// A failure to decode or encode the version 1 wire format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    MessageTooLarge,
    Truncated,
    InvalidMagic,
    UnexpectedMessageKind(u8),
    UnsupportedVersion(u16),
    LengthMismatch,
    UnknownCheck(u8),
    TrailingBytes,
    Domain(ProtocolError),
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message())
    }
}

impl std::error::Error for WireError {}

impl WireError {
    const fn message(&self) -> &'static str {
        match self {
            Self::MessageTooLarge => "message exceeds the byte limit",
            Self::Truncated => "message is truncated",
            Self::InvalidMagic => "message has invalid magic bytes",
            Self::UnexpectedMessageKind(_) => "message kind is not a challenge",
            Self::UnsupportedVersion(_) => "protocol version is unsupported",
            Self::LengthMismatch => "declared payload length does not match the frame",
            Self::UnknownCheck(_) => "message contains an unknown check identifier",
            Self::TrailingBytes => "message contains trailing bytes",
            Self::Domain(_) => "message violates domain validation rules",
        }
    }
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let (value, remaining) = self
            .remaining
            .split_first_chunk::<N>()
            .ok_or(WireError::Truncated)?;
        self.remaining = remaining;
        Ok(*value)
    }

    fn take_byte(&mut self) -> Result<u8, WireError> {
        Ok(self.take_array::<1>()?[0])
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge() -> Challenge {
        Challenge::new(
            [0xA5; NONCE_LENGTH],
            1_000,
            2_000,
            vec![Check::GameExecutable, Check::PlatformCompatibility],
        )
        .expect("valid fixture")
    }

    #[test]
    fn round_trips_a_challenge() {
        let expected = challenge();
        let encoded = encode_challenge(&expected).expect("encodable fixture");

        assert_eq!(decode_challenge(&encoded), Ok(expected));
    }

    #[test]
    fn produces_a_stable_frame_header() {
        let encoded = encode_challenge(&challenge()).expect("encodable fixture");

        assert_eq!(&encoded[..7], b"LIV1\x01\x00\x01");
        assert_eq!(u32::from_be_bytes(encoded[7..11].try_into().unwrap()), 52);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut encoded = encode_challenge(&challenge()).expect("encodable fixture");
        encoded[0] = b'X';

        assert_eq!(decode_challenge(&encoded), Err(WireError::InvalidMagic));
    }

    #[test]
    fn rejects_declared_length_mismatches() {
        let mut encoded = encode_challenge(&challenge()).expect("encodable fixture");
        encoded[10] -= 1;

        assert_eq!(decode_challenge(&encoded), Err(WireError::LengthMismatch));
    }

    #[test]
    fn rejects_unknown_check_identifiers() {
        let mut encoded = encode_challenge(&challenge()).expect("encodable fixture");
        let last = encoded.last_mut().expect("non-empty fixture");
        *last = 99;

        assert_eq!(decode_challenge(&encoded), Err(WireError::UnknownCheck(99)));
    }

    #[test]
    fn rejects_oversized_input_before_parsing() {
        let oversized = vec![0; MAX_CHALLENGE_BYTES + 1];

        assert_eq!(
            decode_challenge(&oversized),
            Err(WireError::MessageTooLarge)
        );
    }
}
