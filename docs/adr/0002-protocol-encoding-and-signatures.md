# ADR-0002: Deterministic protocol encoding and Ed25519 signatures

- Status: accepted
- Date: 2026-07-11
- Deciders: project maintainer

## Context

Evidence reports cross an untrusted network boundary and are signed by clients.
The verifier needs exactly one byte representation for each signed message, strict
resource limits before allocation, explicit version negotiation, and parsers that
are straightforward to test and fuzz.

General-purpose self-describing formats introduce canonicalization and parser
surface that the first protocol does not need. Signing a parsed structure is also
unsafe if multiple byte sequences decode to the same value.

## Decision

Use a project-owned, fixed-layout binary wire format for protocol version 1.
Encoding and decoding live in a dedicated crate and use explicit big-endian integer
fields. Every top-level message starts with:

1. four-byte ASCII magic `LIV1`;
2. one-byte message kind;
3. two-byte protocol version;
4. four-byte unsigned payload length;
5. the exact payload bytes.

Variable-length byte strings use a two-byte unsigned length immediately followed
by content. Collections use a two-byte item count. Version 1 forbids unknown fields,
trailing bytes, duplicate checks, indefinite lengths, and recursive values.

The following limits apply before expensive parsing or cryptographic work:

- complete challenge: 4 KiB;
- complete signed report: 64 KiB;
- nonce: exactly 32 bytes;
- key identifier: at most 64 bytes of restricted ASCII;
- evidence items: at most 256;
- individual evidence value: at most 4 KiB.

Sign reports with Ed25519. The signature input is the complete canonical unsigned
report frame prefixed with the ASCII domain separator
`linux-integrity-vanguard/report/v1\0`. Verification operates on the received raw
bytes before converting them into policy types. Public keys are selected by an
enrollment-issued key identifier; private-key storage and enrollment require a
separate decision record.

Challenges contain the protocol version, a cryptographically random 32-byte nonce,
an issue timestamp, an expiry timestamp, and a bounded ordered list of requested
checks. Reports repeat the nonce and bind every observation to one requested check.
Timestamps are signed Unix milliseconds, but freshness policy uses a server clock
and never trusts client time.

Version negotiation is fail-closed: unsupported versions produce a typed protocol
error and are not reinterpreted. A future protocol version receives a new encoder,
decoder, domain separator, and test vectors.

## Consequences

- The format is deterministic by construction and can be implemented without a
  serialization framework.
- Golden byte vectors become part of the compatibility contract.
- Bounds can be checked while advancing a cursor through a byte slice.
- Protocol evolution requires explicit new versions rather than adding fields
  silently.
- A custom codec requires careful review, property tests, and fuzzing.
- Ed25519 adds a reviewed cryptographic dependency; application code must never
  implement signature arithmetic.

## Alternatives considered

- **Deterministic CBOR:** standardized and compact, but deterministic encoding
  still requires precise application rules and library verification. It remains a
  reasonable future version if interoperability becomes more important.
- **Protocol Buffers:** mature tooling, but unknown-field and reserialization
  behavior complicate signing exact canonical structures.
- **JSON:** easy to inspect, but number, Unicode, whitespace, and key-order rules
  create unnecessary canonicalization risk.
- **Bincode or postcard:** compact Rust formats, but their wire stability would
  couple the public protocol to Rust data-model and dependency behavior.
