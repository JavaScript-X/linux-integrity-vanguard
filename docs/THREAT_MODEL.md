# Threat Model

## Assets

- correctness and availability of multiplayer trust decisions;
- integrity and confidentiality of signing material;
- privacy of client users;
- authenticity and freshness of evidence reports;
- auditability of policy changes and decision reasons.

## Adversaries

The primary adversary controls the client account and may control the entire Linux
host, including processes, files, network traffic, clocks, and kernel. Secondary
adversaries may replay or mutate reports in transit, submit malformed input to the
verifier, or misconfigure an overly invasive collection policy.

## Security goals

- Detect a documented set of integrity inconsistencies at useful confidence.
- Prevent undetected report mutation and cross-challenge replay.
- Keep hostile reports from exhausting or compromising the verifier.
- Make collection scope visible, minimal, and enforceable on the client.
- Produce explainable decisions with enough context for review and appeal.

## Non-goals

- Proving that a user-controlled machine is cheat-free.
- Resisting a fully compromised kernel or physical attacker.
- Inspecting arbitrary memory or personal content.
- Hiding collectors, policies, or protocol behavior from users.
- Automatically banning a player from a single weak or unavailable signal.

## Key threats and mitigations

| Threat | Planned mitigation | Residual risk |
| --- | --- | --- |
| Report tampering | Canonical encoding and authenticated signatures. | A compromised client can sign false observations. |
| Replay | Server nonce, short expiry, and one-time nonce storage. | Store outages may reduce availability. |
| Parser abuse | Size/depth limits, strict schema validation, fuzzing. | Unknown parser defects remain possible. |
| Collector spoofing | Cross-check independent signals and preserve errors. | Host control prevents absolute assurance. |
| Key theft | Restricted storage, rotation, revocation, short-lived enrollment. | User-controlled hosts cannot guarantee secrecy. |
| Privacy overreach | Allowlists, documented fields, no arbitrary-content APIs. | Metadata can still be sensitive. |
| Policy mistakes | Versioned rules, shadow evaluation, reason codes, appeals. | Human review can still be inconsistent. |
| eBPF compatibility | Optional capability probing and user-space fallback. | Reduced signals lower confidence. |

## Decision safety

Outcomes distinguish `allow`, `review`, and `deny`. Missing, unsupported, or
internally inconsistent evidence defaults to `review` unless a narrowly documented
server requirement makes connection impossible. Policies must use multiple
independent signals for high-impact enforcement.

## Review cadence

Update this model whenever collection scope, protocol fields, trust boundaries,
cryptographic primitives, or enforcement behavior changes. Security-relevant pull
requests should state which threat or assumption they affect.
