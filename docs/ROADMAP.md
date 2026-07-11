# Roadmap

This roadmap favors a testable end-to-end path before privileged or invasive
collection. Status markers are: `[ ]` planned, `[~]` active, and `[x]` complete.

## Phase 0 — Project foundation

- [x] Define architecture and trust boundaries.
- [x] Document threat model, privacy constraints, and non-goals.
- [x] Publish phased implementation plan and acceptance criteria.
- [x] Add contribution, security-reporting, and decision-record templates.
- [x] Choose the implementation language and record the decision.

Exit criterion: contributors can explain what the system can and cannot claim.

## Phase 1 — Protocol vertical slice

- [ ] Define a versioned challenge and evidence-envelope schema.
- [ ] Implement deterministic encoding with strict size limits.
- [ ] Implement signing and verification behind interfaces.
- [ ] Add nonce, expiry, and replay validation.
- [~] Build a fixture collector and a three-outcome policy engine (initial policy
  complete; fixture collector pending).
- [ ] Cover valid, expired, replayed, malformed, and unsupported reports.

Exit criterion: a local demo creates, verifies, and evaluates a fixture report with
no privileged access, and automated tests cover failure paths.

## Phase 2 — Linux user-space collectors

- [ ] Collect kernel/distribution compatibility metadata.
- [ ] Hash explicitly configured game artifacts safely.
- [ ] Collect allowlisted game/parent process metadata from `/proc`.
- [ ] Represent permission, race, and unsupported states without guessing.
- [ ] Add golden fixtures across supported distributions.

Exit criterion: collectors run without root and never read fields outside the
documented evidence profile.

## Phase 3 — Server hardening

- [ ] Add persistent one-time nonce handling and enrollment lifecycle.
- [ ] Enforce request rate, byte, nesting, and processing-time budgets.
- [ ] Add structured audit events without raw sensitive evidence.
- [ ] Support policy versioning, shadow evaluation, and reason codes.
- [ ] Fuzz protocol decoding and policy inputs.

Exit criterion: hostile-input tests cannot bypass freshness checks or exceed
documented resource bounds.

## Phase 4 — Optional eBPF telemetry

- [ ] Write an ADR defining exact events, privilege model, and fallback behavior.
- [ ] Prototype tracepoint-based observation with capability probing.
- [ ] Filter in kernel where practical and bound all maps/buffers.
- [ ] Package the sensor as opt-in with explicit operator/user documentation.
- [ ] Test supported kernel ranges and graceful degradation.

Exit criterion: disabling or lacking eBPF never breaks the base agent and only
changes declared evidence confidence.

## Phase 5 — Operational readiness

- [ ] Add reproducible builds, SBOM, artifact signing, and release checksums.
- [ ] Add CI for formatting, linting, tests, dependency audit, and license policy.
- [ ] Publish deployment, key rotation, incident, and appeal runbooks.
- [ ] Commission an independent privacy and security review.

Exit criterion: releases are traceable, rollbackable, monitored, and supported by
documented human review processes.

## Immediate backlog

1. Write ADR-0002 for protocol encoding and signing primitives.
2. Add continuous integration checks for the scaffolded Rust workspace.
3. Define the challenge and evidence-envelope domain types.
4. Implement the Phase 1 fixture-based vertical slice.
5. Revisit roadmap estimates after the vertical slice exposes real complexity.
