# Roadmap

This roadmap favors a testable end-to-end path before privileged or invasive
collection. Status markers are: `[ ]` planned, `[~]` active, and `[x]` complete.

## Phase -1 — Product and authorization gate

- [x] Document why a local Vanguard replacement cannot make VALORANT trust Linux.
- [x] Separate anti-cheat research from impersonation or compatibility bypasses.
- [ ] Select the controlled sample game used for end-to-end development.
- [ ] If VALORANT compatibility remains a goal, obtain a Riot-supported technical
  and authorization path before representing the project as compatible.

Exit criterion: the project has an owned test workload or an authorized game-server
integration, with permission to modify both sides of the trust protocol.

## Phase 0 — Project foundation

- [x] Define architecture and trust boundaries.
- [x] Document threat model, privacy constraints, and non-goals.
- [x] Publish phased implementation plan and acceptance criteria.
- [x] Add contribution, security-reporting, and decision-record templates.
- [x] Choose the implementation language and record the decision.

Exit criterion: contributors can explain what the system can and cannot claim.

## Phase 1 — Protocol vertical slice

- [~] Define a versioned challenge and evidence-envelope schema (validated domain
  types complete; signed wire envelope pending).
- [~] Implement deterministic encoding with strict size limits (encoding contract
  and bounded challenge/report codecs complete; signed envelope pending).
- [~] Implement signing and verification behind interfaces (domain-separated
  Ed25519 primitives complete; signed transport codec and key registry pending).
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

## Phase 4B — Optional hypervisor research

- [ ] Define the research question and show why simpler signals cannot answer it.
- [ ] Write a dedicated threat model and architecture decision record.
- [ ] Choose a narrow hardware target and establish a recoverable test machine.
- [ ] Prototype isolation and attestation against an owned test workload.
- [ ] Measure boot, runtime, device, and compatibility impact on the Linux host.

Exit criterion: the monitor produces independently verified measurements without
claiming third-party game compatibility or bypassing environment checks.

## Phase 5 — Operational readiness

- [ ] Add reproducible builds, SBOM, artifact signing, and release checksums.
- [~] Add CI for formatting, linting, tests, dependency audit, and license policy
  (formatting, linting, and tests complete; supply-chain checks pending).
- [ ] Publish deployment, key rotation, incident, and appeal runbooks.
- [ ] Commission an independent privacy and security review.

Exit criterion: releases are traceable, rollbackable, monitored, and supported by
documented human review processes.

## Immediate backlog

1. Define the challenge and evidence-envelope domain types.
2. Implement the signed report envelope and Ed25519 verification.
3. Add expiry and replay protection.
4. Build a deterministic fixture collector.
5. Complete the Phase 1 end-to-end demo.
