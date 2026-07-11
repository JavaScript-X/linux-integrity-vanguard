# Contributing

This repository currently has a source-available, all-rights-reserved license.
Opening an issue or pull request does not grant permission to use the project. Ask
the copyright holder before contributing substantial work.

## Before changing code

1. Read the architecture, threat model, and current roadmap.
2. Open an issue for changes to collection scope, protocol fields, cryptography,
   enforcement behavior, or trust boundaries.
3. Record durable architectural decisions in `docs/adr`.
4. Keep privileged collection optional and preserve the user-space fallback.

## Change quality

- Make one coherent change per commit and use an imperative conventional subject,
  such as `feat(verifier): reject expired challenges`.
- Add tests for success, failure, malformed input, and boundary conditions.
- Treat unavailable evidence as explicit data; never silently substitute a safe
  value.
- Avoid logging raw evidence, keys, nonces, or user-controlled payloads.
- Update the threat model when assumptions or mitigations change.
- Run formatting, linting, tests, and dependency checks before requesting review.

## Commit types

Use `feat`, `fix`, `docs`, `test`, `refactor`, `build`, `ci`, `chore`, or `security`.
An optional scope should name the affected component.

## Review checklist

- Is the collection scope still minimal and documented?
- Are hostile inputs bounded before allocation or expensive work?
- Does the change preserve explainable `allow`, `review`, and `deny` outcomes?
- Are compatibility failures graceful and observable?
- Are secrets and privacy-sensitive fields excluded from logs and fixtures?
- Do tests demonstrate the claimed security property?
