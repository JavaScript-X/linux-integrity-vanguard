# Security Policy

## Project maturity

Linux Integrity Vanguard is a research prototype and has no production-supported
release. Do not rely on it as the sole security control for a multiplayer service.

## Reporting a vulnerability

Do not publish exploit details in a public issue. Contact the repository owner
privately through the security-reporting mechanism on the repository hosting
platform. Include:

- affected commit or version;
- prerequisites and a minimal reproduction;
- security and privacy impact;
- suggested mitigation, if known.

Do not include real user evidence, credentials, private keys, or unrelated system
data. The maintainer should acknowledge a complete report, establish a private
coordination channel, and agree on disclosure timing before details are published.

## In scope

- signature, challenge, freshness, or replay bypasses;
- parser or verifier denial of service;
- collection outside the documented evidence profile;
- sensitive data or key exposure;
- policy behavior that converts missing evidence into an unsafe assertion;
- privilege-boundary failures in optional sensors.

Generic hardening suggestions without a concrete security impact can use a normal
issue once issue tracking is available.
