# Linux Integrity Vanguard

![Linux Integrity Vanguard](docs/images/linux-integrity-vanguard.png)

Linux Integrity Vanguard is a transparent Linux anti-cheat and system integrity research prototype for custom multiplayer games. It combines user-space integrity checks, optional eBPF observability, signed client reports and server-side trust evaluation.

## Research goals

- Make trust boundaries explicit and reviewable.
- Minimize collection to signals relevant to system integrity.
- Keep eBPF observability optional rather than mandatory.
- Sign structured client reports before server evaluation.
- Produce explainable evidence instead of opaque scores alone.
- Document limitations, failure modes and deployment assumptions.

## Proposed architecture

```text
User-space checks
      |
Optional eBPF events
      |
Normalized evidence
      |
Signed client report
      |
Server-side verification and trust evaluation
```

## Components

### User-space checks

Portable checks collect documented integrity signals without requiring kernel instrumentation for every deployment.

### Optional eBPF observability

When the host supports it, eBPF can provide additional visibility into selected process and system events. The prototype is designed to degrade clearly when this layer is unavailable.

### Signed reports

Evidence is normalized into a structured report. Signing helps the server verify report integrity and associate it with an expected client session.

### Server-side trust evaluation

The server evaluates multiple signals in context. A single event should not automatically become a sanction without corroboration and documented policy.

## Security principles

- Transparency over obscurity
- Least privilege
- Minimal and purpose-bound data collection
- Defense in depth
- Explicit failure handling
- Reproducible testing
- Clear separation between evidence and enforcement policy

## Status

This repository is an early research prototype and portfolio reference. It is not a production anti-cheat solution and does not claim to prevent every form of cheating or host compromise.

## License

This repository is public for transparency and portfolio/reference purposes only.

Copyright (c) 2026 JavaScript-X. All rights reserved.

No permission is granted to use, copy, modify, distribute, sublicense, sell, host, deploy, or create derivative works from this software without prior written permission.
