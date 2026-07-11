# Linux Integrity Vanguard

Linux Integrity Vanguard is a transparent research prototype for evaluating the
integrity of Linux game clients. It combines user-space evidence collection,
optional eBPF telemetry, signed reports, and server-side policy evaluation.

The motivating use case is Linux support for games protected by kernel-level
anti-cheat. It is **not** a replacement for, emulator of, or bypass for Riot
Vanguard. Making VALORANT accept Linux requires Riot's explicit support and
server-side trust integration; see the [feasibility boundary](docs/FEASIBILITY.md).

> [!IMPORTANT]
> This project is an experimental integrity signal, not proof that a client is
> cheat-free. It must not be used as the sole basis for punitive decisions.

## Project status

The repository is in the foundation phase. The architecture, security boundaries,
and delivery roadmap are defined; implementation of the first end-to-end evidence
pipeline is the next milestone.

## Design principles

- **Transparent:** collection and scoring rules are reviewable.
- **Privacy-minimizing:** collect explicit integrity facts, not user content.
- **Fail safe:** missing or invalid evidence produces an unknown result, not an
  automatic accusation.
- **Layered:** user-space checks, optional kernel telemetry, signatures, and
  server policy provide independent signals.
- **Testable:** collectors and policies have deterministic inputs and outputs.

## Planned components

| Component | Responsibility |
| --- | --- |
| Agent | Collect an allowlisted set of local integrity observations. |
| Reporter | Canonicalize and sign a versioned evidence envelope. |
| Verifier | Validate schema, freshness, nonce, and signature. |
| Policy engine | Convert verified evidence into allow, review, or deny outcomes. |
| eBPF sensor | Optionally emit narrowly scoped process and file events. |

See [Architecture](docs/ARCHITECTURE.md), [Threat model](docs/THREAT_MODEL.md),
[Roadmap](docs/ROADMAP.md), [VALORANT feasibility](docs/FEASIBILITY.md), and
[architecture decisions](docs/adr/README.md) for the working specification.

## Development

Core components will use stable Rust as recorded in
[ADR-0001](docs/adr/0001-rust-for-core-components.md). The exact bootstrap and
quality-check commands are:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

The pinned toolchain is installed automatically by `rustup`. See
[CONTRIBUTING.md](CONTRIBUTING.md) for change standards.

## Responsible use

Do not deploy this prototype as covert monitoring, use it to inspect unrelated
processes or user content, or treat a low-confidence result as proof of cheating.
Server operators remain responsible for proportional review and appeal mechanisms.

## License

This repository is public for transparency and portfolio/reference purposes only.
See [LICENSE](LICENSE). No permission is granted to use, copy, modify, distribute,
sublicense, sell, host, deploy, or create derivative works without prior written
permission.
