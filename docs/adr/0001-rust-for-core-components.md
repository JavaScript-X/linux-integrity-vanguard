# ADR-0001: Rust for core components

- Status: accepted
- Date: 2026-07-11
- Deciders: project maintainer

## Context

The agent reads adversary-influenced Linux interfaces, and the verifier parses
hostile network input. Both components need predictable resource handling, strong
types for protocol states, memory safety, and deployable native binaries. The
optional eBPF sensor must remain isolated from the portable core.

## Decision

Implement the user-space agent, report verifier, policy engine, and shared protocol
types as a Rust workspace. Prefer the stable toolchain, deny unsafe code in core
crates, and minimize dependencies. Put Linux-specific collectors behind traits so
fixtures can exercise the complete pipeline without `/proc` or elevated access.

Treat eBPF as a separate optional component with a narrow event interface. Its
specific framework and build toolchain require a later ADR after the user-space
vertical slice establishes the required events.

## Consequences

- Contributors need a stable Rust toolchain and Linux for collector integration.
- The core protocol and policy crates can be tested on non-Linux development hosts.
- Kernel integration cannot leak platform types into the wire protocol.
- Dependency review and compiler-version policy become release responsibilities.
- The repository must not merge scaffolding that cannot pass formatting, linting,
  and tests in the supported toolchain.

## Alternatives considered

- **Go:** simple deployment and concurrency, but weaker modeling of protocol state
  and less direct alignment with the likely eBPF/native integration work.
- **C or C++:** broad systems access, but unnecessary memory-safety risk in hostile
  parsers and privileged collection code.
- **TypeScript:** productive for service prototypes, but adds a runtime and is a
  poor fit for a low-footprint Linux agent and kernel-adjacent work.
