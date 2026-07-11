# VALORANT on Linux: Feasibility Boundary

## Intended outcome

The motivating goal is to make VALORANT playable on Linux without weakening its
competitive integrity. That outcome cannot be delivered unilaterally by replacing,
emulating, or bypassing Riot Vanguard.

As of July 2026, Riot documents Windows 10 and Windows 11 as the supported PC
operating systems and states that virtual machines are unsupported. Riot also
describes Vanguard restrictions that rely on Windows and platform trust features,
including TPM, Secure Boot, and research into VBS, HVCI, and IOMMU enforcement.

These are server-enforced trust requirements. A locally developed Linux monitor
cannot make Riot's servers trust a new client, signing key, kernel, hypervisor, or
evidence format. Only Riot can add that trust relationship and ship or approve the
corresponding game and anti-cheat changes.

## What a “second kernel” means

Two general architectures resemble a second kernel running beside Linux:

1. **Type-1 hypervisor:** a small privileged layer owns the hardware and runs Linux
   and another guest. This creates isolation, but a Windows VALORANT guest remains
   a virtual machine and is not a supported environment.
2. **Co-kernel or privileged monitor:** a separate runtime observes selected host
   events. It is complex, hardware-specific, and cannot independently satisfy
   Vanguard's Windows driver, boot chain, or server attestation.

Neither approach avoids interference with Linux. Anything below or beside the
kernel necessarily participates in CPU scheduling, memory translation, interrupts,
device ownership, boot trust, or all five. Bugs at that layer can compromise or
crash the entire machine.

## Prohibited project direction

This project must not:

- impersonate Vanguard or forge its reports;
- defeat environment, VM, boot-chain, or platform checks;
- reverse engineer private protocols to obtain unauthorized service access;
- hide a virtualized or modified environment from Riot;
- claim compatibility with VALORANT without Riot's written authorization.

Apart from security and legal risk, those approaches would undermine the integrity
goal of the project itself.

## Viable project directions

### Independent research prototype

Build an open, privacy-minimizing Linux integrity system for a controlled sample
game or a multiplayer game whose operator opts in. This validates collectors,
attestation, policy, eBPF, and possibly hypervisor-backed measurements without
pretending to be Vanguard.

### Riot-coordinated Linux design

Produce a technical proposal and proof of concept that Riot could evaluate. A real
deployment would require Riot to provide or approve:

- a native or supported compatibility-layer game build;
- Linux anti-cheat enrollment and signing roots;
- server-side verification and policy changes;
- supported kernel/distribution and hardware requirements;
- update, revocation, telemetry, privacy, and player-support processes.

### Hypervisor research track

Explore a minimal monitor only after the user-space protocol is complete. The goal
would be measuring isolation and trustworthy evidence for a test workload, not
running VALORANT or evading Vanguard. This track needs its own threat model, hardware
lab, recovery strategy, and safety review.

## Decision gate

Before kernel or hypervisor implementation begins, the project must choose one
explicit product claim:

- research anti-cheat for an owned test game; or
- Riot-authorized Linux enablement research.

Without Riot participation, the first claim is the only deliverable one.
