# Architecture

## System context

The system separates evidence collection from trust decisions. The Linux client
collects a small, documented set of observations and signs a report. The game
server verifies that report and applies its own versioned policy.

```text
Linux host                         Trusted server boundary
+----------------------+          +---------------------------+
| Game process         |          | Report verifier           |
| User-space collector |--report->| - schema and size limits  |
| Optional eBPF sensor |          | - nonce and freshness     |
| Reporter and signer  |          | - signature validation    |
+----------------------+          +-------------+-------------+
                                                |
                                      verified evidence
                                                |
                                  +-------------v-------------+
                                  | Versioned policy engine   |
                                  | allow / review / deny     |
                                  +---------------------------+
```

## Evidence flow

1. The server issues a single-use challenge containing a nonce, expiry, and
   requested evidence profile.
2. The agent validates the profile against its local allowlist.
3. Collectors produce typed observations with explicit error states.
4. The reporter creates a canonical, size-bounded evidence envelope.
5. A client key signs the envelope and binds it to the challenge.
6. The verifier checks protocol version, size, freshness, nonce reuse, and
   signature before parsing evidence.
7. The policy engine evaluates only verified, supported observations and emits a
   decision plus machine-readable reason codes.

## Initial evidence profile

The first release should stay intentionally narrow:

- executable identity for the launched game binary;
- selected process metadata for the game process and its direct parent;
- hashes of explicitly configured game files;
- kernel and distribution identifiers needed for compatibility evaluation;
- collector errors and unsupported checks as first-class observations.

Command lines, environment values, arbitrary home-directory files, window titles,
keystrokes, network payloads, and unrelated processes are out of scope.

## Trust boundaries

- The client host is untrusted. Client results are evidence, not facts.
- The server verifier is exposed to hostile input and requires strict limits.
- Signing keys establish report continuity, not a cheat-free machine.
- eBPF increases observation depth but does not turn the kernel into a trusted
  boundary when the user controls the host.
- Policy configuration is security-sensitive and must be versioned and auditable.

## Protocol qualities

The report format must be versioned, deterministic, replay-resistant, bounded,
forward-compatible, and independent of policy. Cryptographic choices will be
recorded in an architecture decision record before implementation.

## Deployment modes

- **Development:** fixture collectors and local verifier, no privileged sensor.
- **User-space:** production collectors and signed reports without eBPF.
- **Enhanced:** user-space agent plus an explicitly enabled eBPF sensor.

The user-space mode remains supported so development and policy behavior never
depend on privileged kernel access.
