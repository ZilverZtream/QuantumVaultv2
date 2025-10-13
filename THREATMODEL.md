<!-- TSK020 -->
# Threat Model

This document summarizes the STRIDE analysis used when evaluating changes to the
QuantumVault reference implementation.

## Assets

- Encrypted container data and metadata (nonce logs, PQC ciphertexts)
- User credentials and derived keys resident in memory
- Plugin signing keys and trust anchors
- Integrity of the orchestrator state machine

## Adversaries

1. **Opportunistic thief** – gains read access to storage (disk theft or cloud
   snapshot). Goal: recover plaintext without credentials.
2. **Malicious operator** – has write access to metadata and binaries but no
   signing material. Goal: introduce replayed nonces, downgrade crypto, or load
   rogue plugins.
3. **Network eavesdropper** – observes plugin download/updates. Goal: inject
   malicious artifacts or downgrade to vulnerable versions.

## Assumptions

- Host OS is patched and enforces standard process isolation.
- Trusted Platform Module (TPM) sealing and secure boot are optional; when
  available they harden plugin trust stores but are not mandatory for correctness.
- Cryptographic primitives use constant-time implementations once the stubs are
  replaced (see `SECURITY.md`).

## Mitigations

| Threat | Mitigation |
| ------ | ---------- |
| Nonce replay | Append-only nonce log validated on mount; CLI refuses to migrate when source log missing. |
| Crypto downgrade | Header stores PQC KEM ciphertext and algorithm identifiers; changes require re-encryption. |
| Plugin tampering | Plugins are Ed25519 signed and verified before load; trust store pinned per release. |
| Credential brute force | PBKDF2 iteration count tunable; hybrid KDF keeps PQC shared secret independent of password. |
| Metadata corruption | Volume header and log carry MACs; orchestrator aborts on validation errors. |

## Validation steps

1. Review all `qv::Error` additions for correct domain/code assignments; CLI exit
   codes must continue to signal user vs. system failures distinctly.
2. Run integration tests with `QV_USE_STUB_CRYPTO=OFF` on all supported
   platforms before shipping.
3. Capture a fresh nonce log after migrations and verify the monotonic counter
   sequence.
4. Document any new threat vectors introduced by plugins in their respective
   `README` files.
