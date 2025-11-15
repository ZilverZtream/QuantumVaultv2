<!-- TSK020 -->
# Security Policy

QuantumVault is designed for high-assurance encrypted storage deployments. This
policy captures the guardrails maintainers enforce while reviewing changes and
during releases.

## Supported threat scenarios

We focus engineering effort on the following adversaries:

- **Offline theft** – an attacker steals a container file or an entire storage
  node and attempts to recover plaintext. All persisted material must remain
  confidential under this scenario.
- **Active tampering** – an attacker can replace metadata files, inject stale
  nonce logs, or modify plugin binaries. Integrity and replay protection must
  prevent silent compromise.
- **Plugin supply chain** – third-party plugins are loaded into the process. The
  host verifies signatures, enforces version pinning, and rejects unknown
  publishers. Plugin APIs must never accept plaintext secrets without a
  MAC/AEAD envelope.

Scenarios **out of scope** for the skeleton build include kernel compromise,
malicious hardware, and side-channel leakage outside the documented timing
budget.

## Cryptography requirements

- **Nonce/IV management** – all AES-GCM invocations must use the deterministic
  `epoch || counter` nonce strategy implemented by `qv::core::NonceLog`. When
  migrating legacy volumes, ensure the log copy preserves ordering; the CLI's
  `migrate-nonces` command enforces this invariant.
- **PQC hybrid KEM** – the header stores a post-quantum ciphertext alongside the
  classical material. When swapping stub crypto for real providers, the
  resulting implementation must encapsulate with ML-KEM-768 (or stronger) and
  retain the ciphertext bytes to guarantee deterministic decapsulation.
- **Key derivation** – password-based keys are derived via PBKDF2-HMAC-SHA256 or
  Argon2id depending on the negotiated header parameters, always with a 128-bit
  salt. PBKDF2 profiles enforce timing padding to match Argon2 budgets, and
  maintainers may increase iterations/memory cost but must document any
  reduction from the defaults. <!-- TSK220 -->

## Reporting vulnerabilities

Security issues should be reported privately by emailing
`security@quantumvault.dev`. Please include proof-of-concept details and an
impact assessment. Maintainers strive to acknowledge reports within 2 business
days and provide a remediation timeline within 7 days.

## Hardening checklist for releases

1. Build with `-DQV_USE_STUB_CRYPTO=OFF` and vendor OpenSSL/libsodium/liboqs.
2. Run the threat-model validation steps in `THREATMODEL.md`.
3. Audit the nonce log for monotonic counters after migrations.
4. Re-sign all plugins and update the trust store fingerprints.
