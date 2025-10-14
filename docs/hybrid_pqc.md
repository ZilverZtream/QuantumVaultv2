# Hybrid Post-Quantum Storage Architecture
<!-- TSK061_Block_Device_and_Chunk_Storage_Engine -->

QuantumVault pairs post-quantum key encapsulation with high-throughput
symmetric encryption to secure bulk storage.

## Key Hierarchy

1. User secrets are strengthened through Argon2id to derive a 256-bit master key.
2. The master key is wrapped using ML-KEM-768 to withstand quantum attacks.
3. Per-purpose keys (data, metadata, index) are derived via HMAC-based KDFs.

## Chunk Protection Pipeline

1. Plaintext payloads are padded to the fixed 64 KiB chunk size.
2. Each chunk obtains an authenticated nonce from the nonce log chain.
3. Associated data binds the epoch, logical offsets, and nonce MACs.
4. Data is encrypted with the fastest available AEAD (AEGIS-128X/128L, AES-GCM fallback).
5. Headers persist cipher identifiers, tag sizes, and nonce material for recovery.

## Cipher Agility

The storage engine negotiates the highest-performance cipher that is compiled
into the build. Deployments with libsodium ≥ 1.0.20 gain AEGIS-128L/256
support; otherwise, AES-256-GCM provides compatibility.

## Quantum Resilience

Even with Grover's algorithm halving the effective symmetric security,
the PQC-wrapped master keys prevent adversaries from mounting brute-force
attacks against the AEAD layer. Attackers must defeat ML-KEM-768 before
attempting to exhaust the 2^64 quantum search space, which is infeasible.

## Operational Notes

- Nonce rotation is enforced through the authenticated nonce log and epoch
  tracking.
- Chunk headers occupy 128 bytes, aligning with cache lines and enabling
  fixed-size records for block device operations.
- The block device abstraction expands sparse files on demand, supporting
  thin-provisioned containers.

