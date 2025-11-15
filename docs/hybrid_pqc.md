# Hybrid Post-Quantum Storage Architecture
<!-- TSK061_Block_Device_and_Chunk_Storage_Engine -->

QuantumVault pairs post-quantum key encapsulation with high-throughput
symmetric encryption to secure bulk storage.

## Key Hierarchy

<!-- // TSK245 -->
1. User secrets are strengthened through Argon2id to derive a 256-bit classical master key.
2. The classical key encrypts (wraps) the ML-KEM-768 secret key with AES-256-GCM, storing the PQC ciphertext, nonce, and tag beside the PQC public key material.
3. Per-purpose keys (data, metadata, index) are derived from the hybrid key via HMAC-based KDFs.

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

## Hybrid Key Formation

1. Volume provisioning generates an ML-KEM-768 keypair and encapsulates the
   public key to obtain a PQC shared secret.
2. The Argon2id-derived classical key acts as the authenticated-encryption key
   that wraps the PQC secret key, binding it to the volume UUID, header version,
   and epoch TLVs via AES-256-GCM associated data.
3. Mount time reverses the wrapping by decrypting the PQC secret key with the
   classical key, decapsulates the ciphertext, and feeds both the classical key
   bytes and the PQC shared secret into HKDF to obtain the hybrid master key.

This "KEM-in-authenticated-encryption" sequence ensures that the PQC secret key
remains opaque unless the classical key is recovered, while the final HKDF
output cannot be computed unless both the classical key and the PQC shared
secret are present.

## Quantum Resilience

Even with Grover's algorithm halving the effective symmetric security, the
adversary must first break the AES-256-GCM wrapping keyed by the Argon2id
output to extract the PQC secret key and then defeat ML-KEM-768 to compute the
shared secret required by the HKDF step. This serial dependency raises the
attack cost well beyond the 2^64 quantum search space for the AEAD layer.

## Operational Notes

- Nonce rotation is enforced through the authenticated nonce log and epoch
  tracking.
- Chunk headers occupy 128 bytes, aligning with cache lines and enabling
  fixed-size records for block device operations.
- The block device abstraction expands sparse files on demand, supporting
  thin-provisioned containers.

