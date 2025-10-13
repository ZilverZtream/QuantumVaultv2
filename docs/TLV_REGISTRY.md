<!-- TSK033 -->
# TLV Type Registry

| Type   | Name              | Length  | Purpose                                  | Since |
|--------|-------------------|---------|------------------------------------------|-------|
| 0x1001 | PBKDF2            | 20      | PBKDF2 iteration count + salt            | v4.0  |
| 0x1002 | HybridSalt        | 32      | Salt for PQC hybrid KDF                  | v4.0  |
| 0x4E4F | Epoch             | 4       | Nonce generator epoch                    | v4.1  |
| 0x7051 | PQC_KEM           | 3516    | ML-KEM-768 ciphertext + encrypted SK     | v4.0  |
| 0x7F02 | ReservedV2        | 32      | Reserved for future ACL metadata         | v4.1  |

**Allocation Policy:** Range 0x1000-0x1FFF reserved for key derivation, 0x7000-0x7FFF for experimental features.

**Forward Compatibility Rule:** Readers must skip unknown TLV types without failing to allow future extensions. <!-- TSK033 -->
