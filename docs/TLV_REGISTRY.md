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

<!-- TSK712_Header_Backup_and_Restore_Tooling -->
### Header backup TLV catalog

| Type   | Name                      | Length  | Purpose                                              | Since |
|--------|---------------------------|---------|------------------------------------------------------|-------|
| 0x5100 | BackupMetadata            | Var.    | Bundle metadata (UUID, version, KDF descriptors)     | v4.1  |
| 0x51F0 | BackupCiphertext          | Var.    | AES-GCM sealed header bytes + nonce/tag              | v4.1  |
| 0x0101 | BackupFormatVersion      | 2       | Format version of metadata block                     | v4.1  |
| 0x0102 | BackupContainerUuid      | 16      | Volume UUID                                          | v4.1  |
| 0x0103 | BackupContainerVersion   | 4       | Volume header version                                | v4.1  |
| 0x0104 | BackupContainerFlags     | 4       | Container flags                                      | v4.1  |
| 0x0110 | BackupContainerPbkdf2    | Var.    | PBKDF2 iterations and salt (if present)              | v4.1  |
| 0x0111 | BackupContainerArgon2    | Var.    | Argon2 parameters and salt (if present)              | v4.1  |
| 0x0120 | BackupRecoveryKdf        | Var.    | Recovery password KDF parameters and salt            | v4.1  |

Backup metadata TLVs are nested inside `BackupMetadata` and extendable; readers
must ignore unknown nested TLVs to preserve forward compatibility.
