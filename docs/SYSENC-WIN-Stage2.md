# Stage 2 – Windows Pre-Boot Full Disk Encryption
<!-- TSK714B_System_Drive_Encryption_(PreBoot_Windows_First)_Stage2_PreBoot_FullDisk -->

## Overview

Stage 2 extends the QuantumVault Windows secure boot chain with a firmware authentication layer and a block device encryption driver that operates before the NT kernel accesses the system volume. The new components introduce a measured hand-off mechanism so the volume key material never traverses user mode.

## Boot Flow

1. **UEFI Pre-Boot (`boot/win/qv-uefi`)** – Presents the unlock UI, collects passphrases or keyfiles, optionally unseals a TPM policy blob, derives the XTS-512 key with Argon2id, and writes it into the volatile `QVKey` firmware variable (GUID `{d16a4c54-0f07-4a28-9a5e-5de41a3b928c}`).
2. **EFI Variable Handoff** – The key is stored with `EFI_VARIABLE_BOOTSERVICE_ACCESS` and cleared once consumed to prevent persistence across reboots.
3. **Boot-Start Driver (`driver/win/qvdisk`)** – Loads before the filesystem stack, reads the handoff key, attaches as a lower filter to the system disk, and applies AES-XTS transforms per sector. Recovery keys are enrolled via IOCTL and kept in non-paged storage until cleared.
4. **Windows Service (`service/qvsvc`)** – Runs as a minimal shim on Windows to support recovery enrollment, TPM replays, and power-state handling. When the pre-boot stage is unavailable, the service falls back to the Stage 1 minifilter stack to keep compatibility with existing deployments.
5. **Boot Preparation Tool (`tools/qv-bootprep-win.cpp`)** – Automates copying the UEFI application onto the ESP, sets up a dedicated BCD boot application entry, and forces the `qvdisk` driver to load as `BOOT_START` so it executes prior to Winload.

## Recovery and Maintenance

* **Recovery keys** – Stored as fixed-size blobs via `IOCTL_QVDISK_ENROLL_RECOVERY`. The service loads a pre-provisioned file from `%ProgramData%\QuantumVault\recovery.qvkey` and marks session keys as recovery-driven when needed.
* **TPM interaction** – The UEFI app can mix TPM-sealed secrets with user input before emitting the session key. PCR bindings ensure Secure Boot policy tampering invalidates the sealed data.
* **Hibernation / Fast Startup** – `qvsvc` listens for `PBT_APMSUSPEND` and explicitly locks `qvdisk` to avoid stale keys in sleep images. Resume triggers a best-effort firmware read of `QVKey` to rehydrate the disk stack.
* **Updates** – The BCD chain isolates QuantumVault in a dedicated boot application object so Windows upgrades can proceed while maintaining our first-stage handoff.

## Threat Model Notes

* The session key is present only in boot services memory and non-paged driver state. After import, both firmware and driver zeroise their buffers.
* Recovery files are optional; when deployed, they must be stored on removable media or a sealed partition protected by standard NTFS ACLs.
* Integrity metadata is planned for a follow-up milestone (Merkle or AEAD tags stored in a hidden region) and is disabled to keep pre-boot latency low.

## Testing Considerations

* Validate cold boot, warm reboot, and Secure Boot tampering scenarios.
* Exercise hibernation, BitLocker-disabled co-existence, crash dumps, and abrupt power loss with encrypted volumes to ensure no deadlock on resume.
* Confirm that deleting the `QVKey` variable or clearing TPM PCRs forces the recovery path before Winload starts.

