# QuantumVault UEFI Pre-Boot Application
<!-- TSK714B_System_Drive_Encryption_(PreBoot_Windows_First)_Stage2_PreBoot_FullDisk -->

This directory hosts the firmware-stage unlock experience for QuantumVault Stage 2.

## Overview

* Presents a pre-boot UI for passphrases, keyfiles, and TPM-backed secrets.
* Derives the per-boot AES-XTS key material with Argon2id tuned for firmware constraints.
* Writes the unlocked session key into the volatile `QVKey` hand-off variable consumed by the `qvdisk` boot driver.

## Building

Building the firmware binary requires the EDK II toolchain:

1. Clone [EDK II](https://github.com/tianocore/edk2) and set up the `edksetup.sh` environment.
2. Add this directory to a custom DSC/FDF that packages `qv_uefi.c` as a `BOOT_APPLICATION`.
3. Provide the Argon2 implementation in `MdeModulePkg/Library` (fallback to `QV_USE_STUB_CRYPTO` while validating the flow).

For development, `qv_uefi.c` is written so it can also be unit tested in host builds by defining `__EFI__` and supplying mocked runtime services.

## Firmware Variables

The pre-boot code stores the unlock key in a boot-services only variable:

* **Name**: `QVKey`
* **GUID**: `{d16a4c54-0f07-4a28-9a5e-5de41a3b928c}`
* **Attributes**: `EFI_VARIABLE_BOOTSERVICE_ACCESS`

The boot driver clears the variable once the key is imported to avoid persistent secrets.

