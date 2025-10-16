# QuantumVault System Drive Encryption — Stage 1 (Windows)

<!-- // TSK714A_System_Drive_Encryption_(PreBoot_Windows_First)_Stage1_Minifilter -->

This document sketches the scaffolding required to bring up the Stage 1
system-drive encryption preview on Windows. The work represented in this commit
is intentionally incomplete; it provides the wiring, ABI definition, and
skeletons necessary for the driver, service, and installer pieces described in
TSK714A.

## Components introduced

| Component | Purpose |
| --- | --- |
| `driver/win/qvflt` | Windows file-system mini-filter driver that handles the in-flight encryption of file buffers. |
| `service/qvsvc` | Early-start Windows service responsible for deriving keys and providing them to the mini-filter. |
| `include/qv/platform/win/qvflt_ioctl.h` | Shared IOCTL contract between kernel and user mode. |
| `tools/qv-bootprep-win.cpp` | Helper utility to install the driver/service and configure boot-time behaviour. |

## Follow-on work

- Flesh out the AES-XTS transform paths and integrate the production crypto
  implementation instead of the placeholder routines.
- Harden the key-ingress path (LSA isolation, secure zeroisation, credential
  acquisition lifecycle).
- Expand coverage to additional directories and non-file-backed regions once
  early boot key provisioning is proven out.
- Integrate the driver build into our CI for Windows once the remaining code is
  functionally complete.

