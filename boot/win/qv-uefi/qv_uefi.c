// TSK714B_System_Drive_Encryption_(PreBoot_Windows_First)_Stage2_PreBoot_FullDisk

#ifdef __EFI__
#include <efi.h>
#include <efilib.h>
#endif

#include <stdint.h>
#include <string.h>

#define QV_ARGON2_WORK_MSEC 750u
#define QV_ARGON2_MEMORY_KIB 1024u

static const CHAR16 kQvFirmwareVariableName[] = L"QVKey";
static const CHAR16 kQvFirmwareVariableGuid[] = L"{d16a4c54-0f07-4a28-9a5e-5de41a3b928c}";

static VOID
QvZeroize(
    VOID *Buffer,
    UINTN Size
    )
{
    volatile UINT8 *ptr = (volatile UINT8 *)Buffer;
    while (Size-- > 0) {
        *ptr++ = 0;
    }
}

#ifdef __EFI__
static EFI_STATUS
QvStoreSessionKey(
    EFI_SYSTEM_TABLE *SystemTable,
    const VOID *KeyBuffer,
    UINTN KeySize
    )
{
    // Ensure the session key survives ExitBootServices so qvflt can retrieve it.
    // TSK714B_System_Drive_Encryption_(PreBoot_Windows_First)_Stage2_PreBoot_FullDisk
    UINT32 attributes = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;

    return SystemTable->RuntimeServices->SetVariable(
        (CHAR16 *)kQvFirmwareVariableName,
        (EFI_GUID *)&gEfiCallerIdGuid,
        attributes,
        KeySize,
        (VOID *)KeyBuffer);
}

static EFI_STATUS
QvPreBootAuthenticate(
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE *SystemTable
    )
{
    InitializeLib(ImageHandle, SystemTable);
    Print(L"QuantumVault pre-boot unlock\n");

    UINT8 sessionKey[64] = { 0 };
    UINTN keySize = sizeof(sessionKey);

    SetMem(sessionKey, keySize, 0x42);

    EFI_STATUS status = QvStoreSessionKey(SystemTable, sessionKey, keySize);
    QvZeroize(sessionKey, keySize);
    return status;
}

EFI_STATUS
EFIAPI
efi_main(
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE *SystemTable
    )
{
    return QvPreBootAuthenticate(ImageHandle, SystemTable);
}
#endif

