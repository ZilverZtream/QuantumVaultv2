// TSK714B_System_Drive_Encryption_(PreBoot_Windows_First)_Stage2_PreBoot_FullDisk

#include <ntddk.h>
#include <ntdddisk.h>
#include "../../../include/qv/platform/win/qvdisk_ioctl.h"

#define QVDISK_TAG 'dVQ'

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD QvDiskUnload;

static NTSTATUS QvDiskCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
static NTSTATUS QvDiskDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
static VOID     QvDiskZeroSessionKey(_Out_ QVDISK_SESSION_KEY *Key);

static QVDISK_SESSION_KEY g_QvDiskActiveKey = { 0 };
static QVDISK_RECOVERY_KEY_BLOB g_QvDiskRecoveryKey = { 0 };
static BOOLEAN g_QvDiskKeyLoaded = FALSE;
static BOOLEAN g_QvDiskUsingRecovery = FALSE;

static VOID
QvDiskZeroSessionKey(
    _Out_ QVDISK_SESSION_KEY *Key
    )
{
    if (Key != NULL) {
        RtlSecureZeroMemory(Key, sizeof(*Key));
    }
}

static NTSTATUS
QvDiskCompleteIrp(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
    )
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS
QvDiskCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return QvDiskCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS
QvDiskImportKey(
    _In_reads_bytes_(InputLength) PVOID InputBuffer,
    _In_ ULONG InputLength
    )
{
    if (InputBuffer == NULL || InputLength < sizeof(QVDISK_IMPORT_SESSION_KEY_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const QVDISK_IMPORT_SESSION_KEY_REQUEST *request = (const QVDISK_IMPORT_SESSION_KEY_REQUEST *)InputBuffer;
    RtlCopyMemory(&g_QvDiskActiveKey, &request->sessionKey, sizeof(g_QvDiskActiveKey));
    g_QvDiskKeyLoaded = TRUE;
    g_QvDiskUsingRecovery = ((request->sessionKey.flags & QVDISK_IMPORT_FLAG_RECOVERY_KEY) != 0);
    return STATUS_SUCCESS;
}

static NTSTATUS
QvDiskEnrollRecovery(
    _In_reads_bytes_(InputLength) PVOID InputBuffer,
    _In_ ULONG InputLength
    )
{
    if (InputBuffer == NULL || InputLength < sizeof(QVDISK_RECOVERY_KEY_BLOB)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const QVDISK_RECOVERY_KEY_BLOB *blob = (const QVDISK_RECOVERY_KEY_BLOB *)InputBuffer;
    if (blob->size > sizeof(blob->key)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&g_QvDiskRecoveryKey, blob, sizeof(*blob));
    return STATUS_SUCCESS;
}

static NTSTATUS
QvDiskQueryStatus(
    _Out_writes_bytes_(OutputLength) PVOID OutputBuffer,
    _In_ ULONG OutputLength,
    _Out_ PULONG_PTR Information
    )
{
    if (OutputBuffer == NULL || OutputLength < sizeof(QVDISK_STATUS_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    QVDISK_STATUS_RESPONSE *status = (QVDISK_STATUS_RESPONSE *)OutputBuffer;
    RtlZeroMemory(status, sizeof(*status));
    status->keyLoaded = g_QvDiskKeyLoaded ? 1 : 0;
    status->usingRecoveryKey = g_QvDiskUsingRecovery ? 1 : 0;
    status->integrityPlaneEnabled = 0;
    *Information = sizeof(*status);
    return STATUS_SUCCESS;
}

static VOID
QvDiskLock()
{
    g_QvDiskKeyLoaded = FALSE;
    g_QvDiskUsingRecovery = FALSE;
    QvDiskZeroSessionKey(&g_QvDiskActiveKey);
    RtlSecureZeroMemory(&g_QvDiskRecoveryKey, sizeof(g_QvDiskRecoveryKey));
}

static NTSTATUS
QvDiskDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    switch (code) {
    case IOCTL_QVDISK_IMPORT_SESSION_KEY:
        status = QvDiskImportKey(Irp->AssociatedIrp.SystemBuffer, stack->Parameters.DeviceIoControl.InputBufferLength);
        break;
    case IOCTL_QVDISK_LOCK:
        QvDiskLock();
        status = STATUS_SUCCESS;
        break;
    case IOCTL_QVDISK_STATUS:
        status = QvDiskQueryStatus(Irp->AssociatedIrp.SystemBuffer, stack->Parameters.DeviceIoControl.OutputBufferLength, &information);
        break;
    case IOCTL_QVDISK_ENROLL_RECOVERY:
        status = QvDiskEnrollRecovery(Irp->AssociatedIrp.SystemBuffer, stack->Parameters.DeviceIoControl.InputBufferLength);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return QvDiskCompleteIrp(Irp, status, information);
}

static VOID
QvDiskUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\QvDisk");
    IoDeleteSymbolicLink(&symLink);

    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    QvDiskLock();
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\QvDisk");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\QvDisk");
    PDEVICE_OBJECT deviceObject = NULL;

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_DISK, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = QvDiskCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = QvDiskCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = QvDiskDeviceControl;
    DriverObject->DriverUnload = QvDiskUnload;

    return STATUS_SUCCESS;
}

