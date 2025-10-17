// TSK714A_System_Drive_Encryption_(PreBoot_Windows_First)_Stage1_Minifilter

#include <fltKernel.h>
#include "ctx.h"
#include "keys.h"

#define QVFLT_TAG 'tfVQ'

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD QvFltUnload;

static NTSTATUS
QvFltInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

static CONST FLT_OPERATION_REGISTRATION g_OperationCallbacks[] = {
    { IRP_MJ_READ, 0, NULL, NULL },
    { IRP_MJ_WRITE, 0, NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

static CONST FLT_CONTEXT_REGISTRATION g_ContextRegistrations[] = {
    { FLT_VOLUME_CONTEXT, 0, (PFLT_CONTEXT_CLEANUP_CALLBACK)QvFltCleanupVolumeContext, sizeof(QVFLT_VOLUME_CONTEXT), QVFLT_TAG },
    { FLT_CONTEXT_END }
};

static CONST FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    g_ContextRegistrations,
    g_OperationCallbacks,
    QvFltUnload,
    QvFltInstanceSetup,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static PFLT_FILTER g_FilterHandle = NULL;
static QVFLT_KEY_STATE g_KeyState = { 0 };

static NTSTATUS
QvFltInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    NTSTATUS status = STATUS_SUCCESS;
    PQVFLT_VOLUME_CONTEXT context = NULL;

    status = QvFltCreateVolumeContext(FltObjects, &context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PFLT_CONTEXT oldContext = NULL;
    NTSTATUS setStatus = FltSetVolumeContext(
        FltObjects->Volume,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        context,
        &oldContext);

    if (setStatus == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        setStatus = STATUS_SUCCESS;
    }

    if (oldContext != NULL) {
        FltReleaseContext(oldContext);
        oldContext = NULL;
    }

    FltReleaseContext(context);

    return setStatus;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    return status;
}

NTSTATUS
QvFltCreateVolumeContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_ PQVFLT_VOLUME_CONTEXT *Context
    )
{
    NTSTATUS status = FltAllocateContext(g_FilterHandle, FLT_VOLUME_CONTEXT, sizeof(QVFLT_VOLUME_CONTEXT), NonPagedPoolNx, (PFLT_CONTEXT*)Context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(*Context, sizeof(**Context));
    (*Context)->IsSystemVolume = FALSE;
    UNREFERENCED_PARAMETER(FltObjects);
    return STATUS_SUCCESS;
}

VOID
QvFltCleanupVolumeContext(
    _Inout_ PQVFLT_VOLUME_CONTEXT Context
    )
{
    if (Context->VolumeName.Buffer != NULL) {
        ExFreePoolWithTag(Context->VolumeName.Buffer, QVFLT_TAG);
        Context->VolumeName.Buffer = NULL;
        Context->VolumeName.Length = 0;
        Context->VolumeName.MaximumLength = 0;
    }
}

VOID
QvFltZeroKey(
    _Inout_ PQVFLT_KEY_STATE State
    )
{
    if (State == NULL) {
        return;
    }

    RtlZeroMemory(&State->ActiveKey, sizeof(State->ActiveKey));
    State->Loaded = FALSE;
}

NTSTATUS
QvFltApplyKey(
    _Inout_ PQVFLT_KEY_STATE State,
    _In_reads_bytes_(sizeof(QVFLT_KEY_REQUEST)) const QVFLT_KEY_REQUEST *Key
    )
{
    if (State == NULL || Key == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&State->ActiveKey, Key, sizeof(*Key));
    State->Loaded = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS
QvFltUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    QvFltZeroKey(&g_KeyState);

    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

