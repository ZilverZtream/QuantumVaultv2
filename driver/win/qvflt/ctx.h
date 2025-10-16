#pragma once

// TSK714A_System_Drive_Encryption_(PreBoot_Windows_First)_Stage1_Minifilter

#include <fltKernel.h>

typedef struct _QVFLT_VOLUME_CONTEXT {
    BOOLEAN IsSystemVolume;
    UNICODE_STRING VolumeName;
} QVFLT_VOLUME_CONTEXT, *PQVFLT_VOLUME_CONTEXT;

NTSTATUS
QvFltCreateVolumeContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_ PQVFLT_VOLUME_CONTEXT *Context
    );

VOID
QvFltCleanupVolumeContext(
    _Inout_ PQVFLT_VOLUME_CONTEXT Context
    );

