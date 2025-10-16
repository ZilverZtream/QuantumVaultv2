#pragma once

// TSK714A_System_Drive_Encryption_(PreBoot_Windows_First)_Stage1_Minifilter

#include <fltKernel.h>
#include "../../../include/qv/platform/win/qvflt_ioctl.h"

typedef struct _QVFLT_KEY_STATE {
    BOOLEAN Loaded;
    QVFLT_KEY_REQUEST ActiveKey;
} QVFLT_KEY_STATE, *PQVFLT_KEY_STATE;

VOID
QvFltZeroKey(
    _Inout_ PQVFLT_KEY_STATE State
    );

NTSTATUS
QvFltApplyKey(
    _Inout_ PQVFLT_KEY_STATE State,
    _In_reads_bytes_(sizeof(QVFLT_KEY_REQUEST)) const QVFLT_KEY_REQUEST *Key
    );

